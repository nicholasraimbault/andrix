#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Standalone public SDK producer. No image build, installation or guest operation.

Only the fixed retained certificate is admitted. All admission checks, including its DER
SHA256, precede output creation. Private key bytes are read only by apksigner and never copied.
Use an absent output directory. A failed producer is retained, never resumed or overwritten.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import zipfile
import zlib

SIGNER = '874cedf46661e33d62b711b266c96e629d1f64007e55350a59a167c9c23183d3'
PACKAGE = 'dev.andrix.proof.principalclosed'
PERMISSIONS = {'android.permission.POST_NOTIFICATIONS', 'android.permission.VIBRATE',
               'android.permission.RECEIVE_BOOT_COMPLETED'}
JDK = 'prebuilts/jdk/jdk25/linux-x86/bin/'
SDK = 'prebuilts/sdk/36/public/android.jar'
AAPT = 'prebuilts/sdk/tools/linux/bin/aapt2'
ALIGN = 'prebuilts/sdk/tools/linux/bin/zipalign'
D8 = 'prebuilts/r8/r8.jar'
APKSIGNER = 'prebuilts/sdk/tools/linux/lib/apksigner.jar'
SETUP_SOURCE = 'setup-src/dev/andrix/proof/b2setup/NotificationSetup.java'
SETUP_CLASSES = {'Ldev/andrix/proof/b2setup/NotificationSetup;'}
SETUP_REFERENCES = {
    'frameworks/base/core/java/android/app/INotificationManager.aidl',
    'frameworks/base/core/java/android/app/NotificationChannel.java',
    'frameworks/base/core/java/android/os/BinderProxy.java',
    'frameworks/base/core/java/android/os/Parcel.java',
    'frameworks/base/core/java/android/os/ServiceManager.java',
    'frameworks/base/cmds/app_process/app_main.cpp',
    'frameworks/base/core/java/com/android/internal/os/RuntimeInit.java',
    'frameworks/base/services/core/java/com/android/server/notification/NotificationManagerService.java',
    'frameworks/base/services/core/java/com/android/server/notification/PreferencesHelper.java',
    'frameworks/base/services/core/java/com/android/server/notification/NotificationShellCmd.java'}
VM = ['-XX:ActiveProcessorCount=2', '-XX:+UseSerialGC', '-XX:CompressedClassSpaceSize=64m',
      '-XX:MaxMetaspaceSize=128m',
      '-XX:ReservedCodeCacheSize=64m', '-Xss512k', '-XX:-UsePerfData']


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def bounded_file(path, bound=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= bound, 'regular bounded input')
        data = stream.read(bound + 1)
        require(len(data) <= bound, 'input grew')
    return data


def certificate_der(path):
    data = bounded_file(path)
    if data.startswith(b'-----BEGIN CERTIFICATE-----'):
        match = re.fullmatch(rb'-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)'
                             rb'-----END CERTIFICATE-----\r?\n?', data)
        require(match is not None, 'one PEM certificate required')
        compact = match[1].replace(b'\r', b'').replace(b'\n', b'')
        data = base64.b64decode(compact, validate=True)
        require(base64.b64encode(data) == compact, 'canonical certificate base64')
    require(data.startswith(b'\x30') and len(data) >= 128, 'DER certificate required')
    return data


def manifest_contract(data):
    require(b'<!' not in data, 'plain manifest XML required')
    root = ET.fromstring(data)
    ns = '{http://schemas.android.com/apk/res/android}'
    attrs = lambda row: {k.removeprefix(ns): v for k, v in row.attrib.items()}
    require(root.tag == 'manifest' and attrs(root) == {
        'package': PACKAGE, 'versionCode': '1', 'versionName': '1'}, 'manifest identity')
    require([x.tag for x in root] == ['uses-sdk', 'uses-permission', 'uses-permission',
                                    'uses-permission', 'application', 'instrumentation'],
            'manifest components or permissions')
    require(attrs(root[0]) == {'minSdkVersion': '37', 'targetSdkVersion': '37'}, 'SDK declarations')
    perms = [attrs(x) for x in root[1:4]]
    require(len(perms) == 3 and {x.get('name') for x in perms} == PERMISSIONS
            and all(set(x) == {'name'} for x in perms), 'exact requested permissions')
    app = root[4]
    require(attrs(app) == {'label': '@string/app_name', 'allowBackup': 'false',
                          'debuggable': 'false', 'testOnly': 'true', 'hasCode': 'true',
                          'usesCleartextTraffic': 'false', 'directBootAware': 'false'},
            'ordinary test application contract')
    require(len(app) == 1 and app[0].tag == 'service' and attrs(app[0]) == {
        'name': '.B2StateJobService', 'exported': 'true',
        'permission': 'android.permission.BIND_JOB_SERVICE', 'directBootAware': 'false'},
        'guarded job service contract')
    require(attrs(root[5]) == {'name': '.B2StateInstrumentation', 'targetPackage': PACKAGE,
                              'functionalTest': 'true', 'handleProfiling': 'false'},
            'self instrumentation contract')
    require(all(len(x) == 0 for x in [*root[:4], app[0], root[5]]), 'unexpected nested element')


def preflight(android_root, source, key, cert, output):
    # This is deliberately FIRST, before mkdir, logs, temporary files or any tool invocation.
    der = certificate_der(cert)
    require(hashlib.sha256(der).hexdigest() == SIGNER, 'refusing another signer certificate')
    require(key.is_absolute() and cert.is_absolute(), 'absolute custody arguments required')
    for path in (source, android_root, output.parent):
        require(path.is_absolute() and path.resolve() == path and path.is_dir()
                and not path.is_symlink(), 'canonical existing input or output parent required')
    require(not output.exists() and not output.is_symlink(), 'output must be absent')
    require(source not in output.parents and android_root not in output.parents,
            'output must be outside source and toolchain')
    require(key.is_file() and not key.is_symlink(), 'regular private key argument required')
    def unique(pairs):
        result = {}
        for name, value in pairs:
            require(name not in result, 'duplicate tool manifest key')
            result[name] = value
        return result

    tools = json.loads(bounded_file(source / 'tools.json'), object_pairs_hook=unique)
    require(type(tools) is dict and set(tools) == {JDK + 'javac', JDK + 'java', JDK + 'jar', SDK, AAPT, ALIGN, D8,
                           APKSIGNER}, 'closed tool manifest')
    require(all(type(h) is str and re.fullmatch('[0-9a-f]{64}', h) and digest(android_root / p) == h
                for p, h in tools.items()), 'pinned tool digest mismatch')
    references = json.loads(bounded_file(source / 'setup-api.json'), object_pairs_hook=unique)
    require(type(references) is dict and set(references) == SETUP_REFERENCES
            and all(type(h) is str and re.fullmatch('[0-9a-f]{64}', h)
                    and digest(android_root / p) == h for p, h in references.items()),
            'pinned notification setup source mismatch')
    manifest_contract(bounded_file(source / 'AndroidManifest.xml'))
    java = sorted(source.glob('src/dev/andrix/proof/principalclosed/*.java'))
    require({p.name for p in java} == {'B2StateInstrumentation.java', 'B2StateJobService.java',
        'Contract.java', 'InitializeState.java', 'ObserveState.java', 'StateFiles.java'},
        'closed Java source set')
    require(sorted(p.relative_to(source).as_posix() for p in source.glob('res/**/*') if p.is_file())
            == ['res/values/strings.xml'], 'closed resources')
    setup_java = sorted(source.glob('setup-src/**/*.java'))
    require([p.relative_to(source).as_posix() for p in setup_java] == [SETUP_SOURCE],
            'one separate shell setup source, never an APK class')
    inputs = [source / 'produce.py', source / 'tools.json', source / 'setup-api.json',
              source / 'AndroidManifest.xml', source / 'res/values/strings.xml', *java, *setup_java]
    require(all(not p.is_symlink() and p.is_file() and p.resolve() == p for p in inputs),
            'regular source inputs without symlink parents')
    return der, tools, references, {p.relative_to(source).as_posix(): digest(p) for p in inputs}, java, setup_java


def artifact_contract(verify, badging, tree):
    certs = re.findall(r'^Signer #\d+ certificate SHA-256 digest: ([0-9a-f]+)$', verify, re.M)
    require(certs == [SIGNER] and 'Number of signers: 1' in verify
            and 'Verified using v3 scheme (APK Signature Scheme v3): true' in verify,
            'APK signature verification for SDK 37')
    require(len(re.findall(r'^package:', badging, re.M)) == 1
            and "package: name='" + PACKAGE + "' versionCode='1'" in badging
            and re.findall(r'^(?:minSdkVersion|sdkVersion):\x27([0-9]+)\x27$', badging, re.M) == ['37']
            and re.findall(r'^targetSdkVersion:\x27([0-9]+)\x27$', badging, re.M) == ['37']
            and 'application-debuggable' not in badging, 'APK badging')
    perms = re.findall(r'^uses-permission: name=\x27([^\x27]+)\x27(?:.*)$', badging, re.M)
    require(len(perms) == 3 and set(perms) == PERMISSIONS, 'APK permission inventory')
    compiled_manifest(tree)


def compiled_manifest(tree):
    """Decode this pinned aapt2 XML dump, including nesting and every attribute."""
    root = None
    stack = []
    for index, line in enumerate(tree.splitlines()):
        if index == 0:
            require(line.startswith('N: android=http://schemas.android.com/apk/res/android '),
                    'manifest namespace')
            continue
        element = re.fullmatch(r'( *)E: ([A-Za-z-]+) \(line=[0-9]+\)', line)
        if element:
            indent = len(element[1])
            while stack and stack[-1][0] >= indent:
                stack.pop()
            node = ET.Element(element[2])
            if stack:
                require(indent == stack[-1][0] + 4, 'compiled element indentation')
                stack[-1][1].append(node)
            else:
                require(root is None, 'one compiled manifest root')
                root = node
            stack.append((indent, node))
            continue
        attr = re.fullmatch(r'( *)A: (?:http://schemas.android.com/apk/res/android:)?'
                            r'([A-Za-z0-9]+)(?:\(0x[0-9a-f]+\))?=(.*)', line)
        require(attr is not None and stack and len(attr[1]) == stack[-1][0] + 2,
                'compiled attribute grammar')
        value = attr[3]
        if value.startswith('"'):
            quoted = re.fullmatch(r'"([^"\n]*)" \(Raw: "([^"\n]*)"\)', value)
            require(quoted is not None and quoted[1] == quoted[2], 'compiled raw string')
            value = quoted[1]
        node = stack[-1][1]
        require(attr[2] not in node.attrib, 'duplicate compiled attribute')
        node.set(attr[2], value)
    require(root is not None and root.tag == 'manifest' and root.attrib == {
        'package': PACKAGE, 'versionCode': '1', 'versionName': '1', 'compileSdkVersion': '36',
        'compileSdkVersionCodename': '16', 'platformBuildVersionCode': '36',
        'platformBuildVersionName': '16'}, 'compiled manifest identity')
    require([x.tag for x in root] == ['uses-sdk', 'uses-permission', 'uses-permission',
                                    'uses-permission', 'application', 'instrumentation'],
            'compiled component inventory')
    require(root[0].attrib == {'minSdkVersion': '37', 'targetSdkVersion': '37'}
            and {x.get('name') for x in root[1:4]} == PERMISSIONS
            and all(set(x.attrib) == {'name'} and not len(x) for x in root[1:4]),
            'compiled SDK or permission contract')
    app = root[4]
    label = app.get('label', '')
    require(re.fullmatch('@0x[0-9a-f]{8}', label) and app.attrib == {
        'label': label, 'hasCode': 'true', 'debuggable': 'false', 'testOnly': 'true',
        'allowBackup': 'false', 'usesCleartextTraffic': 'false', 'directBootAware': 'false'},
        'compiled application contract')
    require(len(app) == 1 and app[0].tag == 'service' and app[0].attrib == {
        'name': '.B2StateJobService', 'permission': 'android.permission.BIND_JOB_SERVICE',
        'exported': 'true', 'directBootAware': 'false'} and not len(app[0]),
        'compiled guarded service')
    require(root[5].attrib == {'name': '.B2StateInstrumentation', 'targetPackage': PACKAGE,
        'handleProfiling': 'false', 'functionalTest': 'true'} and not len(root[5]),
        'compiled self instrumentation')


def dex_inventory(data, expected=None):
    """Definition inventory, not an instruction verifier. Layout follows the existing DEX model."""
    if expected is None:
        expected = {'Ldev/andrix/proof/principalclosed/' + name + ';' for name in (
            'B2StateInstrumentation', 'B2StateJobService', 'Contract', 'InitializeState',
            'ObserveState', 'StateFiles')}
    require(112 <= len(data) <= 4 << 20 and data[:8] == b'dex\n039\0', 'pinned D8 DEX envelope')
    require(hashlib.sha1(data[32:]).digest() == data[12:32]
            and zlib.adler32(data[12:]) == struct.unpack_from('<I', data, 8)[0], 'DEX checksums')

    def word(offset):
        require(0 <= offset <= len(data) - 4, 'DEX word bound')
        return struct.unpack_from('<I', data, offset)[0]

    require(word(32) == len(data) and word(36) == 112 and word(40) == 0x12345678, 'DEX header')
    strings, string_at, types, type_at = (word(i) for i in (56, 60, 64, 68))
    classes, class_at = word(96), word(100)
    require(classes == len(expected) and 0 < strings <= 65535 and 0 < types <= 65535
            and 112 <= string_at <= len(data) - 4 * strings
            and 112 <= type_at <= len(data) - 4 * types
            and 112 <= class_at <= len(data) - 32 * classes, 'DEX table bounds')
    names = []
    for index in range(classes):
        type_index = word(class_at + index * 32)
        require(type_index < types, 'DEX class type')
        string_index = word(type_at + type_index * 4)
        require(string_index < strings, 'DEX descriptor index')
        offset = word(string_at + string_index * 4)
        units = shift = 0
        for _ in range(5):
            require(offset < len(data), 'DEX string length')
            byte = data[offset]; offset += 1
            units |= (byte & 127) << shift; shift += 7
            if byte < 128:
                break
        else:
            raise ValueError('DEX string length bound')
        end = data.find(b'\0', offset, min(len(data), offset + 1024))
        require(end >= offset and end - offset == units, 'ASCII class descriptor')
        names.append(data[offset:end].decode('ascii'))
    require(set(names) == expected and len(set(names)) == len(expected),
            'exact DEX class definition inventory')
    return sorted(names)


def build(android_root, source, key, cert, output, source_revision=None):
    der, tools, references, inputs, java, setup_java = preflight(
        android_root, source, key, cert, output)
    require(type(source_revision) is str and re.fullmatch('[0-9a-f]{40}', source_revision),
            'explicit full source revision claim required')
    deadline = time.monotonic() + 300
    os.umask(0o077)
    output.mkdir(mode=0o700)
    for name in ('work', 'home', 'tmp', 'logs'):
        (output / name).mkdir(mode=0o700)
    work = output / 'work'
    for name in ('classes', 'dex', 'setup-classes', 'setup-dex'):
        (work / name).mkdir()
    env = {'PATH': str(android_root / JDK) + ':/usr/bin:/bin',
           'JAVA_HOME': str((android_root / JDK).parent), 'HOME': str(output / 'home'),
           'TMPDIR': str(output / 'tmp'), 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'}
    steps = []
    vm = [*VM, '-Djava.io.tmpdir=' + str(output / 'tmp'), '-Duser.home=' + str(output / 'home')]

    def save(name, value):
        (output / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

    def display(arg):
        arg = str(arg)
        for flag, replacement in [('--key=', '<private-key>'), ('--cert=', '<certificate>')]:
            if arg.startswith(flag):
                return flag + replacement
        for flag in ('--source=', '--android-root=', '--out='):
            if arg.startswith(flag):
                return flag + display(arg[len(flag):])
        for flag, label in [('java.io.tmpdir', 'tmp'), ('user.home', 'home')]:
            for prefix in ('-D', '-J-D'):
                if arg.startswith(prefix + flag + '='):
                    return prefix + flag + '=<output>/' + label
        if arg == str(key):
            return '<private-key>'
        if arg == str(cert):
            return '<certificate>'
        for path, label in [(output, '<output>'), (source, '<source>'), (android_root, '<android>')]:
            if arg == str(path) or arg.startswith(str(path) + '/'):
                return label + arg[len(str(path)):]
        return arg

    def limits():
        os.nice(max(0, 19 - os.getpriority(os.PRIO_PROCESS, 0)))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_AS, (2 << 30, 2 << 30))
        resource.setrlimit(resource.RLIMIT_CPU, (90, 90))
        resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))

    def run(label, args):
        index = len(steps) + 1
        stem = f'logs/{index:02d}-{label}'
        started = time.monotonic_ns()
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'producer total deadline')
        with (output / (stem + '.stdout')).open('xb') as out, (
                output / (stem + '.stderr')).open('xb') as err:
            try:
                result = subprocess.run(list(map(str, args)), cwd=output, env=env, stdout=out,
                                        stderr=err, timeout=min(90, remaining), preexec_fn=limits)
                code = result.returncode
            except subprocess.TimeoutExpired:
                code = 'timeout'
        record = {'step': index, 'label': label, 'argv': list(map(display, args)), 'exit_code': code,
                  'duration_ms': (time.monotonic_ns() - started) // 1000000}
        for suffix in ('stdout', 'stderr'):
            path = output / (stem + '.' + suffix)
            require(path.stat().st_size <= 4 << 20, 'tool output bound')
            record[suffix + '_sha256'] = digest(path)
        steps.append(record); save('steps.json', steps)
        require(code == 0, 'tool step failed: ' + label)
        return (output / (stem + '.stdout')).read_text(encoding='utf-8')

    def jrun(heap):
        return [android_root / (JDK + 'java'), '-Xmx' + heap, *vm]

    python_digest = digest(sys.executable)
    producer_digest = digest(Path(__file__))
    save('tools.json', tools); save('setup-api.json', references); save('inputs.json', inputs)
    save('host-tool.json', {'python_sha256': python_digest, 'python_version': sys.version,
                            'executed_producer_sha256': producer_digest})
    save('invocation.json', {'argv': ['<producer>', *[display(x) for x in sys.argv[1:]]]})
    (output / 'certificate.der').write_bytes(der)
    save('admission.json', {'source_revision_claim': source_revision,
                           'source_identity': 'Exact file hashes in inputs.json; revision is caller supplied',
                           'signer_sha256': SIGNER, 'compile_sdk': 36, 'dex_min_api': 36,
                           'min_sdk': 37, 'target_sdk': 37, 'version_code': 1,
                           'per_command_wall_seconds': 90, 'producer_wall_seconds': 300,
                           'child_address_space_bytes': 2 << 30,
                           'nice': 19, 'no_guest_action': True})
    try:
        run('javac-version', [android_root / (JDK + 'javac'), *['-J' + x for x in vm], '--version'])
        run('java-version', [*jrun('128m'), '--version'])
        run('jar-version', [android_root / (JDK + 'jar'), *['-J' + x for x in vm], '--version'])
        run('aapt-version', [android_root / AAPT, 'version'])
        run('d8-version', [*jrun('256m'), '-cp', android_root / D8, 'com.android.tools.r8.D8', '--version'])
        run('apksigner-version', [*jrun('128m'), '-jar', android_root / APKSIGNER, 'version'])
        run('compile', [android_root / (JDK + 'javac'), '-J-Xmx256m', *['-J' + x for x in vm],
                        '--release', '17', '-proc:none', '-cp', android_root / SDK,
                        '-d', work / 'classes', *java])
        run('classes', [android_root / (JDK + 'jar'), *['-J' + x for x in vm], '--create',
                        '--file', work / 'classes.jar', '-C', work / 'classes', '.'])
        run('dex', [*jrun('512m'), '-cp', android_root / D8, 'com.android.tools.r8.D8', '--release',
                    '--min-api', '36', '--lib', android_root / SDK, '--output', work / 'dex',
                    work / 'classes.jar'])
        require(sorted(p.name for p in (work / 'dex').iterdir()) == ['classes.dex'], 'one DEX')
        classes = dex_inventory((work / 'dex/classes.dex').read_bytes())
        save('dex-inventory.json', {'definitions': classes, 'instruction_verification_claimed': False})
        run('resources', [android_root / AAPT, 'compile', '--dir', source / 'res', '-o', work / 'res.zip'])
        run('link', [android_root / AAPT, 'link', '-I', android_root / SDK, '--manifest',
                     source / 'AndroidManifest.xml', '--min-sdk-version', '37',
                     '--target-sdk-version', '37', '-o', work / 'resources.apk', work / 'res.zip'])
        with zipfile.ZipFile(work / 'resources.apk') as src, zipfile.ZipFile(work / 'raw.apk', 'x') as dst:
            require(len(src.namelist()) == len(set(src.namelist())), 'duplicate resource ZIP entry')
            for info in src.infolist():
                dst.writestr(info, src.read(info.filename))
            info = zipfile.ZipInfo('classes.dex', date_time=(2009, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            dst.writestr(info, (work / 'dex/classes.dex').read_bytes())
        save('unsigned.json', {p: digest(work / p) for p in ('resources.apk', 'raw.apk', 'dex/classes.dex')})
        run('align', [android_root / ALIGN, '-p', '4', work / 'raw.apk', work / 'aligned.apk'])
        apk = output / 'B2StateSubject.apk'
        run('sign', [*jrun('256m'), '-jar', android_root / APKSIGNER, 'sign', '--key', key,
                     '--cert', output / 'certificate.der', '--min-sdk-version', '37',
                     '--v1-signing-enabled', 'false',
                     '--v2-signing-enabled', 'true', '--v3-signing-enabled', 'true',
                     '--v4-signing-enabled', 'false', '--out', apk, work / 'aligned.apk'])
        run('verify-alignment', [android_root / ALIGN, '-c', '-p', '4', apk])
        verify = run('verify', [*jrun('256m'), '-jar', android_root / APKSIGNER, 'verify', '--verbose',
                                '--print-certs', '--min-sdk-version', '37', '--max-sdk-version', '37', apk])
        badging = run('badging', [android_root / AAPT, 'dump', 'badging', apk])
        tree = run('xmltree', [android_root / AAPT, 'dump', 'xmltree', '--file', 'AndroidManifest.xml', apk])
        artifact_contract(verify, badging, tree)
        # SDK 37 uses v3. This additional artificial range exercises the requested v2 signature,
        # without claiming that the manifest admits installation on those earlier platforms.
        verify_v2 = run('verify-v2', [*jrun('256m'), '-jar', android_root / APKSIGNER, 'verify',
                                     '--verbose', '--print-certs', '--min-sdk-version', '24',
                                     '--max-sdk-version', '27', apk])
        require('Verified using v2 scheme (APK Signature Scheme v2): true' in verify_v2
                and re.findall(r'^Signer #\d+ certificate SHA-256 digest: ([0-9a-f]+)$',
                               verify_v2, re.M) == [SIGNER], 'requested v2 signature')
        with zipfile.ZipFile(apk) as archive:
            require(len(archive.namelist()) == len(set(archive.namelist()))
                    and archive.read('classes.dex') == (work / 'dex/classes.dex').read_bytes(),
                    'signed DEX inventory')
            inventory = {i.filename: {'bytes': i.file_size,
                         'sha256': hashlib.sha256(archive.read(i.filename)).hexdigest()}
                         for i in archive.infolist()}
        run('compile-setup', [android_root / (JDK + 'javac'), '-J-Xmx256m',
                              *['-J' + x for x in vm], '--release', '17', '-proc:none',
                              '-cp', android_root / SDK, '-d', work / 'setup-classes', *setup_java])
        run('classes-setup', [android_root / (JDK + 'jar'), *['-J' + x for x in vm], '--create',
                              '--file', work / 'setup-classes.jar', '-C', work / 'setup-classes', '.'])
        run('dex-setup', [*jrun('256m'), '-cp', android_root / D8, 'com.android.tools.r8.D8',
                          '--release', '--min-api', '36', '--lib', android_root / SDK,
                          '--output', work / 'setup-dex', work / 'setup-classes.jar'])
        require(sorted(p.name for p in (work / 'setup-dex').iterdir()) == ['classes.dex'],
                'one shell setup DEX')
        setup_dex = (work / 'setup-dex/classes.dex').read_bytes()
        setup_definitions = dex_inventory(setup_dex, SETUP_CLASSES)
        setup_jar = output / 'B2NotificationSetup.jar'
        with zipfile.ZipFile(setup_jar, 'x') as archive:
            item = zipfile.ZipInfo('classes.dex', date_time=(2009, 1, 1, 0, 0, 0))
            item.compress_type = zipfile.ZIP_STORED
            archive.writestr(item, setup_dex)
        with zipfile.ZipFile(setup_jar) as archive:
            require(archive.namelist() == ['classes.dex'] and archive.read('classes.dex') == setup_dex,
                    'exact shell command jar, separate from APK')
        setup_artifact = {'file': setup_jar.name, 'sha256': digest(setup_jar),
                          'bytes': setup_jar.stat().st_size, 'dex_sha256': hashlib.sha256(setup_dex).hexdigest(),
                          'dex_class_definitions': setup_definitions, 'required_uid': 2000,
                          'role': 'setup only, not an APK or observer', 'runtime_qualified': False}
        save('setup-artifact.json', setup_artifact)
        require(all(digest(source / p) == h for p, h in inputs.items())
                and all(digest(android_root / p) == h for p, h in references.items())
                and all(digest(android_root / p) == h for p, h in tools.items())
                and digest(sys.executable) == python_digest
                and digest(Path(__file__)) == producer_digest, 'inputs drifted')
        save('artifact.json', {'file': apk.name, 'sha256': digest(apk), 'bytes': apk.stat().st_size,
                              'certificate_sha256': SIGNER, 'zip_inventory': inventory,
                              'dex_class_definitions': classes, 'notification_setup': setup_artifact,
                              'aligned_sha256': digest(work / 'aligned.apk'), 'runtime_qualified': False})
        save('closure.json', {'build_complete': True, 'tools_unchanged': True, 'inputs_unchanged': True,
                              'Android_runtime_qualified': False, 'image_build_performed': False})
    except Exception:
        save('closure.json', {'build_complete': False, 'Android_runtime_qualified': False,
                              'partial_output_retained': True})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--android-root', required=True, type=Path)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--key', required=True, type=Path)
    parser.add_argument('--cert', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    try:
        build(args.android_root, args.source, args.key, args.cert, args.out, args.source_revision)
    except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError, ET.ParseError) as error:
        # The exception message from an OS operation may contain custody paths. Logs contain
        # only redacted argv. Report the class and do not print a private path or key content.
        print('B2 producer refused or failed: ' + type(error).__name__, file=sys.stderr)
        return 2
    print('B2 APK and separate shell setup jar built and verified; Android runtime unqualified.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
