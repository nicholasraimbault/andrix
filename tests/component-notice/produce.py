#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Standalone public SDK producer of the full screen notice fixture and its shell helper. No image
build, installation or guest operation.

  produce.py --android-root <tree> --source-revision <40 hex> --key <PKCS#8 DER> --cert <PEM or DER>
             --signer-sha256 <certificate DER SHA-256> --out <absent directory>
  produce.py --check-output <output directory>

The signer is whoever supplies the key: a disposable one for a host build, the primary's for the
real artifact. Its certificate's SHA-256 must be named explicitly and equal the certificate given.
Every input, tool and pinned framework source is checked before any output, log or child process.
Private key bytes are read only by apksigner. A failed output is kept as partial evidence and never
resumed. The unsigned outputs are reproducible: the DEX, the aligned unsigned APK and the helper jar
must equal pins.json, whatever the signer. --check-output repeats the artifact checks on a finished
output directory, from its files and recorded tool outputs, without running a tool.
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

HERE = Path(__file__).resolve().parent
PACKAGE = 'dev.andrix.lab.notice'
JDK = 'prebuilts/jdk/jdk25/linux-x86/bin/'
SDK = 'prebuilts/sdk/36/public/android.jar'
AAPT = 'prebuilts/sdk/tools/linux/bin/aapt2'
ALIGN = 'prebuilts/sdk/tools/linux/bin/zipalign'
D8 = 'prebuilts/r8/r8.jar'
APKSIGNER = 'prebuilts/sdk/tools/linux/lib/apksigner.jar'
TOOLS = {JDK + 'javac', JDK + 'java', JDK + 'jar', SDK, AAPT, ALIGN, D8, APKSIGNER}
APK = 'NoticeFixture.apk'
HELPER_JAR = 'andrix-notice-present.jar'
APP_SOURCES = ('AndroidDisk.java', 'Delivery.java', 'Disk.java', 'Forms.java', 'NoticeActivity.java',
               'NoticeRequest.java', 'ProviderPolicy.java', 'ReceiptProvider.java', 'ReceiptRow.java',
               'ReceiptStore.java', 'Writer.java')
HELPER_SOURCES = ('present-src/dev/andrix/lab/notice/NoticePresent.java',
                  'src/dev/andrix/lab/notice/NoticeRequest.java', 'src/dev/andrix/lab/notice/Forms.java')
RESOURCES = ('res/layout/notice.xml', 'res/values/strings.xml')
SOURCE_FILES = ('produce.py', 'tools.json', 'framework-api.json', 'pins.json', 'AndroidManifest.xml', *RESOURCES,
                *('src/dev/andrix/lab/notice/' + name for name in APP_SOURCES), HELPER_SOURCES[0])
DEX_CLASSES = ('AndroidDisk', 'AndroidDisk$FileHandle', 'Delivery', 'Disk', 'Disk$Handle', 'Forms', 'NoticeActivity',
               'NoticeActivity$1', 'NoticeActivity$IntentExtras', 'NoticeRequest', 'NoticeRequest$Extras',
               'NoticeRequest$Sink', 'ProviderPolicy', 'R', 'R$id', 'R$layout', 'R$string', 'ReceiptProvider',
               'ReceiptRow', 'ReceiptStore', 'ReceiptStore$Existing', 'ReceiptStore$Listing', 'ReceiptStore$Nonces',
               'ReceiptStore$Outcome', 'Writer', 'Writer$1', 'Writer$2')
HELPER_CLASSES = ('Forms', 'NoticePresent', 'NoticePresent$1', 'NoticePresent$Report', 'NoticeRequest',
                  'NoticeRequest$Extras', 'NoticeRequest$Sink')
# Names the app's DEX must reference, and names that neither the app nor the helper may: keyguard
# dismissal, identity clearing, other starts, network, process execution and class loading.
APP_REQUIRED = ('getLaunchedFromUid', 'getSerialNumberForUser', 'registerFrameCommitCallback', 'fsync',
                'rename', 'createDeviceProtectedStorageContext', 'getCallingUid', 'getBinder', 'writeInterfaceToken')
HELPER_REQUIRED = ('startActivityAndWait', 'setShareIdentityEnabled', 'makeBasic', 'toBundle', 'com.android.shell',
                   'activity_task', 'android.app.IActivityTaskManager', 'android.app.WaitResult', 'putBinder',
                   'enforceInterface', 'onTransact')
FORBIDDEN = ('requestDismissKeyguard', 'setDismissKeyguardIfInsecure', 'disableKeyguard', 'newKeyguardLock',
             'clearCallingIdentity', 'startActivityAsUser', 'startActivityAsCaller', 'sendBroadcast',
             'Ljava/net/', 'Ljava/lang/Runtime;', 'Ljava/lang/ProcessBuilder;', 'Ldalvik/system/DexClassLoader;',
             'Ldalvik/system/PathClassLoader;')
APP_FORBIDDEN = FORBIDDEN + ('Ljava/lang/reflect/Method;', 'startActivity', 'Landroid/content/ContentResolver;')
VM = ['-XX:ActiveProcessorCount=2', '-XX:+UseSerialGC', '-XX:CompressedClassSpaceSize=64m',
      '-XX:MaxMetaspaceSize=128m', '-XX:ReservedCodeCacheSize=64m', '-Xss512k', '-XX:-UsePerfData']
JAVAC = ['--release', '17', '-Xlint:all', '-Werror', '-proc:none', '-implicit:none', '-encoding', 'US-ASCII']
FIXED_TIME = (2009, 1, 1, 0, 0, 0)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def bounded_file(path, bound=1 << 20):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= bound, 'regular bounded input')
        data = stream.read(bound + 1)
        require(len(data) <= bound, 'input grew')
    return data


def strict_json(data):
    def pairs(items):
        keys = [k for k, _ in items]
        require(len(keys) == len(set(keys)), 'duplicate JSON key')
        return dict(items)
    return json.loads(data, object_pairs_hook=pairs)


def certificate_der(path):
    data = bounded_file(path, 65536)
    if data.startswith(b'-----BEGIN CERTIFICATE-----'):
        match = re.fullmatch(rb'-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)'
                             rb'-----END CERTIFICATE-----\r?\n?', data)
        require(match is not None, 'one PEM certificate required')
        compact = match[1].replace(b'\r', b'').replace(b'\n', b'')
        data = base64.b64decode(compact, validate=True)
        require(base64.b64encode(data) == compact, 'canonical certificate base64')
    require(data.startswith(b'\x30') and len(data) >= 128, 'DER certificate required')
    return data


# ------------------------------------------------------------------ the manifest contract

ANDROID = '{http://schemas.android.com/apk/res/android}'
APPLICATION = {'label': '@string/app_name', 'allowBackup': 'false', 'debuggable': 'false', 'testOnly': 'true',
               'hasCode': 'true', 'usesCleartextTraffic': 'false'}
ACTIVITY = {'name': '.NoticeActivity', 'exported': 'true', 'permission': 'android.permission.DUMP',
            'directBootAware': 'true', 'showWhenLocked': 'true', 'turnScreenOn': 'true',
            'excludeFromRecents': 'true', 'launchMode': 'standard',
            'theme': '@android:style/Theme.DeviceDefault.NoActionBar'}
PROVIDER = {'name': '.ReceiptProvider', 'authorities': PACKAGE + '.receipts', 'exported': 'true',
            'permission': 'android.permission.DUMP', 'directBootAware': 'true', 'grantUriPermissions': 'false',
            'multiprocess': 'false'}


def manifest_contract(data):
    """The source manifest: exactly the fixture's identity, SDK, application and two components,
    with no permission requested, no shared UID and no process attribute."""
    require(b'<!DOCTYPE' not in data and b'<!ENTITY' not in data, 'plain manifest XML required')
    root = ET.fromstring(data)
    attrs = lambda row: {k.removeprefix(ANDROID): v for k, v in row.attrib.items()}
    require(root.tag == 'manifest' and attrs(root) == {'package': PACKAGE, 'versionCode': '1', 'versionName': '1'},
            'manifest identity')
    require([x.tag for x in root] == ['uses-sdk', 'application'], 'manifest elements: no permission requested')
    require(attrs(root[0]) == {'minSdkVersion': '37', 'targetSdkVersion': '37'}, 'SDK declarations')
    app = root[1]
    require(attrs(app) == APPLICATION, 'ordinary test application contract')
    require([x.tag for x in app] == ['activity', 'provider'], 'exactly the activity and the provider')
    require(attrs(app[0]) == ACTIVITY and attrs(app[1]) == PROVIDER, 'component contracts')
    require(all(len(x) == 0 for x in (root[0], app[0], app[1])), 'no intent filter or nested element')


def compiled_manifest(tree):
    """The pinned aapt2 XML dump of the APK's manifest, decoded with its nesting and every
    attribute, against the same contract."""
    root = None
    stack = []
    for index, line in enumerate(tree.splitlines()):
        if index == 0:
            require(line.startswith('N: android=http://schemas.android.com/apk/res/android '), 'manifest namespace')
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
        require(attr is not None and stack and len(attr[1]) == stack[-1][0] + 2, 'compiled attribute grammar')
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
        'compileSdkVersionCodename': '16', 'platformBuildVersionCode': '36', 'platformBuildVersionName': '16'},
        'compiled manifest identity')
    require([x.tag for x in root] == ['uses-sdk', 'application'], 'compiled element inventory')
    require(root[0].attrib == {'minSdkVersion': '37', 'targetSdkVersion': '37'}, 'compiled SDK')
    app = root[1]
    label = app.get('label', '')
    require(re.fullmatch('@0x7f[0-9a-f]{6}', label) and app.attrib == dict(APPLICATION, label=label),
            'compiled application contract')
    require([x.tag for x in app] == ['activity', 'provider'] and not len(app[0]) and not len(app[1]),
            'compiled component inventory')
    theme = app[0].get('theme', '')
    require(re.fullmatch('@0x01[0-9a-f]{6}', theme) and app[0].attrib == dict(ACTIVITY, launchMode='0', theme=theme),
            'compiled activity contract')
    require(app[1].attrib == PROVIDER, 'compiled provider contract')


# ------------------------------------------------------------------ DEX inspection


def dex_tables(data):
    """(class definition descriptors, every string) of one DEX file, after its checksums. A
    definition and string inventory, not an instruction verifier."""
    require(112 <= len(data) <= 4 << 20 and data[:8] == b'dex\n039\0', 'pinned D8 DEX envelope')
    require(hashlib.sha1(data[32:]).digest() == data[12:32]
            and zlib.adler32(data[12:]) == struct.unpack_from('<I', data, 8)[0], 'DEX checksums')

    def word(offset):
        require(0 <= offset <= len(data) - 4, 'DEX word bound')
        return struct.unpack_from('<I', data, offset)[0]

    require(word(32) == len(data) and word(36) == 112 and word(40) == 0x12345678, 'DEX header')
    strings, string_at, types, type_at = (word(i) for i in (56, 60, 64, 68))
    classes, class_at = word(96), word(100)
    require(0 < strings <= 65535 and 0 < types <= 65535 and 0 < classes <= 256
            and 112 <= string_at <= len(data) - 4 * strings and 112 <= type_at <= len(data) - 4 * types
            and 112 <= class_at <= len(data) - 32 * classes, 'DEX table bounds')

    def string(index):
        offset = word(string_at + index * 4)
        units = shift = 0
        for _ in range(5):
            require(offset < len(data), 'DEX string length')
            byte = data[offset]
            offset += 1
            units |= (byte & 127) << shift
            shift += 7
            if byte < 128:
                break
        else:
            raise ValueError('DEX string length bound')
        end = data.find(b'\0', offset, min(len(data), offset + 65536))
        require(end >= offset, 'terminated DEX string')
        return data[offset:end].decode('utf-8', 'surrogateescape')

    all_strings = [string(i) for i in range(strings)]
    names = []
    for index in range(classes):
        type_index = word(class_at + index * 32)
        require(type_index < types, 'DEX class type')
        string_index = word(type_at + type_index * 4)
        require(string_index < strings, 'DEX descriptor index')
        names.append(all_strings[string_index])
    require(len(set(names)) == len(names), 'one definition per class')
    return names, all_strings


def class_contract(data, expected, required, forbidden):
    names, strings = dex_tables(data)
    descriptors = {'L' + PACKAGE.replace('.', '/') + '/' + name + ';' for name in expected}
    require(set(names) == descriptors, 'exact DEX class definition inventory: %s' % sorted(set(names) ^ descriptors))
    text = '\n'.join(strings)
    missing = [name for name in required if name not in strings and name not in text]
    require(not missing, 'DEX lacks required references: %s' % missing)
    present = [name for name in forbidden if name in text]
    require(not present, 'DEX holds forbidden references: %s' % present)
    return sorted(names)


def artifact_contract(verify, badging, tree, signer):
    certs = re.findall(r'^Signer #\d+ certificate SHA-256 digest: ([0-9a-f]+)$', verify, re.M)
    require(certs == [signer] and 'Number of signers: 1' in verify
            and 'Verified using v3 scheme (APK Signature Scheme v3): true' in verify
            and 'Verified using v1 scheme (JAR signing): false' in verify, 'APK signature verification for SDK 37')
    require(len(re.findall(r'^package:', badging, re.M)) == 1
            and "package: name='%s' versionCode='1' versionName='1'" % PACKAGE in badging
            and re.findall(r"^(?:minSdkVersion|sdkVersion):'([0-9]+)'$", badging, re.M) == ['37']
            and re.findall(r"^targetSdkVersion:'([0-9]+)'$", badging, re.M) == ['37']
            and 'application-debuggable' not in badging and not re.search(r'^uses-permission', badging, re.M),
            'APK badging')
    compiled_manifest(tree)


def apk_entries(path):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), 'duplicate APK entry')
        return {i.filename: {'bytes': i.file_size, 'sha256': hashlib.sha256(archive.read(i.filename)).hexdigest()}
                for i in archive.infolist()}


def helper_jar(dex):
    """The helper jar's exact bytes: one stored classes.dex with a fixed time."""
    from io import BytesIO
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        item = zipfile.ZipInfo('classes.dex', date_time=FIXED_TIME)
        item.compress_type = zipfile.ZIP_STORED
        archive.writestr(item, dex)
    return buffer.getvalue()


# ------------------------------------------------------------------ preflight and build


def pins_contract(pins):
    require(type(pins) is dict and set(pins) == {'schema', 'apk', 'helper_jar', 'binder'}
            and pins['schema'] == 'andrix-notice-fixture-pins-v1', 'pins schema')
    require(set(pins['apk']) == {'classes_dex_sha256', 'resources_sha256', 'aligned_unsigned_sha256'}
            and set(pins['helper_jar']) == {'name', 'bytes', 'sha256', 'dex_sha256'}
            and pins['helper_jar']['name'] == HELPER_JAR, 'pins keys')
    for value in [*pins['apk'].values(), pins['helper_jar']['sha256'], pins['helper_jar']['dex_sha256']]:
        require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'pinned digests')
    binder = pins['binder']
    require(set(binder) == {'aidl', 'lines', 'lines_sha256', 'method', 'parameters', 'returns'}
            and binder['method'] == 'startActivityAndWait', 'pinned Binder signature')
    return pins


def preflight(android_root, source, key, cert, signer, output):
    # Deliberately first: before mkdir, logs, temporary files or any tool invocation.
    require(type(signer) is str and re.fullmatch('[0-9a-f]{64}', signer), 'explicit signer certificate SHA-256')
    der = certificate_der(cert)
    require(hashlib.sha256(der).hexdigest() == signer, 'the certificate is not the named signer')
    require(key.is_absolute() and cert.is_absolute(), 'absolute custody arguments required')
    for path in (source, android_root, output.parent):
        require(path.is_absolute() and path.resolve() == path and path.is_dir() and not path.is_symlink(),
                'canonical existing input or output parent required')
    require(not output.exists() and not output.is_symlink(), 'output must be absent')
    require(source not in output.parents and android_root not in output.parents and output != source,
            'output must be outside source and toolchain')
    require(key.is_file() and not key.is_symlink(), 'regular private key argument required')
    tools = strict_json(bounded_file(source / 'tools.json'))
    require(type(tools) is dict and set(tools) == TOOLS, 'closed tool manifest')
    require(all(type(h) is str and re.fullmatch('[0-9a-f]{64}', h) and digest(android_root / p) == h
                for p, h in tools.items()), 'pinned tool digest mismatch')
    references = strict_json(bounded_file(source / 'framework-api.json'))
    require(type(references) is dict and references and all(
        type(h) is str and re.fullmatch('[0-9a-f]{64}', h) and p.startswith('frameworks/base/')
        and digest(android_root / p) == h for p, h in references.items()), 'pinned framework source mismatch')
    pins = pins_contract(strict_json(bounded_file(source / 'pins.json')))
    binder = pins['binder']
    require(binder['aidl'] in references, 'the pinned Binder interface source is a pinned reference')
    lines = (android_root / binder['aidl']).read_bytes().split(b'\n')
    first, last = binder['lines']
    require(hashlib.sha256(b'\n'.join(lines[first - 1:last]) + b'\n').hexdigest() == binder['lines_sha256'],
            'the pinned Binder signature lines changed')
    manifest_contract(bounded_file(source / 'AndroidManifest.xml'))
    found = sorted(p.relative_to(source).as_posix() for p in source.rglob('*')
                   if p.is_file() and p.relative_to(source).parts[0] in ('src', 'present-src', 'res'))
    require(found == sorted([*RESOURCES, *('src/dev/andrix/lab/notice/' + n for n in APP_SOURCES),
                             HELPER_SOURCES[0]]), 'closed source set')
    inputs = [source / name for name in SOURCE_FILES]
    require(all(not p.is_symlink() and p.is_file() and p.resolve() == p for p in inputs),
            'regular source inputs without symlink parents')
    return der, tools, references, pins, {p.relative_to(source).as_posix(): digest(p) for p in inputs}


def build(android_root, source, key, cert, signer, output, source_revision=None):
    der, tools, references, pins, inputs = preflight(android_root, source, key, cert, signer, output)
    require(type(source_revision) is str and re.fullmatch('[0-9a-f]{40}', source_revision),
            'explicit full source revision claim required')
    deadline = time.monotonic() + 300
    os.umask(0o077)
    output.mkdir(mode=0o700)
    for name in ('work', 'home', 'tmp', 'logs'):
        (output / name).mkdir(mode=0o700)
    work = output / 'work'
    for name in ('gen', 'classes', 'dex', 'helper-classes', 'helper-dex'):
        (work / name).mkdir()
    env = {'PATH': str(android_root / JDK) + ':/usr/bin:/bin', 'JAVA_HOME': str((android_root / JDK).parent),
           'HOME': str(output / 'home'), 'TMPDIR': str(output / 'tmp'), 'LANG': 'C.UTF-8',
           'PYTHONDONTWRITEBYTECODE': '1'}
    steps = []
    vm = [*VM, '-Djava.io.tmpdir=' + str(output / 'tmp'), '-Duser.home=' + str(output / 'home')]

    def save(name, value):
        (output / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

    def display(arg):
        arg = str(arg)
        for flag, replacement in (('--key=', '<private-key>'), ('--cert=', '<certificate>')):
            if arg.startswith(flag):
                return flag + replacement
        for flag, label in (('java.io.tmpdir', 'tmp'), ('user.home', 'home')):
            for prefix in ('-D', '-J-D'):
                if arg.startswith(prefix + flag + '='):
                    return prefix + flag + '=<output>/' + label
        if arg == str(key):
            return '<private-key>'
        if arg == str(cert):
            return '<certificate>'
        for path, label in ((output, '<output>'), (source, '<source>'), (android_root, '<android>')):
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
        stem = 'logs/%02d-%s' % (index, label)
        started = time.monotonic_ns()
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'producer total deadline')
        with (output / (stem + '.stdout')).open('xb') as out, (output / (stem + '.stderr')).open('xb') as err:
            try:
                result = subprocess.run(list(map(str, args)), cwd=output, env=env, stdout=out, stderr=err,
                                        timeout=min(90, remaining), preexec_fn=limits)
                code = result.returncode
            except subprocess.TimeoutExpired:
                code = 'timeout'
        record = {'step': index, 'label': label, 'argv': list(map(display, args)), 'exit_code': code,
                  'duration_ms': (time.monotonic_ns() - started) // 1000000}
        for suffix in ('stdout', 'stderr'):
            path = output / (stem + '.' + suffix)
            require(path.stat().st_size <= 4 << 20, 'tool output bound')
            record[suffix + '_sha256'] = digest(path)
        steps.append(record)
        save('steps.json', steps)
        require(code == 0, 'tool step failed: ' + label)
        return (output / (stem + '.stdout')).read_text(encoding='utf-8')

    def jrun(heap):
        return [android_root / (JDK + 'java'), '-Xmx' + heap, *vm]

    def javac(destination, sources):
        return [android_root / (JDK + 'javac'), '-J-Xmx384m', *['-J' + x for x in vm], *JAVAC, '-cp',
                android_root / SDK, '-d', destination, *sources]

    python_digest = digest(sys.executable)
    producer_digest = digest(Path(__file__))
    save('tools.json', tools)
    save('framework-api.json', references)
    save('inputs.json', inputs)
    save('host-tool.json', {'python_sha256': python_digest, 'python_version': sys.version,
                            'executed_producer_sha256': producer_digest})
    save('invocation.json', {'argv': ['<producer>', *[display(x) for x in sys.argv[1:]]]})
    (output / 'certificate.der').write_bytes(der)
    save('admission.json', {'source_revision_claim': source_revision,
                            'source_identity': 'exact file hashes in inputs.json; the revision is caller supplied',
                            'signer_sha256': signer, 'compile_sdk': 36, 'dex_min_api': 36, 'min_sdk': 37,
                            'target_sdk': 37, 'version_code': 1, 'per_command_wall_seconds': 90,
                            'producer_wall_seconds': 300, 'child_address_space_bytes': 2 << 30, 'nice': 19,
                            'no_guest_action': True})
    observed = {}
    try:
        run('javac-version', [android_root / (JDK + 'javac'), *['-J' + x for x in vm], '--version'])
        run('java-version', [*jrun('128m'), '--version'])
        run('jar-version', [android_root / (JDK + 'jar'), *['-J' + x for x in vm], '--version'])
        run('aapt-version', [android_root / AAPT, 'version'])
        run('d8-version', [*jrun('256m'), '-cp', android_root / D8, 'com.android.tools.r8.D8', '--version'])
        run('apksigner-version', [*jrun('128m'), '-jar', android_root / APKSIGNER, 'version'])
        run('resources', [android_root / AAPT, 'compile', '--dir', source / 'res', '-o', work / 'res.zip'])
        run('link', [android_root / AAPT, 'link', '-I', android_root / SDK, '--manifest',
                     source / 'AndroidManifest.xml', '--min-sdk-version', '37', '--target-sdk-version', '37',
                     '--java', work / 'gen', '-o', work / 'resources.apk', work / 'res.zip'])
        generated = sorted(p.relative_to(work / 'gen').as_posix() for p in (work / 'gen').rglob('*') if p.is_file())
        require(generated == ['dev/andrix/lab/notice/R.java'], 'one generated R class')
        run('compile', javac(work / 'classes', [*(source / 'src/dev/andrix/lab/notice' / n for n in APP_SOURCES),
                                                work / 'gen/dev/andrix/lab/notice/R.java']))
        run('classes', [android_root / (JDK + 'jar'), *['-J' + x for x in vm], '--create', '--file',
                        work / 'classes.jar', '-C', work / 'classes', '.'])
        run('dex', [*jrun('512m'), '-cp', android_root / D8, 'com.android.tools.r8.D8', '--release', '--min-api', '36',
                    '--lib', android_root / SDK, '--output', work / 'dex', work / 'classes.jar'])
        require(sorted(p.name for p in (work / 'dex').iterdir()) == ['classes.dex'], 'one DEX')
        dex = (work / 'dex/classes.dex').read_bytes()
        classes = class_contract(dex, DEX_CLASSES, APP_REQUIRED, APP_FORBIDDEN)
        with zipfile.ZipFile(work / 'resources.apk') as src, zipfile.ZipFile(work / 'raw.apk', 'x') as dst:
            require(sorted(src.namelist()) == ['AndroidManifest.xml', 'res/layout/notice.xml', 'resources.arsc'],
                    'exact linked resource inventory')
            for info in src.infolist():
                dst.writestr(info, src.read(info.filename))
            info = zipfile.ZipInfo('classes.dex', date_time=FIXED_TIME)
            info.compress_type = zipfile.ZIP_STORED
            dst.writestr(info, dex)
        run('align', [android_root / ALIGN, '-p', '4', work / 'raw.apk', work / 'aligned.apk'])
        observed = {'classes_dex_sha256': hashlib.sha256(dex).hexdigest(),
                    'resources_sha256': digest(work / 'resources.apk'),
                    'aligned_unsigned_sha256': digest(work / 'aligned.apk')}
        save('unsigned.json', dict(observed, raw_sha256=digest(work / 'raw.apk')))
        apk = output / APK
        run('sign', [*jrun('256m'), '-jar', android_root / APKSIGNER, 'sign', '--key', key,
                     '--cert', output / 'certificate.der', '--min-sdk-version', '37',
                     '--v1-signing-enabled', 'false', '--v2-signing-enabled', 'true',
                     '--v3-signing-enabled', 'true', '--v4-signing-enabled', 'false', '--out', apk,
                     work / 'aligned.apk'])
        run('verify-alignment', [android_root / ALIGN, '-c', '-p', '4', apk])
        verify = run('verify', [*jrun('256m'), '-jar', android_root / APKSIGNER, 'verify', '--verbose',
                                '--print-certs', '--min-sdk-version', '37', '--max-sdk-version', '37', apk])
        badging = run('badging', [android_root / AAPT, 'dump', 'badging', apk])
        tree = run('xmltree', [android_root / AAPT, 'dump', 'xmltree', '--file', 'AndroidManifest.xml', apk])
        artifact_contract(verify, badging, tree, signer)
        inventory = apk_entries(apk)
        require(sorted(inventory) == ['AndroidManifest.xml', 'META-INF/MANIFEST.MF', 'classes.dex',
                                      'res/layout/notice.xml', 'resources.arsc']
                or sorted(inventory) == ['AndroidManifest.xml', 'classes.dex', 'res/layout/notice.xml',
                                         'resources.arsc'], 'signed APK entry inventory')
        require(inventory['classes.dex']['sha256'] == observed['classes_dex_sha256'], 'signed DEX inventory')
        run('compile-helper', javac(work / 'helper-classes', [source / name for name in HELPER_SOURCES]))
        run('classes-helper', [android_root / (JDK + 'jar'), *['-J' + x for x in vm], '--create', '--file',
                               work / 'helper-classes.jar', '-C', work / 'helper-classes', '.'])
        run('dex-helper', [*jrun('256m'), '-cp', android_root / D8, 'com.android.tools.r8.D8', '--release',
                           '--min-api', '36', '--lib', android_root / SDK, '--output', work / 'helper-dex',
                           work / 'helper-classes.jar'])
        require(sorted(p.name for p in (work / 'helper-dex').iterdir()) == ['classes.dex'], 'one helper DEX')
        helper_dex = (work / 'helper-dex/classes.dex').read_bytes()
        helper_classes = class_contract(helper_dex, HELPER_CLASSES, HELPER_REQUIRED, FORBIDDEN)
        jar = helper_jar(helper_dex)
        (output / HELPER_JAR).write_bytes(jar)
        helper = {'name': HELPER_JAR, 'bytes': len(jar), 'sha256': hashlib.sha256(jar).hexdigest(),
                  'dex_sha256': hashlib.sha256(helper_dex).hexdigest()}
        save('reproduced.json', {'apk': observed, 'helper_jar': helper})
        require(observed == pins['apk'], 'the unsigned APK outputs differ from pins.json')
        require(helper == pins['helper_jar'], 'the helper jar differs from pins.json')
        require(all(digest(source / p) == h for p, h in inputs.items())
                and all(digest(android_root / p) == h for p, h in references.items())
                and all(digest(android_root / p) == h for p, h in tools.items())
                and digest(sys.executable) == python_digest and digest(Path(__file__)) == producer_digest,
                'inputs drifted')
        save('artifact.json', {'file': APK, 'sha256': digest(apk), 'bytes': apk.stat().st_size,
                               'certificate_sha256': signer, 'zip_inventory': inventory,
                               'dex_class_definitions': classes, 'unsigned': observed,
                               'helper': dict(helper, dex_class_definitions=helper_classes, required_uid=2000,
                                              role='shell presentation helper, not an APK or observer'),
                               'runtime_qualified': False})
        save('closure.json', {'build_complete': True, 'tools_unchanged': True, 'inputs_unchanged': True,
                              'Android_runtime_qualified': False, 'image_build_performed': False})
    except Exception:
        save('closure.json', {'build_complete': False, 'Android_runtime_qualified': False,
                              'partial_output_retained': True})
        raise


def check_output(output, source=HERE):
    """Repeats the artifact checks on a finished output directory, without running a tool: the
    recorded closure, the file digests, the signer, the recorded verify, badging and manifest
    dumps, the APK's and the helper jar's DEX inventories and references, and the pins."""
    output = Path(output)
    closure = strict_json((output / 'closure.json').read_bytes())
    require(closure.get('build_complete') is True, 'a completed build')
    artifact = strict_json((output / 'artifact.json').read_bytes())
    pins = pins_contract(strict_json(bounded_file(source / 'pins.json')))
    apk = output / APK
    require(digest(apk) == artifact['sha256'] and apk.stat().st_size == artifact['bytes'], 'APK digest')
    signer = hashlib.sha256((output / 'certificate.der').read_bytes()).hexdigest()
    require(signer == artifact['certificate_sha256'], 'certificate')
    steps = {s['label']: s for s in strict_json((output / 'steps.json').read_bytes())}
    logs = {}
    for label in ('verify', 'badging', 'xmltree'):
        step = steps[label]
        path = output / ('logs/%02d-%s.stdout' % (step['step'], label))
        require(digest(path) == step['stdout_sha256'] and step['exit_code'] == 0, 'recorded %s output' % label)
        logs[label] = path.read_text(encoding='utf-8')
    artifact_contract(logs['verify'], logs['badging'], logs['xmltree'], signer)
    inventory = apk_entries(apk)
    require(inventory == artifact['zip_inventory'], 'APK entry inventory')
    with zipfile.ZipFile(apk) as archive:
        dex = archive.read('classes.dex')
    require(hashlib.sha256(dex).hexdigest() == pins['apk']['classes_dex_sha256'], 'APK DEX pin')
    class_contract(dex, DEX_CLASSES, APP_REQUIRED, APP_FORBIDDEN)
    jar = (output / HELPER_JAR).read_bytes()
    with zipfile.ZipFile(output / HELPER_JAR) as archive:
        require(archive.namelist() == ['classes.dex'], 'helper jar inventory')
        helper_dex = archive.read('classes.dex')
    require(jar == helper_jar(helper_dex), 'helper jar layout')
    require({'name': HELPER_JAR, 'bytes': len(jar), 'sha256': hashlib.sha256(jar).hexdigest(),
             'dex_sha256': hashlib.sha256(helper_dex).hexdigest()} == pins['helper_jar'], 'helper jar pin')
    class_contract(helper_dex, HELPER_CLASSES, HELPER_REQUIRED, FORBIDDEN)
    return {'apk_sha256': artifact['sha256'], 'certificate_sha256': signer,
            'helper_jar_sha256': pins['helper_jar']['sha256']}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--android-root', type=Path)
    parser.add_argument('--source', type=Path, default=HERE)
    parser.add_argument('--source-revision')
    parser.add_argument('--key', type=Path)
    parser.add_argument('--cert', type=Path)
    parser.add_argument('--signer-sha256')
    parser.add_argument('--out', type=Path)
    parser.add_argument('--check-output', type=Path)
    args = parser.parse_args()
    try:
        if args.check_output is not None:
            print(json.dumps(check_output(args.check_output, args.source), sort_keys=True))
            return 0
        require(None not in (args.android_root, args.key, args.cert, args.out), 'build arguments')
        build(args.android_root, args.source, args.key, args.cert, args.signer_sha256, args.out, args.source_revision)
    except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError, ET.ParseError,
            zipfile.BadZipFile) as error:
        # An OS error's message may hold custody paths, so only the producer's own refusals, which
        # are fixed text, are printed. Logs hold only redacted argv.
        own = type(error) is ValueError
        print('notice fixture producer refused or failed: ' + type(error).__name__
              + (': ' + str(error) if own else ''), file=sys.stderr)
        return 2
    print('Notice fixture APK and shell helper jar built and checked; Android runtime unqualified.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
