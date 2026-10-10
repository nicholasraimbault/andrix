#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Guarded host qualification of the optional lab preparation for V2 header only recovery.

Read only source checks run first. No compiler or JVM starts, and nothing is created, unless an
actual cgroup bounds this process to 2 GiB of memory, no swap, 2 CPUs and 256 tasks, with core
dumps disabled, and a JDK is on PATH. Otherwise the run reports NOT_RUN and exits 2. A guarded
run creates files only under the fresh --work directory, including its progress.json checkpoint,
and the fresh --evidence file. Every compiler and JVM it starts runs with its working directory
inside --work, a heap of at most 256 MiB, no HotSpot performance data, its temporary directory below --work,
fatal error and compiler replay logs in <work>/jvm and no core requested. The subprocess suites it
starts receive the same JVM options through JAVA_TOOL_OPTIONS, TMPDIR below --work and a working
directory inside --work. A JDK that does not support these options stops the run. Diagnostics are
never silenced.

One report is shared by every phase. Each phase's record is installed in it before the phase
works, and every finished step is checkpointed at once, so a compiler log survives a later
timeout. An exception keeps every finished record and problem, the stopped command's streams and
the unfinished phases, and the run is NOT_COMPLETE. Nothing is retried.

This qualifies host tools, guards and a host facade rehearsal only. It is not Android, SELinux,
crash, storage, activation or V2 publication evidence, and it admits no Android build. The lab
format token it once checked is retired: the normal image now constructs Format.V2 itself, and
the production format guard of the B1 runner checks that construction.
"""
from pathlib import Path
import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import android_lifecycle  # noqa: E402
import native_creation_binding as b1  # noqa: E402

LAB_DIR = ROOT / 'tests/native-identity/lab-history'
NATIVE_IDENTITY = ROOT / 'tests/native-identity'
PLATFORM = ROOT / 'owner/tests/platform'
FRAMEWORK = ROOT / 'owner/platform/framework'
PREDICTIONS = ROOT / 'scripts/proof/native_lab_history_predictions.json'
PHASES = ('jdk', 'store fixture', 'guest inputs', 'rehearsal', 'writer regression', 'pure suites')
FAULTS = ('error', 'exception', 'observation')
GENERATOR = 'dev.andrix.proof.nativelab.LabHistoryStore'
# The guest generator's codec: the record codec of the lifecycle record at the revision of B1's host
# packages, read from its Git object and pinned by SHA-256, so the guest layouts are what B1's own
# codec encodes. The guest layouts are generated at these fixed values.
GUEST_REVISION = 'e6f8b681021b5c36256a50337803ef8ec4268ab1'
GUEST_CODEC = ('owner/platform/framework/NativeIdentityRecords.java',
               '4be9c8a0135d3793bb4153e9dc794c2afbf6e4bdbc3466d447b883fe30e0b032')
GUEST_VALUES = ('00112233445566778899aabbccddeeff', 10148, 10149, 7)
OTHER = 'dev.andrix.proof.lifecycleother'
# The one reviewed host facade overlap, as in the B1 runner: the XML stub's Log replaces the
# native principal stub's. Any other overlap refuses rather than silently replacing a stub.
STUB_OVERLAPS = frozenset({'android/util/Log.java'})
# The host facade's synthetic test certificate, the bytes 1, 2 and 3 that the existing fixture
# tests install. Its digest is computed here, independently of any transcript. It is no Android
# signer: the lab command line predicts only the development signer of the pinned writer fixture.
HOST_SIGNER = hashlib.sha256(bytes([1, 2, 3])).hexdigest()
# The writer route and observer. The fixture, its profile, its patch and the observer are byte
# identical to the lab producer's. The writer tool changed when the lab format token was retired:
# its lab admission, at the shared fence and per action, requires the complete stack.
FIXTURE = 'tests/native-identity/writer/NativePrincipalWriterFixture.java'
UNCHANGED = {
    'tests/native-identity/writer/NativePrincipalWriterFixture.java':
        '7628d42b1535aac7ea971eb1161fd22e403518f889fe619ad6170d5d5fde8a21',
    'patches/grapheneos-2026081300/native-identity-writer.json':
        '1591b623b8b276d0835da91c4e7358c1b13ae10cfd80b8a5bcf4b8622fb119e3',
    'patches/grapheneos-2026081300/native-identity-writer.patch':
        '2ede775d3e67610457b294870854310d38d97ff873bec2f70fe08646253a328b',
    'scripts/proof/native_identity_writer.py':
        'fc12beb83e0f4706af87f7ec9cfb893e3fe61f90d05d24f97b29189337054032',
    'tests/native-identity/writer_observe.py': 'd9663ba6a880f970c8914a035989e3159cc0ab7ce10e54904ab073cc4f2115e1'}
# Host facade and fixture calls that would inject state instead of observing the actual writer.
INJECTIONS = ('restoreBindingsWithoutCounter', '.restore(', 'rememberNative', 'mNativeRememberedBindings',
              'reservePending', 'writeHeader', 'initializeNew', 'publishCreatingSlot', 'Retirement',
              'markRetiring', 'Issuance', 'NativeHistoryHarness', 'registerExistingAppId', 'storeHolds',
              'new NativeIdentityStore(', 'new NativeIdentityPersistence(', 'Files.write(', 'Files.writeString(',
              'new NativePrincipalPins(', 'mNativeIdentityLoaded =')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError('non-finite value')


def strict(text):
    return json.loads(text, object_pairs_hook=unique, parse_constant=invalid_constant)


def subject_constants(text):
    """The fixed subject, development signer, version and user the writer fixture selects."""
    found = {'package': re.findall(r'^    private static final String SUBJECT = "([^"\n]*)";$', text, re.M),
             'signer_sha256': re.findall(r'^    private static final String FIXTURE_SIGNER =\n'
                                         r'            "([0-9a-f]{64})";$', text, re.M),
             'version_code': re.findall(r'\bchosen\.versionCode != ([0-9]+)\b', text),
             'user_id': re.findall(r'\bchosen\.userId != ([0-9]+)\b', text)}
    if any(len(values) != 1 for values in found.values()) or text.count('Set.of(FIXTURE_SIGNER)') != 1:
        raise ValueError('writer fixture subject constants are not exact')
    return {'package': found['package'][0], 'signer_sha256': found['signer_sha256'][0],
            'version_code': int(found['version_code'][0]), 'user_id': int(found['user_id'][0])}


def fixture_subject():
    """The subject constants parsed from the pinned writer fixture, never another copy."""
    data = (ROOT / FIXTURE).read_bytes()
    if sha(data) != UNCHANGED[FIXTURE]:
        raise ValueError('writer fixture differs from its pin')
    return subject_constants(data.decode())


def observer():
    spec = importlib.util.spec_from_file_location('lab_history_observe_runner', NATIVE_IDENTITY / 'lab_history_observe.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ------------------------------------------------------------ independent wire oracle, tests only

def _record(kind, version, body):
    raw = bytearray(struct.pack('<IHHI', 0x44495841, kind, version, 0) + body)
    raw[8:12] = struct.pack('<I', len(raw) + 32)
    return bytes(raw) + hashlib.sha256(bytes(raw)).digest()


def _ascii(value):
    return struct.pack('<H', len(value)) + value.encode('ascii')


def goldens(lineage='00112233445566778899aabbccddeeff', app_id=10148, serial=7,
            signer='874cedf46661e33d62b711b266c96e629d1f64007e55350a59a167c9c23183d3',
            subject='dev.andrix.proof.principalclosed'):
    """The four lab records from the documented layout alone. A test oracle for the actual codec,
    evaluated at the fixed golden values and at the values of each actual run. It never produces
    lab input or predictions; only the actual codec does."""
    signers = struct.pack('<H', 1) + bytes.fromhex(signer)
    head = bytes.fromhex(lineage)
    return {
        'EMPTY': _record(1, 1, head + struct.pack('<qH', 0, 0)),
        'CREATING': _record(1, 2, head + struct.pack('<qH', 1, 1) + struct.pack('<iBq', app_id, 1, 1)
                            + _ascii(subject) + b'\x01' + struct.pack('<iq', 0, serial) + signers),
        'LIVE': _record(1, 2, head + struct.pack('<qH', 1, 1) + struct.pack('<iBq', app_id, 2, 0) + _ascii('')),
        'BODY': _record(2, 1, head + struct.pack('<iq', app_id, 1) + _ascii(subject) + signers
                        + struct.pack('<H', 1) + struct.pack('<qiqB', 1, 0, serial, 0))}


def lifecycle_goldens(mode, lineage='00112233445566778899aabbccddeeff', app_id=10148, other_app_id=10149, serial=7,
                      signer='874cedf46661e33d62b711b266c96e629d1f64007e55350a59a167c9c23183d3',
                      subject='dev.andrix.proof.principalclosed', other=OTHER):
    """The files of one lifecycle guest layout, by path relative to the store, from the documented
    layouts alone: the plan's version 2 slot with one ELIGIBLE user suspended by that user for
    USER_PAUSED, code 1, at the fixed time, and the version 1 body and headers as above. A test oracle
    for the actual codec only; it never produces lab input."""
    signers = struct.pack('<H', 1) + bytes.fromhex(signer)
    head = bytes.fromhex(lineage)

    def version_1_body(app, package, principal, retiring):
        return _record(2, 1, head + struct.pack('<iq', app, 1) + _ascii(package) + signers + struct.pack('<H', 1)
                       + struct.pack('<qiqB', principal, 0, serial, 1 if retiring else 0))

    def suspended(app, package, principal):
        entry = struct.pack('<BBiq', 1, 0, 0, serial) + bytes(16) + struct.pack('<Hq', 1, 1_700_000_000_000) + b'\x00'
        return _record(2, 2, head + struct.pack('<iq', app, 2) + _ascii(package) + signers + struct.pack('<H', 1)
                       + struct.pack('<qiq', principal, 0, serial) + struct.pack('<BB', 1, 1) + entry)

    def header(version, last, entries):
        body = head + struct.pack('<qH', last, len(entries))
        for app, phase, creation, package, bound in sorted(entries):
            body += struct.pack('<iBq', app, phase, creation) + _ascii(package)
            if version == 2 and phase == 1:
                body += (b'\x01' + struct.pack('<iq', 0, serial) + signers) if bound else b'\x00'
        return _record(1, version, body)

    live = (app_id, 2, 0, '', False)
    if mode == 'retiring-v1':
        store, slots = header(1, 1, [live]), {app_id: version_1_body(app_id, subject, 1, True)}
    elif mode == 'v2-slot':
        store, slots = header(1, 1, [live]), {app_id: suspended(app_id, subject, 1)}
    elif mode == 'v2-beside-reservation':
        store = header(2, 2, [(app_id, 1, 1, subject, True), (other_app_id, 2, 0, '', False)])
        slots = {other_app_id: suspended(other_app_id, other, 2)}
    elif mode == 'v2-beside-sibling':
        store = header(1, 2, [live, (other_app_id, 2, 0, '', False)])
        slots = {app_id: version_1_body(app_id, subject, 1, False), other_app_id: suspended(other_app_id, subject, 2)}
    else:
        raise ValueError('lifecycle guest mode')
    files = {'store.bin': store, 'store.bin.reservecopy': store}
    for app, data in slots.items():
        files['slots/%d/record.bin' % app] = data
        files['slots/%d/record.bin.reservecopy' % app] = data
    return files


def oracle_problems(files, gold, where):
    """Actual bytes that differ from the oracle, by relative name."""
    return ['%s differs from the independent layout oracle at %s' % (name, where)
            for name, record in files.items() if name.read_bytes() != gold[record]]


def java_constant(text, name):
    found = re.findall(r'private static final (?:String|int) %s = "?([0-9a-f]+)"?;' % name, text)
    if len(found) != 1:
        raise ValueError('Java constant ' + name)
    return found[0]


# ------------------------------------------------------------ read only source checks

def labels_in(text):
    labels = re.findall(r'\b(?:reply|lost)\("([a-z-]+)"', text)
    labels += ['%s-%s' % (kind, step) for kind in FAULTS for step in ('info', 'select', 'prepare', 'commit', 'status')]
    return labels


def rehearsal_problems(text):
    """The rehearsal observes the actual writer. It injects no pin, history, issuance, hold or
    store bytes, and constructs exactly the production format of the boot read, Format.V2, only
    for its own facade boots."""
    code = b1.strip_java_comments(text)
    problems = ['rehearsal injects state: ' + item for item in INJECTIONS if item in code]
    if (code.count(b1.PRODUCTION) != 2 or 'Format.V1' in code
            or b1.boot_literal() != b1.PRODUCTION):
        problems.append('rehearsal format selection')
    return problems


def subject_problems(subject, store, observe):
    """The generator's subject, signer and user and the observer's subject and fixed signer, each
    against the values parsed from the pinned writer fixture."""
    if (re.findall(r'public static final String SUBJECT = "([^"]+)";', store) != [subject['package']]
            or re.findall(r'public static final String FIXTURE_SIGNER =\n\s+"([0-9a-f]{64})";', store)
            != [subject['signer_sha256']]
            or re.findall(r'public static final int USER = ([0-9]+);', store) != [str(subject['user_id'])]
            or observe.FIXTURE_SIGNER != subject['signer_sha256'] or observe.SUBJECT != subject['package']):
        return ['generator or observer subject differs from the writer fixture']
    return []


def source_checks():
    """Pure and read only: nothing is created, and no compiler or JVM starts."""
    problems = []
    for name, digest in UNCHANGED.items():
        if sha((ROOT / name).read_bytes()) != digest:
            problems.append('changed existing input: ' + name)
    try:
        subject = fixture_subject()
    except ValueError as error:
        return problems + ['writer fixture subject: %s' % error]
    problems += ['production format guard: ' + item for item in b1.format_violations(b1.production_texts())]
    store = (LAB_DIR / 'LabHistoryStore.java').read_text()
    code = b1.strip_java_comments(store)
    problems += subject_problems(subject, store, observer())
    for forbidden in ('NativeIdentityStore', 'NativeIdentityPersistence', 'NativePrincipalManager', 'PackageSetting',
                      'initializeNew', 'java.lang.reflect', 'System.getProperty', 'System.getenv'):
        if forbidden in code:
            problems.append('generator reaches beyond the codec: ' + forbidden)
    test = (LAB_DIR / 'LabHistoryStoreTest.java').read_text()
    for name, data in goldens().items():
        if (java_constant(test, name + '_SHA256') != sha(data)
                or int(java_constant(test, name + '_BYTES')) != len(data)):
            problems.append('Java golden differs from the documented layout: ' + name)
    rehearsal = (LAB_DIR / 'NativeWriterLabRehearsal.java').read_text()
    problems += rehearsal_problems(rehearsal)
    predictions = strict(PREDICTIONS.read_text())
    if (predictions['rehearsal']['facade_signer_sha256'] != HOST_SIGNER
            or HOST_SIGNER == subject['signer_sha256']):
        problems.append('the host test signer is not distinct from the fixture signer')
    labels = labels_in(b1.strip_java_comments(rehearsal))
    if (len(labels) != len(set(labels)) or set(labels) != set(predictions['rehearsal']['labels'])
            or predictions['status'] != 'PREDICTIONS_NOT_RESULTS'):
        problems.append('rehearsal labels differ from the predictions')
    for label, want in predictions['rehearsal']['labels'].items():
        partner = want.get('retained_by')
        if partner is not None and predictions['rehearsal']['labels'].get(partner, {}).get('kind') not in (
                'false-commit', 'unknown'):
            problems.append('retention partner of %s is no status observation' % label)
    for name in predictions['pure_suites']:
        if not (ROOT / name).is_file():
            problems.append('missing pure suite: ' + name)
    return problems


# ------------------------------------------------------------ JVM phases, guarded

def run(args, timeout, cwd=None, env=None):
    result = subprocess.run([str(item) for item in args], capture_output=True, text=True, timeout=timeout,
                            cwd=cwd, env=env)
    return {'args': [str(item) for item in args], 'returncode': result.returncode,
            'stdout': result.stdout, 'stderr': result.stderr}


def stubs(*bases):
    """Host facade sources of these bases in order, and the reviewed overlaps they used. A later
    base replaces an earlier stub only for a reviewed overlap; any other overlap refuses."""
    found, overlaps = {}, []
    for base in bases:
        for source in sorted(base.rglob('*.java')):
            if source.name == 'Xml.java':
                continue
            relative = source.relative_to(base).as_posix()
            if relative in found:
                if relative not in STUB_OVERLAPS:
                    raise ValueError('unreviewed host facade overlap: ' + relative)
                overlaps.append(relative)
            found[relative] = source
    return list(found.values()), overlaps


def jvm_options(work):
    """Bounded JVM options: fatal error and compiler replay logs in <work>/jvm, not an inherited
    working directory or /tmp, and no core requested. Diagnostics still print."""
    diagnostics = work / 'jvm'
    return ['-Xmx256m', '-XX:-UsePerfData', '-XX:ErrorFile=%s/hs_err_%%p.log' % diagnostics,
            '-XX:ReplayDataFile=%s/replay_%%p.log' % diagnostics, '-XX:-CreateCoredumpOnCrash',
            '-Djava.io.tmpdir=' + str(work / 'tmp')]


def inside(work, cwd):
    """A working directory inside --work: <work>/jvm unless the caller names another there."""
    if cwd is None:
        cwd = work / 'jvm'
        cwd.mkdir(exist_ok=True)
    if cwd != work and work not in cwd.parents:
        raise ValueError('compiler or JVM working directory outside --work')
    return cwd


def javac(work, files, out):
    out.mkdir()
    return run(['javac', *('-J' + option for option in jvm_options(work)), '--release', '17', '-Xlint:all',
                '-Werror', '-d', out, *files], 600, cwd=inside(work, None))


def java(work, main, *args, assertions=True, timeout=600, cwd=None, classes=None):
    return run(['java', *jvm_options(work),
                *(['-ea'] if assertions else []), '-cp', classes, main, *args], timeout, cwd=inside(work, cwd))


def jdk_phase(work, predictions, pinned, record, problems, save):
    """The JDK must accept every bounded option before anything compiles or runs. There is no
    fallback that drops an unsupported option."""
    record['version'] = run(['java', *jvm_options(work), '-version'], 120, cwd=inside(work, None))
    save()
    record['flags'] = run(['java', *jvm_options(work), '-XX:+PrintFlagsFinal', '-version'], 120,
                          cwd=inside(work, None))
    save()
    def bounded(result):
        flags = {}
        for line in result['stdout'].splitlines():
            fields = line.split()
            if len(fields) >= 4 and fields[2] == '=':
                flags[fields[1]] = fields[3]
        return {name: flags.get(name) for name in wanted}
    wanted = {'ErrorFile': str(work / 'jvm/hs_err_%p.log'), 'ReplayDataFile': str(work / 'jvm/replay_%p.log'),
              'CreateCoredumpOnCrash': 'false', 'UsePerfData': 'false', 'MaxHeapSize': str(256 << 20)}
    record['bounded'] = bounded(record['flags'])
    save()
    if (record['version']['returncode'] or record['flags']['returncode'] or record['bounded'] != wanted):
        raise ValueError('the JDK does not apply the bounded JVM options: %s' % record['bounded'])
    record['javac_flags'] = run(['javac', *('-J' + option for option in jvm_options(work)),
                                  '-J-XX:+PrintFlagsFinal', '-version'], 120, cwd=inside(work, None))
    record['javac_bounded'] = bounded(record['javac_flags'])
    save()
    if record['javac_flags']['returncode'] or record['javac_bounded'] != wanted:
        raise ValueError('the compiler JVM does not apply the bounded JVM options')
    record['suite_flags'] = run(['java', '-XX:+PrintFlagsFinal', '-XshowSettings:properties', '-version'], 120,
                                cwd=inside(work, None), env=subprocess_env(work))
    record['suite_bounded'] = bounded(record['suite_flags'])
    temporary = re.findall(r'^\s*java\.io\.tmpdir = (.+)$', record['suite_flags']['stderr'], re.M)
    record['suite_tmpdir'] = temporary
    save()
    if (record['suite_flags']['returncode'] or record['suite_bounded'] != wanted
            or temporary != [str(work / 'tmp')]):
        raise ValueError('the suite JVM does not apply the bounded options and temporary directory')


def store_fixture(work, predictions, pinned, record, problems, save):
    sources = work / 'store-sources'
    sources.mkdir()
    shutil.copyfile(PLATFORM / 'ResilientAtomicFile.java.inc', sources / 'ResilientAtomicFile.java')
    classes = work / 'store-classes'
    facades, record['stub_overlaps'] = stubs(PLATFORM / 'native_principal_xml_stubs')
    record['compile'] = javac(work, [FRAMEWORK / 'NativeIdentityRecords.java', FRAMEWORK / 'NativeIdentityStore.java',
                                     sources / 'ResilientAtomicFile.java', *facades, LAB_DIR / 'LabHistoryStore.java',
                                     LAB_DIR / 'LabHistoryStoreTest.java'], classes)
    save()
    if record['compile']['returncode']:
        problems.append('store fixture compilation failed')
        return
    target = work / 'store-fixture'
    target.mkdir()
    record['run'] = java(work, 'com.android.server.pm.LabHistoryStoreTest', target, classes=classes)
    save()
    expected = predictions['store_fixture']
    passes = re.findall(r'^PASS (.+)$', record['run']['stdout'], re.M)
    if (record['run']['returncode'] or passes != expected['pass']
            or record['run']['stdout'].strip().splitlines()[-1:] != [expected['final']]):
        problems.append('store fixture controls did not pass exactly')
    unused = work / 'store-fixture-without-assertions'
    record['without_assertions'] = java(work, 'com.android.server.pm.LabHistoryStoreTest', unused,
                                        assertions=False, classes=classes)
    save()
    if (not record['without_assertions']['returncode'] or '-ea' not in record['without_assertions']['stderr']
            or unused.exists()):
        problems.append('store fixture test ran without Java assertions')
    # The actual command line at a fresh random lineage with the fixed signer, against the oracle.
    observe = observer()
    generated, predicted = work / 'cli-generated', work / 'cli-prediction'
    record['cli_generate'] = java(work, GENERATOR, 'empty-v1', generated, classes=classes, timeout=120)
    save()
    generation = observe.load_generation(record['cli_generate']['stdout'].strip())
    record['cli_predict'] = java(work, GENERATOR, 'predict-v2', predicted, generation['lineage'], '10148', '7', '1',
                                 classes=classes, timeout=120)
    save()
    prediction = observe.load_prediction(predicted)
    gold = goldens(lineage=generation['lineage'], signer=fixture_subject()['signer_sha256'])
    oracle = {generated / 'store.bin': 'EMPTY', generated / 'store.bin.reservecopy': 'EMPTY',
              predicted / 'v2-creating-header.bin': 'CREATING', predicted / 'v2-live-header.bin': 'LIVE',
              predicted / 'v2-slot-body.bin': 'BODY'}
    found = oracle_problems(oracle, gold, 'a fresh command line lineage')
    if (record['cli_generate']['returncode'] or record['cli_predict']['returncode']
            or sorted(os.listdir(generated)) != ['slots', 'store.bin', 'store.bin.reservecopy']
            or os.listdir(generated / 'slots') or prediction['lineage'] != generation['lineage']
            or (prediction['app_id'], prediction['user_serial'], prediction['principal_id']) != (10148, 7, 1)
            or record['cli_predict']['stdout'] != (predicted / 'prediction.json').read_text()):
        found.append('command line output differs from its controlled input and prediction')
    record['oracle'] = found
    problems.extend(found)
    record['cli_refusals'] = []
    cwd = work / 'cli-cwd'
    cwd.mkdir()
    for flag in ('-ea', '-da'):
        for index, arguments in enumerate(expected['cli_refusals']):
            output = work / ('cli-%s-%d' % (flag[1:], index))
            args = [str(output) if item == 'OUTPUT' else item for item in arguments]
            result = run(['java', *jvm_options(work), '-Djava.io.tmpdir=' + str(work / 'tmp'), flag, '-cp',
                          classes, GENERATOR, *args], 120, cwd=inside(work, cwd))
            record['cli_refusals'].append(result)
            save()
            if not result['returncode'] or output.exists() or any(cwd.iterdir()):
                problems.append('generator accepted %s with %s' % (' '.join(arguments), flag))


def guest_inputs(work, predictions, pinned, record, problems, save):
    """The lifecycle guest layouts: the generator compiled with B1's codec from its pinned Git object,
    each mode's store against the independent oracle byte for byte and against the observer's matching
    phase, one changed byte refused by the observer, and the generator's refusals before any file."""
    expected = predictions['guest_inputs']
    path, digest = GUEST_CODEC
    codec = b1.git_bytes(GUEST_REVISION, path)
    record['codec_sha256'] = sha(codec)
    save()
    if record['codec_sha256'] != digest or expected['codec_sha256'] != digest:
        problems.append('guest generator codec differs from its pinned Git object')
        return
    sources = work / 'guest-sources'
    sources.mkdir()
    (sources / 'NativeIdentityRecords.java').write_bytes(codec)
    classes = work / 'guest-classes'
    record['compile'] = javac(work, [sources / 'NativeIdentityRecords.java', LAB_DIR / 'LabHistoryStore.java'], classes)
    save()
    if record['compile']['returncode']:
        problems.append('guest generator compilation failed')
        return
    observe = observer()
    lineage, app_id, other_app_id, serial = GUEST_VALUES
    record['modes'] = {}
    if list(observe.LIFECYCLE_MODES) != list(expected['modes']):
        problems.append('guest modes differ from the predictions')
    for mode in observe.LIFECYCLE_MODES:
        output = work / ('guest-' + mode)
        companion = mode.startswith('v2-beside-')
        result = java(work, GENERATOR, mode, output, lineage, str(app_id), *([str(other_app_id)] if companion else []),
                      str(serial), classes=classes, timeout=120)
        entry = record['modes'][mode] = {'returncode': result['returncode'], 'stdout': result['stdout'][-4000:],
                                         'stderr': result['stderr'][-2000:]}
        save()
        try:
            manifest = observe.load_lifecycle_generation(result['stdout'].strip())
            entry['assessed'] = observe.assess_store(output, mode, generation=manifest)
        except (OSError, ValueError) as error:
            problems.append('guest input %s: %s' % (mode, error))
            continue
        gold = lifecycle_goldens(mode, lineage, app_id, other_app_id, serial)
        entry['oracle'] = sorted(name for name in set(gold) | set(manifest['files'])
                                 if not (output / name).is_file() or (output / name).read_bytes() != gold.get(name))
        save()
        if result['returncode'] or entry['oracle'] or sorted(gold) != expected['modes'][mode]:
            problems.append('guest input %s differs from the independent oracle: %s' % (mode, entry['oracle']))
        # The control: one changed byte in a copy of the store is refused by the observer.
        control = work / ('guest-control-' + mode)
        shutil.copytree(output, control)
        target = control / sorted(gold)[0]
        changed = bytearray(target.read_bytes())
        changed[-1] ^= 1
        target.write_bytes(bytes(changed))
        if not refused(lambda: observe.assess_store(control, mode, generation=manifest)):
            problems.append('guest input %s control was not refused' % mode)
    record['refusals'] = []
    for index, arguments in enumerate(expected['refusals']):
        output = work / ('guest-refused-%d' % index)
        result = java(work, GENERATOR, *[str(output) if item == 'OUTPUT' else item for item in arguments],
                      classes=classes, timeout=120)
        record['refusals'].append(result)
        save()
        if not result['returncode'] or output.exists():
            problems.append('guest generator accepted ' + ' '.join(arguments))


def rehearsal(work, predictions, pinned, record, problems, save):
    sources = work / 'rehearsal-sources'
    sources.mkdir()
    for name in ('AppIdSettingMap', 'ResilientAtomicFile'):
        shutil.copyfile(PLATFORM / (name + '.java.inc'), sources / (name + '.java'))
    classes = work / 'rehearsal-classes'
    facades, record['stub_overlaps'] = stubs(PLATFORM / 'native_principal_stubs', PLATFORM / 'native_principal_xml_stubs',
                                             NATIVE_IDENTITY / 'writer/stubs')
    record['compile'] = javac(work, [
        sources / 'AppIdSettingMap.java', sources / 'ResilientAtomicFile.java', *facades,
        *(FRAMEWORK / (name + '.java') for name in ('NativePrincipalPins', 'NativePrincipalManager',
                                                    'NativeIdentityRecords', 'NativeIdentityStore',
                                                    'NativeIdentityPersistence', 'NativePrincipalRecovery')),
        NATIVE_IDENTITY / 'writer/NativePrincipalWriterFixture.java', LAB_DIR / 'LabHistoryStore.java',
        LAB_DIR / 'NativeWriterLabRehearsal.java'], classes)
    save()
    if record['compile']['returncode']:
        problems.append('rehearsal compilation failed')
        return
    target = work / 'rehearsal'
    target.mkdir()
    record['run'] = java(work, 'com.android.server.pm.NativeWriterLabRehearsal', target, classes=classes)
    save()
    if record['run']['returncode']:
        problems.append('rehearsal exited %d' % record['run']['returncode'])
    unused = work / 'rehearsal-without-assertions'
    record['without_assertions'] = java(work, 'com.android.server.pm.NativeWriterLabRehearsal', unused,
                                        assertions=False, classes=classes)
    save()
    if (not record['without_assertions']['returncode'] or '-ea' not in record['without_assertions']['stderr']
            or unused.exists()):
        problems.append('rehearsal ran without Java assertions')
    found, record['outcomes'] = check_transcript(record['run']['stdout'], target, predictions)
    record['transcript_problems'] = found
    problems.extend(found)
    save()


def parse_transcript(stdout):
    """Events in transcript order: every issued request, with its reply when one was captured."""
    events, context, passes, done, problems, labels = [], {}, [], [], [], set()
    for line in stdout.splitlines():
        fields = line.split('\t')
        if line.startswith('PASS '):
            passes.append(line[5:])
        elif fields[0] in ('REPLY', 'ISSUED') and len(fields) == (8 if fields[0] == 'REPLY' else 5) \
                and (fields[0] == 'ISSUED' or fields[5] in ('0', '1')):
            label = fields[1]
            if label in labels:
                problems.append('replayed operation label ' + label)
                continue
            labels.add(label)
            event = {'operation': fields[2], 'instance': fields[3], 'nonce': fields[4], 'reply': fields[0] == 'REPLY'}
            if event['reply']:
                try:
                    event.update(returncode=int(fields[5]),
                                 stdout=base64.b64decode(fields[6], validate=True).decode(),
                                 stderr=base64.b64decode(fields[7], validate=True).decode())
                except ValueError as error:
                    problems.append('undecodable reply %s: %s' % (label, error))
                    continue
            events.append((label, event))
        elif fields[0] == 'CONTEXT' and len(fields) == 3 and fields[1] not in context:
            context[fields[1]] = fields[2]
        elif fields[0] == 'DONE' and len(fields) == 2:
            done.append(fields[1])
        else:
            problems.append('unexpected transcript line: ' + line[:160])
    return events, context, passes, done, problems


def refused(call):
    try:
        call()
    except ValueError:
        return True
    return False


def original_request(value, nonce, subject):
    """A reply that still carries the original select-new request after its one commit attempt."""
    return (value['request'] == nonce and value['subject'] == subject and value['selection_intent'] == 'select-new'
            and value['operation'] == 'commit' and value['attempt'] == 3 and value['prepare_ack_attempt'] == 2
            and value['first_prepare_ack_attempt'] == 2 and value['commit_ack_attempt'] == 0
            and value['first_commit_ack_attempt'] == 0 and value.get('principal_id') == '1')


def assess_label(observe, event, want, selected, current):
    """One issued request against its predicted assessment. Returns the observed outcome."""
    writer = observe.writer
    kind, operation, instance, nonce = want['kind'], event['operation'], event['instance'], event['nonce']
    if not event['reply']:
        if instance != current:
            raise ValueError('request not issued to the captured instance')
        if kind != 'unknown':
            raise ValueError('a reply is required')
        result = observe.retain_unknown(None, issued={'kind': operation, 'instance': instance, 'nonce': nonce},
                                        returncode=None, stderr=None, selected=selected)
        if result['reason'] != want['reason'] or 'retained' in result or 'retained_by' not in want:
            raise ValueError('issued request without a reply is not retained as UNKNOWN')
        return result['reason']
    text, code, err = event['stdout'], event['returncode'], event['stderr']
    false_arm = dict(instance=instance, nonce=nonce, selected=selected, expected_id=1, intent='select-new',
                     issued_kind=operation, returncode=code, stderr=err)
    if kind == 'info':
        if operation != 'info':
            raise ValueError('info label for another operation')
        return writer.parse_info(text, returncode=code, stderr=err)['instance']
    if kind == 'refusal':
        writer.refusal(text, want['code'], current, requested_instance=instance, returncode=code, stderr=err)
        return want['code']
    if instance != current:
        raise ValueError('request not issued to the captured instance')
    if kind == 'parse':
        if code or err.strip():
            raise ValueError('unsuccessful transport')
        # A refused selection has no selected identity to compare, and the strict parser refuses one.
        value = writer.parse(text, instance=instance, nonce=nonce,
                             selected=None if want.get('selection') == 'absent' else selected)
        for key, wanted in want.items():
            if key not in ('kind', 'signer', 'selection') and value.get(key) != wanted:
                raise ValueError('%s is %r, not %r' % (key, value.get(key), wanted))
        if not refused(lambda: observe.assess_false_commit(text, **false_arm)):
            raise ValueError('a non commit reply was assessed as a false commit')
        return value['state']
    if kind == 'false-commit':
        result = observe.assess_false_commit(text, **false_arm)
        if (result['assessment_origin'] != want['origin'] or result['no_effect_inferred'] is not False
                or result['effects'] != 'unknown'):
            raise ValueError('false commit assessment ' + result['assessment_origin'])
        if not refused(lambda: writer.assess_commit(text, instance=instance, nonce=nonce, selected=selected,
                                                    expected_id=1, intent='select-new', transport_operation=operation,
                                                    returncode=code, stderr=err)):
            raise ValueError('the positive assessor accepted a false commit')
        return result['assessment_origin']
    if kind == 'positive-commit':
        result = writer.assess_commit(text, instance=instance, nonce=nonce, selected=selected, expected_id=1,
                                      intent='select-rebind', transport_operation=operation, returncode=code,
                                      stderr=err)
        if result['assessment_origin'] != want['origin']:
            raise ValueError('positive commit assessment ' + result['assessment_origin'])
        if not refused(lambda: observe.assess_false_commit(text, **false_arm)):
            raise ValueError('a positive commit was assessed as a false commit')
        return result['assessment_origin']
    if kind == 'unknown':
        if not refused(lambda: observe.assess_false_commit(text, **false_arm)):
            raise ValueError('an unresolved commit was assessed as false')
        result = observe.retain_unknown(text, issued={'kind': operation, 'instance': instance, 'nonce': nonce},
                                        returncode=code, stderr=err, selected=selected)
        if (result['outcome'] != 'UNKNOWN' or result['reason'] != want['reason'] or result['no_effect_inferred']
                or result['issued'] != {'kind': operation, 'instance': instance, 'nonce': nonce}):
            raise ValueError('unknown outcome %s' % result['reason'])
        retained = result.get('retained')
        if retained is None and 'retained_by' not in want:
            raise ValueError('no reply fields retain the request and no later status is named')
        if retained is not None and not original_request(retained, nonce, observe.SUBJECT):
            raise ValueError('the reply did not retain the original request')
        return result['reason']
    raise ValueError('unknown predicted kind ' + kind)


def check_transcript(stdout, work, predictions):
    """Actual fixture replies through the observers, then the store bytes and modes, separately."""
    observe = observer()
    expected = predictions['rehearsal']
    events, context, passes, done, problems = parse_transcript(stdout)
    if sorted(passes) != sorted(expected['pass']) or len(passes) != len(set(passes)):
        problems.append('rehearsal cases %s' % passes)
    if done != [expected['done']]:
        problems.append('rehearsal did not finish')
    by_label = dict(events)
    if set(by_label) != set(expected['labels']):
        problems.append('rehearsal labels %s' % sorted(set(by_label) ^ set(expected['labels'])))
    outcomes = {}
    try:
        selected = observe.captured_selection(strict(context['selected']))
        # The host signer is computed independently of the transcript and the predictions. It is
        # the facade's synthetic test certificate, never the Android subject's signer.
        if selected['signer_sha256'] != HOST_SIGNER or expected['facade_signer_sha256'] != HOST_SIGNER:
            problems.append('selected identity is not the host facade test signer')
    except (KeyError, ValueError) as error:
        return problems + ['selected identity context: %s' % error], outcomes
    changed = dict(selected, signer_sha256=expected['changed_signer_sha256'])
    current = None
    for label, event in events:
        want = expected['labels'].get(label)
        if want is None:
            continue
        try:
            outcome = assess_label(observe, event, want, changed if want.get('signer') == 'changed' else selected,
                                   current)
            if want['kind'] == 'info':
                current = outcome
            outcomes[label] = outcome
        except (ValueError, KeyError, TypeError) as error:
            problems.append('%s: %s' % (label, error))
    # A retention claim needs a later actual status reply to the same issued instance and nonce.
    order = [label for label, _ in events]
    for label, want in expected['labels'].items():
        partner = want.get('retained_by')
        if partner is None:
            continue
        first, second = by_label.get(label), by_label.get(partner)
        try:
            if (first is None or second is None or not second['reply'] or second['operation'] != 'status'
                    or (second['instance'], second['nonce']) != (first['instance'], first['nonce'])
                    or order.index(partner) < order.index(label)):
                raise ValueError('no later status of the same issued request')
            value = observe.writer.parse(second['stdout'], instance=first['instance'], nonce=first['nonce'],
                                         selected=selected)
            if not original_request(value, first['nonce'], observe.SUBJECT):
                raise ValueError('the later status lost the original request')
            outcomes[label + ' retained by'] = partner
        except (ValueError, KeyError) as error:
            problems.append('%s retention: %s' % (label, error))
    try:
        generation = observe.load_generation(context['generation'])
        prediction = observe.load_prediction(work / 'host-prediction', signer=selected['signer_sha256'])
        if context['prediction'] + '\n' != (work / 'host-prediction/prediction.json').read_text():
            problems.append('prediction context differs from its manifest')
        for name, phase in expected['snapshots'].items():
            outcomes['snapshot ' + name] = observe.assess_store(work / 'snapshots' / name, phase,
                                                                generation=generation, prediction=prediction)['phase']
        outcomes['final store'] = observe.assess_store(work / 'store', 'live', generation=generation,
                                                       prediction=prediction)['phase']
        if not refused(lambda: observe.assess_store(work / 'snapshots/creating', 'live', prediction=prediction)):
            problems.append('a creating snapshot was accepted as published')
        # Predictor inputs from the ledger's own records, tied to the captured prediction manifest.
        prepare = by_label['prepare']
        prepared = observe.writer.parse(prepare['stdout'], instance=prepare['instance'], nonce=prepare['nonce'],
                                        selected=selected)
        arguments = observe.prediction_arguments(generation, prepared, selected, signer=selected['signer_sha256'])
        manifest = [prediction['lineage'], str(prediction['app_id']), str(prediction['user_serial']),
                    str(prediction['principal_id'])]
        if (arguments != manifest or generation['lineage'] != prediction['lineage']
                or prediction['subject'] != observe.SUBJECT or prediction['signer_sha256'] != HOST_SIGNER):
            problems.append('predictor inputs differ from the captured prediction manifest')
        # The independent oracle at this run's actual values from the independent captures: the
        # generated lineage, the selected app ID and serial and the independently computed host
        # signer, never the manifest. The command line oracle uses the profile's fixture signer.
        gold = goldens(lineage=generation['lineage'], app_id=selected['app_id'], serial=selected['user_serial'],
                       signer=HOST_SIGNER)
        slot = 'slots/%d' % selected['app_id']
        oracle = {work / 'snapshots/empty/store.bin': 'EMPTY', work / 'snapshots/empty/store.bin.reservecopy': 'EMPTY',
                  work / 'snapshots/creating/store.bin': 'CREATING',
                  work / 'snapshots/creating/store.bin.reservecopy': 'CREATING',
                  work / 'snapshots/live/store.bin': 'LIVE', work / 'snapshots/live/store.bin.reservecopy': 'LIVE',
                  work / 'snapshots/live' / slot / 'record.bin': 'BODY',
                  work / 'snapshots/live' / slot / 'record.bin.reservecopy': 'BODY',
                  work / 'host-prediction/v2-creating-header.bin': 'CREATING',
                  work / 'host-prediction/v2-live-header.bin': 'LIVE',
                  work / 'host-prediction/v2-slot-body.bin': 'BODY'}
        problems.extend(oracle_problems(oracle, gold, 'the rehearsal values'))
        # Modes are observed on the live store; the byte copies carry none.
        modes = strict(context['modes'])
        if modes != expected['modes']:
            problems.append('observed live store modes %s' % modes)
        outcomes['modes'] = modes
    except (KeyError, ValueError, OSError) as error:
        problems.append('store observation: %s' % error)
    return problems, outcomes


def subprocess_env(work, pinned=None):
    """The same bounded JVM options for every JVM a subprocess suite starts. A suite's own heap
    option still applies after these; the JVM reports that it picked them up."""
    env = dict(os.environ, TMPDIR=str(work / 'tmp'), JAVA_TOOL_OPTIONS=' '.join(jvm_options(work)),
               PYTHONDONTWRITEBYTECODE='1')
    if pinned:
        env['ANDRIX_PINNED_FRAMEWORK'] = str(pinned)
    return env


def suite_cwd(work):
    cwd = work / 'suites'
    cwd.mkdir(exist_ok=True)
    return inside(work, cwd)


def writer_regression(work, predictions, pinned, record, problems, save):
    record['run'] = run([sys.executable, '-B', ROOT / predictions['writer_regression']['module']], 1800,
                        cwd=suite_cwd(work), env=subprocess_env(work))
    save()
    wanted = 'Ran %d tests' % predictions['writer_regression']['tests']
    if record['run']['returncode'] or wanted not in record['run']['stderr'] or 'skipped' in record['run']['stderr']:
        problems.append('legacy writer fixture regression')


def pure_suites(work, predictions, pinned, record, problems, save):
    for name in predictions['pure_suites']:
        record[name] = run([sys.executable, '-B', ROOT / name], 1800, cwd=suite_cwd(work),
                           env=subprocess_env(work, pinned))
        save()
        skipped = re.findall(r'skipped=(\d+)', record[name]['stderr'])
        record[name]['skipped_tests'] = sum(int(count) for count in skipped)
        save()
        if record[name]['returncode']:
            problems.append('pure suite failed: ' + name)
        elif record[name]['skipped_tests']:
            problems.append('required pure suite checks skipped: ' + name)


STEPS = {'jdk': jdk_phase, 'store fixture': store_fixture, 'guest inputs': guest_inputs, 'rehearsal': rehearsal,
         'writer regression': writer_regression, 'pure suites': pure_suites}


# ------------------------------------------------------------ orchestration

class Progress:
    """The one report of a guarded run, shared by every phase before any starts. Each phase's
    record is installed before its work and every finished step is checkpointed to
    <work>/progress.json with a synced writing descriptor and directory. This records process
    interruption only. A phase counts as complete only when it returns."""

    def __init__(self, report, path):
        self.report, self.path = report, path
        report.update(status='RUNNING', running_phase=None, completed_phases=[])
        report.setdefault('problems', [])
        self.write()

    def begin(self, phase):
        record = self.report[phase] = {'complete': False}
        self.report['running_phase'] = phase
        self.write()
        return record

    def done(self, phase):
        if self.report['running_phase'] != phase:
            raise ValueError('phase %s ended while %s ran' % (phase, self.report['running_phase']))
        self.report[phase]['complete'] = True
        self.report['completed_phases'].append(phase)
        self.report['running_phase'] = None
        self.write()

    def write(self):
        data = (json.dumps(self.report, indent=2) + '\n').encode()
        temporary = self.path.with_name('.progress.json.tmp')
        with open(temporary, 'wb') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, self.path)
        directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def stream_text(stream):
    return stream.decode(errors='replace') if isinstance(stream, bytes) else stream or ''


def exception_record(error):
    """The error that stopped a run, with a timed out command's own captured streams."""
    record = {'type': type(error).__name__, 'message': str(error)}
    if isinstance(error, subprocess.TimeoutExpired):
        command = error.cmd
        record.update(command=[str(part) for part in command] if isinstance(command, (list, tuple))
                      else str(command), timeout=error.timeout, stdout=stream_text(error.stdout),
                      stderr=stream_text(error.stderr))
    return record


def fresh_outside(path, what):
    resolved = path.resolve()
    if (resolved.exists() or resolved.is_symlink() or ROOT in resolved.parents or resolved == ROOT
            or android_lifecycle.sealed_ancestor(resolved)):
        raise ValueError('fresh unsealed %s outside the repository required' % what)
    return resolved


def work_path_problem(work):
    """JVM option values and JAVA_TOOL_OPTIONS carry the work path unquoted, and HotSpot expands
    percent signs in log names and parses quotes, so none of those characters may occur."""
    if re.search(r'[\s%\'"]', str(work)):
        return 'work path contains whitespace, a quote or a percent sign'
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, help='fresh JSON path outside the repository')
    parser.add_argument('--work', type=Path, help='fresh scratch directory outside the repository')
    parser.add_argument('--pinned-framework', type=Path,
                        help='pinned canonical framework copies, for the pure suites that rebuild them')
    parser.add_argument('--source-checks-only', action='store_true')
    args = parser.parse_args(argv)
    predictions = strict(PREDICTIONS.read_text())
    report = {'runtime_qualified': False, 'android_qualified': False, 'activation': False,
              'v2_publication': False, 'native_execution_enabled': False}
    problems = source_checks()
    report['source_checks'] = list(problems) or 'PASS'
    if args.source_checks_only:
        # The pinned rebuild of the native outputs is the B1 runner's --verify-candidate.
        if args.work or args.pinned_framework or args.evidence:
            parser.error('source checks take no --work, --pinned-framework or --evidence')
        report['status'] = 'FAIL' if problems else 'SOURCE_ONLY'
        report['problems'] = problems
        print(json.dumps(report, indent=2))
        return 1 if problems else 0
    if not (args.evidence and args.work and args.pinned_framework):
        parser.error('--evidence, --work and --pinned-framework are required for a guarded run')
    evidence = fresh_outside(args.evidence, 'evidence path')
    work = fresh_outside(args.work, 'work directory')
    pinned = args.pinned_framework.resolve(strict=True)
    # Pure refusals, in order. Nothing below is created or started until each one passes.
    reason = work_path_problem(work) or b1.resource_guard()
    if not reason and not (shutil.which('javac') and shutil.which('java')):
        reason = 'no JDK on PATH'
    if reason:
        report.update(status='NOT_RUN', reason=reason, problems=problems)
        print(json.dumps(report, indent=2))
        return 2
    work.mkdir(parents=True)
    (work / 'tmp').mkdir()
    tempfile.tempdir = str(work / 'tmp')
    report['problems'] = problems
    progress = Progress(report, work / 'progress.json')
    try:
        for phase in PHASES:
            record = progress.begin(phase)
            STEPS[phase](work, predictions, pinned, record, problems, progress.write)
            progress.done(phase)
        report['status'] = 'FAIL' if problems else 'PASS'
    except Exception as error:  # Keep every finished record, the stopped streams and the phase.
        report['exception'] = exception_record(error)
        problems.append('qualification did not complete')
        report['status'] = 'NOT_COMPLETE'
    report['not_completed_phases'] = [phase for phase in PHASES if phase not in report['completed_phases']]
    if report['not_completed_phases'] and report['status'] != 'NOT_COMPLETE':
        problems.append('phases did not complete: %s' % report['not_completed_phases'])
        report['status'] = 'NOT_COMPLETE'
    progress.write()
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'problems': problems}, indent=2))
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
