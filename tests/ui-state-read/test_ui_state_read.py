# SPDX-License-Identifier: Apache-2.0
"""Host checks for the UI state helper's source, its pins, its Binder signatures and its build.

The pin, source and refusal checks always run. The others run only when they are given what they
need, and write only into fresh directories under ANDRIX_UI_STATE_READ_WORK, or the system's
temporary directory, never into the repository:

- the AIDL checks, when ANDRIX_FRAMEWORKS_BASE names the pinned `frameworks/base` tree;
- the rebuild, when ANDRIX_UI_STATE_READ_JDK names the pinned JDK 25 home and
  ANDRIX_UI_STATE_READ_R8 the pinned r8 jar;
- the host runs, which run the pinned class file on the host JVM against the stub services in
  `hoststubs/`, when ANDRIX_UI_STATE_READ_JDK is given;
- the dex inspection, when ANDRIX_UI_STATE_READ_DEXDUMP also names a dexdump binary.

A host run shows what the helper's own code does with each answer, exception, absent service and
signature. It shows nothing about a device's services, permissions or answers.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import resource
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / 'tests' / 'component-lab'))
import reproduce  # noqa: E402
import health_compose  # noqa: E402

SOURCE = HERE / 'UiStateRead.java'
SIGNATURES = HERE / 'signatures.json'
STUBS = HERE / 'hoststubs'
# Names the helper must never hold: every mutation the four interfaces offer near the calls it
# makes, and every route to another process, file or raw transaction.
FORBIDDEN = ('lockCeStorage', 'unlockCeStorage', 'unlockUserKey', 'lockUserKey', 'setDeviceLockedForUser',
             'reportUnlockAttempt', 'reportUserRequestedUnlock', 'reportUserMayRequestUnlock', 'reportUnlockLockout',
             'unlockedByBiometricForUser', 'clearAllBiometricRecognized', 'dismissKeyguard', 'disableKeyguard',
             'reenableKeyguard', 'exitKeyguardSecurely', 'wakeUp', 'goToSleep', 'userActivity', 'nap',
             'setPowerSaveModeEnabled', 'startCheckpoint', 'commitChanges', 'abortChanges', 'prepareUserStorage',
             'destroyUserStorage', 'setCeStorageProtection', 'getRuntime', 'exec(', 'ProcessBuilder', 'transact',
             'File', 'Socket', 'setAccessible')
CALL = re.compile(r'ask\("(\w+)", "([\w.]+)", "(\w+)", (NONE|USER|USER_DEVICE)((?:, \w+)*)\)')
TYPES = {'NONE': [], 'USER': ['int'], 'USER_DEVICE': ['int', 'int']}
ARGUMENTS = {'user': 'user', 'DEFAULT_DEVICE': 'default_device'}


def java_code(text):
    """Java source without comments."""
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    return re.sub(r'//[^\n]*', '', text)


def signatures():
    return reproduce.strict(SIGNATURES.read_text())


def scratch():
    parent = os.environ.get('ANDRIX_UI_STATE_READ_WORK') or None
    return tempfile.TemporaryDirectory(dir=parent)


def bounded(argv, cwd, timeout=120):
    """One tool or JVM, bounded like the reproduction's, with its status and both streams."""
    def limits():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout))
    environment = {k: v for k, v in os.environ.items() if k not in reproduce.CLEARED}
    done = subprocess.run([str(a) for a in argv], cwd=cwd, env=environment, capture_output=True, timeout=timeout,
                          preexec_fn=limits)
    return done.returncode, done.stdout.decode('utf-8', 'surrogateescape'), done.stderr.decode('utf-8', 'surrogateescape')


class PinTests(unittest.TestCase):
    def test_the_pins_name_the_committed_source(self):
        pins = reproduce.pins()
        data = SOURCE.read_bytes()
        self.assertEqual((len(data), hashlib.sha256(data).hexdigest()),
                         (pins['source']['bytes'], pins['source']['sha256']))
        self.assertEqual(set(pins), {'schema', 'source', 'jdk', 'javac', 'class', 'r8', 'd8', 'jar'})
        self.assertEqual(pins['javac'], ['--release', '17', '-Xlint:all', '-Werror'])
        self.assertEqual(pins['d8'], ['--release', '--min-api', '30'])
        self.assertEqual(pins['jar']['name'], 'andrix-ui-state-read.jar')

    def test_the_composer_admits_exactly_the_pinned_jar_and_its_one_invocation(self):
        pins = reproduce.pins()
        self.assertEqual(health_compose.UI_STATE_HELPER_SHA256, pins['jar']['sha256'])
        self.assertEqual(Path(health_compose.UI_STATE_HELPER).name, pins['jar']['name'])
        for user in (0, 13, 21473):
            self.assertEqual(health_compose.ui_state_command(user), 'CLASSPATH=%s app_process /system/bin UiStateRead %d'
                             % (health_compose.UI_STATE_HELPER, user))
        for user in (-1, 21474, True, '10', 1.0):
            with self.assertRaises(ValueError):
                health_compose.ui_state_command(user)
        self.assertEqual(health_compose.UI_STATE_HEADER, 'andrix-ui-state-read-v1')
        self.assertEqual(list(health_compose.UI_STATE_CAPABILITIES), [c['capability'] for c in signatures()['calls']])


class SourceTests(unittest.TestCase):
    def test_the_source_asks_exactly_the_pinned_binder_calls_in_order(self):
        code = java_code(SOURCE.read_text())
        found = []
        for service, interface, method, types, args in CALL.findall(code):
            found.append({'service': service, 'interface': interface, 'method': method, 'parameters': TYPES[types],
                          'arguments': [ARGUMENTS[a] for a in args.split(', ')[1:]]})
        pinned = [{k: c[k] for k in ('service', 'interface', 'method', 'parameters', 'arguments')}
                  for c in signatures()['calls']]
        self.assertEqual(found, pinned)
        self.assertEqual(code.count('ask("'), len(pinned))
        self.assertEqual(re.findall(r'CAPABILITIES =\s*"([^"]*)"', code),
                         [','.join(c['capability'] for c in signatures()['calls'])])
        constants = signatures()['constants']
        self.assertIn('DEFAULT_DEVICE = %d;' % constants['default_device']['value'], code)
        self.assertIn('MAX_USER = %d;' % constants['max_user']['value'], code)
        self.assertIn('private static final Class<?>[] USER = {int.class};', code)
        self.assertIn('private static final Class<?>[] USER_DEVICE = {int.class, int.class};', code)
        # The one lookup of each service, by the name the service registers under.
        self.assertEqual(re.findall(r'getMethod\("(\w+)", String\.class\)', code), ['getService'])
        self.assertEqual(re.findall(r'getMethod\("(\w+)", ibinder\)', code), ['asInterface'])

    def test_the_source_has_no_mutation_and_no_other_route(self):
        code = java_code(SOURCE.read_text())
        for name in FORBIDDEN:
            self.assertNotIn(name, code)
        self.assertEqual(re.findall(r'import ([\w.]+);', code),
                         ['java.lang.reflect.InvocationTargetException', 'java.lang.reflect.Method'])
        self.assertNotIn('System.err', code)

    def test_the_protocol_in_the_source(self):
        code = java_code(SOURCE.read_text())
        self.assertEqual(re.findall(r'HEADER = "([^"]*)"', code), ['andrix-ui-state-read-v1'])
        self.assertEqual(re.findall(r'System\.exit\(([^)]*)\)', code), ['2', 'complete ? 0 : 5'])
        self.assertIn('"error=arguments"', code)
        self.assertIn('"end=" + HEADER', code)
        self.assertIn('"status=" + (complete ? "complete" : "unavailable")', code)
        # A failed call is unavailable with its reason, never false.
        self.assertEqual(sorted(set(re.findall(r'"unavailable:([^"]*)"', code))),
                         ['', 'not-boolean', 'service-absent'])
        self.assertIn('text.matches("0|[1-9][0-9]{0,4}")', code)


@unittest.skipUnless(os.environ.get('ANDRIX_FRAMEWORKS_BASE'), 'the pinned frameworks/base tree is not given')
class AidlTests(unittest.TestCase):
    def test_each_pinned_signature_is_the_aidl_declaration(self):
        base = Path(os.environ['ANDRIX_FRAMEWORKS_BASE'])
        s = signatures()

        def line(path, number):
            return (base / path).read_bytes().decode('utf-8').split('\n')[number - 1]
        for call in s['calls']:
            aidl = call['aidl']
            data = (base / aidl['path']).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), aidl['sha256'], aidl['path'])
            self.assertEqual(line(aidl['path'], aidl['line']), aidl['declaration'])
            declared = re.fullmatch(r'    (\w+) (\w+)\(([^)]*)\);', aidl['declaration'].replace(' = 65;', ';'))
            self.assertEqual(declared[1], call['returns'])
            self.assertEqual(declared[2], call['method'])
            self.assertEqual([p.split(' ')[0] for p in declared[3].split(', ') if p], call['parameters'])
            self.assertIn('package %s;' % call['interface'].rsplit('.', 1)[0], data.decode())
            self.assertRegex(data.decode(), r'\binterface %s\s*\{' % call['interface'].rsplit('.', 1)[1])
        for pinned in list(s['constants'].values()) + list(s['services'].values()):
            self.assertEqual(line(pinned['path'], pinned['line']), pinned['declaration'])


class RefusalTests(unittest.TestCase):
    """Nothing starts until the work directory and every input are the pinned ones."""

    def refused(self, **arguments):
        with mock.patch.object(reproduce.subprocess, 'run', side_effect=AssertionError('a tool started')):
            with self.assertRaises(reproduce.Refused):
                reproduce.reproduce(**arguments)

    def test_a_work_directory_in_the_repository_or_not_new_is_refused(self):
        self.refused(jdk='/nonexistent', r8='/nonexistent', work=ROOT / 'tests' / 'ui-state-read' / 'out')
        self.refused(jdk='/nonexistent', r8='/nonexistent', work=ROOT)
        with tempfile.TemporaryDirectory() as existing:
            self.refused(jdk='/nonexistent', r8='/nonexistent', work=existing)

    def test_inputs_that_are_not_the_pinned_ones_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            jdk = base / 'jdk'
            (jdk / 'bin').mkdir(parents=True)
            (jdk / 'release').write_text('JAVA_VERSION="25"\n')
            r8 = base / 'r8.jar'
            r8.write_bytes(b'not r8')
            self.refused(jdk=jdk, r8=r8, work=base / 'work')
            self.refused(jdk=base / 'missing', r8=r8, work=base / 'work')
            self.assertFalse((base / 'work').exists())

    def test_a_changed_source_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / 'UiStateRead.java'
            changed.write_bytes(SOURCE.read_bytes().replace(b'isCeStorageUnlocked', b'lockCeStorage'))
            pins = reproduce.pins()
            with self.assertRaises(reproduce.Refused):
                reproduce.pinned_file(changed, pins['source']['bytes'], pins['source']['sha256'], 'the helper source')


def _tools():
    return os.environ.get('ANDRIX_UI_STATE_READ_JDK') and os.environ.get('ANDRIX_UI_STATE_READ_R8')


@unittest.skipUnless(_tools(), 'the pinned JDK and r8 jar are not given')
class RebuildTests(unittest.TestCase):
    def test_the_source_rebuilds_to_the_pinned_jar(self):
        with scratch() as directory:
            work = Path(directory) / 'work'
            record = reproduce.reproduce(os.environ['ANDRIX_UI_STATE_READ_JDK'], os.environ['ANDRIX_UI_STATE_READ_R8'],
                                         work)
            pins = reproduce.pins()
            self.assertEqual(record['status'], 'PASS', record.get('problem'))
            self.assertEqual(record['jar'], {'bytes': pins['jar']['bytes'], 'sha256': pins['jar']['sha256']})
            data = (work / pins['jar']['name']).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), health_compose.UI_STATE_HELPER_SHA256)


@unittest.skipUnless(os.environ.get('ANDRIX_UI_STATE_READ_JDK'), 'the pinned JDK is not given')
class HostRunTests(unittest.TestCase):
    """The pinned class file run on the host JVM against the stub services."""

    @classmethod
    def setUpClass(cls):
        # The class's scratch is removed even when this setup fails part way.
        directory = scratch()
        cls.addClassCleanup(directory.cleanup)
        cls.work = Path(directory.name)
        jdk = Path(os.environ['ANDRIX_UI_STATE_READ_JDK']) / 'bin'
        cls.java = jdk / 'java'
        options = ['-J' + o for o in reproduce.JVM_LIMITS]
        pins = reproduce.pins()
        (cls.work / 'helper').mkdir()
        code, _, err = bounded([jdk / 'javac', *options, *pins['javac'], '-d', 'helper', SOURCE], cls.work)
        assert code == 0, err
        compiled = (cls.work / 'helper' / pins['class']['name']).read_bytes()
        assert (len(compiled), hashlib.sha256(compiled).hexdigest()) == (pins['class']['bytes'], pins['class']['sha256'])
        for name, edit in (('stubs', None), ('wrong', ('isDeviceLocked(int userId, int deviceId)',
                                                       'isDeviceLocked(int userId)'))):
            tree = cls.work / (name + '-src')
            for path in STUBS.rglob('*.java'):
                target = tree / path.relative_to(STUBS)
                target.parent.mkdir(parents=True, exist_ok=True)
                text = path.read_text()
                if edit is not None and path.name == 'ITrustManager.java':
                    text = text.replace(*edit).replace('"isDeviceLocked(" + userId + "," + deviceId + ")"',
                                                       '"isDeviceLocked(" + userId + ")"')
                target.write_text(text)
            (cls.work / name).mkdir()
            sources = sorted(str(p) for p in tree.rglob('*.java'))
            code, _, err = bounded([jdk / 'javac', *options, '--release', '17', '-d', name, *sources], cls.work)
            assert code == 0, err

    def run_helper(self, args, answers=None, absent=(), stubs='stubs'):
        trace = self.work / 'trace.txt'
        if trace.exists():
            trace.unlink()
        properties = ['-Dandrix.trace=%s' % trace, '-Dandrix.absent=%s' % ','.join(absent)]
        properties += ['-Dandrix.answer.%s=%s' % item for item in sorted((answers or {}).items())]
        code, out, err = bounded([self.java, '-Xmx64m', '-XX:+UseSerialGC', *properties, '-cp',
                                  '%s:%s' % (self.work / stubs, self.work / 'helper'), 'UiStateRead', *args], self.work)
        calls = trace.read_text().split('\n')[:-1] if trace.exists() else []
        return code, out, err, calls

    def test_every_answer_is_printed_whole_with_its_user_and_the_default_device(self):
        answers = {'isInteractive': 'true', 'isKeyguardLocked': 'false', 'isKeyguardSecure': 'true',
                   'isDeviceLocked': 'false', 'isDeviceSecure': 'true', 'isCeStorageUnlocked': 'true'}
        code, out, err, calls = self.run_helper(['13'], answers)
        self.assertEqual((code, err), (0, ''))
        self.assertEqual(out, 'andrix-ui-state-read-v1\nuser=13\ncapabilities=interactive,keyguard_locked,'
                              'keyguard_secure,device_locked,device_secure,ce_unlocked\ninteractive=true\n'
                              'keyguard_locked=false\nkeyguard_secure=true\ndevice_locked=false\ndevice_secure=true\n'
                              'ce_unlocked=true\nstatus=complete\nend=andrix-ui-state-read-v1\n')
        self.assertEqual(calls, ['getService(power)', 'isInteractive()', 'getService(window)', 'isKeyguardLocked()',
                                 'getService(window)', 'isKeyguardSecure(13)', 'getService(trust)',
                                 'isDeviceLocked(13,0)', 'getService(trust)', 'isDeviceSecure(13,0)',
                                 'getService(mount)', 'isCeStorageUnlocked(13)'])
        reading = health_compose.parse_ui_state(code, out, err, 13)
        self.assertEqual(reading['values'], {'interactive': True, 'keyguard_locked': False, 'keyguard_secure': True,
                                             'device_locked': False, 'device_secure': True, 'ce_unlocked': True})

    def test_an_exception_is_unavailable_never_false(self):
        code, out, err, calls = self.run_helper(['0'], {'isDeviceLocked': 'security', 'isCeStorageUnlocked': 'remote',
                                                        'isInteractive': 'true'})
        self.assertEqual((code, err), (5, ''))
        lines = out.split('\n')
        self.assertIn('device_locked=unavailable:java.lang.SecurityException', lines)
        self.assertIn('ce_unlocked=unavailable:android.os.RemoteException', lines)
        self.assertIn('interactive=true', lines)
        self.assertEqual(lines[-3:], ['status=unavailable', 'end=andrix-ui-state-read-v1', ''])
        reading = health_compose.parse_ui_state(code, out, err, 0)
        self.assertIsNone(reading['values']['device_locked'])
        self.assertIsNone(reading['values']['ce_unlocked'])
        self.assertEqual(reading['unavailable']['device_locked'], 'java.lang.SecurityException')
        self.assertEqual(len(calls), 12)

    def test_an_absent_service_and_a_wrong_signature_are_unavailable(self):
        code, out, _, calls = self.run_helper(['10'], absent=('trust',))
        self.assertEqual(code, 5)
        self.assertIn('device_locked=unavailable:service-absent', out.split('\n'))
        self.assertIn('device_secure=unavailable:service-absent', out.split('\n'))
        self.assertNotIn('isDeviceLocked(10,0)', calls)
        code, out, _, calls = self.run_helper(['10'], {'isDeviceLocked': 'true'}, stubs='wrong')
        self.assertEqual(code, 5)
        self.assertIn('device_locked=unavailable:java.lang.NoSuchMethodException', out.split('\n'))
        self.assertNotIn('isDeviceLocked(10)', calls)

    def test_only_one_bounded_user_id_is_accepted(self):
        for args in ([], ['1', '2'], ['21474'], ['010'], ['-1'], ['+1'], ['1x'], [''], ['99999999999']):
            with self.subTest(args):
                code, out, err, calls = self.run_helper(args)
                self.assertEqual((code, out, err, calls),
                                 (2, 'andrix-ui-state-read-v1\nerror=arguments\nend=andrix-ui-state-read-v1\n', '', []))
        code, out, _, _ = self.run_helper(['21473'], {'isInteractive': 'true'})
        self.assertEqual((code, out.split('\n')[1]), (0, 'user=21473'))


@unittest.skipUnless(_tools() and os.environ.get('ANDRIX_UI_STATE_READ_DEXDUMP'),
                     'the pinned JDK, r8 jar and a dexdump are not given')
class DexTests(unittest.TestCase):
    def test_the_dex_holds_only_the_pinned_names_and_reflective_calls(self):
        with scratch() as directory:
            work = Path(directory) / 'work'
            record = reproduce.reproduce(os.environ['ANDRIX_UI_STATE_READ_JDK'], os.environ['ANDRIX_UI_STATE_READ_R8'],
                                         work)
            self.assertEqual(record['status'], 'PASS', record.get('problem'))
            code, out, _ = bounded([os.environ['ANDRIX_UI_STATE_READ_DEXDUMP'], '-d', reproduce.pins()['jar']['name']],
                                   work)
            self.assertEqual(code, 0)
        strings = set(re.findall(r'const-string[^"]*"([^"]*)"', out))
        methods = {c['method'] for c in signatures()['calls']}
        named = {s for s in strings if re.fullmatch(r'[a-z][A-Za-z]+', s) and s[0:2] in ('is', 'ge', 'as')}
        self.assertEqual(named, methods | {'getService', 'asInterface'})
        for name in FORBIDDEN:
            self.assertFalse(any(name.rstrip('(') in s for s in strings), name)
        invoked = set(re.findall(r'invoke-[a-z/]+ \{[^}]*\}, (L[^;]+;)\.', out))
        self.assertEqual(invoked, {'LUiStateRead;', 'Ljava/io/PrintStream;', 'Ljava/lang/Boolean;', 'Ljava/lang/Class;',
                                   'Ljava/lang/Integer;', 'Ljava/lang/Object;', 'Ljava/lang/String;',
                                   'Ljava/lang/StringBuilder;', 'Ljava/lang/System;',
                                   'Ljava/lang/reflect/InvocationTargetException;', 'Ljava/lang/reflect/Method;'})


if __name__ == '__main__':
    unittest.main()
