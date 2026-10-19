# SPDX-License-Identifier: Apache-2.0
"""Host checks for the process health helper's source, its pins, its Binder signatures and its
build.

The pin, source and refusal checks always run. The others run only when they are given what they
need, and write only into fresh directories under ANDRIX_PROCESS_HEALTH_READ_WORK, or the system's
temporary directory, never into the repository:

- the AIDL and source line checks, when ANDRIX_FRAMEWORKS_BASE names the pinned `frameworks/base`;
- the rebuild, when ANDRIX_PROCESS_HEALTH_READ_JDK names the pinned JDK 25 home and
  ANDRIX_PROCESS_HEALTH_READ_R8 the pinned r8 jar;
- the host runs, which run the pinned class file on the host JVM against the stub services in
  `hoststubs/`, when ANDRIX_PROCESS_HEALTH_READ_JDK is given;
- the dex inspection, when ANDRIX_PROCESS_HEALTH_READ_DEXDUMP also names a dexdump binary.

A host run shows what the helper's own code does with each reply, exception, absent service and
signature, and that the reader's parser and the simulated guest's form agree with it. It shows
nothing about a device's services, permissions or replies.
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
import process_health  # noqa: E402
import sim_android  # noqa: E402

SOURCE = HERE / 'ProcessHealthRead.java'
SIGNATURES = HERE / 'signatures.json'
STUBS = HERE / 'hoststubs'
# Names the helper must never hold: every mutation of the activity manager near the reads it
# makes, the trace and tombstone routes of an exit record, and every route to another process,
# file or raw transaction.
FORBIDDEN = ('killProcess', 'killBackgroundProcesses', 'killAllBackgroundProcesses', 'killUid', 'killPids',
             'killProcessesWhenImperceptible', 'forceStopPackage', 'crashApplication', 'appNotResponding',
             'clearApplicationUserData', 'setProcessStateSummary', 'getTraceInputStream', 'getTraceFile',
             'getNativeTombstoneRetriever', 'getAppTraceRetriever', 'clearHistoricalProcessExitReasons', 'stopUser',
             'restart', 'startActivity', 'sendBroadcast', 'getRuntime', 'exec(', 'ProcessBuilder', 'transact', 'File',
             'Socket', 'setAccessible', 'System.err')
EXIT_GETTERS = ('getTimestamp', 'getPid', 'getRealUid', 'getPackageUid', 'getDefiningUid', 'getUserHandle',
                'getProcessName', 'getReason', 'getSubReason', 'getStatus')
ERROR_FIELDS = ('condition', 'pid', 'uid', 'processName', 'tag', 'shortMsg', 'longMsg', 'stackTrace')


def java_code(text):
    """Java source without comments."""
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    return re.sub(r'//[^\n]*', '', text)


def signatures():
    return reproduce.strict(SIGNATURES.read_text())


def scratch():
    parent = os.environ.get('ANDRIX_PROCESS_HEALTH_READ_WORK') or None
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


def escape(text):
    """A value in the properties file form the stubs read: every character but letters and digits
    as its \\u escape, a character above the basic plane as its two surrogates."""
    out = []
    for unit in range(0, len(text.encode('utf-16-le', 'surrogatepass')), 2):
        code = int.from_bytes(text.encode('utf-16-le', 'surrogatepass')[unit:unit + 2], 'little')
        out.append(chr(code) if chr(code).isascii() and chr(code).isalnum() else '\\u%04x' % code)
    return ''.join(out)


class PinTests(unittest.TestCase):
    def test_the_pins_name_the_committed_source(self):
        pins = reproduce.pins()
        data = SOURCE.read_bytes()
        self.assertEqual((len(data), hashlib.sha256(data).hexdigest()),
                         (pins['source']['bytes'], pins['source']['sha256']))
        self.assertEqual(set(pins), {'schema', 'source', 'jdk', 'javac', 'class', 'r8', 'd8', 'jar'})
        self.assertEqual(pins['schema'], 'andrix-process-health-read-build-v1')
        self.assertEqual(pins['javac'], ['--release', '17', '-Xlint:all', '-Werror'])
        self.assertEqual(pins['d8'], ['--release', '--min-api', '30'])
        self.assertEqual(pins['jar']['name'], 'andrix-process-health-read.jar')

    def test_the_reader_admits_exactly_the_pinned_jar_and_its_one_invocation(self):
        pins = reproduce.pins()
        self.assertEqual(process_health.HELPER_SHA256, pins['jar']['sha256'])
        self.assertEqual(Path(process_health.HELPER).name, pins['jar']['name'])
        for user in (0, 13, 21473):
            self.assertEqual(process_health.command(user), 'CLASSPATH=%s app_process /system/bin ProcessHealthRead %d'
                             % (process_health.HELPER, user))
            self.assertTrue(process_health.read_allowed(process_health.command(user)))
        for user in (-1, 21474, True, '10', 1.0):
            with self.assertRaises(ValueError):
                process_health.command(user)
        for command in (process_health.command(13) + ' 1', process_health.command(13).replace('13', '013'),
                        'CLASSPATH=%s app_process /system/bin ProcessHealthRead 21474' % process_health.HELPER):
            self.assertFalse(process_health.read_allowed(command))
        self.assertEqual(process_health.HEADER, 'andrix-process-health-read-v1')
        self.assertEqual(list(process_health.CAPABILITIES), [c['capability'] for c in signatures()['calls']])
        self.assertEqual(process_health.MAX_USER, signatures()['constants']['max_user']['value'])


class SourceTests(unittest.TestCase):
    def test_the_source_asks_exactly_the_pinned_binder_calls(self):
        code = ' '.join(java_code(SOURCE.read_text()).split())
        s = signatures()
        calls = re.findall(r'Class\.forName\(MANAGER\)\.getMethod\("(\w+)"((?:, \w+\.class)*)\)', code)
        found = [{'method': m, 'parameters': ['java.lang.String' if t == 'String' else t for t in
                                               re.findall(r'(\w+)\.class', types)]} for m, types in calls]
        self.assertEqual(found, [{'method': c['method'], 'parameters': c['parameters']} for c in s['calls']])
        # The history is asked for SystemUI with no PID and no count filter, for the one user.
        self.assertEqual(re.findall(r'call\.invoke\(manager[^)]*\)', code),
                         ['call.invoke(manager, PACKAGE, 0, 0, user)', 'call.invoke(manager)'])
        self.assertIn('private static final String PACKAGE = "com.android.systemui";', code)
        self.assertIn('private static final String SERVICE = "%s";' % s['service']['name'], code)
        self.assertIn('private static final String MANAGER = "%s";' % s['interface'], code)
        self.assertIn('private static final int MAX_USER = %d;' % s['constants']['max_user']['value'], code)
        self.assertEqual(re.findall(r'getMethod\("(\w+)", String\.class\)', code), ['getService'])
        self.assertEqual(re.findall(r'getMethod\("(\w+)", ibinder\)', code), ['asInterface'])
        # Each row's fields come from the record's own getters and fields, as pinned.
        getters = re.findall(r'get\(info, "(\w+)"\)', code)
        self.assertEqual(sorted(set(getters)), sorted(EXIT_GETTERS))
        self.assertEqual(sorted(set(re.findall(r'getField\("(\w+)"\)', code))), sorted(ERROR_FIELDS))
        reads = {r['name'] for r in s['reads']}
        self.assertLessEqual(set(EXIT_GETTERS) | set(ERROR_FIELDS) | {'getList', 'getIdentifier', 'elapsedRealtime'},
                             reads)

    def test_the_source_has_no_mutation_and_no_other_route(self):
        code = java_code(SOURCE.read_text())
        for name in FORBIDDEN:
            self.assertNotIn(name, code)
        self.assertEqual(re.findall(r'import ([\w.]+);', code),
                         ['java.lang.reflect.InvocationTargetException', 'java.lang.reflect.Method',
                          'java.nio.charset.StandardCharsets', 'java.security.MessageDigest',
                          'java.security.NoSuchAlgorithmException', 'java.util.ArrayList', 'java.util.List'])
        # One class: no inner, anonymous or lambda class whose bytes the pins would not name.
        self.assertEqual(len(re.findall(r'(?<![.\w])class\b', code)), 1)
        self.assertNotRegex(code, r'new \w+(<[^>]*>)?\([^)]*\) *\{')
        self.assertNotIn('->', code)

    def test_the_protocol_in_the_source(self):
        code = java_code(SOURCE.read_text())
        self.assertEqual(re.findall(r'HEADER = "([^"]*)"', code), [process_health.HEADER])
        self.assertIn('private static final int MAX_ROWS = %d;' % process_health.MAX_ROWS, code)
        self.assertIn('private static final int MAX_TEXT = %d;' % process_health.MAX_TEXT, code)
        self.assertEqual(re.findall(r'return end\(([^;]*)\);', code),
                         ['"error=arguments", 2', '"error=clock", 3', '"error=clock", 3', '"error=clock", 3',
                          'null, complete ? 0 : 5'])
        self.assertIn('"status=" + (complete ? "complete" : "unavailable")', code)
        self.assertIn('out.append("end=").append(HEADER).append(" lines=").append(lines).append(" sha256=")', code)
        # A failed read is ERROR or UNAVAILABLE with its reason, never zero rows.
        self.assertEqual(sorted(set(re.findall(r'"(ERROR reason=[^"]*|UNAVAILABLE reason=[^"]*)"', code))),
                         ['ERROR reason=', 'ERROR reason=not-a-list', 'ERROR reason=not-a-list-slice',
                          'ERROR reason=not-an-error-state', 'ERROR reason=not-an-exit-info', 'ERROR reason=overflow',
                          'UNAVAILABLE reason=service-absent'])
        self.assertIn('" returned=" + (reply == null ? "null" : "list")', code)
        self.assertIn('text.matches("0|[1-9][0-9]{0,4}")', code)


@unittest.skipUnless(os.environ.get('ANDRIX_FRAMEWORKS_BASE'), 'the pinned frameworks/base tree is not given')
class AidlTests(unittest.TestCase):
    def test_each_pinned_signature_is_the_aidl_declaration(self):
        base = Path(os.environ['ANDRIX_FRAMEWORKS_BASE'])
        s = signatures()

        def line(path, number):
            return (base / path).read_bytes().decode('utf-8').split('\n')[number - 1]
        data = (base / s['aidl']['path']).read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), s['aidl']['sha256'])
        self.assertIn('package android.app;', data.decode())
        self.assertRegex(data.decode(), r'\binterface IActivityManager\s*\{')
        for call in s['calls']:
            self.assertEqual([line(s['aidl']['path'], n) for n in call['lines']], call['declaration'])
            declared = re.fullmatch(r'\s*(\S+) (\w+)\(([^)]*)\);', ' '.join(d.strip() for d in call['declaration']))
            self.assertEqual(declared[2], call['method'])
            self.assertEqual(declared[1].split('<')[0], call['returns'].rsplit('.', 1)[1])
            names = {'String': 'java.lang.String', 'int': 'int'}
            self.assertEqual([names[p.split(' ')[0]] for p in declared[3].split(', ') if p], call['parameters'])
        for pinned in s['reads'] + s['checks'] + list(s['constants'].values()) + [s['service']]:
            self.assertEqual(line(pinned['path'], pinned['line']), pinned['declaration'], pinned['path'])


class RefusalTests(unittest.TestCase):
    """Nothing starts until the work directory and every input are the pinned ones."""

    def refused(self, **arguments):
        with mock.patch.object(reproduce.subprocess, 'run', side_effect=AssertionError('a tool started')):
            with self.assertRaises(reproduce.Refused):
                reproduce.reproduce(**arguments)

    def test_a_work_directory_in_the_repository_or_not_new_is_refused(self):
        self.refused(jdk='/nonexistent', r8='/nonexistent', work=ROOT / 'tests' / 'process-health-read' / 'out')
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
            changed = Path(directory) / 'ProcessHealthRead.java'
            changed.write_bytes(SOURCE.read_bytes().replace(b'PACKAGE, 0, 0, user', b'PACKAGE, 0, 1, user'))
            pins = reproduce.pins()
            with self.assertRaises(reproduce.Refused):
                reproduce.pinned_file(changed, pins['source']['bytes'], pins['source']['sha256'], 'the helper source')


def _tools():
    return os.environ.get('ANDRIX_PROCESS_HEALTH_READ_JDK') and os.environ.get('ANDRIX_PROCESS_HEALTH_READ_R8')


@unittest.skipUnless(_tools(), 'the pinned JDK and r8 jar are not given')
class RebuildTests(unittest.TestCase):
    def test_the_source_rebuilds_to_the_pinned_jar(self):
        with scratch() as directory:
            work = Path(directory) / 'work'
            record = reproduce.reproduce(os.environ['ANDRIX_PROCESS_HEALTH_READ_JDK'],
                                         os.environ['ANDRIX_PROCESS_HEALTH_READ_R8'], work)
            pins = reproduce.pins()
            self.assertEqual(record['status'], 'PASS', record.get('problem'))
            self.assertEqual(record['jar'], {'bytes': pins['jar']['bytes'], 'sha256': pins['jar']['sha256']})
            data = (work / pins['jar']['name']).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), process_health.HELPER_SHA256)


ROW = (1791504000123, 4734, 1310112, 1310112, 1310112, 13, 'com.android.systemui', 4, 0, 0)


def row(**changes):
    value = dict(zip(process_health.ROW_FIELDS, ROW))
    value.update(changes)
    return value


@unittest.skipUnless(os.environ.get('ANDRIX_PROCESS_HEALTH_READ_JDK'), 'the pinned JDK is not given')
class HostRunTests(unittest.TestCase):
    """The pinned class file run on the host JVM against the stub services."""

    @classmethod
    def setUpClass(cls):
        # The class's scratch is removed even when this setup fails part way.
        directory = scratch()
        cls.addClassCleanup(directory.cleanup)
        cls.work = Path(directory.name)
        jdk = Path(os.environ['ANDRIX_PROCESS_HEALTH_READ_JDK']) / 'bin'
        cls.java = jdk / 'java'
        options = ['-J' + o for o in reproduce.JVM_LIMITS]
        pins = reproduce.pins()
        (cls.work / 'helper').mkdir()
        code, _, err = bounded([jdk / 'javac', *options, *pins['javac'], '-d', 'helper', SOURCE], cls.work)
        assert code == 0, err
        compiled = (cls.work / 'helper' / pins['class']['name']).read_bytes()
        assert (len(compiled), hashlib.sha256(compiled).hexdigest()) == (pins['class']['bytes'], pins['class']['sha256'])
        for name, edit in (('stubs', None), ('wrong', ('int maxNum,\n            int userId)', 'int maxNum)'))):
            tree = cls.work / (name + '-src')
            for path in STUBS.rglob('*.java'):
                target = tree / path.relative_to(STUBS)
                target.parent.mkdir(parents=True, exist_ok=True)
                text = path.read_text()
                if edit is not None and path.name == 'IActivityManager.java':
                    text = text.replace(*edit).replace('int pid, int maxNum, int userId) throws',
                                                       'int pid, int maxNum) throws').replace(
                        ' + maxNum + ","\n                            + userId + ")");', ' + maxNum + ")");')
                    assert 'int userId' not in text
                target.write_text(text)
            (cls.work / name).mkdir()
            sources = sorted(str(p) for p in tree.rglob('*.java'))
            code, _, err = bounded([jdk / 'javac', *options, '--release', '17', '-d', name, *sources], cls.work)
            assert code == 0, err

    def run_helper(self, args, script=None, stubs='stubs'):
        trace, properties = self.work / 'trace.txt', self.work / 'script.properties'
        for path in (trace, properties):
            if path.exists():
                path.unlink()
        lines = []
        for key, value in sorted((script or {}).items()):
            lines.append('%s=%s' % (key, escape(value) if isinstance(value, str) else
                                    '\\t'.join(escape(str(v)) for v in value)))
        properties.write_text('\n'.join(lines) + '\n')
        code, out, err = bounded([self.java, '-Xmx64m', '-XX:+UseSerialGC', '-Dandrix.script=%s' % properties,
                                  '-Dandrix.trace=%s' % trace, '-cp', '%s:%s' % (self.work / stubs, self.work / 'helper'),
                                  'ProcessHealthRead', *args], self.work)
        calls = trace.read_text().split('\n')[:-1] if trace.exists() else []
        return code, out, err, calls

    @staticmethod
    def samples(out):
        return [[int(e), int(w)] for e, w in re.findall(r'sample=\w+ elapsed=(\d+) wall=(\d+)', out)]

    def test_every_row_is_printed_whole_and_the_sim_prints_the_same_form(self):
        rows = [row(), row(timestamp=1791503000000, pid=4700, process='com.android.systemui:screen shot-x', reason=3,
                          status=9)]
        entries = [{'condition': 1, 'pid': 4734, 'uid': 1310112, 'process': 'com.android.systemui', 'tag': None,
                    'short': 'java.lang.RuntimeException: boom', 'long': 'long one\nline two',
                    'stack': 'stack \u00e9\U0001F600'}]
        script = {'errors.answer': 'list', 'clock.elapsed': '50000,50001,50002,50003,50004'}
        for i, r in enumerate(rows):
            script['history.%d' % i] = [r[f] for f in process_health.ROW_FIELDS]
        for i, e in enumerate(entries):
            script['errors.%d' % i] = [e['condition'], e['pid'], e['uid'], e['process'], '\x00null', e['short'],
                                       e['long'], e['stack']]
        code, out, err, calls = self.run_helper(['13'], script)
        self.assertEqual((code, err), (0, ''))
        self.assertEqual(calls, ['getService(activity)', 'asInterface()',
                                 'getHistoricalProcessExitReasons(com.android.systemui,0,0,13)', 'getList()',
                                 'getProcessesInErrorState()'])
        samples = self.samples(out)
        self.assertEqual([s[0] for s in samples], [50001, 50002, 50003, 50004])
        reading = process_health.parse_reply(code, out, err, 13)
        self.assertEqual(reading['history']['rows'][1][6], 'com.android.systemui:screen%20shot%2Dx')
        self.assertEqual(process_health.decode_text(reading['current']['entries'][0][10]), 'stack \u00e9\U0001F600')
        self.assertEqual(reading['current']['entries'][0][11], 9)
        # The simulated guest's form is the helper's own, byte for byte.
        self.assertEqual(sim_android.process_health_reply(13, ('OK', rows), ('OK', entries), samples), (code, out))

    def test_a_complete_empty_reply_is_whole_and_null_is_no_current_error(self):
        code, out, err, calls = self.run_helper(['0'])
        self.assertEqual((code, err), (0, ''))
        reading = process_health.parse_reply(code, out, err, 0)
        self.assertTrue(reading['complete'])
        self.assertEqual((reading['history']['rows'], reading['current']['entries'], reading['current']['returned']),
                         ([], [], 'null'))
        self.assertIn('current-errors status=OK count=0 returned=null', out.split('\n'))
        self.assertEqual(sim_android.process_health_reply(0, ('OK', []), ('OK', []), self.samples(out)), (code, out))
        # An empty list, which the service never returns, is printed as it came: no known form.
        code, out, err, _ = self.run_helper(['0'], {'errors.answer': 'list'})
        self.assertIn('current-errors status=OK count=0 returned=list', out.split('\n'))
        with self.assertRaises(process_health.FormError):
            process_health.parse_reply(code, out, err, 0)

    def test_an_exception_or_an_absent_service_is_never_zero_rows(self):
        cases = {'denied': ({'history.answer': 'throw:java.lang.SecurityException'},
                            'history status=ERROR reason=java.lang.SecurityException'),
                 'remote': ({'errors.answer': 'throw:android.os.RemoteException'},
                            'current-errors status=ERROR reason=android.os.RemoteException'),
                 'user': ({'history.answer': 'throw:java.lang.IllegalArgumentException'},
                          'history status=ERROR reason=java.lang.IllegalArgumentException'),
                 'no slice': ({'history.answer': 'null'}, 'history status=ERROR reason=not-a-list'),
                 'no list': ({'history.answer': 'list-null'}, 'history status=ERROR reason=not-a-list'),
                 'a getter': ({'history.0': [*ROW, 'getReason']}, 'history status=ERROR reason=java.lang.IllegalStateException')}
        for name, (script, line) in cases.items():
            with self.subTest(name):
                code, out, err, _ = self.run_helper(['13'], dict(script, **{'history.1': list(ROW)}))
                self.assertEqual((code, err), (5, ''))
                self.assertIn(line, out.split('\n'))
                self.assertNotIn('history row=', out)
                reading = process_health.parse_reply(code, out, err, 13)
                self.assertFalse(reading['complete'])
        code, out, err, calls = self.run_helper(['13'], {'service.absent': 'true'})
        self.assertEqual(code, 5)
        self.assertIn('history status=UNAVAILABLE reason=service-absent', out.split('\n'))
        self.assertIn('current-errors status=UNAVAILABLE reason=service-absent', out.split('\n'))
        self.assertEqual(calls, ['getService(activity)'])
        self.assertFalse(process_health.parse_reply(code, out, err, 13)['complete'])

    def test_a_wrong_signature_or_an_overflow_is_an_error(self):
        code, out, err, calls = self.run_helper(['13'], {'history.0': list(ROW)}, stubs='wrong')
        self.assertEqual(code, 5)
        self.assertIn('history status=ERROR reason=java.lang.NoSuchMethodException', out.split('\n'))
        self.assertNotIn('getHistoricalProcessExitReasons(com.android.systemui,0,0)', calls)
        script = {'history.%d' % i: list(ROW) for i in range(process_health.MAX_ROWS + 1)}
        code, out, err, _ = self.run_helper(['13'], script)
        self.assertIn('history status=ERROR reason=overflow', out.split('\n'))
        self.assertFalse(process_health.parse_reply(code, out, err, 13)['complete'])
        script.pop('history.%d' % process_health.MAX_ROWS)
        code, out, err, _ = self.run_helper(['13'], script)
        self.assertEqual(len(process_health.parse_reply(code, out, err, 13)['history']['rows']), process_health.MAX_ROWS)
        long_name = 'com.android.systemui:' + 'x' * process_health.MAX_TEXT
        code, out, err, _ = self.run_helper(['13'], {'history.0': [*ROW[:6], long_name, *ROW[7:]]})
        self.assertIn('history status=ERROR reason=overflow', out.split('\n'))

    def test_diagnostic_strings_are_bounded_with_their_whole_length(self):
        stack = 'a' * 255 + '\U0001F600' + 'b' * 40
        script = {'errors.answer': 'list', 'errors.0': [2, 4734, 1310112, 'com.android.systemui', 'Tag', 'ANR',
                                                        'x' * 1000, stack]}
        code, out, err, _ = self.run_helper(['13'], script)
        self.assertEqual(code, 0)
        reading = process_health.parse_reply(code, out, err, 13)
        entry = reading['current']['entries'][0]
        self.assertEqual((process_health.decode_text(entry[8]), entry[9]), ('x' * 256, 1000))
        # The cut never splits the surrogate pair at the bound.
        self.assertEqual((process_health.decode_text(entry[10]), entry[11]), ('a' * 255, 297))
        self.assertEqual(sim_android.process_health_reply(13, ('OK', []), ('OK', [{
            'condition': 2, 'pid': 4734, 'uid': 1310112, 'process': 'com.android.systemui', 'tag': 'Tag', 'short': 'ANR',
            'long': 'x' * 1000, 'stack': stack}]), self.samples(out)), (code, out))

    def test_only_one_bounded_user_id_is_accepted_and_a_clock_failure_reads_nothing(self):
        for args in ([], ['1', '2'], ['21474'], ['010'], ['-1'], ['+1'], ['1x'], [''], ['99999999999']):
            with self.subTest(args):
                code, out, err, calls = self.run_helper(args)
                self.assertEqual((code, err, calls), (2, '', []))
                self.assertEqual(out.split('\n')[:2], [process_health.HEADER, 'error=arguments'])
                with self.assertRaises(process_health.FormError):
                    process_health.parse_reply(code, out, err, 0)
        code, out, _, calls = self.run_helper(['21473'])
        self.assertEqual((code, out.split('\n')[1]), (0, 'user=21473'))
        code, out, err, calls = self.run_helper(['13'], {'clock.fails': 'true'})
        self.assertEqual((code, calls), (3, []))
        self.assertEqual(out.split('\n')[1], 'error=clock')
        with self.assertRaises(process_health.FormError):
            process_health.parse_reply(code, out, err, 13)


@unittest.skipUnless(_tools() and os.environ.get('ANDRIX_PROCESS_HEALTH_READ_DEXDUMP'),
                     'the pinned JDK, r8 jar and a dexdump are not given')
class DexTests(unittest.TestCase):
    def test_the_dex_holds_only_the_pinned_names_and_reflective_calls(self):
        with scratch() as directory:
            work = Path(directory) / 'work'
            record = reproduce.reproduce(os.environ['ANDRIX_PROCESS_HEALTH_READ_JDK'],
                                         os.environ['ANDRIX_PROCESS_HEALTH_READ_R8'], work)
            self.assertEqual(record['status'], 'PASS', record.get('problem'))
            code, out, _ = bounded([os.environ['ANDRIX_PROCESS_HEALTH_READ_DEXDUMP'], '-d',
                                    reproduce.pins()['jar']['name']], work)
            self.assertEqual(code, 0)
        strings = set(re.findall(r'const-string[^"]*"([^"]*)"', out))
        calls = {c['method'] for c in signatures()['calls']}
        named = {s for s in strings if re.fullmatch(r'[a-z][A-Za-z]+', s) and s.startswith(('get', 'as', 'elapsed'))}
        self.assertEqual(named, calls | set(EXIT_GETTERS) | {'getService', 'asInterface', 'getList', 'getIdentifier',
                                                             'elapsedRealtime'})
        self.assertLessEqual(set(ERROR_FIELDS), strings)
        for name in FORBIDDEN:
            self.assertFalse(any(name.rstrip('(') in s for s in strings), name)
        invoked = set(re.findall(r'invoke-[a-z/]+ \{[^}]*\}, (L[^;]+;)\.', out))
        self.assertEqual(invoked, {'LProcessHealthRead;', 'Ljava/io/PrintStream;', 'Ljava/lang/Character;',
                                   'Ljava/lang/Class;', 'Ljava/lang/IllegalStateException;', 'Ljava/lang/Integer;',
                                   'Ljava/lang/Long;', 'Ljava/lang/Math;', 'Ljava/lang/Object;', 'Ljava/lang/String;',
                                   'Ljava/lang/StringBuilder;', 'Ljava/lang/System;', 'Ljava/lang/reflect/Field;',
                                   'Ljava/lang/reflect/InvocationTargetException;', 'Ljava/lang/reflect/Method;',
                                   'Ljava/security/MessageDigest;', 'Ljava/util/ArrayList;', 'Ljava/util/Iterator;',
                                   'Ljava/util/List;'})


if __name__ == '__main__':
    unittest.main()
