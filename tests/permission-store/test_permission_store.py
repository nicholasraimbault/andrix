# SPDX-License-Identifier: Apache-2.0
"""Host checks for the offline permission store reader.

Profile, intake, argument, output, command line, decode flow and resource guard checks always
run. Pinned source checks need ANDRIX_SOURCE_ROOT. JVM checks start a JDK only when the resource
guard passes; they run the pinned parser on a host JVM and are not Android runtime evidence.
"""
from pathlib import Path
import copy
import io
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import permission_store as ps  # noqa: E402

PASS = 'PERMISSION_STORE_HOST_CHECKS_PASS_NO_ANDROID_CLAIM'
IDS = [10123, 10124, 10125, 10126, 10127, 10999]
DEFENSIVE_CODES = {'event_accounting', 'post_end_probe'}
NOT_CODES = {'access', 'permission', 'id', 'name', 'flags', 'permission_absent',
             'app_id_absent', 'data', 'parsed', 'refused', 'null'}
DECODE_KEYS = {'schema', 'result', 'requested_app_ids', 'input', 'document', 'app_ids',
               'refusal', 'not_run', 'provenance', 'scope'}
SOURCES_KEYS = {'schema', 'result', 'not_run', 'provenance'}


def java_code(text):
    """Java source without comments, string literals or character literals."""
    out, i, n = [], 0, len(text)
    while i < n:
        if text.startswith('//', i):
            i = text.find('\n', i)
            i = n if i < 0 else i
        elif text.startswith('/*', i):
            end = text.find('*/', i + 2)
            i = n if end < 0 else end + 2
        elif text[i] in '"\'':
            quote, i = text[i], i + 1
            while i < n and text[i] != quote:
                i += 2 if text[i] == '\\' else 1
            i += 1
            out.append('""')
        else:
            out.append(text[i])
            i += 1
    return ''.join(out)


def snake_literals(text):
    return set(re.findall(r'"([a-z]+(?:_[a-z]+)*)"', text))


def completed(value, returncode=None, text=None):
    if text is None:
        text = json.dumps(value, separators=(',', ':')) + '\n'
    if returncode is None:
        returncode = 0 if value.get('result') == 'parsed' else 1
    return subprocess.CompletedProcess(['reader'], returncode, text.encode('ascii'), b'')


def parsed_output(data, app_ids, states=None):
    states = states or [('flags', 24624)] * len(app_ids)
    return {'schema': ps.READER_SCHEMA, 'result': 'parsed',
            'input': {'length': len(data), 'sha256': ps.sha(data)},
            'document': {'elements': 4, 'app_id_entries': 1, 'permission_entries': 1},
            'app_ids': [{'app_id': app_id, 'state': state, 'flags': flags}
                        for app_id, (state, flags) in zip(app_ids, states)]}


def refused_output(data, code='trailing_bytes'):
    return {'schema': ps.READER_SCHEMA, 'result': 'refused',
            'input': {'length': len(data), 'sha256': ps.sha(data)},
            'refusal': {'code': code, 'exception': None, 'offset': len(data), 'step': 3}}


class ProfileTests(unittest.TestCase):
    def test_profile_names_the_expected_sources(self):
        value = ps.profile()
        self.assertEqual([entry['path'] for entry in value['compile']], list(ps.COMPILE_SOURCES))
        self.assertEqual([entry['path'] for entry in value['reference']],
                         list(ps.REFERENCE_SOURCES))
        self.assertEqual([entry['path'] for entry in value['store']], list(ps.STORE_SOURCES))
        self.assertEqual(value['jdk']['path'], 'prebuilts/jdk/jdk25/linux-x86')
        self.assertFalse(value['git_revisions_checked'])
        every = ps.COMPILE_SOURCES + ps.REFERENCE_SOURCES + ps.STORE_SOURCES
        self.assertEqual(len(set(every)), len(every))

    def test_profile_refuses_drift(self):
        original = json.loads(ps.PROFILE.read_text())

        def variant(change):
            value = copy.deepcopy(original)
            change(value)
            return json.dumps(value).encode()

        drifted = [
            variant(lambda v: v.update(extra=1)),
            variant(lambda v: v.pop('scope')),
            variant(lambda v: v.pop('store')),
            variant(lambda v: v.update(version=True)),
            variant(lambda v: v.update(version=2)),
            variant(lambda v: v.update(status='applied')),
            variant(lambda v: v.update(git_revisions_checked=True)),
            variant(lambda v: v.update(source_release='')),
            variant(lambda v: v['compile'].reverse()),
            variant(lambda v: v['compile'].pop()),
            variant(lambda v: v['store'].reverse()),
            variant(lambda v: v['store'].pop()),
            variant(lambda v: v['reference'].append(copy.deepcopy(v['reference'][0]))),
            variant(lambda v: v['compile'][0].update(path='../' + v['compile'][0]['path'])),
            variant(lambda v: v['store'][0].update(path='/' + v['store'][0]['path'])),
            variant(lambda v: v['compile'][0].update(sha256=v['compile'][0]['sha256'].upper())),
            variant(lambda v: v['compile'][0].update(sha256=v['compile'][0]['sha256'][:63])),
            variant(lambda v: v['compile'][0].update(size=0)),
            variant(lambda v: v['compile'][0].update(size=True)),
            variant(lambda v: v['compile'][0].update(size=ps.MAX_SOURCE_BYTES + 1)),
            variant(lambda v: v['compile'][0].update(extra='x')),
            variant(lambda v: v['jdk'].update(path='/opt/jdk')),
            variant(lambda v: v['jdk'].update(java_version='25.0')),
            variant(lambda v: v['jdk'].update(release_sha256='0' * 63)),
            ps.PROFILE.read_bytes().replace(b'"version": 1', b'"version": 1, "version": 1', 1),
            ps.PROFILE.read_bytes().replace(b'"size": 32593', b'"size": NaN', 1),
            b'\xff',
            b'[',
        ]
        for data in drifted:
            with self.subTest(data=data[:80]), self.assertRaises(ps.ProfileDrift):
                ps.profile(data)
        self.assertTrue(issubclass(ps.ProfileDrift, ValueError))
        self.assertEqual(ps.profile(json.dumps(original).encode())['version'], 1)


class ToolSourceTests(unittest.TestCase):
    def test_facades_are_compile_only(self):
        expected = {
            'facades/android/text/TextUtils.java': (
                'package android.text;', ['isGraphic'], []),
            'facades/android/util/Base64.java': (
                'package android.util;', ['encodeToString', 'decode'], ['NO_WRAP']),
        }
        for name, (package, methods, constants) in expected.items():
            with self.subTest(name):
                text = (HERE / name).read_text()
                code = java_code(text)
                self.assertIn(package, text)
                self.assertNotIn('import', code)
                self.assertEqual(re.findall(r'public static \w+(?:\[\])? (\w+)\(', code), methods)
                self.assertEqual(re.findall(r'public static final int (\w+) =', code), constants)
                self.assertEqual(code.count('throw new UnsupportedOperationException('),
                                 len(methods))
                self.assertEqual(len(re.findall(r';', code)), len(methods) + len(constants) + 1)

    def test_java_sources_have_no_assert_reflection_process_or_network(self):
        for path in [ps.READER, ps.CHECKS, *(HERE / name for name in ps.FACADES)]:
            with self.subTest(path.name):
                code = java_code(path.read_text())
                for forbidden in (r'\bassert\b', r'setAccessible', r'java\.lang\.reflect',
                                  r'getDeclared', r'ProcessBuilder', r'Runtime\.getRuntime',
                                  r'java\.net', r'Socket', r'\bURL\b', r'VarHandle',
                                  r'MethodHandles', r'Unsafe'):
                    self.assertIsNone(re.search(forbidden, code), forbidden)
        reader = java_code(ps.READER.read_text())
        for forbidden in ('FileOutputStream', 'Files.', 'RandomAccessFile', 'FileWriter'):
            self.assertNotIn(forbidden, reader)

    def test_reader_overrides_only_the_parser_hook_and_checked_reads(self):
        code = java_code(ps.READER.read_text())
        self.assertEqual(re.findall(r'extends (\w+)', code),
                         ['InputStream', 'IOException', 'FastDataInput', 'BinaryXmlPullParser',
                          'Exception'])
        parser = code[code.index('class RecordingParser'):code.index('class Refusal')]
        self.assertEqual(re.findall(r'@Override\s+(?:public|protected) \w+ (\w+)\(', parser),
                         ['obtainFastDataInput'])
        recorder = code[code.index('class RecordingInput'):code.index('class RecordingParser')]
        reads = ['readByte', 'readUTF', 'readInternedUTF']
        self.assertEqual(re.findall(r'@Override\s+(?:public|protected) \w+ (\w+)\(', recorder),
                         reads)
        # Each checked read delegates to the pinned method once and returns its value.
        self.assertEqual(re.findall(r'super\.(\w+)\(', recorder), reads)
        self.assertIn('super(source, DEFAULT_BUFFER_SIZE);', code)
        # Strings are checked only with pinned routines; there is no second codec.
        self.assertEqual(re.findall(r'ModifiedUtf8\.(\w+)\(', code), ['countBytes', 'encode'])
        # Only the pinned protected buffer positions are read, never a private field.
        self.assertEqual(set(re.findall(r'\bm[A-Z]\w*', code)), {'mBufferLim', 'mBufferPos'})
        self.assertIn('interned.size() < MAX_UNSIGNED_SHORT', code)

    def test_refusal_codes_match_the_tool_and_the_checks(self):
        reader = snake_literals(ps.READER.read_text()) - NOT_CODES
        self.assertEqual(reader, set(ps.READER_REFUSALS) | {'input_too_large'})
        checks = snake_literals(ps.CHECKS.read_text()) & (set(ps.READER_REFUSALS)
                                                           | {'input_too_large'})
        self.assertEqual(checks, set(ps.READER_REFUSALS) - DEFENSIVE_CODES | {'input_too_large'})

    def test_reader_bounds_match_the_tool(self):
        text = ps.READER.read_text()

        def constant(name):
            return re.search(r'static final int ' + name + r' = ([^;]+);', text)[1]

        self.assertEqual(constant('MAX_INPUT_BYTES'), '8 * 1024 * 1024')
        self.assertEqual(8 * 1024 * 1024, ps.MAX_INPUT_BYTES)
        self.assertEqual(int(constant('MIN_APP_ID').replace('_', '')), ps.MIN_APP_ID)
        self.assertEqual(int(constant('MAX_APP_ID').replace('_', '')), ps.MAX_APP_ID)
        self.assertEqual(int(constant('MAX_REQUESTED_APP_IDS')), ps.MAX_APP_IDS)
        self.assertEqual((constant('MAX_DEPTH'), constant('MAX_ATTRIBUTES')), ('32', '64'))
        self.assertEqual((constant('EXIT_PARSED'), constant('EXIT_REFUSED')), ('0', '1'))
        self.assertIn('"' + ps.READER_SCHEMA + '"', text)

    def test_jvm_options_bound_resources_and_fatal_errors(self):
        for flag in ('-Xmx512m', '-XX:ActiveProcessorCount=2', '-XX:+ExitOnOutOfMemoryError',
                     '-XX:-UsePerfData', '-XX:+DisableAttachMechanism',
                     '-XX:-CreateCoredumpOnCrash', '-XX:+ErrorFileToStderr',
                     '-XX:-DumpReplayDataOnError'):
            self.assertIn(flag, ps.JVM_BOUNDS)
        work = Path('/scratch')
        self.assertEqual(ps._private(work), ('-XX:ErrorFile=/scratch/hs_err_%p.log',
                                             '-Djava.io.tmpdir=/scratch'))
        self.assertEqual(set(ps.ENVIRONMENT), {'LC_ALL', 'LANG', 'TZ'})

    def test_sources_are_ascii_and_licensed(self):
        for path in sorted(HERE.rglob('*')):
            if path.is_file() and path.suffix in ('.java', '.py', '.json', '.md'):
                with self.subTest(path.name):
                    data = path.read_bytes()
                    self.assertTrue(data.isascii())
                    if path.suffix in ('.java', '.py'):
                        self.assertIn(b'SPDX-License-Identifier: Apache-2.0', data)


class ArgumentTests(unittest.TestCase):
    def test_app_id_argument_bounds_and_syntax(self):
        for text in ('10000', '19999', '12345'):
            self.assertEqual(ps.app_id_argument(text), int(text))
        for text in ('9999', '20000', '0', '010000', '+10000', '-10000', '1e4', ' 10000',
                     '10000 ', '100000', '', '0x2710', '\uff11\uff10\uff10\uff10\uff10'):
            with self.subTest(text=text), self.assertRaises(Exception):
                ps.app_id_argument(text)

    def test_validate_app_ids(self):
        self.assertEqual(ps.validate_app_ids([10000, 19999]), [10000, 19999])
        many = list(range(10000, 10000 + ps.MAX_APP_IDS + 1))
        self.assertEqual(len(ps.validate_app_ids(many[:-1])), ps.MAX_APP_IDS)
        for values in ([], many, [10000, 10000], [9999], [20000], [True], [10000.0], ['10000']):
            with self.subTest(values=values[:3]), self.assertRaises(ValueError):
                ps.validate_app_ids(values)

    def test_cli_refuses_invalid_or_duplicate_app_ids(self):
        base = ['decode', '--source-root', '/nonexistent', '--input', '/nonexistent']
        for extra in (['--app-id', '9999'], ['--app-id', '10000', '--app-id', '10000'], []):
            with self.subTest(extra=extra), mock.patch('sys.stderr'), \
                    self.assertRaises(SystemExit) as raised:
                ps.main(base + extra)
            self.assertEqual(raised.exception.code, 2)


class OpenRecorder:
    """Records every os.open call, delegating to the real one.

    after_capture runs right after an O_PATH open returns. reopen, if set, replaces the path of
    the /proc/self/fd reopen with another file.
    """

    def __init__(self, after_capture=None, reopen=None):
        self.real = os.open
        self.calls = []
        self.after_capture = after_capture
        self.reopen = reopen

    def __call__(self, path, flags, *args, **kwargs):
        path = os.fspath(path)
        self.calls.append((path, flags))
        if self.reopen is not None and path.startswith(ps.PROC_FD):
            path = os.fspath(self.reopen)
        fd = self.real(path, flags, *args, **kwargs)
        if self.after_capture is not None and flags & os.O_PATH:
            self.after_capture()
        return fd

    def readable(self):
        return [call for call in self.calls if not call[1] & os.O_PATH]


class IntakeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def refusal(self, path, recorder=None):
        recorder = recorder or OpenRecorder()
        with mock.patch.object(ps.os, 'open', side_effect=recorder), \
                self.assertRaises(ps.InputRefusal) as raised:
            ps.read_input(path)
        return raised.exception, recorder

    def test_flags(self):
        self.assertEqual(ps.PATH_FLAGS, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.assertFalse(ps.READ_FLAGS & (os.O_NOFOLLOW | os.O_PATH | os.O_ACCMODE))
        self.assertEqual(ps.READ_FLAGS & os.O_ACCMODE, os.O_RDONLY)

    def test_regular_file_is_captured_then_read_exactly(self):
        path = self.root / 'access.abx'
        path.write_bytes(b'ABX\x00\x10\x11')
        recorder = OpenRecorder()
        with mock.patch.object(ps.os, 'open', side_effect=recorder):
            self.assertEqual(ps.read_input(path), b'ABX\x00\x10\x11')
        [(first, first_flags), (second, second_flags)] = recorder.calls
        self.assertEqual((first, first_flags), (str(path), ps.PATH_FLAGS))
        self.assertRegex(second, r'^/proc/self/fd/[0-9]+$')
        self.assertEqual(second_flags, ps.READ_FLAGS)

    def test_final_symlink_is_refused_without_a_readable_open(self):
        target = self.root / 'target'
        target.write_bytes(b'ABX\x00')
        link = self.root / 'link'
        link.symlink_to(target)
        refusal, recorder = self.refusal(link)
        self.assertEqual(refusal.code, 'input_symlink')
        self.assertEqual((recorder.calls, recorder.readable()), ([(str(link), ps.PATH_FLAGS)], []))
        loop = self.root / 'loop'
        loop.symlink_to(loop)
        self.assertEqual(self.refusal(loop)[0].code, 'input_symlink')

    def test_special_files_are_refused_without_a_readable_open(self):
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(server.close)
        # A short path through the directory descriptor: temporary paths can exceed the
        # AF_UNIX path limit.
        directory = os.open(self.root, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, directory)
        server.bind('%s%d/socket' % (ps.PROC_FD, directory))

        def blocked(*_):
            raise TimeoutError('intake blocked')

        previous = signal.signal(signal.SIGALRM, blocked)
        signal.alarm(10)
        try:
            for path in (fifo, self.root, Path('/dev/null'), self.root / 'socket'):
                with self.subTest(path=path):
                    refusal, recorder = self.refusal(path)
                    self.assertEqual(refusal.code, 'input_not_regular')
                    self.assertEqual(recorder.readable(), [])
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)

    def test_size_bound_is_checked_before_a_readable_open(self):
        path = self.root / 'large'
        with open(path, 'wb') as handle:
            handle.truncate(ps.MAX_INPUT_BYTES + 1)
        with mock.patch.object(ps.os, 'read', side_effect=AssertionError('read')):
            refusal, recorder = self.refusal(path)
        self.assertEqual((refusal.code, recorder.readable()), ('input_too_large', []))
        with open(path, 'wb') as handle:
            handle.truncate(ps.MAX_INPUT_BYTES)
        self.assertEqual(len(ps.read_input(path)), ps.MAX_INPUT_BYTES)

    def test_captured_object_is_read_after_the_path_is_replaced(self):
        path = self.root / 'access.abx'
        path.write_bytes(b'captured')
        replacement = self.root / 'replacement'
        replacement.write_bytes(b'replaced')
        recorder = OpenRecorder(after_capture=lambda: os.replace(replacement, path))
        with mock.patch.object(ps.os, 'open', side_effect=recorder):
            self.assertEqual(ps.read_input(path), b'captured')
        self.assertEqual(path.read_bytes(), b'replaced')

    def test_reopened_object_must_be_the_captured_object(self):
        path = self.root / 'access.abx'
        path.write_bytes(b'captured')
        other = self.root / 'other'
        other.write_bytes(b'captured')
        refusal, recorder = self.refusal(path, OpenRecorder(reopen=other))
        self.assertEqual(refusal.code, 'input_changed')
        self.assertEqual(len(recorder.readable()), 1)

    def test_parent_directories_resolve_normally(self):
        # A documented limit: only the final component is captured without following.
        real = self.root / 'real'
        real.mkdir()
        (real / 'access.abx').write_bytes(b'ABX\x00')
        (self.root / 'linked').symlink_to(real, target_is_directory=True)
        self.assertEqual(ps.read_input(self.root / 'linked' / 'access.abx'), b'ABX\x00')

    def test_open_failures_name_only_the_error(self):
        refusal, _ = self.refusal(self.root / 'missing')
        self.assertEqual((refusal.code, refusal.exception), ('input_open_failed', 'OSError:ENOENT'))
        loop = self.root / 'loop'
        loop.symlink_to(loop)
        refusal, _ = self.refusal(loop / 'access.abx')
        self.assertEqual((refusal.code, refusal.exception), ('input_open_failed', 'OSError:ELOOP'))

    def test_changes_during_reading_are_refused(self):
        path = self.root / 'access.abx'
        path.write_bytes(b'0123456789')
        # Capture and reopen differ, then the reopened object changes while it is read.
        for identities in ([1, 2], [1, 1, 2, 1]):
            with self.subTest(identities=identities), \
                    mock.patch.object(ps, '_identity', side_effect=identities):
                self.assertEqual(self.refusal(path)[0].code, 'input_changed')
        real_read = os.read
        grown = iter([True])

        def growing(fd, size):
            data = real_read(fd, size)
            return data + b'x' if data and next(grown, False) else data

        with mock.patch.object(ps.os, 'read', side_effect=growing):
            self.assertEqual(self.refusal(path)[0].code, 'input_changed')


class ReaderOutputTests(unittest.TestCase):
    data = b'ABX\x00example bytes'

    def accepted(self, value, **options):
        return ps.reader_result(completed(value, **options), self.data, [10123, 10124])

    def refused(self, value, **options):
        with self.assertRaises(ValueError):
            ps.reader_result(completed(value, **options), self.data, [10123, 10124])

    def test_valid_outputs_are_accepted(self):
        states = [('flags', -(1 << 31)), ('app_id_absent', None)]
        self.assertEqual(self.accepted(parsed_output(self.data, [10123, 10124], states))
                         ['app_ids'][0]['flags'], -(1 << 31))
        for code in ('trailing_bytes', 'noncanonical_string', 'duplicate_interned_string'):
            with self.subTest(code=code):
                self.assertEqual(self.accepted(refused_output(self.data, code))['refusal']['code'],
                                 code)

    def test_malformed_outputs_are_refused(self):
        good = parsed_output(self.data, [10123, 10124])

        def variant(change, base=good):
            value = copy.deepcopy(base)
            change(value)
            return value

        for value in [
            variant(lambda v: v.update(extra=1)),
            variant(lambda v: v.pop('document')),
            variant(lambda v: v.update(schema='other')),
            variant(lambda v: v['input'].update(length=True)),
            variant(lambda v: v['input'].update(length=len(self.data) + 1)),
            variant(lambda v: v['input'].update(sha256='0' * 64)),
            variant(lambda v: v.update(input=None)),
            variant(lambda v: v['app_ids'].reverse()),
            variant(lambda v: v['app_ids'].pop()),
            variant(lambda v: v['app_ids'][0].update(flags=True)),
            variant(lambda v: v['app_ids'][0].update(flags=1 << 31)),
            variant(lambda v: v['app_ids'][0].update(flags=None)),
            variant(lambda v: v['app_ids'][1].update(state='app_id_absent')),
            variant(lambda v: v['app_ids'][0].update(state='granted')),
            variant(lambda v: v['app_ids'][0].update(state=['flags'])),
            variant(lambda v: v['app_ids'][0].update(extra=1)),
            variant(lambda v: v['document'].update(elements=2)),
            variant(lambda v: v['document'].update(elements=-1)),
            variant(lambda v: v.update(result='partial')),
            variant(lambda v: v.update(result=['parsed'])),
        ]:
            with self.subTest(value=value):
                self.refused(value)
        bad_refusals = refused_output(self.data)
        for change in [lambda r: r.update(code='unknown'),
                       lambda r: r.update(code='input_too_large'),
                       lambda r: r.update(code=['trailing_bytes']),
                       lambda r: r.update(code={'trailing_bytes': 1}),
                       lambda r: r.update(exception='java.io.EOFException: bytes'),
                       lambda r: r.update(offset=len(self.data) + 1),
                       lambda r: r.update(step=-1), lambda r: r.update(extra=1)]:
            value = copy.deepcopy(bad_refusals)
            change(value['refusal'])
            with self.subTest(refusal=value['refusal']):
                self.refused(value)
        self.refused(good, returncode=1)
        self.refused(bad_refusals, returncode=0)
        text = json.dumps(good)
        for framing in [text, text + '\n\n', text + '\n' + text + '\n',
                        text.replace('"parsed"', '"parsed", "result": "parsed"', 1) + '\n',
                        text.replace('"elements": 4', '"elements": NaN', 1) + '\n',
                        ' ' * ps.MAX_READER_OUTPUT + text + '\n']:
            with self.subTest(framing=framing[:60]):
                self.refused(good, text=framing)
        with self.assertRaises(ValueError):
            ps.reader_result(subprocess.CompletedProcess([], 0, '\u00e9'.encode() + b'\n', b''),
                             self.data, [10123])


class DecodeFlowTests(unittest.TestCase):
    """Decision flow with every process boundary mocked: no JDK or other process starts."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.input = self.root / 'access.abx'
        self.input.write_bytes(b'ABX\x00stored bytes')
        self.tools = {'javac': Path('/fake/javac'), 'java': Path('/fake/java'),
                      'record': {'pinned_path': True}}
        patches = [mock.patch.object(ps.subprocess, 'run',
                                     side_effect=AssertionError('process started')),
                   mock.patch.object(ps, 'verify_sources', return_value={}),
                   mock.patch.object(ps, 'resource_guard', return_value=None),
                   mock.patch.object(ps, 'jdk_tools', return_value=self.tools),
                   mock.patch.object(ps, 'build', return_value=Path('/fake/classes'))]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def tearDown(self):
        self.directory.cleanup()

    def decode(self, reader=None, ids=(10123, 10999), path=None):
        with mock.patch.object(ps, 'run_reader', side_effect=reader or AssertionError('run')):
            return ps.decode(self.root, path or self.input, list(ids))

    def test_parsed_result_carries_binding_and_no_policy(self):
        data = self.input.read_bytes()
        output = self.decode(lambda *args, **kwargs: completed(parsed_output(
            data, [10123, 10999], [('flags', 24608), ('app_id_absent', None)])))
        self.assertEqual(set(output), DECODE_KEYS)
        self.assertEqual(output['result'], 'parsed')
        self.assertEqual(output['input'], {'length': len(data), 'sha256': ps.sha(data)})
        self.assertEqual(output['requested_app_ids'], [10123, 10999])
        self.assertEqual(output['app_ids'][0], {'app_id': 10123, 'state': 'flags', 'flags': 24608})
        self.assertEqual((output['refusal'], output['not_run']), (None, None))
        self.assertTrue(output['provenance']['pinned_sources_verified'])
        self.assertEqual(set(output['provenance']['tool_sha256']),
                         {'permission_store.py', ps.PROFILE.name, ps.READER.name, *ps.FACADES})
        self.assertEqual({key for key, value in output['scope'].items() if value is not False},
                         {'record'})
        self.assertLess(len(json.dumps(output)), 16 * 1024)

    def test_reader_refusal_reports_no_app_results(self):
        data = self.input.read_bytes()
        for code in ('truncated', 'noncanonical_string', 'duplicate_interned_string'):
            with self.subTest(code=code):
                output = self.decode(lambda *args, **kwargs: completed(refused_output(data,
                                                                                      code)))
                self.assertEqual((output['result'], output['app_ids'], output['document']),
                                 ('refused', None, None))
                self.assertEqual((output['refusal']['stage'], output['refusal']['code']),
                                 ('reader', code))

    def test_intake_refusal_starts_nothing(self):
        link = self.root / 'link'
        link.symlink_to(self.input)
        output = self.decode(path=link)
        self.assertEqual((output['result'], output['refusal']['stage'], output['refusal']['code']),
                         ('refused', 'intake', 'input_symlink'))
        self.assertIsNone(output['input'])

    def test_resource_guard_failure_starts_nothing(self):
        with mock.patch.object(ps, 'resource_guard', return_value='required bounds absent'):
            output = self.decode()
        self.assertEqual((output['result'], output['not_run']['reason']),
                         ('not_run', 'resource_guard'))
        ps.jdk_tools.assert_not_called()
        ps.build.assert_not_called()

    def test_source_drift_starts_nothing(self):
        with mock.patch.object(ps, 'verify_sources', side_effect=ps.NotRun('source_drift', 'x')):
            output = self.decode()
        self.assertEqual((output['result'], output['not_run']['reason'], output['input']),
                         ('not_run', 'source_drift', None))
        ps.build.assert_not_called()

    def test_reader_failures_are_refusals_not_absence(self):
        data = self.input.read_bytes()
        deep = '[' * 100000 + ']' * 100000 + '\n'
        cases = [
            (lambda *a, **k: subprocess.CompletedProcess([], 70, b'', b'failure'),
             'reader_failure'),
            (lambda *a, **k: subprocess.CompletedProcess([], 3, b'', b''), 'reader_failure'),
            (lambda *a, **k: subprocess.CompletedProcess([], 1, b'', b'crash report'),
             'reader_output_invalid'),
            (lambda *a, **k: completed(parsed_output(data, [10123])), 'reader_output_invalid'),
            (lambda *a, **k: completed(parsed_output(b'other', [10123, 10999])),
             'reader_output_invalid'),
            (lambda *a, **k: completed({}, returncode=1, text=deep[:ps.MAX_READER_OUTPUT - 1]
                                       + '\n'), 'reader_output_invalid'),
            (mock.Mock(side_effect=subprocess.TimeoutExpired('java', 120)), 'reader_timeout'),
        ]
        for reader, code in cases:
            with self.subTest(code=code):
                output = self.decode(reader)
                self.assertEqual((output['result'], output['refusal']['code'], output['app_ids']),
                                 ('refused', code, None))

    def test_build_timeout_is_not_run_and_never_absence(self):
        with mock.patch.object(ps, 'build', side_effect=subprocess.TimeoutExpired('javac', 300)):
            output = self.decode()
        self.assertEqual((output['result'], output['not_run']['reason'], output['app_ids']),
                         ('not_run', 'build_failed', None))
        self.assertEqual(output['input']['sha256'], ps.sha(self.input.read_bytes()))

    def test_build_failure_is_not_run(self):
        with mock.patch.object(ps, 'build', side_effect=ps.BuildError('x' * 10000)):
            output = self.decode()
        self.assertEqual((output['result'], output['not_run']['reason']),
                         ('not_run', 'build_failed'))
        self.assertLessEqual(len(output['not_run']['detail']), ps.MAX_DETAIL)


class CommandLineTests(unittest.TestCase):
    """main() envelopes and delivery. Every process boundary is mocked except where noted."""

    decode_args = ['decode', '--source-root', '/nonexistent', '--input', '/nonexistent/private',
                   '--app-id', '10123', '--app-id', '10999']

    def run_main(self, args):
        stdout = io.StringIO()
        with mock.patch('sys.stdout', stdout), mock.patch('sys.stderr', io.StringIO()):
            status = ps.main(args)
        return status, stdout.getvalue()

    def test_unexpected_decode_exception_is_a_decode_tool_error(self):
        secret = 'private-input-bytes'
        with mock.patch.object(ps, 'decode', side_effect=KeyError(secret)):
            status, text = self.run_main(self.decode_args)
        self.assertEqual(status, 3)
        self.assertNotIn(secret, text)
        output = ps.strict_json(text)
        self.assertEqual(set(output), DECODE_KEYS)
        self.assertEqual((output['schema'], output['result'], output['not_run']),
                         (ps.SCHEMA, 'not_run', {'reason': 'tool_error', 'detail': 'KeyError'}))
        self.assertEqual(output['requested_app_ids'], [10123, 10999])
        for key in ('input', 'document', 'app_ids', 'refusal', 'provenance'):
            self.assertIsNone(output[key], key)
        self.assertEqual(output['scope'], ps.SCOPE)

    def test_unexpected_check_sources_exception_is_a_sources_tool_error(self):
        with mock.patch.object(ps, 'check_sources', side_effect=RuntimeError('detail')):
            status, text = self.run_main(['check-sources', '--source-root', '/nonexistent'])
        output = ps.strict_json(text)
        self.assertEqual((status, set(output)), (3, SOURCES_KEYS))
        self.assertEqual(output, {'schema': ps.SOURCES_SCHEMA, 'result': 'not_run',
                                  'not_run': {'reason': 'tool_error', 'detail': 'RuntimeError'},
                                  'provenance': None})

    def test_profile_drift_is_a_tool_error(self):
        files = ps.tool_files()
        files[ps.PROFILE.name] = files[ps.PROFILE.name].replace(b'"store"', b'"stored"', 1)
        with mock.patch.object(ps, 'tool_files', return_value=files):
            for args, keys in ((self.decode_args, DECODE_KEYS),
                               (['check-sources', '--source-root', '/nonexistent'],
                                SOURCES_KEYS)):
                with self.subTest(command=args[0]):
                    status, text = self.run_main(args)
                    output = ps.strict_json(text)
                    self.assertEqual((status, set(output), output['not_run']),
                                     (3, keys, {'reason': 'tool_error',
                                                'detail': 'ProfileDrift'}))

    def test_known_outcomes_keep_their_envelopes(self):
        status, text = self.run_main(['check-sources', '--source-root', '/nonexistent'])
        output = ps.strict_json(text)
        self.assertEqual((status, set(output), output['result'], output['not_run']['reason']),
                         (3, SOURCES_KEYS, 'not_run', 'source_root'))
        self.assertIsNotNone(output['provenance'])
        status, text = self.run_main(self.decode_args)
        output = ps.strict_json(text)
        self.assertEqual((status, set(output), output['not_run']['reason']),
                         (3, DECODE_KEYS, 'source_root'))

    def test_every_decode_envelope_has_the_same_keys(self):
        provenance = ps._provenance(ps.tool_files(), ps.profile())
        reader = parsed_output(b'x', [10123])
        envelopes = [
            ps.compose('parsed', [10123], provenance, data=b'x', reader=reader),
            ps.compose('refused', [10123], provenance, refusal=ps._refusal('intake', 'x')),
            ps.compose('not_run', [10123], provenance, not_run=ps.NotRun('jdk', 'x')),
            ps.tool_error('decode', [10123], ValueError('x')),
        ]
        for envelope in envelopes:
            with self.subTest(result=envelope['result']):
                self.assertEqual(set(envelope), DECODE_KEYS)
                self.assertEqual(envelope['schema'], ps.SCHEMA)
        self.assertEqual(set(ps.tool_error('check-sources', None, ValueError('x'))), SOURCES_KEYS)

    def test_output_failure_is_undelivered_and_names_only_the_class(self):
        class Broken(io.StringIO):
            def write(self, text):
                raise BrokenPipeError(32, 'private-input-bytes')

        stderr = io.StringIO()
        with mock.patch('sys.stdout', Broken()), mock.patch('sys.stderr', stderr):
            status = ps.main(['check-sources', '--source-root', '/nonexistent'])
        self.assertEqual(status, ps.EXIT_UNDELIVERED)
        self.assertNotIn(status, ps.EXIT_CODES.values())
        self.assertEqual(stderr.getvalue(),
                         'permission_store: result not delivered: BrokenPipeError\n')

    def test_closed_stdout_pipe_exits_undelivered(self):
        # A real process whose stdout pipe has no reader. No JDK starts: the source root is
        # missing, so the tool reports not_run and then cannot deliver it.
        read, write = os.pipe()
        os.close(read)
        try:
            result = subprocess.run(
                [sys.executable, '-B', str(HERE / 'permission_store.py'), 'check-sources',
                 '--source-root', str(Path(tempfile.gettempdir()) / 'andrix-absent-root')],
                stdout=write, stderr=subprocess.PIPE, timeout=120, check=False)
        finally:
            os.close(write)
        self.assertEqual(result.returncode, ps.EXIT_UNDELIVERED, result.stderr)
        self.assertEqual(result.stderr, b'permission_store: result not delivered: '
                                        b'BrokenPipeError\n')


class SourceVerificationTests(unittest.TestCase):
    """Drift refusals with a synthetic source tree and matching synthetic profile."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name) / 'android'
        value = json.loads(ps.PROFILE.read_text())
        for group, _ in ps.SOURCE_GROUPS:
            for index, entry in enumerate(value[group]):
                data = ('synthetic %s %d\n' % (group, index)).encode()
                path = self.root / entry['path']
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                entry.update(sha256=ps.sha(data), size=len(data))
        self.value = ps.profile(json.dumps(value).encode())

    def tearDown(self):
        self.directory.cleanup()

    def reason(self):
        with self.assertRaises(ps.NotRun) as raised:
            ps.verify_sources(self.root, self.value)
        return raised.exception

    def test_exact_bytes_are_returned(self):
        pinned = ps.verify_sources(self.root, self.value)
        self.assertEqual(set(pinned),
                         set(ps.COMPILE_SOURCES + ps.REFERENCE_SOURCES + ps.STORE_SOURCES))

    def test_changed_missing_and_linked_sources_are_refused(self):
        for source in (ps.COMPILE_SOURCES[0], ps.STORE_SOURCES[-1]):
            with self.subTest(source=source):
                first = self.root / source
                original = first.read_bytes()
                first.write_bytes(original + b' ')
                self.assertIn('bytes differ', self.reason().detail)
                first.write_bytes(original[:-1] + b'X')
                self.assertIn('bytes differ', self.reason().detail)
                first.unlink()
                self.assertEqual(self.reason().reason, 'source_drift')
                elsewhere = Path(self.directory.name) / 'elsewhere'
                elsewhere.write_bytes(original)
                first.symlink_to(elsewhere)
                self.assertIn('symlink', self.reason().detail)
                first.unlink()
                first.write_bytes(original)
                ps.verify_sources(self.root, self.value)
                parent = first.parent
                moved = parent.with_name(parent.name + '.real')
                parent.rename(moved)
                parent.symlink_to(moved, target_is_directory=True)
                self.assertIn('symlink', self.reason().detail)
                parent.unlink()
                moved.rename(parent)
                ps.verify_sources(self.root, self.value)

    def test_missing_root_is_not_run(self):
        with self.assertRaises(ps.NotRun) as raised:
            ps.verify_sources(self.root / 'absent', self.value)
        self.assertEqual(raised.exception.reason, 'source_root')


class ResourceGuardTests(unittest.TestCase):
    good = {'memory.max': str(2 << 30), 'memory.swap.max': '0', 'cpu.max': '200000 100000',
            'pids.max': '256'}
    unlimited = {'memory.max': 'max', 'memory.swap.max': 'max', 'cpu.max': 'max 100000',
                 'pids.max': 'max'}

    @mock.patch.object(ps.resource, 'getrlimit', return_value=(0, 0))
    def test_guard_requires_every_bound(self, core_limit):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'cgroup'
            parent = root / 'user.slice'
            leaf = parent / 'check.scope'
            leaf.mkdir(parents=True)
            membership = Path(directory) / 'membership'
            membership.write_text('0::/user.slice/check.scope\n')
            for name, value in self.good.items():
                (leaf / name).write_text(value + '\n')
            self.assertIsNone(ps.resource_guard(root, membership))
            for limits in [(0, -1), (1, 1), (-1, -1), (0, 1024)]:
                core_limit.return_value = limits
                self.assertIn('core dumps', ps.resource_guard(root, membership))
            core_limit.return_value = (0, 0)
            for name, weaker in [('memory.max', str(4 << 30)), ('memory.max', 'max'),
                                 ('memory.max', '-1'), ('memory.swap.max', 'max'),
                                 ('memory.swap.max', '1'), ('cpu.max', 'max 100000'),
                                 ('cpu.max', '300000 100000'), ('cpu.max', '200000 0'),
                                 ('cpu.max', '200000'), ('pids.max', '257'),
                                 ('pids.max', 'max'), ('pids.max', 'garbage')]:
                (leaf / name).write_text(weaker + '\n')
                self.assertIsNotNone(ps.resource_guard(root, membership), name + ' ' + weaker)
                (leaf / name).write_text(self.good[name] + '\n')
            (leaf / 'pids.max').unlink()
            self.assertIsNotNone(ps.resource_guard(root, membership))
            for name, value in self.good.items():
                (leaf / name).write_text(self.unlimited[name] + '\n')
                (parent / name).write_text(value + '\n')
            self.assertIsNone(ps.resource_guard(root, membership))
            for text in ['0::/../escape\n', '', '0::/a\n0::/b\n', '1:name=systemd:/x\n',
                         '0::relative\n']:
                membership.write_text(text)
                self.assertIsNotNone(ps.resource_guard(root, membership), text)
            self.assertIsNotNone(ps.resource_guard(root, Path(directory) / 'missing'))

    def test_guard_only_reports_on_this_host(self):
        result = ps.resource_guard()
        self.assertTrue(result is None or isinstance(result, str))


def source_root():
    return Path(os.environ['ANDRIX_SOURCE_ROOT']).resolve(strict=True)


@unittest.skipUnless(os.environ.get('ANDRIX_SOURCE_ROOT'),
                     'set ANDRIX_SOURCE_ROOT to the pinned Android checkout')
class PinnedSourceTests(unittest.TestCase):
    """Read only checks of the pinned checkout. They start no process."""

    @classmethod
    def setUpClass(cls):
        cls.value = ps.profile()
        cls.pinned = ps.verify_sources(source_root(), cls.value)

    def text(self, suffix):
        [path] = [path for path in self.pinned if path.endswith(suffix)]
        return self.pinned[path].decode()

    def between(self, text, start, end):
        return text[text.index(start):text.index(end, text.index(start))]

    def test_sources_and_jdk_metadata_verify(self):
        output = ps.check_sources(source_root())
        self.assertEqual(output['result'], 'verified', output)
        self.assertEqual(set(output), SOURCES_KEYS)
        self.assertTrue(output['provenance']['jdk']['matches_profile'])

    def test_compile_set_is_the_binary_xml_module(self):
        blocks = self.text('modules/utils/Android.bp').split('\n}\n')
        [block] = [block for block in blocks if 'name: "modules-utils-binary-xml"' in block]
        sources = re.findall(r'"(\w+\.java)"', block)
        self.assertEqual(sorted(sources), sorted(Path(path).name for path in ps.COMPILE_SOURCES
                                                 if '/modules/utils/' in path))
        self.assertNotIn('host_supported', block)
        annotations = self.text('modules-utils/java/Android.bp').split('\n}\n')
        [library] = [block for block in annotations
                     if 'name: "framework-annotations-lib"' in block]
        self.assertIn('host_supported: true', library)

    def test_compile_sources_have_no_assert_statements(self):
        for path in ps.COMPILE_SOURCES:
            with self.subTest(path):
                self.assertIsNone(re.search(r'\bassert\b', java_code(self.pinned[path].decode())))

    def test_parser_branches_the_reader_relies_on(self):
        parser = self.text('/BinaryXmlPullParser.java')
        code = java_code(parser)
        self.assertEqual(code.count('mIn.readByte()'), 1)
        self.assertEqual(code.count('mIn.peekByte()'), 1)
        # Plain string values, text tokens and entity names; names and interned values.
        self.assertEqual(code.count('mIn.readUTF()'), 3)
        self.assertEqual(code.count('mIn.readInternedUTF()'), 4)
        for absent in ('readBoolean', 'readUnsignedByte', 'skipBytes'):
            self.assertNotIn(absent, code)
        self.assertEqual(parser.count('        } catch (EOFException e) {\n'
                                      '            token = END_DOCUMENT;\n        }'), 1)
        next_token = parser[parser.index('    public int nextToken()'):
                            parser.index('    private int peekNextExternalToken()')]
        self.assertLess(next_token.index('catch (EOFException e)'),
                        next_token.index('                peekNextExternalToken();'))
        self.assertIn('    protected FastDataInput obtainFastDataInput(@NonNull InputStream is) {',
                      parser)
        self.assertIn('            if (peekNextExternalToken() == START_DOCUMENT) {', parser)
        data = self.text('/FastDataInput.java')
        self.assertIn('    protected static final int DEFAULT_BUFFER_SIZE = 32_768;', data)
        self.assertIn('    public byte readByte() throws IOException {', data)
        fill = data[data.index('    protected void fill(int need)'):
                    data.index('    @Override\n    public void close()')]
        self.assertIn('        while (need > 0) {', fill)
        self.assertIn('            if (c == -1) {\n                throw new EOFException();', fill)
        self.assertIn('            return mStringRefs[ref];', data)

    def test_string_reads_the_recording_input_checks(self):
        data = self.text('/FastDataInput.java')
        # Overridable, with the buffer positions visible to a subclass.
        for line in ('    protected static final int MAX_UNSIGNED_SHORT = 65_535;',
                     '    protected int mBufferPos;', '    protected int mBufferLim;',
                     '    public String readUTF() throws IOException {',
                     '    public @NonNull String readInternedUTF() throws IOException {'):
            self.assertIn(line, data)
        read_utf = self.between(data, '    public String readUTF()', '    /**')
        self.assertIn('        final int len = readUnsignedShort();\n'
                      '        if (mBufferCap > len) {\n'
                      '            if (mBufferLim - mBufferPos < len) fill(len);\n'
                      '            final String res = ModifiedUtf8.decode(mBuffer, new char[len],'
                      ' mBufferPos, len);\n'
                      '            mBufferPos += len;\n'
                      '            return res;\n'
                      '        } else {\n'
                      '            final byte[] tmp = newByteArray(len + 1);\n'
                      '            readFully(tmp, 0, len);\n'
                      '            return ModifiedUtf8.decode(tmp, new char[len], 0, len);\n'
                      '        }', read_utf)
        interned = self.between(data, '    public @NonNull String readInternedUTF()',
                                '    @Override')
        self.assertIn('        final int ref = readUnsignedShort();\n'
                      '        if (ref == MAX_UNSIGNED_SHORT) {\n'
                      '            final String s = readUTF();\n', interned)
        self.assertIn('            if (mStringRefCount < MAX_UNSIGNED_SHORT) {', interned)
        self.assertIn('                mStringRefs[mStringRefCount++] = s;', interned)
        self.assertIn('            if (ref >= mStringRefs.length) {', interned)
        self.assertEqual(java_code(interned).count('readUTF()'), 1)
        output = self.text('/FastDataOutput.java')
        self.assertIn('        final int len = (int) ModifiedUtf8.countBytes(s, false);', output)
        self.assertIn('            writeShort(len);\n'
                      '            ModifiedUtf8.encode(mBuffer, mBufferPos, s);', output)
        self.assertIn('            ModifiedUtf8.encode(tmp, 0, s);\n'
                      '            writeShort(len);\n'
                      '            write(tmp, 0, len);', output)
        self.assertIn('        Integer ref = mStringRefs.get(s);\n'
                      '        if (ref != null) {\n'
                      '            writeShort(ref);\n'
                      '        } else {\n'
                      '            writeShort(MAX_UNSIGNED_SHORT);\n'
                      '            writeUTF(s);\n', output)
        self.assertIn('            ref = mStringRefs.size();\n'
                      '            if (ref < MAX_UNSIGNED_SHORT) {\n'
                      '                mStringRefs.put(s, ref);', output)
        utf8 = self.text('/ModifiedUtf8.java')
        self.assertIn('    public static long countBytes(String s, boolean shortLength)', utf8)
        self.assertIn('    public static void encode(byte[] dst, int offset, String s) {', utf8)
        self.assertEqual(utf8.count('if (ch != 0 && ch <= 127) { // U+0000 uses two bytes.'), 2)
        serializer = self.text('/BinaryXmlSerializer.java')
        self.assertIn('        mOut.writeByte(ATTRIBUTE | TYPE_STRING_INTERNED);\n'
                      '        mOut.writeInternedUTF(name);\n'
                      '        mOut.writeInternedUTF(value);', serializer)
        self.assertIn('        mOut.writeByte(ATTRIBUTE | TYPE_INT);\n'
                      '        mOut.writeInternedUTF(name);\n'
                      '        mOut.writeInt(value);', serializer)

    def test_store_writer_and_reader_schema(self):
        policy = self.text('/access/AccessPolicy.kt')
        self.assertIn('        private const val TAG_ACCESS = "access"\n', policy)
        self.assertIn('                addPolicy(AppIdPermissionPolicy())', policy)
        self.assertIn('    fun BinaryXmlSerializer.serializeUserState(state: AccessState, '
                      'userId: Int) {\n        tag(TAG_ACCESS) {', policy)
        self.assertIn('            forEachSchemePolicy { with(it) { serializeUserState(state, '
                      'userId) } }\n        }\n    }', policy)
        self.assertIn('                TAG_ACCESS -> {\n                    forEachTag {', policy)
        self.assertIn('forEachSchemePolicy { with(it) { parseUserState(state, userId) } }',
                      policy)
        app_policy = self.text('/permission/AppIdPermissionPolicy.kt')
        self.assertIn('    private val persistence = AppIdPermissionPersistence()', app_policy)
        self.assertIn('with(persistence) { this@parseUserState.parseUserState(state, userId) }',
                      app_policy)
        self.assertIn('with(persistence) { this@serializeUserState.serializeUserState(state, userId) }',
                      app_policy)
        persistence = self.text('/permission/AppIdPermissionPersistence.kt')
        for constant in ('TAG_APP_ID = "app-id"', 'TAG_APP_ID_PERMISSIONS = "app-id-permissions"',
                         'TAG_PERMISSION = "permission"', 'ATTR_FLAGS = "flags"',
                         'ATTR_ID = "id"', 'ATTR_NAME = "name"'):
            self.assertIn('        private const val ' + constant + '\n', persistence)
        self.assertIn('        serializeAppIdPermissions(state.userStates[userId]!!'
                      '.appIdPermissionFlags)', persistence)
        self.assertIn('        tag(TAG_APP_ID_PERMISSIONS) {\n'
                      '            appIdPermissionFlags.forEachIndexed { _, appId, '
                      'permissionFlags ->\n'
                      '                serializeAppId(appId, permissionFlags)\n'
                      '            }\n'
                      '        }', persistence)
        self.assertIn('        tag(TAG_APP_ID) {\n'
                      '            attributeInt(ATTR_ID, appId)\n'
                      '            permissionFlags.forEachIndexed { _, name, flags ->\n'
                      '                serializeAppIdPermission(name, flags)\n'
                      '            }\n'
                      '        }', persistence)
        self.assertIn('        tag(TAG_PERMISSION) {\n'
                      '            attributeInterned(ATTR_NAME, name)\n'
                      '            // Never serialize one-time permissions as granted.\n'
                      '            val serializedFlags =\n'
                      '                if (flags.hasBits(PermissionFlags.ONE_TIME)) {\n'
                      '                    flags andInv PermissionFlags.RUNTIME_GRANTED\n'
                      '                } else {\n'
                      '                    flags\n'
                      '                }\n'
                      '            attributeInt(ATTR_FLAGS, serializedFlags)\n'
                      '        }', persistence)
        self.assertIn('        val appId = getAttributeIntOrThrow(ATTR_ID)', persistence)
        self.assertIn('        val name = getAttributeValueOrThrow(ATTR_NAME).intern()\n'
                      '        val flags = getAttributeIntOrThrow(ATTR_FLAGS)', persistence)
        for helper in ('attributeInt', 'attributeInterned', 'tag'):
            self.assertIn('import com.android.server.permission.access.util.' + helper + '\n',
                          persistence)
        writer = self.text('/util/BinaryXmlSerializerExtensions.kt')
        self.assertIn('    BinaryXmlSerializer().apply {\n'
                      '        setOutput(this@serializeBinaryXml, null)\n'
                      '        document(block)\n    }', writer)
        self.assertIn('    startDocument(null, true)\n    block()\n    endDocument()', writer)
        self.assertIn('    startTag(null, name)\n    block()\n    endTag(null, name)', writer)
        self.assertIn('inline fun BinaryXmlSerializer.attributeInt(name: String, value: Int) {\n'
                      '    attributeInt(null, name, value)\n}', writer)
        self.assertIn('inline fun BinaryXmlSerializer.attributeInterned(name: String, value: '
                      'String) {\n    attributeInterned(null, name, value)\n}', writer)
        reader = self.text('/util/BinaryXmlPullParserExtensions.kt')
        self.assertIn('    BinaryXmlPullParser().apply {\n'
                      '        setInput(this@parseBinaryXml, null)\n'
                      '        block()\n    }', reader)
        self.assertIn('inline fun BinaryXmlPullParser.getAttributeIntOrThrow(name: String): Int ='
                      '\n    getAttributeInt(null, name)', reader)
        for source in (writer, reader):
            # The plain classes, not the Xml factory and its ART variants.
            code = java_code(source)
            for factory in (r'\bXml\.', r'ArtBinaryXml', r'ArtFastData', r'resolveSerializer',
                            r'resolvePullParser', r'newBinary'):
                self.assertIsNone(re.search(factory, code), factory)
        store = self.text('/access/AccessPersistence.kt')
        self.assertIn('        private const val FILE_NAME = "access.abx"', store)
        self.assertIn('    private fun getUserFile(userId: Int): File =\n'
                      '        File(PermissionApex.getUserDataDirectory(userId), FILE_NAME)', store)
        self.assertIn('getUserFile(userId).serialize { with(policy) { serializeUserState(state, '
                      'userId) } }', store)
        self.assertIn('getUserFile(userId).parse { with(policy) { parseUserState(state, '
                      'userId) } }', store)
        self.assertIn('AtomicFile(this).writeWithReserveCopy { it.serializeBinaryXml(block) }',
                      store)
        self.assertIn('AtomicFile(this).readWithReserveCopy { it.parseBinaryXml(block) }', store)
        apex = self.text('/util/PermissionApex.kt')
        self.assertIn('    private const val MODULE_NAME = "com.android.permission"', apex)
        self.assertIn('    fun getUserDataDirectory(userId: Int): File =\n'
                      '        apexEnvironment.getDeviceProtectedDataDirForUser('
                      'UserHandle.of(userId))', apex)
        atomic = self.text('/util/AtomicFileExtensions.kt')
        self.assertEqual(atomic.count('val reserveFile = File(baseFile.parentFile, '
                                      'baseFile.name + ".reservecopy")'), 2)
        self.assertIn('        openRead().use(block)', atomic)
        self.assertIn('            AtomicFile(reserveFile).openRead().use(block)', atomic)
        self.assertIn('    writeInlined(block)\n', atomic)
        service = self.text('/access/AccessCheckingService.kt')
        self.assertIn('    private val policy = AccessPolicy()', service)
        self.assertIn('    private val persistence = AccessPersistence(policy)', service)
        self.assertIn('        persistence.read(state)', service)

    def test_serializer_encodings_match_the_reader(self):
        serializer = self.text('/BinaryXmlSerializer.java')
        reader = ps.READER.read_text()
        for name, value in (('TYPE_NULL', '1 << 4'), ('TYPE_STRING', '2 << 4'),
                            ('TYPE_STRING_INTERNED', '3 << 4'), ('TYPE_INT', '6 << 4'),
                            ('TYPE_INT_HEX', '7 << 4'), ('TYPE_BOOLEAN_FALSE', '13 << 4')):
            self.assertIn('static final int %s = %s;' % (name, value), serializer)
            self.assertIn('static final int %s = %s;' % (name, value), reader)
        self.assertIn('static final int ATTRIBUTE = 15;', serializer)
        for event in ('START_DOCUMENT | TYPE_NULL', 'END_DOCUMENT | TYPE_NULL',
                      'START_TAG | TYPE_STRING_INTERNED', 'END_TAG | TYPE_STRING_INTERNED'):
            self.assertIn('mOut.writeByte(%s);' % event, serializer)
            self.assertIn('XmlPullParser.' + event + ';', reader)

    def test_references_behind_the_crosscheck_limits(self):
        abx = self.text('abx/Abx.java')
        self.assertIn('in = Xml.newBinaryPullParser();', abx)
        self.assertIn('Xml.copy(in, out);', abx)
        xml = self.text('android/util/Xml.java')
        self.assertIn('        return new ArtBinaryXmlPullParser();', xml)
        self.assertIn('                case XmlPullParser.END_DOCUMENT:\n'
                      '                    out.endDocument();\n                    return;', xml)
        self.assertIn('return XmlObjectFactory.newXmlSerializer();', xml)
        self.assertIn('return ArtFastDataInput.obtain(is);',
                      self.text('/ArtBinaryXmlPullParser.java'))
        self.assertIn('CharsetUtils.fromModifiedUtf8Bytes', self.text('/ArtFastDataInput.java'))
        self.assertIn('return ArtFastDataOutput.obtain(os);',
                      self.text('/ArtBinaryXmlSerializer.java'))
        self.assertIn('    public void endDocument() throws IOException {\n'
                      '        while (depth > 0) {', self.text('/KXmlSerializer.java'))

    def test_drifted_checkout_copy_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path, data in self.pinned.items():
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_bytes(data)
            ps.verify_sources(root, self.value)
            for path, old, new in ((ps.COMPILE_SOURCES[0], b'token = END_DOCUMENT;',
                                    b'throw e;'),
                                   (ps.STORE_SOURCES[3], b'attributeInt(ATTR_FLAGS',
                                    b'attributeIntHex(ATTR_FLAGS')):
                with self.subTest(path=path):
                    target = root / path
                    original = target.read_bytes()
                    target.write_bytes(original.replace(old, new, 1))
                    with self.assertRaises(ps.NotRun) as raised:
                        ps.verify_sources(root, self.value)
                    self.assertEqual(raised.exception.reason, 'source_drift')
                    target.write_bytes(original)


class JvmTests(unittest.TestCase):
    """Guarded host JVM checks. No JDK process starts unless the resource guard passes."""

    @classmethod
    def setUpClass(cls):
        reason = None
        if not os.environ.get('ANDRIX_SOURCE_ROOT'):
            reason = 'ANDRIX_SOURCE_ROOT required for the pinned sources'
        else:
            guard = ps.resource_guard()
            if guard is not None:
                reason = 'resource guard: ' + guard
        if reason is None:
            value = ps.profile()
            try:
                cls.pinned = ps.verify_sources(source_root(), value)
                cls.tools = ps.jdk_tools(source_root(), value, os.environ.get('ANDRIX_JDK'))
            except ps.NotRun as error:
                reason = '%s: %s' % (error.reason, error.detail)
        if reason is not None:
            if os.environ.get('ANDRIX_REQUIRE_JVM_CHECKS') == '1':
                raise AssertionError('JVM checks required but not run: ' + reason)
            raise unittest.SkipTest(reason)
        cls.directory = tempfile.TemporaryDirectory(prefix='andrix-permission-store-test-')
        cls.work = Path(cls.directory.name)
        cls.files = ps.tool_files(checks=True)
        cls.classes = ps.build(cls.pinned, cls.work, cls.tools, cls.files)
        cls.fixtures = cls.work / 'fixtures'
        cls.fixtures.mkdir()
        result = cls.java('-ea', 'PermissionStoreChecks', '--write-fixtures', cls.fixtures)
        if result.returncode != 0:
            raise AssertionError('fixture writer failed\n' + ps._output(result))

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    @classmethod
    def java(cls, assertions, *args, stdin=None):
        return ps._run([cls.tools['java'], *ps.JVM_BOUNDS, *ps._private(cls.work), assertions,
                        '-cp', cls.classes, *args], work=cls.work, timeout=600, stdin=stdin)

    def decode_fixture(self, name, app_ids, assertions='-ea'):
        data = ps.read_input(self.fixtures / name)
        result = ps.run_reader(self.classes, self.work, self.tools, data, app_ids,
                               assertions=assertions)
        return ps.reader_result(result, data, app_ids), result

    def test_host_checks_pass_with_and_without_assertions(self):
        outputs = []
        for assertions in ('-ea', '-da'):
            with self.subTest(assertions):
                result = self.java(assertions, 'PermissionStoreChecks')
                self.assertEqual(result.returncode, 0, ps._output(result))
                self.assertIn(PASS, result.stdout.decode())
                outputs.append(result.stdout)
        self.assertEqual(outputs[0], outputs[1])
        text = outputs[0].decode()
        for name in ('every proper prefix refused as incomplete',
                     'every single trailing byte refused',
                     'parser reports end of input as END_DOCUMENT',
                     'parser propagates end of input after a start tag',
                     'parser reads nothing after END_DOCUMENT',
                     'recording parser decodes like the plain parser',
                     'recording parser decodes long strings like the plain parser',
                     'recording parser decodes a full intern pool like the plain parser',
                     'serializer event bytes as recorded',
                     'overlong access name', 'overlong target name', 'raw single NUL',
                     'overlong form offset by a raw NUL',
                     'overlong form offset by a raw NUL in a long string',
                     'duplicate definition of a tag name',
                     'pool ceiling document reaches the writer\'s ceiling',
                     'pool ceiling keeps repeated uncached definitions',
                     'definition of the last interned string after the ceiling',
                     'stray attribute before START_DOCUMENT',
                     'stray attribute before END_DOCUMENT',
                     'unassigned interned attribute name', 'unassigned interned end tag',
                     'limit: a valid target name substitution stays well formed',
                     'limit: a valid flags substitution stays well formed',
                     'limit: a clean deletion stays well formed',
                     'parser decodes an overlong name as the plain name',
                     'parser accepts duplicate intern definitions'):
            self.assertIn('ok: ' + name + '\n', text)
        self.assertGreaterEqual(int(re.search(PASS + r' checks=(\d+)', text)[1]), 160)

    def test_no_assertions_were_compiled(self):
        class_files = list(self.classes.rglob('*.class'))
        self.assertGreater(len(class_files), 10)
        for path in class_files:
            self.assertNotIn(b'$assertionsDisabled', path.read_bytes(), path.name)

    def test_sample_flags_are_returned_raw(self):
        value, _ = self.decode_fixture('canonical.abx', IDS)
        self.assertEqual(value['result'], 'parsed')
        self.assertEqual([(entry['state'], entry['flags']) for entry in value['app_ids']],
                         [('flags', 24624), ('flags', 24608), ('flags', 24672),
                          ('permission_absent', None), ('app_id_absent', None),
                          ('app_id_absent', None)])
        self.assertEqual(value['document'],
                         {'elements': 23, 'app_id_entries': 5, 'permission_entries': 6})
        value, _ = self.decode_fixture('flag-bounds.abx', [10000, 19999, 10001])
        self.assertEqual([entry['flags'] for entry in value['app_ids']],
                         [-(1 << 31), (1 << 31) - 1, -1])

    def test_fixture_refusals_through_the_tool_path(self):
        for name, code in (('missing-end-document.abx', 'missing_end_document'),
                           ('trailing-byte.abx', 'trailing_bytes'),
                           ('truncated-after-target.abx', 'truncated'),
                           ('unclosed-after-target.abx', 'unclosed_elements'),
                           ('duplicate-app-id.abx', 'duplicate_app_id'),
                           ('duplicate-permission.abx', 'duplicate_permission'),
                           ('wrong-root.abx', 'wrong_root'),
                           ('int-hex-flags.abx', 'attribute_encoding'),
                           ('noncanonical-name.abx', 'noncanonical_string'),
                           ('duplicate-definition.abx', 'duplicate_interned_string')):
            with self.subTest(name):
                value, result = self.decode_fixture(name, [10123])
                self.assertEqual((value['result'], value['refusal']['code']), ('refused', code))
                self.assertEqual(result.returncode, 1)
                self.assertNotIn('app_ids', value)

    def test_assertion_setting_does_not_change_results(self):
        for name in ('canonical.abx', 'trailing-byte.abx', 'truncated-after-target.abx',
                     'noncanonical-name.abx'):
            with self.subTest(name):
                enabled = self.decode_fixture(name, IDS, '-ea')[1]
                disabled = self.decode_fixture(name, IDS, '-da')[1]
                self.assertEqual((enabled.returncode, enabled.stdout),
                                 (disabled.returncode, disabled.stdout))

    def test_reader_bounds_stdin_and_arguments(self):
        result = self.java('-ea', 'PermissionStoreReader', '10123',
                           stdin=bytes(ps.MAX_INPUT_BYTES + 1))
        self.assertEqual(result.returncode, 1, ps._output(result))
        value = json.loads(result.stdout)
        self.assertEqual((value['input'], value['refusal']['code']),
                         ({'length': None, 'sha256': None}, 'input_too_large'))
        for args in (['9999'], ['20000'], ['10123', '10123'], [], ['010123']):
            with self.subTest(args=args):
                result = self.java('-ea', 'PermissionStoreReader', *args, stdin=b'')
                self.assertEqual((result.returncode, result.stdout), (2, b''))

    def test_cli_end_to_end(self):
        command = [sys.executable, '-B', str(HERE / 'permission_store.py'), 'decode',
                   '--source-root', str(source_root())]
        if os.environ.get('ANDRIX_JDK'):
            command += ['--jdk', os.environ['ANDRIX_JDK']]
        link = self.work / 'linked.abx'
        if not link.exists():
            link.symlink_to(self.fixtures / 'canonical.abx')
        for name, ids, code, result_name in (
                ('canonical.abx', ['10124', '10999'], 0, 'parsed'),
                ('missing-end-document.abx', ['10124'], 1, 'refused'),
                ('noncanonical-name.abx', ['10123'], 1, 'refused'),
                ('../linked.abx', ['10124'], 1, 'refused')):
            with self.subTest(name):
                args = [part for app_id in ids for part in ('--app-id', app_id)]
                result = subprocess.run([*command, '--input', str(self.fixtures / name), *args],
                                        capture_output=True, timeout=900, check=False)
                self.assertEqual(result.returncode, code, ps._output(result))
                value = ps.strict_json(result.stdout.decode('ascii'))
                self.assertEqual(set(value), DECODE_KEYS)
                self.assertEqual(value['result'], result_name)
                self.assertTrue(value['provenance']['pinned_sources_verified'])
                if result_name == 'parsed':
                    self.assertEqual(value['app_ids'][0], {'app_id': 10124, 'state': 'flags',
                                                           'flags': 24608})
                    self.assertTrue(value['provenance']['jdk']['matches_profile']
                                    or bool(os.environ.get('ANDRIX_JDK')))
                elif name.startswith('..'):
                    self.assertEqual(value['refusal']['code'], 'input_symlink')
                elif name.startswith('noncanonical'):
                    self.assertEqual(value['refusal'], {
                        'stage': 'reader', 'code': 'noncanonical_string', 'exception': None,
                        'offset': value['refusal']['offset'], 'step': value['refusal']['step'],
                        'exit_status': 1})
                else:
                    self.assertEqual(value['refusal']['code'], 'missing_end_document')


if __name__ == '__main__':
    unittest.main()
