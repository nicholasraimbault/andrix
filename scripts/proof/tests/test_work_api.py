# SPDX-License-Identifier: Apache-2.0
"""Metadata and exact work targeting checks, not Android identity or cleanup proof."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
AIDL = ROOT / 'owner/aidl/dev/andrix/session'


def info_members():
    text = (AIDL / 'WorkInfo.aidl').read_text()
    constants = re.findall(r'^\s*const int (\w+) = ([0-9]+);', text, re.M)
    fields = re.findall(r'^\s*(long|int) (\w+);', text, re.M)
    assert [n for _,n in fields] == ['workId', 'state', 'lifetimePolicy', 'terminalRecovery']
    assert len(constants) == 8
    return constants, fields


def java_info(directory):
    constants,fields = info_members()
    source = directory / 'dev/andrix/session/WorkInfo.java'
    source.parent.mkdir(parents=True)
    source.write_text('package dev.andrix.session;\npublic final class WorkInfo {\n' +
        ''.join(f'public static final int {n} = {v};\n' for n,v in constants) +
        ''.join(f'public {t} {n};\n' for t,n in fields) + '}\n')
    return source


class WorkApiTests(unittest.TestCase):
    def test_actual_native_metadata_and_stop_methods(self):
        compiler = shutil.which('g++'); self.assertIsNotNone(compiler)
        native = (ROOT / 'owner/native/andrixd.cpp').read_text()
        methods = native[native.index('  WorkInfo work_info_locked() const {'):
                         native.index('  ScopedAStatus attach_locked(')]
        constants,fields = info_members()
        facade = 'struct WorkInfo {\n' + ''.join(f'static constexpr int {n} = {v};\n' for n,v in constants)
        facade += ''.join(('int64_t' if t == 'long' else 'int') + ' ' + n + '{};\n' for t,n in fields) + '};\n'
        harness = (ROOT / 'owner/tests/work_api_test.cpp.in').read_text().replace(
            '// WORK_INFO_FACADE', facade).replace('// PRODUCTION_WORK_API', methods)
        with tempfile.TemporaryDirectory() as directory:
            cpp = Path(directory) / 'work.cpp'; cpp.write_text(harness)
            for name,flags in [('optimized', ['-O2']), ('sanitized',
                    ['-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer'])]:
                binary = Path(directory) / name
                result = subprocess.run([compiler, '-std=c++20', '-Wall', '-Wextra', '-Werror',
                    *flags, '-I' + str(ROOT / 'owner/native'), str(cpp),
                    str(ROOT / 'owner/native/terminal_process.cpp'), '-o', str(binary)],
                    capture_output=True, text=True, timeout=180)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
                self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
                self.assertIn('Android unqualified', ran.stdout)

    def test_work_reference_and_observation_model(self):
        self.run_java('WorkTrackerTest', (ROOT / 'owner/tests/WorkTrackerTest.java').read_text())

    def test_actual_console_completion_methods(self):
        source = (ROOT / 'owner/terminal/src/dev/andrix/terminal/TerminalController.java').read_text()
        query = source[source.index('    private void finishWorkQuery('):source.index('    void startKept()')]
        stop = source[source.index('    private void finishWorkStop('):source.index('    private boolean disconnect(')]
        harness = (ROOT / 'owner/tests/WorkCallbacksTest.java.in').read_text().replace(
            '// PRODUCTION_WORK_QUERY_COMPLETION', query).replace('// PRODUCTION_WORK_STOP_COMPLETION', stop)
        self.run_java('WorkCallbacksTest', harness)

    def test_actual_detached_stop_request_target(self):
        source = (ROOT / 'owner/terminal/src/dev/andrix/terminal/TerminalController.java').read_text()
        request = source[source.index('    void endSession()'):source.index('    private void finishWorkStop(')]
        completion = source[source.index('    private void finishWorkStop('):source.index('    private boolean disconnect(')]
        harness = (ROOT / 'owner/tests/WorkStopRequestTest.java.in').read_text().replace(
            '// PRODUCTION_STOP_REQUEST', request).replace('// PRODUCTION_STOP_COMPLETION', completion)
        self.run_java('WorkStopRequestTest', harness)

    def run_java(self, name, content):
        self.assertIsNotNone(shutil.which('javac')); self.assertIsNotNone(shutil.which('java'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / (name + '.java'); source.write_text(content)
            facade = java_info(root)
            protocol = ROOT / 'owner/terminal/protocol'
            compiled = subprocess.run(['javac', '--release', '17', '-Xlint:all', '-Werror', '-d', str(root),
                str(facade), str(source), str(protocol / 'WorkReference.java'),
                str(protocol / 'WorkTracker.java'), str(protocol / 'AttachmentLifecycle.java')],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            ran = subprocess.run(['java', '-ea', '-cp', str(root), name], capture_output=True, text=True, timeout=30)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            self.assertIn('Android unqualified', ran.stdout)

    def test_api_append_only_and_no_implicit_io_or_retargeting(self):
        text = (AIDL / 'IOwnerSession.aidl').read_text()
        methods = re.findall(r'^\s*(?:void|Attachment|boolean|String|WorkInfo)\s+(\w+)\(', text, re.M)
        self.assertEqual(methods, ['registerController', 'attach', 'renew', 'acknowledgeOutput',
            'resize', 'detach', 'endSession', 'status', 'startKept', 'stopKeptWork', 'describeWork', 'stopWork'])
        native = (ROOT / 'owner/native/andrixd.cpp').read_text()
        query = native[native.index('  ScopedAStatus describeWork('):native.index('  ScopedAStatus stopWork(')]
        stop = native[native.index('  ScopedAStatus stopWork('):native.index('  ScopedAStatus attach_locked(')]
        for forbidden in ['gate_.attach', 'gate_.renew', 'start_terminal_locked', 'platform_.retain', 'socketpair']:
            self.assertNotIn(forbidden, query + stop)
        self.assertNotIn('gate_.generation', stop)
        self.assertNotIn('gate_.live', stop)
        self.assertIn('uint64_t(work) != work_id_', stop)
        for method in [query, stop]:
            self.assertIn('caller_allowed()', method)
            self.assertIn('controller_matches()', method)
        self.assertIn('result->work = work_info_locked()', native)
        controller = (ROOT / 'owner/terminal/src/dev/andrix/terminal/TerminalController.java').read_text()
        end = controller[controller.index('    void endSession()'):controller.index('    private void finishWorkStop(')]
        self.assertIn('selected.service.stopWork(selected.id)', end)
        self.assertNotIn('ServiceManager', end)
        self.assertNotIn('current.generation', end)
        self.assertNotIn('knownService', controller)
        self.assertNotIn('keptWork && !cursor.inputAllowed()', controller)
        self.assertIn('gapMessage(current.work.recreatesTerminal())', controller)
        self.assertIn('value = new WorkReference<>(service, binder, service.describeWork())', controller)
        activity = (ROOT / 'owner/terminal/src/dev/andrix/terminal/ConsoleActivity.java').read_text()
        self.assertIn('end.setEnabled(controller.canStopWork()', activity)


if __name__ == '__main__':
    unittest.main()
