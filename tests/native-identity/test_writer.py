# SPDX-License-Identifier: Apache-2.0
"""Test fixture transport ownership over the real manager/store with host Android facades."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


class WriterFixtureTests(unittest.TestCase):
    def test_route_does_not_expose_initialization_retirement_or_execution(self):
        source = (HERE / 'writer/NativePrincipalWriterFixture.java').read_text()
        for forbidden in ('beginRetirement(', 'finishRetirementAfterQuiescence(',
                          'initializeNew(', 'NativeIdentityStore(', 'NativeIdentityPersistence(',
                          'Runtime.getRuntime()', 'ProcessBuilder', 'reservePending('):
            self.assertNotIn(forbidden, source)
        self.assertIn('Binder.getCallingUid() != Process.ROOT_UID', source)
        self.assertIn('!Build.IS_DEBUGGABLE', source)
        self.assertIn('.put("execution_authorized", false)', source)
        self.assertIn('if (firstCommitAckAttempt == 0) firstCommitAckAttempt = attempt', source)
        self.assertIn('response = snapshot("recorded")', source)
        self.assertIn('catch (RuntimeException | Error error)', source)
        self.assertIn('native writer fixture outcome unknown: REPLY_UNAVAILABLE', source)

    def test_missing_jdk_is_not_a_qualified_success(self):
        with mock.patch.object(shutil, 'which', return_value=None):
            with self.assertRaisesRegex(AssertionError, 'requires a JDK'):
                self.test_owned_requests_and_real_manager_on_jvm()

    def test_owned_requests_and_real_manager_on_jvm(self):
        self.assertTrue(shutil.which('javac') and shutil.which('java'), 'writer qualification requires a JDK on PATH')
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            allocator = output / 'AppIdSettingMap.java'
            allocator.write_bytes((ROOT / 'owner/tests/platform/AppIdSettingMap.java.inc').read_bytes())
            writer = output / 'ResilientAtomicFile.java'
            writer.write_bytes((ROOT / 'owner/tests/platform/ResilientAtomicFile.java.inc').read_bytes())
            stubs = {}
            for base in (ROOT / 'owner/tests/platform/native_principal_stubs',
                         ROOT / 'owner/tests/platform/native_principal_xml_stubs', HERE / 'writer/stubs'):
                for source in base.rglob('*.java'):
                    if source.name != 'Xml.java':
                        stubs[source.relative_to(base).as_posix()] = source
            files = [allocator, writer, *stubs.values(),
                     *(ROOT / 'owner/platform/framework' / (name + '.java') for name in
                       ('NativePrincipalPins', 'NativePrincipalManager', 'NativeIdentityRecords',
                        'NativeIdentityStore', 'NativeIdentityPersistence', 'NativePrincipalRecovery')),
                     HERE / 'writer/NativePrincipalWriterFixture.java',
                     HERE / 'writer/NativePrincipalWriterFixtureTest.java',
                     HERE / 'writer/NativePrincipalWriterFixtureFaultTest.java']
            result = subprocess.run(['javac', '-J-Xmx256m', '--release', '17', '-Xlint:all', '-Werror',
                                     '-d', str(output), *map(str, files)],
                                    capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for name in ('NativePrincipalWriterFixtureTest', 'NativePrincipalWriterFixtureFaultTest'):
                args = ['java', '-Xmx256m', '-Djava.io.tmpdir=' + str(output), '-ea', '-cp', str(output),
                        'com.android.server.pm.' + name]
                result = subprocess.run(args, capture_output=True, text=True, timeout=90)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('Android route unqualified', result.stdout)
                args.remove('-ea')
                refused = subprocess.run(args, capture_output=True, text=True, timeout=20)
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn('-ea', refused.stderr)



if __name__ == '__main__':
    unittest.main()
