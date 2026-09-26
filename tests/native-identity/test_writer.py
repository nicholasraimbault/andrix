# SPDX-License-Identifier: Apache-2.0
"""Test fixture transport ownership over the real manager/store with host Android facades."""
from pathlib import Path
import base64
import importlib.util
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
                     HERE / 'writer/NativePrincipalWriterFixtureFaultTest.java',
                     HERE / 'writer/NativePrincipalWriterFixtureTranscript.java']
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
            transcript = subprocess.run(['java', '-Xmx256m', '-Djava.io.tmpdir=' + str(output), '-ea',
                                         '-cp', str(output), 'com.android.server.pm.NativePrincipalWriterFixtureTranscript'],
                                        capture_output=True, text=True, timeout=90)
            self.assertEqual(transcript.returncode, 0, transcript.stdout + transcript.stderr)
            spec = importlib.util.spec_from_file_location('writer_observe_actual', HERE / 'writer_observe.py')
            observer = importlib.util.module_from_spec(spec); spec.loader.exec_module(observer)
            instance, nonce = 'a' * 32, 'b' * 32
            selected = {'app_id': 10148, 'user_id': 0, 'user_serial': 7, 'version_code': 1,
                        'signer_sha256': '039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81'}
            seen = set()
            for line in transcript.stdout.splitlines():
                label, code, encoded, errors = line.split('\t'); code = int(code); self.assertNotIn(label, seen); seen.add(label)
                text = base64.b64decode(encoded, validate=True).decode(); stderr = base64.b64decode(errors, validate=True).decode()
                if label == 'denied': observer.caller_denied(text, stderr, code)
                elif label == 'info': self.assertEqual(observer.parse_info(text)['instance'], instance)
                elif label == 'stale': observer.refusal(text, 'STALE_INSTANCE', instance,
                        requested_instance='c' * 32, returncode=code, stderr=stderr)
                elif label in {'commit', 'status'}:
                    observed = observer.assess_commit(text, instance=instance, nonce=nonce, selected=selected,
                            expected_id=1, intent='select-new', transport_operation=label, returncode=code, stderr=stderr)
                    self.assertEqual(observed['assessment_origin'], 'commit-reply' if label == 'commit' else 'status-reconciliation')
                elif label == 'unknown':
                    self.assertEqual(code, 1)
                    self.assertEqual(stderr.strip(), 'native writer fixture outcome unknown: REPLY_UNAVAILABLE')
                    self.assertNotIn('test detail', text + stderr)
                    with self.assertRaises(ValueError): observer.parse(text, instance=instance, nonce=nonce, selected=selected)
                else: observer.parse(text, instance=instance, nonce=nonce, selected=selected)
            self.assertEqual(seen, {'denied', 'info', 'stale', 'select', 'prepare', 'commit', 'status', 'unknown'})


if __name__ == '__main__':
    unittest.main()
