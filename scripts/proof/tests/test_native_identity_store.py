# SPDX-License-Identifier: Apache-2.0
"""Actual native identity records/store with host facades, not PMS or device proof."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import native_principal_pins as integration
import native_creation_binding as b1


class NativeIdentityStoreTests(unittest.TestCase):
    def test_records_and_store_on_jvm(self):
        self.assertTrue(shutil.which('javac') and shutil.which('java'), 'identity store qualification requires a JDK on PATH')
        # The writer is the exact guarded framework adaptation, not a parallel
        # Python model or a replacement that treats readback as fsync success.
        integration.profile()
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            writer = work / 'ResilientAtomicFile.java'
            writer.write_bytes(integration.FIXTURES[
                integration.PREFIX + 'ResilientAtomicFile.java'].read_bytes())
            sources = [writer,
                       *[ROOT / 'owner/platform/framework' / (name + '.java') for name in
                         ['NativeIdentityRecords', 'NativeIdentityStore']],
                       *[ROOT / 'owner/tests/platform' / (name + '.java') for name in
                         ['NativeIdentityRecordsTest', 'NativeIdentityStoreTest', 'NativeIdentityVersionGateTest',
                          'NativeIdentityFutureFormatTest', 'NativeIdentityPresenceTest']],
                       *[p for p in sorted((ROOT / 'owner/tests/platform/native_principal_xml_stubs')
                                          .rglob('*.java')) if p.name != 'Xml.java']]
            compile_result = subprocess.run(
                ['javac', '-J-Xmx256m', '--release', '17', '-Xlint:all', '-Werror',
                 '-d', str(work), *map(str, sources)], capture_output=True, text=True, timeout=120)
            self.assertEqual(compile_result.returncode, 0,
                             compile_result.stdout + compile_result.stderr)
            for name in ['NativeIdentityRecordsTest', 'NativeIdentityStoreTest', 'NativeIdentityVersionGateTest',
                         'NativeIdentityFutureFormatTest', 'NativeIdentityPresenceTest']:
                result = subprocess.run(
                    ['java', '-Xmx256m', '-ea', '-cp', str(work), 'com.android.server.pm.' + name,
                     str(work)], capture_output=True, text=True, timeout=90)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('unqualified', result.stdout)
                if name == 'NativeIdentityFutureFormatTest':
                    # Every isolated writer path ran with its healthy control and damaged twin,
                    # over slot frames above version 2 with and without a valid stable prefix.
                    self.assertIn('291 passed, 0 failed', result.stdout)
                    self.assertNotIn('FAIL ', result.stdout)
                if name == 'NativeIdentityPresenceTest':
                    # Actual unprivileged permissions refused both probes; a bypass fails the run. Under
                    # Format.V1 each release step and the retiring flag refuse on their healthy layout.
                    self.assertIn('Unprivileged DAC refused', result.stdout)
                    self.assertIn('%d passed, 0 failed' % b1.PRESENCE_PASSED['V1'], result.stdout)
                    self.assertNotIn('FAIL ', result.stdout)
                    for refusal in b1.PRESENCE_REFUSALS:
                        self.assertIn('PASS V1 / ' + refusal + '\n', result.stdout)
                if name == 'NativeIdentityVersionGateTest':
                    # The format refusal control beside the gate rows: every lifecycle write refuses on a
                    # healthy version 1 layout, so the gate rows mask nothing.
                    self.assertIn('PASS V1 / every lifecycle write refused on a healthy layout', result.stdout)
            # The future format matrix's lifecycle rows under Format.V3: their own entry point, run as
            # their own step with their own limit, beside the version 1 matrix's.
            lifecycle = subprocess.run(
                ['java', '-Xmx256m', '-ea', '-cp', str(work), 'com.android.server.pm.NativeIdentityFutureFormatTest',
                 str(work), 'V3'], capture_output=True, text=True, timeout=120)
            self.assertEqual(lifecycle.returncode, 0, lifecycle.stdout + lifecycle.stderr)
            self.assertIn('148 passed, 0 failed', lifecycle.stdout)
            self.assertNotIn('FAIL ', lifecycle.stdout)
            self.assertIn('unqualified', lifecycle.stdout)
            gate = subprocess.run(
                ['java', '-Xmx256m', '-ea', '-cp', str(work), 'com.android.server.pm.NativeIdentityVersionGateTest',
                 str(work), 'V3'], capture_output=True, text=True, timeout=60)
            self.assertEqual(gate.returncode, 0, gate.stdout + gate.stderr)
            self.assertIn('Lifecycle format refusal of the release primitives', gate.stdout)
            # The production format's refusal controls: their own entry point, under the production label.
            production = subprocess.run(
                ['java', '-Xmx256m', '-ea', '-cp', str(work), 'com.android.server.pm.NativeIdentityVersionGateTest',
                 str(work), 'V2'], capture_output=True, text=True, timeout=60)
            self.assertEqual(production.returncode, 0, production.stdout + production.stderr)
            self.assertEqual(production.stdout, 'PASS V2 / every lifecycle write refused on a healthy layout\n')
            for name in ['NativeIdentityRecordsTest', 'NativeIdentityVersionGateTest',
                         'NativeIdentityFutureFormatTest', 'NativeIdentityPresenceTest']:
                negative = subprocess.run(
                    ['java', '-Xmx256m', '-cp', str(work), 'com.android.server.pm.' + name, str(work)],
                    capture_output=True, text=True, timeout=30)
                self.assertNotEqual(negative.returncode, 0)
                self.assertIn('-ea', negative.stderr)


if __name__ == '__main__':
    unittest.main()
