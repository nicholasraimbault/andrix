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


class NativeIdentityStoreTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('javac') and shutil.which('java'), 'JDK required')
    def test_records_and_store_on_jvm(self):
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
                         ['NativeIdentityRecordsTest', 'NativeIdentityStoreTest']],
                       *[p for p in sorted((ROOT / 'owner/tests/platform/native_principal_xml_stubs')
                                          .rglob('*.java')) if p.name != 'Xml.java']]
            compile_result = subprocess.run(
                ['javac', '-J-Xmx256m', '--release', '17', '-Xlint:all', '-Werror',
                 '-d', str(work), *map(str, sources)], capture_output=True, text=True, timeout=120)
            self.assertEqual(compile_result.returncode, 0,
                             compile_result.stdout + compile_result.stderr)
            for name in ['NativeIdentityRecordsTest', 'NativeIdentityStoreTest']:
                result = subprocess.run(
                    ['java', '-Xmx256m', '-ea', '-cp', str(work), 'com.android.server.pm.' + name,
                     str(work)], capture_output=True, text=True, timeout=90)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('unqualified', result.stdout)
            negative = subprocess.run(
                ['java', '-Xmx256m', '-cp', str(work),
                 'com.android.server.pm.NativeIdentityRecordsTest'],
                capture_output=True, text=True, timeout=30)
            self.assertNotEqual(negative.returncode, 0)
            self.assertIn('run with java -ea', negative.stderr)


if __name__ == '__main__':
    unittest.main()
