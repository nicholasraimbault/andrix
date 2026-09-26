# SPDX-License-Identifier: Apache-2.0
"""Host checks of actual fixture request and production record codec logic, not Android execution."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


@unittest.skipUnless(shutil.which('javac') and shutil.which('java'), 'JDK required')
class FixtureJvmTests(unittest.TestCase):
    def test_request_and_canonical_variants(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            files = [ROOT / 'owner/platform/framework/NativeIdentityRecords.java',
                     HERE / 'src/dev/andrix/proof/uidstore/RecoveryRequest.java',
                     HERE / 'RecoveryRequestTest.java', HERE / 'FixtureStore.java',
                     HERE / 'FixtureVariant.java', HERE / 'FixtureVariantTest.java']
            result = subprocess.run(['javac', '-J-Xmx256m', '--release', '17', '-Xlint:all', '-Werror',
                                     '-d', str(output), *map(str, files)],
                                    capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for name in ('RecoveryRequestTest', 'FixtureVariantTest'):
                result = subprocess.run(['java', '-Xmx256m', '-ea', '-cp', str(output), name],
                                        capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                refused = subprocess.run(['java', '-Xmx256m', '-cp', str(output), name],
                                         capture_output=True, text=True, timeout=60)
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn('-ea', refused.stderr)


if __name__ == '__main__':
    unittest.main()
