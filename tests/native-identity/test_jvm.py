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
                     HERE / 'FixtureVariant.java', HERE / 'FixtureVariantTest.java',
                     HERE / 'WriterStoreCheck.java', HERE / 'WriterStoreCheckTest.java',
                     HERE / 'FutureHeaderFixture.java', HERE / 'FutureHeaderFixtureTest.java',
                     HERE / 'HeaderFootprintFixture.java', HERE / 'HeaderFootprintFixtureTest.java']
            result = subprocess.run(['javac', '-J-Xmx256m', '--release', '17', '-Xlint:all', '-Werror',
                                     '-d', str(output), *map(str, files)],
                                    capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for name in ('RecoveryRequestTest', 'FixtureVariantTest', 'WriterStoreCheckTest',
                         'FutureHeaderFixtureTest', 'HeaderFootprintFixtureTest'):
                result = subprocess.run(['java', '-Xmx256m', '-Djava.io.tmpdir=' + str(output), '-ea', '-cp', str(output), name],
                                        capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                refused = subprocess.run(['java', '-Xmx256m', '-Djava.io.tmpdir=' + str(output), '-cp', str(output), name],
                                         capture_output=True, text=True, timeout=60)
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn('-ea', refused.stderr)
            # Generator validation is explicit, not disabled with Java assertions.
            for assertions in ('-ea', '-da'):
                for mode in ('bad-mode', 'legacy-addition'):
                    destination = (str(output / ('bad-' + assertions))
                                   if mode == 'bad-mode' else 'relative-header-fixture')
                    refused = subprocess.run(
                        ['java', '-Xmx128m', assertions, '-cp', str(output),
                         'HeaderFootprintFixture', destination, '10123', mode],
                        capture_output=True, text=True, timeout=30, cwd=output)
                    self.assertNotEqual(refused.returncode, 0)
                    self.assertFalse((output / destination).exists())


if __name__ == '__main__':
    unittest.main()
