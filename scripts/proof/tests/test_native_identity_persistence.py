# SPDX-License-Identifier: Apache-2.0
"""Native identity transactions and negative recovery view on the JVM, not PMS/device proof."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import native_principal_pins as integration


class NativeIdentityPersistenceTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('javac') and shutil.which('java'), 'JDK required')
    def test_owned_transactions_and_recovery_view_on_jvm(self):
        integration.profile()
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            writer = work / 'ResilientAtomicFile.java'
            writer.write_bytes(integration.FIXTURES[
                integration.PREFIX + 'ResilientAtomicFile.java'].read_bytes())
            sources = [writer,
                       *[ROOT / 'owner/platform/framework' / (name + '.java') for name in
                         ['NativePrincipalPins', 'NativeIdentityRecords', 'NativeIdentityStore',
                          'NativeIdentityPersistence', 'NativePrincipalRecovery']],
                       *[ROOT / 'owner/tests/platform' / (name + '.java') for name in
                         ['NativeIdentityPersistenceTest', 'NativePrincipalRecoveryTest']],
                       *[p for p in sorted((ROOT / 'owner/tests/platform/native_principal_xml_stubs')
                                          .rglob('*.java')) if p.name != 'Xml.java']]
            built = subprocess.run(
                ['javac', '-J-Xmx256m', '--release', '17', '-Xlint:all', '-Werror',
                 '-d', str(work), *map(str, sources)], capture_output=True, text=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            for name in ['NativePrincipalRecoveryTest', 'NativeIdentityPersistenceTest']:
                result = subprocess.run(
                    ['java', '-Xmx256m', '-ea', '-cp', str(work), 'com.android.server.pm.' + name,
                     str(work)], capture_output=True, text=True, timeout=300)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('unqualified', result.stdout)


if __name__ == '__main__':
    unittest.main()
