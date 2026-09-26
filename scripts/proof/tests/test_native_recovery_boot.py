# SPDX-License-Identifier: Apache-2.0
"""Exact adapted boot fragments. Not Android boot, PMS permissions or filesystem proof."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import native_principal_pins as integration


def boot_source(fragments=None):
    fragments = fragments or {name: path.read_text() for name, (_, path) in integration.FRAGMENTS.items()}
    text = (ROOT / 'owner/tests/platform/NativeRecoveryBootTest.java.in').read_text()
    tags = {'IDENTITY_PREDICATE': 'identity', 'SYSTEM_CLEANUP_PREFIX': 'system-cleanup',
            'PARSE_FAILURE_PRESERVATION': 'parse-failure', 'INSTALL_MARKERS': 'install-markers',
            'SYSTEM_DELETE': 'system-delete', 'PATH_SAFETY': 'path-safety',
            'RESTORE_CAPACITY': 'restore-capacity'}
    for tag, name in tags.items():
        text = text.replace('@' + tag + '@', fragments[name])
    return text


class NativeRecoveryBootTests(unittest.TestCase):
    def test_fragment_source_profile(self):
        profile = integration.profile()
        self.assertEqual(len(profile['fragments']), 7)
        source = boot_source()
        self.assertNotIn('@IDENTITY_PREDICATE@', source)
        self.assertIn('claimInstallingPackageLocked', source)
        self.assertIn('if (!ps.isSystem())', source)

    @unittest.skipUnless(shutil.which('javac') and shutil.which('java'), 'JDK required')
    def test_actual_patched_fragments_on_jvm(self):
        integration.profile()
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            test = work / 'NativeRecoveryBootTest.java'
            test.write_text(boot_source())
            writer = work / 'ResilientAtomicFile.java'
            writer.write_bytes(integration.FIXTURES[
                integration.PREFIX + 'ResilientAtomicFile.java'].read_bytes())
            sources = [test, writer,
                       *[ROOT / 'owner/platform/framework' / (name + '.java') for name in
                         ['NativePrincipalPins', 'NativeIdentityRecords', 'NativeIdentityStore',
                          'NativePrincipalRecovery']],
                       *[p for p in sorted((ROOT / 'owner/tests/platform/native_principal_xml_stubs')
                                          .rglob('*.java')) if p.name != 'Xml.java']]
            compiled = subprocess.run(['javac', '-J-Xmx256m', '--release', '17', '-Xlint:all',
                                       '-Werror', '-d', str(work), *map(str, sources)],
                                      capture_output=True, text=True, timeout=120)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run(['java', '-Xmx256m', '-ea', '-cp', str(work),
                                     'com.android.server.pm.NativeRecoveryBootTest'],
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('Android boot unqualified', result.stdout)


if __name__ == '__main__':
    unittest.main()
