# SPDX-License-Identifier: Apache-2.0
"""Native PMS reservation components with host facades, not Android runtime proof."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import native_principal_pins as integration


class NativePrincipalPinsTests(unittest.TestCase):
    def test_exact_source_profile_and_fixtures(self):
        profile = integration.profile()
        self.assertEqual(len(profile['files']), 6)
        self.assertEqual(len(profile['added']), 5)
        self.assertEqual(len(profile['fixtures']), 2)
        with self.assertRaises(ValueError):
            integration.targets({name: b'wrong source' for name in integration.FILES}, profile)
        patch = integration.PATCH.read_text()
        self.assertIn('finishWriteStrict(str)', patch)
        self.assertIn('mNativePrincipalWriteConfirmed', patch)
        self.assertIn('nativePrincipalMutationsAllowedLocked', patch)
        self.assertIn('mNativePrincipalMutations', patch)
        self.assertIn('NativePrincipalPinsXml.readForSettings(parser)', patch)
        self.assertIn('Native account backing package cannot be replaced by a system scan', patch)
        self.assertLess(patch.index('Native account backing package cannot be replaced by a system scan'),
                        patch.index('PackageVerityExt.addSystemPackage(parsedPackage)'))
        self.assertNotIn('INSTR_FLAG_DISABLE_HIDDEN_API_CHECKS', patch)

    def test_profile_drift_refused(self):
        original = json.loads(integration.PROFILE.read_text())
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'profile.json'
            for changed in [dict(original, version=True), dict(original, head='0' * 40),
                            dict(original, patch_sha256='0' * 64), dict(original, fixtures=[])]:
                path.write_text(json.dumps(changed))
                with mock.patch.object(integration, 'PROFILE', path), self.assertRaises(ValueError):
                    integration.profile()
            patch = Path(temporary) / 'wrong.patch'
            patch.write_text(integration.PATCH.read_text().replace('a/' + integration.FILES[0], 'a/../outside.java'))
            path.write_text(json.dumps(dict(original, patch_sha256=hashlib.sha256(patch.read_bytes()).hexdigest())))
            with mock.patch.object(integration, 'PROFILE', path), mock.patch.object(integration, 'PATCH', patch), self.assertRaises(ValueError):
                integration.profile()

    def test_retirement_and_publication_are_separate_gates(self):
        manager = (ROOT / 'owner/platform/framework/NativePrincipalManager.java').read_text()
        self.assertIn('beginRetirement(Handle handle)', manager)
        self.assertIn('finishRetirementAfterQuiescence(Handle handle)', manager)
        self.assertIn('if (!handle.retirementCommitted)', manager)
        self.assertIn('pins.snapshotWithout(handle.pin)', manager)
        self.assertLess(manager.index('persistNativePrincipalPinsLPr(pm.snapshotComputer(), candidate)'),
                        manager.index('pins.finishRetire(handle.pin)'))
        self.assertIn('pm.mInstallLock.acquireLock()', manager)
        self.assertIn('pm.isInstallingNativePrincipalPackage', manager)
        self.assertIn('nativePrincipalMutationInProgressLPr', manager)
        self.assertIn('UserHandle.USER_SYSTEM', manager)
        self.assertNotIn('extends Binder', manager)
        self.assertNotIn('publishBinderService', manager)
        writer = integration.FIXTURES[integration.PREFIX + 'ResilientAtomicFile.java'].read_text()
        strict = writer[writer.index('void finishWriteStrict'):writer.index('public void failWrite')]
        self.assertIn('stream.getFD().sync()', strict)
        self.assertNotIn('FileUtils.sync', strict)
        self.assertLess(strict.index('finalizeStrict(mReserveOutStream)'), strict.index('mTemporaryBackup.delete()'))
        self.assertIn('Os.fsync(directory)', strict)

    @unittest.skipUnless(shutil.which('javac') and shutil.which('java'), 'JDK required')
    def test_state_allocator_and_adapter_on_jvm(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            allocator = work / 'AppIdSettingMap.java'
            allocator.write_bytes(integration.FIXTURES[integration.PREFIX + 'AppIdSettingMap.java'].read_bytes())
            sources = [ROOT / 'owner/platform/framework/NativePrincipalPins.java',
                       ROOT / 'owner/platform/framework/NativePrincipalManager.java', allocator,
                       *sorted((ROOT / 'owner/tests/platform/native_principal_stubs').rglob('*.java')),
                       *[ROOT / 'owner/tests/platform' / (name + '.java') for name in
                         ['NativePrincipalPinsTest', 'NativePrincipalAllocatorTest', 'NativePrincipalManagerTest']]]
            subprocess.run(['javac', '-J-Xmx256m', '--release', '17', '-Xlint:all', '-Werror', '-d', str(work),
                            *map(str, sources)], check=True, capture_output=True, timeout=120)
            for name in ['NativePrincipalPinsTest', 'NativePrincipalAllocatorTest', 'NativePrincipalManagerTest']:
                result = subprocess.run(['java', '-Xmx256m', '-ea', '-cp', str(work), 'com.android.server.pm.' + name],
                                        capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('unqualified', result.stdout)

    @unittest.skipUnless(shutil.which('javac') and shutil.which('java'), 'JDK required')
    def test_xml_and_actual_writer_failure_checks_with_facades(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            writer = work / 'ResilientAtomicFile.java'
            writer.write_bytes(integration.FIXTURES[integration.PREFIX + 'ResilientAtomicFile.java'].read_bytes())
            fragments = '\n'.join(line[1:] for line in integration.PATCH.read_text().splitlines()
                                  if line.startswith((' ', '+')) and not line.startswith('+++'))
            start = fragments.index('                // Every failed settings read needs native recovery, even before our tag.')
            end = fragments.index('                // Remove corrupted file and retry.', start)
            fence = fragments[start:end]
            self.assertNotIn('if (sawNativePins)', fence)
            recovery = work / 'NativePrincipalReadFailureTest.java'
            template = (ROOT / 'owner/tests/platform/NativePrincipalReadFailureTest.java.in').read_text()
            recovery.write_text(template.replace('@FAILURE_FENCE@', fence))
            sources = [ROOT / 'owner/platform/framework/NativePrincipalPins.java',
                       ROOT / 'owner/platform/framework/NativePrincipalPinsXml.java', writer, recovery,
                       *sorted((ROOT / 'owner/tests/platform/native_principal_xml_stubs').rglob('*.java')),
                       ROOT / 'owner/tests/platform/NativePrincipalPersistenceTest.java']
            subprocess.run(['javac', '-J-Xmx256m', '--release', '17', '-Xlint:all', '-Werror', '-d', str(work),
                            *map(str, sources)], check=True, capture_output=True, timeout=120)
            files = work / 'files'
            files.mkdir()
            result = subprocess.run(['java', '-Xmx256m', '-ea', '-cp', str(work),
                                     'com.android.server.pm.NativePrincipalPersistenceTest', str(files)],
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('unqualified', result.stdout)
            result = subprocess.run(['java', '-Xmx256m', '-ea', '-cp', str(work),
                                     'com.android.server.pm.NativePrincipalReadFailureTest'],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('unqualified', result.stdout)


if __name__ == '__main__':
    unittest.main()
