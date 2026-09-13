# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class CeStorageAccessTests(unittest.TestCase):
    def test_exact_framework_connection_lock_restore_and_reset(self):
        javac, java = shutil.which('javac'), shutil.which('java')
        self.assertIsNotNone(javac)
        self.assertIsNotNone(java)
        harness = (ROOT / 'owner/tests/platform/StorageManagerHookTest.java.in').read_text()
        methods = (ROOT / 'owner/tests/platform/StorageManagerMethods.java.inc').read_text()
        self.assertEqual(harness.count('// EXACT_FRAMEWORK_METHODS'), 1)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'StorageManagerHookTest.java'
            source.write_text(harness.replace('// EXACT_FRAMEWORK_METHODS', methods))
            subprocess.run([javac, '--release', '17', '-Xlint:all', '-Werror', '-d', directory,
                str(ROOT / 'owner/platform/framework/CeStorageAccessTracker.java'), str(source)],
                check=True, capture_output=True, text=True, timeout=60)
            ran = subprocess.run([java, '-ea', '-cp', directory, 'StorageManagerHookTest'],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            self.assertIn('Exact framework connection/lock/restore/reset methods passed', ran.stdout)
            self.assertIn('Android unqualified', ran.stdout)

    def test_user_and_ce_composition(self):
        javac, java = shutil.which('javac'), shutil.which('java')
        self.assertIsNotNone(javac)
        self.assertIsNotNone(java)
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run([javac, '--release', '17', '-Xlint:all', '-Werror', '-d', directory,
                str(ROOT / 'owner/platform/java/dev/andrix/server/OwnerLifecycleState.java'),
                str(ROOT / 'owner/tests/platform/OwnerLifecycleStateTest.java')],
                check=True, capture_output=True, text=True, timeout=60)
            ran = subprocess.run([java, '-ea', '-cp', directory,
                'dev.andrix.server.OwnerLifecycleStateTest'],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            self.assertIn('composition/epoch model passed; runtime unqualified', ran.stdout)

    def test_actual_tracker_fencing_and_listener_contract(self):
        javac, java = shutil.which('javac'), shutil.which('java')
        self.assertIsNotNone(javac)
        self.assertIsNotNone(java)
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run([javac, '--release', '17', '-Xlint:all', '-Werror', '-d', directory,
                str(ROOT / 'owner/platform/framework/CeStorageAccessTracker.java'),
                str(ROOT / 'owner/tests/platform/CeStorageAccessTrackerTest.java')],
                check=True, capture_output=True, text=True, timeout=60)
            ran = subprocess.run([java, '-ea', '-cp', directory,
                'com.android.server.storage.CeStorageAccessTrackerTest'],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            self.assertIn('CE observation fencing/registration/reset tests passed', ran.stdout)
            self.assertIn('Android unqualified', ran.stdout)


if __name__ == '__main__':
    unittest.main()
