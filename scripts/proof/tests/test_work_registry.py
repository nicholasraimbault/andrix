# SPDX-License-Identifier: Apache-2.0
"""Actual internal registry/gate tests, not Android caller or cleanup proof."""
from pathlib import Path
import json
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
NATIVE = ROOT/'owner/native'


class WorkRegistryTests(unittest.TestCase):
    def test_bounded_registry_and_selected_concurrent_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory)/'work-registry'
            command = ['g++', '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror',
                       '-UNDEBUG', '-pthread', '-I'+str(NATIVE),
                       *[str(NATIVE/name) for name in ['work_registry.cpp', 'work_admission.cpp',
                                                      'launch_description.cpp']],
                       str(ROOT/'owner/tests/work_registry_test.cpp'), '-o', str(binary)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=180)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=45)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            observations = json.loads(result.stdout)
            self.assertEqual(observations['registry_cases'], 13)
            self.assertEqual(observations['finite_duplicate_start_races'], 200)
            self.assertEqual(observations['finite_start_stop_races'], 200)
            self.assertEqual(observations['finite_late_allocation_races'], 200)
            self.assertFalse(observations['Android_authentication_or_kernel_cleanup_qualified'])

    def test_direct_stop_has_no_registry_or_record_lock(self):
        source = (NATIVE/'work_registry.cpp').read_text()
        start = source.index('  bool Stop(WorkStopSource source)')
        stop = source[start:source.index('  bool InitialAccounted()', start)]
        self.assertIn('requests.compare_exchange_weak', stop)
        self.assertIn('gate->Stop()', stop)
        for token in ['lock_guard', 'unique_lock', 'new ', 'notify_', 'syscall', 'write(']:
            self.assertNotIn(token, stop)
        self.assertIn('ordinary entry exit does NOT request termination', source)

    def test_no_new_public_entry_or_persistent_recording(self):
        legacy = (NATIVE/'andrixd.cpp').read_text()
        self.assertNotIn('work_registry.h', legacy)
        self.assertNotIn('WorkRegistry', legacy)
        product = (ROOT/'products/andrix_gos_cf_arm64_only_phone.mk').read_text()
        self.assertNotIn('andrix_work_registry', product)
        build = (ROOT/'owner/Android.bp').read_text()
        registry = build[build.index('name: "andrix_work_registry",'):]
        registry = registry[:registry.index('\n}')]
        self.assertIn('whole_static_libs: ["andrix_launch_description"]', registry)
        source = (NATIVE/'work_registry.cpp').read_text()
        for token in ['fopen(', 'open(', 'write(', 'printf(', 'LOG(', 'fork(', 'execve(']:
            self.assertNotIn(token, source)
        header = (NATIVE/'work_registry.h').read_text()
        self.assertIn('not a public transport or authenticator', header)
        self.assertIn('not a claim of exclusive physical causation', header)


if __name__ == '__main__':
    unittest.main()
