# SPDX-License-Identifier: Apache-2.0
"""Actual terminal process bookkeeping, not Android supervision or retention authority."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class TerminalProcessTests(unittest.TestCase):
    def test_roles_replacement_exit_and_retirement(self):
        compiler = shutil.which('g++')
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory() as directory:
            for name,flags in [('optimized', ['-O2']),
                               ('sanitized', ['-g', '-fsanitize=address,undefined',
                                              '-fno-omit-frame-pointer'])]:
                with self.subTest(configuration=name):
                    binary = Path(directory) / name
                    built = subprocess.run([compiler, '-std=c++20', '-Wall', '-Wextra', '-Werror',
                        *flags, '-I' + str(ROOT / 'owner/native'),
                        str(ROOT / 'owner/native/terminal_process.cpp'),
                        str(ROOT / 'owner/tests/terminal_process_test.cpp'), '-o', str(binary)],
                        capture_output=True, text=True, timeout=180)
                    self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
                    ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
                    self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
                    self.assertIn('Android unqualified', ran.stdout)


if __name__ == '__main__':
    unittest.main()
