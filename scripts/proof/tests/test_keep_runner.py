# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class KeepRunnerTests(unittest.TestCase):
    def test_fixed_modes_and_namespaces(self):
        compiler = shutil.which('g++')
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'runner-command'
            compiled = subprocess.run([compiler, '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-I' + str(ROOT / 'owner/native'), str(ROOT / 'owner/tests/runner_command_test.cpp'),
                '-o', str(binary)], capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            self.assertIn('Android unqualified', ran.stdout)


if __name__ == '__main__':
    unittest.main()
