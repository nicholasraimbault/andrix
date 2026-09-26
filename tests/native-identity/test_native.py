# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(shutil.which('cc'), 'C compiler required')
class QuiesceHelperTests(unittest.TestCase):
    def test_captured_process_descriptor_and_subject_validation(self):
        source = Path(__file__).with_name('quiesce_writer.c')
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'test'
            result = subprocess.run(['cc', '-std=c17', '-O2', '-Wall', '-Wextra', '-Werror',
                                     '-DQUIESCE_TEST', '-UNDEBUG', str(source), '-o', str(target)],
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(target)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('Android stop unqualified', result.stdout)
            refused = subprocess.run(['cc', '-std=c17', '-DQUIESCE_TEST', '-DNDEBUG', str(source),
                                      '-o', str(target)], capture_output=True, text=True, timeout=60)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn('assertions are required', refused.stderr)


if __name__ == '__main__':
    unittest.main()
