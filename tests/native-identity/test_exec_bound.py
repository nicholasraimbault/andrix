# SPDX-License-Identifier: Apache-2.0
"""Host controls only. The caller must provide the actual bounded cgroup."""
from pathlib import Path
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import native_creation_binding


class ExecutableBoundHelperTests(unittest.TestCase):
    def test_running_bytes_and_child_lifetime(self):
        reason = native_creation_binding.resource_guard()
        if reason:
            raise RuntimeError('real resource scope required before compilation: ' + reason)
        compiler = shutil.which('cc')
        if compiler is None:
            self.fail('C compiler required, not a qualified skip')
        directory = Path(__file__).parent
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            env = dict(os.environ, TMPDIR=str(work))
            flags = ['-std=c17', '-O2', '-Wall', '-Wextra', '-Werror', '-fPIE', '-pie']
            source = directory / 'quiesce_writer_exec_bound.c'
            target = work / 'self-test'
            build = subprocess.run([compiler, *flags, '-DQUIESCE_EXEC_TEST', '-UNDEBUG',
                                    str(source), '-o', str(target)],
                                   capture_output=True, text=True, timeout=60, env=env)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            target.chmod(0o700)
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            result = subprocess.run([str(target), digest], capture_output=True, text=True,
                                    timeout=20, env=env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(digest, result.stdout)
            self.assertIn('Android stop unqualified', result.stdout)
            refused = subprocess.run([compiler, '-std=c17', '-DQUIESCE_EXEC_TEST',
                                      '-DNDEBUG', str(source), '-o', str(work / 'refused')],
                                     capture_output=True, text=True, timeout=60, env=env)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn('assertions and explicit verification must remain enabled', refused.stderr)
            supplemental = directory / 'quiesce_writer_exec_bound_test.c'
            more = work / 'metadata-test'
            build = subprocess.run([compiler, *flags, '-UNDEBUG', str(supplemental),
                                    '-o', str(more)], capture_output=True, text=True,
                                   timeout=60, env=env)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            more.chmod(0o700)
            result = subprocess.run([str(more)], capture_output=True, text=True,
                                    timeout=20, env=env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('actual PDEATHSIG child exit passed', result.stdout)


if __name__ == '__main__':
    unittest.main()
