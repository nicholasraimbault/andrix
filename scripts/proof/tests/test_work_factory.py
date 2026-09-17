# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]


class WorkFactoryFixtureTests(unittest.TestCase):
    def test_kernel_probe_refuses_undelegated_invocation(self):
        probe = ROOT/'tests/work-factory/kernel_scopes.py'
        result = subprocess.run([sys.executable, '-I', '-B', str(probe)],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('refusing a cgroup outside the exact proof-unit shape', result.stderr)
        self.assertNotIn('released', result.stdout)


if __name__ == '__main__':
    unittest.main()
