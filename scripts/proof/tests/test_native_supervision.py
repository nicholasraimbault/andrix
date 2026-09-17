# SPDX-License-Identifier: Apache-2.0
"""Native component checks, not Android service integration or authorization proof."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
NATIVE = ROOT/'supervision/native'


class NativeSupervisionTests(unittest.TestCase):
    def compile_and_run(self, name, extra=()):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory)/name
            result = subprocess.run(['g++','-std=c++20','-O2','-Wall','-Wextra','-Werror',
                '-I'+str(NATIVE),str(NATIVE/(name+'.cpp')),
                *[str(NATIVE/(source+'.cpp')) for source in extra],
                str(ROOT/'supervision/tests'/(name+'_test.cpp')),'-o',str(binary)],
                capture_output=True,text=True,timeout=180)
            self.assertEqual(result.returncode,0,result.stderr)
            result = subprocess.run([str(binary)],capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_native_instance_state(self):
        self.compile_and_run('instance_state')

    def test_captured_group_parser_and_refusal(self):
        self.compile_and_run('captured_cgroup')

    def test_private_cleanup_worker_channel(self):
        self.compile_and_run('cleanup_worker', ('captured_cgroup',))

    def test_cleanup_worker_driver_requires_owned_delegation(self):
        result = subprocess.run([sys.executable,'-I','-B',
            str(ROOT/'tests/delegated-supervision/cleanup_worker_kernel.py')],
            capture_output=True,text=True,timeout=15)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('owned cleanup worker proof delegation only',result.stderr)

    def test_native_kernel_driver_requires_owned_delegation(self):
        result = subprocess.run([sys.executable,'-I','-B',
            str(ROOT/'tests/delegated-supervision/native_cleanup_kernel.py')],
            capture_output=True,text=True,timeout=15)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('owned native proof delegation only',result.stderr)


if __name__ == '__main__':
    unittest.main()
