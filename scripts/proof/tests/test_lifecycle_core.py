# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]


class LifecycleCoreTests(unittest.TestCase):
    def test_actual_native_lifecycle_gate_boundaries(self):
        compiler=shutil.which('g++')
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory() as temp:
            binary=Path(temp)/'lifecycle-core'
            result=subprocess.run([compiler,'-std=c++20','-Wall','-Wextra','-Werror','-O2',
                '-I'+str(ROOT/'owner/native'),str(ROOT/'owner/native/lifecycle_core.cpp'),
                str(ROOT/'owner/native/session_core.cpp'),str(ROOT/'owner/tests/lifecycle_core_test.cpp'),
                '-o',str(binary)],capture_output=True,text=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            ran=subprocess.run([str(binary)],capture_output=True,text=True,timeout=20)
            self.assertEqual(ran.returncode,0,ran.stdout+ran.stderr)
            self.assertIn('Android unqualified',ran.stdout)


if __name__=='__main__':unittest.main()
