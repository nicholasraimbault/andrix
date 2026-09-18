# SPDX-License-Identifier: Apache-2.0
"""Linux execute-only bootstrap mechanism, not Android entry/MAC qualification."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class ProtectedEntryTests(unittest.TestCase):
    def test_kernel_protects_bootstrap_then_restores_ordinary_debugging(self):
        if os.getuid()==0:
            self.skipTest('Requires an unprivileged caller, not a DAC override root process')
        with tempfile.TemporaryDirectory() as directory:
            directory=Path(directory)
            binary=directory/'readable-entry'
            result=subprocess.run(['g++','-std=c++20','-O2','-Wall','-Wextra','-Werror',
                str(ROOT/'owner/tests/protected_entry_test.cpp'),'-o',str(binary)],
                capture_output=True,text=True,timeout=90)
            self.assertEqual(result.returncode,0,result.stderr)
            binary.chmod(0o755)
            protected=directory/'execute-only-entry';shutil.copyfile(binary,protected);protected.chmod(0o111)
            result=subprocess.run([str(binary),str(binary),str(protected)],capture_output=True,text=True,timeout=40)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            rows=[json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual([row['protected_mode'] for row in rows],[False,True,False])
            self.assertEqual(rows[0]['initial_dumpable'],1)
            self.assertNotEqual(rows[1]['initial_dumpable'],1)
            self.assertTrue(all(row['final_readable_exec_debuggable'] for row in rows))


if __name__=='__main__':unittest.main()
