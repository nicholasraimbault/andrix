# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]


class LaunchDescriptionTests(unittest.TestCase):
    def compile_and_run(self, name):
        with tempfile.TemporaryDirectory() as directory:
            binary=Path(directory)/'launch-description'
            result=subprocess.run(['g++','-std=c++20','-O2','-Wall','-Wextra','-Werror',
                '-I'+str(ROOT/'owner/native'),str(ROOT/'owner/native'/(name+'.cpp')),
                str(ROOT/'owner/tests'/(name+'_test.cpp')),'-o',str(binary)],
                capture_output=True,text=True,timeout=120)
            self.assertEqual(result.returncode,0,result.stderr)
            result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=20)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_immutable_bounded_ordinary_description(self):
        self.compile_and_run('launch_description')

    def test_private_complete_launch_handoff(self):
        self.compile_and_run('work_launch_protocol')

    def test_control_handles_leave_before_owner_role(self):
        launcher=''.join((ROOT/'owner/native/work_launcher.cpp').read_text().split())
        final_exec=launcher.index('execve(entry,arguments,environment)')
        self.assertLess(launcher.index('install_worker_filter()'),final_exec)
        self.assertLess(launcher.index('ClaimEntry('),launcher.index('gate.reset()'))
        self.assertLess(launcher.index('gate.reset()'),final_exec)
        self.assertLess(launcher.index('SYS_close_range'),final_exec)
        self.assertIn('/system_ext/bin/andrix-work-entry',launcher)
        entry=''.join((ROOT/'owner/native/work_entry.cpp').read_text().split())
        self.assertNotIn('WorkAdmission',entry)
        self.assertIn('CheckOwnerEntry()',entry)
        self.assertLess(entry.index('close(3)'),entry.index('chdir(description.directory'))
        self.assertIn('execve(description.executable',entry)


if __name__=='__main__':unittest.main()
