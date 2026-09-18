# SPDX-License-Identifier: Apache-2.0
"""Internal gate units and real host processes, not Android work API qualification."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
NATIVE = ROOT/'owner/native'


class WorkAdmissionTests(unittest.TestCase):
    def compile_and_run(self, name):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory)/name
            command = ['g++','-std=c++20','-O2','-Wall','-Wextra','-Werror','-pthread',
                       '-I'+str(NATIVE),str(NATIVE/'work_admission.cpp'),
                       str(ROOT/'owner/tests'/(name+'.cpp')),'-o',str(binary)]
            result = subprocess.run(command,capture_output=True,text=True,timeout=180)
            self.assertEqual(result.returncode,0,result.stderr)
            result = subprocess.run([str(binary)],capture_output=True,text=True,timeout=40)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            return result.stdout

    def test_atomic_admission_and_authority_lifetime(self):
        self.compile_and_run('work_admission_test')

    def test_real_queued_wake_cannot_revive_a_stopped_gate(self):
        output = self.compile_and_run('work_admission_process_test')
        self.assertIn('"queued_wake_after_Stop_denied":true',output)
        self.assertIn('"late_helper_old_epoch_denied":true',output)
        self.assertIn('"Android_authority_or_exec_profile_qualified":false',output)

    def test_platform_adapter_supplies_original_binding_and_issue_deadline(self):
        source = (NATIVE/'platform_lifecycle.cpp').read_text()
        self.assertIn('admissions_.Revoke()',source)
        self.assertIn('gate_.ready_until(received)',source)
        self.assertIn('static_cast<uint64_t>(generation_), 0',source)
        self.assertIn('admissions_.Admit(work, current)',source)
        self.assertIn('admissions_.Release(work, current, gate_.ready_until(current))',source)
        self.assertLess(source.index('gate_.report(registration_, challenge, received'),
                        source.index('admissions_.Observe(epoch'))
        # Existing presentation/Keep code does not start using the candidate API.
        legacy = (NATIVE/'andrixd.cpp').read_text()
        for method in ['admit_work(', 'prepare_work(', 'release_work(']:
            self.assertNotIn(method,legacy)


if __name__ == '__main__':unittest.main()
