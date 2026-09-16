# SPDX-License-Identifier: Apache-2.0
"""Real Linux process/PTY observations, not an Android supervision implementation."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / 'tests/owner-work-lifetime'
CASES = ('pty_hangup', 'last_master', 'ignored_hup', 'parent_exit', 'setsid_scope',
         'bash_hangup', 'bash_nohup', 'bash_disown', 'bash_exit', 'bash_login_exit')


class UnixWorkLifetimeTests(unittest.TestCase):
    def test_real_kernel_and_selected_shell_lifetime(self):
        compiler = shutil.which('g++')
        bash = shutil.which('bash')
        nohup = shutil.which('nohup')
        self.assertIsNotNone(compiler)
        self.assertIsNotNone(bash)
        self.assertIsNotNone(nohup)
        self.assertTrue(hasattr(os, 'pidfd_open'))
        shell_version = subprocess.run([bash, '--version'], capture_output=True, text=True, timeout=10)
        utility_version = subprocess.run([nohup, '--version'], capture_output=True, text=True, timeout=10)
        self.assertEqual(shell_version.returncode, 0, shell_version.stderr)
        self.assertEqual(utility_version.returncode, 0, utility_version.stderr)
        self.assertIn('GNU bash', shell_version.stdout)
        self.assertIn('GNU coreutils', utility_version.stdout)
        results = os.environ.get('ANDRIX_LIFETIME_PROOF_RESULTS_DIR')
        if results:
            results = Path(results)
            results.mkdir(mode=0o700)
            with (results / 'tools.json').open('x') as f:
                json.dump({'shell': bash, 'version': shell_version.stdout,
                           'nohup': nohup, 'nohup_version': utility_version.stdout}, f, indent=2)
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / 'lifetime-probe'
            build = subprocess.run([compiler, '-std=c++20', '-Wall', '-Wextra', '-Werror', '-O2',
                '-I' + str(ROOT / 'owner/native'), str(FIXTURE / 'lifetime_probe.cpp'),
                str(ROOT / 'owner/native/worker_filter.cpp'), '-o', str(binary)],
                capture_output=True, text=True, timeout=180)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            for case in CASES:
                with self.subTest(case=case):
                    run = subprocess.run(['python3', '-I', '-B', str(FIXTURE / 'probe.py'),
                        '--binary', str(binary), '--case', case, '--bash', bash, '--nohup', nohup],
                        capture_output=True, text=True, timeout=45)
                    if results:
                        for suffix, text in [('stdout', run.stdout), ('stderr', run.stderr),
                                             ('status', str(run.returncode) + '\n')]:
                            with (results / (case + '.' + suffix)).open('x') as f:
                                f.write(text)
                    self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                    report = json.loads(run.stdout)
                    self.assertEqual(report['case'], case)
                    self.assertIn('Android unqualified', report['scope'])
                    self.assertFalse(report['complete_work_group_cleanup_proved'])
                    self.assertEqual(report['observations'][-1], {'event': 'empty', 'ECHILD': True})


if __name__ == '__main__':
    unittest.main()
