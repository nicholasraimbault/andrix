# SPDX-License-Identifier: Apache-2.0
"""Principal launch components, not Package Manager or Android MAC qualification."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
NATIVE = ROOT / 'owner/native'


class PrincipalEntryTests(unittest.TestCase):
    def compile_run(self, name, sources=(), flags=()):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / name
            built = subprocess.run([
                'g++', '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror', '-UNDEBUG',
                '-pthread', '-I' + str(NATIVE),
                *[str(NATIVE / source) for source in sources],
                str(ROOT / 'owner/tests' / (name + '_test.cpp')), *flags,
                '-o', str(binary)], capture_output=True, text=True, timeout=150)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)

    def test_immutable_principal_data_and_exact_binding(self):
        self.compile_run('principal_profile', ['principal_profile.cpp'])

    def test_role_and_home_metadata_cannot_establish_credentials(self):
        self.compile_run('principal_credentials',
                         ['principal_profile.cpp', 'principal_credentials.cpp'], ['-lselinux'])

    def test_ordinary_and_legacy_filter_programs(self):
        self.compile_run('principal_filter')

    def test_description_size_is_observed_only_after_sealing(self):
        self.compile_run('launch_seal_order', ['launch_description.cpp'], ['-Wl,--wrap=fstat'])

    def test_principal_handoff_does_not_change_public_launch_inputs(self):
        public = (NATIVE / 'launch_description.h').read_text()
        self.assertNotIn('PrincipalProfile', public)
        self.assertNotIn('principal_home', public)
        runtime = (NATIVE / 'work_runtime.cpp').read_text()
        self.assertIn('SealPrincipalLaunch', runtime)
        self.assertIn('!principal_identity(*config.principal)', runtime)
        self.assertIn('!authority->AcceptsPrincipal(*config.principal)', runtime)
        self.assertIn('effective == real && saved == real', runtime)
        self.assertIn('geffective == greal && gsaved == greal', runtime)
        self.assertIn('principal.get()', runtime)
        self.assertIn('state->home.get()', runtime)
        self.assertIn('initial->placed.store(true)', runtime)
        self.assertIn('scope->Kill()', runtime)
        self.assertIn('gate()->Stop()', runtime)

    def test_separate_entry_remains_unselected_and_closes_control(self):
        stage = (NATIVE / 'principal_work_launcher.cpp').read_text()
        entry = (NATIVE / 'principal_work_entry.cpp').read_text()
        for mutation in ['setuid(', 'setresuid(', 'setgid(', 'setresgid(', 'setgroups(']:
            self.assertNotIn(mutation, stage + entry)
        self.assertIn('getpeercon', stage)
        self.assertIn('PrincipalManagerContext(principal)', stage)
        self.assertIn('request.packet.principal_profile != 1', stage)
        self.assertLess(stage.index('CheckPrincipalCredentials'), stage.index('ClaimEntry('))
        self.assertLess(stage.index('CheckCapturedWorkScope'), stage.index('ClaimEntry('))
        self.assertLess(stage.index('gate.reset()'), stage.index('SYS_close_range'))
        self.assertLess(stage.index('SYS_close_range'), stage.index('execve(entry'))
        self.assertIn('CheckPrincipalHome(5, profile)', entry)
        home = (NATIVE / 'principal_credentials.cpp').read_text().split('std::string CheckPrincipalHome', 1)[1]
        self.assertNotIn('info.st_gid', home)
        self.assertNotIn('0700', home)
        self.assertIn('DE can also use fscrypt v2', home)
        self.assertIn('PrincipalStage::Payload', entry)
        self.assertLess(entry.index('close(4)'), entry.index('execve(description.executable'))
        self.assertLess(entry.index('OnlyDeclaredDescriptors({})'), entry.index('chdir(description.directory'))
        self.assertNotIn('open_ce_home', entry)
        product = (ROOT / 'products/andrix_gos_cf_arm64_only_phone.mk').read_text()
        self.assertNotIn('andrix-principal-launcher', product)
        self.assertNotIn('andrix-principal-entry', product)
        legacy = (NATIVE / 'work_launcher.cpp').read_text()
        self.assertIn('request.packet.principal_profile != 0', legacy)
        self.assertIn('install_worker_filter()', legacy)


if __name__ == '__main__':
    unittest.main()
