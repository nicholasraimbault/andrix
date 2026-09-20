# SPDX-License-Identifier: Apache-2.0
"""Service component checks, not Android endpoint or real cgroup qualification."""
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
NATIVE = ROOT/'owner/native'
BASE = ['work_catalog.cpp', 'work_registry.cpp', 'work_io.cpp', 'work_admission.cpp', 'launch_description.cpp']


class WorkServiceTests(unittest.TestCase):
    def compile_and_run(self, test, sources):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory)/test
            result = subprocess.run(['g++', '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror', '-UNDEBUG', '-pthread',
                '-I'+str(NATIVE), '-I'+str(ROOT/'supervision/native'),
                *[str(NATIVE/source) for source in sources],
                *([str(ROOT/'supervision/native/captured_cgroup.cpp')] if test == 'work_runtime_test' else []),
                str(ROOT/'owner/tests'/(test+'.cpp')), '-o', str(binary)], capture_output=True, text=True, timeout=180)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=45)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            return json.loads(result.stdout)

    def test_catalog_inputs_retry_and_disconnect_ordering(self):
        result = self.compile_and_run('work_catalog_test', BASE+['work_service_protocol.cpp'])
        self.assertEqual(result['catalog_prepare_stop_races'], 100)
        self.assertEqual(result['start_disconnect_races'], 100)
        self.assertTrue(result['consumed_registration_EOF'])
        self.assertFalse(result['Android_authentication_or_runtime_backend_qualified'])

    def test_runtime_refusal_retains_creator_ownership(self):
        result = self.compile_and_run('work_runtime_test', BASE+['work_runtime.cpp', 'work_launch_protocol.cpp'])
        self.assertTrue(result['creator_ticket_retained_on_submit_refusal'])
        self.assertFalse(result['real_kernel_runtime_qualified'])

    def test_optional_service_negative_requires_live_owner_control(self):
        native = (ROOT/'tests/owner-negative/probe.cpp').read_text()
        java = (ROOT/'tests/owner-negative/src/dev/andrix/proof/ownernegative/OwnerNegative.java').read_text()
        self.assertIn('nativeWorkServiceProbe', native)
        self.assertIn('"andrix.work.endpoint"', native)
        self.assertIn('"andrix-work-manager"', native)
        self.assertIn('work_service_endpoint', java)
        self.assertIn('service.getInt("management_connect_errno") == 13', java)
        self.assertIn('service.getInt("control_connect_errno") == 13', java)
        self.assertIn('Missing service is not denial', java)

    def test_runtime_kernel_driver_requires_owned_delegation(self):
        result = subprocess.run([sys.executable, '-I', '-B', str(ROOT/'tests/owner-work-service/runtime_kernel.py')],
                                capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('owned work runtime proof delegation only', result.stderr)

    def test_selected_service_and_private_descriptor_boundaries(self):
        product = (ROOT/'products/andrix_gos_cf_arm64_only_phone.mk').read_text()
        self.assertIn('soong_config_set_bool,andrix,owner_work_service_proof,false', product)
        self.assertIn('ANDRIX_OWNER_WORK_SERVICE_PROOF requires the qualified launch boundary selection', product)
        self.assertNotIn('WorkCatalog', (NATIVE/'andrixd.cpp').read_text())
        manager = (NATIVE/'work_manager.cpp').read_text()
        self.assertIn('ReceiveAuthorizedWorkFrame', manager)
        self.assertIn('bound.Stop()', manager)
        self.assertLess(manager.index('ReceiveServiceActivation'), manager.index('std::thread(accept_loop'))
        self.assertLess(manager.index('ReceiveServiceActivation'), manager.index('SetProperty(kEndpointProperty'))
        self.assertIn('WorkRuntimePhase::Missing', manager)
        self.assertIn('platform.failed()) _exit(0)', manager)
        self.assertNotIn('waitpid(', manager)
        self.assertNotIn('cgroup.kill', manager)
        policy = (ROOT/'tests/owner-work-service/sepolicy/work_service.te').read_text()
        self.assertIn('neverallow andrixd andrix_home_file:file { open map execute execute_no_trans', policy)
        self.assertIn('neverallow andrixd andrix_owner:process ptrace;', policy)
        entry = (NATIVE/'work_entry.cpp').read_text()
        self.assertLess(entry.index('const unsigned closed_stdio'), entry.index('CheckOwnerEntry()'))
        self.assertLess(entry.index('chdir(description.directory'), entry.index('close(fd)'))
        self.assertLess(entry.index('close(fd)'), entry.index('execve(description.executable'))


if __name__ == '__main__':
    unittest.main()
