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
    def compile_and_run(self, test, sources, json_lines=False):
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
            return ([json.loads(line) for line in result.stdout.splitlines()]
                    if json_lines else json.loads(result.stdout))

    def test_catalog_capture_cannot_recreate_collected_forgotten_work(self):
        rows = self.compile_and_run('work_catalog_capture_test', BASE, json_lines=True)
        self.assertEqual([row['operation'] for row in rows[:3]], ['Find', 'Reserve', 'Lookup'])
        for row in rows[:3]:
            self.assertTrue(row['registry_control_pinned'])
            self.assertFalse(row['late_handle'])
            self.assertTrue(row['capacity_reusable'])
        self.assertEqual(rows[1]['late_result'], 5)  # WorkRegistryResult::Stale
        self.assertEqual(rows[2]['late_result'], 5)
        self.assertTrue(rows[-1]['catalog_capture_retirement'])
        self.assertEqual(rows[-1]['concurrent_rounds'], 200)
        self.assertFalse(rows[-1]['production_capture_code_instrumented'])
        self.assertFalse(rows[-1]['Android_runtime_qualified'])

    def test_request_identity_recovery_and_provisional_stream_lifetime(self):
        result = self.compile_and_run('work_request_recovery_test', BASE+['work_service_protocol.cpp'])
        self.assertEqual(result['unused_stream_closure_cycles'], 100)
        self.assertEqual(result['unused_close_reserve_races'], 200)
        self.assertTrue(result['lookup_never_allocates'])
        self.assertTrue(result['closed_stream_result_recovery'])
        self.assertTrue(result['query_does_not_adopt_submission'])
        self.assertTrue(result['retained_stream_independent_of_work_stop'])
        self.assertTrue(result['reference_codec'])
        self.assertFalse(result['Android_runtime_qualified'])

    def test_recovery_dispatch_and_client_publication_order(self):
        manager = (NATIVE/'work_manager.cpp').read_text()
        query = manager[manager.index('} else if (operation == WorkServiceOperation::LookupRequest)'):
                        manager.index('} else if (operation == WorkServiceOperation::List)')]
        self.assertIn('server.catalog.LookupRequest', query)
        self.assertNotIn('reservations.push_back', query)
        self.assertNotIn('CancelUnstarted()', query)
        self.assertNotIn('catalog.Reserve(', query)
        self.assertIn('provisional_streams->OpenStream()', manager)
        self.assertIn('provisional_streams->CloseUnused()', manager)
        client = (NATIVE/'work_client.cpp').read_text()
        self.assertLess(client.index('andrix-work: request %s'),
                        client.index('management.Call(WorkServiceOperation::Reserve'))
        self.assertLess(client.index('andrix-work: reserved '),
                        client.index('management.Call(WorkServiceOperation::Prepare'))
        self.assertIn('operation == "request-info"', client)
        self.assertIn('operation == "stream-close"', client)
        self.assertIn('WorkServiceOperation::LookupRequest', client)

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

    def test_ordinary_transport_probe_codec_and_link(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory)/'transport_probe'
            result = subprocess.run(['g++', '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror',
                '-I'+str(NATIVE), str(ROOT/'tests/owner-work-service/transport_probe.cpp'),
                *[str(NATIVE/name) for name in ['work_peer.cpp', 'work_channel.cpp',
                    'work_service_protocol.cpp', 'launch_description.cpp']], '-o', str(binary)],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary), '--self-test'], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            report = json.loads(result.stdout)
            self.assertTrue(report['transport_probe_codec_and_link'])
            self.assertFalse(report['Android_runtime_qualified'])

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

    def test_termination_routes_follow_positive_placement(self):
        source = ''.join((NATIVE/'work_runtime.cpp').read_text().split())
        termination = source[source.index('void*terminate('):source.index('boolsame(')]
        self.assertLess(termination.index('gate()->Stop()'), termination.index('initial->placed.load()'))
        self.assertIn('initial&&!initial->placed.load()&&initial->pidfd.get()>=0', termination)
        self.assertIn('scope->Kill()', termination)
        creation = source[source.index('autocreate='):source.index('interror=create()')]
        self.assertLess(creation.index('initial->placed.store(true)'), creation.index('SendWorkLaunch('))
        self.assertLess(creation.index('initial->placed.store(true)'), creation.index('authority->Release('))

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
