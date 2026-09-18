# SPDX-License-Identifier: Apache-2.0
"""Source gates for an optional adapter, not init execution or MAC qualification."""
from pathlib import Path
import json
import unittest

ROOT=Path(__file__).resolve().parents[3]


class DelegatedInitSourceTests(unittest.TestCase):
    def test_opt_in_is_separate_and_default_off(self):
        product=(ROOT/'products/andrix_gos_cf_arm64_only_phone.mk').read_text()
        self.assertIn('$(call soong_config_set_bool,andrix,delegated_service,false)',product)
        self.assertIn('ifeq ($(ANDRIX_DELEGATED_SERVICE_PROOF),true)',product)
        for guard in ['requires userdebug or eng','requires ANDRIX_OWNER_SESSION=true',
                      'requires ANDRIX_OWNER_LIFECYCLE=true','cannot use Keep or older fault/scope controls',
                      'cannot use the older factory experiment']:
            self.assertIn('ANDRIX_DELEGATED_SERVICE_PROOF '+guard,product)

    def test_patch_is_pinned_and_separates_reaping_from_retirement(self):
        directory=ROOT/'supervision/init'
        meta=json.loads((directory/'integration-inputs.json').read_text())
        self.assertEqual(meta['system_core_revision'],'84ebea5e21110f31b632473a2fdb1c656b599b24')
        self.assertEqual(len(meta['files']),12)
        patch=(directory/'integration.patch').read_text()
        for name,row in meta['files'].items():
            self.assertIn('--- a/'+name,patch)
            for digest in row.values():self.assertRegex(digest,r'^[0-9a-f]{64}$')
        for gate in ['DelegatedService::BeforeStart(*this)','DelegatedService::DeferReap(*this, siginfo)',
                     'DelegatedService::Reaped(pid)','DelegatedService::Pending(*s)',
                     'DelegatedService::Removable(*old_service)','DelegatedService::Removable(*service)',
                     'DelegatedService::AnyStopping()','POSIX_SPAWN']:
            text=patch+(directory/'delegated_service.cpp').read_text()
            self.assertIn(gate,text)
        self.assertIn('exec waits are not qualified',patch)
        self.assertIn('whole_static_libs: ["andrix_delegated_scope"]',patch)

    def test_builtin_wrappers_stay_outside_generated_map_region(self):
        patch=(ROOT/'supervision/init/integration.patch').read_text()
        self.assertLess(patch.index('+static Result<void> do_stop_service_instance'),
                        patch.index(' // Builtin-function-map start'))
        self.assertLess(patch.index('+static Result<void> do_service_worker_fault'),
                        patch.index(' // Builtin-function-map start'))

    def test_memory_supervision_uses_exact_handles_and_incarnation(self):
        directory=ROOT/'supervision/lmkd'
        meta=json.loads((directory/'integration-inputs.json').read_text())
        self.assertEqual(meta['lmkd_revision'],'c3601e823bd07c9c190f67e2f9bc7486e4978328')
        self.assertEqual(len(meta['files']),5)
        patch=(directory/'integration.patch').read_text()
        for marker in ['SCM_RIGHTS','LMK_SERVICE_INSTANCE','LMK_SERVICE_REMOVE','LMK_SERVICE_TEST_KILL',
                       'service_pidfd_matches','same_service_control','init_service_sender',
                       'if (procp->service_instance) return false','MSG_CMSG_CLOEXEC']:
            self.assertIn(marker,patch)
        source=(ROOT/'supervision/init/delegated_service.cpp').read_text()
        self.assertIn('lmkd_register_service_instance',source)
        self.assertIn('LmkdUnregisterCaptured',source)

    def test_runtime_vehicle_is_fixed_and_separately_selected(self):
        directory=ROOT/'tests/delegated-supervision/android'
        rc=(directory/'service-probe.rc').read_text()
        self.assertIn('delegated_scope 268435456 0 64 8',rc)
        self.assertIn('service andrix-delegated-peer',rc)
        self.assertIn('stop_service_instance andrix-delegated-proof ${sys.andrix.delegated.ref}',rc)
        self.assertIn('setprop sys.andrix.delegated.ack ${sys.andrix.delegated.sequence}',rc)
        self.assertIn('memory_service_test andrix-delegated-proof ${sys.andrix.delegated.ref}',rc)
        policy=(directory/'sepolicy/delegated_service.te').read_text()
        self.assertIn('neverallow { domain -init -shell } andrix_delegated_control_prop',policy)
        self.assertIn('neverallow { domain -init } andrix_delegated_status_prop',policy)

    def test_runtime_observer_waits_for_actual_control_processing(self):
        source=(ROOT/'tests/delegated-supervision/android/service-client.cpp').read_text()
        for text in ['sys.andrix.delegated.sequence','sys.andrix.delegated.ack',
                     'fresh init command processing acknowledgement','SYS_pidfd_open',
                     'GroupObservation old_group','memory-kill','DELEGATED_SERVICE_PROOF_COMPLETE']:
            self.assertIn(text,source)
        bootstrap=(ROOT/'tests/delegated-supervision/android/service-probe.cpp').read_text()
        self.assertIn('actual profile and endpoint readiness',bootstrap)
        self.assertIn('explicit zero capabilities',bootstrap)
        self.assertIn('migration ancestor protected',bootstrap)

    def test_generic_adapter_does_not_own_work_or_ce_authority(self):
        source=(ROOT/'supervision/init/delegated_service.cpp').read_text()
        for forbidden in ['PlatformLifecycle','CeStorageAccessTracker','WorkInfo','terminal_mode','killProcessGroup(']:
            self.assertNotIn(forbidden,source)
        self.assertIn('SCM_CREDENTIALS',source)
        self.assertIn('getpidcon(initial_pid',source)
        self.assertIn('SYS_pidfd_send_signal',source)
        self.assertIn('state.finish_confirmed_removal',source)
        worker=(ROOT/'supervision/native/cleanup_worker_main.cpp').read_text()
        self.assertIn('u:r:andrix_scope_cleanup:s0',worker)
        self.assertIn('PR_CAPBSET_DROP',worker)
        self.assertIn('CAP_CHOWN',worker)
        self.assertNotIn('CAP_DAC_OVERRIDE',worker)
        self.assertIn('/system_ext/bin/andrix-scope-cleaner',source)
        self.assertNotIn('DelegatedService::WorkerMain',source)

    def test_worker_spawn_never_resets_uncatchable_signal_dispositions(self):
        source=(ROOT/'supervision/native/cleanup_worker.cpp').read_text()
        self.assertIn('sigdelset(&defaults, SIGKILL)',source)
        self.assertIn('sigdelset(&defaults, SIGSTOP)',source)
        adapter=(ROOT/'supervision/init/delegated_service.cpp').read_text()
        self.assertIn('ConfigureWorkerSignalMasks(empty, defaults)',adapter)
        self.assertNotIn('sigfillset(&defaults)',adapter)
        patch=(ROOT/'supervision/init/integration.patch').read_text()
        self.assertIn('if (delegation_profile_) _exit(EXIT_FAILURE);',patch)

    def test_bootstrap_waits_for_worker_and_event_handles_retire_after_dispatch(self):
        source=(ROOT/'supervision/init/delegated_service.cpp').read_text()
        patch=(ROOT/'supervision/init/integration.patch').read_text()
        self.assertIn('HoldActivation(*this, std::move(cgroups_activated))',patch)
        self.assertIn('DelegatedService::AfterWait()',patch)
        self.assertIn('retired_event_fds.emplace_back(std::move(fd))',source)
        self.assertIn('retired_event_fds.clear()',source)
        self.assertIn('activation_released && bootstrap_ready',source)
        policy=(ROOT/'tests/delegated-supervision/android/sepolicy/delegated_service.te').read_text()
        self.assertIn('init_daemon_domain(andrix_scope_cleanup)',policy)
        self.assertIn('andrix_delegation_ready_socket',policy)
        self.assertNotIn('allow init init_exec:file execute_no_trans',policy)


if __name__=='__main__':unittest.main()
