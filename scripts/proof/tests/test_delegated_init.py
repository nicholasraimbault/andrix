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
        self.assertEqual(len(meta['files']),11)
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

    def test_builtin_wrappers_stay_outside_generated_map_region(self):
        patch=(ROOT/'supervision/init/integration.patch').read_text()
        self.assertLess(patch.index('+static Result<void> do_stop_service_instance'),
                        patch.index(' // Builtin-function-map start'))
        self.assertLess(patch.index('+static Result<void> do_service_worker_fault'),
                        patch.index(' // Builtin-function-map start'))

    def test_generic_adapter_does_not_own_work_or_ce_authority(self):
        source=(ROOT/'supervision/init/delegated_service.cpp').read_text()
        for forbidden in ['PlatformLifecycle','CeStorageAccessTracker','WorkInfo','terminal_mode','killProcessGroup(']:
            self.assertNotIn(forbidden,source)
        self.assertIn('SCM_CREDENTIALS',source)
        self.assertIn('getpidcon(initial_pid',source)
        self.assertIn('SYS_pidfd_send_signal',source)
        self.assertIn('state.finish_confirmed_removal',source)
        self.assertIn('fixed internal worker profile',source.lower())


if __name__=='__main__':unittest.main()
