# SPDX-License-Identifier: Apache-2.0
"""Source selection and structure checks, never Android launch/authority proof."""
from pathlib import Path
import unittest
import re

ROOT=Path(__file__).resolve().parents[3]
VEHICLE=ROOT/'tests/owner-work-launch'


class WorkLaunchVehicleTests(unittest.TestCase):
    def test_separate_debug_vehicle_keeps_existing_path(self):
        product=(ROOT/'products/andrix_gos_cf_arm64_only_phone.mk').read_text()
        self.assertIn('soong_config_set_bool,andrix,owner_work_proof,false',product)
        self.assertIn('ANDRIX_OWNER_WORK_PROOF requires the selected delegated service environment',product)
        self.assertIn('ANDRIX_DELEGATED_SERVICE_PROOF requires userdebug or eng',product)
        board=(ROOT/'board/andrix_cf_arm64_only/BoardConfig.mk').read_text()
        self.assertIn('ifeq ($(ANDRIX_OWNER_WORK_PROOF),true)',board)
        legacy=(ROOT/'owner/native/andrixd.cpp').read_text()
        self.assertNotIn('andrix-work-launcher',legacy)
        rc=(VEHICLE/'work-launch.rc').read_text()
        self.assertIn('delegated_scope 268435456 0 64 8',rc)
        self.assertIn('    capabilities\n',rc)

    def test_control_and_owner_data_are_not_the_same_boundary(self):
        policy=(VEHICLE/'sepolicy/work_launch.te').read_text()
        self.assertIn('allow andrixd andrix_owner:process2 nnp_transition;',policy)
        self.assertIn('allow andrix_owner andrixd:memfd_file { read getattr };',policy)
        self.assertIn('neverallow andrix_owner andrixd:memfd_file { write append map execute };',policy)
        self.assertIn('neverallow andrix_owner andrixd:unix_stream_socket { read write };',policy)
        bridge=(ROOT/'patches/grapheneos-2026081300/owner-session-policy.patch').read_text()
        self.assertIn('neverallow domain andrix_owner:process dyntransition;',bridge)
        self.assertIn('neverallow { domain -andrix_owner } andrix_home_file:file no_x_file_perms;',bridge)

    def test_stopped_and_blocked_requests_keep_their_obligations(self):
        source=''.join(re.sub(r'//[^\n]*','',(VEHICLE/'manager.cpp').read_text()).split())
        self.assertIn('work->gate->Stop()',source)
        self.assertIn('allocation_started=true;',source)
        self.assertIn('work->obligation=captured;',source)
        self.assertIn('unique_fd&pidfd=work->initial;',source)
        self.assertNotIn('waitpid(-1',source)
        self.assertIn('scope::GroupPopulation::Empty',source)
        self.assertIn('scope::CursorState::Retired',source)
        self.assertIn('work->state.no_process=1',source)
        self.assertIn('work->state.gate_refused=1',source)
        dispatch=source[source.index('intmain('):]
        self.assertNotIn('captured->Kill()',dispatch)
        self.assertNotIn('mkdirat(',dispatch)

    def test_optional_live_app_negatives_distinguish_exec_from_refusal(self):
        native=(ROOT/'tests/owner-negative/probe.cpp').read_text()
        self.assertIn('nativeWorkLaunchProbe',native)
        self.assertIn('andrix-work-launcher',native)
        self.assertIn('andrix-work-entry',native)
        self.assertIn('Zero means exec actually succeeded',native)
        java=(ROOT/'tests/owner-negative/src/dev/andrix/proof/ownernegative/OwnerNegative.java').read_text()
        self.assertIn('work_launch_reference',java)
        self.assertIn('work.getInt("launcher_exec_errno") == 13',java)
        self.assertIn('work.getInt("ctl_stop_result") != 0',java)


if __name__=='__main__':unittest.main()
