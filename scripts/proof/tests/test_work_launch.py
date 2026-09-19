# SPDX-License-Identifier: Apache-2.0
"""Source selection and host encoding checks, not Android authority proof."""
from pathlib import Path
import json
import unittest
import re
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[3]
VEHICLE=ROOT/'tests/owner-work-launch'


class WorkLaunchVehicleTests(unittest.TestCase):
    def test_snapshot_output_preserves_binary_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            binary=Path(directory)/'output-test'
            result=subprocess.run(['g++','-std=c++20','-O2','-Wall','-Wextra','-Werror',
                '-UNDEBUG',str(VEHICLE/'output_test.cpp'),'-o',str(binary)],
                capture_output=True,text=True,timeout=120)
            self.assertEqual(result.returncode,0,result.stderr)
            result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=20)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual(json.loads(result.stdout).encode('latin-1'),bytes(range(256)))
        client=(VEHICLE/'client.cpp').read_text()
        self.assertIn('proof::SnapshotOutputJson(state, output_json)',client)
        self.assertNotIn('quote(state.output)',client)
        manager=(VEHICLE/'manager.cpp').read_text()
        self.assertIn('state.output_size = static_cast<uint32_t>(work->output.size())',manager)

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

    def test_real_make_ce_composition_preserves_required_guards(self):
        product=ROOT/'products/andrix_gos_cf_arm64_only_phone.mk'
        with tempfile.TemporaryDirectory() as directory:
            makefile=Path(directory)/'Makefile'
            makefile.write_text('soong_config_set_bool = $(eval CFG_$(2) := $(3))\ninclude '+str(product)+
                '\nall:\n\t@printf "%s\\n" "$(CFG_owner_work_ce_proof)|$(CFG_owner_fault_tests)|$(CFG_owner_keep)|$(CFG_owner_work_proof)"\n')
            base={'TARGET_PRODUCT':'andrix_gos_cf_arm64_only_phone','TARGET_BUILD_VARIANT':'userdebug',
                  'ANDRIX_OWNER_SESSION':'true','ANDRIX_OWNER_LIFECYCLE':'true','ANDRIX_OWNER_COMPILER':'true',
                  'ANDRIX_DELEGATED_SERVICE_PROOF':'true','ANDRIX_OWNER_WORK_PROOF':'true',
                  'ANDRIX_OWNER_WORK_CE_PROOF':'true','ANDRIX_OWNER_KEEP':'true','ANDRIX_OWNER_FAULT_TESTS':'true'}
            for changes,passed,selection in [
                ({},True,'true|true|true|true'),
                ({'TARGET_BUILD_VARIANT':'eng'},True,'true|true|true|true'),
                ({'TARGET_BUILD_VARIANT':'user'},False,None),
                ({'TARGET_PRODUCT':'other'},False,None),
                ({'ANDRIX_OWNER_KEEP':''},False,None),
                ({'ANDRIX_OWNER_FAULT_TESTS':''},False,None),
                ({'ANDRIX_OWNER_WORK_PROOF':''},False,None),
                ({'ANDRIX_DELEGATED_SERVICE_PROOF':''},False,None),
                ({'ANDRIX_OWNER_WORK_CE_PROOF':''},False,None),
                ({'ANDRIX_OWNER_SCOPE_PROOF':'true'},False,None),
                ({'ANDRIX_WORK_FACTORY_PROOF':'delegated'},False,None),
                ({'ANDRIX_OWNER_KEEP':'','ANDRIX_OWNER_FAULT_TESTS':'','ANDRIX_OWNER_WORK_CE_PROOF':''},True,'false|false||true')]:
                values=dict(base,**changes)
                result=subprocess.run(['make','--no-print-directory','-f',str(makefile),*[k+'='+v for k,v in values.items()]],capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode==0,passed,result.stdout+result.stderr)
                if passed:self.assertEqual(result.stdout.strip(),selection)

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
