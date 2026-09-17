# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class WorkFactoryFixtureTests(unittest.TestCase):
    def test_kernel_probe_refuses_undelegated_invocation(self):
        probe = ROOT/'tests/work-factory/kernel_scopes.py'
        result = subprocess.run([sys.executable, '-I', '-B', str(probe)],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('refusing a cgroup outside the exact proof-unit shape', result.stderr)
        self.assertNotIn('released', result.stdout)

    def test_android_comparison_selection_is_separate_and_debug_only(self):
        product = ROOT/'products/andrix_gos_cf_arm64_only_phone.mk'
        with tempfile.TemporaryDirectory() as directory:
            makefile = Path(directory)/'Makefile'
            makefile.write_text('soong_config_set_bool =\ninclude '+str(product)+
                '\nall:\n\t@printf "%s\\n" "$(PRODUCT_PACKAGES)|$(PRODUCT_SYSTEM_EXT_PROPERTIES)"\n')
            base = dict(TARGET_PRODUCT='andrix_gos_cf_arm64_only_phone', TARGET_BUILD_VARIANT='userdebug',
                        ANDRIX_OWNER_SESSION='true',ANDRIX_OWNER_LIFECYCLE='true')
            for backend in ['', 'delegated', 'init', 'other', 'delegated init']:
                for changes in [{}, {'TARGET_BUILD_VARIANT':'eng'}, {'TARGET_BUILD_VARIANT':'user'}, {'TARGET_PRODUCT':'other'},
                                {'ANDRIX_OWNER_SCOPE_PROOF':'true'}, {'ANDRIX_OWNER_SESSION':''},
                                {'ANDRIX_OWNER_KEEP':'true','ANDRIX_OWNER_COMPILER':'true'}]:
                    values=dict(base,ANDRIX_WORK_FACTORY_PROOF=backend,**changes)
                    result=subprocess.run(['make','--no-print-directory','-f',str(makefile),
                        *[k+'='+v for k,v in values.items()]],capture_output=True,text=True,timeout=10)
                    if not backend:
                        # Other experiments have their own independent gates.
                        if result.returncode==0:self.assertNotIn('andrix-factory-manager-probe',result.stdout)
                    else:
                        expected=backend in ['delegated','init'] and changes in [{},{'TARGET_BUILD_VARIANT':'eng'}]
                        self.assertEqual(result.returncode==0,expected,result.stdout+result.stderr)
                        if expected:
                            self.assertIn('andrix-factory-manager-probe',result.stdout)
                            self.assertIn('ro.andrix.factory_backend='+backend,result.stdout)

    def test_actual_work_stop_and_command_ordering(self):
        source=(ROOT/'tests/work-factory/manager.cpp').read_text()
        stop=source[source.index('  ScopedAStatus stop('):source.index('  const uint64_t manager_id')]
        # Compiles the actual stop/command methods, not a rewritten state model.
        harness='''#include <atomic>
#include <cassert>
#include <cstdint>
#include <mutex>
using int64_t = std::int64_t;
struct ScopedAStatus { static ScopedAStatus ok() { return {}; } };
bool allowed=true;
bool caller(bool=true) { return allowed; }
ScopedAStatus denied() { return {}; }
int AIBinder_getCallingPid() { return 0; }
enum { Preparing, Ready, Holding, Held, Released, Stopping, Removed };
enum { Hold=3, Release=4 };
struct Base { virtual ScopedAStatus stop(int64_t,bool)=0; };
struct Work:Base {
 uint64_t work_id=42; std::atomic<bool> stopped=false,crash_guardian=false;
 std::atomic<int> stop_pid=-1,stop_count=0;std::mutex mutex;
 bool removed=false,hold_issued=false,release_issued=false;uint32_t pending=0;
 struct { int phase=Preparing; } state;
'''+stop+'''};
int main() {
 Work work; bool accepted=true;
 work.stop(41,false);assert(!work.stopped && work.stop_count==1 && work.stop_pid==0);
 work.state.phase=Ready;work.command(42,Hold,Ready,&accepted);assert(accepted);
 work.pending=0;work.command(42,Hold,Ready,&accepted);assert(!accepted);
 work.stop(42,false);assert(work.stopped);
 work.state.phase=Held;work.command(42,Release,Held,&accepted);assert(!accepted);
 Work pending;pending.stop(42,true);assert(pending.stopped && pending.crash_guardian);
 allowed=false;Work forbidden;forbidden.stop(42,false);assert(!forbidden.stopped && forbidden.stop_count==0);
}
'''
        with tempfile.TemporaryDirectory() as directory:
            cpp=Path(directory)/'work.cpp';cpp.write_text(harness);binary=Path(directory)/'work'
            built=subprocess.run(['g++','-std=c++20','-O2','-Wall','-Wextra','-Werror',str(cpp),'-o',str(binary)],capture_output=True,text=True,timeout=180)
            self.assertEqual(built.returncode,0,built.stderr)
            self.assertEqual(subprocess.run([str(binary)],timeout=10).returncode,0)

    def test_actual_opaque_identity_parser_and_pid_narrowing_guard(self):
        source=(ROOT/'tests/work-factory/common.cpp').read_text()
        parser=source[source.index('bool parse_id('):source.index('std::string read_small(')]
        harness='#include <cstdint>\n#include <cassert>\n'+parser+'''
int main() {
 uint64_t value=0;
 assert(!parse_id(nullptr,&value));assert(!parse_id("",&value));
 assert(!parse_id("0",&value));assert(!parse_id("-1",&value));
 assert(!parse_id("1:2",&value));assert(parse_id("42",&value) && value==42);
 assert(parse_id("4611686018427387904",&value) && value==(uint64_t{1}<<62));
 assert(!parse_id("4611686018427387905",&value));
 assert(!parse_id("18446744073709551616",&value));
}
'''
        with tempfile.TemporaryDirectory() as directory:
            cpp=Path(directory)/'id.cpp';cpp.write_text(harness);binary=Path(directory)/'id'
            built=subprocess.run(['g++','-std=c++20','-O2','-Wall','-Wextra','-Werror',str(cpp),'-o',str(binary)],capture_output=True,text=True,timeout=180)
            self.assertEqual(built.returncode,0,built.stderr)
            self.assertEqual(subprocess.run([str(binary)],timeout=10).returncode,0)
        manager=(ROOT/'tests/work-factory/manager.cpp').read_text()
        self.assertLess(manager.index('std::numeric_limits<pid_t>::max()'),manager.index('const auto created_pid = static_cast<pid_t>(pid)'))

    def test_new_crossings_do_not_grant_worker_management_authority(self):
        proof=ROOT/'tests/work-factory'
        policy=(proof/'sepolicy/factory_proof.te').read_text()
        owner=[line for line in policy.splitlines() if line.startswith('allow andrix_owner ')]
        self.assertEqual(owner,['allow andrix_owner andrix_factory_probe_socket:unix_stream_socket { read write };'])
        self.assertIn('neverallow andrix_owner andrixd:unix_stream_socket connectto',policy)
        manager=(proof/'manager.cpp').read_text()
        self.assertIn('work_binders.push_back(std::move(binder))',manager)
        self.assertIn('AServiceManager_addService(binder.get(), kManagerService)',manager)
        self.assertNotIn('own_binder(factory->asBinder().get())',manager)
        rc=(proof/'factory-probe.rc').read_text()
        self.assertEqual(rc.count('service andrix-factory-manager '),1)
        self.assertNotIn('service andrix-profile-probe-',rc)
        self.assertNotIn('    user root',rc)
        self.assertIn('    capabilities\n',rc)
        worker=(proof/'worker.cpp').read_text()
        self.assertLess(worker.index('install_worker_filter()'),worker.index('pid_t child = fork()'))
        self.assertLess(worker.index("release != 'R'"),worker.index('pid_t child = fork()'))
        patch=(proof/'init/runtime-probe.patch').read_text()
        self.assertIn('ANDRIX_FACTORY_INIT',patch)
        self.assertLess(patch.index('ActivateForInit(*this)'),patch.index('cgroups_activated.Write(kCgroupsActivated)'))
        runtime=(proof/'init/work_profile_runtime.cpp').read_text()
        self.assertIn('getpid() != 1 || getuid() != 0',runtime)
        self.assertIn('ro.andrix.factory_backend',runtime)
        self.assertRegex(runtime,r'tickets\.emplace\(\s*key,\s*""\)')


if __name__ == '__main__':
    unittest.main()
