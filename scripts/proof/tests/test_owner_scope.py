# SPDX-License-Identifier: Apache-2.0
"""Scope experiment ordering/selection contracts, not Android scope qualification."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
PROOF = ROOT / 'tests/owner-scope'


class OwnerScopeProofTests(unittest.TestCase):
    def test_actual_atomic_gate_ordering(self):
        compiler = shutil.which('g++')
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'gate'
            compile_result = subprocess.run([compiler, '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-O2', '-pthread', '-I' + str(PROOF), str(PROOF/'gate_test.cpp'), '-o', str(binary)],
                capture_output=True, text=True, timeout=180)
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            self.assertIn('Android identity/resources/cleanup unqualified', ran.stdout)

    def test_actual_caller_predicates_distinguish_oneway_pid(self):
        source = (PROOF/'guardian.cpp').read_text()
        methods = source[source.index('bool shell_identity() {'):source.index('ScopedAStatus denied()')]
        harness = '''#include <cassert>
#include <cstring>
#include <iostream>
#include <sys/types.h>
static uid_t uid = 2000;
static pid_t pid = 42;
static const char* sid = "u:r:shell:s0";
uid_t AIBinder_getCallingUid() { return uid; }
pid_t AIBinder_getCallingPid() { return pid; }
const char* AIBinder_getCallingSid() { return sid; }
''' + methods + '''
int main() {
 assert(shell_identity() && shell_caller());
 pid = 0; assert(shell_identity() && !shell_caller());
 uid = 1000; assert(!shell_identity() && !shell_caller());
 uid = 10146; assert(!shell_identity());
 uid = 2000; sid = "u:r:andrix_owner:s0"; assert(!shell_identity());
 sid = nullptr; assert(!shell_identity());
 sid = "u:r:shell:s0"; pid = 1; assert(shell_identity() && !shell_caller());
 std::cout << "Caller predicate model passed; actual Android identity unqualified\\n";
}
'''
        with tempfile.TemporaryDirectory() as directory:
            cpp = Path(directory)/'caller.cpp';cpp.write_text(harness)
            binary = Path(directory)/'caller'
            built = subprocess.run(['g++','-std=c++20','-Wall','-Wextra','-Werror','-O2',
                str(cpp),'-o',str(binary)],capture_output=True,text=True,timeout=180)
            self.assertEqual(built.returncode,0,built.stderr)
            result = subprocess.run([str(binary)],capture_output=True,text=True,timeout=20)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn('actual Android identity unqualified',result.stdout)

    def test_explicit_debug_selection_and_separate_fault_scope(self):
        product = ROOT/'products/andrix_gos_cf_arm64_only_phone.mk'
        with tempfile.TemporaryDirectory() as directory:
            makefile = Path(directory)/'Makefile'
            makefile.write_text('soong_config_set_bool =\ninclude ' + str(product) +
                '\nall:\n\t@printf "%s\\n" "$(PRODUCT_PACKAGES)"\n')
            base = {'TARGET_PRODUCT':'andrix_gos_cf_arm64_only_phone',
                    'TARGET_BUILD_VARIANT':'userdebug', 'ANDRIX_OWNER_SESSION':'true',
                    'ANDRIX_OWNER_LIFECYCLE':'true', 'ANDRIX_OWNER_SCOPE_PROOF':'true'}
            for changes, valid, selected in [({},True,True),
                    ({'TARGET_BUILD_VARIANT':'eng'},True,True),
                    ({'ANDRIX_OWNER_SCOPE_PROOF':''},True,False),
                    ({'ANDRIX_OWNER_SCOPE_PROOF':'false'},True,False),
                    ({'TARGET_PRODUCT':'other'},False,False),
                    ({'TARGET_BUILD_VARIANT':'user'},False,False),
                    ({'TARGET_BUILD_VARIANT':''},False,False),
                    ({'ANDRIX_OWNER_SESSION':''},False,False),
                    ({'ANDRIX_OWNER_LIFECYCLE':''},False,False),
                    ({'ANDRIX_OWNER_KEEP':'true','ANDRIX_OWNER_COMPILER':'true'},False,False),
                    ({'ANDRIX_OWNER_FAULT_TESTS':'true'},False,False)]:
                with self.subTest(changes=changes):
                    result = subprocess.run(['make', '--no-print-directory', '-f', str(makefile),
                        *[k+'='+v for k,v in dict(base,**changes).items()]],
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode == 0, valid, result.stdout + result.stderr)
                    if valid:
                        self.assertEqual('andrix-scope-guardian-probe' in result.stdout, selected)
                        self.assertEqual('andrix-scope-worker-probe' in result.stdout, selected)
                        self.assertEqual('andrix-scope-proof-client' in result.stdout, selected)

    def test_fixed_factory_and_real_caller_boundaries(self):
        rc = (PROOF/'scope-probe.rc').read_text()
        self.assertNotIn('    exec_background ', rc)
        self.assertEqual(rc.count('service andrix-scope-'), 2)
        self.assertEqual(rc.count('    capabilities\n'), 2)
        self.assertEqual(rc.count('    oneshot\n'), 2)
        self.assertEqual(rc.count('    rlimit nproc 32 32\n'), 2)
        self.assertEqual(rc.count('    oom_score_adjust 700\n'), 2)
        self.assertIn('property:sys.andrix.scope_probe.consumed=false', rc)
        self.assertIn('property:sys.andrix.scope_probe.replaced=false', rc)
        self.assertIn('property:sys.user.0.ce_available=true', rc)
        self.assertNotIn('ro.config.per_app_memcg', rc)
        self.assertNotIn('    user root', rc)
        self.assertIn('memory.max 268435456', rc)
        self.assertIn('memory.swap.max 0', rc)
        source = (PROOF/'guardian.cpp').read_text()
        for term in ['AIBinder_getCallingUid() == 2000', 'AIBinder_getCallingPid() > 1',
                     'strcmp(sid, "u:r:shell:s0") == 0', 'getppid() != 1',
                     'role != "u:r:andrixd:s0"', 'AIBinder_setRequestingSid(binder.get(), true)',
                     'andrix::check_resource_bounds()', 'andrix::PlatformLifecycle platform']:
            self.assertIn(term, source)
        stop = source[source.index('  ScopedAStatus stop('):source.index('  void tick()')]
        self.assertIn('if (gate_.stop(id)) _exit(crash ? 77 : 0)', stop)
        self.assertNotIn('mutex_', stop)
        self.assertIn('if (!shell_identity())', stop)
        self.assertNotIn('shell_caller()', stop)
        self.assertIn('last_stop_pid_.store(AIBinder_getCallingPid())', stop)
        self.assertNotIn('kill(', source)
        self.assertIn('setsockcreatecon("u:object_r:andrix_scope_probe_socket:s0")', source)
        self.assertIn('setsockcreatecon(nullptr)', source)
        self.assertIn('SOCK_SEQPACKET | SOCK_CLOEXEC', source)
        self.assertNotIn('pipe2(', source)
        worker = (PROOF/'worker.cpp').read_text()
        self.assertLess(worker.index('install_worker_filter()'), worker.index('pid_t child = fork()'))
        self.assertLess(worker.index('release gate closed'), worker.index('pid_t child = fork()'))
        self.assertIn('role != "u:r:andrix_owner:s0"', worker)
        self.assertIn('signal(SIGTERM, SIG_IGN)', worker)
        self.assertIn('setsid()', worker)
        policy = (PROOF/'sepolicy/scope_proof.te').read_text()
        self.assertIn('neverallow { domain -init -shell } andrix_scope_probe_control_prop:property_service set', policy)
        self.assertIn('neverallow { andrix_owner andrix_terminal untrusted_app_all isolated_app_all }', policy)
        owner_allow = [line for line in policy.splitlines() if line.startswith('allow andrix_owner ')]
        self.assertEqual(owner_allow, ['allow andrix_owner andrix_scope_probe_socket:unix_stream_socket { read write };'])
        self.assertNotIn('allow andrix_owner andrixd:fifo_file', policy)
        self.assertIn('create_socket_perms_no_ioctl', policy)
        self.assertNotIn('create_stream_socket_perms', policy)
        self.assertNotIn('cgroup_v2:file { write', policy)
        client = (PROOF/'client.cpp').read_text()
        self.assertIn('live group before Stop', client)
        self.assertIn('old.getStatus() == STATUS_DEAD_OBJECT', client)
        self.assertIn('late.getStatus() == STATUS_DEAD_OBJECT', client)


if __name__ == '__main__':
    unittest.main()
