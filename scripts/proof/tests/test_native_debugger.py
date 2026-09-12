# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class NativeDebuggerTests(unittest.TestCase):
    def test_profile_keeps_abi_and_strict_linking(self):
        profile = json.loads((ROOT/'toolchain/lldb/profile.json').read_text())
        self.assertEqual(profile['target'], 'aarch64-linux-android37')
        self.assertFalse(profile['policy_changed'])
        self.assertFalse(profile['upstream_android_client_supported'])
        self.assertEqual(profile['base_toolchain_sha256'], hashlib.sha256(
            (ROOT/'toolchain/AndroidBionic.cmake').read_bytes()).hexdigest())
        patch = ROOT/'toolchain/lldb'/profile['patch']['file']
        self.assertEqual(hashlib.sha256(patch.read_bytes()).hexdigest(),
                         profile['patch']['sha256'])
        for item in profile['additional_patches']:
            patch = ROOT/'toolchain/lldb'/item['file']
            self.assertEqual(hashlib.sha256(patch.read_bytes()).hexdigest(), item['sha256'])
        visibility = (ROOT/'toolchain/lldb/android-api-visibility.patch').read_text()
        self.assertIn('+#define LLDB_API __attribute__((visibility("default")))', visibility)
        self.assertIn('+#elif defined(__ANDROID__)', visibility)
        self.assertIn('-DCMAKE_PLATFORM_NO_VERSIONED_SONAME=ON', profile['native_cmake_options'])
        self.assertIn('-DCLANG_RESOURCE_DIR=../etc/andrix/clang/23', profile['native_cmake_options'])
        cmake = (ROOT/'toolchain/lldb/AndroidBionic.cmake').read_text()
        self.assertIn('include("${CMAKE_CURRENT_LIST_DIR}/../AndroidBionic.cmake")', cmake)
        self.assertEqual(cmake.count('-Wl,--no-undefined'), 2)
        for feature in ['SWIG', 'PYTHON', 'LUA', 'LIBEDIT', 'CURSES', 'LIBXML2',
                        'LZMA', 'PROTOCOL_SERVERS']:
            self.assertIn('-DLLDB_ENABLE_'+feature+'=OFF', profile['cmake_options'])

    @unittest.skipUnless(shutil.which('cmake'), 'host CMake required')
    def test_exact_android_selection_condition(self):
        patch = (ROOT/'toolchain/lldb/android-host-selection.patch').read_text()
        condition = next(line[1:].strip() for line in patch.splitlines()
                         if line.startswith('+    if ('))
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'selection.cmake'
            path.write_text(condition+'\nset(selected 1)\nelse()\nset(selected 0)\nendif()\n'
                            'if(NOT selected EQUAL expected)\nmessage(FATAL_ERROR "selection mismatch")\nendif()\n')
            for system, android, expected in [('Linux', 'ON', 1), ('Linux', 'OFF', 0),
                                               ('Android', 'OFF', 1)]:
                subprocess.run(['cmake', '-DCMAKE_SYSTEM_NAME='+system,
                                '-DANDROID='+android, '-Dexpected='+str(expected),
                                '-P', str(path)], check=True, capture_output=True, timeout=15)

    @unittest.skipUnless(shutil.which('cc') and shutil.which('c++'), 'host C/C++ compiler required')
    def test_self_probe_under_worker_filter_and_denial_control(self):
        # Host syscall/helper control only, not Android SELinux qualification.
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            subprocess.run(['cc', '-std=c11', '-D_POSIX_C_SOURCE=200809L', '-O2',
                            '-Wall', '-Wextra', '-Werror', '-Dmain=probe_main', '-c',
                            str(ROOT/'tests/owner-debugger/self_trace.c'), '-o', str(temp/'probe.o')],
                           check=True, capture_output=True, timeout=30)
            wrapper = temp/'wrapper.cpp'
            wrapper.write_text('''#include "worker_filter.h"
#include <cerrno>
#include <cstddef>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
extern "C" int probe_main(void);
int main(int argc, char **) {
  if (!andrix::install_worker_filter()) return 70;
  if (argc > 1) {
    sock_filter code[] = {
      BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(seccomp_data, nr)),
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_ptrace, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|EPERM),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW)
    };
    sock_fprog program{4, code};
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) return 71;
  }
  return probe_main();
}
''')
            binary = temp/'probe'
            subprocess.run(['c++', '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror',
                            '-I'+str(ROOT/'owner/native'), str(wrapper),
                            str(ROOT/'owner/native/worker_filter.cpp'), str(temp/'probe.o'),
                            '-o', str(binary)], check=True, capture_output=True, timeout=30)
            passed = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
            self.assertEqual(passed.returncode, 0, passed.stdout+passed.stderr)
            self.assertIn('NNP=1 SECCOMP=2 CHILD_ERRNO=0', passed.stdout)
            self.assertIn('SELF_TRACE_READ_WRITE_CONTINUE_OK', passed.stdout)
            denied = subprocess.run([str(binary), 'deny'], capture_output=True, text=True, timeout=20)
            self.assertEqual(denied.returncode, 2, denied.stdout+denied.stderr)
            self.assertIn('SELF_TRACE_DENIED', denied.stdout)
            self.assertIn('CHILD_ERRNO=1', denied.stdout)


if __name__ == '__main__':
    unittest.main()
