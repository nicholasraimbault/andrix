// SPDX-License-Identifier: Apache-2.0
#include "worker_filter.h"

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>

namespace andrix {

bool install_worker_filter() {
#if defined(__aarch64__)
  constexpr uint32_t arch = AUDIT_ARCH_AARCH64;
#elif defined(__x86_64__) && !defined(__ANDROID__)
  // Host syscall checks only. The Android product remains ARM64-only.
  constexpr uint32_t arch = AUDIT_ARCH_X86_64;
#else
  constexpr uint32_t arch = 0;
#endif
  if (arch == 0) return false;
  constexpr uint32_t denied = SECCOMP_RET_ERRNO | EPERM;
  // Binder's Android ioctls use type 'b'. Blocking the entire family prevents
  // direct Binder/hwbinder/vndbinder transactions from the reserved Unix UID,
  // even where upstream SELinux has a generic binder-stats allow. Block io_uring
  // as well, rather than permit an alternative asynchronous operation gateway.
  // This is an intentionally small extra filter, not a general syscall allowlist.
  const sock_filter instructions[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_setup, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, denied),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_enter, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, denied),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_register, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, denied),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 4),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args[1])),
      BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xff00),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, uint32_t('b') << 8, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, denied),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  sock_fprog program{static_cast<unsigned short>(sizeof(instructions) / sizeof(instructions[0])),
                     const_cast<sock_filter*>(instructions)};
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return false;
  return syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &program) == 0
      && prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == SECCOMP_MODE_FILTER;
}

}  // namespace andrix
