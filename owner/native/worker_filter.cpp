// SPDX-License-Identifier: Apache-2.0
#include "worker_filter.h"

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>

namespace andrix {
namespace {
bool install_filter(bool block_binder) {
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
  // Both paths retain the architecture and io_uring restrictions. The legacy
  // reserved UID additionally blocks Binder's entire ioctl family. This is an
  // extra filter, not a complete general syscall allowlist.
  const sock_filter common[] = {
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
  };
  const sock_filter binder[] = {
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 4),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args[1])),
      BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xff00),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, uint32_t('b') << 8, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, denied),
  };
  std::array<sock_filter, std::size(common) + std::size(binder) + 1> instructions{};
  auto end = std::copy(std::begin(common), std::end(common), instructions.begin());
  if (block_binder) end = std::copy(std::begin(binder), std::end(binder), end);
  *end++ = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
  // Native service authorities still enforce the real UID and permissions.
  // Installing this program cannot remove an inherited legacy denial.
  sock_fprog program{static_cast<unsigned short>(end - instructions.begin()),
                     instructions.data()};
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return false;
  return syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &program) == 0
      && prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == SECCOMP_MODE_FILTER;
}
}  // namespace

bool install_worker_filter() { return install_filter(true); }

bool install_principal_filter() {
  uid_t real, effective, saved;
  if (getresuid(&real, &effective, &saved) || real != effective || real != saved ||
      real % 100000 < 10000 || real % 100000 >= 20000)
    return false;
  return install_filter(false);
}
}  // namespace andrix
