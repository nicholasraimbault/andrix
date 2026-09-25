// SPDX-License-Identifier: Apache-2.0
// Exercise the actual BPF programs in child processes without fabricating an
// Android principal. This is not Android Binder or caller-authority proof.
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../native/worker_filter.cpp"

namespace {
void ioctl_result(bool denied) {
  errno = 0;
  assert(ioctl(-1, _IO('b', 7), nullptr) == -1);
  assert(errno == (denied ? EPERM : EBADF));
  errno = 0;
  assert(ioctl(-1, _IO('x', 7), nullptr) == -1 && errno == EBADF);
}
void run(int mode) {
  pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    ioctl_result(false);  // Same-subject positive before installing the filter.
    if (mode == 0) assert(andrix::install_worker_filter());
    else assert(andrix::install_filter(false));  // Test the native BPF, not its authority guard.
    ioctl_result(mode == 0);
    assert(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
    assert(prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == 2);
    errno = 0;
    assert(syscall(SYS_io_uring_setup, 0, nullptr) == -1 && errno == EPERM);
    errno = 0;
    assert(syscall(SYS_io_uring_enter, -1, 0, 0, 0, nullptr, 0) == -1 && errno == EPERM);
    errno = 0;
    assert(syscall(SYS_io_uring_register, -1, 0, nullptr, 0) == -1 && errno == EPERM);
    // Adding either program can never relax an inherited legacy denial.
    assert(andrix::install_worker_filter());
    assert(andrix::install_filter(false));
    ioctl_result(true);
    _exit(0);
  }
  int status = 0;
  assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
}  // namespace
int main() {
  const auto uid = getuid() % 100000;
  if (uid < 10000 || uid >= 20000) {
    const int before = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    assert(!andrix::install_principal_filter());
    assert(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == before);
  }
  run(0);
  run(1);
  puts("principal/legacy filter programs and inherited denial checked; not Android qualification");
}
