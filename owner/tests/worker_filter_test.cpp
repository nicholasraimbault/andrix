// SPDX-License-Identifier: Apache-2.0
// Real host-kernel syscall restriction and exec inheritance, not Android policy proof.
#include "worker_filter.h"
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <iostream>

void denied_binder() {
  for (unsigned long request : {static_cast<unsigned long>(_IOWR('b', 1, uint64_t[6])),
                                static_cast<unsigned long>(_IOWR('b', 9, int32_t)),
                                0x6200UL, 0xffff62ffUL}) {
    errno = 0;
    assert(ioctl(-1, request, nullptr) == -1 && errno == EPERM);
  }
  errno = 0;
  assert(syscall(__NR_io_uring_setup, 0, nullptr) == -1 && errno == EPERM);
  assert(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
  assert(prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == 2);
}

int main(int argc, char** argv) {
  if (argc == 2 && std::strcmp(argv[1], "--child") == 0) {
    denied_binder();
    return 0;
  }
  assert(argc == 1);
  errno = 0;
  assert(ioctl(-1, _IOWR('b', 9, int32_t), nullptr) == -1 && errno == EBADF);
  int master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
  assert(master >= 0);
  winsize size{24, 80, 0, 0};
  assert(ioctl(master, TIOCSWINSZ, &size) == 0);
  assert(andrix::install_worker_filter());
  denied_binder();
  size = {};
  assert(ioctl(master, TIOCGWINSZ, &size) == 0 && size.ws_row == 24 && size.ws_col == 80);
  errno = 0;
  assert(ioctl(-1, _IOWR('f', 22, int), nullptr) == -1 && errno == EBADF);
  pid_t child = fork();
  assert(child >= 0);
  if (child == 0) {
    execl(argv[0], argv[0], "--child", static_cast<char*>(nullptr));
    _exit(127);
  }
  int status = 0;
  assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  close(master);
  std::cout << "worker-only host seccomp/PTY/exec checks passed; Android unqualified\n";
}
