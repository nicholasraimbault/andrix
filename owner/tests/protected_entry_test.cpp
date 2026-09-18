// SPDX-License-Identifier: Apache-2.0
// Real Linux exec dumpability and inherited-FD controls, not Android MAC proof.
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {
constexpr char kCanary[] = "private admission control";
struct Bootstrap {
  pid_t pid;
  uid_t uid;
  int dumpable;
  unsigned long secure;
};
int bootstrap(const char* payload) {
  // Do not set dumpability before reporting. The question is what the kernel
  // established before ANY bootstrap userspace instruction could execute.
  Bootstrap observed{getpid(), getuid(), prctl(PR_GET_DUMPABLE, 0, 0, 0, 0),
                     getauxval(AT_SECURE)};
  assert(send(4, &observed, sizeof(observed), MSG_NOSIGNAL) ==
         static_cast<ssize_t>(sizeof(observed)));
  char go = 0;
  assert(read(4, &go, 1) == 1 && go == 'R');
  close(3);
  close(4);
  // Ordinary readable exec must be debuggable again, with no management FD.
  const char* arguments[] = {payload, "--payload", nullptr};
  char value[] = "ANDRIX_PAYLOAD_TEST=ordinary-environment";
  char* environment[] = {value, nullptr};
  execve(payload, const_cast<char* const*>(arguments), environment);
  return 127;
}
int payload() {
  assert(prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 1);
  assert(fcntl(3, F_GETFD) == -1 && errno == EBADF);
  assert(fcntl(4, F_GETFD) == -1 && errno == EBADF);
  assert(getenv("ANDRIX_PAYLOAD_TEST") &&
         !strcmp(getenv("ANDRIX_PAYLOAD_TEST"), "ordinary-environment"));
  puts("PAYLOAD_DEBUGGABLE_WITHOUT_MANAGEMENT_FDS");
  return 0;
}
void run(const char* executable, const char* payload_path,
         bool protected_mode) {
  int secret =
      static_cast<int>(syscall(SYS_memfd_create, "entry-test-control", 1U));
  assert(secret >= 0);
  assert(write(secret, kCanary, sizeof(kCanary)) ==
         static_cast<ssize_t>(sizeof(kCanary)));
  int channel[2], output[2];
  assert(!socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel));
  assert(!pipe2(output, O_CLOEXEC));
  const char* arguments[] = {executable, "--bootstrap", payload_path, nullptr};
  char* environment[] = {nullptr};
  pid_t pid = fork();
  assert(pid >= 0);
  if (!pid) {
    int saved_secret = fcntl(secret, F_DUPFD_CLOEXEC, 10),
        saved_channel = fcntl(channel[1], F_DUPFD_CLOEXEC, 10),
        saved_output = fcntl(output[1], F_DUPFD_CLOEXEC, 10);
    if (saved_secret < 0 || saved_channel < 0 || saved_output < 0 ||
        dup2(saved_secret, 3) != 3 || dup2(saved_channel, 4) != 4 ||
        dup2(saved_output, 1) != 1 || syscall(SYS_close_range, 5, ~0U, 0))
      _exit(125);
    execve(executable, const_cast<char* const*>(arguments), environment);
    _exit(127);
  }
  close(channel[1]);
  close(output[1]);
  close(secret);
  int identity = static_cast<int>(syscall(SYS_pidfd_open, pid, 0));
  assert(identity >= 0);
  pollfd wait{channel[0], POLLIN, 0};
  assert(poll(&wait, 1, 5000) == 1);
  Bootstrap observed{};
  assert(recv(channel[0], &observed, sizeof(observed), MSG_TRUNC) ==
         static_cast<ssize_t>(sizeof(observed)));
  assert(observed.pid == pid && observed.uid == getuid());
  assert(protected_mode ? observed.dumpable != 1 : observed.dumpable == 1);
  std::string path = "/proc/" + std::to_string(pid) + "/fd/3";
  errno = 0;
  int stolen = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  int fd_error = errno;
  if (protected_mode)
    assert(stolen == -1 && (fd_error == EACCES || fd_error == EPERM));
  else {
    assert(stolen >= 0);
    char canary[sizeof(kCanary)]{};
    assert(pread(stolen, canary, sizeof(canary), 0) ==
               static_cast<ssize_t>(sizeof(canary)) &&
           !memcmp(canary, kCanary, sizeof(canary)));
    close(stolen);
  }
  path = "/proc/" + std::to_string(pid) + "/mem";
  errno = 0;
  int memory = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  int memory_error = errno;
  if (protected_mode)
    assert(memory == -1 && (memory_error == EACCES || memory_error == EPERM));
  else {
    assert(memory >= 0);
    close(memory);
  }
  const char go = 'R';
  assert(write(channel[0], &go, 1) == 1);
  wait = {identity, POLLIN, 0};
  assert(poll(&wait, 1, 5000) == 1);
  int status = 0;
  assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
         WEXITSTATUS(status) == 0);
  char result[256]{};
  ssize_t count = read(output[0], result, sizeof(result));
  assert(count > 0);
  assert(std::string(result, static_cast<size_t>(count))
             .find("PAYLOAD_DEBUGGABLE_WITHOUT_MANAGEMENT_FDS") !=
         std::string::npos);
  printf(
      "{\"protected_mode\":%s,\"initial_dumpable\":%d,\"at_secure\":%lu,"
      "\"control_fd_open_errno\":%d,\"memory_open_errno\":%d,\"final_readable_"
      "exec_debuggable\":true}\n",
      protected_mode ? "true" : "false", observed.dumpable, observed.secure,
      fd_error, memory_error);
  close(identity);
  close(channel[0]);
  close(output[0]);
}
}  // namespace
int main(int argc, char** argv) {
  if (argc == 3 && !strcmp(argv[1], "--bootstrap")) return bootstrap(argv[2]);
  if (argc == 2 && !strcmp(argv[1], "--payload")) return payload();
  assert(argc == 3 && getuid() != 0);
  alarm(30);
  struct stat readable{}, execute_only{};
  assert(!stat(argv[1], &readable) && !stat(argv[2], &execute_only));
  assert((readable.st_mode & 0777) == 0755 &&
         (execute_only.st_mode & 0777) == 0111);
  run(argv[1], argv[1], false);
  run(argv[2], argv[1], true);
  run(argv[1], argv[1], false);
}
