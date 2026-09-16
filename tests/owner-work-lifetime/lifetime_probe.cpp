// SPDX-License-Identifier: Apache-2.0
// Real syscall fixture. No Binder, Android authority or cgroup cleanup simulation.
#include "worker_filter.h"

#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <termios.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {
[[noreturn]] void fail(const char* why) {
  dprintf(2, "lifetime fixture: %s: %s\n", why, strerror(errno));
  _exit(120);
}
void check(bool value, const char* why) { if (!value) fail(why); }
int descriptor(const char* value) {
  char* end = nullptr;
  long n = strtol(value, &end, 10);
  check(end && *end == '\0' && n >= 3 && n < 64, "control descriptor");
  return static_cast<int>(n);
}
int connect_control(const char* name) {
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  size_t length = strlen(name);
  check(length > 0 && length < sizeof(address.sun_path) - 1, "control name");
  memcpy(address.sun_path + 1, name, length); // Private random Linux abstract fixture address.
  int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  check(fd >= 3 && fd < 64, "control socket");
  check(connect(fd, reinterpret_cast<sockaddr*>(&address),
                offsetof(sockaddr_un, sun_path) + 1 + length) == 0, "control connect");
  return fd;
}
void close_other(int a, int b = -1) {
  // The fixture only passes descriptors below 64. Never used as product FD sanitation.
  for (int fd = 3; fd < 64; ++fd) if (fd != a && fd != b) close(fd);
}
unsigned long long cgroup_fingerprint() {
  int fd = open("/proc/self/cgroup", O_RDONLY | O_CLOEXEC);
  check(fd >= 0, "cgroup observation");
  std::array<unsigned char, 4096> bytes{};
  ssize_t n = read(fd, bytes.data(), bytes.size());
  close(fd);
  check(n > 0 && n < static_cast<ssize_t>(bytes.size()), "bounded cgroup observation");
  unsigned long long hash = 14695981039346656037ULL;
  for (ssize_t i = 0; i < n; ++i) hash = (hash ^ bytes[i]) * 1099511628211ULL;
  return hash; // Compare membership without exposing host paths in the report.
}
void packet(int fd, const std::string& text) {
  check(text.size() < 2048 && send(fd, text.data(), text.size(), MSG_NOSIGNAL) ==
        static_cast<ssize_t>(text.size()), "control packet");
}
void report(int fd, const char* event, pid_t child = 0, int written = 0, int error = 0) {
  struct sigaction hup{};
  int death = -1;
  check(sigaction(SIGHUP, nullptr, &hup) == 0 && prctl(PR_GET_PDEATHSIG, &death) == 0,
        "signal observation");
  char data[2048];
  int n = snprintf(data, sizeof(data),
      "{\"event\":\"%s\",\"pid\":%d,\"ppid\":%d,\"sid\":%d,\"pgid\":%d,"
      "\"child\":%d,\"hup_ignored\":%s,\"pdeathsig\":%d,\"nnp\":%d,"
      "\"filter\":%d,\"cgroup\":%llu,\"written\":%d,\"error\":%d}",
      event, getpid(), getppid(), getsid(0), getpgrp(), child,
      hup.sa_handler == SIG_IGN ? "true" : "false", death,
      prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0), prctl(PR_GET_SECCOMP, 0, 0, 0, 0),
      cgroup_fingerprint(), written, error);
  check(n > 0 && n < static_cast<int>(sizeof(data)), "report length");
  packet(fd, data);
}
void terminal() {
  check(getsid(0) == getpid(), "launcher did not create a session");
  check(ioctl(0, TIOCSCTTY, 0) == 0 && tcsetpgrp(0, getpgrp()) == 0,
        "controlling terminal");
}
[[noreturn]] void loop(int fd, pid_t child = 0) {
  check(signal(SIGALRM, SIG_DFL) != SIG_ERR, "alarm disposition");
  sigset_t alarm_signal;
  check(sigemptyset(&alarm_signal) == 0 && sigaddset(&alarm_signal, SIGALRM) == 0 &&
        sigprocmask(SIG_UNBLOCK, &alarm_signal, nullptr) == 0, "alarm mask");
  alarm(25); // Independent failure bound, not readiness or a survival assertion.
  report(fd, "ready", child);
  for (;;) {
    pollfd p{fd, POLLIN, 0};
    int rc;
    do { rc = poll(&p, 1, 15000); } while (rc < 0 && errno == EINTR);
    check(rc > 0, "control deadline");
    char command = 0;
    ssize_t n = recv(fd, &command, 1, 0);
    if (n == 0) _exit(0);
    check(n == 1, "control read");
    if (command == 'Q') _exit(0);
    if (command == 'P') { report(fd, "pong", child); continue; }
    if (command == 'W') {
      constexpr char output[] = "WORK_LIFETIME_OUTPUT\n";
      errno = 0;
      ssize_t written = write(1, output, sizeof(output) - 1);
      int error = written < 0 ? errno : 0;
      report(fd, "write", child, static_cast<int>(written), error);
      continue;
    }
    fail("unknown control command");
  }
}
}

int main(int argc, char** argv) {
  check(argc >= 3, "arguments");
  const std::string mode(argv[1]);
  check(andrix::install_worker_filter(), "production worker filter");
  int fd = mode == "connect-job" ? connect_control(argv[2]) : descriptor(argv[2]);
  if (mode == "terminal") {
    check(argc == 4, "terminal arguments");
    close_other(fd);
    terminal();
    check(signal(SIGHUP, strcmp(argv[3], "ignore") == 0 ? SIG_IGN : SIG_DFL) != SIG_ERR,
          "terminal HUP disposition");
    loop(fd);
  }
  if (mode == "shell") {
    check(argc == 7, "shell arguments");
    int acknowledgement = descriptor(argv[3]);
    close_other(fd, acknowledgement);
    terminal();
    if (strcmp(argv[5], "login") == 0) {
      execl(argv[4], argv[4], "--noprofile", "--norc", "--noediting", "--login", "-i", "-c", argv[6], nullptr);
    } else {
      execl(argv[4], argv[4], "--noprofile", "--norc", "--noediting", "-i", "-c", argv[6], nullptr);
    }
    fail("selected shell exec");
  }
  if (mode == "job" || mode == "connect-job") {
    check(argc == 3, "job arguments");
    close_other(fd);
    loop(fd); // Preserve the disposition inherited through the shell/nohup exec.
  }
  if (mode == "parent") {
    check(argc == 5, "parent arguments");
    int job = descriptor(argv[3]);
    bool detached = strcmp(argv[4], "detached") == 0;
    close_other(fd, job);
    if (detached) terminal();
    const pid_t parent = getppid();
    check(prctl(PR_SET_PDEATHSIG, SIGKILL) == 0 && getppid() == parent,
          "fixture supervisor lifetime");
    pid_t child = fork();
    check(child >= 0, "fork");
    if (child == 0) {
      close(fd);
      if (detached) {
        check(setsid() > 1, "descendant setsid");
        int null = open("/dev/null", O_RDWR | O_CLOEXEC);
        check(null >= 0, "detached streams");
        for (int i = 0; i < 3; ++i) check(dup2(null, i) == i, "redirect stream");
        close(null);
      }
      loop(job);
    }
    close(job);
    loop(fd, child);
  }
  fail("unknown mode");
}
