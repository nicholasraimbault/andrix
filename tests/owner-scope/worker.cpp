// SPDX-License-Identifier: Apache-2.0
// Fixed owner-domain payload for the scope proof. Never a general exec interface.
#include "guards.h"
#include "worker_filter.h"
#include "wire.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {
[[noreturn]] void fail(const char* why) { dprintf(2, "scope worker refused: %s\n", why); _exit(126); }
void event(uint32_t type, pid_t guardian) {
  using namespace andrix::scope_proof;
  errno = 0;
  const int binder = ioctl(0, _IO('b', 1), nullptr);
  const int binder_error = errno;
  std::string group = "/sys/fs/cgroup/system/uid_7500/pid_" + std::to_string(guardian) + "/cgroup.procs";
  errno = 0;
  int fd = open(group.c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
  int group_error = errno;
  if (fd >= 0) { close(fd); fail("worker obtained cgroup control descriptor"); }
  if (binder != -1 || binder_error != EPERM || (group_error != EACCES && group_error != EPERM))
    fail("negative control mismatch");
  Event value{kMagic, type, getpid(), getppid(), getsid(0), getpgrp(), static_cast<int32_t>(getuid()),
              binder_error, group_error};
  if (write(1, &value, sizeof(value)) != sizeof(value)) {
    // Broken observer is not permission to leave the resource group. Surviving
    // descendants ignore the channel failure and still require actual group cleanup.
    if (type == kHeld) fail("held acknowledgement");
  }
}
}

int main(int argc, char** argv) {
  if (argc != 2) fail("fixed guardian argument");
  char* end = nullptr;
  long parsed = strtol(argv[1], &end, 10);
  if (!end || *end || parsed <= 1 || parsed != getppid()) fail("actual parent mismatch");
  const pid_t guardian = static_cast<pid_t>(parsed);
  // The forking Binder thread can temporarily inherit the Shell caller's nice
  // priority. Restore the fixed worker floor before checking inherited bounds.
  if (setpriority(PRIO_PROCESS, 0, 10) != 0) fail("worker priority floor");
  if (!andrix::check_identity().empty() || !andrix::check_resource_bounds(guardian).empty())
    fail("identity or resource bounds");
  if (!andrix::install_worker_filter()) fail("worker filter");
  char sid[128]{};
  int label = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
  ssize_t n = label >= 0 ? read(label, sid, sizeof(sid) - 1) : -1;
  if (label >= 0) close(label);
  if (n <= 0) fail("worker MAC observation");
  std::string role(sid, n);
  while (!role.empty() && (role.back() == '\n' || role.back() == '\0')) role.pop_back();
  if (role != "u:r:andrix_owner:s0") fail("worker MAC role");
  if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != guardian) fail("guardian lost");
  alarm(300);
  event(andrix::scope_proof::kHeld, guardian);
  char release = 0;
  if (read(0, &release, 1) != 1 || release != 'R') fail("release gate closed");
  if (!andrix::check_resource_bounds(guardian).empty()) fail("bounds lost before payload");
  for (int i = 0; i < 2; ++i) {
    pid_t child = fork();
    if (child < 0) fail("bounded descendant fork");
    if (child == 0) {
      // These descendants deliberately defeat PGID-only cleanup and observer EOF.
      if (setsid() <= 1 || signal(SIGHUP, SIG_IGN) == SIG_ERR ||
          signal(SIGTERM, SIG_IGN) == SIG_ERR || signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        fail("detached descendant setup");
      int death = -1;
      if (prctl(PR_GET_PDEATHSIG, &death) != 0 || death != 0) fail("fork death-signal control");
      alarm(300); // Independent fixture bound, not the intended Stop mechanism.
      for (;;) {
        event(andrix::scope_proof::kPulse, guardian);
        usleep(200000);
      }
    }
  }
  _exit(0); // Detached descendants must outlive this entry, inside the SAME cgroup.
}
