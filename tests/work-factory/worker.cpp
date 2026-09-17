// SPDX-License-Identifier: Apache-2.0
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <string>

#include "common.h"
#include "worker_filter.h"

using namespace andrix::factory_proof;
namespace {
WorkerEvent event(uint32_t kind, const std::string& group) {
  WorkerEvent value;
  value.kind = kind;
  value.pid = getpid();
  value.parent = getppid();
  value.session = getsid(0);
  value.group = getpgrp();
  value.uid = getuid();
  errno = 0;
  int result = ioctl(0, _IO('b', 1));
  value.binder_errno = errno;
  if (result != -1 || value.binder_errno != EPERM) _exit(123);
  errno = 0;
  int fd = open((group + "/cgroup.procs").c_str(),
                O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
  value.cgroup_errno = errno;
  if (fd >= 0 || (value.cgroup_errno != EACCES && value.cgroup_errno != EPERM))
    _exit(124);
  return value;
}
void publish(const WorkerEvent& value) {
  // Observation loss does not make detached payloads exit. Stop must kill their
  // group.
  (void)send(1, &value, sizeof(value), MSG_NOSIGNAL);
}
}  // namespace
int main(int argc, char** argv) {
  uint64_t parent = 0;
  if (argc != 3 || !parse_id(argv[1], &parent) || uint64_t(getppid()) != parent)
    return 125;
  const std::string group = argv[2];
  if (setpriority(PRIO_PROCESS, 0, 10) || !bounds_error(group, true).empty())
    return 126;
  if (!andrix::install_worker_filter()) return 127;
  signal(SIGALRM, SIG_DFL);
  alarm(240);
  publish(event(WorkerHeld, group));
  char release = 0;
  if (read(0, &release, 1) != 1 || release != 'R' ||
      !bounds_error(group, true).empty())
    return 126;
  for (int i = 0; i < 2; ++i) {
    pid_t child = fork();
    if (child < 0) return 124;
    if (!child) {
      if (setsid() < 0) _exit(125);
      signal(SIGHUP, SIG_IGN);
      signal(SIGTERM, SIG_IGN);
      signal(SIGPIPE, SIG_IGN);
      signal(SIGALRM, SIG_DFL);
      alarm(240);
      for (;;) {
        publish(event(WorkerPulse, group));
        usleep(200000);
      }
    }
  }
  return 0;
}
