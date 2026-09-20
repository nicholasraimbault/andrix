// SPDX-License-Identifier: Apache-2.0
// Fixed lower-role entry. No supervisor channel, gate or resource FD reaches
// here.
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <string>
#include <vector>

#include "guards.h"
#include "launch_description.h"
#include "work_profile.h"
#include "worker_filter.h"

namespace {
[[noreturn]] void fail(const std::string& reason) {
  dprintf(2, "andrix owner work entry refused: %s (%d)\n", reason.c_str(),
          errno);
  _exit(126);
}
}  // namespace
int main(int argc, char** argv) {
  if (argc != 2 || !argv[1] || argv[1][0] < '0' || argv[1][0] > '7' ||
      argv[1][1] || !andrix::ManagementDescriptorsClosed(3))
    fail("fixed owner entry descriptors");
  const unsigned closed_stdio = static_cast<unsigned>(argv[1][0] - '0');
  for (int fd = 0; fd <= 3; ++fd)
    if (fcntl(fd, F_GETFD) < 0) fail("missing declared owner descriptor");
  auto profile = andrix::CheckOwnerEntry();
  if (!profile.empty()) fail(profile);
  // The exact filter was installed before the MAC crossing. Installing the
  // same restriction again cannot remove it, and preserves this entry's guard.
  if (!andrix::install_worker_filter()) fail("owner syscall restriction");
  int mode = fcntl(3, F_GETFL);
  if (mode < 0 || (mode & O_ACCMODE) != O_RDONLY || (mode & O_PATH))
    fail("read-only ordinary description");
  andrix::LaunchDescription description;
  andrix::LaunchFailure error;
  if (!andrix::ReadLaunch(3, {}, description, error))
    fail("immutable ordinary description");
  if (close(3) || !andrix::ManagementDescriptorsClosed(-1))
    fail("ordinary descriptor closure");
  // All remaining state is ordinary owner state. Paths and LD_* values below
  // never select a privileged bootstrap or its startup environment.
  std::string home_error;
  int home = andrix::open_ce_home(&home_error);
  if (home < 0) fail(home_error);
  if (fchdir(home)) {
    close(home);
    fail("initial owner directory");
  }
  if (close(home)) fail("owner directory descriptor closure");
  if (chdir(description.directory.c_str())) fail("requested working directory");
  umask(0077);
  std::vector<char*> arguments, environment;
  for (auto& value : description.arguments) arguments.push_back(value.data());
  arguments.push_back(nullptr);
  for (auto& value : description.environment)
    environment.push_back(value.data());
  environment.push_back(nullptr);
  // Bionic's fixed entry startup may have opened /dev/null for missing stdio.
  // Preserve the requested kernel exec handoff instead of leaking those
  // intermediate replacements into a payload that does not establish its own
  // stdio. The payload's runtime may itself reopen null, as Bionic normally
  // does.
  for (int fd = 0; fd < 3; ++fd)
    if ((closed_stdio & (1U << fd)) && close(fd) && errno != EBADF)
      fail("ordinary closed standard descriptor");
  execve(description.executable.c_str(), arguments.data(), environment.data());
  fail("ordinary program exec");
}
