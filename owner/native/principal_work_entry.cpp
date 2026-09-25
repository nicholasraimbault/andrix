// SPDX-License-Identifier: Apache-2.0
// Ordinary principal entry after the protected manager-role exec transition.
// The only extra descriptors are immutable data and the captured account home.
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <charconv>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

#include "launch_description.h"
#include "principal_credentials.h"
#include "principal_profile.h"
#include "work_profile.h"
#include "worker_filter.h"

namespace {
[[noreturn]] void fail(const char* message) {
  dprintf(2, "andrix principal entry refused: %s\n", message);
  _exit(126);
}
uint64_t number(const char* text, uint64_t maximum, bool zero = false) {
  if (!text || !*text) fail("missing internal identity");
  const size_t length = strlen(text);
  if (length > 20 || (length > 1 && text[0] == '0')) fail("internal identity format");
  uint64_t value = 0;
  auto parsed = std::from_chars(text, text + length, value);
  if (parsed.ec != std::errc{} || parsed.ptr != text + length || value > maximum ||
      (!zero && !value)) fail("internal identity range");
  return value;
}
}  // namespace
int main(int argc, char** argv) {
  using namespace andrix;
  constexpr std::array<int, 3> data_fds{3, 4, 5};
  if (argc != 7 || !OnlyDeclaredDescriptors(data_fds)) fail("fixed entry descriptors");
  for (int fd = 0; fd <= 5; ++fd)
    if (fcntl(fd, F_GETFD) < 0) fail("missing entry descriptor");
  const auto closed_stdio = static_cast<uint32_t>(number(argv[1], 7, true));
  constexpr uint64_t maximum = std::numeric_limits<int64_t>::max();
  WorkIdentity work{number(argv[2], UINT64_MAX), number(argv[3], UINT64_MAX)};
  AuthorityEpoch epoch{number(argv[4], maximum), number(argv[5], maximum),
                       static_cast<int32_t>(number(argv[6], INT32_MAX, true))};
  PrincipalProfile profile;
  int error = 0;
  if (!ReadPrincipalLaunch(4, work, epoch, profile, error)) fail("principal binding");
  auto refused = CheckPrincipalCredentials(profile, PrincipalStage::Payload);
  if (!refused.empty()) fail(refused.c_str());
  refused = CheckWorkLimits();
  if (!refused.empty()) fail(refused.c_str());
  refused = CheckPrincipalHome(5, profile);
  if (!refused.empty()) fail(refused.c_str());
  if (!install_principal_filter()) fail("principal syscall restriction");
  int flags = fcntl(3, F_GETFL);
  if (flags < 0 || (flags & O_PATH) || (flags & O_ACCMODE) != O_RDONLY)
    fail("ordinary launch descriptor mode");
  LaunchDescription description;
  LaunchFailure failure;
  if (!ReadLaunch(3, {}, description, failure)) fail("immutable ordinary launch data");
  // No package app-data or plaintext home fallback. CE freshness was established
  // by admission, not by possession of this still-readable directory descriptor.
  if (fchdir(5) || close(5) || close(4) || close(3) || !OnlyDeclaredDescriptors({}))
    fail("data descriptor closure");
  if (chdir(description.directory.c_str())) fail("ordinary working directory");
  umask(0077);
  std::vector<char*> arguments, environment;
  for (auto& value : description.arguments) arguments.push_back(value.data());
  arguments.push_back(nullptr);
  for (auto& value : description.environment) environment.push_back(value.data());
  environment.push_back(nullptr);
  for (int fd = 0; fd < 3; ++fd)
    if ((closed_stdio & (1U << fd)) && close(fd) && errno != EBADF)
      fail("closed ordinary standard descriptor");
  execve(description.executable.c_str(), arguments.data(), environment.data());
  fail("ordinary program exec");
}
