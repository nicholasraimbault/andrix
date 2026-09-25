// SPDX-License-Identifier: Apache-2.0
// Deterministic writer interleaving at the size observation, using a real memfd.
// Link with --wrap=fstat. This tests record integrity, not Android authority.
#include "launch_description.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <vector>

namespace {
int watched = -1;
size_t original_size = 0;
bool armed = false;
constexpr int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
}
extern "C" int __real_fstat(int, struct stat*);
extern "C" int __wrap_fstat(int fd, struct stat* info) {
  int result = __real_fstat(fd, info);
  if (!result && armed && fd == watched) {
    // A writer grows and seals just after the reader observes the old size.
    assert(pwrite(fd, "x", 1, static_cast<off_t>(original_size)) == 1);
    assert(fcntl(fd, F_ADD_SEALS, seals) == 0);
    armed = false;
  }
  return result;
}
int main() {
  andrix::LaunchDescription original{"/usr/bin/example", {"example"}, {}, "/"};
  andrix::LaunchFailure failure;
  std::vector<uint8_t> bytes;
  assert(andrix::EncodeLaunch(original, {}, bytes, failure));
  watched = static_cast<int>(syscall(SYS_memfd_create, "launch-seal-order", 3U));
  assert(watched >= 0);
  original_size = bytes.size();
  assert(pwrite(watched, bytes.data(), bytes.size(), 0) == static_cast<ssize_t>(bytes.size()));
  armed = true;
  andrix::LaunchDescription output;
  assert(!andrix::ReadLaunch(watched, {}, output, failure));
  // The current reader rejects before inspecting a mutable size.
  assert(armed && failure.code == andrix::LaunchError::NotSealed);
  // Positive control: the link wrapper really intercepts this platform's
  // fstat call and performs the competing writer operation.
  struct stat old_size{};
  assert(fstat(watched, &old_size) == 0 && !armed &&
         old_size.st_size == static_cast<off_t>(bytes.size()));
  assert(!andrix::ReadLaunch(watched, {}, output, failure));
  close(watched);
  int valid = andrix::SealLaunch(original, {}, failure);
  assert(valid >= 0 && andrix::ReadLaunch(valid, {}, output, failure) && output == original);
  close(valid);
}
