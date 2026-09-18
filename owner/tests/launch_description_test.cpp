// SPDX-License-Identifier: Apache-2.0
#include "launch_description.h"

#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <string>
#include <vector>

using namespace andrix;
namespace {
void integer(std::vector<uint8_t>& bytes, size_t at, uint32_t value) {
  for (size_t n = 0; n < 4; ++n)
    bytes.at(at + n) = static_cast<uint8_t>(value >> (8 * n));
}
}  // namespace
int main() {
  LaunchLimits limits;
  LaunchFailure failure;
  LaunchDescription request{
      "./out/program",
      {"chosen-argv0", "", "a b", "$(not a shell)", std::string("\x80\xff", 2)},
      {"PATH=/usr/bin:/system/bin",
       "LD_PRELOAD=/data/misc_ce/0/andrix/libmine.so", "ENV=owner.rc",
       "X=first", "X=second", ""},
      "/data/misc_ce/0/andrix/project"};
  std::vector<uint8_t> bytes;
  assert(EncodeLaunch(request, limits, bytes, failure) &&
         failure.code == LaunchError::None);
  LaunchDescription decoded;
  assert(DecodeLaunch(bytes, limits, decoded, failure) && decoded == request);
  auto empty_env = request;
  empty_env.environment.clear();
  std::vector<uint8_t> empty_bytes;
  assert(EncodeLaunch(empty_env, limits, empty_bytes, failure) &&
         DecodeLaunch(empty_bytes, limits, decoded, failure) &&
         decoded == empty_env);
  for (int kind = 0; kind < 4; ++kind) {
    auto invalid = request;
    if (kind == 0) invalid.executable = std::string("bad\0path", 8);
    if (kind == 1) invalid.directory = std::string("bad\0dir", 7);
    if (kind == 2) invalid.arguments[1] = std::string("a\0b", 3);
    if (kind == 3) invalid.environment[0] = std::string("X=a\0b", 5);
    std::vector<uint8_t> untouched{1, 2, 3};
    assert(!EncodeLaunch(invalid, limits, untouched, failure) &&
           failure.code == LaunchError::Invalid &&
           untouched == std::vector<uint8_t>({1, 2, 3}));
  }
  for (int kind = 0; kind < 3; ++kind) {
    auto invalid = request;
    if (kind == 0) invalid.executable.clear();
    if (kind == 1) invalid.directory.clear();
    if (kind == 2) invalid.arguments.clear();
    assert(!EncodeLaunch(invalid, limits, empty_bytes, failure) &&
           failure.code == LaunchError::Invalid);
  }
  auto limited = limits;
  limited.arguments = 1;
  assert(!EncodeLaunch(request, limited, empty_bytes, failure) &&
         failure.code == LaunchError::Limit);
  limited = limits;
  limited.environment = 1;
  assert(!EncodeLaunch(request, limited, empty_bytes, failure) &&
         failure.code == LaunchError::Limit);
  limited = limits;
  limited.bytes = bytes.size() - 1;
  assert(!EncodeLaunch(request, limited, empty_bytes, failure) &&
         failure.code == LaunchError::Limit);
  limited.bytes = bytes.size();
  assert(EncodeLaunch(request, limited, empty_bytes, failure) &&
         empty_bytes == bytes);
  limited.bytes = 0;
  assert(!EncodeLaunch(request, limited, empty_bytes, failure) &&
         failure.code == LaunchError::Invalid);
  const LaunchDescription sentinel{"sentinel", {"unchanged"}, {}, "/"};
  for (size_t size = 0; size < bytes.size(); ++size) {
    std::vector<uint8_t> prefix(bytes.begin(), bytes.begin() + size);
    decoded = sentinel;
    assert(!DecodeLaunch(prefix, limits, decoded, failure) &&
           decoded == sentinel);
  }
  for (size_t offset : {size_t(0), size_t(4), size_t(8), size_t(12), size_t(16),
                        size_t(20), size_t(24)}) {
    auto invalid = bytes;
    integer(invalid, offset, 0xffffffffU);
    decoded = sentinel;
    assert(!DecodeLaunch(invalid, limits, decoded, failure) &&
           decoded == sentinel);
  }
  auto nul = bytes;
  nul[28] = 0;
  decoded = sentinel;
  assert(!DecodeLaunch(nul, limits, decoded, failure) && decoded == sentinel);
  auto trailing = bytes;
  trailing.push_back(0);
  integer(trailing, 8, static_cast<uint32_t>(trailing.size()));
  assert(!DecodeLaunch(trailing, limits, decoded, failure));
  int fd = SealLaunch(request, limits, failure);
  assert(fd >= 0 && (fcntl(fd, F_GETFD) & FD_CLOEXEC));
  assert(ReadLaunch(fd, limits, decoded, failure) && decoded == request);
  assert((fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDONLY);
  assert(pwrite(fd, "x", 1, 0) == -1 && errno == EBADF);
  int writable =
      open(("/proc/self/fd/" + std::to_string(fd)).c_str(), O_RDWR | O_CLOEXEC);
  assert(writable >= 0);
  assert(pwrite(writable, "x", 1, 0) == -1 && errno == EPERM);
  assert(ftruncate(writable, 0) == -1 && errno == EPERM);
  close(writable);
  assert(lseek(fd, 17, SEEK_SET) == 17);
  assert(ReadLaunch(fd, limits, decoded, failure) && decoded == request);
  close(fd);
  assert(!ReadLaunch(-1, limits, decoded, failure) && failure.error == EBADF);
  int unsealed =
      static_cast<int>(syscall(SYS_memfd_create, "unsealed-request", 3U));
  assert(unsealed >= 0);
  assert(write(unsealed, bytes.data(), bytes.size()) ==
         static_cast<ssize_t>(bytes.size()));
  decoded = sentinel;
  assert(!ReadLaunch(unsealed, limits, decoded, failure) &&
         failure.code == LaunchError::NotSealed && decoded == sentinel);
  close(unsealed);
}
