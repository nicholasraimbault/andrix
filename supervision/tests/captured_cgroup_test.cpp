// SPDX-License-Identifier: Apache-2.0
#include "captured_cgroup.h"

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <string>
#include <string_view>

using namespace andrix::supervision;
namespace {
size_t open_fds() {
  DIR* dir = opendir("/proc/self/fd");
  assert(dir);
  size_t count = 0;
  while (auto entry = readdir(dir))
    if (entry->d_name[0] != '.') ++count;
  closedir(dir);
  return count;
}
}  // namespace
int main() {
  using detail::ParsePopulation;
  assert(ParsePopulation("populated 0\nfrozen 0\n").state ==
         GroupPopulation::Empty);
  assert(ParsePopulation("frozen 0\npopulated 1\n").state ==
         GroupPopulation::Populated);
  for (std::string_view text :
       {"", "populated 0", "populated 2\n", "populated 00\n",
        "populated 0\npopulated 1\n", "populated 0\npopulated 0\n",
        "frozen 0\n", "populated \n", "populated\t0\n", "populated 0\nbroken\n",
        "populated 0\n\n"}) {
    auto result = ParsePopulation(text);
    assert(result.state == GroupPopulation::Unknown && result.error != 0);
  }
  const char nul[] = "populated 0\0\nfrozen 0\n";
  assert(ParsePopulation(std::string_view(nul, sizeof(nul) - 1)).state ==
         GroupPopulation::Unknown);
  assert(ParsePopulation(std::string(4096, 'x')).state ==
         GroupPopulation::Unknown);

  const CleanupLimits limits{8, 64, 4096, 8192, 32};
  Failure error;
  const int temporary = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  assert(temporary >= 0);
  const size_t before = open_fds();
  for (int n = 0; n < 20; ++n) {
    assert(!CapturedCgroup::Capture(temporary, "scope", limits, error));
    assert(error.code == GroupError::WrongFilesystem);
    assert(!CapturedCgroup::Capture(-1, "scope", limits, error));
    assert(error.code == GroupError::Io);
    for (std::string_view name : {"", ".", "..", "a/b", "/absolute"}) {
      assert(!CapturedCgroup::Capture(temporary, name, limits, error));
      assert(error.code == GroupError::InvalidArgument);
    }
    const char name[] = "scope\0other";
    assert(!CapturedCgroup::Capture(
        temporary, std::string_view(name, sizeof(name) - 1), limits, error));
    assert(error.code == GroupError::InvalidArgument);
    assert(!CapturedCgroup::Capture(temporary, "scope",
                                    CleanupLimits{65, 1, 1, 1, 1}, error));
    assert(error.code == GroupError::InvalidArgument);
    auto invalid_policy = limits;
    invalid_policy.directory_retirement = static_cast<DirectoryRetirement>(99);
    assert(!CapturedCgroup::Capture(temporary, "scope", invalid_policy, error));
    assert(error.code == GroupError::InvalidArgument);
  }
  assert(open_fds() == before);
  assert(!CapturedCgroup::Adopt(nullptr, error));
  assert(error.code == GroupError::InvalidArgument);
  auto invalid = std::make_unique<CgroupTransfer>();
  invalid->name = "scope";
  invalid->limits = limits;
  for (int& descriptor : invalid->descriptors) descriptor = dup(temporary);
  assert(!CapturedCgroup::Adopt(std::move(invalid), error));
  assert(error.code == GroupError::WrongFilesystem && open_fds() == before);
  close(temporary);
}
