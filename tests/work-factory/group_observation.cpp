// SPDX-License-Identifier: Apache-2.0
#include "group_observation.h"

#include <fcntl.h>
#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <cerrno>
#include <string_view>

namespace andrix::factory_proof {
GroupObservation::GroupObservation(int directory)
    : directory_(fcntl(directory, F_DUPFD_CLOEXEC, 0)) {}
GroupObservation::~GroupObservation() {
  if (directory_ >= 0) close(directory_);
}
GroupPopulation GroupObservation::read() {
  struct statfs fs{};
  struct stat object{};
  if (directory_ < 0 || fstatfs(directory_, &fs) ||
      fs.f_type != CGROUP2_SUPER_MAGIC || fstat(directory_, &object) ||
      !S_ISDIR(object.st_mode))
    return GroupPopulation::Unknown;
  const int fd =
      openat(directory_, "cgroup.events", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    // Core cgroup.events cannot be unlinked independently from a live group.
    // Access denial/other failures are not proof of either population or
    // removal.
    return observed_ && (errno == ENOENT || errno == ENODEV)
               ? GroupPopulation::Removed
               : GroupPopulation::Unknown;
  }
  char bytes[256];
  const ssize_t size = ::read(fd, bytes, sizeof(bytes));
  const int error = errno;
  close(fd);
  if (size < 0)
    return observed_ && error == ENODEV ? GroupPopulation::Removed
                                        : GroupPopulation::Unknown;
  if (size == 0 || size == static_cast<ssize_t>(sizeof(bytes)))
    return GroupPopulation::Unknown;
  const std::string_view text(bytes, static_cast<size_t>(size));
  GroupPopulation result = GroupPopulation::Unknown;
  size_t offset = 0;
  while (offset < text.size()) {
    auto end = text.find('\n', offset);
    if (end == std::string_view::npos) return GroupPopulation::Unknown;
    const auto line = text.substr(offset, end - offset);
    offset = end + 1;
    if (line.starts_with("populated ")) {
      if (result != GroupPopulation::Unknown) return GroupPopulation::Unknown;
      if (line == "populated 0")
        result = GroupPopulation::Empty;
      else if (line == "populated 1")
        result = GroupPopulation::Populated;
      else
        return GroupPopulation::Unknown;
    }
  }
  if (result != GroupPopulation::Unknown) observed_ = true;
  return result;
}
const char* population_name(GroupPopulation value) {
  switch (value) {
    case GroupPopulation::Populated:
      return "populated";
    case GroupPopulation::Empty:
      return "empty";
    case GroupPopulation::Removed:
      return "removed";
    case GroupPopulation::Unknown:
      return "unknown";
  }
  return "unknown";
}
}  // namespace andrix::factory_proof
