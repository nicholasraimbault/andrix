// SPDX-License-Identifier: Apache-2.0
#include "work_profile.h"

#include <android-base/unique_fd.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <linux/openat2.h>
#include <selinux/selinux.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <charconv>
#include <cstring>
#include <string_view>
#include <utility>

#include "guards.h"
#include "session_core.h"

namespace andrix {
namespace {
using android::base::unique_fd;
std::string read_file(int directory, const char* name) {
  unique_fd fd(openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  if (fd < 0) return {};
  char bytes[8192];
  ssize_t count = read(fd.get(), bytes, sizeof(bytes));
  if (count <= 0 || count == static_cast<ssize_t>(sizeof(bytes))) return {};
  return std::string(bytes, static_cast<size_t>(count));
}
bool number(std::string text, uint64_t wanted) {
  while (!text.empty() && text.back() == '\n') text.pop_back();
  uint64_t value = 0;
  auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
  return !text.empty() && parsed.ec == std::errc{} &&
         parsed.ptr == text.data() + text.size() && value == wanted;
}
bool directory(int fd, LaunchObjectIdentity& result) {
  struct stat info{};
  struct statfs fs{};
  const int mode = fcntl(fd, F_GETFL);
  if (mode < 0 || (mode & O_PATH) || (mode & O_ACCMODE) != O_RDONLY ||
      fstat(fd, &info) || fstatfs(fd, &fs) || !S_ISDIR(info.st_mode) ||
      fs.f_type != CGROUP2_SUPER_MAGIC)
    return false;
  result = {static_cast<uint64_t>(info.st_dev),
            static_cast<uint64_t>(info.st_ino)};
  return true;
}
bool protected_file(int fd, const char* name, uint64_t expected) {
  unique_fd file(openat(fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  struct stat info{};
  if (file < 0 || fstat(file.get(), &info) || !S_ISREG(info.st_mode) ||
      (info.st_uid != 0 && info.st_uid != 1000) ||
      (info.st_gid != 0 && info.st_gid != 1000) || (info.st_mode & S_IWOTH))
    return false;
  unique_fd denied(openat(fd, name, O_WRONLY | O_CLOEXEC | O_NOFOLLOW));
  if (denied >= 0 || errno != EACCES) return false;
  return number(read_file(fd, name), expected);
}
std::string identity_and_limits(const char* expected_role) {
  auto error = check_identity();
  if (!error.empty()) return error;
  uid_t r, e, s;
  gid_t gr, ge, gs;
  if (getresuid(&r, &e, &s) || getresgid(&gr, &ge, &gs) || r != kOwnerUid ||
      e != kOwnerUid || s != kOwnerUid || gr != kOwnerUid || ge != kOwnerUid ||
      gs != kOwnerUid)
    return "saved owner identity";
  gid_t group = 0;
  if (getgroups(1, &group) != 1 || group != 3003)
    return "declared supplementary groups";
  char* role = nullptr;
  if (getcon(&role) || !role) return "actual launch role unavailable";
  const bool correct = std::string_view(role) == expected_role;
  freecon(role);
  if (!correct) return "wrong launch role";
  for (auto [resource, bound] : {std::pair{RLIMIT_NPROC, rlim_t(kProcessLimit)},
                                 {RLIMIT_NOFILE, rlim_t(kDescriptorLimit)},
                                 {RLIMIT_CORE, rlim_t(0)},
                                 {RLIMIT_FSIZE, rlim_t(67108864)}}) {
    rlimit actual{};
    if (getrlimit(resource, &actual) || actual.rlim_cur != bound ||
        actual.rlim_max != bound)
      return "declared launch rlimit missing";
  }
  errno = 0;
  int nice = getpriority(PRIO_PROCESS, getpid());
  if (errno || nice != 10) return "declared launch priority missing";
  if (!number(read_file(AT_FDCWD, "/proc/self/oom_score_adj"), 700))
    return "declared memory priority missing";
  return {};
}
std::string membership() {
  auto text = read_file(AT_FDCWD, "/proc/self/cgroup");
  std::string result;
  size_t offset = 0;
  while (offset < text.size()) {
    auto end = text.find('\n', offset);
    if (end == std::string::npos) return {};
    std::string_view line(text.data() + offset, end - offset);
    offset = end + 1;
    if (line.starts_with("0::")) {
      if (!result.empty()) return {};
      result = line.substr(3);
    }
  }
  if (result.empty() || result.front() != '/' ||
      result.find('\0') != std::string::npos)
    return {};
  return result;
}
}  // namespace
std::string CheckLaunchStage(int aggregate_fd, int scope_fd,
                             LaunchObjectIdentity expected_aggregate,
                             LaunchObjectIdentity expected_scope) {
  auto error = identity_and_limits("u:r:andrixd:s0");
  if (!error.empty()) return error;
  LaunchObjectIdentity aggregate, scope;
  if (!directory(aggregate_fd, aggregate) || !directory(scope_fd, scope) ||
      aggregate != expected_aggregate || scope != expected_scope ||
      aggregate.device != scope.device || aggregate == scope)
    return "captured launch resource identity";
  auto relative = membership();
  if (relative.size() < 2) return "actual unified launch membership";
  unique_fd mount(
      open("/sys/fs/cgroup", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  open_how how{};
  how.flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW;
  how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |
                RESOLVE_NO_XDEV;
  unique_fd actual(static_cast<int>(syscall(
      SYS_openat2, mount.get(), relative.c_str() + 1, &how, sizeof(how))));
  LaunchObjectIdentity location;
  if (actual < 0 || !directory(actual.get(), location) || location != scope)
    return "not in captured work scope";
  bool contained = false;
  for (size_t depth = 0; depth < 16; ++depth) {
    unique_fd parent(openat(actual.get(), "..",
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    LaunchObjectIdentity next;
    if (parent < 0 || !directory(parent.get(), next) ||
        next.device != scope.device || next == location)
      return "work aggregate ancestry";
    if (next == aggregate) {
      contained = true;
      break;
    }
    actual = std::move(parent);
    location = next;
  }
  if (!contained) return "work ancestry bound";
  if (!protected_file(aggregate_fd, "memory.max", kMemoryLimit) ||
      !protected_file(aggregate_fd, "memory.swap.max", 0) ||
      !protected_file(aggregate_fd, "memory.oom.group", 1))
    return "protected aggregate limits";
  unique_fd ancestor(openat(aggregate_fd, "..",
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  unique_fd migration(openat(ancestor.get(), "cgroup.procs",
                             O_WRONLY | O_CLOEXEC | O_NOFOLLOW));
  if (ancestor < 0 || migration >= 0 || errno != EACCES)
    return "migration above aggregate is not protected";
  return {};
}
std::string CheckOwnerEntry() {
  auto error = identity_and_limits("u:r:andrix_owner:s0");
  if (!error.empty()) return error;
  if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
      prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != 2)
    return "inherited owner syscall profile missing";
  return {};
}
bool ManagementDescriptorsClosed(int description) {
  DIR* directory = opendir("/proc/self/fd");
  if (!directory) return false;
  bool valid = true;
  for (;;) {
    errno = 0;
    auto* entry = readdir(directory);
    if (!entry) {
      if (errno) valid = false;
      break;
    }
    if (entry->d_name[0] == '.') continue;
    int fd = -1;
    const char* end = entry->d_name + strlen(entry->d_name);
    auto parsed = std::from_chars(entry->d_name, end, fd);
    if (parsed.ec != std::errc{} || parsed.ptr != end || fd < 0 ||
        (fd > 2 && fd != description && fd != dirfd(directory)))
      valid = false;
  }
  if (closedir(directory)) valid = false;
  return valid;
}
}  // namespace andrix
