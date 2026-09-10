// SPDX-License-Identifier: Apache-2.0
#include "guards.h"
#include "session_core.h"

#include <fcntl.h>
#include <linux/fscrypt.h>
#include <linux/magic.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>

namespace andrix {
namespace {

bool number(std::string_view text, uint64_t* value) {
  while (!text.empty() && (text.back() == '\n' || text.back() == ' ')) text.remove_suffix(1);
  auto result = std::from_chars(text.data(), text.data() + text.size(), *value);
  return !text.empty() && result.ec == std::errc{} && result.ptr == text.data() + text.size();
}

bool read_small(const std::string& path, std::string* data, bool immutable = false) {
  int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return false;
  struct stat st{};
  bool ok = fstat(fd, &st) == 0;
  if (immutable) {
    // The owner must not own or be in the group controlling these kernel bounds.
    ok = ok && S_ISREG(st.st_mode) && (st.st_uid == 0 || st.st_uid == 1000) &&
         (st.st_gid == 0 || st.st_gid == 1000) && !(st.st_mode & S_IWOTH) &&
         access(path.c_str(), W_OK) != 0;
  }
  std::array<char, 8193> bytes{};
  ssize_t length = ok ? read(fd, bytes.data(), bytes.size()) : -1;
  if (length < 0 || length == static_cast<ssize_t>(bytes.size())) ok = false;
  if (ok) data->assign(bytes.data(), static_cast<size_t>(length));
  close(fd);
  return ok;
}

int open_existing_home() {
  // O_PATH lets us traverse the search-only CE parent without giving the daemon
  // the misc group's access or reading the parent's other directory entries.
  int fd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0) return -1;
  for (const char* part : {"data", "misc_ce", "0", "andrix"}) {
    bool leaf = std::strcmp(part, "andrix") == 0;
    int next = openat(fd, part, (leaf ? O_RDONLY : O_PATH) | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    const int saved = errno;
    close(fd);
    if (next < 0) { errno = saved; return -1; }
    fd = next;
  }
  return fd;
}

}  // namespace

std::string check_identity() {
  if (getuid() != kOwnerUid || geteuid() != kOwnerUid || getgid() != kOwnerUid ||
      getegid() != kOwnerUid) return "wrong native owner identity";
  std::array<gid_t, 16> groups{};
  int count = getgroups(groups.size(), groups.data());
  if (count < 0) return "cannot inspect supplementary groups";
  for (int i = 0; i < count; ++i) {
    if (groups[i] != kOwnerUid && groups[i] != 3003) return "unexpected supplementary group";
  }
  std::string status;
  if (!read_small("/proc/self/status", &status)) return "cannot inspect capabilities";
  for (auto name : {"CapInh:\t", "CapPrm:\t", "CapEff:\t", "CapBnd:\t", "CapAmb:\t"}) {
    auto at = status.find(name);
    if (at == std::string::npos || status.substr(at + std::strlen(name), 16) != "0000000000000000")
      return "nonzero or missing capabilities";
  }
  return {};
}

std::string check_resource_bounds(pid_t coordinator) {
  if (coordinator == 0) coordinator = getpid();
  if (coordinator <= 1) return "invalid coordinator PID";
  struct rlimit limit{};
  if (getrlimit(RLIMIT_NPROC, &limit) != 0 || limit.rlim_max != kProcessLimit ||
      limit.rlim_cur > limit.rlim_max) return "process hard limit missing";
  if (getrlimit(RLIMIT_NOFILE, &limit) != 0 || limit.rlim_max != kDescriptorLimit ||
      limit.rlim_cur > limit.rlim_max) return "descriptor hard limit missing";
  errno = 0;
  // Binder may temporarily donate caller priority to a pool thread. Inspect the
  // process leader, not the currently executing transaction thread.
  int priority = getpriority(PRIO_PROCESS, getpid());
  if (errno || priority < 10) return "background nice floor missing";
  std::string text;
  uint64_t value = 0;
  if (!read_small("/proc/self/oom_score_adj", &text) || !number(text, &value) || value < 700)
    return "OOM priority floor missing";
  if (!read_small("/proc/self/cgroup", &text)) return "cannot inspect cgroup";
  const std::string relative = "/system/uid_" + std::to_string(kOwnerUid) + "/pid_" + std::to_string(coordinator);
  if (text.find("0::" + relative + "\n") == std::string::npos) return "not in init owner cgroup";
  const std::string path = "/sys/fs/cgroup" + relative;
  struct statfs filesystem{};
  if (statfs(path.c_str(), &filesystem) != 0 || filesystem.f_type != CGROUP2_SUPER_MAGIC)
    return "not a real cgroup2 filesystem";
  for (auto [file, expected] : {std::pair{"memory.max", kMemoryLimit},
                                {"memory.swap.max", uint64_t{0}}, {"memory.oom.group", uint64_t{1}}}) {
    if (!read_small(path + "/" + file, &text, true) || !number(text, &value) || value != expected)
      return std::string("immutable aggregate bound missing: ") + file;
  }
  // The unified hierarchy must not offer this UID a writable escape to its
  // ancestors. Other controller/DAC negative tests remain part of device proof.
  for (const auto& parent : {std::string("/sys/fs/cgroup"),
                            std::string("/sys/fs/cgroup/system"),
                            std::string("/sys/fs/cgroup/system/uid_") + std::to_string(kOwnerUid), path}) {
    if (!read_small(parent + "/cgroup.procs", &text, true))
      return "cgroup migration ownership is not protected";
  }
  return {};
}

bool ce_key_present(int home_fd, std::string* error) {
  fscrypt_get_policy_ex_arg policy{};
  policy.policy_size = sizeof(policy.policy);
  if (ioctl(home_fd, FS_IOC_GET_ENCRYPTION_POLICY_EX, &policy) != 0) {
    *error = std::string("cannot read home fscrypt policy: ") + std::strerror(errno);
    return false;
  }
  if (policy.policy.version != FSCRYPT_POLICY_V2 || policy.policy_size != sizeof(fscrypt_policy_v2)) {
    *error = "home lacks a supported fscrypt v2 policy";
    return false;
  }
  fscrypt_get_key_status_arg key{};
  key.key_spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
  std::memcpy(key.key_spec.u.identifier, policy.policy.v2.master_key_identifier, FSCRYPT_KEY_IDENTIFIER_SIZE);
  if (ioctl(home_fd, FS_IOC_GET_ENCRYPTION_KEY_STATUS, &key) != 0) {
    *error = std::string("cannot read CE key status: ") + std::strerror(errno);
    return false;
  }
  if (key.status != FSCRYPT_KEY_STATUS_PRESENT) {
    *error = "CE key is not present";
    return false;
  }
  return true;
}

int open_ce_home(std::string* error) {
  int fd = open_existing_home();
  if (fd < 0) {
    *error = std::string("existing CE home is inaccessible: ") + std::strerror(errno);
    return -1;
  }
  struct stat st{};
  if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != kOwnerUid ||
      st.st_gid != kOwnerUid || (st.st_mode & 07777) != 0700 || !ce_key_present(fd, error)) {
    if (error->empty()) *error = "CE home identity or mode mismatch";
    close(fd);
    return -1;
  }
  return fd;
}

}  // namespace andrix
