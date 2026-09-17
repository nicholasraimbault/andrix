// SPDX-License-Identifier: Apache-2.0
#include "common.h"

#include <android-base/logging.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <selinux/selinux.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <ctime>
#include <utility>

#include "guards.h"

namespace andrix::factory_proof {
using android::base::unique_fd;
uint64_t now_ms() {
  timespec t{};
  if (clock_gettime(CLOCK_MONOTONIC, &t)) _exit(125);
  return uint64_t(t.tv_sec) * 1000 + uint64_t(t.tv_nsec) / 1000000;
}
[[noreturn]] void fail(const std::string& message) {
  LOG(ERROR) << "Factory proof refused: " << message;
  _exit(126);
}
uint64_t random_id() {
  uint64_t value;
  if (getrandom(&value, sizeof(value), 0) != sizeof(value)) fail("entropy");
  return (value & ((uint64_t{1} << 62) - 1)) + 1;
}
bool parse_id(const char* text, uint64_t* out) {
  if (!text || !*text) return false;
  uint64_t value = 0;
  for (const char* p = text; *p; ++p) {
    if (*p < '0' || *p > '9' ||
        value > ((uint64_t{1} << 62) - uint64_t(*p - '0')) / 10)
      return false;
    value = value * 10 + uint64_t(*p - '0');
  }
  if (!value || value > (uint64_t{1} << 62)) return false;
  *out = value;
  return true;
}
std::string read_small(const std::string& path) {
  unique_fd fd(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  if (fd < 0) return {};
  char data[4097];
  ssize_t n = read(fd, data, sizeof(data));
  if (n < 0 || n >= ssize_t(sizeof(data))) return {};
  return std::string(data, size_t(n));
}
std::string role() {
  auto value = read_small("/proc/self/attr/current");
  while (!value.empty() && (value.back() == '\n' || value.back() == 0))
    value.pop_back();
  return value;
}
std::string current_group() {
  auto text = read_small("/proc/self/cgroup");
  std::string selected;
  size_t begin = 0;
  while (begin < text.size()) {
    auto end = text.find('\n', begin);
    if (end == std::string::npos) end = text.size();
    auto line = text.substr(begin, end - begin);
    begin = end + 1;
    if (line.starts_with("0::")) {
      if (!selected.empty()) return {};
      selected = "/sys/fs/cgroup" + line.substr(3);
    }
  }
  if (!selected.starts_with(std::string(kUidGroup) + "/pid_") ||
      selected.find("..") != std::string::npos)
    return {};
  return selected;
}
unique_fd open_group(const std::string& group) {
  unique_fd fd(
      open(group.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  struct statfs fs{};
  if (fd < 0 || fstatfs(fd, &fs) || fs.f_type != CGROUP2_SUPER_MAGIC) return {};
  return fd;
}
bool write_control(int directory, const char* name, const std::string& value) {
  unique_fd fd(openat(directory, name, O_WRONLY | O_CLOEXEC | O_NOFOLLOW));
  return fd >= 0 &&
         write(fd, value.data(), value.size()) == ssize_t(value.size());
}
bool populated(int directory) {
  unique_fd fd(
      openat(directory, "cgroup.events", O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  if (fd < 0) return true;
  char bytes[128];
  auto n = read(fd, bytes, sizeof(bytes));
  return n <= 0 || std::string(bytes, size_t(n)).find("populated 0\n") ==
                       std::string::npos;
}
std::string bounds_error(const std::string& group, bool worker) {
  struct statfs filesystem {};
  if (group.empty() || current_group() != group ||
      statfs(group.c_str(), &filesystem) || filesystem.f_type != CGROUP2_SUPER_MAGIC)
    return "actual group membership";
  if (auto error = andrix::check_identity(); !error.empty()) return error;
  if (role() != (worker ? "u:r:andrix_owner:s0" : "u:r:andrixd:s0"))
    return "actual MAC role";
  for (auto [resource, value] : {std::pair{RLIMIT_NPROC, rlim_t(32)},
                                 {RLIMIT_NOFILE, rlim_t(128)},
                                 {RLIMIT_CORE, rlim_t(0)},
                                 {RLIMIT_FSIZE, rlim_t(67108864)}}) {
    rlimit limit{};
    if (getrlimit(resource, &limit) || limit.rlim_cur != value ||
        limit.rlim_max != value)
      return "inherited rlimits";
  }
  errno = 0;
  int nice = getpriority(PRIO_PROCESS, getpid());
  if (errno || nice < 10) return "background priority";
  if (read_small("/proc/self/oom_score_adj") != "700\n") return "OOM priority";
  for (const std::string path : {std::string(kUidGroup), group}) {
    for (auto [file, value] : {std::pair{"memory.max", kMemory},
                               {"memory.swap.max", uint64_t(0)},
                               {"memory.oom.group", uint64_t(1)}}) {
      const std::string full = path + "/" + file;
      struct stat st{};
      if (lstat(full.c_str(), &st) || (st.st_mode & S_IWOTH) ||
          (st.st_uid != 0 && st.st_uid != 1000 && st.st_uid != 7500) ||
          read_small(full) != std::to_string(value) + "\n")
        return "verified memory bounds";
      if (path == kUidGroup && ((st.st_uid != 0 && st.st_uid != 1000) ||
                                (st.st_gid != 0 && st.st_gid != 1000)))
        return "protected aggregate owner";
      if (worker) {
        unique_fd denied(open(full.c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW));
        if (denied >= 0 || (errno != EACCES && errno != EPERM))
          return "worker memory write authority";
      }
    }
  }
  // No writable migration through the owner UID's ancestor, even for the
  // trusted manager. A's per-manager subtree is deliberately delegated.
  for (auto parent : {"/sys/fs/cgroup", "/sys/fs/cgroup/system", kUidGroup}) {
    const std::string file = std::string(parent) + "/cgroup.procs";
    struct stat st{};
    if (lstat(file.c_str(), &st) || (st.st_uid != 0 && st.st_uid != 1000) ||
        (st.st_gid != 0 && st.st_gid != 1000) || (st.st_mode & S_IWOTH))
      return "protected migration ancestor";
  }
  return {};
}
void labelled_channel(int pair[2]) {
  if (setsockcreatecon(kSocketLabel)) fail("channel label");
  const int result =
      socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair);
  if (setsockcreatecon(nullptr)) fail("channel label reset");
  if (result) fail("channel creation");
}
unique_fd manager_socket(uint64_t manager, bool listener) {
  unique_fd fd(
      socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  const std::string name = "andrix.factory." + std::to_string(manager);
  if (fd < 0 || name.size() + 1 >= sizeof(address.sun_path)) return {};
  memcpy(address.sun_path + 1, name.data(), name.size());
  const socklen_t length = offsetof(sockaddr_un, sun_path) + 1 + name.size();
  if (listener) {
    if (bind(fd, reinterpret_cast<sockaddr*>(&address), length) ||
        listen(fd, 8))
      return {};
  } else if (connect(fd, reinterpret_cast<sockaddr*>(&address), length))
    return {};
  return fd;
}
bool peer_is_coordinator(int fd, pid_t* pid) {
  ucred peer{};
  socklen_t size = sizeof(peer);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) ||
      size != sizeof(peer) || peer.uid != 7500 || peer.gid != 7500 ||
      peer.pid <= 1)
    return false;
  char context[128]{};
  size = sizeof(context);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERSEC, context, &size) ||
      size >= sizeof(context))
    return false;
  if (std::string(context, strnlen(context, size)) != "u:r:andrixd:s0")
    return false;
  *pid = peer.pid;
  return true;
}
bool send_packet(int fd, const Packet& packet) {
  return send(fd, &packet, sizeof(packet), MSG_NOSIGNAL | MSG_DONTWAIT) ==
         sizeof(packet);
}
bool receive_packet(int fd, Packet* packet) {
  const auto n = recv(fd, packet, sizeof(*packet), MSG_DONTWAIT | MSG_TRUNC);
  return n == sizeof(*packet) && packet->magic == kMagic;
}
}  // namespace andrix::factory_proof
