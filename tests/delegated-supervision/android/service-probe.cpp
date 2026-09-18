// SPDX-License-Identifier: Apache-2.0
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <poll.h>
#include <selinux/selinux.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>

#include "probe-wire.h"

using android::base::unique_fd;
using namespace andrix::delegated_probe;
namespace {
[[noreturn]] void fail(const char* reason) {
  LOG(ERROR) << "delegated service probe: " << reason;
  _exit(125);
}
void require(bool value, const char* reason) {
  if (!value) fail(reason);
}
std::string read_fd(int fd) {
  char bytes[4096];
  ssize_t n = read(fd, bytes, sizeof(bytes));
  if (n <= 0 || n == static_cast<ssize_t>(sizeof(bytes))) return {};
  std::string value(bytes, static_cast<size_t>(n));
  while (!value.empty() && (value.back() == '\n' || value.back() == 0))
    value.pop_back();
  return value;
}
std::string read_path(const std::string& path) {
  unique_fd fd(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  return fd < 0 ? "" : read_fd(fd.get());
}
std::string read_at(int directory, const char* name) {
  unique_fd fd(openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  return fd < 0 ? "" : read_fd(fd.get());
}
bool write_at(int directory, const char* name, const std::string& value) {
  unique_fd fd(openat(directory, name, O_WRONLY | O_CLOEXEC | O_NOFOLLOW));
  return fd >= 0 && write(fd.get(), value.data(), value.size()) ==
                        static_cast<ssize_t>(value.size());
}
std::string role() {
  char* context = nullptr;
  if (getcon(&context) || !context) return {};
  std::string value(context);
  freecon(context);
  return value;
}
bool reference(const std::string& value, uint64_t& boot, uint64_t& instance) {
  auto point = value.find('.');
  if (point == std::string::npos) return false;
  auto a = std::from_chars(value.data(), value.data() + point, boot);
  auto b = std::from_chars(value.data() + point + 1,
                           value.data() + value.size(), instance);
  return a.ec == std::errc{} && b.ec == std::errc{} &&
         a.ptr == value.data() + point &&
         b.ptr == value.data() + value.size() && boot && instance;
}
int inherited(const char* name) {
  const char* value = getenv(name);
  if (!value) return -1;
  int fd = -1;
  auto p = std::from_chars(value, value + strlen(value), fd);
  return p.ec == std::errc{} && *p.ptr == 0 && fd >= 3 && fd < 128 ? fd : -1;
}
std::string membership() {
  auto text = read_path("/proc/self/cgroup");
  size_t start = 0;
  std::string path;
  while (start < text.size()) {
    auto end = text.find('\n', start);
    if (end == std::string::npos) end = text.size();
    auto line = text.substr(start, end - start);
    start = end + 1;
    if (line.starts_with("0::")) {
      require(path.empty(), "duplicate unified group");
      path = line.substr(3);
    }
  }
  require(!path.empty() && path.front() == '/' &&
              path.find("..") == std::string::npos,
          "actual unified membership");
  return path;
}
void common_profile() {
  require(getuid() == 7500 && getgid() == 7500 && role() == "u:r:andrixd:s0",
          "actual service credentials");
  gid_t groups[4]{};
  require(getgroups(4, groups) == 1 && groups[0] == 3003,
          "supplementary groups");
  require(read_path("/proc/self/oom_score_adj") == "700",
          "actual memory priority");
  auto status = read_path("/proc/self/status");
  for (const char* field :
       {"CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"}) {
    auto at = status.find(field);
    require(at != std::string::npos, "capability field");
    auto end = status.find('\n', at);
    auto value = status.substr(at + strlen(field), end - at - strlen(field));
    for (char c : value)
      require(c == '0' || c == ' ' || c == '\t', "explicit zero capabilities");
  }
  for (auto [resource, bound] : {std::pair{RLIMIT_CORE, rlim_t(0)},
                                 {RLIMIT_NOFILE, rlim_t(128)},
                                 {RLIMIT_NPROC, rlim_t(32)},
                                 {RLIMIT_FSIZE, rlim_t(67108864)}}) {
    rlimit actual{};
    require(!getrlimit(resource, &actual) && actual.rlim_cur == bound &&
                actual.rlim_max == bound,
            "actual rlimit");
  }
  errno = 0;
  require(getpriority(PRIO_PROCESS, 0) == 10 && !errno, "actual scheduling");
}
unique_fd listener(const std::string& key) {
  unique_fd fd(
      socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
  require(fd >= 0, "observer socket");
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  std::string name = "andrix.delegated-proof." + key;
  require(name.size() + 1 < sizeof(address.sun_path), "socket name");
  memcpy(address.sun_path + 1, name.data(), name.size());
  require(!bind(fd.get(), reinterpret_cast<sockaddr*>(&address),
                static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 +
                                       name.size())) &&
              !listen(fd.get(), 4),
          "private listener");
  return fd;
}
bool peer(int fd) {
  ucred identity{};
  socklen_t size = sizeof(identity);
  char* context = nullptr;
  bool matched = !getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &identity, &size) &&
                 identity.uid == 2000 && identity.gid == 2000 &&
                 identity.pid > 1 && !getpeercon(fd, &context) && context &&
                 std::string_view(context) == "u:r:shell:s0";
  if (context) freecon(context);
  return matched;
}
void child_main(int channel, int number) {
  require(setsid() > 0, "detached session");
  signal(SIGHUP, SIG_IGN);
  signal(SIGTERM, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  alarm(240);
  for (int fd = 3; fd < 128; ++fd)
    if (fd != channel) close(fd);
  char byte = 'H';
  require(send(channel, &byte, 1, MSG_NOSIGNAL) == 1, "child held report");
  require(recv(channel, &byte, 1, 0) == 1 && byte == 'R', "fixed release gate");
  for (uint64_t n = 1;; ++n) {
    auto name = "d" + std::to_string(number) + "_" + std::to_string(n);
    prctl(PR_SET_NAME, name.c_str(), 0, 0, 0);
    send(channel, &n, sizeof(n), MSG_NOSIGNAL | MSG_DONTWAIT);
    usleep(100000);
  }
}
}  // namespace
int main(int argc, char** argv) {
  android::base::InitLogging(argv,
                             android::base::LogdLogger(android::base::SYSTEM));
  require(argc == 2, "fixed service mode");
  bool standalone = std::string_view(argv[1]) == "peer";
  require(standalone || std::string_view(argv[1]) == "serve",
          "fixed bootstrap only");
  common_profile();
  alarm(300);
  Packet state;
  state.pid = getpid();
  unique_fd root, ready;
  ReadyMessage ready_message;
  std::string key = "peer";
  if (!standalone) {
    require(getppid() == 1, "platform parent");
    const char* ref = getenv("ANDROID_DELEGATED_INSTANCE");
    require(ref && reference(ref, state.boot, state.instance),
            "instance binding");
    key = ref;
    root.reset(inherited("ANDROID_DELEGATED_ROOT_FD"));
    ready.reset(inherited("ANDROID_DELEGATED_READY_FD"));
    require(root >= 0 && ready >= 0, "declared handoff");
    fcntl(root.get(), F_SETFD, FD_CLOEXEC);
    fcntl(ready.get(), F_SETFD, FD_CLOEXEC);
    struct stat object{};
    struct statfs filesystem{};
    require(!fstat(root.get(), &object) && !fstatfs(root.get(), &filesystem) &&
                filesystem.f_type == CGROUP2_SUPER_MAGIC &&
                object.st_uid == 0 && object.st_gid == 0 &&
                (object.st_mode & 0777) == 0755,
            "captured protected root");
    state.root_device = object.st_dev;
    state.root_inode = object.st_ino;
    auto group = membership();
    auto suffix = "/system/init-scopes/instance_" +
                  std::to_string(state.instance) + "/control";
    require(group == suffix, "actual control membership");
    auto path = "/sys/fs/cgroup" + group.substr(0, group.size() - 8);
    require(path.size() < sizeof(state.group), "bounded group metadata");
    memcpy(state.group, path.c_str(), path.size() + 1);
    struct stat named{};
    require(!stat(path.c_str(), &named) && named.st_dev == object.st_dev &&
                named.st_ino == object.st_ino,
            "actual inherited scope identity");
    require(read_at(root.get(), "memory.max") == "268435456" &&
                read_at(root.get(), "memory.swap.max") == "0" &&
                read_at(root.get(), "memory.oom.group") == "1" &&
                read_at(root.get(), "cgroup.max.descendants") == "64" &&
                read_at(root.get(), "cgroup.max.depth") == "8",
            "complete aggregate bounds");
    int denied = openat(root.get(), "memory.max", O_WRONLY | O_CLOEXEC);
    state.aggregate_write_errno = denied < 0 ? errno : 0;
    if (denied >= 0) close(denied);
    require(state.aggregate_write_errno == EACCES, "aggregate protected");
    denied = open("/sys/fs/cgroup/system/init-scopes/cgroup.procs",
                  O_WRONLY | O_CLOEXEC);
    state.ancestor_write_errno = denied < 0 ? errno : 0;
    if (denied >= 0) close(denied);
    require(state.ancestor_write_errno == EACCES,
            "migration ancestor protected");
    ready_message.boot = state.boot;
    ready_message.instance = state.instance;
    ready_message.device = state.root_device;
    ready_message.inode = state.root_inode;
  }
  auto server = listener(key);
  if (!standalone) {
    require(send(ready.get(), &ready_message, sizeof(ready_message),
                 MSG_NOSIGNAL) == static_cast<ssize_t>(sizeof(ready_message)),
            "actual profile and endpoint readiness");
    ready.reset();
  }
  std::array<unique_fd, 2> channels;
  for (;;) {
    pollfd wait{server.get(), POLLIN, 0};
    poll(&wait, 1, 20);
    for (size_t n = 0; n < channels.size(); ++n)
      if (channels[n] >= 0) {
        uint64_t pulse = 0;
        while (recv(channels[n].get(), &pulse, sizeof(pulse), MSG_DONTWAIT) ==
               static_cast<ssize_t>(sizeof(pulse)))
          state.pulses[n] = pulse;
      }
    unique_fd client(accept4(server.get(), nullptr, nullptr, SOCK_CLOEXEC));
    if (client < 0) continue;
    if (!peer(client.get())) continue;
    timeval deadline{3, 0};
    setsockopt(client.get(), SOL_SOCKET, SO_RCVTIMEO, &deadline,
               sizeof(deadline));
    setsockopt(client.get(), SOL_SOCKET, SO_SNDTIMEO, &deadline,
               sizeof(deadline));
    Packet command;
    const auto count = recv(client.get(), &command, sizeof(command), MSG_TRUNC);
    if (count != static_cast<ssize_t>(sizeof(command)) ||
        command.magic != kMagic || command.boot != state.boot ||
        command.instance != state.instance)
      continue;
    ++state.requests;
    if (command.operation == Populate && !standalone &&
        state.children[0] == 0) {
      unique_fd work(openat(root.get(), "work",
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
      require(work >= 0, "delegated work directory");
      for (size_t n = 0; n < 2; ++n) {
        auto name = "fixed_" + std::to_string(n);
        require(!mkdirat(work.get(), name.c_str(), 0755),
                "fresh child directory");
        unique_fd leaf(openat(work.get(), name.c_str(),
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        require(leaf >= 0 && !fchmod(leaf.get(), 0755),
                "observable owned child");
        int pair[2];
        require(!socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair),
                "child channel");
        unique_fd parent(pair[0]), child(pair[1]);
        pid_t pid = fork();
        require(pid >= 0, "fixed child fork");
        if (!pid) {
          parent.reset();
          child_main(child.get(), static_cast<int>(n));
          _exit(127);
        }
        child.reset();
        char byte = 0;
        require(recv(parent.get(), &byte, 1, 0) == 1 && byte == 'H',
                "child remains held");
        require(write_at(leaf.get(), "cgroup.procs", std::to_string(pid)),
                "owned unreaped child placement");
        if (n == 0)
          require(!fchmod(leaf.get(), 0),
                  "empty retirement must reclaim directory access");
        state.children[n] = pid;
        channels[n] = std::move(parent);
      }
    } else if (command.operation == Release && !standalone && !state.released) {
      require(state.children[0] > 0 && state.children[1] > 0,
              "held children before release");
      char byte = 'R';
      for (auto& channel : channels)
        require(send(channel.get(), &byte, 1, MSG_NOSIGNAL) == 1,
                "release fixed payload");
      state.released = 1;
    } else
      require(command.operation == Inspect || command.operation == Exit ||
                  command.operation == Populate || command.operation == Release,
              "fixed observer command");
    state.operation = command.operation;
    require(send(client.get(), &state, sizeof(state), MSG_NOSIGNAL) ==
                static_cast<ssize_t>(sizeof(state)),
            "observer reply");
    if (command.operation == Exit) _exit(37);
  }
}
