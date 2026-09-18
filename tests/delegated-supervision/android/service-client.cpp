// SPDX-License-Identifier: Apache-2.0
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>
#include <fcntl.h>
#include <poll.h>
#include <selinux/selinux.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>

#include "../../work-factory/group_observation.h"
#include "cleanup_worker.h"
#include "probe-wire.h"

using namespace andrix::delegated_probe;
using android::base::unique_fd;
namespace {
constexpr char kService[] = "andrix-delegated-proof";
[[noreturn]] void fail(const std::string& reason) {
  std::cerr << "DELEGATED_PROOF_FAILED " << reason << '\n';
  exit(1);
}
void require(bool ok, const std::string& reason) {
  if (!ok) fail(reason);
}
uint64_t now() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}
void until(const std::function<bool()>& condition, const std::string& reason,
           int seconds = 20) {
  auto end = now() + seconds * 1000;
  while (now() < end) {
    if (condition()) return;
    usleep(50000);
  }
  fail(reason);
}
std::string read(const std::string& path) {
  unique_fd fd(open(path.c_str(), O_RDONLY | O_CLOEXEC));
  if (fd < 0) return {};
  char data[4096];
  auto n = ::read(fd.get(), data, sizeof(data));
  return n > 0 ? std::string(data, static_cast<size_t>(n)) : "";
}
std::string prop(const char* name) {
  return android::base::GetProperty(name, "");
}
void control(const char* command, const std::string& reference = "") {
  static uint64_t sequence = now() * 1024;
  const auto ticket = std::to_string(++sequence);
  require(android::base::SetProperty("sys.andrix.delegated.sequence", ticket),
          "fresh command ticket");
  require(android::base::SetProperty("sys.andrix.delegated.ref", reference),
          "set exact reference");
  require(android::base::SetProperty("sys.andrix.delegated.command", ""),
          "reset fixed command");
  require(android::base::SetProperty("sys.andrix.delegated.command", command),
          "fixed platform command");
  until([&] { return prop("sys.andrix.delegated.ack") == ticket; },
        "fresh init command processing acknowledgement");
}
struct State {
  std::string ref, phase;
  pid_t worker = 0;
};
State scope_state() {
  auto value =
      android::base::GetProperty(std::string("init.svc_scope.") + kService, "");
  auto a = value.find(':'), b = value.find(':', a + 1);
  if (a == std::string::npos || b == std::string::npos) return {};
  int pid = 0;
  auto parsed =
      std::from_chars(value.data() + b + 1, value.data() + value.size(), pid);
  if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size())
    return {};
  return {value.substr(0, a), value.substr(a + 1, b - a - 1), pid};
}
bool ids(const std::string& ref, uint64_t& boot, uint64_t& instance) {
  auto at = ref.find('.');
  if (at == std::string::npos) return false;
  auto x = std::from_chars(ref.data(), ref.data() + at, boot);
  auto y =
      std::from_chars(ref.data() + at + 1, ref.data() + ref.size(), instance);
  return x.ec == std::errc{} && y.ec == std::errc{} &&
         x.ptr == ref.data() + at && y.ptr == ref.data() + ref.size() && boot &&
         instance;
}
bool endpoint_ready(const std::string& key) {
  unique_fd fd(socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0));
  if (fd < 0) return false;
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  auto name = "andrix.delegated-proof." + key;
  if (name.size() + 1 >= sizeof(address.sun_path)) return false;
  memcpy(address.sun_path + 1, name.data(), name.size());
  return connect(fd.get(), reinterpret_cast<sockaddr*>(&address),
                 static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 +
                                        name.size())) == 0;
}
Packet rpc(const std::string& key, Operation operation) {
  until([&] { return endpoint_ready(key); }, "fresh probe endpoint readiness");
  unique_fd fd(socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0));
  require(fd >= 0, "client socket");
  timeval deadline{3, 0};
  setsockopt(fd.get(), SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline));
  setsockopt(fd.get(), SOL_SOCKET, SO_SNDTIMEO, &deadline, sizeof(deadline));
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  auto name = "andrix.delegated-proof." + key;
  require(name.size() + 1 < sizeof(address.sun_path), "bounded name");
  memcpy(address.sun_path + 1, name.data(), name.size());
  require(!connect(fd.get(), reinterpret_cast<sockaddr*>(&address),
                   static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 +
                                          name.size())),
          "live declared probe endpoint");
  ucred peer{};
  socklen_t size = sizeof(peer);
  char* sid = nullptr;
  require(!getsockopt(fd.get(), SOL_SOCKET, SO_PEERCRED, &peer, &size) &&
              peer.uid == 7500 && peer.gid == 7500 && peer.pid > 1 &&
              !getpeercon(fd.get(), &sid) && sid,
          "actual probe credentials");
  bool role = std::string_view(sid) == "u:r:andrixd:s0";
  freecon(sid);
  require(role, "actual probe SID");
  Packet request;
  request.operation = operation;
  if (key != "peer")
    require(ids(key, request.boot, request.instance), "instance reference");
  require(send(fd.get(), &request, sizeof(request), MSG_NOSIGNAL) ==
              static_cast<ssize_t>(sizeof(request)),
          "request sent");
  Packet reply;
  require(recv(fd.get(), &reply, sizeof(reply), MSG_TRUNC) ==
                  static_cast<ssize_t>(sizeof(reply)) &&
              reply.magic == kMagic && reply.boot == request.boot &&
              reply.instance == request.instance &&
              reply.operation == operation && reply.pid == peer.pid,
          "exact reply");
  require(memchr(reply.group, 0, sizeof(reply.group)), "bounded group reply");
  return reply;
}
void emit(const char* event, const std::string& reference, const Packet& p) {
  std::cout << "{\"event\":\"" << event << "\",\"reference\":\"" << reference
            << "\",\"pid\":" << p.pid << ",\"children\":[" << p.children[0]
            << ',' << p.children[1] << "],\"pulses\":[" << p.pulses[0] << ','
            << p.pulses[1] << "],\"requests\":" << p.requests << ",\"group\":\""
            << p.group << "\",\"root_device\":" << p.root_device
            << ",\"root_inode\":" << p.root_inode
            << ",\"aggregate_write_errno\":" << p.aggregate_write_errno
            << ",\"ancestor_write_errno\":" << p.ancestor_write_errno << "}\n"
            << std::flush;
}
unique_fd pidfd(pid_t pid) {
  unique_fd fd(static_cast<int>(syscall(SYS_pidfd_open, pid, 0)));
  require(fd >= 0, "capture live process identity");
  return fd;
}
bool dead(int fd) {
  pollfd value{fd, POLLIN, 0};
  return poll(&value, 1, 0) == 1;
}
int signal_spawn_control(bool invalid_defaults) {
  posix_spawnattr_t attributes;
  require(!posix_spawnattr_init(&attributes), "spawn control attributes");
  sigset_t mask, defaults;
  require(!andrix::supervision::ConfigureWorkerSignalMasks(mask, defaults),
          "fixed spawn signals");
  if (invalid_defaults)
    require(!sigfillset(&defaults), "negative signal control");
  require(
      !posix_spawnattr_setsigmask(&attributes, &mask) &&
          !posix_spawnattr_setsigdefault(&attributes, &defaults) &&
          !posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT |
                                                     POSIX_SPAWN_SETSIGMASK |
                                                     POSIX_SPAWN_SETSIGDEF),
      "spawn control profile");
  const char* arguments[] = {"/system/bin/true", nullptr};
  char* environment[] = {nullptr};
  pid_t child = 0;
  const int spawned =
      posix_spawn(&child, arguments[0], nullptr, &attributes,
                  const_cast<char* const*>(arguments), environment);
  posix_spawnattr_destroy(&attributes);
  require(!spawned && child > 1, "fixed nonprivileged spawn control");
  auto identity = pidfd(child);
  pollfd wait{identity.get(), POLLIN, 0};
  const int ready = TEMP_FAILURE_RETRY(poll(&wait, 1, 5000));
  if (ready != 1)
    syscall(SYS_pidfd_send_signal, identity.get(), SIGKILL, nullptr, 0);
  int status = 0;
  require(TEMP_FAILURE_RETRY(waitpid(child, &status, 0)) == child &&
              ready == 1 && WIFEXITED(status),
          "exact spawn control wait");
  return WEXITSTATUS(status);
}
char state(pid_t pid) {
  auto stat = read("/proc/" + std::to_string(pid) + "/stat");
  auto at = stat.rfind(')');
  return at != std::string::npos && at + 2 < stat.size() ? stat[at + 2] : '?';
}
}  // namespace
int main(int argc, char** argv) {
  android::base::InitLogging(argv,
                             android::base::LogdLogger(android::base::SYSTEM));
  char* sid = nullptr;
  require(getuid() == 2000 && !getcon(&sid) && sid, "actual Shell client");
  bool shell = std::string_view(sid) == "u:r:shell:s0";
  freecon(sid);
  require(shell, "Shell MAC role");
  require(argc == 2 && std::string_view(argv[1]) == "exercise",
          "fixed exercise command");
  require(signal_spawn_control(false) == 0, "Bionic valid signal baseline");
  require(signal_spawn_control(true) == 127,
          "Bionic rejects uncatchable signal reset");
  require(signal_spawn_control(false) == 0, "Bionic valid signal recovery");
  std::cout
      << R"({"event":"signal_controls","valid_exit":0,"invalid_exit":127})"
      << '\n'
      << std::flush;
  control("peer-start");
  until([] { return prop("init.svc.andrix-delegated-peer") == "running"; },
        "ordinary peer start");
  usleep(100000);
  auto peer = rpc("peer", Inspect);
  emit("peer_live", "peer", peer);
  control("start");
  until([] { return scope_state().phase == "active"; },
        "complete delegated profile readiness");
  auto first = scope_state();
  require(first.worker > 1, "owned cleanup process");
  auto info = rpc(first.ref, Inspect);
  emit("active", first.ref, info);
  require(info.aggregate_write_errno == EACCES &&
              info.ancestor_write_errno == EACCES,
          "protected resource/migration boundaries");
  auto held = rpc(first.ref, Populate);
  emit("held", first.ref, held);
  require(held.children[0] > 1 && held.children[1] > 1 && held.pulses[0] == 0 &&
              held.pulses[1] == 0,
          "two held fixed descendants");
  unique_fd manager = pidfd(held.pid), a = pidfd(held.children[0]),
            b = pidfd(held.children[1]);
  unique_fd directory(
      open(held.group, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  require(directory >= 0, "capture actual group");
  andrix::factory_proof::GroupObservation old_group(directory.get());
  rpc(first.ref, Release);
  until(
      [&] {
        auto p = rpc(first.ref, Inspect);
        return p.pulses[0] > 2 && p.pulses[1] > 2;
      },
      "actual descendant execution");
  auto released = rpc(first.ref, Inspect);
  emit("released", first.ref, released);
  require(old_group.read() == andrix::factory_proof::GroupPopulation::Populated,
          "captured nested population");
  control("pause-worker", first.ref);
  until([&] { return state(first.worker) == 'T'; },
        "actual stopped cleanup worker");
  rpc(first.ref, Exit);
  until([&] { return dead(manager.get()); }, "initial service process exit");
  require(
      !dead(a.get()) && !dead(b.get()) &&
          old_group.read() == andrix::factory_proof::GroupPopulation::Populated,
      "detached descendants survive manager exit while cleanup paused");
  until(
      [&] {
        return scope_state().ref == first.ref &&
               scope_state().phase == "blocked";
      },
      "visible cleanup deadline without retirement", 15);
  auto pulse_before =
      read("/proc/" + std::to_string(held.children[0]) + "/comm");
  control("peer-stop");
  until([] { return prop("init.svc.andrix-delegated-peer") == "stopped"; },
        "unrelated init Stop progresses");
  control("peer-start");
  until([] { return prop("init.svc.andrix-delegated-peer") == "running"; },
        "unrelated init Start progresses");
  usleep(100000);
  auto peer_after = rpc("peer", Inspect);
  emit("peer_after_restart", "peer", peer_after);
  require(peer_after.pid != peer.pid, "ordinary service genuinely restarted");
  control("start");
  usleep(200000);
  require(scope_state().ref == first.ref && !dead(a.get()) && !dead(b.get()),
          "start fenced during old cleanup");
  auto pulse_after =
      read("/proc/" + std::to_string(held.children[0]) + "/comm");
  require(pulse_after != pulse_before,
          "live detached process progressed while init handled control");
  control("stop-exact", first.ref);
  usleep(100000);
  control("resume-worker", first.ref);
  until(
      [&] {
        return dead(a.get()) && dead(b.get()) &&
               old_group.read() ==
                   andrix::factory_proof::GroupPopulation::Removed;
      },
      "recursive task kill and actual tree reclamation");
  until(
      [&] {
        return scope_state().ref == first.ref &&
               scope_state().phase == "retired";
      },
      "worker and scope retirement before restart");
  std::cout << "{\"event\":\"old_retired\",\"reference\":\"" << first.ref
            << "\"}\n"
            << std::flush;
  control("start");
  until(
      [&] {
        return scope_state().phase == "active" &&
               scope_state().ref != first.ref;
      },
      "fresh exact service instance");
  auto fresh = scope_state();
  auto clean = rpc(fresh.ref, Inspect);
  emit("fresh", fresh.ref, clean);
  require(clean.children[0] == 0 && clean.children[1] == 0,
          "no restored ordinary jobs");
  auto fresh_manager = pidfd(clean.pid);
  control("stop-exact", first.ref);
  usleep(200000);
  require(!dead(fresh_manager.get()) && scope_state().ref == fresh.ref,
          "stale reference cannot stop replacement");
  auto before = scope_state();
  auto old_worker = pidfd(before.worker);
  control("crash-worker", fresh.ref);
  until(
      [&] {
        auto s = scope_state();
        return dead(old_worker.get()) && s.ref == fresh.ref &&
               s.phase == "active" && s.worker > 1 && s.worker != before.worker;
      },
      "dead cleanup worker recovered without replacing active service");
  require(!dead(fresh_manager.get()),
          "manager survives internal worker recovery");
  emit("worker_recovered", fresh.ref, rpc(fresh.ref, Inspect));
  auto last = rpc(fresh.ref, Populate);
  rpc(fresh.ref, Release);
  until([&] { return rpc(fresh.ref, Inspect).pulses[0] > 1; },
        "fresh useful work after recovery");
  unique_fd last_a = pidfd(last.children[0]), last_b = pidfd(last.children[1]);
  control("memory-kill", fresh.ref);
  until(
      [&] {
        return dead(fresh_manager.get()) && dead(last_a.get()) &&
               dead(last_b.get());
      },
      "memory supervisor killed exact captured scope");
  until(
      [&] {
        return scope_state().phase == "active" &&
               scope_state().ref != fresh.ref;
      },
      "memory kill cleanup followed by fresh empty service");
  auto recovered = scope_state();
  auto empty = rpc(recovered.ref, Inspect);
  emit("memory_recovered", recovered.ref, empty);
  require(empty.children[0] == 0 && empty.children[1] == 0,
          "memory recovery does not restore jobs");
  control("stop-exact", recovered.ref);
  until(
      [&] {
        return scope_state().ref == recovered.ref &&
               scope_state().phase == "retired";
      },
      "final exact service Stop");
  emit("peer_final", "peer", rpc("peer", Inspect));
  control("peer-stop");
  until([] { return prop("init.svc.andrix-delegated-peer") == "stopped"; },
        "final ordinary cleanup");
  std::cout << "DELEGATED_SERVICE_PROOF_COMPLETE\n";
  return 0;
}
