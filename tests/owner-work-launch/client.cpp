// SPDX-License-Identifier: Apache-2.0
#include <android-base/unique_fd.h>
#include <poll.h>
#include <selinux/selinux.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "launch_description.h"
#include "wire.h"

using android::base::unique_fd;
namespace proof = andrix::work_probe;
namespace {
[[noreturn]] void fail(const char* why) {
  dprintf(2, "work launch client: %s\n", why);
  _exit(1);
}
uint64_t number(std::string_view value) {
  uint64_t result = 0;
  auto p = std::from_chars(value.data(), value.data() + value.size(), result);
  if (value.empty() || p.ec != std::errc{} ||
      p.ptr != value.data() + value.size())
    fail("invalid integer");
  return result;
}
std::string quote(std::string_view text) {
  std::string out = "\"";
  for (unsigned char c : text) {
    if (c == '"' || c == '\\') {
      out += '\\';
      out += c;
    } else if (c < 32 || c >= 127) {
      char escaped[7];
      snprintf(escaped, sizeof(escaped), "\\u%04x", c);
      out += escaped;
    } else
      out += c;
  }
  return out + '"';
}
}  // namespace
int main(int argc, char** argv) {
  if (argc < 4 || getuid() != 2000 || getgid() != 2000)
    fail(
        "requires Shell: BOOT.INSTANCE.MANAGER operation slot [flags cwd "
        "executable env-count ENV... -- ARG0 ARG...]");
  proof::Command command;
  std::string_view ref(argv[1]);
  auto dot = ref.find('.'),
       next = ref.find('.', dot == ref.npos ? dot : dot + 1);
  if (dot == ref.npos || next == ref.npos)
    fail("complete service/manager reference");
  command.boot = number(ref.substr(0, dot));
  command.instance = number(ref.substr(dot + 1, next - dot - 1));
  command.manager = number(ref.substr(next + 1));
  uint64_t slot = number(argv[3]);
  if (slot > 1) fail("two-slot vehicle");
  command.slot = slot;
  std::string_view operation(argv[2]);
  std::vector<uint8_t> body;
  if (operation == "inspect")
    command.operation = proof::Operation::Inspect;
  else if (operation == "stop")
    command.operation = proof::Operation::Stop;
  else if (operation == "release")
    command.operation = proof::Operation::Release;
  else if (operation == "continue")
    command.operation = proof::Operation::ContinueCreation;
  else if (operation == "exit-manager")
    command.operation = proof::Operation::ExitManager;
  else if (operation == "start") {
    command.operation = proof::Operation::Start;
    if (argc < 10) fail("complete ordinary launch arguments");
    uint64_t flags = number(argv[4]), env_count = number(argv[7]);
    if (flags > 7 || env_count > 1024 ||
        env_count > static_cast<uint64_t>(argc - 10))
      fail("launch bounds");
    command.flags = flags;
    andrix::LaunchDescription launch;
    launch.directory = argv[5];
    launch.executable = argv[6];
    int at = 8;
    for (uint64_t i = 0; i < env_count; ++i)
      launch.environment.emplace_back(argv[at++]);
    if (at >= argc || strcmp(argv[at++], "--")) fail("explicit argv boundary");
    while (at < argc) launch.arguments.emplace_back(argv[at++]);
    andrix::LaunchFailure error;
    if (!andrix::EncodeLaunch(launch, {}, body, error) ||
        body.size() > proof::kBody)
      fail("bounded ordinary launch description");
    command.bytes = body.size();
  } else
    fail("operation");
  if (command.operation != proof::Operation::Start && argc != 4)
    fail("unexpected arguments");
  if (command.operation != proof::Operation::Inspect && !command.manager)
    fail("inspect first, then use exact manager reference");
  unique_fd fd(socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0));
  if (fd < 0) fail("socket");
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  auto name = "andrix.work-launch-proof." + std::to_string(command.boot) + "." +
              std::to_string(command.instance);
  if (name.size() + 1 >= sizeof(address.sun_path)) fail("socket name");
  memcpy(address.sun_path + 1, name.data(), name.size());
  if (connect(fd.get(), reinterpret_cast<sockaddr*>(&address),
              offsetof(sockaddr_un, sun_path) + 1 + name.size()))
    fail("connect");
  ucred actual{};
  socklen_t size = sizeof(actual);
  char* context = nullptr;
  bool peer = !getsockopt(fd.get(), SOL_SOCKET, SO_PEERCRED, &actual, &size) &&
              size == sizeof(actual) && actual.uid == 7500 &&
              actual.gid == 7500 && actual.pid > 1 &&
              !getpeercon(fd.get(), &context) && context &&
              std::string_view(context) == "u:r:andrixd:s0";
  if (context) freecon(context);
  if (!peer) fail("actual coordinator peer");
  std::vector<uint8_t> wire(sizeof(command) + body.size());
  memcpy(wire.data(), &command, sizeof(command));
  if (!body.empty())
    memcpy(wire.data() + sizeof(command), body.data(), body.size());
  if (send(fd.get(), wire.data(), wire.size(), MSG_NOSIGNAL) !=
      static_cast<ssize_t>(wire.size()))
    fail("request send");
  pollfd wait{fd.get(), POLLIN, 0};
  if (poll(&wait, 1, 5000) != 1) fail("response deadline");
  proof::Snapshot state;
  if (recv(fd.get(), &state, sizeof(state), MSG_TRUNC) != sizeof(state) ||
      state.magic != proof::kMagic || state.boot != command.boot ||
      state.instance != command.instance ||
      (command.manager && state.manager != command.manager) ||
      state.serial != command.slot + 1 ||
      strnlen(state.output, sizeof(state.output)) >= sizeof(state.output))
    fail("exact response");
  printf(
      "{\"reference\":\"%llu.%llu.%llu\",\"slot\":%u,\"serial\":%llu,\"error\":"
      "%d,\"platform\":%llu,\"generation\":%llu,\"device\":%llu,\"inode\":%llu,"
      "\"pid\":%d,\"started\":%u,\"creator_pending\":%u,\"staged\":%u,"
      "\"queued\":%u,\"committed\":%u,\"stopped\":%u,\"reaped\":%u,\"no_"
      "process\":%u,\"empty\":%u,\"retired\":%u,\"blocked\":%u,\"gate_"
      "refused\":%u,\"authority_failed\":%u,\"exit_code\":%d,\"launch_error\":%"
      "d,\"cleanup_error\":%d,\"output_bytes\":%llu,\"manager_pid\":%d,"
      "\"authority_ready\":%u,\"output\":%s}\n",
      (unsigned long long)state.boot, (unsigned long long)state.instance,
      (unsigned long long)state.manager, command.slot,
      (unsigned long long)state.serial, state.error,
      (unsigned long long)state.platform, (unsigned long long)state.generation,
      (unsigned long long)state.device, (unsigned long long)state.inode,
      state.pid, state.started, state.creator_pending, state.staged,
      state.queued, state.committed, state.stopped, state.reaped,
      state.no_process, state.empty, state.retired, state.blocked,
      state.gate_refused, state.authority_failed, state.exit_code,
      state.launch_error, state.cleanup_error,
      (unsigned long long)state.output_bytes, actual.pid, state.authority_ready,
      quote(state.output).c_str());
  return state.error ? 1 : 0;
}
