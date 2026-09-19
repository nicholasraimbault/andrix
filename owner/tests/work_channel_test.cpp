// SPDX-License-Identifier: Apache-2.0
#include "work_channel.h"

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

using namespace andrix;
namespace {
size_t descriptor_count() {
  DIR* directory = opendir("/proc/self/fd");
  assert(directory);
  size_t count = 0;
  while (auto* item = readdir(directory))
    if (item->d_name[0] != '.') ++count;
  assert(closedir(directory) == 0);
  return count;
}
WorkFrameHeader header(uint64_t correlation = 1) {
  WorkFrameHeader result;
  result.operation = 1;
  result.correlation = correlation;
  return result;
}
void raw(int fd, const WorkFrameHeader& input, std::span<const uint8_t> body,
         std::span<const int> rights, bool empty = false) {
  iovec data[] = {{const_cast<WorkFrameHeader*>(&input), sizeof(input)},
                  {const_cast<uint8_t*>(body.data()), body.size()}};
  alignas(cmsghdr) char buffer[CMSG_SPACE(32 * sizeof(int))]{};
  msghdr message{};
  message.msg_iov = data;
  message.msg_iovlen = empty ? 0 : body.empty() ? 1 : 2;
  if (!rights.empty()) {
    message.msg_control = buffer;
    message.msg_controllen = CMSG_SPACE(rights.size_bytes());
    auto* control = CMSG_FIRSTHDR(&message);
    control->cmsg_level = SOL_SOCKET;
    control->cmsg_type = SCM_RIGHTS;
    control->cmsg_len = CMSG_LEN(rights.size_bytes());
    memcpy(CMSG_DATA(control), rights.data(), rights.size_bytes());
  }
  assert(sendmsg(fd, &message, MSG_NOSIGNAL) ==
         static_cast<ssize_t>(empty ? 0 : sizeof(input) + body.size()));
}
void expect_ready(int fd) {
  pollfd wait{fd, POLLIN, 0};
  assert(poll(&wait, 1, 5000) == 1);
}
void policy_units() {
  using Role = WorkPeerRole;
  using Side = WorkPeerSide;
  assert(MatchWorkPeerRole({2, 7500, 7500}, "u:r:andrix_owner:s0",
                           Side::Manager) == Role::Owner);
  assert(MatchWorkPeerRole({2, 7500, 7500}, "u:r:andrixd:s0", Side::Manager) ==
         Role::None);
  assert(MatchWorkPeerRole({2, 0, 0}, "u:r:andrix_owner:s0", Side::Manager) ==
         Role::None);
  assert(MatchWorkPeerRole({2, 7500, 3003}, "u:r:andrix_owner:s0",
                           Side::Manager) == Role::None);
  assert(MatchWorkPeerRole({2, 10001, 10001},
                           "u:r:andrix_terminal:s0:c512,c768",
                           Side::Manager) == Role::Console);
  assert(MatchWorkPeerRole({2, 110001, 110001},
                           "u:r:andrix_terminal:s0:c512,c768",
                           Side::Manager) == Role::None);
  assert(MatchWorkPeerRole({2, 10001, 10001}, "u:r:andrix_terminal:s00",
                           Side::Manager) == Role::None);
  assert(MatchWorkPeerRole({2, 10001, 10001}, "u:r:andrix_terminal:s0:",
                           Side::Manager) == Role::None);
  assert(MatchWorkPeerRole({0, 10001, 10001}, "u:r:andrix_terminal:s0",
                           Side::Manager) == Role::None);
  assert(MatchWorkPeerRole({1, 10001, 10001}, "u:r:andrix_terminal:s0",
                           Side::Manager) == Role::Console);
  assert(MatchWorkPeerRole({2, 7500, 7500},
                           "u:object_r:andrix_work_api_socket:s0",
                           Side::Client) == Role::Manager);
  assert(MatchWorkPeerRole({2, 7500, 7500},
                           "u:object_r:andrix_work_api_socket:s0:c512,c768",
                           Side::Client) == Role::Manager);
  assert(MatchWorkPeerRole({2, 7500, 7500}, "u:r:andrixd:s0", Side::Client) ==
         Role::None);
  assert(MatchWorkPeerRole({2, 7500, 7500},
                           std::string("u:r:andrix_owner:s0\0forged", 25),
                           Side::Manager) == Role::None);
}
void framing_and_fd_closure() {
  int pair[2];
  assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) == 0);
  assert(ConfigureWorkPeerSocket(pair[0]) == 0 &&
         ConfigureWorkPeerSocket(pair[1]) == 0);
  int error = 0;
  auto peer = WorkPeerEndpoint::Capture(pair[1], error);
  assert(peer && !error && peer->credentials().pid == getpid());
  assert(peer->MatchesSocket(pair[1]) && !peer->MatchesSocket(pair[0]));
  auto auth =
      AuthorizedWorkPeer::Capture(pair[1], WorkPeerSide::Manager, error);
  // This host is not an Android owner/Console identity. No authorization
  // fallback is allowed when SO_PEERSEC is absent (as on the current host).
  assert(!auth && (error == ENOPROTOOPT || error == EPERM || error == ENODATA));
  WorkFrame message;
  assert(ReceiveAuthorizedWorkFrame(pair[1], {}, message) == EPERM);
  assert(ReceiveCorrelatedWorkFrame(pair[0], *peer, message) == ESTALE);
  assert(ReceiveCorrelatedWorkFrame(pair[1], *peer, message) == EAGAIN);
  int null = open("/dev/null", O_RDWR | O_CLOEXEC);
  assert(null >= 0);
  auto other = peer->credentials();
  ++other.uid;
  assert(!peer->MatchesSender(other));
  other = peer->credentials();
  ++other.gid;
  assert(!peer->MatchesSender(other));
  other = peer->credentials();
  ++other.pid;
  assert(
      peer->MatchesSender(other));  // Principal authority, not a PID allowlist.
  std::array<int, 3> rights{null, null, null};
  const size_t before = descriptor_count();
  std::vector<uint8_t> body(kWorkFrameBytes);
  for (size_t n = 0; n < body.size(); ++n) body[n] = n % 256;
  assert(SendWorkFrame(pair[0], header(), body, rights) == 0);
  assert(ReceiveCorrelatedWorkFrame(pair[1], *peer, message) == 0);
  assert(message.body().size() == body.size() &&
         memcmp(message.body().data(), body.data(), body.size()) == 0);
  assert(message.descriptor_count() == 3 && descriptor_count() == before + 3);
  for (size_t n = 0; n < 3; ++n) {
    int fd = message.Take(n);
    assert(fd >= 0 && (fcntl(fd, F_GETFD) & FD_CLOEXEC));
    assert(message.Take(n) == -1);
    close(fd);
  }
  message.Reset();
  assert(descriptor_count() == before);
  assert(SendWorkFrame(pair[0], header(), {},
                       std::span<const int>(rights.data(), 3)) == 0);
  assert(ReceiveCorrelatedWorkFrame(pair[1], *peer, message) == 0);
  message.Reset();
  assert(descriptor_count() == before);
  for (size_t n = 0; n < 80; ++n) {
    auto bad = header(n + 1);
    bad.descriptors = 3;
    if (n % 4 == 0) bad.magic ^= 1;
    if (n % 4 == 1) bad.reserved = 1;
    if (n % 4 == 2) bad.correlation = 0;
    if (n % 4 == 3) bad.descriptors = 2;
    raw(pair[0], bad, {}, rights);
    assert(ReceiveCorrelatedWorkFrame(pair[1], *peer, message) == EPROTO);
    assert(!message.descriptor_count() && message.body().empty() &&
           descriptor_count() == before);
  }
  std::array<int, 8> excess;
  excess.fill(null);
  auto bad = header();
  bad.descriptors = 8;
  raw(pair[0], bad, {}, excess);
  assert(ReceiveCorrelatedWorkFrame(pair[1], *peer, message) == EPROTO);
  assert(descriptor_count() == before);
  std::array<int, 32> truncated;
  truncated.fill(null);
  bad.descriptors =
      3;  // Header itself is valid; ancillary space is insufficient.
  raw(pair[0], bad, {}, truncated);
  assert(ReceiveCorrelatedWorkFrame(pair[1], *peer, message) == EPROTO);
  assert(descriptor_count() == before);
  raw(pair[0], header(), {}, rights, true);
  assert(ReceiveCorrelatedWorkFrame(pair[1], *peer, message) == ECONNRESET);
  assert(descriptor_count() == before);
  body.push_back(17);
  bad = header();
  bad.bytes = body.size();
  bad.descriptors = 3;
  assert(SendWorkFrame(pair[0], header(), body) == EMSGSIZE);
  raw(pair[0], bad, body, rights);
  assert(ReceiveCorrelatedWorkFrame(pair[1], *peer, message) == EPROTO);
  assert(descriptor_count() == before);
  int disabled = 0;
  assert(setsockopt(pair[1], SOL_SOCKET, SO_PASSCRED, &disabled,
                    sizeof(disabled)) == 0);
  assert(SendWorkFrame(pair[0], header()) == 0);
  assert(ReceiveCorrelatedWorkFrame(pair[1], *peer, message) == EPERM);
  assert(ConfigureWorkPeerSocket(pair[1]) == 0);
  assert(SendWorkFrame(pair[0], header()) == 0);
  assert(ReceiveCorrelatedWorkFrame(pair[1], *peer, message) == 0);
  // Newer kernels can attach an unrequested pidfd after a local socket option
  // mistake. It is not used for authority and must not leak when rejected.
  int enabled = 1;
  if (setsockopt(pair[1], SOL_SOCKET, 76, &enabled, sizeof(enabled)) == 0) {
    assert(SendWorkFrame(pair[0], header()) == 0);
    assert(ReceiveCorrelatedWorkFrame(pair[1], *peer, message) == EPROTO);
    assert(descriptor_count() == before);
  } else {
    assert(errno == ENOPROTOOPT || errno == EINVAL);
  }
  close(null);
  close(pair[0]);
  close(pair[1]);
}
void control_frame_under_descriptor_pressure() {
  pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    rlimit limit;
    assert(getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_max >= 64);
    limit.rlim_cur = 64;
    assert(setrlimit(RLIMIT_NOFILE, &limit) == 0);
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) == 0);
    assert(ConfigureWorkPeerSocket(pair[0]) == 0 &&
           ConfigureWorkPeerSocket(pair[1]) == 0);
    int error;
    auto peer = WorkPeerEndpoint::Capture(pair[1], error);
    assert(peer);
    std::vector<int> fill;
    for (;;) {
      int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
      if (fd < 0) {
        assert(errno == EMFILE);
        break;
      }
      fill.push_back(fd);
    }
    assert(!fill.empty());
    std::array<int, 3> rights{fill[0], fill[0], fill[0]};
    assert(SendWorkFrame(pair[0], header(1), {}, rights) == 0);
    WorkFrame message;
    assert(ReceiveCorrelatedWorkFrame(pair[1], *peer, message) == EPROTO);
    assert(SendWorkFrame(pair[0], header(2)) == 0);
    assert(ReceiveCorrelatedWorkFrame(pair[1], *peer, message) == 0 &&
           message.header().correlation == 2);
    for (int fd : fill) close(fd);
    close(pair[0]);
    close(pair[1]);
    _exit(0);
  }
  int status;
  assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
         WEXITSTATUS(status) == 0);
}
void separate_process_and_forwarded_connection() {
  int listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  assert(listener >= 0 && ConfigureWorkPeerSocket(listener) == 0);
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  const std::string name =
      "andrix-peer-process-test-" + std::to_string(getpid());
  memcpy(address.sun_path + 1, name.data(), name.size());
  const auto length =
      static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + name.size());
  assert(bind(listener, reinterpret_cast<sockaddr*>(&address), length) == 0 &&
         listen(listener, 1) == 0);
  int command[2], status[2];
  assert(pipe2(command, O_CLOEXEC) == 0 && pipe2(status, O_CLOEXEC) == 0);
  const pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    close(listener);
    close(command[1]);
    close(status[0]);
    int connection = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    assert(connection >= 0 &&
           connect(connection, reinterpret_cast<sockaddr*>(&address), length) ==
               0);
    assert(ConfigureWorkPeerSocket(connection) == 0);
    auto ready = [&] {
      char c;
      assert(read(command[0], &c, 1) == 1 && c == 'R');
    };
    ready();
    assert(SendWorkFrame(connection, header(1)) == 0);
    ready();
    std::thread sender(
        [&] { assert(SendWorkFrame(connection, header(2)) == 0); });
    sender.join();
    ready();
    // Sharing within the same principal is ordinary descriptor semantics.
    // MAC authorization is separate and cannot be qualified on this host.
    pid_t forwarded = fork();
    assert(forwarded >= 0);
    if (!forwarded) {
      int null = open("/dev/null", O_RDWR | O_CLOEXEC);
      assert(null >= 0);
      assert(SendWorkFrame(connection, header(3), {},
                           std::span<const int>(&null, 1)) == 0);
      raise(SIGSTOP);
      close(null);
      _exit(0);
    }
    int waited;
    assert(waitpid(forwarded, &waited, WUNTRACED) == forwarded &&
           WIFSTOPPED(waited));
    assert(write(status[1], "F", 1) == 1);
    ready();
    assert(kill(forwarded, SIGCONT) == 0);
    assert(waitpid(forwarded, &waited, 0) == forwarded && WIFEXITED(waited) &&
           WEXITSTATUS(waited) == 0);
    assert(SendWorkFrame(connection, header(4)) == 0);
    ready();
    // Unprivileged callers cannot spoof another process's SCM_CREDENTIALS.
    auto h = header(5);
    iovec bytes{&h, sizeof(h)};
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(ucred))]{};
    msghdr message{};
    message.msg_iov = &bytes;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    auto* cmsg = CMSG_FIRSTHDR(&message);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_CREDENTIALS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(ucred));
    ucred spoof{getppid(), getuid(), getgid()};
    memcpy(CMSG_DATA(cmsg), &spoof, sizeof(spoof));
    assert(sendmsg(connection, &message, MSG_NOSIGNAL) == -1 && errno == EPERM);
    spoof = {getpid(), 0, 0};
    memcpy(CMSG_DATA(cmsg), &spoof, sizeof(spoof));
    assert(sendmsg(connection, &message, MSG_NOSIGNAL) == -1 && errno == EPERM);
    assert(write(status[1], "S", 1) == 1);
    ready();
    close(connection);
    close(command[0]);
    close(status[1]);
    _exit(0);
  }
  close(command[0]);
  close(status[1]);
  int connection =
      accept4(listener, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
  assert(connection >= 0);
  int error;
  auto peer = WorkPeerEndpoint::Capture(connection, error);
  assert(peer && peer->credentials() ==
                     (WorkPeerCredentials{child, getuid(), getgid()}));
  const size_t before = descriptor_count();
  auto release = [&] { assert(write(command[1], "R", 1) == 1); };
  WorkFrame message;
  release();
  expect_ready(connection);
  assert(ReceiveCorrelatedWorkFrame(connection, *peer, message) == 0 &&
         message.header().correlation == 1);
  release();
  expect_ready(connection);
  assert(ReceiveCorrelatedWorkFrame(connection, *peer, message) == 0 &&
         message.header().correlation == 2);
  release();
  char marker;
  assert(read(status[0], &marker, 1) == 1 && marker == 'F');
  assert(ReceiveCorrelatedWorkFrame(connection, *peer, message) == 0 &&
         message.header().correlation == 3 && message.descriptor_count() == 1);
  message.Reset();
  assert(descriptor_count() == before);
  release();
  expect_ready(connection);
  assert(ReceiveCorrelatedWorkFrame(connection, *peer, message) == 0 &&
         message.header().correlation == 4);
  release();
  assert(read(status[0], &marker, 1) == 1 && marker == 'S');
  release();
  int waited;
  assert(waitpid(child, &waited, 0) == child && WIFEXITED(waited) &&
         WEXITSTATUS(waited) == 0);
  assert(ReceiveCorrelatedWorkFrame(connection, *peer, message) == ECONNRESET);
  close(connection);
  close(listener);
  close(command[1]);
  close(status[0]);
}
}  // namespace
int main() {
  assert(getuid() != 0);
  alarm(30);
  const size_t before = descriptor_count();
  policy_units();
  framing_and_fd_closure();
  control_frame_under_descriptor_pressure();
  separate_process_and_forwarded_connection();
  assert(descriptor_count() == before);
  puts(
      "{\"actual_kernel_credentials_and_connection_correlation\":true,"
      "\"same_principal_forwarded_connection_accepted\":true,"
      "\"same_process_thread_allowed\":true,\"control_frame_at_EMFILE\":true,"
      "\"malformed_received_FDs_closed\":true,\"claimed_credentials_not_"
      "trusted\":true,\"Android_MAC_or_forced_PID_reuse_qualified\":false}");
}
