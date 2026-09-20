// SPDX-License-Identifier: Apache-2.0
// Real private socket framing/credentials, not Android init activation proof.
#include "service_handoff.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <span>

using namespace andrix::supervision;
size_t descriptors() {
  DIR* dir = opendir("/proc/self/fd");
  assert(dir);
  size_t count = 0;
  while (auto* item = readdir(dir))
    if (item->d_name[0] != '.') ++count;
  closedir(dir);
  return count;
}
void send_packet(int fd, const ServiceReadyMessage& packet, size_t bytes,
                 std::span<const int> rights = {}) {
  iovec body{const_cast<ServiceReadyMessage*>(&packet), bytes};
  alignas(cmsghdr) char control[CMSG_SPACE(16 * sizeof(int))]{};
  msghdr message{};
  message.msg_iov = &body;
  message.msg_iovlen = 1;
  if (!rights.empty()) {
    message.msg_control = control;
    message.msg_controllen = CMSG_SPACE(rights.size_bytes());
    auto* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(rights.size_bytes());
    memcpy(CMSG_DATA(header), rights.data(), rights.size_bytes());
  }
  assert(sendmsg(fd, &message, MSG_NOSIGNAL) == static_cast<ssize_t>(bytes));
}
int main() {
  int pair[2];
  assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) == 0);
  int enabled = 1;
  assert(setsockopt(pair[1], SOL_SOCKET, SO_PASSCRED, &enabled,
                    sizeof(enabled)) == 0);
  ServiceReadyMessage request;
  request.magic = kServiceReadyRequestActivation;
  request.boot = 7;
  request.instance = 9;
  request.device = 11;
  request.inode = 13;
  ServiceHandoffPeer peer{getpid(), getuid(), getgid()};
  assert(ReceiveServiceActivation(pair[1], request, peer) == EAGAIN);
  auto receipt = request;
  receipt.magic = kServiceActivation;
  send_packet(pair[0], request, sizeof(request));
  assert(ReceiveServiceActivation(pair[1], request, peer) == ESTALE);
  send_packet(pair[0], receipt, sizeof(receipt));
  assert(ReceiveServiceActivation(pair[1], request, peer) == 0);
  for (int kind = 0; kind < 5; ++kind) {
    auto wrong = receipt;
    if (kind == 0) wrong.magic = kServiceReady;
    if (kind == 1) ++wrong.boot;
    if (kind == 2) ++wrong.instance;
    if (kind == 3) ++wrong.device;
    if (kind == 4) ++wrong.inode;
    send_packet(pair[0], wrong, sizeof(wrong));
    assert(ReceiveServiceActivation(pair[1], request, peer) == ESTALE);
  }
  send_packet(pair[0], receipt, sizeof(receipt));
  assert(ReceiveServiceActivation(pair[1], request,
                                  {getpid() + 1, getuid(), getgid()}) != 0);
  int null = open("/dev/null", O_RDONLY | O_CLOEXEC);
  assert(null >= 0);
  const size_t before = descriptors();
  std::array<int, 16> rights;
  rights.fill(null);
  send_packet(pair[0], receipt, sizeof(receipt), rights);
  assert(ReceiveServiceActivation(pair[1], request, peer) == EPROTO &&
         descriptors() == before);
  send_packet(pair[0], receipt, 0, std::span<const int>(rights.data(), 1));
  assert(ReceiveServiceActivation(pair[1], request, peer) == ECONNRESET &&
         descriptors() == before);
  // A queued activation receipt survives the supervisor closing its channel.
  send_packet(pair[0], receipt, sizeof(receipt));
  assert(shutdown(pair[0], SHUT_RDWR) == 0);
  close(pair[0]);
  assert(ReceiveServiceActivation(pair[1], request, peer) == 0);
  assert(ReceiveServiceActivation(pair[1], request, peer) == ECONNRESET);
  close(null);
  close(pair[1]);
  puts(
      "{\"private_activation_receipt\":true,\"wrong_instance_and_peer_"
      "refused\":true,\"received_FDs_closed\":true,\"Android_activation_"
      "qualified\":false}");
}
