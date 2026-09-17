// SPDX-License-Identifier: Apache-2.0
#include "cleanup_worker.h"

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <cstring>
#include <vector>

using namespace andrix::supervision;
int main() {
  int sockets[2];
  assert(!socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets));
  assert(!ConfigureWorkerSocket(sockets[0]) &&
         !ConfigureWorkerSocket(sockets[1]));
  WorkerPeer self{getpid(), getuid(), getgid()};
  WorkerPacket packet;
  packet.boot = 1;
  packet.instance = 2;
  packet.worker = 3;
  packet.sequence = 1;
  assert(!SendWorkerPacket(sockets[0], packet));
  ReceivedWorkerPacket message;
  assert(!ReceiveWorkerPacket(sockets[1], self, message) &&
         !message.descriptor_count);
  int null = open("/dev/null", O_RDONLY | O_CLOEXEC);
  assert(null >= 0);
  int descriptors[]{null, null, null, null};
  assert(!SendWorkerPacket(sockets[0], packet, descriptors, 4));
  assert(!ReceiveWorkerPacket(sockets[1], self, message) &&
         message.descriptor_count == 4);
  for (int fd : message.descriptors) assert(fcntl(fd, F_GETFD) & FD_CLOEXEC);
  assert(SendWorkerPacket(sockets[0], packet, descriptors, 1) == EINVAL);
  assert(ReceiveWorkerPacket(sockets[1], self, message) == EAGAIN &&
         !message.descriptor_count);
  assert(!SendWorkerPacket(sockets[0], packet, descriptors, 4));
  assert(ReceiveWorkerPacket(sockets[1],
                             WorkerPeer{getpid() + 1, getuid(), getgid()},
                             message) == EPERM);
  packet.magic = 0;
  assert(!SendWorkerPacket(sockets[0], packet));
  assert(ReceiveWorkerPacket(sockets[1], self, message) == EPROTO);
  packet.magic = 0x44534350;
  packet.sequence = 0;
  assert(!SendWorkerPacket(sockets[0], packet));
  assert(ReceiveWorkerPacket(sockets[1], self, message) == EPROTO);
  packet.sequence = 1;
  std::vector<char> oversized(sizeof(packet) + 1);
  memcpy(oversized.data(), &packet, sizeof(packet));
  assert(send(sockets[0], oversized.data(), oversized.size(), 0) ==
         static_cast<ssize_t>(oversized.size()));
  assert(ReceiveWorkerPacket(sockets[1], self, message) == EPROTO);
  close(null);

  // SO_PEERCRED of a socketpair names the creator, not the later child sender.
  pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    close(sockets[0]);
    WorkerPacket reply = packet;
    reply.operation = WorkerOperation::Observe;
    _exit(SendWorkerPacket(sockets[1], reply) ? 1 : 0);
  }
  close(sockets[1]);
  pollfd wait{sockets[0], POLLIN, 0};
  assert(poll(&wait, 1, 5000) == 1);
  ucred creator{};
  socklen_t size = sizeof(creator);
  assert(!getsockopt(sockets[0], SOL_SOCKET, SO_PEERCRED, &creator, &size) &&
         creator.pid == getpid());
  assert(!ReceiveWorkerPacket(sockets[0], WorkerPeer{child, getuid(), getgid()},
                              message));
  int status = 0;
  assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
         WEXITSTATUS(status) == 0);
  close(sockets[0]);
}
