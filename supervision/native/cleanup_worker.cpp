// SPDX-License-Identifier: Apache-2.0
#include "cleanup_worker.h"

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <memory>
#include <type_traits>

namespace andrix::supervision {
static_assert(std::is_trivially_copyable_v<WorkerPacket>);
ReceivedWorkerPacket::~ReceivedWorkerPacket() {
  for (int fd : descriptors)
    if (fd >= 0) close(fd);
}
int ConfigureWorkerSocket(int fd) {
  int enabled = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)))
    return errno;
  return 0;
}
int SendWorkerPacket(int fd, const WorkerPacket& packet, const int* descriptors,
                     size_t count) {
  if (count != 0 && (count != 4 || !descriptors)) return EINVAL;
  iovec data{const_cast<WorkerPacket*>(&packet), sizeof(packet)};
  alignas(cmsghdr) char ancillary[CMSG_SPACE(4 * sizeof(int))]{};
  msghdr message{};
  message.msg_iov = &data;
  message.msg_iovlen = 1;
  if (count) {
    message.msg_control = ancillary;
    message.msg_controllen = sizeof(ancillary);
    auto* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(count * sizeof(int));
    memcpy(CMSG_DATA(header), descriptors, count * sizeof(int));
  }
  ssize_t sent = sendmsg(fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
  return sent == static_cast<ssize_t>(sizeof(packet)) ? 0
         : sent < 0                                   ? errno
                                                      : EIO;
}
int ReceiveWorkerPacket(int fd, WorkerPeer expected,
                        ReceivedWorkerPacket& received) {
  for (int& owned : received.descriptors) {
    if (owned >= 0) close(owned);
    owned = -1;
  }
  received.descriptor_count = 0;
  received.packet = {};
  iovec data{&received.packet, sizeof(received.packet)};
  alignas(cmsghdr) char
      ancillary[CMSG_SPACE(sizeof(ucred)) + CMSG_SPACE(4 * sizeof(int))]{};
  msghdr message{};
  message.msg_iov = &data;
  message.msg_iovlen = 1;
  message.msg_control = ancillary;
  message.msg_controllen = sizeof(ancillary);
  const ssize_t size = recvmsg(fd, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
  if (size < 0) return errno;
  bool credentials = false, malformed = false;
  for (auto* header = CMSG_FIRSTHDR(&message); header;
       header = CMSG_NXTHDR(&message, header)) {
    if (header->cmsg_len < CMSG_LEN(0)) {
      malformed = true;
      break;
    }
    const size_t bytes = header->cmsg_len - CMSG_LEN(0);
    if (header->cmsg_level != SOL_SOCKET) {
      malformed = true;
      continue;
    }
    if (header->cmsg_type == SCM_RIGHTS) {
      if (bytes % sizeof(int)) malformed = true;
      for (size_t offset = 0; offset + sizeof(int) <= bytes;
           offset += sizeof(int)) {
        int owned = -1;
        memcpy(&owned, CMSG_DATA(header) + offset, sizeof(owned));
        if (received.descriptor_count < received.descriptors.size())
          received.descriptors[received.descriptor_count++] = owned;
        else {
          close(owned);
          malformed = true;
        }
      }
    } else if (header->cmsg_type == SCM_CREDENTIALS && bytes == sizeof(ucred) &&
               !credentials) {
      ucred actual{};
      memcpy(&actual, CMSG_DATA(header), sizeof(actual));
      credentials = actual.pid == expected.pid && actual.uid == expected.uid &&
                    actual.gid == expected.gid;
      if (!credentials) malformed = true;
    } else
      malformed = true;
  }
  if (!size) return ECONNRESET;
  if (malformed || !credentials) return EPERM;
  if (size != static_cast<ssize_t>(sizeof(received.packet)) ||
      (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)))
    return EPROTO;
  const auto& packet = received.packet;
  if (packet.magic != 0x44534350 || packet.version != 1 || !packet.boot ||
      !packet.instance || !packet.worker || !packet.sequence ||
      packet.operation < WorkerOperation::Initialize ||
      packet.operation > WorkerOperation::Exit)
    return EPROTO;
  return 0;
}
int RunCleanupWorker(int fd, WorkerPeer parent) {
  if (ConfigureWorkerSocket(fd)) return 120;
  std::shared_ptr<CapturedCgroup> scope;
  std::unique_ptr<ReclamationCursor> cursor;
  uint64_t boot = 0, instance = 0, worker = 0, sequence = 0;
  for (;;) {
    pollfd wait{fd, POLLIN, 0};
    int polled;
    do {
      polled = poll(&wait, 1, -1);
    } while (polled < 0 && errno == EINTR);
    if (polled <= 0) return 121;
    ReceivedWorkerPacket message;
    const int error = ReceiveWorkerPacket(fd, parent, message);
    if (error == EAGAIN || error == EINTR) continue;
    if (error == ECONNRESET) return 0;
    if (error) return 122;
    WorkerPacket reply = message.packet;
    const auto& request = message.packet;
    if (!scope) {
      if (request.operation != WorkerOperation::Initialize ||
          message.descriptor_count != 4 ||
          !memchr(request.name.data(), 0, request.name.size()))
        return 123;
      auto transfer = std::make_unique<CgroupTransfer>();
      transfer->descriptors = message.descriptors;
      message.descriptors.fill(-1);
      message.descriptor_count = 0;
      transfer->identities = request.objects;
      transfer->limits = request.limits;
      transfer->stats = request.stats;
      transfer->name = request.name.data();
      Failure failure;
      scope = CapturedCgroup::Adopt(std::move(transfer), failure);
      reply.error = failure.code;
      reply.error_number = failure.error;
      boot = request.boot;
      instance = request.instance;
      worker = request.worker;
      sequence = request.sequence;
      if (SendWorkerPacket(fd, reply) || !scope) return 124;
      continue;
    }
    if (message.descriptor_count ||
        request.operation == WorkerOperation::Initialize ||
        request.boot != boot || request.instance != instance ||
        request.worker != worker || request.sequence <= sequence)
      return 125;
    sequence = request.sequence;
    reply.error = GroupError::None;
    reply.error_number = 0;
    reply.population = GroupPopulation::Unknown;
    Failure failure;
    switch (request.operation) {
      case WorkerOperation::Kill:
        failure = scope->Kill();
        break;
      case WorkerOperation::Observe: {
        auto population = scope->ObservePopulation();
        reply.population = population.state;
        reply.error_number = population.error;
        if (population.state == GroupPopulation::Unknown)
          reply.error = GroupError::UnknownPopulation;
        break;
      }
      case WorkerOperation::Step: {
        if (!cursor) cursor = scope->BeginReclaim(failure);
        if (cursor) {
          auto step = cursor->Step(request.quantum);
          reply.cursor = step.state;
          failure = step.failure;
        } else
          reply.cursor = CursorState::Blocked;
        break;
      }
      case WorkerOperation::DropCursor:
        cursor.reset();
        break;
      case WorkerOperation::ConfirmRemoved:
        failure = scope->ConfirmRemoved();
        if (failure.code == GroupError::None)
          reply.population = GroupPopulation::Removed;
        break;
      case WorkerOperation::Exit:
        cursor.reset();
        return SendWorkerPacket(fd, reply) ? 126 : 0;
      case WorkerOperation::Initialize:
        return 127;
    }
    if (failure.code != GroupError::None) {
      reply.error = failure.code;
      reply.error_number = failure.error;
    }
    reply.stats = scope->stats();
    if (SendWorkerPacket(fd, reply)) return 126;
  }
}
}  // namespace andrix::supervision
