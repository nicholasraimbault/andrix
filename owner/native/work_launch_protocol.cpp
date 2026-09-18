// SPDX-License-Identifier: Apache-2.0
#include "work_launch_protocol.h"

#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <type_traits>
#include <utility>

namespace andrix {
static_assert(std::is_trivially_copyable_v<WorkLaunchPacket>);
WorkLaunchMessage::~WorkLaunchMessage() {
  for (int fd : descriptors)
    if (fd >= 0) close(fd);
}
int WorkLaunchMessage::Take(LaunchFd role) {
  return std::exchange(descriptors[static_cast<size_t>(role)], -1);
}
int ConfigureWorkLaunchSocket(int socket) {
  int enabled = 1;
  return setsockopt(socket, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled))
             ? errno
             : 0;
}
int SendWorkLaunch(int socket, const WorkLaunchPacket& packet,
                   const int* descriptors, size_t count) {
  if (count && (count != kLaunchFdCount || !descriptors)) return EINVAL;
  iovec bytes{const_cast<WorkLaunchPacket*>(&packet), sizeof(packet)};
  alignas(cmsghdr) char control[CMSG_SPACE(kLaunchFdCount * sizeof(int))]{};
  msghdr message{};
  message.msg_iov = &bytes;
  message.msg_iovlen = 1;
  if (count) {
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    auto* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(count * sizeof(int));
    memcpy(CMSG_DATA(header), descriptors, count * sizeof(int));
  }
  ssize_t sent = sendmsg(socket, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
  return sent == static_cast<ssize_t>(sizeof(packet)) ? 0
         : sent < 0                                   ? errno
                                                      : EIO;
}
int ReceiveWorkLaunch(int socket, LaunchPeer expected,
                      WorkLaunchMessage& result) {
  for (int& fd : result.descriptors) {
    if (fd >= 0) close(fd);
    fd = -1;
  }
  result.count = 0;
  result.packet = {};
  iovec bytes{&result.packet, sizeof(result.packet)};
  alignas(cmsghdr) char control[CMSG_SPACE(sizeof(ucred)) +
                                CMSG_SPACE(kLaunchFdCount * sizeof(int))]{};
  msghdr message{};
  message.msg_iov = &bytes;
  message.msg_iovlen = 1;
  message.msg_control = control;
  message.msg_controllen = sizeof(control);
  ssize_t size = recvmsg(socket, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
  if (size < 0) return errno;
  bool credentials = false, invalid = false;
  for (auto* header = CMSG_FIRSTHDR(&message); header;
       header = CMSG_NXTHDR(&message, header)) {
    if (header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS &&
        header->cmsg_len >= CMSG_LEN(0)) {
      const size_t length = header->cmsg_len - CMSG_LEN(0);
      if (length % sizeof(int)) invalid = true;
      for (size_t offset = 0; offset + sizeof(int) <= length;
           offset += sizeof(int)) {
        int fd = -1;
        memcpy(&fd, CMSG_DATA(header) + offset, sizeof(fd));
        if (result.count < kLaunchFdCount)
          result.descriptors[result.count++] = fd;
        else {
          if (fd >= 0) close(fd);
          invalid = true;
        }
      }
    } else if (!credentials && header->cmsg_level == SOL_SOCKET &&
               header->cmsg_type == SCM_CREDENTIALS &&
               header->cmsg_len == CMSG_LEN(sizeof(ucred))) {
      ucred actual{};
      memcpy(&actual, CMSG_DATA(header), sizeof(actual));
      credentials = actual.pid == expected.pid && actual.uid == expected.uid &&
                    actual.gid == expected.gid;
      if (!credentials) invalid = true;
    } else
      invalid = true;
  }
  auto reject = [&](int error) {
    for (int& fd : result.descriptors) {
      if (fd >= 0) close(fd);
      fd = -1;
    }
    result.count = 0;
    return error;
  };
  if (!size)
    return reject(
        ECONNRESET);  // A zero-byte packet may still have delivered FDs.
  if (size != static_cast<ssize_t>(sizeof(result.packet)) ||
      message.msg_flags & (MSG_TRUNC | MSG_CTRUNC) || invalid)
    return reject(EPROTO);
  if (!credentials) return reject(EPERM);
  const auto& packet = result.packet;
  if (packet.magic != 0x414e44584c41554eULL || packet.version != 1 ||
      packet.reserved || !packet.work.manager || !packet.work.serial ||
      !packet.epoch.platform || !packet.epoch.generation ||
      packet.epoch.user < 0 ||
      packet.operation < WorkLaunchOperation::Prepare ||
      packet.operation > WorkLaunchOperation::Failed ||
      (packet.operation != WorkLaunchOperation::Failed && packet.error != 0))
    return reject(EPROTO);
  if ((packet.operation == WorkLaunchOperation::Prepare
           ? result.count != kLaunchFdCount
           : result.count != 0))
    return reject(EPROTO);
  return 0;
}
}  // namespace andrix
