// SPDX-License-Identifier: Apache-2.0
#include "service_handoff.h"

#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace andrix::supervision {
int ReceiveServiceActivation(int socket, const ServiceReadyMessage& original,
                             ServiceHandoffPeer supervisor) {
  ServiceReadyMessage reply{};
  iovec bytes{&reply, sizeof(reply)};
  alignas(cmsghdr) char
      control[CMSG_SPACE(sizeof(ucred)) + CMSG_SPACE(8 * sizeof(int))]{};
  msghdr message{};
  message.msg_iov = &bytes;
  message.msg_iovlen = 1;
  message.msg_control = control;
  message.msg_controllen = sizeof(control);
  ssize_t count = recvmsg(socket, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
  if (count < 0) return errno;
  bool authenticated = false, invalid = false;
  for (auto* header = CMSG_FIRSTHDR(&message); header;
       header = CMSG_NXTHDR(&message, header)) {
    if (header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS &&
        header->cmsg_len >= CMSG_LEN(0)) {
      size_t length = header->cmsg_len - CMSG_LEN(0);
      for (size_t offset = 0; offset + sizeof(int) <= length;
           offset += sizeof(int)) {
        int fd;
        memcpy(&fd, CMSG_DATA(header) + offset, sizeof(fd));
        if (fd >= 0) close(fd);
      }
      invalid = true;
    } else if (!authenticated && header->cmsg_level == SOL_SOCKET &&
               header->cmsg_type == SCM_CREDENTIALS &&
               header->cmsg_len == CMSG_LEN(sizeof(ucred))) {
      ucred peer{};
      memcpy(&peer, CMSG_DATA(header), sizeof(peer));
      authenticated = peer.pid == supervisor.pid &&
                      peer.uid == supervisor.uid && peer.gid == supervisor.gid;
      if (!authenticated) invalid = true;
    } else
      invalid = true;
  }
  if (!count) return ECONNRESET;
  if (count != static_cast<ssize_t>(sizeof(reply)) ||
      message.msg_flags & (MSG_TRUNC | MSG_CTRUNC) || invalid)
    return EPROTO;
  if (!authenticated) return EPERM;
  if (original.magic != kServiceReadyRequestActivation ||
      reply.magic != kServiceActivation || !original.boot ||
      !original.instance || !original.device || !original.inode ||
      reply.boot != original.boot || reply.instance != original.instance ||
      reply.device != original.device || reply.inode != original.inode)
    return ESTALE;
  return 0;
}
}  // namespace andrix::supervision
