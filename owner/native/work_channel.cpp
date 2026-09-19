// SPDX-License-Identifier: Apache-2.0
#include "work_channel.h"

#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <type_traits>
#include <utility>

namespace andrix {
namespace {
constexpr int kScmPidfd = 4;
#ifdef SCM_PIDFD
static_assert(SCM_PIDFD == kScmPidfd);
#endif
static_assert(std::is_trivially_copyable_v<WorkFrameHeader>);
bool valid(const WorkFrameHeader& header) {
  return header.magic == WorkFrameHeader{}.magic && header.version == 1 &&
         (header.kind == WorkFrameKind::Request ||
          header.kind == WorkFrameKind::Reply) &&
         header.correlation && header.operation &&
         header.bytes <= kWorkFrameBytes &&
         header.descriptors <= kWorkFrameDescriptors && !header.reserved;
}
}  // namespace
WorkFrame::~WorkFrame() { Reset(); }
void WorkFrame::Reset() {
  for (int& fd : descriptors_) {
    if (fd >= 0) close(fd);
    fd = -1;
  }
  count_ = 0;
  size_ = 0;
  header_ = {};
}
int WorkFrame::Take(size_t index) {
  return index < count_ ? std::exchange(descriptors_[index], -1) : -1;
}
int SendWorkFrame(int socket, const WorkFrameHeader& input,
                  std::span<const uint8_t> body,
                  std::span<const int> descriptors) {
  if (body.size() > kWorkFrameBytes ||
      descriptors.size() > kWorkFrameDescriptors)
    return EMSGSIZE;
  auto header = input;
  header.bytes = static_cast<uint32_t>(body.size());
  header.descriptors = static_cast<uint32_t>(descriptors.size());
  if (!valid(header)) return EINVAL;
  for (int fd : descriptors)
    if (fd < 0) return EBADF;
  iovec vectors[] = {{&header, sizeof(header)},
                     {const_cast<uint8_t*>(body.data()), body.size()}};
  alignas(cmsghdr) char
      ancillary[CMSG_SPACE(kWorkFrameDescriptors * sizeof(int))]{};
  msghdr message{};
  message.msg_iov = vectors;
  message.msg_iovlen = body.empty() ? 1 : 2;
  if (!descriptors.empty()) {
    message.msg_control = ancillary;
    message.msg_controllen = CMSG_SPACE(descriptors.size_bytes());
    auto* control = CMSG_FIRSTHDR(&message);
    control->cmsg_level = SOL_SOCKET;
    control->cmsg_type = SCM_RIGHTS;
    control->cmsg_len = CMSG_LEN(descriptors.size_bytes());
    memcpy(CMSG_DATA(control), descriptors.data(), descriptors.size_bytes());
  }
  ssize_t size = sendmsg(socket, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
  return size == static_cast<ssize_t>(sizeof(header) + body.size()) ? 0
         : size < 0                                                 ? errno
                                                                    : EIO;
}
int ReceiveCorrelatedWorkFrame(int socket, const WorkPeerEndpoint& endpoint,
                               WorkFrame& result) {
  result.Reset();
  if (!endpoint || !endpoint.MatchesSocket(socket)) return ESTALE;
  iovec vectors[] = {{&result.header_, sizeof(result.header_)},
                     {result.bytes_.data(), result.bytes_.size()}};
  alignas(cmsghdr) char
      ancillary[CMSG_SPACE(sizeof(ucred)) + CMSG_SPACE(sizeof(int)) +
                CMSG_SPACE(kWorkFrameDescriptors * sizeof(int))]{};
  msghdr message{};
  message.msg_iov = vectors;
  message.msg_iovlen = 2;
  message.msg_control = ancillary;
  message.msg_controllen = sizeof(ancillary);
  ssize_t bytes = recvmsg(socket, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
  if (bytes < 0) return errno;
  bool have_credentials = false, invalid = false;
  WorkPeerCredentials credentials{};
  for (auto* control = CMSG_FIRSTHDR(&message); control;
       control = CMSG_NXTHDR(&message, control)) {
    if (control->cmsg_level != SOL_SOCKET) {
      invalid = true;
      continue;
    }
    if (control->cmsg_type == SCM_RIGHTS && control->cmsg_len >= CMSG_LEN(0)) {
      const size_t size = control->cmsg_len - CMSG_LEN(0);
      if (size % sizeof(int)) invalid = true;
      for (size_t offset = 0; offset + sizeof(int) <= size;
           offset += sizeof(int)) {
        int fd;
        memcpy(&fd, CMSG_DATA(control) + offset, sizeof(fd));
        if (fd < 0)
          invalid = true;
        else if (result.count_ < kWorkFrameDescriptors)
          result.descriptors_[result.count_++] = fd;
        else {
          close(fd);
          invalid = true;
        }
      }
    } else if (control->cmsg_type == kScmPidfd &&
               control->cmsg_len == CMSG_LEN(sizeof(int))) {
      int fd;
      memcpy(&fd, CMSG_DATA(control), sizeof(fd));
      // This protocol does not request pidfds. If a caller misconfigured the
      // socket, reject the unexpected control but still close its actual FD.
      if (fd >= 0) close(fd);
      invalid = true;
    } else if (control->cmsg_type == SCM_CREDENTIALS &&
               control->cmsg_len == CMSG_LEN(sizeof(ucred)) &&
               !have_credentials) {
      ucred value{};
      memcpy(&value, CMSG_DATA(control), sizeof(value));
      credentials = {value.pid, value.uid, value.gid};
      have_credentials = true;
    } else {
      invalid = true;
    }
  }
  const bool matched = have_credentials && endpoint.MatchesSender(credentials);
  auto reject = [&](int error) {
    result.Reset();
    return error;
  };
  if (!bytes)
    return reject(ECONNRESET);  // Empty packets may still have installed FDs.
  if (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC) || invalid ||
      bytes < static_cast<ssize_t>(sizeof(WorkFrameHeader)) ||
      !valid(result.header_) ||
      bytes != static_cast<ssize_t>(sizeof(WorkFrameHeader) +
                                    result.header_.bytes) ||
      result.count_ != result.header_.descriptors)
    return reject(EPROTO);
  if (!matched) return reject(EPERM);
  result.size_ = result.header_.bytes;
  return 0;
}
int ReceiveAuthorizedWorkFrame(int socket, const AuthorizedWorkPeer& peer,
                               WorkFrame& result) {
  if (!peer) {
    result.Reset();
    return EPERM;
  }
  int error = ReceiveCorrelatedWorkFrame(socket, peer.endpoint(), result);
  if (error) return error;
  const auto expected = peer.role() == WorkPeerRole::Manager
                            ? WorkFrameKind::Reply
                            : WorkFrameKind::Request;
  if (result.header().kind != expected) {
    result.Reset();
    return EPROTO;
  }
  return 0;
}
}  // namespace andrix
