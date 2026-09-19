// SPDX-License-Identifier: Apache-2.0
#include "work_peer.h"

#include <sys/socket.h>

#include <array>
#include <cerrno>
#include <utility>

namespace andrix {
namespace {
// Stable Linux socket-cookie ABI, not a newer pidfs or pidfd-socket dependency.
constexpr int kSocketCookie = 57;
#ifdef SO_COOKIE
static_assert(SO_COOKIE == kSocketCookie);
#endif
bool packet_socket(int socket) {
  int type = 0;
  socklen_t size = sizeof(type);
  if (getsockopt(socket, SOL_SOCKET, SO_TYPE, &type, &size) ||
      size != sizeof(type) || type != SOCK_SEQPACKET)
    return false;
  sockaddr_storage address{};
  size = sizeof(address);
  return !getsockname(socket, reinterpret_cast<sockaddr*>(&address), &size) &&
         address.ss_family == AF_UNIX;
}
bool cookie(int socket, uint64_t& value) {
  socklen_t size = sizeof(value);
  return !getsockopt(socket, SOL_SOCKET, kSocketCookie, &value, &size) &&
         size == sizeof(value) && value != 0;
}
bool context_prefix(std::string_view context, std::string_view prefix) {
  return context == prefix ||
         (context.starts_with(prefix) && context.size() > prefix.size() + 1 &&
          context[prefix.size()] == ':');
}
}  // namespace

int ConfigureWorkPeerSocket(int socket) {
  if (!packet_socket(socket)) return EINVAL;
  int enabled = 1;
  return setsockopt(socket, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled))
             ? errno
             : 0;
}
WorkPeerEndpoint::WorkPeerEndpoint(uint64_t socket_cookie,
                                   WorkPeerCredentials credentials)
    : socket_cookie_(socket_cookie), credentials_(credentials) {}
std::optional<WorkPeerEndpoint> WorkPeerEndpoint::Capture(int socket,
                                                          int& error) {
  error = 0;
  if (!packet_socket(socket)) {
    error = EINVAL;
    return {};
  }
  ucred credentials{};
  socklen_t size = sizeof(credentials);
  if (getsockopt(socket, SOL_SOCKET, SO_PEERCRED, &credentials, &size)) {
    error = errno;
    return {};
  }
  if (size != sizeof(credentials) || credentials.pid <= 0) {
    error = EPROTO;
    return {};
  }
  uint64_t socket_cookie = 0;
  if (!cookie(socket, socket_cookie)) {
    error = EPROTO;
    return {};
  }
  return WorkPeerEndpoint(socket_cookie,
                          {credentials.pid, credentials.uid, credentials.gid});
}
bool WorkPeerEndpoint::MatchesSocket(int socket) const {
  uint64_t observed = 0;
  return socket_cookie_ && cookie(socket, observed) &&
         observed == socket_cookie_;
}
bool WorkPeerEndpoint::MatchesSender(WorkPeerCredentials credentials) const {
  return socket_cookie_ && credentials.pid > 0 &&
         credentials.uid == credentials_.uid &&
         credentials.gid == credentials_.gid;
}
WorkPeerRole MatchWorkPeerRole(WorkPeerCredentials credentials,
                               std::string_view context, WorkPeerSide side) {
  if (credentials.pid <= 0 || context.empty() ||
      context.find('\0') != context.npos ||
      context.find('\n') != context.npos || context.find('\r') != context.npos)
    return WorkPeerRole::None;
  if (side == WorkPeerSide::Client) {
    // SELinux copies the connecting client's MLS level to the accepted server
    // socket. Its public endpoint type/role remain fixed, including for
    // Console.
    return credentials.uid == 7500 && credentials.gid == 7500 &&
                   context_prefix(context,
                                  "u:object_r:andrix_work_api_socket:s0")
               ? WorkPeerRole::Manager
               : WorkPeerRole::None;
  }
  if (side != WorkPeerSide::Manager) return WorkPeerRole::None;
  if (credentials.uid == 7500 && credentials.gid == 7500 &&
      context == "u:r:andrix_owner:s0")
    return WorkPeerRole::Owner;
  if (credentials.uid >= 10000 && credentials.uid < 90000 &&
      credentials.gid == credentials.uid &&
      context_prefix(context, "u:r:andrix_terminal:s0"))
    return WorkPeerRole::Console;
  return WorkPeerRole::None;
}
std::optional<AuthorizedWorkPeer> AuthorizedWorkPeer::Capture(int socket,
                                                              WorkPeerSide side,
                                                              int& error) {
  auto endpoint = WorkPeerEndpoint::Capture(socket, error);
  if (!endpoint) return {};
  std::array<char, 512> context{};
  socklen_t length = context.size();
  if (getsockopt(socket, SOL_SOCKET, SO_PEERSEC, context.data(), &length)) {
    error = errno;
    return {};
  }
  if (!length || length > context.size()) {
    error = EPROTO;
    return {};
  }
  if (context[length - 1] == '\0') --length;
  std::string text(context.data(), length);
  const auto role = MatchWorkPeerRole(endpoint->credentials(), text, side);
  if (role == WorkPeerRole::None || !endpoint->MatchesSocket(socket)) {
    error = EPERM;
    return {};
  }
  AuthorizedWorkPeer result;
  result.endpoint_ = *endpoint;
  result.role_ = role;
  result.context_ = std::move(text);
  error = 0;
  return result;
}
}  // namespace andrix
