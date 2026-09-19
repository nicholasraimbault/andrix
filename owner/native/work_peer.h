// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <sys/types.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace andrix {

struct WorkPeerCredentials {
  pid_t pid =
      0;  // Diagnostic only. Never selects a process or grants authority.
  uid_t uid = 0;
  gid_t gid = 0;
  bool operator==(const WorkPeerCredentials&) const = default;
};

// Connected Unix packet socket setup. Kernel per-message credentials are
// required, not caller claims. Does not authorize an owner/Console role.
int ConfigureWorkPeerSocket(int socket);

// Captures a connection, not a reusable numeric process identity. Per-message
// credentials must remain in its UID/GID principal. Same-principal descriptor
// sharing is allowed, subject to current MAC permission to use that socket.
// The PID is not compared, used for signaling, or opened through /proc.
// Borrowed socket numbers must stay owned and stable throughout operations.
// Cookies detect a different connection, not concurrent close/reuse of an FD.
class WorkPeerEndpoint {
 public:
  WorkPeerEndpoint() = default;
  static std::optional<WorkPeerEndpoint> Capture(int socket, int& error);
  explicit operator bool() const { return socket_cookie_ != 0; }
  WorkPeerCredentials credentials() const { return credentials_; }
  bool MatchesSocket(int socket) const;
  bool MatchesSender(WorkPeerCredentials credentials) const;

 private:
  WorkPeerEndpoint(uint64_t socket_cookie, WorkPeerCredentials credentials);
  uint64_t socket_cookie_ = 0;
  WorkPeerCredentials credentials_{};
};

enum class WorkPeerRole { None, Owner, Console, Manager };
enum class WorkPeerSide { Client, Manager };
// Pure matching of supplied facts, not authentication by itself. Client
// sockets originate in the owner/Console domains. The public manager endpoint
// has its own object label, never the private andrixd channel label.
WorkPeerRole MatchWorkPeerRole(WorkPeerCredentials credentials,
                               std::string_view socket_context,
                               WorkPeerSide side);

// Authorization uses actual kernel credentials and SO_PEERSEC. The latter is
// a socket security context, NOT the current task SID. The declared MAC policy
// must restrict label creation and ongoing socket use. It must not let another
// principal acquire this authority just by forwarding a descriptor. Untrusted
// owner/Console callers have no credential-spoofing capabilities. Future
// isolated agents need their own principal/rights policy, not this owner grant.
// Missing context fails closed, including on a host without socket LSM data.
class AuthorizedWorkPeer {
 public:
  AuthorizedWorkPeer() = default;
  static std::optional<AuthorizedWorkPeer> Capture(int socket,
                                                   WorkPeerSide side,
                                                   int& error);
  explicit operator bool() const {
    return role_ != WorkPeerRole::None && bool(endpoint_);
  }
  WorkPeerRole role() const { return role_; }
  const WorkPeerEndpoint& endpoint() const { return endpoint_; }
  const std::string& socket_context() const { return context_; }

 private:
  WorkPeerEndpoint endpoint_;
  WorkPeerRole role_ = WorkPeerRole::None;
  std::string context_;
};

}  // namespace andrix
