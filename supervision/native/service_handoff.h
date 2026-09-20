// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <sys/types.h>

#include <cstdint>

namespace andrix::supervision {
// Generic delegated service bootstrap receipt. No work, terminal or CE policy.
// The private handoff's actual peer/profile/object checks remain mandatory.
constexpr uint64_t kServiceReady = 0x44454c4547415445ULL;
constexpr uint64_t kServiceReadyRequestActivation = 0x44454c4547415452ULL;
constexpr uint64_t kServiceActivation = 0x44454c4547415441ULL;
struct ServiceReadyMessage {
  uint64_t magic = kServiceReady;
  uint64_t boot = 0, instance = 0, device = 0, inode = 0;
};
static_assert(sizeof(ServiceReadyMessage) == 40);
struct ServiceHandoffPeer {
  pid_t pid;
  uid_t uid;
  gid_t gid;
};
// Nonblocking receipt on the already inherited private channel. Kernel
// credentials and exact instance/object fields are mandatory. Unexpected FDs
// are closed. This is supervisor activation, not Andrix work or CE authority.
int ReceiveServiceActivation(int socket, const ServiceReadyMessage& original,
                             ServiceHandoffPeer supervisor);
}  // namespace andrix::supervision
