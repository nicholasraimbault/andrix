// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <cstdint>

namespace andrix::supervision {
// Generic delegated service bootstrap receipt. No work, terminal or CE policy.
// The private handoff's actual peer/profile/object checks remain mandatory.
struct ServiceReadyMessage {
  uint64_t magic = 0x44454c4547415445ULL;
  uint64_t boot = 0, instance = 0, device = 0, inode = 0;
};
static_assert(sizeof(ServiceReadyMessage) == 40);
}  // namespace andrix::supervision
