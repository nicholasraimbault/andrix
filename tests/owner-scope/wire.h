// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <cstdint>

namespace andrix::scope_proof {
constexpr uint32_t kMagic = 0x41535031;
constexpr uint32_t kHeld = 1, kPulse = 2;
struct Event {
  uint32_t magic, type;
  int32_t pid, parent, session, group;
  int32_t uid, binder_errno, cgroup_errno;
};
static_assert(sizeof(Event) < 512); // One bounded SEQPACKET message, no text parser.
} // namespace andrix::scope_proof
