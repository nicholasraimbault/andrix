// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>

namespace andrix {

constexpr uint64_t kLifecycleLeaseMillis = 2000;

// Registration/state core only. Binder UID/SID, process-local lifetime binding,
// foreground-service ownership and actual Android queries are separate checks.
// Call with CLOCK_MONOTONIC milliseconds (Android uptime), excluding suspend.
// This never grants a UI attachment or changes its CLOCK_BOOTTIME lease.
class LifecycleGate {
 public:
  explicit LifecycleGate(uint64_t seed = 0) : generation_(seed) {}
  uint64_t begin(uint64_t now); // pending until a successful fresh state report
  bool renew(uint64_t generation, uint64_t now, bool user_running, bool user_unlocked);
  bool valid(uint64_t now); // includes a pending, not-yet-ready registration
  bool ready(uint64_t now);
  bool release(uint64_t generation);
  void revoke();
  uint64_t generation() const { return generation_; }

 private:
  enum class State { Absent, Pending, Ready };
  bool advance(uint64_t now);
  uint64_t generation_ = 0;
  uint64_t observed_ = 0;
  uint64_t deadline_ = 0;
  State state_ = State::Absent;
};

} // namespace andrix
