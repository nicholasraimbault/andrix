// SPDX-License-Identifier: Apache-2.0
#include "lifecycle_core.h"

#include <limits>

namespace andrix {

bool LifecycleGate::advance(uint64_t now) {
  if (now < observed_) { revoke(); return false; }
  observed_ = now;
  return true;
}

uint64_t LifecycleGate::begin(uint64_t now) {
  revoke();
  if (!advance(now) || generation_ >= uint64_t(std::numeric_limits<int64_t>::max()) ||
      now > std::numeric_limits<uint64_t>::max() - kLifecycleLeaseMillis) return 0;
  ++generation_;
  state_ = State::Pending;
  deadline_ = now + kLifecycleLeaseMillis;
  return generation_;
}

bool LifecycleGate::valid(uint64_t now) {
  if (!advance(now)) return false;
  if (state_ != State::Absent && now >= deadline_) revoke();
  return state_ != State::Absent;
}

bool LifecycleGate::ready(uint64_t now) {
  return valid(now) && state_ == State::Ready;
}

bool LifecycleGate::renew(uint64_t generation, uint64_t now, bool running, bool unlocked) {
  // A stale sender cannot extend OR revoke another registration. Its supplied
  // state has no effect; the coordinator supplies the trusted clock value.
  if (!advance(now) || generation == 0 || generation != generation_) return false;
  if (!valid(now)) return false; // An expired registration can never revive.
  if (!running || !unlocked ||
      now > std::numeric_limits<uint64_t>::max() - kLifecycleLeaseMillis) {
    revoke();
    return false;
  }
  deadline_ = now + kLifecycleLeaseMillis;
  state_ = State::Ready;
  return true;
}

bool LifecycleGate::release(uint64_t generation) {
  if (generation == 0 || generation != generation_) return false;
  revoke();
  return true;
}

void LifecycleGate::revoke() {
  state_ = State::Absent;
  deadline_ = 0;
}

} // namespace andrix
