// SPDX-License-Identifier: Apache-2.0
#include "lifecycle_core.h"

#include <limits>

namespace andrix {
namespace {
constexpr uint64_t kMaxToken = uint64_t(std::numeric_limits<int64_t>::max());
constexpr uint64_t kLastIssue = std::numeric_limits<uint64_t>::max() - kLifecycleLeaseMillis;
static_assert(kLifecycleQueryMillis <= kLifecycleLeaseMillis);
} // namespace

bool LifecycleGate::advance(uint64_t now) {
  if (now < observed_) { revoke(); return false; }
  observed_ = now;
  return true;
}

uint64_t LifecycleGate::begin(uint64_t now) {
  revoke();
  if (!advance(now) || generation_ >= kMaxToken || now > kLastIssue) return 0;
  ++generation_;
  state_ = State::Pending;
  deadline_ = now + kLifecycleLeaseMillis;
  return generation_;
}

bool LifecycleGate::valid(uint64_t now) {
  if (!advance(now)) return false;
  if (state_ != State::Absent && now >= deadline_) revoke();
  // Do not leave a failed current query hanging while the previous ready lease
  // still looks valid. Matching query timeout is an irreversible failure.
  if (query_ != 0 && now - issued_ >= kLifecycleQueryMillis) revoke();
  return state_ != State::Absent;
}

bool LifecycleGate::ready(uint64_t now) {
  return valid(now) && state_ == State::Ready;
}

uint64_t LifecycleGate::begin_query(uint64_t generation, uint64_t now) {
  if (!valid(now) || generation == 0 || generation != generation_ || query_ != 0) return 0;
  if (query_sequence_ >= kMaxToken || now > kLastIssue) {
    revoke();
    return 0;
  }
  query_ = ++query_sequence_;
  issued_ = now;
  return query_; // Deliberately does not change deadline_ or pending/ready state.
}

bool LifecycleGate::report(uint64_t generation, uint64_t challenge, uint64_t now,
                           bool running, bool unlocked) {
  // Stale handles do not apply supplied state to another registration/query.
  // The coordinator's trusted clock still expires an actually stale registration.
  if (!valid(now) || generation == 0 || generation != generation_ ||
      challenge == 0 || challenge != query_) return false;
  const uint64_t issued = issued_;
  query_ = 0; // Consume exactly once, even when the reported state is invalid.
  issued_ = 0;
  if (!running || !unlocked) {
    revoke();
    return false;
  }
  deadline_ = issued + kLifecycleLeaseMillis; // begin_query checked overflow.
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
  query_ = 0;
  issued_ = 0;
}

} // namespace andrix
