// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>

namespace andrix {

constexpr uint64_t kLifecycleLeaseMillis = 2000;
constexpr uint64_t kLifecycleQueryMillis = 1000;

// Unwired registration/freshness model, NOT an Android lifecycle authority.
// Callers serialize all operations and supply trusted CLOCK_MONOTONIC milliseconds
// (Android uptime, excluding suspend). Identity, service ownership, observation of
// real Android state, and lossless user/key revocation remain separate requirements.
//
// A trusted observer must query Android AFTER receiving begin_query's challenge.
// Issuing a challenge never renews permission. A successful report's deadline is
// based on issue time, not arrival time; delay cannot buy a fresh full lease.
// Neither pending registration nor a query grants continuation or UI access. This
// model never changes the separate CLOCK_BOOTTIME UI attachment lease.
class LifecycleGate {
 public:
  explicit LifecycleGate(uint64_t seed = 0, uint64_t query_seed = 0)
      : generation_(seed), query_sequence_(query_seed) {}
  uint64_t begin(uint64_t now);
  uint64_t begin_query(uint64_t generation, uint64_t now); // one outstanding query
  bool report(uint64_t generation, uint64_t challenge, uint64_t now,
              bool user_running, bool user_unlocked);
  bool valid(uint64_t now); // includes a pending, NOT ready registration
  bool ready(uint64_t now);
  // Trusted adapter only: earliest currently known failure deadline, including
  // an outstanding query. Neither one is renewed from response arrival time.
  uint64_t ready_until(uint64_t now) {
    if (!ready(now)) return 0;
    const uint64_t pending = issued_ + kLifecycleQueryMillis;
    return query_ && pending < deadline_ ? pending : deadline_;
  }
  bool release(uint64_t generation);
  void revoke();
  uint64_t generation() const { return generation_; }

 private:
  enum class State { Absent, Pending, Ready };
  bool advance(uint64_t now);
  uint64_t generation_ = 0;
  uint64_t observed_ = 0;
  uint64_t deadline_ = 0;
  uint64_t query_sequence_ = 0;
  uint64_t query_ = 0;
  uint64_t issued_ = 0;
  State state_ = State::Absent;
};

} // namespace andrix
