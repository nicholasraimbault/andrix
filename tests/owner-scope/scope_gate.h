// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <atomic>
#include <cstdint>

namespace andrix::scope_proof {
// Request ordering only. No authority, cgroup membership or cleanup acknowledgement.
class Gate {
 public:
  enum Phase { Ready = 0, Holding = 1, Held = 2, Released = 3, Stopped = 4 };
  explicit Gate(uint64_t id) : id_(id) { }
  bool matches(int64_t id) const { return id > 0 && uint64_t(id) == id_; }
  bool hold(int64_t id) { return matches(id) && advance(Ready, Holding); }
  bool held() { return advance(Holding, Held); }
  bool release(int64_t id) { return matches(id) && advance(Held, Released); }
  bool stop(int64_t id) {
    if (!matches(id)) return false;
    phase_.store(Stopped); return true;
  }
  Phase phase() const { return phase_.load(); }
  uint64_t id() const { return id_; }
 private:
  bool advance(Phase from, Phase to) { return phase_.compare_exchange_strong(from, to); }
  const uint64_t id_;
  std::atomic<Phase> phase_{Ready};
};
} // namespace andrix::scope_proof
