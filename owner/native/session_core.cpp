// SPDX-License-Identifier: Apache-2.0
#include "session_core.h"

#include <algorithm>
#include <limits>

namespace andrix {

bool authorized_console(uint32_t uid, std::string_view sid) {
  constexpr std::string_view prefix = "u:r:andrix_terminal:s0";
  if (uid < 10000 || uid >= 90000 || !sid.starts_with(prefix)) return false;
  return sid.size() == prefix.size() || sid[prefix.size()] == ':';
}

bool valid_dimensions(int rows, int columns) {
  return rows >= 2 && rows <= 200 && columns >= 10 && columns <= 400;
}

bool AttachmentGate::advance(uint64_t now) {
  if (now < observed_) {
    revoke();
    return false;
  }
  observed_ = now;
  return true;
}

uint64_t AttachmentGate::attach(uint64_t now, bool ui_eligible, bool ce_ready,
                                bool bounds_ready) {
  revoke();
  if (!advance(now) || !ui_eligible || !ce_ready || !bounds_ready ||
      generation_ >= uint64_t(std::numeric_limits<int64_t>::max()) ||
      now > std::numeric_limits<uint64_t>::max() - kLeaseMillis) return 0;
  ++generation_;
  deadline_ = now + kLeaseMillis;
  active_ = true;
  return generation_;
}

bool AttachmentGate::live(uint64_t now) {
  if (!advance(now)) return false;
  if (active_ && now >= deadline_) revoke();
  return active_;
}

bool AttachmentGate::renew(uint64_t generation, uint64_t now, bool ui_eligible,
                           bool ce_ready) {
  // A delayed message belonging to an old attachment cannot renew or tear down a
  // newer one. Time still advances, so stale calls cannot preserve an expired FD.
  if (!live(now) || generation != generation_) return false;
  if (!ui_eligible || !ce_ready ||
      now > std::numeric_limits<uint64_t>::max() - kLeaseMillis) {
    revoke();
    return false;
  }
  deadline_ = now + kLeaseMillis;
  return true;
}

bool AttachmentGate::detach(uint64_t generation) {
  if (generation != generation_) return false;
  revoke();
  return true;
}

void AttachmentGate::revoke() {
  active_ = false;
  deadline_ = 0;
}

void OutputTail::append(std::string_view bytes) {
  for (char byte : bytes) {
    if (capacity_ == 0) {
      if (dropped_ != std::numeric_limits<uint64_t>::max()) ++dropped_;
      continue;
    }
    if (bytes_.size() == capacity_) {
      bytes_.pop_front();
      if (dropped_ != std::numeric_limits<uint64_t>::max()) ++dropped_;
    }
    bytes_.push_back(byte);
  }
}

std::string OutputTail::peek(size_t maximum) const {
  const auto length = std::min(maximum, bytes_.size());
  return {bytes_.begin(), bytes_.begin() + length};
}

bool OutputTail::consume(size_t count) {
  if (count > bytes_.size()) return false;
  bytes_.erase(bytes_.begin(), bytes_.begin() + count);
  return true;
}

}  // namespace andrix
