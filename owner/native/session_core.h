// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <string_view>

namespace andrix {

constexpr uint32_t kOwnerUid = 7500;
constexpr size_t kOutputLimit = 128 * 1024;
constexpr uint64_t kLeaseMillis = 1500;
constexpr uint64_t kMemoryLimit = 256ULL * 1024 * 1024;
constexpr uint64_t kProcessLimit = 32;
constexpr uint64_t kDescriptorLimit = 128;
constexpr std::string_view kServiceName = "andrix.owner.session";
constexpr std::string_view kHome = "/data/misc_ce/0/andrix";
constexpr std::string_view kRunner = "/system_ext/bin/andrix-session-runner";

// Identity comes from Binder's calling UID and requested kernel security context,
// never from a parcel. Only the named, signer-mapped primary-user console is TCB.
bool authorized_console(uint32_t uid, std::string_view sid);
bool valid_dimensions(int rows, int columns);

// Caller supplies CLOCK_BOOTTIME milliseconds so suspension consumes the lease.
// This does not establish Android keyguard/CE state: the authenticated console
// checks UI state, and the daemon separately checks the kernel home/bounds.
class AttachmentGate {
 public:
  explicit AttachmentGate(uint64_t generation_seed = 0) : generation_(generation_seed) {}
  uint64_t attach(uint64_t now, bool ui_eligible, bool ce_ready, bool bounds_ready);
  bool renew(uint64_t generation, uint64_t now, bool ui_eligible, bool ce_ready);
  bool live(uint64_t now);
  bool detach(uint64_t generation);
  void revoke();
  uint64_t generation() const { return generation_; }

 private:
  bool advance(uint64_t now);
  uint64_t generation_ = 0;
  uint64_t deadline_ = 0;
  uint64_t observed_ = 0;
  bool active_ = false;
};

// Keep a bounded tail while detached or backpressured. Dropped output is counted,
// not misrepresented as a complete transcript. No shell-output interpretation.
class OutputTail {
 public:
  explicit OutputTail(size_t capacity = kOutputLimit) : capacity_(capacity) {}
  void append(std::string_view bytes);
  std::string peek(size_t maximum) const;
  bool consume(size_t count);
  size_t size() const { return bytes_.size(); }
  uint64_t dropped() const { return dropped_; }

 private:
  const size_t capacity_;
  std::deque<char> bytes_;
  uint64_t dropped_ = 0;
};

}  // namespace andrix
