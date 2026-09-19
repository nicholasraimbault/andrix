// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace andrix {
namespace work_io_detail {
struct Pool;
struct Binding;
}  // namespace work_io_detail

struct WorkIoIdentity {
  uint64_t manager = 0, serial = 0;
  bool operator==(const WorkIoIdentity&) const = default;
};
enum class WorkIoResult {
  Accepted,
  Existing,
  Invalid,
  Foreign,
  Stale,
  Capacity,
  Exhausted,
  Closed,
  Io
};

// Immutable binding to actual retained open file descriptions. File data,
// offsets and file status flags still have normal shared Unix semantics.
// There is no claim that fstat metadata or an FD number identifies that
// binding.
class WorkIoBinding {
 public:
  WorkIoBinding() = default;
  // Explicit no-descriptor plan, not inheritance of the manager's stdio.
  static WorkIoBinding Closed();
  explicit operator bool() const { return closed_plan_ || bool(binding_); }
  bool closed_plan() const { return closed_plan_; }
  WorkIoIdentity identity() const;
  // Borrow only while this value is held. -1 deliberately closes that standard
  // descriptor. Never close, replace or change flags on this borrowed number.
  int descriptor(size_t standard) const;
  bool operator==(const WorkIoBinding& other) const {
    return closed_plan_ == other.closed_plan_ && binding_ == other.binding_;
  }

 private:
  friend class WorkIoPool;
  explicit WorkIoBinding(std::shared_ptr<work_io_detail::Binding> binding);
  std::shared_ptr<work_io_detail::Binding> binding_;
  bool closed_plan_ = false;
};
class WorkIoReservation {
 public:
  WorkIoReservation() = default;
  explicit operator bool() const { return bool(issuer_); }
  WorkIoIdentity identity() const { return identity_; }

 private:
  friend class WorkIoPool;
  WorkIoReservation(std::shared_ptr<work_io_detail::Pool> issuer,
                    WorkIoIdentity identity);
  std::shared_ptr<work_io_detail::Pool> issuer_;
  WorkIoIdentity identity_{};
};
struct WorkIoReply {
  WorkIoResult result = WorkIoResult::Invalid;
  WorkIoReservation reservation{};
  WorkIoBinding binding{};
  int error = 0;
};
struct WorkIoUsage {
  size_t occupied = 0, pending = 0;
  bool closed = false;
};

// Internal standard-stream slice, not a complete arbitrary-FD public API.
// The authenticated ingress must bound its own temporary SCM_RIGHTS receipts.
// Reserve accounts a retained set BEFORE Capture duplicates descriptors outside
// the pool mutex. Capture can run once per ticket. A timeout does not reset it.
class WorkIoPool {
 public:
  static constexpr size_t kMaximumBindings = 256;
  WorkIoPool(uint64_t manager, size_t capacity, uint64_t serial_limit);
  ~WorkIoPool();
  WorkIoPool(const WorkIoPool&) = delete;
  WorkIoPool& operator=(const WorkIoPool&) = delete;
  WorkIoReply Reserve();
  // The caller retains ownership and keeps these numbers stable through this
  // call (normally the private received-message object does so). -1 is Closed.
  // No user data is read/written, no flags/offsets are changed on the OFD.
  // Existing means no new descriptors were imported, not that supplied FDs
  // were compared for equivalence. Start retries use the returned binding.
  WorkIoReply Capture(const WorkIoReservation& ticket,
                      const std::array<int, 3>& descriptors);
  // Cancellation before Capture prevents its claim. Once Capture claimed the
  // slot, cancellation retains it until that actual operation finishes.
  bool Cancel(const WorkIoReservation& ticket);
  WorkIoBinding Find(WorkIoIdentity identity) const;
  // Drop discovery, not borrowed FD authority. Already held values/jobs retain
  // their actual descriptors, and pin capacity until those values are gone.
  bool Forget(const WorkIoBinding& binding);
  WorkIoUsage usage() const;
  void Close();

 private:
  std::shared_ptr<work_io_detail::Pool> state_;
};

}  // namespace andrix
