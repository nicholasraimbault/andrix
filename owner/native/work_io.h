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
struct Descriptors;
}  // namespace work_io_detail

struct WorkIoIdentity {
  uint64_t manager = 0, serial = 0;
  bool operator==(const WorkIoIdentity&) const = default;
};
enum class WorkIoResult {
  Accepted,
  Existing,
  Pending,
  Invalid,
  Foreign,
  Stale,
  Capacity,
  Exhausted,
  Closed,
  Io
};

// Immutable identity/role token, not ownership of live descriptors. Keeping
// work metadata must not suppress pipe EOF or terminal hangup.
class WorkIoBinding {
 public:
  WorkIoBinding() = default;
  static WorkIoBinding Closed();
  explicit operator bool() const { return closed_plan_ || bool(binding_); }
  bool closed_plan() const { return closed_plan_; }
  WorkIoIdentity identity() const;
  bool operator==(const WorkIoBinding& other) const {
    return closed_plan_ == other.closed_plan_ && binding_ == other.binding_;
  }

 private:
  friend class WorkIoPool;
  explicit WorkIoBinding(std::shared_ptr<work_io_detail::Binding> binding);
  std::shared_ptr<work_io_detail::Binding> binding_;
  bool closed_plan_ = false;
};

// A separate live descriptor lease for the actual creator/handoff operation.
// Drop it after successful descriptor handoff or definite cancellation, not
// when historical work metadata is finally forgotten. File contents, offsets
// and status flags retain ordinary shared Unix semantics.
class WorkIoLease {
 public:
  WorkIoLease() = default;
  static WorkIoLease Closed();
  static WorkIoLease Reference(const WorkIoBinding& binding);
  const WorkIoBinding& binding() const { return binding_; }
  bool available() const {
    return binding_.closed_plan() || bool(descriptors_);
  }
  // Borrow only while this live lease is retained. -1 deliberately closes that
  // standard descriptor. Never close/replace/change flags on a borrowed number.
  int descriptor(size_t standard) const;
  // Releases resources, retaining only the immutable token for exact retries.
  void Release();

 private:
  friend class WorkIoPool;
  WorkIoLease(WorkIoBinding binding,
              std::shared_ptr<work_io_detail::Descriptors> descriptors);
  WorkIoBinding binding_;
  std::shared_ptr<work_io_detail::Descriptors> descriptors_;
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

// Internal standard stream slice, not a complete arbitrary FD public API.
// Authenticated ingress also bounds its temporary SCM_RIGHTS receipts.
// Reserve accounts a set before Capture duplicates outside the pool mutex.
// Capture claims once per ticket; timeout does not reset an outstanding copy.
class WorkIoPool {
 public:
  static constexpr size_t kMaximumBindings = 256;
  WorkIoPool(uint64_t manager, size_t capacity, uint64_t serial_limit);
  ~WorkIoPool();
  WorkIoPool(const WorkIoPool&) = delete;
  WorkIoPool& operator=(const WorkIoPool&) = delete;
  WorkIoReply Reserve();
  // Caller owns and keeps these numbers stable through this call. -1 is Closed.
  // No user data is read/written or OFD flags/offsets changed. Existing means
  // no new import, NOT equivalence of the newly supplied descriptor numbers.
  WorkIoReply Capture(const WorkIoReservation& ticket,
                      const std::array<int, 3>& descriptors);
  bool Cancel(const WorkIoReservation& ticket);
  WorkIoBinding Find(WorkIoIdentity identity) const;
  // Metadata only, including forgotten bindings still pinned by existing work.
  // This cannot obtain descriptors or authorize a new Start by itself.
  WorkIoBinding FindReference(WorkIoIdentity identity) const;
  WorkIoLease Lease(const WorkIoBinding& binding) const;
  // Drop registration and release its descriptors outside the mutex. Existing
  // creator leases remain live. Metadata references alone do not hold FDs open,
  // but both metadata and actual leases still prevent identity/slot recycling.
  bool Forget(const WorkIoBinding& binding);
  WorkIoUsage usage() const;
  void Close();

 private:
  std::shared_ptr<work_io_detail::Pool> state_;
};

}  // namespace andrix
