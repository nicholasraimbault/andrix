// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <array>
#include <memory>
#include <vector>

#include "work_registry.h"

namespace andrix {
namespace work_catalog_detail {
struct Catalog;
struct Work;
}  // namespace work_catalog_detail

enum class WorkInputState {
  Empty,
  Preparing,
  Ready,
  Consumed,
  Releasing,
  Rejected
};
struct WorkCatalogSnapshot {
  WorkSnapshot work;
  WorkInputState inputs = WorkInputState::Empty;
  WorkIoIdentity input{};
  int input_error = 0;
};

// Exact bound control for the dispatcher. No owner-supplied ID is authority.
// The transport must authenticate its principal before issuing this value.
class WorkHandle {
 public:
  WorkHandle() = default;
  explicit operator bool() const { return bool(work_); }
  WorkIdentity identity() const;
  // Entry closure and input cancellation only, no mutex, allocation or I/O.
  // Preparing inputs remain owned until their actual operation finishes.
  bool Stop() const;
  // Used when an unaccepted management reservation loses its connection.
  // Accepted work is independent of client lifetime and is not stopped here.
  bool CancelUnstarted() const;
  WorkCatalogSnapshot Inspect() const;

 private:
  friend class WorkCatalog;
  explicit WorkHandle(std::shared_ptr<work_catalog_detail::Work> work);
  std::shared_ptr<work_catalog_detail::Work> work_;
};
struct WorkCatalogReply {
  WorkRegistryResult result = WorkRegistryResult::Invalid;
  WorkIdentity identity{};
  WorkHandle work;
  int error = 0;
};
struct WorkInputReply {
  WorkRegistryResult result = WorkRegistryResult::Invalid;
  WorkIoIdentity identity{};
  WorkInputState state = WorkInputState::Empty;
  int error = 0;
};

// Trusted bounded preparation/registry orchestration. No public authenticator,
// process creator, Android lifecycle oracle or persistent activity recorder.
// Reserve and Prepare perform descriptor I/O on caller-owned worker lanes,
// never on a shared Stop loop. The caller must bound those workers/connections.
class WorkCatalog {
 public:
  WorkCatalog(uint64_t manager, WorkRegistryLimits limits);
  ~WorkCatalog();
  WorkCatalog(const WorkCatalog&) = delete;
  WorkCatalog& operator=(const WorkCatalog&) = delete;
  bool valid() const;
  uint64_t OpenStream();
  bool CloseStream(uint64_t stream);
  bool StreamUnused(uint64_t stream) const;
  bool CloseStreamIfUnused(uint64_t stream);
  // A stream/sequence retry returns the original request. Gate allocation is
  // outside registry/control locks. CloseStream cancels unfinished allocations.
  WorkCatalogReply Reserve(uint64_t stream, uint64_t sequence);
  // Observation only, not adoption into a submitting conversation. Neither
  // NotFound nor Stale licenses automatic resubmission under a new key.
  WorkCatalogReply LookupRequest(uint64_t stream, uint64_t sequence);
  // A lookup started before Forget may still obtain the retained canonical
  // handle. It must never recreate catalog metadata after that handle's Work
  // has been collected, even if its temporary registry control is still live.
  WorkHandle Find(WorkIdentity work);
  std::vector<WorkCatalogSnapshot> List();
  // One preparation attempt per reserved work. Descriptors are borrowed from
  // an owned received message and must remain stable through this call. The
  // description must be genuinely read-only and sealed. -1 standard roles
  // explicitly mean Closed. No privileged paths/profiles are caller fields.
  // A duplicate Prepare never imports replacement FDs or claims equivalence.
  // After a lost reply inspect the exact work to recover the original input ID.
  WorkInputReply Prepare(const WorkHandle& work, int description,
                         const std::array<int, 3>& standard);
  // No FD import on Start. Consume the original prepared registration into the
  // returned creator lease BEFORE acknowledging acceptance. Its identity stays
  // retryable, but client loss cannot retain an unclaimed registration writer.
  WorkStartReply Start(const WorkHandle& work, WorkIoIdentity expected_input);
  // After fast Stop, release any unconsumed registration on a worker lane.
  // Pending reads/captures finish their own cancellation. This can wait for
  // actual descriptor release and is NOT part of the fast Stop acknowledgement.
  WorkInputReply CancelInputs(const WorkHandle& work);
  // Complete work only, and no input preparation still pending. Live scope
  // retirement remains the backend's separate obligation.
  WorkRegistryResult Forget(const WorkHandle& work);
  WorkRegistryUsage usage() const;
  void Collect();
  // May release registered user FDs. Run only on a teardown lane, not the CE
  // failure/Stop path. Android's enclosing environment remains the backstop.
  void Close();

 private:
  WorkHandle Capture(const WorkControl& control);
  std::shared_ptr<work_catalog_detail::Catalog> state_;
};

// One management conversation's provisional stream ownership. The catalog must
// outlive this single-lane helper. Other conversations may concurrently use a
// stream; only the registry's atomic unused check can close it on loss. Used
// streams require explicit CloseStream and remain reconnectable. Numeric IDs
// here are issued, non-reused metadata, not authentication or resource handles.
class WorkStreamScope {
 public:
  explicit WorkStreamScope(WorkCatalog& catalog);
  ~WorkStreamScope();
  WorkStreamScope(const WorkStreamScope&) = delete;
  WorkStreamScope& operator=(const WorkStreamScope&) = delete;
  uint64_t OpenStream();
  void CloseUnused();

 private:
  WorkCatalog& catalog_;
  std::vector<uint64_t> streams_;
};

}  // namespace andrix
