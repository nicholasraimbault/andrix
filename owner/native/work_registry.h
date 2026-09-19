// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "launch_description.h"
#include "work_admission.h"
#include "work_io.h"

namespace andrix {
namespace work_detail {
struct Registry;
struct Record;
struct Stream;
}  // namespace work_detail

// Internal metadata/control component, not a public transport or authenticator.
// A trusted adapter supplies a manager incarnation that is never reused in its
// enclosing authenticated namespace, authenticates every caller and owns all
// kernel resources. No ID, sequence or byte string below is authentication.
struct WorkRegistryLimits {
  size_t records;
  size_t request_streams;
  size_t creators;
  LaunchLimits launch;
  uint64_t work_serial_limit;
  uint64_t stream_serial_limit;
  uint64_t operation_limit;
};  // Explicit configuration; implementation ceilings are not product quotas.

enum class WorkRegistryResult {
  Accepted,
  Existing,
  Pending,
  Invalid,
  Foreign,
  Stale,
  Capacity,
  Exhausted,
  Closed,
  Conflict,
  WrongState,
  Incomplete
};
enum class WorkInitialState {
  NotRequested,
  Unknown,
  Absent,
  Owned,
  Exited,
  Reaped
};
enum class WorkScopeState {
  NotRequested,
  Unknown,
  Absent,
  Captured,
  Reclaimed
};
enum class WorkPopulation { Unknown, Populated, Empty };
enum class WorkExitKind { Unknown, Code, Signal };
struct WorkExit {
  WorkExitKind kind = WorkExitKind::Unknown;
  int value = 0;
  bool operator==(const WorkExit&) const = default;
};
struct WorkScopeIdentity {
  uint64_t device = 0, inode = 0;
  bool operator==(const WorkScopeIdentity&) const = default;
};
enum class WorkResourceFact { Absent, Captured, Unknown };
enum class WorkCleanupResult { Progress, Failed, Reclaimed };
enum class WorkRegistryFault {
  None,
  UnknownResources,
  SequenceExhausted,
  InvalidAdmission
};
enum class WorkStopSource : uint32_t {
  Owner = 1,
  Authority = 2,
  Manager = 4,
  BackendFailure = 8
};

struct WorkSnapshot {
  WorkIdentity work{};
  uint64_t stream = 0, request_sequence = 0;
  bool start_accepted = false, admission_pending = false,
       creator_pending = false;
  bool stdio_configured = false, stdio_closed_plan = false;
  WorkIoIdentity stdio{};
  // Claim is permission, not an ordinary exec acknowledgement. Gate closure
  // alone is not whole-work Stop (ordinary initial exit closes entry only).
  bool entry_claimed = false, entry_gate_closed = false;
  // Known requests, not a claim of exclusive physical causation. Frozen when
  // complete; late Stop cannot rewrite the completed result.
  uint32_t stop_sources = 0;
  std::optional<AuthorityEpoch> epoch;
  AdmissionResult admission = AdmissionResult::Invalid;
  WorkInitialState initial = WorkInitialState::NotRequested;
  WorkExit initial_exit;
  WorkScopeState scope = WorkScopeState::NotRequested;
  WorkScopeIdentity scope_identity;
  WorkPopulation population = WorkPopulation::Unknown;
  bool observation_pending = false, cleanup_pending = false;
  bool blocked = false, complete = false, forgotten = false;
  WorkRegistryFault fault = WorkRegistryFault::None;
  int launch_error = 0, cleanup_error = 0;
};

class WorkRegistry;
class WorkBackend;
class WorkObservation;
class WorkCleanup;

// Values hold bounded registry records alive, never a reusable slot address.
// A forgotten record cannot free its slot while a control/backend/ticket owns
// it. These C++ values stay in trusted management code; do not transfer gates
// or management descriptors to ordinary payloads.
class WorkControl {
 public:
  WorkControl() = default;
  explicit operator bool() const { return bool(record_); }
  WorkIdentity identity() const;
  // No registry/record/admission mutex, allocation, syscall or external I/O.
  // Always closes the actual entry gate before returning. True means the
  // first Owner stop request, NOT process termination or cleanup completion.
  bool Stop() const;
  WorkSnapshot Inspect() const;

 private:
  friend class WorkRegistry;
  explicit WorkControl(std::shared_ptr<work_detail::Record> record);
  std::shared_ptr<work_detail::Record> record_;
};

// One authenticated caller request stream, not necessarily one connection.
// The adapter must retain/recover THIS stream across a lost reply. Sequence
// numbers increase within it. Reordering past a newer accepted sequence is
// refused, not treated as permission to allocate a replacement reservation.
class WorkRequestStream {
 public:
  WorkRequestStream() = default;
  explicit operator bool() const { return bool(stream_); }
  uint64_t identity() const;

 private:
  friend class WorkRegistry;
  explicit WorkRequestStream(std::shared_ptr<work_detail::Stream> stream);
  std::shared_ptr<work_detail::Stream> stream_;
};

// Reserve capacity BEFORE memfd allocation. The allocator owns this ticket
// until it reports definite completion; cancellation never frees its slot.
class WorkReservation {
 public:
  WorkReservation() = default;
  explicit operator bool() const { return bool(issuer_); }
  WorkIdentity identity() const { return work_; }

 private:
  friend class WorkRegistry;
  WorkReservation(std::shared_ptr<work_detail::Registry> issuer,
                  WorkIdentity work);
  std::shared_ptr<work_detail::Registry> issuer_;
  WorkIdentity work_{};
};
struct WorkReserveReply {
  WorkRegistryResult result = WorkRegistryResult::Invalid;
  WorkIdentity work{};
  WorkReservation allocation{};
  WorkControl control{};
  int error = 0;
};
struct WorkRegistryUsage {
  size_t records = 0, allocating = 0, streams = 0, creators = 0;
  bool closed = false;
};

// Single initial creator per work in this slice. All suboperations must cease
// before CreatorFinished. A timeout or destroying this value does NOT attest
// cessation or release its creator slot. There is no replacement creator API.
// Resource/exit facts are supplied by the trusted adapter, not measured here.
class WorkBackend {
 public:
  WorkBackend() = default;
  explicit operator bool() const { return bool(record_); }
  WorkIdentity identity() const;
  const std::vector<uint8_t>& description() const;
  // Identity only. Metadata never owns the creator's live standard descriptors.
  const WorkIoBinding& stdio() const;
  // Borrow only while this backend lease lives. The platform/launcher may
  // retain references for their actual obligations, never expose them to an
  // owner caller or retain unaccounted weak references after retirement.
  const std::shared_ptr<WorkAdmission>& gate() const;
  // Called AFTER the genuine platform adapter binds the original gate. No
  // payload resource/process creation is permitted until this returns true.
  // A declared refusal consumes the attempt, never a retry under new authority.
  // Misordered/contradictory adapter facts instead quarantine the occupied
  // slot.
  bool AdmissionFinished(AdmissionResult result) const;
  bool CaptureScope(WorkScopeIdentity identity) const;
  bool InitialCreated() const;
  bool InitialExited(WorkExit result) const;
  bool InitialReaped() const;
  bool CreatorFinished(WorkResourceFact initial, WorkResourceFact scope,
                       int launch_error = 0) const;
  // Requests termination, independent of ordinary initial process exit.
  bool Abort(int error) const;
  bool termination_requested() const;
  std::optional<WorkObservation> Observe() const;
  std::optional<WorkCleanup> Reclaim() const;

 private:
  friend class WorkRegistry;
  explicit WorkBackend(std::shared_ptr<work_detail::Record> record);
  std::shared_ptr<work_detail::Record> record_;
};
struct WorkStartReply {
  WorkRegistryResult result = WorkRegistryResult::Invalid;
  WorkBackend backend{};
  // The adapter transfers this lease to the actual creator and releases it
  // after descriptor handoff/cancellation. Do not retain it as result metadata.
  WorkIoLease stdio_lease{};
};

class WorkObservation {
 public:
  WorkObservation() = default;
  // Read must start after issue, against the retained exact captured scope.
  bool Finish(WorkPopulation population) const;
  // Invalidate evidence but retain the occupied reader until Finish or a
  // verified Ceased acknowledgement, not just a request to cancel it.
  bool TimedOut() const;
  bool Ceased() const;

 private:
  friend class WorkBackend;
  WorkObservation(std::shared_ptr<work_detail::Record> record,
                  uint64_t sequence);
  std::shared_ptr<work_detail::Record> record_;
  uint64_t sequence_ = 0;
};
class WorkCleanup {
 public:
  WorkCleanup() = default;
  // Reclaimed attests actual complete removal AND retirement of backend scope
  // controls. Missing paths, errors and worker death are not that evidence.
  bool Finish(WorkCleanupResult result, int error = 0) const;
  bool TimedOut() const;
  bool Ceased() const;

 private:
  friend class WorkBackend;
  WorkCleanup(std::shared_ptr<work_detail::Record> record, uint64_t sequence);
  std::shared_ptr<work_detail::Record> record_;
  uint64_t sequence_ = 0;
};

class WorkRegistry {
 public:
  static constexpr size_t kMaximumRecords = 256, kMaximumStreams = 256;
  WorkRegistry(uint64_t manager, WorkRegistryLimits limits);
  ~WorkRegistry();
  WorkRegistry(const WorkRegistry&) = delete;
  WorkRegistry& operator=(const WorkRegistry&) = delete;
  bool valid() const;
  WorkRequestStream OpenStream();
  // Authenticated reconnection only. A numeric stream ID is not permission.
  WorkRequestStream FindStream(uint64_t identity) const;
  bool CloseStream(const WorkRequestStream& stream);
  WorkReserveReply Reserve(const WorkRequestStream& stream, uint64_t sequence);
  // Real WorkAdmission::Reserve runs outside this component's locks, once per
  // allocation ticket. Failed/late completion still consumes its exact slot.
  WorkReserveReply ReservationFinished(const WorkReservation& ticket,
                                       std::shared_ptr<WorkAdmission> gate,
                                       int error = 0);
  bool CancelReservation(const WorkReservation& ticket);
  WorkControl Find(WorkIdentity identity) const;
  std::vector<WorkSnapshot> List() const;
  // Request bytes and the actual immutable standard-stream binding are both
  // accepted once. A new binding with matching numeric metadata is not a retry.
  // New Start requires a live lease. A token without descriptors can report an
  // identical accepted retry, never create new work from retired input
  // resources. Default is explicitly closed stdio, never inherited coordinator
  // handles. General descriptor maps and authenticated public import remain
  // separate.
  WorkStartReply Start(const WorkControl& work,
                       const std::vector<uint8_t>& encoded_description,
                       const WorkIoLease& stdio = WorkIoLease::Closed());
  // Complete work only. Removes discovery/retry visibility, not any kernel
  // resource. Existing handles remain exact and keep this bounded slot owned.
  WorkRegistryResult Forget(const WorkControl& work);
  WorkRegistryUsage usage() const;
  // Permanent admission closure; also cancels outstanding reservations. The
  // adapter still owes creator cessation, termination and real cleanup. Neither
  // this call nor the destructor is a claim of completed kernel cleanup.
  void Close(WorkStopSource source = WorkStopSource::Manager);

 private:
  std::shared_ptr<work_detail::Registry> state_;
};

}  // namespace andrix
