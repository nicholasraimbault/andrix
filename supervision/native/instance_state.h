// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace andrix::supervision {

// Identity, not authorization. The owner supplies a boot incarnation that is
// not reused and allocates serials uniquely in that boot. Zero components are
// invalid.
class InstanceId {
 public:
  constexpr InstanceId(std::uint64_t boot, std::uint64_t serial)
      : boot_(boot), serial_(serial) {}
  constexpr std::uint64_t boot() const { return boot_; }
  constexpr std::uint64_t serial() const { return serial_; }
  constexpr bool valid() const { return boot_ != 0 && serial_ != 0; }
  bool operator==(const InstanceId&) const = default;

 private:
  const std::uint64_t boot_;
  const std::uint64_t serial_;
};

// All limits are caller configuration, not product defaults. Zero capacity
// disables mutations. Zero counter limits cause exhaustion on the first
// advance. Construction allocates the bounded mutation table before any
// external work.
struct InstanceLimits {
  static constexpr std::size_t kMaximumMutationCapacity = 4096;
  std::size_t max_pending_mutations;
  std::uint64_t max_operation_sequence;
  std::uint64_t max_boundary;
};

enum class Population { Unknown, Populated, Empty, Removed };
enum class Cleanup { NotStarted, Stopping, Reclaiming, Blocked, Retired };
enum class InstanceFault {
  None,
  InvalidIdentity,
  InvalidLimits,
  SequenceExhausted,
  BoundaryExhausted
};
enum class SlotFault { None, InvalidBoot, InvalidLimits, SerialExhausted };
enum class CleanupResult { Progress, Failed, Reclaimed };

class InstanceState;

// Only InstanceState can issue tickets. Copies correlate a completion, not a
// second worker. Ticket types cannot be substituted for one another.
class MutationTicket {
 public:
  const InstanceId& instance() const { return instance_; }
  std::uint64_t sequence() const { return sequence_; }
  bool operator==(const MutationTicket&) const = default;

 private:
  friend class InstanceState;
  MutationTicket(InstanceId instance, std::uint64_t sequence)
      : instance_(instance), sequence_(sequence) {}
  const InstanceId instance_;
  const std::uint64_t sequence_;
};

class ObservationTicket {
 public:
  const InstanceId& instance() const { return instance_; }
  std::uint64_t sequence() const { return sequence_; }
  std::uint64_t boundary() const { return boundary_; }
  bool operator==(const ObservationTicket&) const = default;

 private:
  friend class InstanceState;
  ObservationTicket(InstanceId instance, std::uint64_t sequence,
                    std::uint64_t boundary)
      : instance_(instance), sequence_(sequence), boundary_(boundary) {}
  const InstanceId instance_;
  const std::uint64_t sequence_;
  const std::uint64_t boundary_;
};

class CleanupTicket {
 public:
  const InstanceId& instance() const { return instance_; }
  std::uint64_t sequence() const { return sequence_; }
  std::uint64_t boundary() const { return boundary_; }
  std::uint64_t observation_sequence() const { return observation_sequence_; }
  bool operator==(const CleanupTicket&) const = default;

 private:
  friend class InstanceState;
  CleanupTicket(InstanceId instance, std::uint64_t sequence,
                std::uint64_t boundary, std::uint64_t observation_sequence)
      : instance_(instance),
        sequence_(sequence),
        boundary_(boundary),
        observation_sequence_(observation_sequence) {}
  const InstanceId instance_;
  const std::uint64_t sequence_;
  const std::uint64_t boundary_;
  const std::uint64_t observation_sequence_;
};

// Internal ordering component, not a wire ABI or an Android/kernel authority.
// One owner/event loop serializes every call. There is no I/O, locking, clock
// or worker here. Issue a ticket, perform bounded external work without
// borrowing this object, then deliver its result on the owner's loop.
//
// The adapter retains the exact root and initial SERVICE process ownership.
// Root capture is single assignment. A path, recycled descriptor number, old
// PID or pidfd is never numeric process lifetime authority. Supplied profile,
// setup, exit, reap and reclamation facts must be verified by the trusted
// adapter.
//
// Every external creator/mutator must hold a mutation ticket before doing work,
// including creation that finishes after Stop. Completion means it can do no
// further mutation and all its late resources remain owned. Stop must also
// fence any delegated creators not represented here. Cleanup runs only after
// this fence, initial service exit AND reap, and fresh exact-root Empty
// evidence. Signals and staged child termination precede reclamation and live
// elsewhere. An owner shell exit is not an initial service exit.
//
// Observation reads must start AFTER ticket issuance against the captured root.
// Invalidation keeps the reader slot occupied. Cleanup Progress means bounded
// removal work only, never adding members/directories. Reclaimed attests actual
// authoritative removal of that original root and its descendants, not request
// acceptance, a missing read, or a worker disappearing. No accounting
// completion or kernel authority is inferred by this component.
//
// Exhaustion is permanent Blocked quarantine: no new operation or activation,
// no retirement/restart, no counter wrap. Exact outstanding results still
// consume their own slots, and late root ownership is still recorded. Boolean
// returns report event acceptance, not cleanup success. Inspect fault() and
// cleanup().
class InstanceState {
 public:
  InstanceState(InstanceId identity, InstanceLimits limits);
  InstanceState(const InstanceState&) = delete;
  InstanceState& operator=(const InstanceState&) = delete;
  InstanceState(InstanceState&&) = delete;
  InstanceState& operator=(InstanceState&&) = delete;

  const InstanceId& identity() const { return identity_; }
  InstanceFault fault() const { return fault_; }
  Cleanup cleanup() const { return cleanup_; }
  Population population() const { return population_; }
  bool root_bound() const { return root_bound_; }
  bool profile_verified() const { return profile_verified_; }
  bool setup_complete() const { return setup_complete_; }
  bool active() const { return active_; }
  bool activated_once() const { return activated_once_; }
  bool stop_latched() const { return stop_latched_; }
  bool process_exited() const { return process_exited_; }
  bool process_reaped() const { return process_reaped_; }
  bool initial_process_absent() const { return initial_process_absent_; }
  std::size_t pending_mutations() const { return pending_mutations_; }
  bool observation_pending() const { return observation_.has_value(); }
  bool cleanup_pending() const { return cleanup_step_.has_value(); }
  std::uint64_t boundary() const { return boundary_; }
  std::uint64_t operation_sequence() const { return operation_sequence_; }

  std::optional<MutationTicket> begin_mutation(InstanceId ref);
  bool finish_mutation(const MutationTicket& ticket);
  bool capture_root(InstanceId ref);  // Late successful creation remains owned.
  bool verify_profile(InstanceId ref);
  // Attests complete setup/readiness of the actual initial service process.
  // A new preparation mutation invalidates this attestation before activation.
  bool complete_setup(InstanceId ref);
  bool activate(
      InstanceId ref);        // At most once; not an external release write.
  bool stop(InstanceId ref);  // Idempotent for this exact instance.
  bool report_initial_process_exit(InstanceId ref);
  // Reap cannot stand in for the separate exit fact. It grants no signal right.
  bool report_initial_process_reaped(InstanceId ref);
  // All creators have ceased and no initial process was created. This is not an
  // invented exit/reap result. It closes activation after a definite start
  // failure.
  bool report_no_initial_process(InstanceId ref);
  // Definite failure before root allocation, with no remaining owned resources.
  // The adapter must not use this for an uncertain mkdir/fork result or a
  // leftover root.
  bool retire_unallocated(InstanceId ref);

  std::optional<ObservationTicket> begin_observation(InstanceId ref);
  // An exact stale reply consumes its own slot but returns false and applies no
  // evidence. A duplicate/foreign reply cannot consume a currently occupied
  // slot. Removed is not an observation result. Only authoritative reclamation
  // sets it.
  bool finish_observation(const ObservationTicket& ticket,
                          Population population);
  // Separate authoritative reconciliation after a lost cleanup reply. The
  // adapter must have proved removal through its original captured descriptor
  // cohort and absent owned entry. Not a failed path read or generic Removed
  // enum.
  bool finish_confirmed_removal(const ObservationTicket& ticket);
  // Expiry invalidates evidence but retains the occupied reader slot. A late
  // result consumes that slot without becoming a fresh observation.
  bool observation_timed_out(const ObservationTicket& ticket);
  // Acknowledgement that the worker has ceased, NOT a cancellation request.
  bool acknowledge_observation_cancellation(const ObservationTicket& ticket);

  bool can_begin_cleanup() const;
  std::optional<CleanupTicket> begin_cleanup_step(InstanceId ref);
  // Timeout retains the slot and evidence. No replacement worker may be issued
  // until an exact result or confirmed cancellation acknowledgement consumes
  // it.
  bool cleanup_timed_out(const CleanupTicket& ticket);
  // Failed consumes a finished worker, retains ownership, and requires a new
  // observation before retry. Progress permits another bounded step. A matching
  // late Reclaimed result can retire even after timeout, but never after
  // Unknown.
  bool finish_cleanup_step(const CleanupTicket& ticket, CleanupResult result);
  bool acknowledge_cleanup_cancellation(const CleanupTicket& ticket);
  bool restart_allowed() const;

 private:
  void invalidate_population();
  void fail_closed(InstanceFault fault);
  bool advance_boundary();
  std::optional<std::uint64_t> issue_sequence();
  bool closed_empty_boundary() const;
  void block_cleanup();

  const InstanceId identity_;
  const InstanceLimits limits_;
  // Zero is vacant. Issued sequences start at one and are never reused.
  std::vector<std::uint64_t> mutations_;
  std::size_t pending_mutations_ = 0;
  std::optional<ObservationTicket> observation_;
  std::optional<CleanupTicket> cleanup_step_;
  std::uint64_t boundary_ = 0;
  std::uint64_t operation_sequence_ = 0;
  std::optional<std::uint64_t> population_boundary_;
  std::uint64_t population_sequence_ = 0;
  InstanceFault fault_ = InstanceFault::None;
  Cleanup cleanup_ = Cleanup::NotStarted;
  Population population_ = Population::Unknown;
  bool root_bound_ = false;
  bool profile_verified_ = false;
  bool setup_complete_ = false;
  bool active_ = false;
  bool activated_once_ = false;
  bool stop_latched_ = false;
  bool process_exited_ = false;
  bool process_reaped_ = false;
  bool initial_process_absent_ = false;
  bool observation_expired_ = false;
};

// Shared by all service slots in one supervisor boot. It must outlive those
// slots; reconstructing it with the same boot identity would reuse serials.
// Instance values and tickets are still not caller authorization.
class InstanceAllocator {
 public:
  InstanceAllocator(std::uint64_t boot, std::uint64_t max_serial);
  InstanceAllocator(const InstanceAllocator&) = delete;
  InstanceAllocator& operator=(const InstanceAllocator&) = delete;
  std::optional<InstanceId> allocate();
  SlotFault fault() const { return fault_; }
  std::uint64_t serial() const { return serial_; }

 private:
  const std::uint64_t boot_;
  const std::uint64_t max_serial_;
  std::uint64_t serial_ = 0;
  SlotFault fault_ = SlotFault::None;
};

// One declared service's restart fence. Identity allocation is shared, not
// independently restarted at serial one for each service definition.
class ServiceSlot {
 public:
  ServiceSlot(InstanceAllocator& allocator, InstanceLimits limits);
  ServiceSlot(const ServiceSlot&) = delete;
  ServiceSlot& operator=(const ServiceSlot&) = delete;
  ServiceSlot(ServiceSlot&&) = delete;
  ServiceSlot& operator=(ServiceSlot&&) = delete;

  // Borrowed pointer, valid only until the next successful start. Workers keep
  // copied tickets/identities, never pointers to this replaceable owner state.
  InstanceState* start();
  InstanceState* current() { return current_ ? &*current_ : nullptr; }
  const InstanceState* current() const {
    return current_ ? &*current_ : nullptr;
  }
  SlotFault fault() const { return fault_; }

 private:
  InstanceAllocator& allocator_;
  const InstanceLimits limits_;
  SlotFault fault_ = SlotFault::None;
  std::optional<InstanceState> current_;
};

}  // namespace andrix::supervision
