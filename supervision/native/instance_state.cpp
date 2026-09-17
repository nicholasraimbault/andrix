// SPDX-License-Identifier: Apache-2.0
#include "instance_state.h"

#include <algorithm>
#include <limits>

namespace andrix::supervision {
namespace {
bool valid_limits(InstanceLimits limits) {
  return limits.max_pending_mutations <=
         InstanceLimits::kMaximumMutationCapacity;
}
}  // namespace

InstanceState::InstanceState(InstanceId identity, InstanceLimits limits)
    : identity_(identity),
      limits_(limits),
      mutations_(valid_limits(limits) ? limits.max_pending_mutations : 0, 0) {
  if (!identity.valid())
    fail_closed(InstanceFault::InvalidIdentity);
  else if (!valid_limits(limits))
    fail_closed(InstanceFault::InvalidLimits);
}
void InstanceState::invalidate_population() {
  population_ = Population::Unknown;
  population_boundary_.reset();
  population_sequence_ = 0;
}
void InstanceState::fail_closed(InstanceFault fault) {
  if (fault_ == InstanceFault::None) fault_ = fault;
  stop_latched_ = true;
  active_ = false;
  cleanup_ = Cleanup::Blocked;
  invalidate_population();
}
bool InstanceState::advance_boundary() {
  invalidate_population();
  if (fault_ != InstanceFault::None) return false;
  if (boundary_ >= limits_.max_boundary ||
      boundary_ == std::numeric_limits<uint64_t>::max()) {
    fail_closed(InstanceFault::BoundaryExhausted);
    return false;
  }
  ++boundary_;
  return true;
}
std::optional<uint64_t> InstanceState::issue_sequence() {
  if (fault_ != InstanceFault::None) return {};
  if (operation_sequence_ >= limits_.max_operation_sequence ||
      operation_sequence_ == std::numeric_limits<uint64_t>::max()) {
    fail_closed(InstanceFault::SequenceExhausted);
    return {};
  }
  return ++operation_sequence_;
}
std::optional<MutationTicket> InstanceState::begin_mutation(InstanceId ref) {
  if (ref != identity_ || stop_latched_ || fault_ != InstanceFault::None ||
      cleanup_ != Cleanup::NotStarted ||
      pending_mutations_ >= mutations_.size())
    return {};
  auto sequence = issue_sequence();
  if (!sequence || !advance_boundary()) return {};
  auto free = std::find(mutations_.begin(), mutations_.end(), 0);
  if (free == mutations_.end())
    return {};  // Capacity was checked; no external work issued.
  *free = *sequence;
  ++pending_mutations_;
  if (!activated_once_) setup_complete_ = false;
  return MutationTicket(identity_, *sequence);
}
bool InstanceState::finish_mutation(const MutationTicket& ticket) {
  if (ticket.instance() != identity_ || ticket.sequence() == 0) return false;
  auto found =
      std::find(mutations_.begin(), mutations_.end(), ticket.sequence());
  if (found == mutations_.end()) return false;
  *found = 0;
  --pending_mutations_;
  advance_boundary();  // Even a failed/exhausted instance must retain late
                       // resource facts.
  return true;
}
bool InstanceState::capture_root(InstanceId ref) {
  if (ref != identity_ || root_bound_ || cleanup_ == Cleanup::Retired)
    return false;
  root_bound_ = true;
  advance_boundary();
  return true;
}
bool InstanceState::verify_profile(InstanceId ref) {
  if (ref != identity_ || cleanup_ == Cleanup::Retired) return false;
  profile_verified_ = true;
  return true;
}
bool InstanceState::complete_setup(InstanceId ref) {
  if (ref != identity_ || !root_bound_ || !profile_verified_ ||
      process_exited_ || stop_latched_ || fault_ != InstanceFault::None ||
      pending_mutations_ != 0 || cleanup_ != Cleanup::NotStarted)
    return false;
  setup_complete_ = true;
  return true;
}
bool InstanceState::activate(InstanceId ref) {
  if (ref != identity_ || activated_once_ || stop_latched_ || process_exited_ ||
      fault_ != InstanceFault::None || !root_bound_ || !profile_verified_ ||
      !setup_complete_ || pending_mutations_ != 0 ||
      cleanup_ != Cleanup::NotStarted)
    return false;
  activated_once_ = active_ = true;
  return true;
}
bool InstanceState::stop(InstanceId ref) {
  if (ref != identity_) return false;
  if (cleanup_ == Cleanup::Retired || stop_latched_) return true;
  stop_latched_ = true;
  active_ = false;
  cleanup_ = Cleanup::Stopping;
  advance_boundary();
  return true;
}
bool InstanceState::report_initial_process_exit(InstanceId ref) {
  if (ref != identity_ || cleanup_ == Cleanup::Retired) return false;
  if (!process_exited_) {
    process_exited_ = true;
    active_ = false;
    advance_boundary();
  }
  stop(ref);
  return true;
}
bool InstanceState::report_initial_process_reaped(InstanceId ref) {
  if (ref != identity_ || !process_exited_ || cleanup_ == Cleanup::Retired)
    return false;
  if (!process_reaped_) {
    process_reaped_ = true;
    advance_boundary();
  }
  return true;
}
std::optional<ObservationTicket> InstanceState::begin_observation(
    InstanceId ref) {
  if (ref != identity_ || !root_bound_ || observation_ || cleanup_step_ ||
      fault_ != InstanceFault::None || cleanup_ == Cleanup::Retired)
    return {};
  const auto sequence = issue_sequence();
  if (!sequence) return {};
  invalidate_population();
  observation_expired_ = false;
  observation_.emplace(ObservationTicket(identity_, *sequence, boundary_));
  return observation_;
}
bool InstanceState::finish_observation(const ObservationTicket& ticket,
                                       Population population) {
  if (!observation_ || ticket != *observation_) return false;
  const bool current = ticket.instance() == identity_ &&
                       ticket.boundary() == boundary_ &&
                       fault_ == InstanceFault::None &&
                       cleanup_ != Cleanup::Retired && !observation_expired_;
  observation_.reset();
  observation_expired_ = false;
  if (!current) return false;
  switch (population) {
    case Population::Empty:
    case Population::Populated:
      population_ = population;
      population_boundary_ = boundary_;
      population_sequence_ = ticket.sequence();
      if (stop_latched_ && population != Population::Empty) block_cleanup();
      return true;
    case Population::Unknown:
      invalidate_population();
      if (stop_latched_) block_cleanup();
      return true;
    case Population::Removed:
      // A missing read cannot authorize retirement; actual removal has a
      // distinct result.
      invalidate_population();
      if (stop_latched_) block_cleanup();
      return false;
  }
  invalidate_population();
  if (stop_latched_) block_cleanup();
  return false;
}
bool InstanceState::observation_timed_out(const ObservationTicket& ticket) {
  if (!observation_ || ticket != *observation_) return false;
  observation_expired_ = true;
  invalidate_population();
  if (stop_latched_) block_cleanup();
  return true;
}
bool InstanceState::acknowledge_observation_cancellation(
    const ObservationTicket& ticket) {
  if (!observation_ || ticket != *observation_) return false;
  observation_.reset();
  observation_expired_ = false;
  invalidate_population();
  return true;
}
bool InstanceState::closed_empty_boundary() const {
  return fault_ == InstanceFault::None && stop_latched_ && root_bound_ &&
         process_exited_ && process_reaped_ && pending_mutations_ == 0 &&
         !observation_ && population_ == Population::Empty &&
         population_boundary_ && *population_boundary_ == boundary_ &&
         population_sequence_ != 0;
}
bool InstanceState::can_begin_cleanup() const {
  return cleanup_ != Cleanup::Retired && !cleanup_step_ &&
         closed_empty_boundary();
}
std::optional<CleanupTicket> InstanceState::begin_cleanup_step(InstanceId ref) {
  if (ref != identity_ || !can_begin_cleanup()) return {};
  const auto sequence = issue_sequence();
  if (!sequence) return {};
  cleanup_step_.emplace(
      CleanupTicket(identity_, *sequence, boundary_, population_sequence_));
  cleanup_ = Cleanup::Reclaiming;
  return cleanup_step_;
}
bool InstanceState::cleanup_timed_out(const CleanupTicket& ticket) {
  if (!cleanup_step_ || ticket != *cleanup_step_) return false;
  cleanup_ = Cleanup::Blocked;  // Do not free the still executing worker slot.
  return true;
}
void InstanceState::block_cleanup() {
  if (cleanup_ != Cleanup::Retired) cleanup_ = Cleanup::Blocked;
}
bool InstanceState::finish_cleanup_step(const CleanupTicket& ticket,
                                        CleanupResult result) {
  if (!cleanup_step_ || ticket != *cleanup_step_) return false;
  cleanup_step_.reset();
  if (ticket.instance() != identity_ || ticket.boundary() != boundary_ ||
      ticket.observation_sequence() != population_sequence_ ||
      !closed_empty_boundary()) {
    block_cleanup();
    invalidate_population();
    return false;
  }
  switch (result) {
    case CleanupResult::Reclaimed:
      population_ = Population::Removed;
      cleanup_ = Cleanup::Retired;
      return true;
    case CleanupResult::Progress:
      // A timed out step remains explicitly Blocked. The controller decides
      // retry policy.
      if (cleanup_ != Cleanup::Blocked) cleanup_ = Cleanup::Reclaiming;
      return true;
    case CleanupResult::Failed:
      block_cleanup();
      invalidate_population();
      return true;
  }
  block_cleanup();
  invalidate_population();
  return false;
}
bool InstanceState::acknowledge_cleanup_cancellation(
    const CleanupTicket& ticket) {
  if (!cleanup_step_ || ticket != *cleanup_step_) return false;
  cleanup_step_.reset();
  invalidate_population();
  block_cleanup();
  return true;
}
bool InstanceState::restart_allowed() const {
  return fault_ == InstanceFault::None && cleanup_ == Cleanup::Retired &&
         pending_mutations_ == 0 && !observation_ && !cleanup_step_ &&
         stop_latched_ && process_exited_ && process_reaped_ && !active_;
}
InstanceAllocator::InstanceAllocator(uint64_t boot, uint64_t max_serial)
    : boot_(boot), max_serial_(max_serial) {
  if (!boot_) fault_ = SlotFault::InvalidBoot;
}
std::optional<InstanceId> InstanceAllocator::allocate() {
  if (fault_ != SlotFault::None) return {};
  if (serial_ >= max_serial_ ||
      serial_ == std::numeric_limits<uint64_t>::max()) {
    fault_ = SlotFault::SerialExhausted;
    return {};
  }
  return InstanceId(boot_, ++serial_);
}
ServiceSlot::ServiceSlot(InstanceAllocator& allocator, InstanceLimits limits)
    : allocator_(allocator), limits_(limits) {
  if (!valid_limits(limits)) fault_ = SlotFault::InvalidLimits;
}
InstanceState* ServiceSlot::start() {
  if (fault_ != SlotFault::None || (current_ && !current_->restart_allowed()))
    return nullptr;
  auto identity = allocator_.allocate();
  if (!identity) {
    fault_ = allocator_.fault();
    return nullptr;
  }
  current_.emplace(*identity, limits_);
  return &*current_;
}
}  // namespace andrix::supervision
