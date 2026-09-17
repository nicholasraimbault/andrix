// SPDX-License-Identifier: Apache-2.0
#include "instance_state.h"

#include <cassert>
#include <cstdint>
#include <limits>
#include <type_traits>

using namespace andrix::supervision;
namespace {
constexpr InstanceLimits limits{4, 10000, 10000};
constexpr InstanceId ref{10, 1};
constexpr InstanceId foreign{11, 1};
static_assert(!std::is_convertible_v<MutationTicket, ObservationTicket>);
static_assert(!std::is_convertible_v<ObservationTicket, CleanupTicket>);
static_assert(!std::is_default_constructible_v<MutationTicket>);

void ready(InstanceState& state) {
  auto id = state.identity();
  assert(state.capture_root(id));
  assert(state.verify_profile(id));
  assert(state.complete_setup(id));
  assert(state.activate(id));
}
void close(InstanceState& state) {
  auto id = state.identity();
  assert(state.stop(id));
  assert(state.report_initial_process_exit(id));
  assert(state.report_initial_process_reaped(id));
}
void observe(InstanceState& state, Population value) {
  auto ticket = state.begin_observation(state.identity());
  assert(ticket);
  assert(state.finish_observation(*ticket, value));
}
void retire(InstanceState& state) {
  close(state);
  observe(state, Population::Empty);
  auto ticket = state.begin_cleanup_step(state.identity());
  assert(ticket &&
         state.finish_cleanup_step(*ticket, CleanupResult::Reclaimed));
  assert(state.restart_allowed());
}
void activation_and_exit() {
  InstanceState s(ref, limits);
  assert(!s.activate(ref));
  auto mutation = s.begin_mutation(ref);
  assert(mutation && s.capture_root(ref) && s.verify_profile(ref));
  assert(!s.complete_setup(ref));
  assert(s.finish_mutation(*mutation));
  assert(s.complete_setup(ref));
  auto more = s.begin_mutation(ref);
  assert(more && !s.setup_complete() && !s.activate(ref));
  assert(s.finish_mutation(*more) && s.complete_setup(ref) && s.activate(ref));
  assert(!s.activate(ref));
  assert(!s.report_initial_process_reaped(ref));
  assert(s.report_initial_process_exit(ref));
  assert(!s.active() && s.stop_latched() && !s.activate(ref));
  observe(s, Population::Empty);
  assert(!s.can_begin_cleanup());  // Exit is not reap.
  assert(s.report_initial_process_reaped(ref));
  assert(s.population() == Population::Unknown && !s.can_begin_cleanup());
  observe(s, Population::Empty);
  assert(s.can_begin_cleanup());

  InstanceState early(ref, limits);
  assert(early.capture_root(ref) && early.verify_profile(ref));
  assert(early.report_initial_process_exit(ref));
  assert(!early.complete_setup(ref) && !early.activate(ref));
}
void stop_before_late_creation() {
  InstanceState s(ref, limits);
  auto creation = s.begin_mutation(ref);
  assert(creation && s.stop(ref));
  assert(!s.begin_mutation(ref));
  assert(s.capture_root(ref) && s.verify_profile(ref));
  assert(s.finish_mutation(*creation));
  assert(!s.complete_setup(ref) && !s.activate(ref));
  retire(s);
}
void mutation_and_observation_fences() {
  InstanceState s(ref, limits);
  ready(s);
  auto mutation = s.begin_mutation(ref);
  assert(mutation);
  close(s);
  auto old = s.begin_observation(ref);
  assert(old);
  assert(s.finish_mutation(*mutation));
  assert(s.observation_pending() && !s.begin_observation(ref));
  assert(!s.finish_observation(*old, Population::Empty));
  assert(!s.observation_pending() && s.population() == Population::Unknown);
  assert(!s.can_begin_cleanup());
  observe(s, Population::Empty);
  assert(s.can_begin_cleanup());

  InstanceState cached(ref, limits);
  ready(cached);
  auto m = cached.begin_mutation(ref);
  assert(m);
  close(cached);
  observe(cached, Population::Empty);
  assert(!cached.can_begin_cleanup());
  assert(cached.finish_mutation(*m));
  assert(cached.population() == Population::Unknown &&
         !cached.can_begin_cleanup());
  observe(cached, Population::Empty);
  assert(cached.can_begin_cleanup());
}
void query_identity_timeout_and_unknown() {
  InstanceState s(ref, limits);
  ready(s);
  InstanceState other(foreign, limits);
  ready(other);
  auto first = s.begin_observation(ref);
  assert(first);
  auto alien = other.begin_observation(foreign);
  assert(alien);
  assert(!s.finish_observation(*alien, Population::Empty));
  assert(s.observation_pending());
  assert(s.finish_observation(*first, Population::Populated));
  auto second = s.begin_observation(ref);
  assert(second);
  assert(!s.finish_observation(*first, Population::Empty) &&
         s.observation_pending());
  assert(s.observation_timed_out(*second));
  assert(s.observation_pending() && !s.begin_observation(ref));
  assert(!s.finish_observation(*second, Population::Empty));
  assert(!s.observation_pending() && s.population() == Population::Unknown);
  close(s);
  observe(s, Population::Unknown);
  assert(!s.can_begin_cleanup());
  observe(s, Population::Populated);
  assert(!s.can_begin_cleanup());
  auto removed = s.begin_observation(ref);
  assert(removed);
  assert(!s.finish_observation(*removed, Population::Removed));
  assert(!s.restart_allowed());
  auto cancelled = s.begin_observation(ref);
  assert(cancelled);
  assert(s.acknowledge_observation_cancellation(*cancelled));
  assert(!s.finish_observation(*cancelled, Population::Empty));
  assert(s.population() == Population::Unknown);
  retire(s);
}
void stale_query_after_stop_and_reap() {
  InstanceState s(ref, limits);
  ready(s);
  auto before_stop = s.begin_observation(ref);
  assert(before_stop);
  close(s);
  assert(!s.finish_observation(*before_stop, Population::Empty));
  assert(!s.can_begin_cleanup());
  observe(s, Population::Empty);
  assert(s.can_begin_cleanup());
}
void cleanup_worker_occupancy() {
  InstanceState s(ref, limits);
  ready(s);
  close(s);
  observe(s, Population::Empty);
  auto first = s.begin_cleanup_step(ref);
  assert(first);
  assert(!s.begin_cleanup_step(ref) && !s.begin_observation(ref));
  assert(s.cleanup_timed_out(*first));
  assert(s.cleanup() == Cleanup::Blocked && s.cleanup_pending());
  assert(!s.begin_cleanup_step(ref) && !s.restart_allowed());
  assert(s.finish_cleanup_step(*first, CleanupResult::Progress));
  assert(!s.cleanup_pending() && s.cleanup() == Cleanup::Blocked);
  auto second = s.begin_cleanup_step(ref);
  assert(second);
  assert(!s.finish_cleanup_step(*first, CleanupResult::Reclaimed) &&
         s.cleanup_pending());
  assert(s.cleanup_timed_out(*second));
  assert(s.finish_cleanup_step(*second, CleanupResult::Reclaimed));
  assert(s.population() == Population::Removed && s.restart_allowed());
  assert(!s.begin_observation(ref) && !s.begin_cleanup_step(ref));
}
void failed_or_cancelled_cleanup_needs_new_evidence() {
  InstanceState s(ref, limits);
  ready(s);
  close(s);
  observe(s, Population::Empty);
  auto first = s.begin_cleanup_step(ref);
  assert(first);
  assert(s.finish_cleanup_step(*first, CleanupResult::Failed));
  assert(s.cleanup() == Cleanup::Blocked && s.root_bound());
  assert(!s.can_begin_cleanup());
  observe(s, Population::Empty);
  auto second = s.begin_cleanup_step(ref);
  assert(second);
  assert(s.acknowledge_cleanup_cancellation(*second));
  assert(!s.finish_cleanup_step(*second, CleanupResult::Reclaimed));
  assert(!s.can_begin_cleanup());
  retire(s);
}
void bounded_mutation_capacity_and_reuse() {
  InstanceState s(ref, {1, 100, 100});
  auto first = s.begin_mutation(ref);
  assert(first);
  assert(!s.begin_mutation(ref) && s.pending_mutations() == 1);
  assert(s.fault() == InstanceFault::None);
  assert(s.finish_mutation(*first));
  auto second = s.begin_mutation(ref);
  assert(second && second->sequence() != first->sequence());
  assert(!s.finish_mutation(*first) && s.pending_mutations() == 1);
  assert(s.stop(ref) && s.finish_mutation(*second));
  assert(!s.begin_mutation(ref));
  InstanceState zero(ref, {0, 100, 100});
  assert(!zero.begin_mutation(ref));
}
void exhaustion_is_permanent_but_owns_late_results() {
  InstanceState sequence(ref, {1, 1, 100});
  auto first = sequence.begin_mutation(ref);
  assert(first);
  assert(sequence.capture_root(ref));
  auto observation = sequence.begin_observation(ref);
  assert(!observation && sequence.fault() == InstanceFault::SequenceExhausted);
  assert(sequence.stop_latched() && sequence.cleanup() == Cleanup::Blocked);
  assert(sequence.finish_mutation(*first) && sequence.pending_mutations() == 0);
  assert(!sequence.restart_allowed() && !sequence.activate(ref));
  assert(sequence.operation_sequence() == 1);

  InstanceState boundary(ref, {1, 100, 2});
  ready(boundary);
  auto query = boundary.begin_observation(ref);
  assert(query);
  auto mutation = boundary.begin_mutation(ref);
  assert(mutation && boundary.boundary() == 2);
  assert(boundary.stop(ref) &&
         boundary.fault() == InstanceFault::BoundaryExhausted);
  assert(boundary.observation_pending() && boundary.pending_mutations() == 1);
  assert(boundary.finish_mutation(*mutation));
  assert(!boundary.finish_observation(*query, Population::Empty));
  assert(!boundary.observation_pending() && !boundary.restart_allowed());
  assert(boundary.boundary() == 2);

  InstanceState zero(ref, {1, 100, 0});
  assert(zero.capture_root(ref) && zero.root_bound());
  assert(zero.fault() == InstanceFault::BoundaryExhausted &&
         zero.stop_latched());
}
void service_slots_share_allocation_and_fence_restart() {
  InstanceAllocator ids(71, 3);
  ServiceSlot a(ids, limits), b(ids, limits);
  auto* old = a.start();
  assert(old);
  auto old_ref = old->identity();
  ready(*old);
  auto* other = b.start();
  assert(other && other->identity() != old_ref);
  assert(!a.start());
  close(*old);
  observe(*old, Population::Empty);
  auto cleanup = old->begin_cleanup_step(old_ref);
  assert(cleanup);
  assert(old->cleanup_timed_out(*cleanup) && !a.start());
  assert(old->finish_cleanup_step(*cleanup, CleanupResult::Reclaimed));
  auto* fresh = a.start();
  assert(fresh && fresh->identity() != old_ref);
  ready(*fresh);
  assert(!fresh->stop(old_ref) && fresh->active());
  assert(!fresh->finish_cleanup_step(*cleanup, CleanupResult::Reclaimed));
  retire(*fresh);
  assert(!a.start() && a.fault() == SlotFault::SerialExhausted &&
         ids.serial() == 3);
  assert(other->identity().serial() ==
         2);  // Another slot's state was not replaced.
}
void lost_cleanup_reply_needs_authoritative_current_reconciliation() {
  InstanceState s(ref, limits);
  ready(s);
  close(s);
  observe(s, Population::Empty);
  auto cleanup = s.begin_cleanup_step(ref);
  assert(cleanup);
  assert(!s.begin_observation(ref));
  assert(s.cleanup_timed_out(*cleanup));
  assert(
      s.acknowledge_cleanup_cancellation(*cleanup));  // Verified worker ceased.
  auto query = s.begin_observation(ref);
  assert(query);
  assert(s.observation_timed_out(*query));
  assert(!s.finish_confirmed_removal(*query) && !s.restart_allowed());
  auto fresh = s.begin_observation(ref);
  assert(fresh);
  assert(s.finish_confirmed_removal(*fresh) && s.restart_allowed());
  assert(!s.finish_confirmed_removal(*fresh));

  InstanceState active(ref, limits);
  ready(active);
  auto invalid = active.begin_observation(ref);
  assert(invalid);
  assert(!active.finish_confirmed_removal(*invalid) && active.active());

  InstanceState delayed(ref, limits);
  ready(delayed);
  auto mutator = delayed.begin_mutation(ref);
  assert(mutator);
  close(delayed);
  auto old = delayed.begin_observation(ref);
  assert(old);
  assert(delayed.finish_mutation(*mutator));
  assert(!delayed.finish_confirmed_removal(*old) && !delayed.restart_allowed());
}
void definite_start_failure_does_not_invent_a_process() {
  InstanceState before_root(ref, limits);
  auto creator = before_root.begin_mutation(ref);
  assert(creator && before_root.stop(ref));
  assert(!before_root.report_no_initial_process(ref));
  assert(!before_root.retire_unallocated(ref));
  assert(before_root.finish_mutation(*creator));
  assert(before_root.report_no_initial_process(ref));
  assert(!before_root.process_exited() && !before_root.process_reaped());
  assert(before_root.retire_unallocated(ref) && before_root.restart_allowed());
  assert(before_root.population() == Population::Unknown &&
         !before_root.root_bound());
  assert(!before_root.capture_root(ref));

  InstanceState fork_failed(ref, limits);
  assert(fork_failed.capture_root(ref));
  assert(fork_failed.report_no_initial_process(ref));
  assert(!fork_failed.retire_unallocated(ref));
  assert(!fork_failed.report_initial_process_exit(ref));
  assert(!fork_failed.report_initial_process_reaped(ref));
  assert(!fork_failed.complete_setup(ref) && !fork_failed.activate(ref));
  observe(fork_failed, Population::Empty);
  auto cleanup = fork_failed.begin_cleanup_step(ref);
  assert(cleanup &&
         fork_failed.finish_cleanup_step(*cleanup, CleanupResult::Reclaimed));
  assert(fork_failed.restart_allowed() && !fork_failed.process_exited());

  InstanceState started(ref, limits);
  ready(started);
  assert(!started.report_no_initial_process(ref) &&
         !started.retire_unallocated(ref));
}
void malformed_configuration() {
  InstanceState invalid(InstanceId(0, 1), limits);
  assert(invalid.fault() == InstanceFault::InvalidIdentity &&
         invalid.stop_latched());
  InstanceLimits too_many{InstanceLimits::kMaximumMutationCapacity + 1, 100,
                          100};
  InstanceState oversized(ref, too_many);
  assert(oversized.fault() == InstanceFault::InvalidLimits &&
         !oversized.active());
  InstanceAllocator ids(5, 10);
  ServiceSlot bad(ids, too_many);
  assert(!bad.start());
  InstanceAllocator no_boot(0, 10);
  ServiceSlot bad_boot(no_boot, limits);
  assert(!bad_boot.start() && bad_boot.fault() == SlotFault::InvalidBoot);
  InstanceAllocator no_serial(5, 0);
  assert(!no_serial.allocate());
}
}  // namespace
int main() {
  activation_and_exit();
  stop_before_late_creation();
  mutation_and_observation_fences();
  query_identity_timeout_and_unknown();
  stale_query_after_stop_and_reap();
  cleanup_worker_occupancy();
  failed_or_cancelled_cleanup_needs_new_evidence();
  bounded_mutation_capacity_and_reuse();
  exhaustion_is_permanent_but_owns_late_results();
  service_slots_share_allocation_and_fence_restart();
  malformed_configuration();
  definite_start_failure_does_not_invent_a_process();
  lost_cleanup_reply_needs_authoritative_current_reconciliation();
}
