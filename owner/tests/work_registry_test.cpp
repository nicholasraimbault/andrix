// SPDX-License-Identifier: Apache-2.0
// Real gate allocation/atomics and supplied backend facts, not Android
// authority or actual process/cgroup cleanup qualification.
#include "work_registry.h"

#include <atomic>
#include <barrier>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <limits>
#include <thread>
#include <vector>

using namespace andrix;
using R = WorkRegistryResult;
using F = WorkResourceFact;
constexpr AuthorityEpoch epoch{10, 20, 0};
WorkRegistryLimits limits(size_t records = 4, size_t streams = 4,
                          size_t creators = 2) {
  return {records,    streams,    creators,  {4096, 32, 32},
          UINT64_MAX, UINT64_MAX, UINT64_MAX};
}
std::vector<uint8_t> request(const char* argument = "hello") {
  LaunchDescription launch{"/owner/arbitrary-program",
                           {"custom-argv0", argument},
                           {"LD_PRELOAD=/owner/extension.so", "X=1", "X=2"},
                           "/owner/project"};
  std::vector<uint8_t> encoded;
  LaunchFailure failure;
  assert(EncodeLaunch(launch, {4096, 32, 32}, encoded, failure));
  return encoded;
}
WorkControl reserve(WorkRegistry& registry, const WorkRequestStream& stream,
                    uint64_t sequence) {
  auto issued = registry.Reserve(stream, sequence);
  assert(issued.result == R::Accepted && issued.allocation && !issued.control);
  int error = 0;
  auto gate = WorkAdmission::Reserve(issued.work, error);
  assert(gate && !error);
  auto finished = registry.ReservationFinished(issued.allocation, gate);
  assert(finished.result == R::Accepted && finished.control &&
         !finished.allocation);
  return finished.control;
}
WorkBackend start(WorkRegistry& registry, const WorkControl& control,
                  AdmissionAuthority& authority) {
  auto result = registry.Start(control, request());
  assert(result.result == R::Accepted && result.backend);
  assert(!result.backend.CaptureScope({1, 2}));
  assert(!result.backend.InitialCreated());
  assert(result.backend.AdmissionFinished(
      authority.Admit(result.backend.gate(), 100)));
  return result.backend;
}
void capture(WorkBackend& backend, uint64_t inode = 2) {
  assert(backend.CaptureScope({1, inode}));
  assert(backend.InitialCreated());
}
void claim(WorkBackend& backend, AdmissionAuthority& authority) {
  assert(authority.Prepared(backend.gate(), 110) == AdmissionResult::Accepted);
  assert(authority.Release(backend.gate(), 120) == AdmissionResult::Accepted);
  assert(backend.gate()->ClaimEntry(backend.identity(), epoch, 130) ==
         EntryResult::Entered);
}
void exit_and_reap(WorkBackend& backend,
                   WorkExit result = {WorkExitKind::Code, 0}) {
  assert(!backend.InitialReaped());
  assert(backend.InitialExited(result));
  assert(backend.InitialReaped());
}
void reclaim(WorkBackend& backend) {
  auto observation = backend.Observe();
  assert(observation && observation->Finish(WorkPopulation::Empty));
  auto cleanup = backend.Reclaim();
  assert(cleanup && cleanup->Finish(WorkCleanupResult::Reclaimed));
}
void reservations_and_retry() {
  WorkRegistry registry(1, limits(2, 2));
  assert(registry.valid());
  auto stream = registry.OpenStream();
  assert(stream && stream.identity() == 1);
  auto reconnect = registry.FindStream(stream.identity());
  assert(reconnect && reconnect.identity() == stream.identity());
  assert(registry.Reserve(stream, 0).result == R::Invalid);
  auto pending = registry.Reserve(stream, 5);
  assert(pending.result == R::Accepted && pending.work == (WorkIdentity{1, 1}));
  assert(registry.usage().allocating == 1);
  auto duplicate = registry.Reserve(reconnect, 5);
  assert(duplicate.result == R::Pending && duplicate.work == pending.work &&
         !duplicate.allocation);
  assert(registry.Reserve(stream, 4).result == R::Stale);
  assert(registry.List().empty() && !registry.Find(pending.work));
  int error;
  auto gate = WorkAdmission::Reserve(pending.work, error);
  auto completed = registry.ReservationFinished(pending.allocation, gate);
  assert(completed.result == R::Accepted &&
         completed.control.identity() == pending.work);
  gate.reset();
  assert(registry.ReservationFinished(pending.allocation, {}, ENOMEM).result ==
         R::Stale);
  auto again = registry.Reserve(reconnect, 5);
  assert(again.result == R::Existing &&
         again.control.identity() == pending.work);
  assert(registry.List().size() == 1 && registry.Find(pending.work));
  assert(registry.Forget(completed.control) == R::Incomplete);
  assert(completed.control.Stop());
  assert(!completed.control.Stop());
  auto snapshot = completed.control.Inspect();
  assert(snapshot.complete && snapshot.initial == WorkInitialState::Absent &&
         snapshot.scope == WorkScopeState::Absent &&
         snapshot.stop_sources == 1);
  assert(registry.Forget(completed.control) == R::Accepted);
  assert(registry.Forget(completed.control) == R::Existing);
  assert(registry.Reserve(stream, 5).result == R::Stale);
  assert(!registry.Find(pending.work) && registry.List().empty());
  auto second = reserve(registry, stream, 6);
  assert(second.identity().serial == 2);
  assert(!completed.control.Stop() && !second.Inspect().entry_gate_closed);
  assert(registry.Reserve(stream, 7).result ==
         R::Capacity);  // Old handles still pin slot1.
  completed.control = {};
  assert(registry.Reserve(stream, 7).result ==
         R::Capacity);  // Duplicate reply also retained it.
  again.control = {};
  auto next = registry.Reserve(stream, 7);
  assert(next.result == R::Accepted && next.work.serial == 3);
  assert(registry.Reserve(stream, 5).result ==
         R::Stale);  // No unbounded tombstone needed.
  assert(
      !second.Inspect().entry_gate_closed);  // Old Stop never retargets slot2.
  assert(registry.CancelReservation(next.allocation));
  auto late = WorkAdmission::Reserve(next.work, error);
  assert(registry.ReservationFinished(next.allocation, late).result ==
         R::Closed);
  assert(late->phase() == AdmissionPhase::Stopped);
}
void allocation_cancellation_and_foreign_handles() {
  WorkRegistry a(10, limits(1, 1, 1)), b(11, limits(1, 1, 1));
  auto sa = a.OpenStream(), sb = b.OpenStream();
  auto pending = a.Reserve(sa, 1);
  assert(a.Reserve(sb, 1).result == R::Foreign);
  assert(!b.CancelReservation(pending.allocation));
  assert(b.ReservationFinished(pending.allocation, {}, EIO).result ==
         R::Foreign);
  assert(a.CancelReservation(pending.allocation));
  assert(a.usage().allocating == 1 && a.Reserve(sa, 2).result == R::Capacity);
  int error;
  auto foreign = WorkAdmission::Reserve({99, 1}, error);
  assert(a.ReservationFinished(pending.allocation, foreign).result ==
         R::Invalid);
  assert(foreign->phase() == AdmissionPhase::Unbound &&
         a.usage().allocating == 1);
  assert(a.ReservationFinished(pending.allocation, {}).result == R::Invalid);
  assert(a.ReservationFinished(pending.allocation, {}, ENOMEM).result ==
         R::Closed);
  assert(a.usage().allocating == 0);
  assert(a.Reserve(sa, 1).error == ENOMEM);
  auto replacement = a.Reserve(sa, 2);
  assert(replacement.result == R::Accepted);
  assert(a.Reserve(sa, 1).result == R::Stale);
  auto gate = WorkAdmission::Reserve(replacement.work, error);
  a.Close(WorkStopSource::Authority);
  assert(a.ReservationFinished(replacement.allocation, gate).result ==
         R::Closed);
  assert(gate->phase() == AdmissionPhase::Stopped);
  assert(a.usage().allocating == 0 && a.usage().closed && !a.OpenStream());
  auto cb = reserve(b, sb, 1);
  assert(a.Start(cb, request()).result == R::Foreign);
  assert(a.Forget(cb) == R::Foreign && !cb.Inspect().entry_gate_closed);
}
void stream_retirement_and_reordering() {
  WorkRegistry registry(1, limits(4, 2));
  auto a = registry.OpenStream(), b = registry.OpenStream();
  assert(a && b && !registry.OpenStream());
  auto ca = reserve(registry, a, 9), cb = reserve(registry, b, 1);
  assert(registry.Reserve(a, 8).result == R::Stale);
  assert(registry.Reserve(b, 1).result == R::Existing);
  auto pending = registry.Reserve(a, 10);
  assert(registry.CloseStream(a) && !registry.FindStream(a.identity()));
  assert(registry.Reserve(a, 11).result == R::Closed);
  assert(!ca.Inspect().entry_gate_closed && !cb.Inspect().entry_gate_closed);
  assert(
      !registry.OpenStream());  // Closed stream handle still pins its record.
  a = {};
  auto c = registry.OpenStream();
  assert(c && c.identity() == 3);
  assert(registry.Reserve(c, 1).result == R::Accepted);
  int error;
  auto gate = WorkAdmission::Reserve(pending.work, error);
  assert(registry.ReservationFinished(pending.allocation, gate).result ==
         R::Closed);
  assert(gate->phase() == AdmissionPhase::Stopped);
}
void limits_and_exhaustion() {
  auto bad = limits();
  bad.records = WorkRegistry::kMaximumRecords + 1;
  WorkRegistry invalid(1, bad);
  assert(!invalid.valid() && !invalid.OpenStream() && invalid.List().empty());
  assert(invalid.usage().closed);
  WorkRegistry zero(0, limits());
  assert(!zero.valid());
  auto limited = limits(1, 1, 0);
  limited.work_serial_limit = 2;
  limited.stream_serial_limit = 2;
  WorkRegistry registry(1, limited);
  auto stream = registry.OpenStream();
  auto c = reserve(registry, stream, 1);
  assert(registry.Start(c, request()).result == R::Capacity);
  c.Stop();
  registry.Forget(c);
  c = {};
  c = reserve(registry, stream, 2);
  c.Stop();
  registry.Forget(c);
  c = {};
  assert(registry.Reserve(stream, 3).result == R::Exhausted);
  registry.CloseStream(stream);
  stream = {};
  stream = registry.OpenStream();
  assert(stream.identity() == 2);
  registry.CloseStream(stream);
  stream = {};
  assert(!registry.OpenStream());
  WorkRegistry end(2, limits(2));
  auto s = end.OpenStream();
  auto last = reserve(end, s, UINT64_MAX);
  assert(end.Reserve(s, UINT64_MAX).result == R::Existing);
  assert(end.Reserve(s, UINT64_MAX - 1).result == R::Stale);
  assert(end.Reserve(s, 0).result == R::Invalid);
}
void immutable_start_and_creator_budget() {
  WorkRegistry registry(1, limits(3, 1, 1));
  auto stream = registry.OpenStream();
  auto a = reserve(registry, stream, 1), b = reserve(registry, stream, 2);
  auto malformed = request();
  malformed.push_back(0);
  assert(registry.Start(a, malformed).result == R::Invalid);
  assert(!a.Inspect().start_accepted && !registry.usage().creators);
  auto original = request();
  auto first = registry.Start(a, original);
  assert(first.result == R::Accepted && first.backend);
  original.assign(100, 0xff);
  assert(first.backend.description() == request());
  assert(a.Inspect().admission_pending && registry.usage().creators == 1);
  auto retry = registry.Start(a, request());
  assert(retry.result == R::Existing && !retry.backend);
  assert(registry.Start(a, request("different")).result == R::Conflict);
  assert(registry.Start(b, request()).result == R::Capacity);
  auto backend = first.backend;
  first.backend = {};  // Dropping a handle does not prove worker cessation.
  assert(registry.usage().creators == 1);
  assert(!backend.AdmissionFinished(AdmissionResult::NotReady));
  assert(registry.usage().creators == 0 && a.Inspect().complete);
  assert(a.Inspect().admission == AdmissionResult::NotReady);
  assert(registry.Start(a, request()).result == R::Existing);
  assert(!backend.AdmissionFinished(AdmissionResult::Accepted));
  assert(registry.Start(b, request()).result == R::Accepted);
}
void original_authority_and_stopped_start() {
  WorkRegistry registry(1, limits(2));
  auto stream = registry.OpenStream();
  auto old = reserve(registry, stream, 1), other = reserve(registry, stream, 2);
  AdmissionAuthority authority;
  assert(authority.Observe(epoch, 2100, 100) == AdmissionResult::Accepted);
  auto pending = registry.Start(old, request());
  assert(pending.result == R::Accepted);
  assert(authority.Admit(pending.backend.gate(), 100) ==
         AdmissionResult::Accepted);
  authority.Revoke();
  registry.Close(WorkStopSource::Authority);
  assert(!pending.backend.AdmissionFinished(AdmissionResult::Accepted));
  assert(old.Inspect().epoch == epoch && old.Inspect().complete);
  assert(old.Inspect().stop_sources ==
         static_cast<uint32_t>(WorkStopSource::Authority));
  assert(!old.Inspect().entry_claimed);
  assert(registry.Start(old, request()).result == R::Existing);
  assert(!pending.backend.CaptureScope({1, 2}));
  assert(other.Inspect().complete && !other.Inspect().epoch);
  assert(authority.Retire(pending.backend.gate()) == AdmissionResult::Accepted);
  assert(registry.Forget(old) == R::Accepted);
  assert(registry.Start(old, request()).result == R::Stale);

  WorkRegistry fresh(2, limits());
  auto fresh_stream = fresh.OpenStream();
  auto stopped = reserve(fresh, fresh_stream, 1);
  assert(stopped.Stop() && fresh.Start(stopped, request()).result == R::Closed);
  assert(!stopped.Inspect().start_accepted);
}
void natural_entry_exit_does_not_stop_descendants() {
  WorkRegistry registry(1, limits());
  auto stream = registry.OpenStream();
  auto control = reserve(registry, stream, 1);
  AdmissionAuthority authority;
  authority.Observe(epoch, 2100, 100);
  auto backend = start(registry, control, authority);
  capture(backend);
  claim(backend, authority);
  assert(backend.CreatorFinished(F::Captured, F::Captured));
  assert(!registry.usage().creators);
  assert(!backend.Observe());  // Initial process has not exited/reaped.
  exit_and_reap(backend);
  assert(control.Inspect().entry_claimed &&
         control.Inspect().entry_gate_closed);
  assert(!backend.termination_requested() && !control.Inspect().complete);
  auto still_populated = backend.Observe();
  assert(still_populated && still_populated->Finish(WorkPopulation::Populated));
  assert(control.Inspect().population == WorkPopulation::Populated &&
         !backend.Reclaim());
  assert(!backend.termination_requested());
  reclaim(backend);
  auto done = control.Inspect();
  assert(done.complete && !done.stop_sources &&
         done.initial_exit == (WorkExit{WorkExitKind::Code, 0}));
  assert(done.scope == WorkScopeState::Reclaimed);
  assert(!control.Stop() && control.Inspect().stop_sources ==
                                0);  // Late Stop cannot rewrite result.
  assert(authority.Retire(backend.gate()) == AdmissionResult::Accepted);
}
void late_creation_and_unallocated_paths() {
  WorkRegistry registry(1, limits());
  auto stream = registry.OpenStream();
  auto control = reserve(registry, stream, 1);
  AdmissionAuthority authority;
  authority.Observe(epoch, 2100, 100);
  auto backend = start(registry, control, authority);
  assert(control.Stop());
  assert(backend.termination_requested() && control.Inspect().creator_pending);
  assert(!backend.Observe() && registry.Forget(control) == R::Incomplete);
  capture(backend);  // Late creation adds ownership despite Stop.
  assert(backend.CaptureScope({1, 2}) && !backend.CaptureScope({1, 3}));
  assert(!backend.CreatorFinished(F::Absent, F::Captured));
  exit_and_reap(backend, {WorkExitKind::Signal, 9});
  assert(
      !backend
           .Observe());  // Even reap is insufficient until creator cessation.
  assert(backend.CreatorFinished(F::Captured, F::Captured, ECANCELED));
  assert(!backend.CreatorFinished(F::Captured, F::Captured));
  reclaim(backend);
  assert(control.Inspect().complete &&
         control.Inspect().initial_exit.kind == WorkExitKind::Signal);

  auto no_scope = reserve(registry, stream, 2);
  auto ns = start(registry, no_scope, authority);
  assert(ns.InitialCreated());
  assert(ns.CreatorFinished(F::Captured, F::Absent, EIO));
  assert(!no_scope.Inspect().complete);
  exit_and_reap(ns, {WorkExitKind::Code, 125});
  assert(no_scope.Inspect().complete &&
         no_scope.Inspect().scope == WorkScopeState::Absent);

  auto no_task = reserve(registry, stream, 3);
  auto nt = start(registry, no_task, authority);
  assert(nt.Abort(EACCES));
  assert(registry.usage().creators == 1);
  assert(nt.CreatorFinished(F::Absent, F::Absent, EAGAIN));
  assert(no_task.Inspect().complete &&
         no_task.Inspect().initial == WorkInitialState::Absent);
  assert(no_task.Inspect().launch_error ==
         EACCES);  // Preserve the first reported failure.
  assert(!no_task.Inspect().entry_claimed);
}
void unknown_resources_and_bad_admission_remain_owned() {
  WorkRegistry registry(1, limits(3));
  auto stream = registry.OpenStream();
  auto unknown = reserve(registry, stream, 1);
  AdmissionAuthority authority;
  authority.Observe(epoch, 2100, 100);
  auto backend = start(registry, unknown, authority);
  assert(backend.CreatorFinished(F::Unknown, F::Unknown, EIO));
  assert(unknown.Inspect().blocked && !unknown.Inspect().complete);
  assert(unknown.Inspect().fault == WorkRegistryFault::UnknownResources);
  assert(!backend.Observe() && !backend.Reclaim());
  assert(registry.Forget(unknown) == R::Incomplete);
  assert(!backend.CaptureScope({1, 2}));

  auto misordered = reserve(registry, stream, 2);
  auto launch = registry.Start(misordered, request());
  assert(authority.Admit(launch.backend.gate(), 100) ==
         AdmissionResult::Accepted);
  assert(authority.Prepared(launch.backend.gate(), 110) ==
         AdmissionResult::Accepted);
  assert(!launch.backend.AdmissionFinished(AdmissionResult::Accepted));
  assert(misordered.Inspect().blocked &&
         misordered.Inspect().admission_pending);
  assert(misordered.Inspect().fault == WorkRegistryFault::InvalidAdmission);
  assert(!misordered.Inspect().complete && registry.usage().creators == 1);
  assert(!launch.backend.AdmissionFinished(AdmissionResult::Stopped));
  assert(registry.usage().creators ==
         1);  // Invalid adapter sequence is quarantined.
}
void observation_cleanup_correlation_and_timeout() {
  WorkRegistry registry(1, limits());
  auto stream = registry.OpenStream();
  auto control = reserve(registry, stream, 1);
  AdmissionAuthority authority;
  authority.Observe(epoch, 2100, 100);
  auto backend = start(registry, control, authority);
  capture(backend);
  assert(backend.CreatorFinished(F::Captured, F::Captured));
  exit_and_reap(backend);
  auto old = backend.Observe();
  assert(old && old->TimedOut());
  assert(control.Inspect().observation_pending && control.Inspect().blocked);
  assert(!backend.Observe() && !backend.Reclaim());
  assert(!old->Finish(WorkPopulation::Empty));
  assert(!control.Inspect().observation_pending &&
         control.Inspect().population == WorkPopulation::Unknown);
  auto current = backend.Observe();
  assert(current && !old->Finish(WorkPopulation::Empty) && !old->Ceased());
  assert(control.Inspect().observation_pending);
  assert(current->Finish(WorkPopulation::Empty));
  auto first = backend.Reclaim();
  assert(first && !backend.Observe() && !backend.Reclaim());
  assert(first->TimedOut() && control.Inspect().cleanup_pending);
  assert(!backend.Reclaim());
  assert(!first->Finish(WorkCleanupResult::Progress, EIO));
  assert(first->Finish(WorkCleanupResult::Progress));
  auto second = backend.Reclaim();
  assert(second && !first->Finish(WorkCleanupResult::Reclaimed));
  assert(second->Finish(WorkCleanupResult::Failed, EBUSY));
  assert(!backend.Reclaim());
  auto fresh = backend.Observe();
  assert(fresh && fresh->TimedOut() && fresh->Ceased());
  fresh = backend.Observe();
  assert(fresh && fresh->Finish(WorkPopulation::Empty));
  auto cancelled = backend.Reclaim();
  assert(cancelled && cancelled->TimedOut() && cancelled->Ceased());
  assert(!backend.Reclaim());  // Cancellation invalidated the earlier Empty.
  fresh = backend.Observe();
  assert(fresh && fresh->Finish(WorkPopulation::Empty));
  auto last = backend.Reclaim();
  assert(last && last->TimedOut());
  assert(last->Finish(
      WorkCleanupResult::Reclaimed));  // Exact late completion is still owned.
  assert(control.Inspect().complete && !last->Ceased() &&
         !last->Finish(WorkCleanupResult::Reclaimed));
}
void ticket_exhaustion_and_gate_ownership() {
  auto configuration = limits(1, 1, 1);
  configuration.operation_limit = 1;
  WorkRegistry registry(1, configuration);
  auto stream = registry.OpenStream();
  auto control = reserve(registry, stream, 1);
  AdmissionAuthority authority;
  authority.Observe(epoch, 2100, 100);
  auto backend = start(registry, control, authority);
  capture(backend);
  backend.CreatorFinished(F::Captured, F::Captured);
  exit_and_reap(backend);
  auto observation = backend.Observe();
  assert(observation && observation->Finish(WorkPopulation::Empty));
  assert(!backend.Reclaim() && control.Inspect().blocked);
  assert(control.Inspect().fault == WorkRegistryFault::SequenceExhausted);
  assert(registry.Forget(control) == R::Incomplete &&
         registry.Reserve(stream, 2).result == R::Capacity);

  WorkRegistry another(2, limits(1, 1, 1));
  auto s = another.OpenStream();
  auto c = reserve(another, s, 1);
  auto b = start(another, c, authority);
  assert(b.CreatorFinished(F::Absent, F::Absent, EIO));
  auto borrowed_gate = b.gate();
  assert(another.Forget(c) == R::Accepted);
  c = {};
  b = {};
  assert(another.Reserve(s, 2).result ==
         R::Capacity);  // Platform and borrowed gate still retain it.
  assert(authority.Retire(borrowed_gate) == AdmissionResult::Accepted);
  assert(another.Reserve(s, 2).result == R::Capacity);
  borrowed_gate.reset();
  assert(another.Reserve(s, 2).result == R::Accepted);
}
void manager_lifetime_closes_exact_handles() {
  WorkControl surviving;
  {
    WorkRegistry registry(1, limits());
    auto stream = registry.OpenStream();
    surviving = reserve(registry, stream, 1);
  }
  auto closed = surviving.Inspect();
  assert(closed.complete && closed.entry_gate_closed &&
         closed.stop_sources == static_cast<uint32_t>(WorkStopSource::Manager));
  assert(!surviving.Stop());
  WorkRegistry different(2, limits());
  assert(different.Start(surviving, request()).result == R::Foreign);
}
void concurrent_duplicate_start_stop_and_late_allocation() {
  for (size_t i = 0; i < 200; ++i) {
    WorkRegistry registry(i + 1, limits(1, 1, 1));
    auto stream = registry.OpenStream();
    auto control = reserve(registry, stream, 1);
    const auto a = request(), b = request(i % 2 ? "different" : "hello");
    WorkStartReply one, two;
    std::barrier ready(2);
    std::thread other([&] {
      ready.arrive_and_wait();
      two = registry.Start(control, b);
    });
    ready.arrive_and_wait();
    one = registry.Start(control, a);
    other.join();
    assert((one.result == R::Accepted) != (two.result == R::Accepted));
    const auto loser = one.result == R::Accepted ? two.result : one.result;
    assert(loser == (i % 2 ? R::Conflict : R::Existing));
    const auto backend = one.backend ? one.backend : two.backend;
    assert(backend.description() == (one.backend ? a : b));
    assert(registry.usage().creators == 1);
    control.Stop();
    assert(!backend.AdmissionFinished(AdmissionResult::Stopped));
    assert(control.Inspect().complete && !registry.usage().creators);
  }
  for (size_t i = 0; i < 200; ++i) {
    WorkRegistry registry(i + 1, limits(2, 1, 1));
    auto stream = registry.OpenStream();
    auto a = reserve(registry, stream, 1);
    auto b = reserve(registry, stream, 2);
    WorkStartReply one, two;
    std::barrier ready(3);
    std::thread first([&] {
      ready.arrive_and_wait();
      one = registry.Start(a, request());
    });
    std::thread duplicate([&] {
      ready.arrive_and_wait();
      two = registry.Start(a, request());
    });
    ready.arrive_and_wait();
    a.Stop();
    first.join();
    duplicate.join();
    assert(a.Inspect().entry_gate_closed && !a.Inspect().entry_claimed);
    const size_t accepted =
        (one.result == R::Accepted) + (two.result == R::Accepted);
    assert(accepted <= 1 && registry.usage().creators == accepted);
    WorkBackend backend = one.backend ? one.backend : two.backend;
    if (backend) {
      AdmissionAuthority authority;
      authority.Observe(epoch, 2100, 100);
      auto admitted = authority.Admit(backend.gate(), 100);
      assert(admitted != AdmissionResult::Accepted);
      assert(!backend.AdmissionFinished(admitted));
      assert(registry.Start(a, request()).result == R::Existing);
    }
    assert(a.Inspect().complete && registry.usage().creators == 0);
    assert(registry.Start(b, request()).result ==
           R::Accepted);  // Independent work still progresses.
  }
  for (size_t i = 0; i < 200; ++i) {
    WorkRegistry registry(i + 1, limits(1, 1, 1));
    auto stream = registry.OpenStream();
    auto reservation = registry.Reserve(stream, 1);
    WorkReserveReply finished;
    std::barrier ready(2);
    std::thread allocator([&] {
      int error;
      auto gate = WorkAdmission::Reserve(reservation.work, error);
      assert(gate);
      ready.arrive_and_wait();
      finished = registry.ReservationFinished(reservation.allocation, gate);
    });
    ready.arrive_and_wait();
    registry.Close(WorkStopSource::Authority);
    allocator.join();
    assert(registry.usage().closed && registry.usage().allocating == 0);
    if (finished.control)
      assert(finished.control.Inspect().entry_gate_closed);
    else
      assert(finished.result == R::Closed);
  }
}
int main() {
  reservations_and_retry();
  allocation_cancellation_and_foreign_handles();
  stream_retirement_and_reordering();
  limits_and_exhaustion();
  immutable_start_and_creator_budget();
  original_authority_and_stopped_start();
  natural_entry_exit_does_not_stop_descendants();
  late_creation_and_unallocated_paths();
  unknown_resources_and_bad_admission_remain_owned();
  observation_cleanup_correlation_and_timeout();
  ticket_exhaustion_and_gate_ownership();
  manager_lifetime_closes_exact_handles();
  concurrent_duplicate_start_stop_and_late_allocation();
  puts(
      "{\"registry_cases\":13,\"finite_duplicate_start_races\":200,\"finite_"
      "start_stop_races\":200,\"finite_late_allocation_races\":200,\"Android_"
      "authentication_or_kernel_cleanup_qualified\":false}");
}
