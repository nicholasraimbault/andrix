// SPDX-License-Identifier: Apache-2.0
#include "work_registry.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <limits>
#include <mutex>
#include <utility>

namespace andrix {
namespace work_detail {
constexpr uint32_t kStopMask = 15, kComplete = 16;
static_assert(std::atomic<uint32_t>::is_always_lock_free);

struct CreatorBudget {
  explicit CreatorBudget(size_t maximum) : maximum(maximum) {}
  const size_t maximum;
  std::atomic<size_t> used{0};
  bool Acquire() {
    size_t value = used.load();
    while (value < maximum)
      if (used.compare_exchange_weak(value, value + 1)) return true;
    return false;
  }
  void Release() { used.fetch_sub(1); }
};
struct Stream {
  Stream(const std::shared_ptr<Registry>& owner, uint64_t serial)
      : owner(owner), serial(serial) {}
  const std::weak_ptr<Registry> owner;
  const uint64_t serial;
  // Registry mutex owns these fields, including the permanent close.
  uint64_t high_water = 0;
  bool closed = false;
};
struct Record {
  Record(const std::shared_ptr<Registry>& owner,
         std::shared_ptr<CreatorBudget> budget,
         std::shared_ptr<WorkAdmission> gate, uint64_t stream,
         uint64_t request_sequence, uint64_t operation_limit)
      : owner(owner),
        budget(std::move(budget)),
        gate(std::move(gate)),
        operation_limit(operation_limit) {
    state.work = this->gate->work();
    state.stream = stream;
    state.request_sequence = request_sequence;
  }
  const std::weak_ptr<Registry> owner;
  const std::shared_ptr<CreatorBudget> budget;
  const std::shared_ptr<WorkAdmission> gate;
  const uint64_t operation_limit;
  mutable std::mutex mutex;
  WorkSnapshot state;
  std::vector<uint8_t> description;
  WorkIoBinding stdio;
  std::atomic<uint32_t> requests{0};
  uint64_t sequence = 0, observation = 0, cleanup = 0;
  bool observation_invalid = false, creator_charged = false;
  bool permanent_fault = false;

  // No mutex or I/O. Finalization and Stop arbitrate record metadata here;
  // entry permission still arbitrates on the separate existing shared gate.
  // Every Stop caller closes that gate before returning, even if another
  // caller already requested Stop but was descheduled before closing it.
  bool Stop(WorkStopSource source) {
    const uint32_t bit = static_cast<uint32_t>(source);
    uint32_t previous = requests.load();
    bool first = false;
    while (!(previous & kComplete)) {
      if (previous & bit) break;
      if (requests.compare_exchange_weak(previous, previous | bit)) {
        first = true;
        break;
      }
    }
    gate->Stop();
    return first;
  }
  bool InitialAccounted() const {
    return state.initial == WorkInitialState::Absent ||
           state.initial == WorkInitialState::Reaped;
  }
  bool BoundaryClosed() const {
    return state.start_accepted && !state.admission_pending &&
           !state.creator_pending && InitialAccounted();
  }
  void ReleaseCreator() {
    if (creator_charged) {
      creator_charged = false;
      budget->Release();
    }
  }
  void Settle() {
    // Caller has verified the complete metadata preconditions while locked.
    // This does not perform or invent kernel reclamation.
    gate->Stop();
    state.stop_sources = requests.fetch_or(kComplete) & kStopMask;
    state.complete = true;
    state.blocked = false;
  }
  void SettleAbsentScope() {
    if (!permanent_fault && BoundaryClosed() &&
        state.scope == WorkScopeState::Absent && !observation && !cleanup &&
        !state.complete)
      Settle();
  }
  void SettleUnstarted() {
    if (!state.start_accepted && !state.complete &&
        gate->phase() == AdmissionPhase::Stopped) {
      state.initial = WorkInitialState::Absent;
      state.scope = WorkScopeState::Absent;
      Settle();
    }
  }
  uint64_t Issue() {
    if (permanent_fault || sequence >= operation_limit) {
      permanent_fault = true;
      if (state.fault == WorkRegistryFault::None)
        state.fault = WorkRegistryFault::SequenceExhausted;
      state.blocked = true;
      Stop(WorkStopSource::BackendFailure);
      return 0;
    }
    return ++sequence;
  }
  WorkSnapshot Snapshot() {
    std::lock_guard lock(mutex);
    SettleUnstarted();
    auto result = state;
    result.entry_claimed = gate->entered();
    result.entry_gate_closed = gate->phase() == AdmissionPhase::Stopped;
    result.epoch = gate->epoch();
    if (!result.complete) result.stop_sources = requests.load() & kStopMask;
    result.observation_pending = observation != 0;
    result.cleanup_pending = cleanup != 0;
    return result;
  }
};
enum class ReservationState { Empty, Allocating, Ready, Failed };
struct Slot {
  WorkIdentity work{};
  uint64_t stream = 0, request_sequence = 0;
  ReservationState phase = ReservationState::Empty;
  bool cancelled = false;
  int error = 0;
  std::shared_ptr<Record> record;
};
struct Registry {
  Registry(uint64_t manager, WorkRegistryLimits limits, bool valid)
      : manager(manager),
        limits(limits),
        valid(valid),
        closed(!valid),
        budget(std::make_shared<CreatorBudget>(valid ? limits.creators : 0)),
        slots(valid ? limits.records : 0),
        streams(valid ? limits.request_streams : 0) {}
  const uint64_t manager;
  const WorkRegistryLimits limits;
  const bool valid;
  mutable std::mutex mutex;
  bool closed;
  uint64_t work_serial = 0, stream_serial = 0;
  const std::shared_ptr<CreatorBudget> budget;
  std::vector<Slot> slots;
  std::vector<std::shared_ptr<Stream>> streams;
};
}  // namespace work_detail
namespace {
using work_detail::Record;
using work_detail::Registry;
using work_detail::ReservationState;
using work_detail::Slot;

bool valid_limits(uint64_t manager, const WorkRegistryLimits& limits) {
  return manager && limits.records &&
         limits.records <= WorkRegistry::kMaximumRecords &&
         limits.request_streams &&
         limits.request_streams <= WorkRegistry::kMaximumStreams &&
         limits.creators <= limits.records && limits.launch.bytes >= 24 &&
         limits.launch.bytes <= 1024 * 1024 && limits.launch.arguments &&
         limits.launch.arguments <= 4096 && limits.launch.environment <= 4096;
}
bool valid_source(WorkStopSource source) {
  return source == WorkStopSource::Owner ||
         source == WorkStopSource::Authority ||
         source == WorkStopSource::Manager ||
         source == WorkStopSource::BackendFailure;
}
Slot* find_slot(Registry& state, WorkIdentity work) {
  if (!work.serial || work.manager != state.manager) return nullptr;
  for (auto& slot : state.slots)
    if (slot.phase != ReservationState::Empty && slot.work == work)
      return &slot;
  return nullptr;
}
bool scope_valid(WorkScopeIdentity identity) {
  return identity.device && identity.inode;
}
bool exit_valid(WorkExit result) {
  return (result.kind == WorkExitKind::Code && result.value >= 0 &&
          result.value <= 255) ||
         (result.kind == WorkExitKind::Signal && result.value > 0 &&
          result.value <= 64);
}
bool initial_fact(const Record& record, WorkResourceFact fact) {
  if (fact == WorkResourceFact::Captured)
    return record.state.initial == WorkInitialState::Owned ||
           record.state.initial == WorkInitialState::Exited ||
           record.state.initial == WorkInitialState::Reaped;
  return (fact == WorkResourceFact::Absent ||
          fact == WorkResourceFact::Unknown) &&
         record.state.initial == WorkInitialState::Unknown;
}
bool scope_fact(const Record& record, WorkResourceFact fact) {
  if (fact == WorkResourceFact::Captured)
    return record.state.scope == WorkScopeState::Captured;
  return (fact == WorkResourceFact::Absent ||
          fact == WorkResourceFact::Unknown) &&
         record.state.scope == WorkScopeState::Unknown;
}
}  // namespace

WorkControl::WorkControl(std::shared_ptr<Record> record)
    : record_(std::move(record)) {}
WorkIdentity WorkControl::identity() const {
  return record_ ? record_->gate->work() : WorkIdentity{};
}
bool WorkControl::Stop() const {
  return record_ && record_->Stop(WorkStopSource::Owner);
}
WorkSnapshot WorkControl::Inspect() const {
  return record_ ? record_->Snapshot() : WorkSnapshot{};
}
WorkRequestStream::WorkRequestStream(
    std::shared_ptr<work_detail::Stream> stream)
    : stream_(std::move(stream)) {}
uint64_t WorkRequestStream::identity() const {
  return stream_ ? stream_->serial : 0;
}
WorkReservation::WorkReservation(std::shared_ptr<Registry> issuer,
                                 WorkIdentity work)
    : issuer_(std::move(issuer)), work_(work) {}
WorkBackend::WorkBackend(std::shared_ptr<Record> record)
    : record_(std::move(record)) {}
WorkIdentity WorkBackend::identity() const {
  return record_ ? record_->gate->work() : WorkIdentity{};
}
const std::vector<uint8_t>& WorkBackend::description() const {
  static const std::vector<uint8_t> empty;
  return record_ ? record_->description : empty;
}
const WorkIoBinding& WorkBackend::stdio() const {
  static const WorkIoBinding empty;
  return record_ ? record_->stdio : empty;
}
const std::shared_ptr<WorkAdmission>& WorkBackend::gate() const {
  static const std::shared_ptr<WorkAdmission> empty;
  return record_ ? record_->gate : empty;
}

bool WorkBackend::AdmissionFinished(AdmissionResult result) const {
  if (!record_ || result < AdmissionResult::Accepted ||
      result > AdmissionResult::Invalid)
    return false;
  std::lock_guard lock(record_->mutex);
  auto& state = record_->state;
  if (!state.admission_pending || state.complete) return false;
  const auto phase = record_->gate->phase();
  if ((result == AdmissionResult::Accepted &&
       phase != AdmissionPhase::Admitted && phase != AdmissionPhase::Stopped) ||
      (result != AdmissionResult::Accepted &&
       phase != AdmissionPhase::Unbound && phase != AdmissionPhase::Stopped)) {
    // A misordered/contradictory trusted completion cannot authorize creation
    // or manufacture a no-resource result. Keep the admission slot occupied.
    record_->permanent_fault = true;
    state.fault = WorkRegistryFault::InvalidAdmission;
    state.blocked = true;
    record_->Stop(WorkStopSource::BackendFailure);
    return false;
  }
  if (record_->permanent_fault) return false;
  if (result == AdmissionResult::Accepted && !record_->gate->epoch()) {
    // A Stop before Bind is a refused admission, not an invented original
    // epoch.
    if (phase != AdmissionPhase::Stopped) return false;
    result = AdmissionResult::Stopped;
  }
  state.admission_pending = false;
  state.admission = result;
  if (result == AdmissionResult::Accepted &&
      phase == AdmissionPhase::Admitted && !termination_requested()) {
    state.creator_pending = true;
    state.initial = WorkInitialState::Unknown;
    state.scope = WorkScopeState::Unknown;
    return true;
  }
  if (result == AdmissionResult::Accepted)
    state.admission = AdmissionResult::Stopped;
  // This ticket allowed binding ONLY. No payload resources may yet exist.
  state.initial = WorkInitialState::Absent;
  state.scope = WorkScopeState::Absent;
  record_->ReleaseCreator();
  record_->Settle();
  return false;
}
bool WorkBackend::CaptureScope(WorkScopeIdentity identity) const {
  if (!record_ || !scope_valid(identity)) return false;
  std::lock_guard lock(record_->mutex);
  auto& state = record_->state;
  if (!state.creator_pending || state.complete) return false;
  if (state.scope == WorkScopeState::Captured)
    return state.scope_identity == identity;
  if (state.scope != WorkScopeState::Unknown) return false;
  state.scope = WorkScopeState::Captured;
  state.scope_identity = identity;
  return true;
}
bool WorkBackend::InitialCreated() const {
  if (!record_) return false;
  std::lock_guard lock(record_->mutex);
  auto& state = record_->state;
  if (!state.creator_pending || state.complete ||
      state.initial != WorkInitialState::Unknown)
    return false;
  state.initial = WorkInitialState::Owned;
  return true;
}
bool WorkBackend::InitialExited(WorkExit result) const {
  if (!record_ || !exit_valid(result)) return false;
  std::lock_guard lock(record_->mutex);
  auto& state = record_->state;
  if (state.complete) return false;
  if (state.initial == WorkInitialState::Exited ||
      state.initial == WorkInitialState::Reaped)
    return state.initial_exit == result;
  if (state.initial != WorkInitialState::Owned) return false;
  state.initial = WorkInitialState::Exited;
  state.initial_exit = result;
  // No late entry if the initial bootstrap died. This is gate closure only:
  // ordinary entry exit does NOT request termination of surviving descendants.
  record_->gate->Stop();
  return true;
}
bool WorkBackend::InitialReaped() const {
  if (!record_) return false;
  std::lock_guard lock(record_->mutex);
  if (record_->state.complete) return false;
  if (record_->state.initial == WorkInitialState::Reaped) return true;
  if (record_->state.initial != WorkInitialState::Exited) return false;
  record_->state.initial = WorkInitialState::Reaped;
  record_->SettleAbsentScope();
  return true;
}
bool WorkBackend::CreatorFinished(WorkResourceFact initial,
                                  WorkResourceFact scope, int error) const {
  if (!record_ || error < 0) return false;
  std::lock_guard lock(record_->mutex);
  auto& state = record_->state;
  if (!state.creator_pending || state.complete ||
      !initial_fact(*record_, initial) || !scope_fact(*record_, scope))
    return false;
  if (record_->gate->entered() && (initial == WorkResourceFact::Absent ||
                                   scope == WorkResourceFact::Absent))
    return false;
  state.creator_pending = false;
  if (error && !state.launch_error) state.launch_error = error;
  if (initial == WorkResourceFact::Absent)
    state.initial = WorkInitialState::Absent;
  if (scope == WorkResourceFact::Absent) state.scope = WorkScopeState::Absent;
  if (error) record_->Stop(WorkStopSource::BackendFailure);
  if (initial == WorkResourceFact::Unknown ||
      scope == WorkResourceFact::Unknown) {
    record_->permanent_fault = true;
    state.fault = WorkRegistryFault::UnknownResources;
    state.blocked = true;
    record_->Stop(WorkStopSource::BackendFailure);
  }
  record_->ReleaseCreator();
  if (state.initial == WorkInitialState::Absent) record_->gate->Stop();
  record_->SettleAbsentScope();
  return true;
}
bool WorkBackend::Abort(int error) const {
  if (!record_ || error <= 0) return false;
  const bool requested = record_->Stop(WorkStopSource::BackendFailure);
  std::lock_guard lock(record_->mutex);
  if (!record_->state.complete && !record_->state.launch_error)
    record_->state.launch_error = error;
  return requested;
}
bool WorkBackend::termination_requested() const {
  return record_ && (record_->requests.load() & work_detail::kStopMask);
}
std::optional<WorkObservation> WorkBackend::Observe() const {
  if (!record_) return {};
  std::lock_guard lock(record_->mutex);
  auto& state = record_->state;
  if (state.complete || record_->permanent_fault ||
      !record_->BoundaryClosed() || state.scope != WorkScopeState::Captured ||
      record_->observation || record_->cleanup)
    return {};
  const uint64_t sequence = record_->Issue();
  if (!sequence) return {};
  state.population = WorkPopulation::Unknown;
  record_->observation = sequence;
  record_->observation_invalid = false;
  return WorkObservation(record_, sequence);
}
std::optional<WorkCleanup> WorkBackend::Reclaim() const {
  if (!record_) return {};
  std::lock_guard lock(record_->mutex);
  auto& state = record_->state;
  if (state.complete || record_->permanent_fault ||
      !record_->BoundaryClosed() || state.scope != WorkScopeState::Captured ||
      state.population != WorkPopulation::Empty || record_->observation ||
      record_->cleanup || record_->gate->phase() != AdmissionPhase::Stopped)
    return {};
  const uint64_t sequence = record_->Issue();
  if (!sequence) return {};
  record_->cleanup = sequence;
  return WorkCleanup(record_, sequence);
}

WorkObservation::WorkObservation(std::shared_ptr<Record> record,
                                 uint64_t sequence)
    : record_(std::move(record)), sequence_(sequence) {}
bool WorkObservation::Finish(WorkPopulation population) const {
  if (!record_ || (population != WorkPopulation::Unknown &&
                   population != WorkPopulation::Populated &&
                   population != WorkPopulation::Empty))
    return false;
  std::lock_guard lock(record_->mutex);
  if (!sequence_ || record_->observation != sequence_) return false;
  const bool valid = !record_->observation_invalid;
  record_->observation = 0;
  record_->observation_invalid = false;
  record_->state.population = valid ? population : WorkPopulation::Unknown;
  if (valid) record_->state.blocked = false;
  return valid;
}
bool WorkObservation::TimedOut() const {
  if (!record_) return false;
  std::lock_guard lock(record_->mutex);
  if (!sequence_ || record_->observation != sequence_) return false;
  record_->observation_invalid = true;
  record_->state.population = WorkPopulation::Unknown;
  record_->state.blocked = true;
  return true;
}
bool WorkObservation::Ceased() const {
  if (!record_) return false;
  std::lock_guard lock(record_->mutex);
  if (!sequence_ || record_->observation != sequence_) return false;
  record_->observation = 0;
  record_->observation_invalid = false;
  record_->state.population = WorkPopulation::Unknown;
  return true;
}
WorkCleanup::WorkCleanup(std::shared_ptr<Record> record, uint64_t sequence)
    : record_(std::move(record)), sequence_(sequence) {}
bool WorkCleanup::Finish(WorkCleanupResult result, int error) const {
  if (!record_ || error < 0 ||
      (result != WorkCleanupResult::Progress &&
       result != WorkCleanupResult::Failed &&
       result != WorkCleanupResult::Reclaimed))
    return false;
  std::lock_guard lock(record_->mutex);
  if (!sequence_ || record_->cleanup != sequence_) return false;
  if (result != WorkCleanupResult::Failed && error) return false;
  record_->cleanup = 0;
  record_->state.cleanup_error =
      result == WorkCleanupResult::Failed && !error ? EIO : error;
  if (result == WorkCleanupResult::Reclaimed) {
    record_->state.scope = WorkScopeState::Reclaimed;
    record_->Settle();
  } else if (result == WorkCleanupResult::Failed) {
    record_->state.population = WorkPopulation::Unknown;
    record_->state.blocked = true;
  } else {
    record_->state.blocked = false;
  }
  return true;
}
bool WorkCleanup::TimedOut() const {
  if (!record_) return false;
  std::lock_guard lock(record_->mutex);
  if (!sequence_ || record_->cleanup != sequence_) return false;
  record_->state.blocked = true;
  return true;
}
bool WorkCleanup::Ceased() const {
  if (!record_) return false;
  std::lock_guard lock(record_->mutex);
  if (!sequence_ || record_->cleanup != sequence_) return false;
  record_->cleanup = 0;
  record_->state.population = WorkPopulation::Unknown;
  return true;
}

WorkRegistry::WorkRegistry(uint64_t manager, WorkRegistryLimits limits)
    : state_(std::make_shared<Registry>(manager, limits,
                                        valid_limits(manager, limits))) {}
WorkRegistry::~WorkRegistry() { Close(); }
bool WorkRegistry::valid() const { return state_->valid; }
WorkRequestStream WorkRegistry::OpenStream() {
  std::shared_ptr<work_detail::Stream> retired;
  WorkRequestStream result;
  {
    std::lock_guard lock(state_->mutex);
    if (state_->closed ||
        state_->stream_serial >= state_->limits.stream_serial_limit)
      return {};
    for (auto& slot : state_->streams) {
      if (slot && (!slot->closed || slot.use_count() != 1)) continue;
      retired = std::move(slot);
      slot = std::make_shared<work_detail::Stream>(state_,
                                                   ++state_->stream_serial);
      result = WorkRequestStream(slot);
      break;
    }
  }
  return result;
}
WorkRequestStream WorkRegistry::FindStream(uint64_t identity) const {
  std::lock_guard lock(state_->mutex);
  if (!identity || state_->closed) return {};
  for (const auto& stream : state_->streams)
    if (stream && stream->serial == identity && !stream->closed)
      return WorkRequestStream(stream);
  return {};
}
bool WorkRegistry::CloseStream(const WorkRequestStream& stream) {
  if (!stream || stream.stream_->owner.lock() != state_) return false;
  std::lock_guard lock(state_->mutex);
  stream.stream_->closed = true;
  // This closes reservation issuance only. Accepted work is not UI-owned.
  for (auto& slot : state_->slots)
    if (slot.phase == ReservationState::Allocating &&
        slot.stream == stream.identity())
      slot.cancelled = true;
  return true;
}
WorkReserveReply WorkRegistry::Reserve(const WorkRequestStream& stream,
                                       uint64_t sequence) {
  if (!stream || stream.stream_->owner.lock() != state_)
    return {WorkRegistryResult::Foreign};
  if (!sequence) return {WorkRegistryResult::Invalid};
  std::shared_ptr<Record> retired;
  std::unique_lock lock(state_->mutex);
  if (state_->closed || stream.stream_->closed)
    return {WorkRegistryResult::Closed};
  for (const auto& slot : state_->slots) {
    if (slot.phase == ReservationState::Empty ||
        slot.stream != stream.identity() || slot.request_sequence != sequence)
      continue;
    if (slot.phase == ReservationState::Allocating)
      return {WorkRegistryResult::Pending, slot.work};
    if (slot.phase == ReservationState::Failed)
      return {WorkRegistryResult::Closed, slot.work, {}, {}, slot.error};
    std::lock_guard record_lock(slot.record->mutex);
    if (slot.record->state.forgotten)
      return {WorkRegistryResult::Stale, slot.work};
    return {
        WorkRegistryResult::Existing, slot.work, {}, WorkControl(slot.record)};
  }
  if (sequence <= stream.stream_->high_water)
    return {WorkRegistryResult::Stale};
  if (state_->work_serial >= state_->limits.work_serial_limit)
    return {WorkRegistryResult::Exhausted};
  Slot* chosen = nullptr;
  for (auto& slot : state_->slots) {
    if (slot.phase == ReservationState::Empty ||
        slot.phase == ReservationState::Failed) {
      chosen = &slot;
      break;
    }
    if (slot.phase != ReservationState::Ready || slot.record.use_count() != 1)
      continue;
    std::lock_guard record_lock(slot.record->mutex);
    if (slot.record->state.forgotten && slot.record->gate.use_count() == 1) {
      chosen = &slot;
      break;
    }
  }
  if (!chosen) return {WorkRegistryResult::Capacity};
  retired = std::move(chosen->record);
  *chosen = {};
  chosen->phase = ReservationState::Allocating;
  chosen->work = {state_->manager, ++state_->work_serial};
  chosen->stream = stream.identity();
  chosen->request_sequence = sequence;
  stream.stream_->high_water = sequence;
  WorkReserveReply reply{WorkRegistryResult::Accepted, chosen->work,
                         WorkReservation(state_, chosen->work)};
  lock.unlock();  // Destruction can unmap/close a retired gate, never under
                  // this mutex.
  return reply;
}
WorkReserveReply WorkRegistry::ReservationFinished(
    const WorkReservation& ticket, std::shared_ptr<WorkAdmission> gate,
    int error) {
  if (!ticket || ticket.issuer_ != state_) return {WorkRegistryResult::Foreign};
  if (error < 0 ||
      (gate && (gate->work() != ticket.identity() ||
                (gate->phase() != AdmissionPhase::Unbound &&
                 gate->phase() != AdmissionPhase::Stopped))) ||
      (!gate && !error))
    return {WorkRegistryResult::Invalid};
  std::lock_guard lock(state_->mutex);
  Slot* slot = find_slot(*state_, ticket.identity());
  if (!slot || slot->phase != ReservationState::Allocating)
    return {WorkRegistryResult::Stale};
  if (error || state_->closed || slot->cancelled ||
      gate->phase() == AdmissionPhase::Stopped) {
    if (gate) gate->Stop();
    slot->phase = ReservationState::Failed;
    slot->error = error ? error : ECANCELED;
    return {WorkRegistryResult::Closed, slot->work, {}, {}, slot->error};
  }
  slot->record = std::make_shared<Record>(state_, state_->budget, gate,
                                          slot->stream, slot->request_sequence,
                                          state_->limits.operation_limit);
  slot->phase = ReservationState::Ready;
  return {
      WorkRegistryResult::Accepted, slot->work, {}, WorkControl(slot->record)};
}
bool WorkRegistry::CancelReservation(const WorkReservation& ticket) {
  if (!ticket || ticket.issuer_ != state_) return false;
  std::lock_guard lock(state_->mutex);
  Slot* slot = find_slot(*state_, ticket.identity());
  if (!slot || slot->phase != ReservationState::Allocating) return false;
  slot->cancelled = true;
  return true;
}
WorkControl WorkRegistry::Find(WorkIdentity identity) const {
  std::lock_guard lock(state_->mutex);
  Slot* slot = find_slot(*state_, identity);
  if (!slot || slot->phase != ReservationState::Ready) return {};
  std::lock_guard record_lock(slot->record->mutex);
  return slot->record->state.forgotten ? WorkControl{}
                                       : WorkControl(slot->record);
}
std::vector<WorkSnapshot> WorkRegistry::List() const {
  std::vector<WorkControl> controls;
  controls.reserve(
      state_->limits.records <= kMaximumRecords ? state_->limits.records : 0);
  {
    std::lock_guard lock(state_->mutex);
    for (const auto& slot : state_->slots)
      if (slot.phase == ReservationState::Ready)
        controls.push_back(WorkControl(slot.record));
  }
  std::vector<WorkSnapshot> result;
  result.reserve(controls.size());
  for (const auto& control : controls) {
    auto snapshot = control.Inspect();
    if (!snapshot.forgotten) result.push_back(snapshot);
  }
  return result;  // Bounded per-record observations, not one global atomic
                  // snapshot.
}
WorkStartReply WorkRegistry::Start(
    const WorkControl& work, const std::vector<uint8_t>& encoded_description,
    const WorkIoLease& inputs) {
  if (!work || work.record_->owner.lock() != state_)
    return {WorkRegistryResult::Foreign};
  const auto& stdio = inputs.binding();
  if (!stdio) return {WorkRegistryResult::Invalid};
  if (!stdio.closed_plan() && stdio.identity().manager != state_->manager)
    return {WorkRegistryResult::Foreign};
  LaunchDescription decoded;
  LaunchFailure failure;
  if (!DecodeLaunch(encoded_description, state_->limits.launch, decoded,
                    failure))
    return {WorkRegistryResult::Invalid};
  // Validation and allocation do not hold registry/record control locks.
  auto prepared_description = encoded_description;
  auto& record = *work.record_;
  std::lock_guard registry_lock(state_->mutex);
  std::lock_guard record_lock(record.mutex);
  if (record.state.forgotten) return {WorkRegistryResult::Stale};
  if (record.state.start_accepted) {
    return {record.description == encoded_description && record.stdio == stdio
                ? WorkRegistryResult::Existing
                : WorkRegistryResult::Conflict};
  }
  record.SettleUnstarted();
  if (state_->closed || record.state.complete || !inputs.available() ||
      record.gate->phase() == AdmissionPhase::Stopped)
    return {WorkRegistryResult::Closed};
  if (record.gate->phase() != AdmissionPhase::Unbound)
    return {WorkRegistryResult::WrongState};
  if (!record.budget->Acquire()) return {WorkRegistryResult::Capacity};
  record.creator_charged = true;
  record.description = std::move(prepared_description);
  record.stdio = stdio;
  record.state.stdio_configured = true;
  record.state.stdio_closed_plan = stdio.closed_plan();
  record.state.stdio = stdio.identity();
  record.state.start_accepted = true;
  record.state.admission_pending = true;
  return {WorkRegistryResult::Accepted, WorkBackend(work.record_), inputs};
}
WorkRegistryResult WorkRegistry::Forget(const WorkControl& work) {
  if (!work || work.record_->owner.lock() != state_)
    return WorkRegistryResult::Foreign;
  std::lock_guard lock(work.record_->mutex);
  work.record_->SettleUnstarted();
  if (work.record_->state.forgotten) return WorkRegistryResult::Existing;
  if (!work.record_->state.complete) return WorkRegistryResult::Incomplete;
  work.record_->state.forgotten = true;
  return WorkRegistryResult::Accepted;
}
WorkRegistryUsage WorkRegistry::usage() const {
  std::lock_guard lock(state_->mutex);
  WorkRegistryUsage result;
  for (const auto& slot : state_->slots) {
    result.records += slot.phase != ReservationState::Empty;
    result.allocating += slot.phase == ReservationState::Allocating;
  }
  for (const auto& stream : state_->streams) result.streams += bool(stream);
  result.creators = state_->budget->used.load();
  result.closed = state_->closed;
  return result;
}
void WorkRegistry::Close(WorkStopSource source) {
  if (!valid_source(source)) source = WorkStopSource::Manager;
  std::lock_guard lock(state_->mutex);
  state_->closed = true;
  for (auto& stream : state_->streams)
    if (stream) stream->closed = true;
  for (auto& slot : state_->slots) {
    if (slot.phase == ReservationState::Allocating) slot.cancelled = true;
    if (slot.record) slot.record->Stop(source);
  }
}
}  // namespace andrix
