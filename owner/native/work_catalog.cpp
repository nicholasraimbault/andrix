// SPDX-License-Identifier: Apache-2.0
#include "work_catalog.h"

#include <fcntl.h>

#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <mutex>
#include <utility>

namespace andrix {
namespace work_catalog_detail {
struct Work {
  Work(const std::shared_ptr<Catalog>& owner, WorkControl control)
      : owner(owner), control(std::move(control)) {}
  const std::weak_ptr<Catalog> owner;
  const WorkControl control;
  std::atomic<bool> cancelled{false};
  mutable std::mutex mutex;
  std::condition_variable changed;
  size_t starts_pending = 0;
  WorkInputState phase = WorkInputState::Empty;
  WorkIoIdentity input{};
  WorkIoBinding binding;
  std::vector<uint8_t> description;  // Immutable once Ready; no user I/O data.
  int error = 0;
  bool forgotten = false;
};
struct Catalog {
  Catalog(uint64_t manager, WorkRegistryLimits limits)
      : registry(manager, limits),
        io(manager, limits.records, limits.work_serial_limit),
        launch(limits.launch),
        works(registry.valid() ? limits.records : 0) {}
  WorkRegistry registry;
  WorkIoPool io;
  const LaunchLimits launch;
  std::atomic<bool> closed{false};
  std::mutex mutex;
  std::vector<std::shared_ptr<Work>> works;
};
}  // namespace work_catalog_detail
using work_catalog_detail::Catalog;
using work_catalog_detail::Work;

WorkHandle::WorkHandle(std::shared_ptr<Work> work) : work_(std::move(work)) {}
WorkIdentity WorkHandle::identity() const {
  return work_ ? work_->control.identity() : WorkIdentity{};
}
bool WorkHandle::Stop() const {
  if (!work_) return false;
  // Every caller closes the actual entry gate even if another cancellation
  // flag write was observed first. This is not completion of an input read.
  const bool first = work_->control.Stop();
  work_->cancelled.store(true);
  return first;
}
bool WorkHandle::CancelUnstarted() const {
  if (!work_ || !work_->control.CancelUnstarted()) return false;
  work_->cancelled.store(true);
  return true;
}
WorkCatalogSnapshot WorkHandle::Inspect() const {
  if (!work_) return {};
  WorkCatalogSnapshot result;
  result.work = work_->control.Inspect();
  std::lock_guard lock(work_->mutex);
  result.inputs = work_->phase;
  result.input = work_->input;
  result.input_error = work_->error;
  return result;  // Two bounded metadata observations, not a global atomic
                  // sample.
}
WorkCatalog::WorkCatalog(uint64_t manager, WorkRegistryLimits limits)
    : state_(std::make_shared<Catalog>(manager, limits)) {}
WorkCatalog::~WorkCatalog() { Close(); }
bool WorkCatalog::valid() const { return state_->registry.valid(); }
uint64_t WorkCatalog::OpenStream() {
  return state_->registry.OpenStream().identity();
}
bool WorkCatalog::CloseStream(uint64_t stream) {
  return state_->registry.CloseStream(state_->registry.FindStream(stream));
}
void WorkCatalog::Collect() {
  std::vector<std::shared_ptr<Work>> retired;
  retired.reserve(state_->works.size());
  {
    std::lock_guard lock(state_->mutex);
    for (auto& work : state_->works) {
      if (!work || work.use_count() != 1) continue;
      std::lock_guard work_lock(work->mutex);
      if (work->forgotten && work->phase != WorkInputState::Preparing &&
          work->phase != WorkInputState::Releasing && !work->starts_pending)
        retired.push_back(std::move(work));
    }
  }  // Retirement, including registry gate destruction, is outside the mutex.
}
WorkHandle WorkCatalog::Capture(const WorkControl& control) {
  if (!control) return {};
  auto candidate = std::make_shared<Work>(state_, control);
  std::lock_guard lock(state_->mutex);
  for (auto& work : state_->works)
    if (work && work->control.identity() == control.identity())
      return WorkHandle(work);
  for (auto& work : state_->works)
    if (!work) {
      work = std::move(candidate);
      return WorkHandle(work);
    }
  // With equal registry/catalog capacities, every retained catalog entry pins
  // its own registry record. Failure here must never be treated as a new work.
  return {};
}
WorkCatalogReply WorkCatalog::Reserve(uint64_t stream, uint64_t sequence) {
  Collect();
  auto reply =
      state_->registry.Reserve(state_->registry.FindStream(stream), sequence);
  if (reply.allocation) {
    int error = 0;
    auto gate = WorkAdmission::Reserve(reply.work, error);
    reply = state_->registry.ReservationFinished(reply.allocation,
                                                 std::move(gate), error);
  }
  auto handle = Capture(reply.control);
  if (reply.control && !handle) {
    reply.control.Stop();
    return {WorkRegistryResult::Capacity, reply.work, {}, ENOSPC};
  }
  return {reply.result, reply.work, std::move(handle), reply.error};
}
WorkHandle WorkCatalog::Find(WorkIdentity work) {
  return Capture(state_->registry.Find(work));
}
std::vector<WorkCatalogSnapshot> WorkCatalog::List() {
  auto known = state_->registry.List();
  std::vector<WorkCatalogSnapshot> result;
  result.reserve(known.size());
  for (const auto& item : known) {
    auto handle = Find(item.work);
    if (handle) result.push_back(handle.Inspect());
  }
  return result;
}
WorkInputReply WorkCatalog::Prepare(const WorkHandle& work, int description,
                                    const std::array<int, 3>& standard) {
  if (!work || work.work_->owner.lock() != state_)
    return {WorkRegistryResult::Foreign};
  auto& item = *work.work_;
  {
    std::lock_guard lock(item.mutex);
    if (item.forgotten) return {WorkRegistryResult::Stale};
    if (item.phase == WorkInputState::Preparing)
      return {WorkRegistryResult::Pending, item.input, item.phase};
    if (item.phase != WorkInputState::Empty)
      return {WorkRegistryResult::Conflict, item.input, item.phase, item.error};
    if (state_->closed.load() || item.cancelled.load() ||
        item.control.Inspect().entry_gate_closed)
      return {WorkRegistryResult::Closed};
    item.phase = WorkInputState::Preparing;
  }
  auto reservation = state_->io.Reserve();
  int error = reservation.result == WorkIoResult::Accepted ? 0 : ENOSPC;
  if (!error) {
    std::lock_guard lock(item.mutex);
    item.input = reservation.reservation.identity();
  }
  LaunchDescription decoded;
  LaunchFailure failure;
  std::vector<uint8_t> encoded;
  if (!error) {
    int flags = fcntl(description, F_GETFL);
    if (flags < 0)
      error = errno;
    else if ((flags & O_PATH) || (flags & O_ACCMODE) != O_RDONLY)
      error = EACCES;
    else if (!ReadLaunch(description, state_->launch, decoded, failure) ||
             !EncodeLaunch(decoded, state_->launch, encoded, failure))
      error = failure.error ? failure.error : EINVAL;
  }
  WorkIoBinding binding;
  if (!error && !item.cancelled.load() && !state_->closed.load()) {
    auto captured = state_->io.Capture(reservation.reservation, standard);
    if (captured.result == WorkIoResult::Accepted)
      binding = std::move(captured.binding);
    else
      error = captured.error ? captured.error : EIO;
  } else if (!error)
    error = ECANCELED;
  // Serialize the last cancellation check with publication and CancelInputs.
  // A cancelled operation retains Preparing/Releasing until actual FD release.
  std::unique_lock lock(item.mutex);
  if (!error && (item.cancelled.load() || state_->closed.load()))
    error = ECANCELED;
  if (error) {
    item.phase = WorkInputState::Releasing;
    lock.unlock();
    if (binding)
      state_->io.Forget(binding);
    else if (reservation.reservation)
      state_->io.Cancel(reservation.reservation);
    lock.lock();
    item.error = error;
    item.phase = WorkInputState::Rejected;
    item.changed.notify_all();
    return {error == ECANCELED ? WorkRegistryResult::Closed
                               : WorkRegistryResult::Invalid,
            item.input, item.phase, error};
  }
  item.binding = std::move(binding);
  item.description = std::move(encoded);
  item.phase = WorkInputState::Ready;
  return {WorkRegistryResult::Accepted, item.input, item.phase};
}
WorkStartReply WorkCatalog::Start(const WorkHandle& work,
                                  WorkIoIdentity expected_input) {
  if (!work || work.work_->owner.lock() != state_)
    return {WorkRegistryResult::Foreign};
  auto& item = *work.work_;
  WorkIoBinding binding;
  {
    std::lock_guard lock(item.mutex);
    if (item.forgotten) return {WorkRegistryResult::Stale};
    if (item.phase == WorkInputState::Preparing)
      return {WorkRegistryResult::Pending};
    if (item.phase != WorkInputState::Ready &&
        item.phase != WorkInputState::Consumed)
      return {WorkRegistryResult::WrongState};
    if (item.input != expected_input) return {WorkRegistryResult::Conflict};
    binding = item.binding;
    ++item.starts_pending;
  }
  // Description and token are immutable after Ready. This strong work handle
  // protects their lifetime through concurrent Stop/Forget and exact retries.
  auto lease = state_->io.Lease(binding);
  auto reply = state_->registry.Start(item.control, item.description, lease);
  const bool accepted = reply.result == WorkRegistryResult::Accepted ||
                        reply.result == WorkRegistryResult::Existing;
  if (accepted) {
    // The reply already owns the creator lease. Consume before acknowledging,
    // including a lost reply, and never keep a registration writer in history.
    state_->io.Forget(binding);
  }
  lease.Release();  // Actual close precedes reporting this Start call's
                    // cessation.
  {
    std::lock_guard lock(item.mutex);
    if (accepted) item.phase = WorkInputState::Consumed;
    --item.starts_pending;
    item.changed.notify_all();
  }
  return reply;
}
WorkInputReply WorkCatalog::CancelInputs(const WorkHandle& work) {
  if (!work || work.work_->owner.lock() != state_)
    return {WorkRegistryResult::Foreign};
  auto& item = *work.work_;
  if (!item.cancelled.load() && !state_->closed.load())
    return {WorkRegistryResult::WrongState};
  std::unique_lock lock(item.mutex);
  if (item.phase == WorkInputState::Preparing ||
      item.phase == WorkInputState::Releasing)
    return {WorkRegistryResult::Pending, item.input, item.phase};
  if (item.phase == WorkInputState::Consumed ||
      item.phase == WorkInputState::Rejected)
    return {WorkRegistryResult::Existing, item.input, item.phase, item.error};
  item.phase = WorkInputState::Releasing;
  auto binding = item.binding;
  lock.unlock();
  if (binding) state_->io.Forget(binding);
  lock.lock();
  item.changed.wait(lock, [&] { return item.starts_pending == 0; });
  if (item.phase != WorkInputState::Consumed) {
    item.phase = WorkInputState::Rejected;
    item.error = ECANCELED;
  }
  return {WorkRegistryResult::Accepted, item.input, item.phase, item.error};
}
WorkRegistryResult WorkCatalog::Forget(const WorkHandle& work) {
  if (!work || work.work_->owner.lock() != state_)
    return WorkRegistryResult::Foreign;
  auto& item = *work.work_;
  WorkIoBinding binding;
  {
    std::lock_guard lock(item.mutex);
    if (item.forgotten) return WorkRegistryResult::Existing;
    if (item.phase == WorkInputState::Preparing ||
        item.phase == WorkInputState::Releasing || item.starts_pending ||
        !item.control.Inspect().complete)
      return WorkRegistryResult::Incomplete;
    item.cancelled.store(true);
    binding = item.binding;
  }
  if (binding) state_->io.Forget(binding);
  auto result = state_->registry.Forget(item.control);
  if (result == WorkRegistryResult::Accepted ||
      result == WorkRegistryResult::Existing) {
    std::lock_guard lock(item.mutex);
    item.forgotten = true;
  }
  return result;
}
WorkRegistryUsage WorkCatalog::usage() const {
  return state_->registry.usage();
}
void WorkCatalog::Close() {
  state_->closed.store(true);
  state_->registry.Close();
  state_->io.Close();
}
}  // namespace andrix
