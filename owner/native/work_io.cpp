// SPDX-License-Identifier: Apache-2.0
#include "work_io.h"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <mutex>
#include <utility>
#include <vector>

namespace andrix {
namespace work_io_detail {
struct Binding {
  Binding(const std::shared_ptr<Pool>& owner, WorkIoIdentity identity,
          std::array<int, 3> descriptors)
      : owner(owner), identity(identity), descriptors(descriptors) {}
  ~Binding() {
    for (int fd : descriptors)
      if (fd >= 0) close(fd);
  }
  const std::weak_ptr<Pool> owner;
  const WorkIoIdentity identity;
  const std::array<int, 3> descriptors;
  bool forgotten = false;  // Pool mutex, never a descriptor revocation flag.
};
enum class Phase { Empty, Reserved, Capturing, Ready, Failed };
struct Slot {
  WorkIoIdentity identity{};
  Phase phase = Phase::Empty;
  bool cancelled = false;
  int error = 0;
  std::shared_ptr<Binding> binding;
};
struct Pool {
  Pool(uint64_t manager, size_t capacity, uint64_t limit)
      : manager(manager), limit(limit), slots(capacity) {}
  const uint64_t manager, limit;
  mutable std::mutex mutex;
  uint64_t sequence = 0;
  bool closed = false;
  std::vector<Slot> slots;
};
}  // namespace work_io_detail
namespace {
using work_io_detail::Phase;
using work_io_detail::Pool;
using work_io_detail::Slot;
Slot* find(Pool& pool, WorkIoIdentity identity) {
  if (!identity.serial || identity.manager != pool.manager) return nullptr;
  for (auto& slot : pool.slots)
    if (slot.phase != Phase::Empty && slot.identity == identity) return &slot;
  return nullptr;
}
struct Captured {
  std::array<int, 3> descriptors{-1, -1, -1};
  ~Captured() { Reset(); }
  void Reset() {
    for (int& descriptor : descriptors) {
      const int fd = std::exchange(descriptor, -1);
      if (fd >= 0) close(fd);
    }
  }
  std::array<int, 3> Take() { return std::exchange(descriptors, {-1, -1, -1}); }
};
int capture(const std::array<int, 3>& source, Captured& result) {
  for (size_t index = 0; index < source.size(); ++index) {
    if (source[index] == -1) continue;
    if (source[index] < -1) return EBADF;
    const int fd = fcntl(source[index], F_DUPFD_CLOEXEC, 3);
    if (fd < 0) return errno;
    result.descriptors[index] = fd;
    const int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return errno;
    if (flags & O_PATH) return EINVAL;
    const int access = flags & O_ACCMODE;
    if (access != O_RDONLY && access != O_WRONLY && access != O_RDWR)
      return EINVAL;
    if ((index == 0 && access == O_WRONLY) ||
        (index != 0 && access == O_RDONLY))
      return EBADF;
  }
  return 0;
}
}  // namespace
WorkIoBinding::WorkIoBinding(std::shared_ptr<work_io_detail::Binding> binding)
    : binding_(std::move(binding)) {}
WorkIoBinding WorkIoBinding::Closed() {
  WorkIoBinding result;
  result.closed_plan_ = true;
  return result;
}
WorkIoIdentity WorkIoBinding::identity() const {
  return binding_ ? binding_->identity : WorkIoIdentity{};
}
int WorkIoBinding::descriptor(size_t standard) const {
  return binding_ && standard < binding_->descriptors.size()
             ? binding_->descriptors[standard]
             : -1;
}
WorkIoReservation::WorkIoReservation(std::shared_ptr<Pool> issuer,
                                     WorkIoIdentity identity)
    : issuer_(std::move(issuer)), identity_(identity) {}
WorkIoPool::WorkIoPool(uint64_t manager, size_t capacity, uint64_t serial_limit)
    : state_(std::make_shared<Pool>(
          manager, manager && capacity <= kMaximumBindings ? capacity : 0,
          serial_limit)) {
  if (!manager || !capacity || capacity > kMaximumBindings)
    state_->closed = true;
}
WorkIoPool::~WorkIoPool() { Close(); }
WorkIoReply WorkIoPool::Reserve() {
  std::shared_ptr<work_io_detail::Binding> retired;
  std::unique_lock lock(state_->mutex);
  if (state_->closed) return {WorkIoResult::Closed};
  if (state_->sequence >= state_->limit) return {WorkIoResult::Exhausted};
  Slot* chosen = nullptr;
  for (auto& slot : state_->slots) {
    if (slot.phase == Phase::Empty || slot.phase == Phase::Failed ||
        (slot.phase == Phase::Ready && slot.binding->forgotten &&
         slot.binding.use_count() == 1)) {
      chosen = &slot;
      break;
    }
  }
  if (!chosen) return {WorkIoResult::Capacity};
  retired = std::move(chosen->binding);
  *chosen = {};
  chosen->identity = {state_->manager, ++state_->sequence};
  chosen->phase = Phase::Reserved;
  WorkIoReply reply{WorkIoResult::Accepted,
                    WorkIoReservation(state_, chosen->identity)};
  lock.unlock();  // Descriptor destruction is outside the pool mutex.
  return reply;
}
WorkIoReply WorkIoPool::Capture(const WorkIoReservation& ticket,
                                const std::array<int, 3>& descriptors) {
  if (!ticket || ticket.issuer_ != state_) return {WorkIoResult::Foreign};
  {
    std::lock_guard lock(state_->mutex);
    Slot* slot = find(*state_, ticket.identity());
    if (!slot) return {WorkIoResult::Stale};
    if (slot->phase == Phase::Ready) {
      if (slot->binding->forgotten) return {WorkIoResult::Stale};
      return {WorkIoResult::Existing, {}, WorkIoBinding(slot->binding)};
    }
    if (state_->closed || slot->cancelled || slot->phase == Phase::Failed)
      return {WorkIoResult::Closed, {}, {}, slot->error};
    if (slot->phase != Phase::Reserved) return {WorkIoResult::Capacity};
    slot->phase = Phase::Capturing;
  }
  Captured captured;
  int error = capture(descriptors, captured);  // No pool/registry/control lock.
  std::shared_ptr<work_io_detail::Binding> candidate;
  if (!error) {
    // Keep ownership in Captured until allocation/initialization succeeds.
    // Allocation also stays outside shared control locks.
    candidate = std::make_shared<work_io_detail::Binding>(
        state_, ticket.identity(), captured.descriptors);
    captured.Take();
  }
  std::unique_lock lock(state_->mutex);
  Slot* slot = find(*state_, ticket.identity());
  // A Capturing slot cannot be freed or replaced by Cancel/Close/Reserve.
  if (!slot || slot->phase != Phase::Capturing) return {WorkIoResult::Stale};
  if (error || slot->cancelled || state_->closed) {
    const int reported = error ? error : ECANCELED;
    // Last descriptor close can itself stall. Keep the slot charged until the
    // actual closes finish, without holding the pool mutex or replacing it.
    lock.unlock();
    candidate.reset();
    captured.Reset();
    lock.lock();
    slot = find(*state_, ticket.identity());
    if (!slot || slot->phase != Phase::Capturing) return {WorkIoResult::Stale};
    slot->phase = Phase::Failed;
    slot->error = reported;
    return {error ? WorkIoResult::Io : WorkIoResult::Closed, {}, {}, reported};
  }
  slot->binding = std::move(candidate);
  slot->phase = Phase::Ready;
  return {WorkIoResult::Accepted, {}, WorkIoBinding(slot->binding)};
}
bool WorkIoPool::Cancel(const WorkIoReservation& ticket) {
  if (!ticket || ticket.issuer_ != state_) return false;
  std::lock_guard lock(state_->mutex);
  Slot* slot = find(*state_, ticket.identity());
  if (!slot ||
      (slot->phase != Phase::Reserved && slot->phase != Phase::Capturing))
    return false;
  slot->cancelled = true;
  slot->error = ECANCELED;
  if (slot->phase == Phase::Reserved) slot->phase = Phase::Failed;
  return true;
}
WorkIoBinding WorkIoPool::Find(WorkIoIdentity identity) const {
  std::lock_guard lock(state_->mutex);
  Slot* slot = find(*state_, identity);
  return slot && slot->phase == Phase::Ready && !slot->binding->forgotten
             ? WorkIoBinding(slot->binding)
             : WorkIoBinding{};
}
bool WorkIoPool::Forget(const WorkIoBinding& binding) {
  if (!binding.binding_ || binding.binding_->owner.lock() != state_)
    return false;
  std::lock_guard lock(state_->mutex);
  binding.binding_->forgotten = true;
  return true;
}
WorkIoUsage WorkIoPool::usage() const {
  std::lock_guard lock(state_->mutex);
  WorkIoUsage result;
  result.closed = state_->closed;
  for (const auto& slot : state_->slots) {
    result.occupied += slot.phase != Phase::Empty;
    result.pending +=
        slot.phase == Phase::Reserved || slot.phase == Phase::Capturing;
  }
  return result;
}
void WorkIoPool::Close() {
  std::lock_guard lock(state_->mutex);
  state_->closed = true;
  for (auto& slot : state_->slots) {
    if (slot.phase == Phase::Reserved) {
      slot.phase = Phase::Failed;
      slot.error = ECANCELED;
    }
    if (slot.phase == Phase::Capturing) {
      slot.cancelled = true;
      slot.error = ECANCELED;
    }
  }
}
}  // namespace andrix
