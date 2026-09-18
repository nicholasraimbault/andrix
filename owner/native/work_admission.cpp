// SPDX-License-Identifier: Apache-2.0
#include "work_admission.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <new>
#include <utility>

#include "lifecycle_core.h"

namespace andrix {
namespace {
constexpr size_t kMappingBytes = 4096;
constexpr uint64_t kMagic = 0x414e445857474154ULL;
constexpr uint32_t kBinding = 1, kBound = 2, kPrepared = 4, kPublishing = 8,
                   kReleased = 16, kEntered = 32, kStopped = 64;
constexpr int kSeals = F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
// Linux memfd ABI: CLOEXEC | ALLOW_SEALING. The hermetic Soong host
// sysroot has the syscall/seal definitions but no linux/memfd.h.
constexpr unsigned kMemfdOptions = 0x0001U | 0x0002U;
#if defined(MFD_CLOEXEC) && defined(MFD_ALLOW_SEALING)
static_assert(kMemfdOptions == (MFD_CLOEXEC | MFD_ALLOW_SEALING));
#endif
static_assert(std::atomic<uint32_t>::is_always_lock_free);
bool valid(WorkIdentity work) { return work.manager && work.serial; }
bool valid(AuthorityEpoch epoch) {
  return epoch.platform && epoch.generation && epoch.user >= 0;
}
bool valid_word(uint32_t word) {
  word &= ~kStopped;
  return word == 0 || word == kBinding || word == kBound ||
         word == (kBound | kPrepared) ||
         word == (kBound | kPrepared | kPublishing) ||
         word == (kBound | kPrepared | kReleased) ||
         word == (kBound | kPrepared | kReleased | kEntered);
}
AdmissionResult refused(const WorkAdmission& gate) {
  return gate.phase() == AdmissionPhase::Stopped ? AdmissionResult::Stopped
                                                 : AdmissionResult::WrongState;
}
}  // namespace

struct WorkAdmission::Shared {
  uint64_t magic = kMagic;
  uint32_t version = 1;
  uint32_t bytes = kMappingBytes;
  std::atomic<uint32_t> flags{0};
  uint32_t reserved = 0;
  WorkIdentity work{};
  AuthorityEpoch epoch{};
  uint64_t released_at = 0;
  uint64_t deadline = 0;
};

WorkAdmission::WorkAdmission(int fd, Shared* mapping)
    : fd_(fd), shared_(mapping) {}
WorkAdmission::~WorkAdmission() {
  // A mapped gate may still be owned by the trusted launcher. Do not end its
  // atomic object's lifetime from another mapping; kernel references own
  // storage.
  if (shared_) munmap(shared_, kMappingBytes);
  if (fd_ >= 0) close(fd_);
}
std::shared_ptr<WorkAdmission> WorkAdmission::Reserve(WorkIdentity work,
                                                      int& error) {
  static_assert(sizeof(Shared) <= kMappingBytes);
  error = 0;
  if (!valid(work)) {
    error = EINVAL;
    return {};
  }
  int fd = static_cast<int>(
      syscall(SYS_memfd_create, "andrix-work-gate", kMemfdOptions));
  if (fd < 0) {
    error = errno;
    return {};
  }
  if (ftruncate(fd, kMappingBytes) || fcntl(fd, F_ADD_SEALS, kSeals)) {
    error = errno;
    close(fd);
    return {};
  }
  void* address =
      mmap(nullptr, kMappingBytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (address == MAP_FAILED) {
    error = errno;
    close(fd);
    return {};
  }
  auto* mapping = new (address) Shared;
  mapping->work = work;
  return std::shared_ptr<WorkAdmission>(new WorkAdmission(fd, mapping));
}
std::shared_ptr<WorkAdmission> WorkAdmission::Adopt(
    int fd, WorkIdentity expected_work, AuthorityEpoch expected_epoch,
    int& error) {
  error = 0;
  auto reject = [&](int code) {
    error = code;
    if (fd >= 0) close(fd);
    return std::shared_ptr<WorkAdmission>{};
  };
  if (fd < 0 || !valid(expected_work) || !valid(expected_epoch))
    return reject(EINVAL);
  struct stat info{};
  const int mode = fcntl(fd, F_GETFL), seals = fcntl(fd, F_GET_SEALS);
  if (mode < 0 || seals < 0 || fstat(fd, &info)) return reject(errno);
  if (!S_ISREG(info.st_mode) || info.st_size != kMappingBytes ||
      (mode & O_ACCMODE) != O_RDWR || (mode & O_PATH) ||
      (seals & kSeals) != kSeals || (seals & F_SEAL_WRITE))
    return reject(EINVAL);
  if (fcntl(fd, F_SETFD, FD_CLOEXEC)) return reject(errno);
  void* address =
      mmap(nullptr, kMappingBytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (address == MAP_FAILED) return reject(errno);
  auto* mapping = static_cast<Shared*>(address);
  const uint32_t flags = mapping->flags.load(std::memory_order_acquire);
  // Bound is the publication of immutable epoch fields, including on a later
  // stopped gate. A binding interrupted by Stop is not a usable handoff.
  if (!valid_word(flags) || !(flags & kBound) || mapping->magic != kMagic ||
      mapping->version != 1 || mapping->bytes != kMappingBytes ||
      mapping->reserved || mapping->work != expected_work ||
      mapping->epoch != expected_epoch) {
    munmap(mapping, kMappingBytes);
    return reject(ESTALE);
  }
  return std::shared_ptr<WorkAdmission>(new WorkAdmission(fd, mapping));
}
int WorkAdmission::Export(int& error) const {
  error = 0;
  if (!(shared_->flags.load(std::memory_order_acquire) & kBound)) {
    error = EAGAIN;
    return -1;
  }
  int fd = fcntl(fd_, F_DUPFD_CLOEXEC, 0);
  if (fd < 0) error = errno;
  return fd;
}
WorkIdentity WorkAdmission::work() const { return shared_->work; }
std::optional<AuthorityEpoch> WorkAdmission::epoch() const {
  if (!(shared_->flags.load(std::memory_order_acquire) & kBound))
    return std::nullopt;
  return shared_->epoch;
}
AdmissionPhase WorkAdmission::phase() const {
  const auto word = shared_->flags.load(std::memory_order_acquire);
  if (word & kStopped) return AdmissionPhase::Stopped;
  if (word & kEntered) return AdmissionPhase::Entered;
  if (word & kReleased) return AdmissionPhase::Released;
  if (word & kPublishing) return AdmissionPhase::Publishing;
  if (word & kPrepared) return AdmissionPhase::Prepared;
  if (word & kBound) return AdmissionPhase::Admitted;
  if (word & kBinding) return AdmissionPhase::Binding;
  return AdmissionPhase::Unbound;
}
bool WorkAdmission::entered() const {
  return shared_->flags.load(std::memory_order_acquire) & kEntered;
}
bool WorkAdmission::Stop() {
  return !(shared_->flags.fetch_or(kStopped, std::memory_order_seq_cst) &
           kStopped);
}
bool WorkAdmission::Bind(AuthorityEpoch epoch) {
  uint32_t expected = 0;
  if (!shared_->flags.compare_exchange_strong(expected, kBinding)) return false;
  shared_->epoch = epoch;
  expected = kBinding;
  return shared_->flags.compare_exchange_strong(expected, kBound);
}
bool WorkAdmission::Prepared() {
  uint32_t expected = kBound;
  return shared_->flags.compare_exchange_strong(expected, kBound | kPrepared);
}
bool WorkAdmission::Publish(uint64_t now, uint64_t deadline) {
  uint32_t expected = kBound | kPrepared;
  if (!shared_->flags.compare_exchange_strong(expected,
                                              kBound | kPrepared | kPublishing))
    return false;
  shared_->released_at = now;
  shared_->deadline = deadline;
  expected = kBound | kPrepared | kPublishing;
  return shared_->flags.compare_exchange_strong(expected,
                                                kBound | kPrepared | kReleased);
}
EntryResult WorkAdmission::ClaimEntry(WorkIdentity expected_work,
                                      AuthorityEpoch expected_epoch,
                                      uint64_t now) {
  if (work() != expected_work) return EntryResult::Foreign;
  uint32_t word = shared_->flags.load(std::memory_order_acquire);
  if (!(word & kBound))
    return word & kStopped ? EntryResult::Stopped : EntryResult::NotReleased;
  if (shared_->epoch != expected_epoch) return EntryResult::Foreign;
  if (word & kStopped) return EntryResult::Stopped;
  if (word & kEntered) return EntryResult::AlreadyEntered;
  if (!(word & kReleased)) return EntryResult::NotReleased;
  if (now < shared_->released_at || now >= shared_->deadline) {
    Stop();
    return EntryResult::Expired;
  }
  if (shared_->flags.compare_exchange_strong(word, word | kEntered))
    return EntryResult::Entered;
  return word & kStopped ? EntryResult::Stopped : EntryResult::AlreadyEntered;
}

AdmissionAuthority::~AdmissionAuthority() { Revoke(); }
void AdmissionAuthority::RevokeLocked() {
  failed_ = true;
  deadline_ = 0;
  for (const auto& admission : admissions_)
    if (admission) admission->Stop();
}
void AdmissionAuthority::Revoke() {
  std::lock_guard lock(mutex_);
  RevokeLocked();
}
bool AdmissionAuthority::Fresh(uint64_t now) {
  if (capacity_ == 0 || capacity_ > kMaximumAdmissions || now < observed_)
    RevokeLocked();
  observed_ = now;
  if (epoch_ && now >= deadline_) RevokeLocked();
  return !failed_ && epoch_.has_value();
}
bool AdmissionAuthority::Registered(
    const std::shared_ptr<WorkAdmission>& work) const {
  for (const auto& entry : admissions_)
    if (entry && entry == work) return true;
  return false;
}
AdmissionResult AdmissionAuthority::Observe(AuthorityEpoch epoch,
                                            uint64_t deadline, uint64_t now) {
  std::lock_guard lock(mutex_);
  Fresh(now);
  if (failed_) return AdmissionResult::Revoked;
  if (!valid(epoch) || deadline <= now ||
      deadline - now > kLifecycleLeaseMillis || (epoch_ && *epoch_ != epoch)) {
    RevokeLocked();
    return AdmissionResult::Revoked;
  }
  if (!epoch_) epoch_ = epoch;
  if (deadline > deadline_)
    deadline_ = deadline;  // Older evidence cannot renew.
  return AdmissionResult::Accepted;
}
AdmissionResult AdmissionAuthority::Admit(
    const std::shared_ptr<WorkAdmission>& work, uint64_t now) {
  std::lock_guard lock(mutex_);
  if (!Fresh(now))
    return failed_ ? AdmissionResult::Revoked : AdmissionResult::NotReady;
  if (!work) return AdmissionResult::Invalid;
  for (const auto& entry : admissions_) {
    if (entry && entry == work) return AdmissionResult::WrongState;
    if (entry && entry->work() == work->work()) return AdmissionResult::Foreign;
  }
  for (size_t slot = 0; slot < capacity_; ++slot) {
    if (admissions_[slot]) continue;
    if (!work->Bind(*epoch_)) return refused(*work);
    admissions_[slot] = work;
    return AdmissionResult::Accepted;
  }
  return AdmissionResult::Capacity;
}
AdmissionResult AdmissionAuthority::Prepared(
    const std::shared_ptr<WorkAdmission>& work, uint64_t now) {
  std::lock_guard lock(mutex_);
  if (!Fresh(now))
    return failed_ ? AdmissionResult::Revoked : AdmissionResult::NotReady;
  if (!work || !Registered(work) || work->epoch() != epoch_)
    return AdmissionResult::Foreign;
  return work->Prepared() ? AdmissionResult::Accepted : refused(*work);
}
AdmissionResult AdmissionAuthority::Release(
    const std::shared_ptr<WorkAdmission>& work, uint64_t now,
    uint64_t deadline_ceiling) {
  std::lock_guard lock(mutex_);
  if (!Fresh(now))
    return failed_ ? AdmissionResult::Revoked : AdmissionResult::NotReady;
  if (!work || !Registered(work) || work->epoch() != epoch_)
    return AdmissionResult::Foreign;
  const uint64_t deadline =
      deadline_ceiling < deadline_ ? deadline_ceiling : deadline_;
  if (deadline <= now) {
    work->Stop();
    return AdmissionResult::Stopped;
  }
  return work->Publish(now, deadline) ? AdmissionResult::Accepted
                                      : refused(*work);
}
AdmissionResult AdmissionAuthority::Retire(
    const std::shared_ptr<WorkAdmission>& work) {
  std::shared_ptr<WorkAdmission> released;
  {
    std::lock_guard lock(mutex_);
    if (!work) return AdmissionResult::Invalid;
    for (auto& entry : admissions_) {
      if (entry != work) continue;
      if (work->phase() != AdmissionPhase::Stopped)
        return AdmissionResult::WrongState;
      released = std::move(entry);
      break;
    }
  }
  // Descriptor destruction, if this was its last owner, stays outside the lock.
  return released ? AdmissionResult::Accepted : AdmissionResult::Foreign;
}
bool AdmissionAuthority::failed() const {
  std::lock_guard lock(mutex_);
  return failed_;
}

}  // namespace andrix
