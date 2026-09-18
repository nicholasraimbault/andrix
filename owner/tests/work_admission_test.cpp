// SPDX-License-Identifier: Apache-2.0
#include "work_admission.h"

#include <fcntl.h>
#include <unistd.h>

#include <atomic>
#include <barrier>
#include <cassert>
#include <cerrno>
#include <thread>

using namespace andrix;
namespace {
constexpr AuthorityEpoch original{11, 7, 0};
std::shared_ptr<WorkAdmission> reserve(uint64_t serial) {
  int error = 0;
  auto work = WorkAdmission::Reserve({91, serial}, error);
  assert(work && !error);
  return work;
}
void ready(AdmissionAuthority& authority) {
  assert(authority.Observe(original, 2100, 100) == AdmissionResult::Accepted);
}
void prepared(AdmissionAuthority& authority,
              const std::shared_ptr<WorkAdmission>& work) {
  assert(authority.Admit(work, 101) == AdmissionResult::Accepted);
  assert(authority.Prepared(work, 102) == AdmissionResult::Accepted);
}
void basic() {
  AdmissionAuthority authority;
  auto work = reserve(1);
  int error = 0;
  assert(work->phase() == AdmissionPhase::Unbound && !work->epoch());
  assert(work->Export(error) == -1 && error == EAGAIN);
  assert(authority.Admit(work, 1) == AdmissionResult::NotReady);
  assert(authority.Release(work, 1) == AdmissionResult::NotReady);
  ready(authority);
  assert(authority.Release(work, 101) == AdmissionResult::Foreign);
  assert(authority.Admit(work, 101) == AdmissionResult::Accepted);
  assert(work->epoch() == original);
  assert(authority.Release(work, 102) == AdmissionResult::WrongState);
  assert(work->ClaimEntry(work->work(), original, 102) ==
         EntryResult::NotReleased);
  assert(authority.Prepared(work, 102) == AdmissionResult::Accepted);
  assert(authority.Prepared(work, 102) == AdmissionResult::WrongState);
  assert(authority.Release(work, 103) == AdmissionResult::Accepted);
  assert(authority.Release(work, 104) == AdmissionResult::WrongState);
  assert(work->ClaimEntry({91, 2}, original, 104) == EntryResult::Foreign);
  assert(work->ClaimEntry(work->work(), {11, 8, 0}, 104) ==
         EntryResult::Foreign);
  assert(work->phase() == AdmissionPhase::Released);
  assert(work->ClaimEntry(work->work(), original, 104) == EntryResult::Entered);
  assert(work->ClaimEntry(work->work(), original, 105) ==
         EntryResult::AlreadyEntered);
  assert(authority.Retire(work) == AdmissionResult::WrongState);
  assert(work->Stop() && !work->Stop() && work->entered());
  assert(work->ClaimEntry(work->work(), original, 106) == EntryResult::Stopped);
  assert(authority.Release(work, 106) == AdmissionResult::Stopped);
  assert(authority.Retire(work) == AdmissionResult::Accepted);
  assert(authority.Retire(work) == AdmissionResult::Foreign);
  // A retired gate cannot bind again, even through a different authority
  // object.
  AdmissionAuthority replacement;
  ready(replacement);
  assert(replacement.Admit(work, 101) == AdmissionResult::Stopped);
}
void cancellation() {
  AdmissionAuthority authority;
  ready(authority);
  auto unbound = reserve(2);
  assert(unbound->Stop());
  assert(authority.Admit(unbound, 101) == AdmissionResult::Stopped);
  auto work = reserve(3);
  assert(authority.Admit(work, 102) == AdmissionResult::Accepted);
  assert(work->Stop());
  assert(authority.Prepared(work, 103) == AdmissionResult::Stopped);
  assert(authority.Release(work, 104) == AdmissionResult::Stopped);
  auto queued = reserve(4);
  assert(authority.Admit(queued, 105) == AdmissionResult::Accepted);
  assert(authority.Prepared(queued, 106) == AdmissionResult::Accepted);
  assert(authority.Release(queued, 107) == AdmissionResult::Accepted);
  queued->Stop();  // Even an already queued wake cannot convey permission.
  assert(queued->ClaimEntry(queued->work(), original, 108) ==
         EntryResult::Stopped);
  assert(!queued->entered());
}
void epochs_and_expiry() {
  AdmissionAuthority authority;
  ready(authority);
  auto old = reserve(5);
  prepared(authority, old);
  assert(authority.Observe(original, 2200, 200) == AdmissionResult::Accepted);
  assert(authority.Release(old, 201) == AdmissionResult::Accepted);
  // A renewal after publication does not lengthen the already issued entry
  // grant.
  assert(authority.Observe(original, 3000, 1000) == AdmissionResult::Accepted);
  assert(old->ClaimEntry(old->work(), original, 2200) == EntryResult::Expired);
  assert(authority.Release(old, 2201) == AdmissionResult::Stopped);
  auto late = reserve(6);
  assert(authority.Admit(late, 2202) == AdmissionResult::Accepted);
  authority.Revoke();
  assert(authority.Observe({11, 8, 0}, 4300, 2300) == AdmissionResult::Revoked);
  assert(authority.Prepared(late, 2301) == AdmissionResult::Revoked);
  AdmissionAuthority fresh;
  assert(fresh.Observe({11, 8, 0}, 4300, 2300) == AdmissionResult::Accepted);
  assert(fresh.Release(late, 2301) == AdmissionResult::Foreign);
  assert(fresh.Admit(late, 2301) == AdmissionResult::Stopped);
  auto next = reserve(7);
  assert(fresh.Admit(next, 2301) == AdmissionResult::Accepted);
  assert(next->epoch() == (AuthorityEpoch{11, 8, 0}));
  assert(fresh.Prepared(next, 2302) == AdmissionResult::Accepted);
  assert(fresh.Release(next, 2303) == AdmissionResult::Accepted);
  assert(next->ClaimEntry(next->work(), {11, 8, 0}, 2304) ==
         EntryResult::Entered);
  for (auto other : {AuthorityEpoch{12, 7, 0}, AuthorityEpoch{11, 8, 0},
                     AuthorityEpoch{11, 7, 10}}) {
    AdmissionAuthority fixed;
    ready(fixed);
    auto gate = reserve(8);
    prepared(fixed, gate);
    assert(fixed.Observe(other, 2200, 200) == AdmissionResult::Revoked);
    assert(fixed.failed() && gate->phase() == AdmissionPhase::Stopped);
  }
  AdmissionAuthority gap;
  ready(gap);
  auto lost = reserve(9);
  prepared(gap, lost);
  assert(gap.Observe(original, 4100, 2100) == AdmissionResult::Revoked);
  assert(lost->phase() ==
         AdmissionPhase::Stopped);  // Fresh reply cannot revive an expired
                                    // binding.
  AdmissionAuthority backwards;
  ready(backwards);
  auto clock = reserve(10);
  prepared(backwards, clock);
  assert(backwards.Release(clock, 99) == AdmissionResult::Revoked);
  AdmissionAuthority early;
  ready(early);
  auto entry = reserve(11);
  prepared(early, entry);
  assert(early.Release(entry, 103) == AdmissionResult::Accepted);
  assert(entry->ClaimEntry(entry->work(), original, 102) ==
         EntryResult::Expired);
}
void old_observation_cannot_extend_permission() {
  AdmissionAuthority authority;
  ready(authority);
  assert(authority.Observe(original, 2000, 200) == AdmissionResult::Accepted);
  auto gate = reserve(15);
  assert(authority.Admit(gate, 201) == AdmissionResult::Accepted);
  assert(authority.Prepared(gate, 202) == AdmissionResult::Accepted);
  assert(authority.Release(gate, 203) == AdmissionResult::Accepted);
  assert(gate->ClaimEntry(gate->work(), original, 2100) ==
         EntryResult::Expired);
}
void capacity_and_identity() {
  AdmissionAuthority authority(1);
  ready(authority);
  auto first = reserve(12), second = reserve(13), duplicate = reserve(12);
  assert(authority.Admit(first, 101) == AdmissionResult::Accepted);
  assert(authority.Admit(first, 102) == AdmissionResult::WrongState);
  assert(authority.Admit(duplicate, 103) == AdmissionResult::Foreign);
  assert(authority.Admit(second, 104) == AdmissionResult::Capacity);
  first->Stop();
  assert(authority.Admit(second, 105) == AdmissionResult::Capacity);
  assert(authority.Retire(first) == AdmissionResult::Accepted);
  assert(authority.Admit(second, 106) == AdmissionResult::Accepted);
  for (size_t capacity :
       {size_t(0), AdmissionAuthority::kMaximumAdmissions + 1}) {
    AdmissionAuthority invalid(capacity);
    assert(invalid.Observe(original, 2100, 100) == AdmissionResult::Revoked);
  }
  AdmissionAuthority invalid;
  assert(invalid.Observe(original, 2101, 100) == AdmissionResult::Revoked);
}
void descriptors() {
  int error = 0;
  assert(!WorkAdmission::Reserve({0, 1}, error) && error == EINVAL);
  assert(!WorkAdmission::Reserve({1, 0}, error) && error == EINVAL);
  int null = open("/dev/null", O_RDWR | O_CLOEXEC);
  assert(null >= 0);
  assert(!WorkAdmission::Adopt(null, {91, 14}, original, error));
  assert(fcntl(null, F_GETFD) == -1 && errno == EBADF);
  AdmissionAuthority authority;
  ready(authority);
  auto work = reserve(14);
  prepared(authority, work);
  int fd = work->Export(error);
  assert(fd >= 0 && !error);
  assert(
      (fcntl(fd, F_GET_SEALS) & (F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) ==
      (F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL));
  assert(ftruncate(fd, 8192) == -1 && errno == EPERM);
  auto peer = WorkAdmission::Adopt(fd, work->work(), original, error);
  assert(peer && !error);
  fd = work->Export(error);
  assert(fd >= 0);
  assert(!WorkAdmission::Adopt(fd, work->work(), {11, 99, 0}, error) &&
         error == ESTALE);
  assert(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
  assert(authority.Release(work, 103) == AdmissionResult::Accepted);
  assert(peer->ClaimEntry(work->work(), original, 104) == EntryResult::Entered);
  assert(work->entered());
  peer->Stop();
  assert(work->phase() == AdmissionPhase::Stopped);
}
void interleavings() {
  // Actual competing threads and real shared atomics, not a sequential model.
  for (uint64_t n = 0; n < 1000; ++n) {
    AdmissionAuthority authority;
    ready(authority);
    auto gate = reserve(100 + n);
    prepared(authority, gate);
    std::barrier start(4);
    std::atomic<bool> stopped{false};
    AdmissionResult publication = AdmissionResult::Invalid;
    EntryResult entry = EntryResult::Foreign;
    bool after_stop = false;
    std::thread publisher([&] {
      start.arrive_and_wait();
      publication = authority.Release(gate, 103);
    });
    std::thread stopper([&] {
      start.arrive_and_wait();
      gate->Stop();
      stopped.store(true);
    });
    std::thread launcher([&] {
      start.arrive_and_wait();
      after_stop = stopped.load();
      entry = gate->ClaimEntry(gate->work(), original, 104);
    });
    start.arrive_and_wait();
    publisher.join();
    stopper.join();
    launcher.join();
    assert(gate->phase() == AdmissionPhase::Stopped);
    if (after_stop) assert(entry == EntryResult::Stopped);
    if (entry == EntryResult::Entered)
      assert(publication == AdmissionResult::Accepted && gate->entered());
    else
      assert(!gate->entered());
    assert(authority.Release(gate, 105) == AdmissionResult::Stopped);
    assert(gate->ClaimEntry(gate->work(), original, 106) ==
           EntryResult::Stopped);
  }
  for (uint64_t n = 0; n < 500; ++n) {
    AdmissionAuthority authority;
    ready(authority);
    auto gate = reserve(2000 + n);
    prepared(authority, gate);
    std::barrier start(3);
    AdmissionResult publication = AdmissionResult::Invalid;
    std::thread publisher([&] {
      start.arrive_and_wait();
      publication = authority.Release(gate, 103);
    });
    std::thread revoke([&] {
      start.arrive_and_wait();
      authority.Revoke();
    });
    start.arrive_and_wait();
    publisher.join();
    revoke.join();
    assert(publication == AdmissionResult::Accepted ||
           publication == AdmissionResult::Revoked);
    assert(gate->ClaimEntry(gate->work(), original, 104) ==
           EntryResult::Stopped);
    assert(authority.Observe(original, 2200, 200) == AdmissionResult::Revoked);
  }
}
}  // namespace
int main() {
  basic();
  cancellation();
  epochs_and_expiry();
  old_observation_cannot_extend_permission();
  capacity_and_identity();
  descriptors();
  interleavings();
}
