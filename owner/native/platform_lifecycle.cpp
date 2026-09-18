// SPDX-License-Identifier: Apache-2.0
#include "platform_lifecycle.h"

#include <android/binder_manager.h>
#include <chrono>
#include <thread>
#include <time.h>
#include <unistd.h>

namespace andrix {

uint64_t PlatformLifecycle::now() {
  timespec value{};
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) _exit(125);
  return uint64_t(value.tv_sec) * 1000 + uint64_t(value.tv_nsec) / 1000000;
}

bool PlatformLifecycle::start() {
  ndk::SpAIBinder binder(AServiceManager_checkService("andrix.owner.lifecycle"));
  if (!binder.get() || !AIBinder_isRemote(binder.get())) return false;
  service_ = aidl::dev::andrix::lifecycle::IPlatformLifecycle::fromBinder(binder);
  if (!service_) return false;
  death_ = AIBinder_DeathRecipient_new([](void*) {
    // One fixed platform binding for this daemon. Do not wait on its possibly
    // stalled main loop/mutex; init reaps and kills the entire owned cgroup.
    _exit(0);
  });
  if (!death_) return false;
  // No dynamic cookie: its object/process lifetime is fixed, including link error.
  AIBinder_DeathRecipient_setOnUnlinked(death_, [](void*) { });
  if (AIBinder_linkToDeath(binder.get(), death_, this) != STATUS_OK) return false;
  {
    std::lock_guard lock(mutex_);
    registration_ = gate_.begin(now());
    if (registration_ == 0) return false;
  }
  std::thread([this] { observe(); }).detach();
  return true;
}

void PlatformLifecycle::fail_locked() {
  failed_ = true;
  gate_.revoke();
  admissions_.Revoke();
#ifdef ANDRIX_OWNER_KEEP
  if (request_) { request_->done = true; request_->accepted = false; }
  changed_.notify_all();
#endif
}

#ifdef ANDRIX_OWNER_KEEP
bool PlatformLifecycle::retain(const ndk::SpAIBinder& lifetime, uint64_t work_id) {
  if (!lifetime.get() || work_id == 0 || work_id > INT64_MAX) return false;
  std::unique_lock lock(mutex_);
  if (failed_ || !gate_.ready(now()) || request_) return false;
  if (keep_registration_ != 0) return kept_work_ == work_id;
  auto request = std::make_shared<KeepRequest>();
  request->lifetime = lifetime; request->work = work_id;
  request_ = request;
  // The observer's issued query deadline also covers grant+confirmation RPCs.
  // This bounds caller waiting without turning receipt time into a fresh lease.
  if (!changed_.wait_for(lock, std::chrono::milliseconds(kLifecycleLeaseMillis),
                        [&] { return request->done || failed_; })) {
    fail_locked();
  }
  const bool accepted = !failed_ && request->done && request->accepted && gate_.ready(now());
  if (request_ == request) request_.reset();
  return accepted;
}
#endif

bool PlatformLifecycle::ready() {
  std::lock_guard lock(mutex_);
  const uint64_t current = now();
  if (!gate_.valid(current)) fail_locked();
  return !failed_ && gate_.ready(current);
}

bool PlatformLifecycle::failed() {
  std::lock_guard lock(mutex_);
  if (!gate_.valid(now())) fail_locked();
  return failed_;
}

AdmissionResult PlatformLifecycle::admit_work(const std::shared_ptr<WorkAdmission>& work) {
  std::lock_guard lock(mutex_);
  const uint64_t current = now();
  if (!gate_.valid(current)) fail_locked();
  if (failed_) return AdmissionResult::Revoked;
  if (!gate_.ready(current)) return AdmissionResult::NotReady;
  return admissions_.Admit(work, current);
}

AdmissionResult PlatformLifecycle::prepare_work(const std::shared_ptr<WorkAdmission>& work) {
  std::lock_guard lock(mutex_);
  const uint64_t current = now();
  if (!gate_.valid(current)) fail_locked();
  if (failed_) return AdmissionResult::Revoked;
  if (!gate_.ready(current)) return AdmissionResult::NotReady;
  return admissions_.Prepared(work, current);
}

AdmissionResult PlatformLifecycle::release_work(const std::shared_ptr<WorkAdmission>& work) {
  std::lock_guard lock(mutex_);
  const uint64_t current = now();
  if (!gate_.valid(current)) fail_locked();
  if (failed_) return AdmissionResult::Revoked;
  if (!gate_.ready(current)) return AdmissionResult::NotReady;
  return admissions_.Release(work, current, gate_.ready_until(current));
}

AdmissionResult PlatformLifecycle::retire_work(const std::shared_ptr<WorkAdmission>& work) {
  return admissions_.Retire(work);
}

void PlatformLifecycle::observe() {
  for (;;) {
    uint64_t challenge;
#ifdef ANDRIX_OWNER_KEEP
    std::shared_ptr<KeepRequest> request;
    int64_t expected_instance = 0, expected_generation = 0, granted = 0;
#endif
    {
      std::lock_guard lock(mutex_);
      if (failed_) return;
      challenge = gate_.begin_query(registration_, now());
      if (challenge == 0) { fail_locked(); return; }
#ifdef ANDRIX_OWNER_KEEP
      request = request_;
      expected_instance = instance_; expected_generation = generation_;
#endif
    }
    // Never perform synchronous Binder I/O while holding either monitor/daemon
    // mutex. A stalled transaction cannot prevent the main loop noticing expiry.
#ifdef ANDRIX_OWNER_KEEP
    if (request) {
      auto granted_status = service_->keepWork(request->lifetime,
          static_cast<int64_t>(request->work), expected_instance, expected_generation, &granted);
      if (!granted_status.isOk() || granted <= 0) {
        std::lock_guard lock(mutex_); fail_locked(); return;
      }
    }
#endif
    aidl::dev::andrix::lifecycle::PlatformState state;
    auto result = service_->snapshot(&state);
    {
      std::lock_guard lock(mutex_);
      if (failed_) return;
      if (!result.isOk() || state.instance <= 0 || state.generation <= 0 || !state.available ||
          (instance_ != 0 && (instance_ != state.instance || generation_ != state.generation))) {
        fail_locked(); return;
      }
#ifdef ANDRIX_OWNER_KEEP
      const uint64_t expected_work = request ? request->work : kept_work_;
      const int64_t expected_keep = request ? granted : keep_registration_;
      if (expected_keep != 0 && (state.keptWorkId != static_cast<int64_t>(expected_work)
                                || state.keepRegistration != expected_keep)) {
        fail_locked(); return;
      }
#endif
      const uint64_t received = now();
      if (!gate_.report(registration_, challenge, received, true, true)) {
        fail_locked(); return;
      }
      instance_ = state.instance;
      generation_ = state.generation;
      // OwnerLifecycleService observes only Android user 0 in this adapter.
      // This is not a caller-selectable user or a multi-user authority claim.
      const AuthorityEpoch epoch{static_cast<uint64_t>(instance_),
                                 static_cast<uint64_t>(generation_), 0};
      if (admissions_.Observe(epoch, gate_.ready_until(received), received) != AdmissionResult::Accepted) {
        fail_locked(); return;
      }
#ifdef ANDRIX_OWNER_KEEP
      if (request) {
        kept_work_ = request->work; keep_registration_ = granted;
        request->done = true; request->accepted = true;
        changed_.notify_all();
        if (request_ == request) request_.reset();
      }
#endif
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
  }
}

} // namespace andrix
