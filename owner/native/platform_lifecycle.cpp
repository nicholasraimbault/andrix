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
}

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

void PlatformLifecycle::observe() {
  for (;;) {
    uint64_t challenge;
    {
      std::lock_guard lock(mutex_);
      if (failed_) return;
      challenge = gate_.begin_query(registration_, now());
      if (challenge == 0) { fail_locked(); return; }
    }
    // Never perform synchronous Binder I/O while holding either monitor/daemon
    // mutex. A stalled transaction cannot prevent the main loop noticing expiry.
    aidl::dev::andrix::lifecycle::PlatformState state;
    auto result = service_->snapshot(&state);
    {
      std::lock_guard lock(mutex_);
      if (failed_) return;
      if (!result.isOk() || state.instance <= 0 || state.generation <= 0 || !state.available ||
          (instance_ != 0 && (instance_ != state.instance || generation_ != state.generation))) {
        fail_locked(); return;
      }
      if (!gate_.report(registration_, challenge, now(), true, true)) {
        fail_locked(); return;
      }
      instance_ = state.instance;
      generation_ = state.generation;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
  }
}

} // namespace andrix
