// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lifecycle_core.h"
#include "work_admission.h"

#include <aidl/dev/andrix/lifecycle/IPlatformLifecycle.h>
#include <android/binder_ibinder.h>

#include <condition_variable>
#include <memory>
#include <mutex>

namespace andrix {

// Process-lifetime, single system_server binding. This object must outlive its
// detached observer and death recipient; andrixd exits with _exit, never replaces
// or destroys it. Any replacement platform instance ends this native group.
class PlatformLifecycle {
 public:
  bool start(); // Binder thread pool must already be running; no owner child yet.
  bool ready();
  bool failed();
  // Internal work path. The current primary-user framework adapter supplies
  // the epoch; callers cannot choose it. No external I/O runs in these methods.
  AdmissionResult admit_work(const std::shared_ptr<WorkAdmission>& work);
  AdmissionResult prepare_work(const std::shared_ptr<WorkAdmission>& work);
  AdmissionResult release_work(const std::shared_ptr<WorkAdmission>& work);
  AdmissionResult retire_work(const std::shared_ptr<WorkAdmission>& work);
#ifdef ANDRIX_OWNER_KEEP
  // Serialized with platform queries on the observer thread. No daemon mutex may
  // be held by the caller. Success includes a fresh snapshot of the exact grant.
  bool retain(const ndk::SpAIBinder& lifetime, uint64_t work_id);
#endif

 private:
  static uint64_t now();
  void observe();
  void fail_locked();
  std::mutex mutex_;
  LifecycleGate gate_;
  AdmissionAuthority admissions_;
  uint64_t registration_ = 0;
  int64_t instance_ = 0, generation_ = 0;
  bool failed_ = false;
  std::shared_ptr<aidl::dev::andrix::lifecycle::IPlatformLifecycle> service_;
  AIBinder_DeathRecipient* death_ = nullptr;
#ifdef ANDRIX_OWNER_KEEP
  struct KeepRequest {
    ndk::SpAIBinder lifetime;
    uint64_t work;
    bool done = false, accepted = false;
  };
  std::condition_variable changed_;
  std::shared_ptr<KeepRequest> request_;
  uint64_t kept_work_ = 0;
  int64_t keep_registration_ = 0;
#endif
};

} // namespace andrix
