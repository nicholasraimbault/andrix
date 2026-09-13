// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lifecycle_core.h"

#include <aidl/dev/andrix/lifecycle/IPlatformLifecycle.h>
#include <android/binder_ibinder.h>

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

 private:
  static uint64_t now();
  void observe();
  void fail_locked();
  std::mutex mutex_;
  LifecycleGate gate_;
  uint64_t registration_ = 0;
  int64_t instance_ = 0, generation_ = 0;
  bool failed_ = false;
  std::shared_ptr<aidl::dev::andrix::lifecycle::IPlatformLifecycle> service_;
  AIBinder_DeathRecipient* death_ = nullptr;
};

} // namespace andrix
