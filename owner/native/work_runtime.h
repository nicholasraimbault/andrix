// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "captured_cgroup.h"
#include "principal_profile.h"
#include "work_launch_protocol.h"
#include "work_registry.h"
#include "work_runtime_state.h"

namespace andrix {
namespace work_runtime_detail {
struct State;
}

// Supplied only by trusted management code. The Android implementation forwards
// to the one genuine PlatformLifecycle binding. This is not a caller epoch API.
class WorkRuntimeAuthority {
 public:
  virtual ~WorkRuntimeAuthority() = default;
  // Local binding check only, not an IPC lookup or a new permission grant.
  // A principal authority must affirm the exact immutable profile and keep
  // its designation/UID lifetime and user/CE authority live in the admission
  // methods below. Existing CE-only authorities deliberately return false.
  virtual bool AcceptsPrincipal(const PrincipalProfile&) const { return false; }
  virtual AdmissionResult Admit(const std::shared_ptr<WorkAdmission>& gate) = 0;
  virtual AdmissionResult Prepared(
      const std::shared_ptr<WorkAdmission>& gate) = 0;
  virtual AdmissionResult Release(
      const std::shared_ptr<WorkAdmission>& gate) = 0;
  virtual AdmissionResult Retire(
      const std::shared_ptr<WorkAdmission>& gate) = 0;
};
enum class WorkRuntimePoint {
  BeforeScope,
  AfterScope,
  AfterPlacement,
  BeforeObserve,
  BeforeReclaim,
  BeforePlacement,
  BeforeInitialSignal
};
class WorkRuntimeObserver {
 public:
  virtual ~WorkRuntimeObserver() = default;
  // Optional trusted test observation. Never called with control mutexes held.
  // There is no corresponding caller-selected bootstrap or privilege option.
  virtual void At(WorkRuntimePoint point, WorkIdentity work) = 0;
};
struct WorkRuntimeConfig {
  size_t jobs = 0;
  int aggregate = -1,
      work_namespace = -1;  // Borrowed at construction, duplicated.
  LaunchObjectIdentity aggregate_identity;
  // Trusted fixed bootstrap selection, not part of ordinary request bytes.
  std::string launcher;
  // One immutable principal binding per trusted manager incarnation. Absent
  // retains the existing reserved-UID vehicle. This is not caller input and
  // does not create a principal lease: the platform authority must bind the
  // profile, revoke admission on its loss and prevent unsafe UID reuse.
  std::optional<PrincipalProfile> principal;
  // Captured account home, borrowed and duplicated at construction. Required
  // only with principal. It is ordinary directory authority, not evidence of
  // current CE availability and not a fallback to package app data.
  int principal_home = -1;
  supervision::CleanupLimits cleanup{};
  uint64_t handshake_millis = 10000, operation_millis = 10000;
  WorkRuntimeObserver* observer = nullptr;  // Must outlive runtime/drain.
};
// One creator/supervision lane and an independent exact termination lane per
// accepted work. Kernel I/O never holds the table/publication/control mutexes.
// The creator is the sole initial-child reaper and does not reap during a
// possibly outstanding numeric-PID placement. The initial pidfd covers only
// the placement gap; after positive placement use the captured cgroup. No
// numeric PID/PGID fallback or owner-domain direct-signal permission is needed.
class WorkRuntime {
 public:
  WorkRuntime(WorkRuntimeConfig config,
              std::shared_ptr<WorkRuntimeAuthority> authority);
  ~WorkRuntime();
  WorkRuntime(const WorkRuntime&) = delete;
  WorkRuntime& operator=(const WorkRuntime&) = delete;
  bool valid() const;
  // On success moves both backend and IO lease. On refusal keeps them in the
  // caller, who must report definite no-creation failure, not drop the ticket.
  bool Submit(WorkStartReply& accepted, int& error);
  WorkRuntimeSnapshot Inspect(WorkIdentity work) const;
  // Metadata timeout observation/finished-thread retirement only. Timeout does
  // not cancel a syscall, free its ticket, or spawn a replacement worker.
  void Poll();
  void StopAll();
  bool drained() const;
  // Destructor requests Stop and waits on actual owned threads. This can block
  // forever on kernel I/O and is not a physical cleanup guarantee. Production
  // owns this object for the process lifetime; Android retires the enclosing
  // environment on authority failure/manager exit, never reconstructs here.

 private:
  std::shared_ptr<work_runtime_detail::State> state_;
};

}  // namespace andrix
