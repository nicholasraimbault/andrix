// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <sys/types.h>

#include "work_admission.h"

namespace andrix {
enum class WorkRuntimePhase {
  Missing,
  Admitting,
  Creating,
  Supervising,
  Observing,
  Reclaiming,
  Retired,
  Blocked
};
struct WorkRuntimeSnapshot {
  WorkIdentity work{};
  WorkRuntimePhase phase = WorkRuntimePhase::Missing;
  bool kill_pending = false, blocked = false, lifecycle_ceased = false;
  int error = 0, kill_error = 0;
  pid_t initial_pid =
      0;  // Diagnostic only, never a caller authority or signal target.
};
}  // namespace andrix
