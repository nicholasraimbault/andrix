// SPDX-License-Identifier: Apache-2.0
// Link the actual candidate for Android without installing or granting
// authority.
#include "captured_cgroup.h"
#include "cleanup_worker.h"
#include "instance_state.h"

int main() {
  using namespace andrix::supervision;
  InstanceAllocator ids(1, 2);
  ServiceSlot slot(ids, {1, 32, 32});
  auto* instance = slot.start();
  if (!instance || instance->active()) return 1;
  Failure failure;
  auto absent =
      CapturedCgroup::Capture(-1, "invalid", {1, 4, 128, 256, 8}, failure);
  if (absent || failure.code != GroupError::Io) return 2;
  if (ConfigureWorkerSocket(-1) == 0) return 3;
  return 0;
}
