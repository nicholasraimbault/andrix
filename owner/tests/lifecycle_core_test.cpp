// SPDX-License-Identifier: Apache-2.0
#include "lifecycle_core.h"
#include "session_core.h"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <limits>

int main() {
  using andrix::LifecycleGate;
  LifecycleGate gate(100);
  assert(!gate.valid(0) && !gate.ready(0));
  assert(!gate.renew(100, 0, true, true));
  const auto first = gate.begin(10);
  assert(first == 101 && gate.valid(10) && !gate.ready(10));
  assert(!gate.renew(0, 11, true, true));
  assert(!gate.renew(first - 1, 12, false, false));
  assert(gate.valid(12) && !gate.ready(12));
  assert(gate.renew(first, 100, true, true));
  assert(gate.ready(2099));
  assert(!gate.ready(2100));
  assert(!gate.renew(first, 2100, true, true));
  assert(!gate.renew(first, 2200, true, true));

  auto current = gate.begin(2300);
  assert(current > first && !gate.release(first));
  assert(!gate.renew(first, 2301, false, false));
  assert(gate.valid(2301));
  assert(gate.renew(current, 2302, true, true));
  // UserManager can report unlocked while stopping: running is separate.
  assert(!gate.renew(current, 2303, false, true));
  assert(!gate.valid(2303));
  assert(!gate.renew(current, 2304, true, true));
  current = gate.begin(2400);
  assert(!gate.renew(current, 2401, true, false));
  assert(!gate.valid(2401));
  current = gate.begin(2500);
  assert(gate.renew(current, 2501, true, true));
  assert(gate.release(current));
  assert(!gate.ready(2502) && !gate.renew(current, 2502, true, true));

  LifecycleGate pending;
  auto token = pending.begin(1);
  assert(pending.valid(2000));
  assert(!pending.ready(2000));
  assert(!pending.renew(token, 2001, true, true));
  token = pending.begin(3000);
  assert(pending.renew(token, 3001, true, true));
  assert(!pending.ready(2999)); // clock regression invalidates permanently
  assert(!pending.renew(token, 3002, true, true));

  const auto max = std::numeric_limits<uint64_t>::max();
  LifecycleGate exhausted(uint64_t(std::numeric_limits<int64_t>::max()));
  assert(exhausted.begin(1) == 0);
  LifecycleGate overflow;
  assert(overflow.begin(max - andrix::kLifecycleLeaseMillis + 1) == 0);
  LifecycleGate final;
  token = final.begin(max - andrix::kLifecycleLeaseMillis);
  assert(token != 0);
  assert(final.renew(token, max - andrix::kLifecycleLeaseMillis, true, true));
  assert(!final.renew(token, max - andrix::kLifecycleLeaseMillis + 1, true, true));
  assert(!final.ready(max));

  // Model the distinct clock contract; this is not a device suspend test.
  andrix::AttachmentGate ui;
  LifecycleGate lifetime;
  const auto ui_generation = ui.attach(100, true, true, true);
  const auto life_generation = lifetime.begin(100);
  assert(lifetime.renew(life_generation, 100, true, true));
  assert(ui_generation != 0);
  // Suspend consumes CLOCK_BOOTTIME but not the lifecycle's active-time clock.
  assert(!ui.live(30100));
  assert(lifetime.ready(100));
  assert(!ui.renew(ui_generation, 30101, true, true));
  assert(lifetime.renew(life_generation, 101, true, true));
  std::cout << "Lifecycle state/epoch/expiry/clock-contract checks passed; Android unqualified\n";
}
