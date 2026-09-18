// SPDX-License-Identifier: Apache-2.0
#include "lifecycle_core.h"
#include "session_core.h"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <limits>

using andrix::LifecycleGate;

static void query_delay_and_consumption() {
  LifecycleGate gate(100);
  assert(!gate.valid(0) && !gate.ready(0));
  assert(gate.begin_query(100, 0) == 0);
  assert(!gate.report(100, 1, 0, true, true));
  const auto generation = gate.begin(10);
  assert(generation == 101 && gate.valid(10) && !gate.ready(10));
  assert(gate.begin_query(0, 11) == 0);
  assert(gate.begin_query(generation - 1, 12) == 0);
  const auto query = gate.begin_query(generation, 100);
  assert(query != 0 && !gate.ready(100));
  assert(gate.begin_query(generation, 101) == 0); // Cannot replace in-flight work.
  assert(!gate.report(generation, query + 1, 102, true, true));
  assert(!gate.report(generation, 0, 103, true, true));
  assert(gate.report(generation, query, 900, true, true));
  assert(gate.ready_until(900) == 2100); // Export issue-time, not receipt-time freshness.
  // A duplicate, including a stale negative, cannot renew or revoke this lease.
  assert(!gate.report(generation, query, 901, true, true));
  assert(!gate.report(generation, query, 902, false, false));
  assert(gate.ready(2099));
  assert(!gate.ready(2100)); // Issue at100 +2000, NOT receipt at900 +2000.
  assert(gate.ready_until(2100) == 0);
  assert(!gate.report(generation, query, 2100, true, true));
  assert(gate.begin_query(generation, 2101) == 0);
}

static void later_queries_and_stale_generations() {
  LifecycleGate gate;
  auto generation = gate.begin(0);
  const auto first = gate.begin_query(generation, 0);
  assert(gate.report(generation, first, 1, true, true));
  auto next = gate.begin_query(generation, 500);
  assert(next > first);
  assert(!gate.report(generation, first, 501, true, true));
  assert(!gate.report(generation, first, 502, false, false));
  assert(gate.ready(503));
  assert(gate.report(generation, next, 600, true, true));
  assert(gate.ready(2499) && !gate.ready(2500));

  generation = gate.begin(3000);
  const auto outstanding = gate.begin_query(generation, 3001);
  const auto replacement = gate.begin(3002); // Invalidates outstanding old work.
  next = gate.begin_query(replacement, 3003);
  assert(next > outstanding && !gate.release(generation));
  assert(!gate.report(generation, outstanding, 3004, true, true));
  assert(!gate.report(generation, next, 3005, false, false));
  assert(!gate.report(replacement, outstanding, 3006, false, false));
  assert(!gate.ready(3007) && gate.valid(3007));
  assert(gate.report(replacement, next, 3008, true, true));
  assert(gate.release(replacement));
  assert(!gate.ready(3009) && gate.begin_query(replacement, 3010) == 0);
}

static void deadlines_do_not_revive() {
  LifecycleGate gate;
  auto generation = gate.begin(0);
  assert(gate.valid(1999) && !gate.ready(1999));
  auto query = gate.begin_query(generation, 1999);
  assert(query != 0);
  assert(!gate.report(generation, query, 2000, true, true));
  assert(!gate.valid(2000)); // Starting a query didn't renew the pending deadline.

  generation = gate.begin(3000);
  query = gate.begin_query(generation, 3100);
  assert(!gate.report(generation, query, 3100 + andrix::kLifecycleQueryMillis, true, true));
  assert(!gate.valid(4100)); // Exact query deadline fails, before registration expiry.
  assert(!gate.report(generation, query, 4101, true, true));

  generation = gate.begin(5000);
  query = gate.begin_query(generation, 5000);
  assert(gate.report(generation, query, 5001, true, true));
  query = gate.begin_query(generation, 6900);
  assert(!gate.report(generation, query, 7000, true, true)); // Timely query, expired lease.
  assert(!gate.ready(7000));

  generation = gate.begin(8000);
  query = gate.begin_query(generation, 8000);
  assert(gate.report(generation, query, 8001, true, true));
  query = gate.begin_query(generation, 8200);
  assert(query != 0 && gate.ready(9199));
  assert(!gate.ready(9200)); // Hung query revokes, not just a rejected late report.
}

static void invalid_state_and_clock() {
  LifecycleGate gate;
  for (int variant = 0; variant != 3; ++variant) {
    const uint64_t now = 1000 * uint64_t(variant);
    const auto generation = gate.begin(now);
    const auto query = gate.begin_query(generation, now);
    // UserManager's unlocked-while-stopping case is NOT a running user.
    assert(!gate.report(generation, query, now + 1, variant == 0, variant == 1));
    assert(!gate.ready(now + 2));
    assert(!gate.report(generation, query, now + 3, true, true));
  }
  auto generation = gate.begin(4000);
  auto query = gate.begin_query(generation, 4001);
  assert(!gate.report(generation, query, 3999, true, true)); // Trusted-clock rollback.
  assert(!gate.valid(4002));
  generation = gate.begin(5000);
  query = gate.begin_query(generation, 5001);
  assert(gate.report(generation, query, 5002, true, true));
  assert(!gate.ready(5001));
  assert(!gate.ready(5003));
}

static void overflow_and_distinct_clocks() {
  const uint64_t max = std::numeric_limits<uint64_t>::max();
  const uint64_t max_token = uint64_t(std::numeric_limits<int64_t>::max());
  LifecycleGate exhausted(max_token);
  assert(exhausted.begin(1) == 0);
  LifecycleGate last_generation(max_token - 1);
  assert(last_generation.begin(1) == max_token);
  assert(last_generation.begin(2) == 0 && !last_generation.valid(2));
  LifecycleGate exhausted_query(0, max_token);
  auto generation = exhausted_query.begin(0);
  assert(exhausted_query.begin_query(generation, 1) == 0);
  assert(!exhausted_query.valid(1));
  LifecycleGate last_query(0, max_token - 1);
  generation = last_query.begin(0);
  assert(last_query.begin_query(generation, 0) == max_token);
  assert(last_query.report(generation, max_token, 1, true, true));
  assert(last_query.begin_query(generation, 2) == 0 && !last_query.ready(2));

  LifecycleGate overflow;
  assert(overflow.begin(max - andrix::kLifecycleLeaseMillis + 1) == 0);
  LifecycleGate final;
  generation = final.begin(max - andrix::kLifecycleLeaseMillis);
  auto query = final.begin_query(generation, max - andrix::kLifecycleLeaseMillis);
  assert(final.report(generation, query, max - andrix::kLifecycleLeaseMillis, true, true));
  assert(final.begin_query(generation, max - andrix::kLifecycleLeaseMillis + 1) == 0);
  assert(!final.ready(max));

  // A clock-contract test only. Neither clock proves continuous Android key state.
  andrix::AttachmentGate ui;
  LifecycleGate lifetime;
  const auto ui_generation = ui.attach(100, true, true, true);
  generation = lifetime.begin(100);
  query = lifetime.begin_query(generation, 100);
  assert(lifetime.report(generation, query, 100, true, true));
  assert(ui_generation != 0 && !ui.live(30100));
  assert(lifetime.ready(100)); // Suspend is excluded from this model's active clock.
  assert(!ui.renew(ui_generation, 30101, true, true));
  query = lifetime.begin_query(generation, 101);
  assert(lifetime.report(generation, query, 102, true, true));
}

int main() {
  query_delay_and_consumption();
  later_queries_and_stale_generations();
  deadlines_do_not_revive();
  invalid_state_and_clock();
  overflow_and_distinct_clocks();
  std::cout << "Lifecycle challenge/delay/replay/expiry model passed; Android authority unqualified\n";
}
