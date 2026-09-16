// SPDX-License-Identifier: Apache-2.0
#include "scope_gate.h"
#include <cassert>
#include <iostream>
#include <thread>

using andrix::scope_proof::Gate;
int main() {
  Gate g(41);
  assert(!g.hold(0) && !g.hold(-1) && !g.hold(42));
  assert(!g.release(41) && !g.stop(42) && g.phase() == Gate::Ready);
  assert(g.hold(41) && g.phase() == Gate::Holding);
  assert(!g.hold(41) && !g.release(41));
  assert(g.held() && !g.held());
  assert(g.release(41) && !g.release(41));
  assert(g.stop(41) && g.phase() == Gate::Stopped);
  assert(!g.hold(41) && !g.held() && !g.release(41));
  for (int phase = 0; phase < 3; ++phase) {
    Gate candidate(52);
    if (phase > 0) assert(candidate.hold(52));
    if (phase > 1) assert(candidate.held());
    assert(candidate.stop(52));
    assert(!candidate.hold(52) && !candidate.held() && !candidate.release(52));
  }
  for (int i = 0; i < 200; ++i) {
    Gate candidate(61);
    assert(candidate.hold(61));
    std::thread completion([&] { if (candidate.held()) candidate.release(61); });
    assert(candidate.stop(61));
    completion.join();
    assert(candidate.phase() == Gate::Stopped);
  }
  std::cout << "Scope proof ordering passed; Android identity/resources/cleanup unqualified\n";
}
