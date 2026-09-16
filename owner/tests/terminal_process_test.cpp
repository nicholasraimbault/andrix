// SPDX-License-Identifier: Apache-2.0
#include "terminal_process.h"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <limits>

using namespace andrix;

int main() {
  TerminalProcessState root;
  assert(root.role() == TerminalProcessRole::WorkRoot && !root.replaceable());
  assert(!root.has_process() && !root.ever_started() && !root.retiring());
  assert(!root.select_role(static_cast<TerminalProcessRole>(99)));
  assert(!root.started(-1) && !root.started(0) && !root.started(1));
  assert(root.reaped(0, true, 0) == TerminalExit::NotTracked);
  root.retire(10); // No process and no client role: no retirement deadline.
  assert(!root.retiring() && !root.retirement_expired(UINT64_MAX));
  assert(root.started(42));
  assert(root.pid() == 42 && root.ever_started());
  assert(!root.started(43));
  assert(!root.select_role(TerminalProcessRole::PresentationClient));
  root.retire(100); // Detaching a direct terminal does not retire its work root.
  assert(!root.retiring() && !root.retirement_expired(5100));
  assert(root.reaped(43, true, 0) == TerminalExit::NotTracked && root.pid() == 42);
  assert(root.reaped(42, true, 0) == TerminalExit::EndWork);
  assert(!root.has_process() && root.ever_started());
  assert(!root.started(44)); // No automatic work-root replacement.
  assert(root.reaped(42, true, 0) == TerminalExit::NotTracked);
  assert(!root.select_role(TerminalProcessRole::PresentationClient));

  for (bool exited : {false, true}) {
    for (int code : {0, 1, 126}) {
      TerminalProcessState failed_root;
      assert(failed_root.started(50));
      assert(failed_root.reaped(50, exited, code) == TerminalExit::EndWork);
      assert(!failed_root.started(51));

      TerminalProcessState client;
      assert(client.select_role(TerminalProcessRole::PresentationClient));
      assert(client.started(60));
      auto result = client.reaped(60, exited, code);
      assert(result == (exited && code == 0 ? TerminalExit::PresentationEnded : TerminalExit::EndWork));
      assert(client.started(61) == (result == TerminalExit::PresentationEnded));

      TerminalProcessState retiring;
      assert(retiring.select_role(TerminalProcessRole::PresentationClient));
      assert(retiring.started(70));
      retiring.retire(100);
      assert(retiring.retiring());
      assert(!retiring.started(71)); // Reaping, not closing a stream, frees the slot.
      assert(retiring.reaped(71, exited, code) == TerminalExit::NotTracked);
      assert(retiring.pid() == 70 && retiring.retiring());
      assert(retiring.reaped(70, exited, code) == TerminalExit::PresentationEnded);
      assert(!retiring.retiring() && !retiring.has_process());
      assert(!retiring.retirement_expired(UINT64_MAX));
      assert(retiring.started(71) && retiring.ever_started());
    }
  }

  TerminalProcessState timed;
  assert(timed.select_role(TerminalProcessRole::PresentationClient));
  timed.retire(100); // A missing client cannot acquire a phantom deadline.
  assert(!timed.retiring());
  assert(timed.started(80));
  timed.retire(200);
  assert(!timed.retirement_expired(200));
  timed.retire(4000); // Repeated revocation must not extend the original bound.
  assert(!timed.retirement_expired(200 + kTerminalRetirementMillis - 1));
  assert(timed.retirement_expired(200 + kTerminalRetirementMillis));
  assert(timed.retirement_expired(199));

  TerminalProcessState edge;
  assert(edge.select_role(TerminalProcessRole::PresentationClient));
  assert(edge.started(90));
  edge.retire(UINT64_MAX - 10);
  assert(!edge.retirement_expired(UINT64_MAX));
  assert(edge.retirement_expired(0)); // Clock regression cannot wrap into permission.

  std::cout << "Terminal roles, owned exit routing and bounded retirement passed; Android unqualified\n";
}
