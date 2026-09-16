// SPDX-License-Identifier: Apache-2.0
#include "terminal_process.h"

namespace andrix {

bool TerminalProcessState::select_role(TerminalProcessRole role) {
  if (ever_started_ || has_process() || retiring_) return false;
  switch (role) {
    case TerminalProcessRole::WorkRoot:
    case TerminalProcessRole::PresentationClient:
      role_ = role;
      return true;
  }
  return false;
}

bool TerminalProcessState::started(pid_t pid) {
  if (pid <= 1 || has_process() || retiring_ || finished_) return false;
  // Only a presentation client may be replaced inside an existing work scope.
  if (ever_started_ && !replaceable()) return false;
  pid_ = pid;
  ever_started_ = true;
  return true;
}

TerminalExit TerminalProcessState::reaped(pid_t pid, bool exited, int exit_code) {
  if (!has_process() || pid != pid_) return TerminalExit::NotTracked;
  const bool end_work = !replaceable() || (!retiring_ && (!exited || exit_code != 0));
  pid_ = 0;
  retiring_ = false;
  retiring_since_ = 0;
  finished_ = end_work;
  return end_work ? TerminalExit::EndWork : TerminalExit::PresentationEnded;
}

void TerminalProcessState::retire(uint64_t now) {
  if (!replaceable() || !has_process() || retiring_) return;
  retiring_ = true;
  retiring_since_ = now;
}

bool TerminalProcessState::retirement_expired(uint64_t now) const {
  return retiring_ && (now < retiring_since_ || now - retiring_since_ >= kTerminalRetirementMillis);
}

} // namespace andrix
