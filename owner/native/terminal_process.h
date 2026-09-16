// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <sys/types.h>

namespace andrix {

constexpr uint64_t kTerminalRetirementMillis = 5000;

// A process's terminal role is not permission to retain its workload. A direct
// shell is the work root. A replaceable frontend is only a presentation client.
// Work retention, Android authority and complete cgroup cleanup live elsewhere.
enum class TerminalProcessRole { WorkRoot, PresentationClient };
enum class TerminalExit { NotTracked, PresentationEnded, EndWork };

// Bookkeeping for the one directly forked terminal process. The coordinator owns
// the actual PTY/FDs, supplies fork/waitpid results and serializes these methods.
// No PID lookup, signal delivery, platform authority or child-tree ownership is
// inferred here. Presentation retirement is bounded in CLOCK_MONOTONIC time.
// EndWork is a terminal outcome for this record; the coordinator must terminate
// the work scope through init, not replace the process and pretend it survived.
class TerminalProcessState {
 public:
  bool select_role(TerminalProcessRole role); // Before the first process only.
  bool started(pid_t pid);
  TerminalExit reaped(pid_t pid, bool exited, int exit_code);
  void retire(uint64_t now);
  bool retirement_expired(uint64_t now) const;

  TerminalProcessRole role() const { return role_; }
  bool replaceable() const { return role_ == TerminalProcessRole::PresentationClient; }
  pid_t pid() const { return pid_; }
  bool has_process() const { return pid_ != 0; }
  bool ever_started() const { return ever_started_; }
  bool retiring() const { return retiring_; }

 private:
  TerminalProcessRole role_ = TerminalProcessRole::WorkRoot;
  pid_t pid_ = 0;
  bool ever_started_ = false;
  bool finished_ = false;
  bool retiring_ = false;
  uint64_t retiring_since_ = 0;
};

} // namespace andrix
