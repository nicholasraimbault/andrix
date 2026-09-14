# Explicit kept terminals

`ANDRIX_OWNER_KEEP=true` selects the opt-in candidate and requires the existing
owner session, Android lifecycle integration and pinned compiler/tmux payload.
The normal product default remains off. See the [bounded result and limits](../../plans/2026-09-14-keep.md#observed-opt-in-keep-result).

- **Attach** starts ordinary Console-bound work, or returns to existing kept work.
- **New kept** starts a new tmux-backed terminal with a platform notification. It
  does not adopt or replace a running plain shell/editor; End that work first.
- **Detach**, loss of focus, relock or Console-process death retires only the kept
  terminal's client/PTY. Return creates a fresh client and presentation/parser.
- **End** or notification **Stop** ends the entire native workload through init.
  Notification Stop does not require Console to exist and grants no terminal access.
- A Keep grant does not survive reboot or loss of the platform authority. Saved
  owner files are separate from process lifetime. No automatic work restart or wake
  lock is added.

The platform service holds one notification-backed daemon/work registration. Its
Stop action targets a process-bound `IKeptWork` Binder, not a reusable PID/service
name. Native code checks actual system_server UID/SID and immutable work ID, exits,
and lets Android init clean up the group. Old controller death callbacks are fenced
by registration epochs and cookies retire only through NDK `onUnlinked`.

The existing UI foreground/unlocked checks and 1500ms BOOTTIME lease remain separate
from permission to keep computing. Android user/CE observations, platform instance/
generation and issued-query deadlines remain mandatory. Native identity, cgroup
limits, tracing boundary and worker syscall filter are unchanged.

The lab demonstrated kept editor return, relock, Stop/End, reboot and actual Android
watchdog platform-death cleanup. Independent live CE-key eviction, vold failure,
hung snapshot RPCs, broader pressure/suspend and phone/release behavior are not
qualified by those tests. Do not turn this opt-in result into an unconditional
release or hardware claim.
