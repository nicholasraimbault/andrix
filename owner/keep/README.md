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
watchdog platform death cleanup. The later [fixed lifecycle trials](../../plans/2026-09-14-lab-lifecycle-faults.md)
observed real CE locking with busy files, delayed reply cleanup and normal PIN/fresh
work recovery. Complete physical key removal, abnormal vold failure, broader stalled
RPC/pressure/suspend cases and phone/release behavior remain open. Do not turn these
scoped results into an unconditional release or hardware claim.

Android's lockscreen notification settings still apply. The quiet Keep notice is
hidden there when the owner hides silent notifications; enabling their display does
not require showing sensitive content or exposing terminal output. Stop while locked
was exercised with that normal-UI visibility choice. Keep does not override it.

The [owner-channel controls](../../plans/2026-09-14-keep-failure-controls.md#corrected-image-result)
now exercise normal UI blocking of this optional-work channel: active work ends,
blocked state survives reboot, and re-enabling notifications alone starts no work.
A fresh New kept remains necessary. A failed blocked-start currently has a generic
error message; the recorded state/cleanup controls, not that wording, establish the
bounded result.
