# Same-owner debugger probes

`self_trace.c` targets only its own freshly forked child. It reports the real
UID/EUID, no-new-privileges and seccomp modes, then checks `PTRACE_TRACEME`, a child
stop, reading/writing the child's known value and continuing it to a checked exit.
It takes no PID argument, changes no permissions or ASLR state, and cleans up its
child on errors. The readiness loop is bounded; this is not a real-time guarantee
against arbitrary kernel/scheduler stalls.

Expected results are separate:

- exit0 / `SELF_TRACE_READ_WRITE_CONTINUE_OK`: actual child tracing/read/write/continue
  worked in that environment;
- exit2 / `SELF_TRACE_DENIED`: the child's tracing request failed, with recorded
  errno. This alone does not identify which kernel/SELinux restriction denied it;
- exit1 (or timeout): probe/operation failure, not a boundary PASS.

The host test runs this under the existing worker seccomp filter and then with an
additional ptrace-denying filter as an error-handling control. Neither result is an
Android SELinux test.

`trace_access.c` adds a non-stopping SEIZE probe in a dedicated short-lived tracer.
It reports the access result and exits, detaching any unexpectedly accepted external
target without reading its memory or sending it a signal. Target0 creates a fresh
child of the tracer for a real positive. The caller must retain exclusive child
reaping ownership with default SIGCHLD; helper failures and ESRCH are not denials.

`boundary.c` exposes that control and a typed-owner-PTY roundtrip/finite-holder test.
TIOCSTI rejection is recorded with its exact errno; EIO on some hosts is not a MAC
proof. `debug.c`, `debug.cpp` and the LLDB command files exercise actual C/C++ stops,
backtrace, arguments, step-over/out and values with normal stdio and ASLR retained.
The [ordinary app counterpart](../owner-debug-boundary/README.md) supplies separate
self-positive and cross-identity controls.

The [debugger qualification record](../../plans/2026-09-12-native-debugger.md) now
contains bounded native positives, live negative controls and lifecycle results.
Those do not establish every debugger feature, arbitrary attach scenario or workload.
