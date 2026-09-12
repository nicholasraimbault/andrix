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
Android SELinux test. Native owner execution, live controls, compiled-policy checks
and cross-identity negatives remain required before any tracing-policy adoption.

See the [debugger feasibility plan](../../plans/2026-09-12-native-debugger.md).
