# Ordinary-app debugger-boundary fixture

This optional test APK is installed and removed normally; it is never included in a
product image. It declares no permissions or shared UID and uses the non-platform
lab signer. It is explicitly debuggable so its fresh-child self-tracing operation
can be a positive control—not through `run-as`, root or adopted shell authority.
GrapheneOS's pinned implicit `OTHER_SENSORS` metadata is checked separately from
actual permission grants.

The instrumentation takes real live `owner_pid`, `manager_pid` and `/dev/pts/N`
inputs supplied by the operator after observing native owner output. It checks:

- genuine `PTRACE_SEIZE` of a newly created same-app child;
- rejected attempts to seize the selected owner worker and coordinator;
- rejected read-open of the owner-created PTY, without acquiring a controlling TTY.

The shared tracer helper performs each external-PID attempt in a short-lived child
using non-stopping `PTRACE_SEIZE` with no options. It does not read memory or send
signals to the external target. On unexpected success its exit detaches the trace;
that remains a test failure. Only freshly created helper/control children are
eligible for cleanup signals. The exact helper implementation and host controls are
in `tests/owner-debugger/trace_access.*`.

A ready report includes the real app PID/UID/context. The instrumentation then remains
alive for three minutes so an owner-side reverse-direction probe can test that PID.
Its final result alone is insufficient: host/native observations must establish
live targets, same-window owner positives, reverse-direction rejection and cleanup.
`ESRCH`, helper failures or missing devices are not permission-denial passes. DAC,
MAC, kernel tracing restrictions and compiled-policy assertions remain distinct
pieces of evidence.
