# Work factory mechanism tests

These are focused inputs to the owner approved
[backend comparison](../../plans/2026-09-17-work-factory-comparison.md). Neither backend
is a qualified general Android factory yet. The completed fixed-slot Android trial is
separate evidence at a different source revision.

## Nested group mechanics

`kernel_scopes.py` runs real processes, pidfds, sessions and cgroup v2 operations inside
one explicitly delegated proof unit. It refuses an ordinary shell or unrelated cgroup.
The observer and unchanged admission helper stay outside the tested manager subtree.
The fixture only signals its own captured pidfds or its own newly created groups.

Observed on the Linux host kernel:

- Enabling the memory controller while the parent group held an internal process
  failed with `EBUSY`. After moving the manager into its control leaf, activation and
  leaf limits worked. Controller availability is not the same as activation.
- Two processes in separate sessions stayed in their assigned nested groups. Killing
  A's group produced actual SIGKILL wait status while B supplied a fresh response.
- After the manager exited, B remained alive and was adopted by the private subreaper.
  The parent `cgroup.procs` was empty, while its `cgroup.events` still reported population.
- Writing the parent's `cgroup.kill` killed the nested surviving process. Its real wait
  status was SIGKILL. The manager's PID remained an unreaped zombie during cleanup.
- Removing the now unpopulated parent with empty child directories failed with `EBUSY`.
  This corrects an untested source-review prediction of `ENOTEMPTY`; Android's retry loop
  distinguishes those errors. Explicit child-directory removal then allowed parent removal.
- Treating `mkdir(..., exist_ok=True)` on the leftover path as success retained the same
  inode. This was path reuse, not a forced reuse of a numeric process ID.

The first setup attempt assumed systemd delegation had already activated the memory
controller. It had not. That failed attempt is retained; the corrected fixture explicitly
activates the controller within its empty, owned delegation before proceeding.

This is host kernel evidence, not Android SELinux, an init runtime result or proof of an
external manager's recovery implementation. It establishes a viable recursive process
kill mechanism and exposes separate activation, directory reclamation and identity
obligations. Those obligations must be implemented and tested, not assumed away or used
to dismiss an entire backend without examining recovery.

## Init profile construction

`init/work_profile_experiment.cpp` constructs fresh instances by replaying an immutable
trusted token definition through the actual Android `ServiceParser`. It parses into a
private local `ServiceList`, inspects the actual capability, identity, resource and
instance fields, then publishes only a complete valid object. It does not copy mutable
state from a live service. A narrow host integration patch gives the probe access to
those private fields and links the actual `libinit_host`.

The tests contrast an explicit empty capability profile with the actual temporary
service constructor's absent profile. They also cover independent instance state,
sequence/name collisions and rejected definitions without partial publication. This
is construction code, not an installed init launch interface. The first build attempt
stopped during Soong parsing because the test filegroup used an unsupported include
export property. That unnecessary property was removed; no C++ test had run in that
attempt. Compilation/execution remains a separate pending gate, and host success is
not Android authority.

## Running safely

Use a fresh bounded user service selected by the fixture's exact unit-name shape,
`Delegate=yes`, `DelegateSubgroup=control`, 512 MiB memory, zero job swap, bounded CPU,
task and wall time, zero core files and the existing admission helper. Keep evidence
outside the source tree. An undelegated invocation is expected to refuse before writes.
Only the delegated unit's descendants may be manipulated. Do not use a system or shared
service group, widen host permissions or modify the common admission helper.
