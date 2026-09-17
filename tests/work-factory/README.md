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
- After removing and recreating a work-group path, a captured old control FD failed
  with `ENODEV`, and lookup through the old directory FD failed with `ENOENT`. Neither
  resolved the replacement inode. This tests kernel object identity, not an Android API.

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
attempt. A subsequent compile caught a signedness mismatch in a gtest flags assertion;
that assertion now uses the service field's unsigned type. Construction code compiled,
but no tests ran in that failed attempt. The host probe explicitly selects the first
host architecture.

Source `166ff64` then compiled against the actual `libinit_host` and passed all four
construction tests. The frozen binary and matching host libraries were used for execution.
The temporary two-friendship/build-rule integration was reverted and exact upstream
source restored afterward. Framework adaptation checks passed before and after. The
full project host suite also passed 361 tests at that source. These are distinct results:
no owner process was launched by the construction tests, and no new Android image or
runtime was qualified.

## Android comparison vehicle under qualification

The new Android fixture uses one manager and dynamically created work instances.
`ANDRIX_WORK_FACTORY_PROOF=delegated` selects A with unchanged init implementation;
`ANDRIX_WORK_FACTORY_PROOF=init` selects B with the separately gated init patch.
Neither is installed in an ordinary image. Both require the debug Cuttlefish product,
owner session and lifecycle support, with Keep and the other fault/scope fixtures off.

Both managers use the same bounded Binder test controls and exact manager/work IDs.
The actual debug Shell UID/SID is checked. Work control objects remain as tombstones
inside the current manager after cleanup; they are not resolved again by a reused name.
One creator thread can be blocked in a real pipe read while the independent Stop method
latches stopping. Resuming that operation deliberately creates a late helper, which
must be cleaned without owner payload release. This is a specific blocked allocation
case, not proof against every stalled Binder pool or arbitrary uninterruptible I/O.

For A, existing init configuration delegates directory/procs/subtree-control ownership
only inside the manager's own group. Aggregate memory ceilings and migration ancestors
remain protected. The trusted coordinator gets lab directory creation/removal permission;
owner workers retain their write/mkdir denials and cannot become managers. Per-work
control uses captured cgroup directory descriptors. Manager death relies on init's
recursive process kill, followed by explicit empty-directory reconciliation on recovery.
Final parent removal uses the existing init `rmdir` builtin, not a stale numeric PID kill.

For B, `runtime-probe.patch` adds a separately selected init builtin that constructs a
fresh instance from the tested fixed profile. Its memory controls are applied and read
back before the existing child activation pipe is released. The trusted guardian stays
alive after the owner entry exits. Init's normal service registration, PID lifetime pin
and reap/cleanup own that group. The property ticket/reply transport is bounded lab
machinery, not a selected product reservation protocol.

Guardians in both variants independently check actual platform/CE authority and bounds
before owner entry or payload release. Private manager connections authenticate kernel
peer credentials and SID. Owner workers execute the existing filter, prove Binder and
cgroup-control denial, and leave detached children that ignore observation-channel loss.
The common client exercises duplicate creation, wrong/old IDs, held cancellation, late
allocation completion, independent live work, manager failure/recovery and final cleanup.

The native qualification attempts exposed several build issues. The first module
batch passed normal modules/policy, then the build system rejected
the lab backend property being added to the generic system partition. It now belongs to
`system_ext`; the partition rule was not bypassed. The native candidate had not compiled
in that failed batch. The next attempt reached native compilation and rejected an
unnecessary const-string copy in the bounds loop under `-Werror`; the loop now takes a
reference. A subsequent manager compile caught a signed PID comparison; the parsed
value is now bounded to `pid_t` before conversion and checked by a focused parser test.
No warning was disabled. A later batch completed A's native and compiled-policy gates,
with init bytes identical to the earlier unchanged-source artifact. B then reached its
activation-hook compile and rejected implicit descriptor conversions under init's stricter
settings. Those calls now use explicit `.get()` values; the pre-activation check also
requires the actual fresh child membership. These artifact steps, the old fixed-slot
trial and host mechanisms do not qualify the new interfaces or Android recovery.

## First Android comparison observations

Source `7b8a117` passed 365 host tests, native/policy gates and complete normal/A/B
image inspection. A's init bytes matched the unmodified baseline. Both variants used
matching guardian, worker and client bytes. Normal images excluded the experiment.

The first fresh A runtime created two dynamic groups and both owner workers reached
Held without payload release. The Shell observer was then denied access to their
kernel metadata. The source retained init's private umask while requesting mode 0755
for new directories. A real host cgroup test reproduced the resulting 0700 mode and
verified explicit directory chmod. The correction makes only owned lab metadata
readable for the observer, without granting owner workers control. It required new
artifacts and execution; the stopped attempt remains incomplete.

The first fresh B runtime exercised actual dynamic init instances, kernel identity,
capability/limit/filter observations, entry exit with detached descendants, ordinary-app
negatives with live positives, independent Stop, wrong/old IDs and tombstones, held
cancellation, and Stop during a blocked allocation followed by late helper cleanup
without owner payload. Init logs then recorded removal of both groups and SIGKILL of
all four detached descendants after manager loss.

However, the B client timed out before recovery. Its boolean population helper treated
failure to reopen an already removed group's event file as still populated. The overall
run remains incomplete; manager recovery and the final authority snapshot were not reached.
A new observer distinguishes Populated, Empty, Removed and Unknown on a captured cgroup
object. Real host tests of that same C++ code covered permission denial remaining Unknown,
normal Empty, removal and path reuse without retargeting. A retained directory's link
count remained 2 after removal, so link count is deliberately not the removal test.
The corrections at `7127cc7` passed 366 host tests and both Android native/policy
configurations. Those results did not qualify the earlier runtime attempts.

## Corrected Android comparison result

At `409fc6d`, with the same native corrections as `7127cc7`, all 366 host tests and
complete normal/A/B native, policy and image gates passed. Each backend then completed
the listed controls in a separate fresh offline Android fixture with matching tools:

- Dynamic creation, duplicate request identity, held execution and explicit release.
- Actual UID/MAC, zero capabilities, protected bounds, filter and membership checks.
- Entry exit with two surviving detached descendants per scope.
- Ordinary app negatives bracketed by live factory/work positives.
- Independent scope Stop or guardian crash with unrelated work still advancing.
- Wrong/old IDs and tombstone controls, held cancellation and refused late release.
- Stop while the allocator was blocked, followed by late helper creation and removal
  without an owner entry or payload.
- Manager death, process cleanup, a fresh manager identity with zero restored jobs,
  retirement of old handles/hierarchies, new work and final graceful cleanup.

A used unchanged init. Init killed the nested processes but initially could not remove
the parent directory while empty children remained. Captured groups were observed Empty;
the new manager reconciled the old hierarchy through its owned directory controls and
init's existing `rmdir` action. The expected init retry interval and `EBUSY` messages
remain part of the result, not evidence that directory cleanup was immediate. Shell
independently observed the corrected leaf and parent directory modes.

B used the separately enabled init extension. Init removed each work group after its
guardian exited. Captured old groups were observed Removed after manager loss. Fresh
manager admission, no automatic job restart, retirement of old handles and final cleanup
then completed. Both runs retained the same boot, system_server identity and platform
lifecycle epoch within their respective fixture.

These are successful finite comparison trials, not production qualification. They do
not establish forced numeric PID reuse safety, arbitrary hung operations or Binder
saturation, injection of resource or setup failures, natural completion of all
remaining descendants, fully released physical accounting, phone behavior, pressure,
suspend, durability or a new CE loss result. No universal resource defaults follow from
fixture limits. The earlier incomplete runs remain separate.

The owner accepted the refined [delegated supervision ownership model](../../docs/architecture.md#work-supervision),
not either fixture unchanged. See the [decision and rationale](../../plans/2026-09-17-work-factory-comparison.md#accepted-ownership-direction).
These tests inform the combined contract; they do not qualify its unimplemented API,
platform integration or remaining failure behavior.

## Running safely

Use a fresh bounded user service selected by the fixture's exact unit-name shape,
`Delegate=yes`, `DelegateSubgroup=control`, 512 MiB memory, zero job swap, bounded CPU,
task and wall time, zero core files and the existing admission helper. Keep evidence
outside the source tree. An undelegated invocation is expected to refuse before writes.
Only the delegated unit's descendants may be manipulated. Do not use a system or shared
service group, widen host permissions or modify the common admission helper.
