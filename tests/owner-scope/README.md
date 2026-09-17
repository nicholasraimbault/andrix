# Android scope boundary experiment

**Status:** the fixed named-slot boundary trial passed its listed Android controls at
source `0e60a42`. This is not a general dynamic factory, production work API or phone
qualification. It informs the [supervision matrix](../../plans/2026-09-16-unix-work-supervision.md).

The experiment uses two fixed named init service slots, not arbitrary commands supplied
by a client or a claimed dynamic factory. Each trusted guardian gets its own init owned group.
Fixed owner-domain probe workers remain behind a release gate until the guardian has
checked real identity, user/CE authority and protected bounds. They then create
surviving detached descendants. Guardian termination lets init perform complete cleanup.

## Scope and authority

`ANDRIX_OWNER_SCOPE_PROOF=true` is limited to the GrapheneOS Cuttlefish userdebug/eng
product with owner session and platform lifecycle enabled. It is separate from the
existing lifecycle fault controls and cannot be combined with Keep or those controls.
Normal images do not install these executables, init commands or policy entries.

Only actual debug Shell UID/SID callers may invoke the fixed probe controls. Synchronous
calls also require a valid caller PID; Binder supplies no PID for `oneway` Stop. The experiment
has no caller supplied command, path, UID, budget or resource-group path. Probe
workers cannot call the control service or modify cgroups. No general storage or
execution management permission is granted to Shell or ordinary applications.

One batch per boot creates scopes A and B. A separate one-use replacement creates
A2 under the same service lookup name, but with a new process and immutable identity.
The controls are test machinery, not a proposed production property/launch protocol.
Factory creation and limit application are asynchronous. No property value or Binder
death is labelled a cleanup acknowledgement.

The fixture uses the existing 256 MiB leaf budget plus a 256 MiB aggregate UID budget,
zero swap, group OOM, 32 tasks, 128 descriptors, no core files and a 64 MiB per-file
limit. Init applies the empty capability set, process limits and scheduling profile.
The fixed trusted bootstrap verifies those inherited limits and the aggregate before
publishing any endpoint or launching a worker. The init owned leaf controls are read
back before admission. These are proof bounds, not new product
resource defaults. Do not run the batch alongside ordinary owner work in the fixture.

## Source finding before runtime

The first draft used `exec_background`. Inspection of the pinned init implementation
showed that temporary services do not get a parsed `capabilities` field. The nonroot
fallback clears inheritable capabilities, not the bounding set. It therefore cannot
establish the existing all-zero capability invariant. We did not relax that guard or
grant capabilities to the helper. The named-slot experiment uses explicit empty
capabilities and the full init profile. A general profile-preserving factory remains
a separate design/qualification gate. No Android run of the discarded draft is claimed.

## First Android observation and channel correction

Source `57a43b6` passed both module/policy configurations and complete image inspection.
The first fresh offline Android attempt registered both scoped guardians, but SELinux
rejected the owner worker's inherited anonymous pipes at exec. The allowed FD use did
not authorize access to their `andrixd` labelled `fifo_file` objects. The entry exited
before payload release and init removed scope A's group. Later controls were not reached;
the overall attempt failed and remains preserved.

The correction gives the fixture's release/observation socket pairs a dedicated object
label with access only for the guardian and owner roles. It does not grant access to
arbitrary coordinator pipes or sockets. These are fixture synchronization channels,
not a decision to replace normal Unix stdin/stdout pipes with sockets. Actual program
stream types and their MAC crossings remain part of the long term execution design.
The corrected channels require new artifact and runtime checks. The first policy build
also rejected the socket-creation macro's unused unrestricted ioctl permission. The
fixture now selects the existing no-ioctl macro rather than weakening the neverallow or
granting unused operations.

Source `101f253` passed corrected module/policy/image checks. The next Android attempt
reached both held worker acknowledgements without payload release. Its collector then
incorrectly required `/proc/PID/cgroup` to contain only a v2 row; Android also reported
v1 CPU, cpuset and I/O hierarchies. The expected v2 row was present and correct. This
is an observer failure, not a changed Android membership policy or a completed runtime
pass. A tested parser now selects the one exact unified row while validating the other
rows. The next attempt uses fresh state and the same sealed Android inputs.

## Released-work observation and Binder correction

The fresh hybrid-aware collector with image `101f253` observed both released scopes,
entry-process exit, two surviving detached descendants per scope, real kernel identity,
limits and membership, and ordinary-app negatives bracketed by live scope positives.
It then stopped because the wrong-ID Stop never advanced the authenticated request
counter. Source review found that the common caller check required PID > 1 for a
`oneway` method, but `AIBinder_getCallingPid` explicitly returns 0 for `oneway`.

The correction authenticates Stop through the actual kernel UID/SID and immutable scope
ID without inventing a caller PID. Synchronous calls retain their PID check. The next
fixture records the actual Stop caller PID after authentication so the distinction is
measured, not inferred from a missing reply. This does not grant another identity
control authority. Complete Stop and stale-handle checks remain unqualified by that
failed attempt and require fresh artifacts/runtime.

## Observed fixed-slot result

Source `0e60a42` passed 360 host tests, normal/proof module and compiled-policy checks,
and complete image/host-tool inspection. A fresh offline ARM64 emulator then completed:

- Two separately identified scopes with actual guardian/owner MAC roles and UID,
  all-zero capability sets, protected aggregate/leaf limits, and worker filter state.
- Held entry acknowledgements without payload release, followed by explicit release.
- Entry-process exit with two live detached descendants retained in each owned group.
- Ordinary-app service/home negatives between live positive observations of both scopes.
- An authenticated wrong-ID Stop observed with the actual oneway caller PID of zero,
  without ending that scope.
- Deliberate nonzero guardian exit for A, init SIGKILL of both detached descendants,
  and removal of A's group while B supplied fresh output.
- Reuse of the A service slot with a new immutable identity. The captured old Binder
  was dead; an old ID on the new Binder was rejected without ending the new scope.
- Stop of the new held entry before payload release, group removal, rejection of late
  release through its dead Binder, another live B observation and final complete B Stop.

The held entry exited with refusal status on its closed release channel. A parent-death
SIGKILL was also denied across the coordinator/owner MAC roles. We do not count that
signal as a cleanup mechanism or widen its permissions: init's actual SIGKILL and group
removal supplied complete cleanup for the released workloads. Parent-death signals are
not a substitute for the Android supervisor.

The same system_server process/start time, kernel boot and platform epoch remained.
Controller, guest runner, normal shutdown and capture completed successfully. Images,
inputs and evidence are preserved separately from earlier failed attempts.

This is one bounded fixed-slot run. It does not qualify a dynamic factory, saturated
Binder or arbitrary stalled admission, new terminal recovery, independently induced CE
loss in this candidate, general pressure/suspend, phone behavior or storage durability.
No ordinary lifetime, Keep, restart, wake, notification or locked-I/O policy was changed.

## Control matrix

- Both groups have actual owner UID/SID, protected resources and independent identities.
- Starting a gated worker does not imply payload release.
- Released workers leave detached descendants after their entry process exits.
- Stop/crash of A removes A's complete group while B supplies a fresh live positive.
- Replacement A2 cannot be affected by an old captured A Binder/work identity.
- Stop while A2 is held defeats any late release through the old handle.
- Ordinary app control discovery/access and worker cgroup/control-service access remain denied.
- Wrong identities/unknown control commands do not launch or stop work.
- Final group disappearance and init logs are checked independently of request results.

Host checks, compiled artifacts and Android runtime observations are separate gates.
The native client reports observations and failures, not a blanket qualification result.
A fresh complete image and fixture are required; old consumed runtimes are not reused.
