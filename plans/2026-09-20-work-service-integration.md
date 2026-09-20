# Selected work service integration

Status: the dispatcher, native client, bounded catalog and resource backend are implemented
behind a separate selection. At `04348a5`, 431 host tests, component sanitizer checks,
normal/selected Android native and compiled policy gates, and eleven actual frozen host
executables pass. The unchanged backend also passed real Linux cgroup controls under
optimized and ThreadSanitizer builds. This is not a fresh Android image/runtime result,
physical phone qualification or the default Console service.

## Goal and ownership

Connect the [registry](2026-09-19-work-registry-core.md) and
[crossing/stream components](2026-09-19-work-gateway-boundary.md) to actual owner work.
Android still supervises the enclosing environment. Init does not learn work IDs, CE
policy or terminal state. The new `andrix-work-manager` is separately selected; legacy
`andrixd`, Console and plain/Keep routing remain unchanged.

The service consumes the generic init handoff and checks the actual aggregate and limits.
The shared generic readiness structure contains only environment and kernel object identity.
An optional generic activation receipt follows the actual init readiness/profile decision.
The new service must receive that exact receipt from PID 1 on its inherited private
channel before accepting public requests or publishing its locator. Sending readiness is
not evidence that init accepted it. Stop/failure closes the channel without granting
activation. Existing one way readiness vehicles remain explicit compatibility behavior;
init still receives no work ID or CE policy.

A protected property publishes a random service endpoint locator. It is not authentication.
Clients authenticate the kernel credentials and typed socket endpoint, then match the exact
boot/environment/manager namespace on every operation. Old references do not rebind after
manager replacement.

The selected configuration has four retained work records, two concurrent creators, two
management connection workers and four control connection workers. Existing aggregate,
process and FD profile limits remain. These are explicit qualification capacities, not
adopted product quotas or executable restrictions.

## Operation and client lifetime contract

The internal wire schema uses explicit little endian fields. Hello establishes the service
namespace. OpenStream/Reserve preserve the existing ordered request identity rules.
Prepare carries a sealed ordinary description and explicitly assigned standard descriptors.
Start names the resulting input identity, never caller FD numbers. Inspect/List do not
create work. Stop, Forget and wait results remain distinct. Forget also requires the
runtime slot to have retired after actual thread exit, not just a completed core snapshot.
A blocked runtime obligation must remain discoverable.

A management conversation owns its unaccepted reservations. On connection loss it cancels
only reservations that have not won Start acceptance. This decision is serialized with
Start, not inferred from a stale snapshot. Already accepted work survives the loss, including
when its acceptance reply was lost. Bound control connections never own work lifetime.
The caller can inspect the original reference instead of silently submitting replacement
work. Request streams are not automatically reopened under fresh identities.

Preparation is one attempt per reserved work. A second Prepare does not import new FDs
or pretend they are equivalent to the first set. Pending preparation is visible. After a
lost reply, inspect the exact work for its original input identity. Failed/cancelled
preparation does not become execution permission. A new explicit reservation is needed
for a replacement request.

Start obtains the real creator lease before accepting and consumes the registration before
acknowledgement. A lost client cannot leave a registered pipe writer behind after accepted
handoff. Input cancellation waits for actual outstanding preparation/use to cease, without
holding a control mutex. Work metadata alone still holds no live stream FDs.

`andrix-work run` waits for initial process exit, not for detached descendants. `start`
returns a work reference. `list`, `info`, `stop`, `wait` and `forget` use explicit work
references. The candidate retains bounded volatile results until explicit Forget; it does
not promise history durability. It is not yet an interactive terminal/job control adapter.
Console terminal attachment, foreground signals, Detach and explicit terminal hangup still
need their own integration.

## Independent control and kernel ownership

Connections have fixed, bounded worker lanes. Management and bound control listeners are
separate. Once a control is bound, Stop uses the retained exact work handle, not another
registry lookup or admission call. Stop acknowledgement precedes input cancellation and
any potentially slow last descriptor close. A malicious or stalled import may occupy its
own lane; it must not hold a shared control loop or free an outstanding lane on timeout.
This does not claim immunity to all resource exhaustion by an authorized owner principal.

Each accepted work has a creator/supervision lane and an independent termination lane.
All cgroup operations, handoff I/O, process waiting and user FD release occur outside table
and publication mutexes. Work scopes are created exclusively under the retained `work`
namespace. EEXIST or uncertain capture does not adopt a path or prove absence.

The initial child remains owned by its sole reaper until placement and all creator actions
have ceased. A pidfd is published before placement so Stop can also reach an initial child
that has not entered its work scope yet. Signalling never falls back to a numeric PID/PGID.
If a pidfd cannot be acquired, the still owned child's startup channel closes and the
result remains dependent on actual exit/reap or enclosing Android retirement.

The launcher receives the original admission gate, complete resource/profile transition,
sealed ordinary description and declared streams. No caller environment or executable is
applied in the trusted coordinator role. Initial exit closes entry permission but does not
request termination of detached descendants. Only actual Stop/failure requests drive the
termination lane.

Observation and reclamation use issued registry tickets. A timed out read retains its
operation and cannot supply fresh Empty. A cleanup failure stays blocked and owned. The
termination lane is actually joined before reclamation can retire captured controls, and
runtime slots are not released until the lifecycle thread is actually joined. There is no
replacement worker after a timeout or invented completion after a failed kernel operation.

The genuine platform adapter permanently fails the current manager after authority loss.
Its original gates close, and the manager exits without waiting for input, client, logging
or work I/O. Android's enclosing supervision owns complete retirement before replacement.
The service must not infer authority failure from a Stopped gate alone, since ordinary
initial exit also closes that gate. Clock sampling, entry, exec and physical termination
are still separate events.

## Explicit descriptor delegation without path authority

Kernel `selinux_file_receive` checks backing object read/write access as well as FD use.
Merely allowing the coordinator to use the sender's FD is not sufficient. The selected
service policy therefore permits use of already opened owner streams, while explicitly
forbidding coordinator open, map, execution and pathname mutation on owner home files.
Owner PTY use does not grant coordinator open/ioctl, and owner process ptrace stays denied.
The policy's `open_perms` capability is required for this separation. Conversion of the
actual compiled policy back to CIL verified it, and expanded rule checks verified both
the intended FD access and denied open/map/execute/ptrace permissions. Actual Android
receipt behavior still needs runtime verification. No neverallow is removed to manufacture
success.

This gives trusted management code authority to use an explicitly supplied descriptor for
its lifetime. The implementation only duplicates/transfers standard streams; it does not
read or log their content. The sealed request description is ordinary data and is validated
before acceptance. There is no caller selected UID, SID, capability, bootstrap executable,
cgroup path or management descriptor number.

An owner side descriptor broker was considered. It would avoid coordinator receipt of
backing objects but add another process/handoff boundary, client lifetime obligations and
retry identity design. The selected first implementation uses explicit FD delegation with
no file open authority. Revisit if actual policy/runtime cannot preserve that distinction,
or if additional descriptor types require an inappropriate expansion of authority. Reject
unsupported access rather than silently weaken MAC or substitute stream semantics.

## Closed standard descriptors and Bionic

The private launch packet is now version 2. An explicit mask omits closed standard roles
from SCM_RIGHTS and reconstructs fixed roles at receipt. Old versions, invalid masks and
wrong counts are refused with received FDs closed. The existing all open vehicle remains
its default request.

Bionic's `__libc_init_AT_SECURE` calls `__nullify_closed_stdio` for ordinary processes too,
not only privileged exec. It opens `/dev/null` for missing standard descriptors. Closing
a role before the fixed owner MAC exec is therefore not enough to preserve the ordinary
payload's exec handoff. A bounded mask is carried into the fixed owner entry and reapplied
immediately before the final ordinary exec, after profile checks and all directory/setup
work. The payload's own runtime may establish null descriptors again. That is distinct
from the kernel exec handoff. Bionic's hardening is not disabled or patched.

The cancelled implementation worker supplied a concrete private protocol/launcher patch,
not test evidence or review clearance. Primary reviewed and integrated it, added the owner
entry reapplication and an explicit reserved field, and is responsible for qualification.

## Evidence scope and next gates

The catalog checks cover immutable preparation, consumed registrations and EOF, stale
work/stream handling, 100 Prepare/Stop races and 100 Start/client loss races. The private
protocol tests exercise every closed standard mask, sparse role reconstruction, old
versions, malformed packets, received FD closure and real credential transport.

The real Linux backend fixture uses an explicitly owned delegated cgroup hierarchy. It
exercises actual fork/exec, placement, pidfds, captured group kill, initial reaping,
independent work, detached descendants, held creation/observation and final reclamation.
It also stopped a live, placed bootstrap before late handoff, while preserving creator
ownership until actual completion. The optimized and ThreadSanitizer runtime executions
both reached final retirement and EOF while metadata remained. Its authority epoch and bootstrap profile are host fixture inputs, not genuine Android
lifecycle/MAC proof. Resource bounds and owned cleanup remain mandatory.

The first `0cc7385` native/policy build passed ten frozen host executables. Review then
added the generic activation receipt and composite Forget fence. Corrected `04348a5`
passed 431 host tests and its own normal/selected native-policy gates, including eleven
frozen host executables. Normal legacy coordinator/runner binaries remained byte identical
to the retained reference. Core/LMKD adaptations were restored, framework fences passed,
and Soong remained unchanged. Earlier compile signedness and invalid fixture limit failures
remain recorded; their checks were not suppressed. No image or VM ran in these phases.

A subsequent fresh matching `58b9d94` image passed the
[first finite Android service controls](2026-09-20-work-service-runtime.md). Real owner
clients, ordinary app endpoint negatives, file/pipe/PTY streams, independent work, completed
client exit/caller environment retirement, stale reference lookup and detached descendants
were observed. Stopped logs found denied direct initial signals after owner transition,
although captured cgroup termination succeeded. Placement based routing removes that
unnecessary request without widening MAC. Corrected `4829af5` passed 433 host tests,
sanitizer/kernel controls and a fresh matching image/runtime trial. Binary policy remained
identical and the earlier signal denials were absent. That trial also directly distinguishes
closed stdin at ordinary exec handoff from the Bionic payload's subsequent startup handling.

A later [service CE trial](2026-09-20-work-service-ce.md) passes the finite accepted work
withdrawal, enclosing retirement, old endpoint refusal and normal credential/fresh work
recovery controls at `4829af5`, with the original consent guards unchanged.
Before any default change, extend qualification to uncertain submissions, retained stale
handles, pending admission/entry across recovery and further failure/cleanup races. The diagnostic event catalogue/writer
and ordinary terminal integration also remain unfinished. No persistent activity/output
history, automatic network exposure or wake authority is added by this service.
