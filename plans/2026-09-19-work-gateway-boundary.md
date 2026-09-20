# Work gateway boundary and ordinary streams

Status: internal crossing and standard stream components are implemented. They are not
an installed Work service, released wire API or Console replacement. At `0e6f7a8`, all
426 host tests, optimized/ASan/UBSan/ThreadSanitizer controls, ARM64 library compilation
and three actual frozen Soong host tests pass. The corrected source explicitly references
the unchanged normal/selected policy compiled at `070a842`. Its failed EOF regression
and correction are retained below. There is still no new Android runtime result.

## Goal and ownership

Connect the [registry](2026-09-19-work-registry-core.md) to authenticated owner clients
without exposing its mutable admission gate, cgroup controls or privileged launch
protocol. Retain the [accepted work contract](2026-09-17-delegated-supervision-contract.md#5-andrix-work-contract).
Android owns the enclosing environment. The registry owns work state. The eventual
adapter owns actual resources, caller authorization and operation dispatch.

The first native crossing uses local Unix packet sockets. Ordinary owner programs retain
the existing Binder ioctl restriction. A new work API is not permission to become an
ambient Android Binder client. The existing Console Binder path remains unchanged until
the replacement is qualified. No network listener or upload authority is introduced.

Property commands remain finite fixture controls, not a public request protocol. Direct
access to management descriptors would bypass the required authority and ownership
checks, so it is not an alternative public API.

## Authenticate the principal and endpoint, not a PID

`work_peer` separates connection correlation from authorization. `SO_PEERCRED` supplies
kernel connection credentials. Every received message must also have valid kernel
`SCM_CREDENTIALS` in that connection's UID/GID principal. A socket cookie detects using
a different connection. The adapter must still retain the actual socket descriptor
through each operation and through event retirement. Cookie sampling does not make
concurrent close and descriptor number reuse safe.

Kernel checked credentials are not an unconditional sample of effective credentials.
At this pin, an unprivileged sender may select its real, effective or saved UID/GID.
Namespace checked `CAP_SETUID` and `CAP_SETGID` allow overrides. The declared caller
profiles must therefore retain their fixed identities and lack those capabilities.
The native owner entry checks all three UID/GID values and empty capability sets. The
host spoof refusal controls cover unprivileged senders, not privileged impersonation.

Authorization additionally requires actual `SO_PEERSEC` data and the declared policy:

- The native owner has the reserved owner UID/GID and an owner domain socket.
- Console has a primary user application UID/GID and the dedicated Console socket context.
- The manager has the reserved UID/GID and a separately typed public endpoint. A private
  `andrixd` channel is not that endpoint.

These are fixed trusted profiles, not caller selected credentials or privileged execution
profiles. IDs, operation names and matching descriptions never authorize a request.
Missing or unexpected security context fails closed. The current Linux host reports
`ENOPROTOOPT` for `SO_PEERSEC`; host tests therefore cannot qualify successful Android MAC
authorization. The lower credential/framing tests are deliberately not an authorization
bypass in the public path.

A socket context is an object label, **not a fresh task SID**. This design depends on
compiled policy controlling who can create and use those socket objects. It does not
replace the actual task profile observation required at privileged bootstrap entry.
The selected public endpoint type can be created and read/written only by trusted
management code. Owner and Console receive connection permission, not access to the
server's internal endpoint descriptor. Private channels, mutable gates and direct Binder
access stay denied.

SELinux copies the connecting client's MLS level to an accepted Unix server socket.
Authorization recognizes the fixed public endpoint type with that level, rather than
requiring every Console connection to have the manager's original plain `s0` level.
This does not grant Console direct owner home access.

Sharing a client descriptor within the same principal is permitted, subject to current
MAC socket use checks. Each message still supplies kernel credentials. Forwarding it to
another UID/GID does not transfer owner authority. A process acting as an authorized proxy
uses its own authority; this crossing does not claim isolation between arbitrary programs
inside one owner identity. Future isolated agents need distinct principals and explicit
scoped rights. They must not inherit the full owner profile merely by matching metadata.

### Why the PID pin experiment was not adopted

A first experiment used `SO_PEERPIDFD`, `SO_PASSPIDFD`, `SCM_PIDFD` and pidfs inode identity
to require the original process on every message. Pinned 6.12 source and a real host
socket control supported that mechanism, including rejection of an inherited connection
used by another process with the same UID. Threads remained in the original group.

The mechanism has an important credential provenance qualification. `SCM_PIDFD` is
created from `scm->pid`, not independently forced to the current sending task. In
`net/core/scm.c:47–64,180–210`, `CAP_SYS_ADMIN` in the active PID namespace's user namespace
permits another credential PID, and `find_get_pid` supplies that PID object. Then
`include/net/scm.h:136–169` creates the received pidfd from it. UID/GID checks are separate.
Pidfs object equality can identify that nominated PID object; it does not by itself prove
which privileged task sent the packet.

The normal automatic paths use `task_tgid(current)` in `net/unix/af_unix.c:760–763,1929–1936`
and `include/net/scm.h:94–102`. The socket paths pass zero flags to `pidfd_prepare`, whose
check in `kernel/fork.c:2088–2095` requires a thread group PID rather than `PIDFD_THREAD`.
`fs/pidfs.c:242–273,399–412` supports comparison through inode identity and a dentry cached
for the retained PID object. These inspected paths and finite unprivileged controls are
not a blanket statement about privileged senders or every namespace scenario.

That was an unnecessary process restriction for this owner principal contract. It also
introduced a newer kernel dependency without a demonstrated need. The caiman reference
uses the caimito 6.1 family, not the Cuttlefish 6.12 kernel. The inspected 6.1 prebuilt
symbol map contains pidfd support but no pidfs symbols. This is not a physical device
feature test or proof about every backport. It is enough not to assume the emulator's
newer combination is a product requirement.

The chosen contract deliberately authorizes the principal and retained endpoint. It
does not claim process pinning with a weaker fallback. No caller PID is used for signaling,
process lookup or authority. The successful experiment and its narrower assumptions
remain recorded. Revisit process binding if a future principal or delegation contract
actually requires it, with target kernel evidence and explicit transfer semantics.

## Bounded framing and received descriptor ownership

`work_channel` implements an internal versioned envelope with a correlation value,
operation tag, explicit byte count and descriptor count. It rejects malformed versions,
lengths, reserved fields, truncation, missing credentials and wrong connections. Received
descriptors are atomically close on exec. Every delivered descriptor is owned immediately
and closed on rejection, including zero byte packets and unexpected pidfd ancillary data.
An authorized peer also determines the permitted request/reply direction.

The component ceiling is 64 KiB per frame and three imported standard stream descriptors.
These are not adopted application argument limits or a complete arbitrary descriptor map.
The operation protocol must reconcile its bounds with launch descriptions, for example
through the existing sealed ordinary description mechanism. It must not silently truncate
an ordinary launch request to fit a control packet.

The adapter still needs explicit bounds on connections, queued replies, buffers, imports
and outstanding work. It must authenticate reconnection into the original request stream.
A lost reply does not silently create a new stream and replay work. Work and input IDs
must be checked within the exact authenticated manager incarnation. Framing alone does
none of this dispatch or namespace work.

## Immutable bindings with ordinary Unix semantics

`work_io` reserves bounded capacity before duplicating caller descriptors. It duplicates
outside the pool mutex and does not read or write user data or change file status flags.
The caller, normally the received message object, must own the supplied numbers until
capture finishes. Input must be readable and output/error writable. An explicit Closed
role is allowed. There is no implicit inheritance of the manager's standard descriptors.

The accepted binding retains the actual open file descriptions. The caller may close and
reuse its original numeric descriptors without changing that binding. File contents,
offsets, shared status flags and pipe behavior still have ordinary Unix semantics. This
is immutable descriptor identity and role assignment, not immutable file data.

Capture claims its reserved slot before performing any duplication. Cancellation before
that claim prevents it. Once capture starts, cancellation retains the slot until actual
completion and descriptor release. Even final close can take time; it runs outside the
mutex without releasing the occupied import slot prematurely. Counter exhaustion refuses
new identities rather than wrapping.

An already captured import ticket returns the existing binding without importing new
supplied descriptors. A capture still in progress reports Pending. Neither result pretends
to compare two arbitrary descriptor sets for equivalence. The public protocol must preserve
that distinction after lost replies.

`Start` compares immutable description bytes and the actual binding identity. Another
binding is a conflict, even if descriptor numbers, inode metadata or supplied numeric
binding IDs match. Validation and request allocation precede control locks. A new Start
requires a live descriptor lease. An identical accepted retry can use a retained identity
without regaining access to already released descriptors.

### Metadata must not keep pipes open

The first implementation put identity and open file descriptions in the same retained
object. A real pipe regression at `070a842` demonstrated the error: retaining completed
work metadata kept the writer open, so a read returned `EAGAIN` instead of EOF after the
input registration was forgotten. Earlier compilation and finite tests had not covered
that lifetime. The failed regression is retained.

`WorkIoBinding` now retains identity only. `WorkIoLease` separately retains actual file
descriptions for a creator/handoff operation. Start returns that live lease alongside the
backend ticket; it does not store the lease in historical work metadata. The adapter must
release it after descriptor handoff or definite cancellation, not wait for result GC.
Forgetting an input registration releases its descriptors outside the mutex. Already held
creator leases keep their actual resources until their own handoff or release completes.
The recipient then owns its received descriptors normally.

Both metadata and actual leases keep bounded identity slots occupied. A descriptor set
retains that identity through every final close, including a stalled close. But metadata
references alone no longer retain any FDs. New pipe controls verify EOF while work,
backend and input identity records remain alive, with and without a separate recipient
holding the handed off writer. Normal file offsets and exact retry identity still hold.
This is descriptor ownership, not whole work Stop or forced terminal hangup.

The default internal plan explicitly closes all standard descriptors. General descriptor
maps and application specific stream delivery remain later integration work. The existing
private launcher has not yet been changed to implement every new binding choice.

## Evidence and remaining gates

Host controls exercise actual packet sockets, SCM_RIGHTS, kernel credentials, ordinary
processes and threads, binary framing, malformed message FD closure and descriptor sharing
within one principal. Credential spoof attempts are rejected by the kernel. Explicit
ancillary truncation closes delivered FDs. A descriptor import is refused at `EMFILE`,
while a subsequent frame that imports no descriptors is still received. This is a bounded
transport control, not end to end Stop or Android MAC qualification. Supplied role matching
cases remain distinct from actual Android authorization.

The IO controls exercise real pipes/files, caller FD reuse, equal inode metadata with
different open file descriptions, normal shared offsets, binding conflicts, pinned capacity,
explicit closed roles, invalid access modes, EOF independent of metadata retention,
200 selected duplicate import races and 200 capture/cancel races. The updated registry
retains its earlier 600 selected Start/Stop/allocation races. Optimized,
ASan/UBSan and separate ThreadSanitizer runs pass for these components. These finite runs
are not exhaustive scheduling, Android resource cleanup or phone qualification.

The initial C++ member access typo and a stale observer output key were corrected with
failed checks retained. No warning or sanitizer check was disabled. No persistent recorder,
activity history or output capture was added. The [accepted recording policy](../docs/architecture.md#work-records-and-diagnostics)
still governs the separate diagnostic writer work.

At `070a842`, normal and selected compilation/policy inspection passed, as did eight
actually frozen Soong host executables. The selected public endpoint had the required
creation/use restrictions and was absent from normal policy. Core/LMKD adaptations were
restored and framework/Soong fences passed. Those results remain specific to that source,
including its subsequently exposed EOF lifetime limitation.

The corrected `0e6f7a8` then passed its own 426 host tests, ARM64 library inspection and
three actual frozen Soong host tests, including EOF retention and the `EMFILE` control.
Normal legacy binaries remained byte identical to the retained reference. The policy
reference is explicit, with only implementation/tests/docs changed since `070a842`, not
a new policy build or a new image. Framework fences passed and Core/LMKD/Soong remained
unchanged. No Android VM or physical device ran in either phase.

The subsequent [selected service integration](2026-09-20-work-service-integration.md)
implements the dispatcher, preparation/input mapping and actual resource adapter. Its
additional component and kernel results are recorded separately. Fresh Android runtime
qualification remains required.
Use exact issued work controls for Stop, separate creator and cleanup lanes, genuine
original epoch admission and truthful resource retirement. Exercise authorized owner
clients, ordinary application negatives, client loss and rediscovery, independent Stop,
late creators, ordinary descendants and CE withdrawal/recovery in fresh Android execution
before routing Console through this service.

## Inspected source anchors

The kernel source below is pinned to Android common `3ec022196c4e`, not a claim about the
caiman kernel or a running phone:

- [`net/core/scm.c`](https://android.googlesource.com/kernel/common/+/3ec022196c4e/net/core/scm.c): kernel credential checks and descriptor reception.
- [`net/unix/af_unix.c`](https://android.googlesource.com/kernel/common/+/3ec022196c4e/net/unix/af_unix.c): connection credentials, queued message credentials and inherited receive flags.
- [`security/selinux/hooks.c`](https://android.googlesource.com/kernel/common/+/3ec022196c4e/security/selinux/hooks.c): socket creation/peer labels, accepted socket MLS copying and current caller socket use checks.
- [`net/core/sock.c`](https://android.googlesource.com/kernel/common/+/3ec022196c4e/net/core/sock.c), [`include/net/scm.h`](https://android.googlesource.com/kernel/common/+/3ec022196c4e/include/net/scm.h), [`fs/pidfs.c`](https://android.googlesource.com/kernel/common/+/3ec022196c4e/fs/pidfs.c) and [`kernel/fork.c`](https://android.googlesource.com/kernel/common/+/3ec022196c4e/kernel/fork.c): the separately assessed, unadopted process pin experiment.

See also the [base assessment](../docs/grapheneos-base-assessment.md) for the device kernel
family distinction. No new physical deployment authority follows from this work.
