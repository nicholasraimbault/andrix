# Work gateway boundary and ordinary streams

Status: internal crossing and standard stream components are implemented. They are not
an installed Work service, released wire API or Console replacement. Host component,
real Linux socket and sanitizer checks pass. Android compilation, compiled policy and
runtime gates for this source remain separate.

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
supplied descriptors. It does not pretend to compare two arbitrary descriptor sets for
equivalence. The public protocol must preserve that distinction after lost replies.

`Start` now compares both immutable description bytes and the actual binding object.
Another binding is a conflict, even if descriptor numbers, inode metadata or supplied
numeric binding IDs match. Validation and request allocation precede control locks.
The accepted work and backend lease retain their binding. Forgetting input discovery does
not revoke descriptors already held by work or other exact handles, and those references
keep bounded capacity occupied. This is not whole work Stop or terminal hangup.

The default internal plan explicitly closes all standard descriptors. General descriptor
maps and application specific stream delivery remain later integration work. The existing
private launcher has not yet been changed to implement every new binding choice.

## Evidence and remaining gates

Host controls exercise actual packet sockets, SCM_RIGHTS, kernel credentials, ordinary
processes and threads, binary framing, malformed message FD closure and descriptor sharing
within one principal. Credential spoof attempts are rejected by the kernel. Supplied role
matching cases remain distinct from actual Android MAC authorization.

The IO controls exercise real pipes/files, caller FD reuse, equal inode metadata with
different open file descriptions, normal shared offsets, binding conflicts, pinned capacity,
explicit closed roles, invalid access modes and 200 selected capture/cancel races. The
updated registry retains its earlier 600 selected Start/Stop/allocation races. Optimized,
ASan/UBSan and separate ThreadSanitizer runs pass for these components. These finite runs
are not exhaustive scheduling, Android resource cleanup or phone qualification.

The initial C++ member access typo and a stale observer output key were corrected with
failed checks retained. No warning or sanitizer check was disabled. No persistent recorder,
activity history or output capture was added. The [accepted recording policy](../docs/architecture.md#work-records-and-diagnostics)
still governs the separate diagnostic writer work.

Next build and inspect matching native components and selected policy. Then implement the
bounded authenticated dispatcher, stream import retry mapping and actual resource adapter.
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
