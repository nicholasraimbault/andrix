# Bounded work registry core

Status: first internal implementation in `owner/native/work_registry.{h,cpp}`. At
`fd75e1e`, 423 host tests, optimized and sanitizer checks, ARM64 library compilation and
the actual frozen Soong host test pass. The component owns real registry records, request
bytes and gate references. It is not yet connected to an Android service or public caller
crossing. Supplied backend facts are not kernel or Android qualification. The later
[gateway and stream slice](2026-09-19-work-gateway-boundary.md) extends Start matching to
actual owned input bindings. The earlier component result alone does not qualify those
changes or their integration.

## Goal and ownership

Replace the fixed two slot vehicle's ad hoc bookkeeping with bounded reusable work
records. Preserve the [accepted work contract](2026-09-17-delegated-supervision-contract.md#5-andrix-work-contract),
original authority binding, independent Stop and ordinary descendant lifetimes. Do not
turn fixture limits, property transport or one shell/session into product requirements.

The registry allocates work serials and request stream serials within one immutable
manager incarnation. The trusted adapter must supply an incarnation that is not reused
in its authenticated enclosing namespace. The registry cannot manufacture that platform
identity, authenticate a numeric ID or repair a caller that reconstructs an allocator
under an old incarnation.

The adapter also owns actual caller authentication, descriptor import, platform queries,
profile transitions, processes, captured scope controls and filesystem operations. This
component owns only its bounded metadata, immutable ordinary request bytes, operation
correlation and the real shared admission gate references. None of its C++ handles or
management descriptors are an owner payload ABI.

## Identity and retry decisions

### Bounded request streams instead of unlimited nonce tombstones

A trusted gateway issues and retains a request stream for an authenticated caller's
requests. The stream is not necessarily a connection. Reconnection must find the same
stream after authentication, not silently open a new one and replay the old request.

Reservation sequence numbers increase within each stream. Existing retained requests
return their original pending state or control handle. Once a request record is forgotten,
a sequence at or below the stream's high water mark is stale, not permission to reserve
a replacement. Closed stream serials and work serials are never reused in that registry.
Counters refuse new issuance on exhaustion rather than wrapping.

The cost is explicit ordering: a request overtaken by a newer accepted sequence can be
refused even if that older sequence had not been accepted. Concurrent callers can use
independent bounded streams. This is an internal candidate protocol, not a released wire
contract. If clients require acceptance of reordered requests, a bounded acknowledgement
window needs a separate design, not an unbounded set of arbitrary nonce tombstones.

A lost reply does not release an outstanding operation. Closing a request stream prevents
new reservations and cancels pending allocation, but does not Stop accepted work. Current
control and work discovery remain independent of that stream's lifetime.

### Reserve capacity before allocating the gate

`Reserve` first reserves a bounded slot and issues one allocation ticket. The trusted
allocator then creates the required memfd gate outside registry locks. No payload or
execution permission exists at this stage. Duplicate requests see Pending; they do not
receive another allocation ticket.

Cancellation retains the occupied allocation slot until definite completion. A late
matching gate is stopped rather than published as a usable reservation. Failure consumes
the exact attempt. Stale or foreign completions do not consume a newer slot or Stop an
unrelated gate. An exact work control is returned only after reservation allocation has
completed, so its gate reference is immutable for the control's lifetime.

### Exact handles keep their slots owned

Control, backend and observation/cleanup ticket values retain their exact record. A
forgotten record disappears from discovery but cannot release its registry slot while
those values retain it. A retained platform/launcher gate reference also prevents reuse.
The public gateway will need bounds on its own connections, request buffers and handle
references; the registry is not a complete service resource accounting policy.

This deliberately trades capacity for safety. An abandoned retained handle can cause
backpressure, not a stale handle that controls a replacement or an unlimited retired
object pool. The adapter must not retain unaccounted weak gate references or exported
management mappings after it claims retirement.

## Admission and creator ownership

`Start` validates the existing ordinary launch encoding, copies it into the record and
accepts it once. Identical bytes return existing state; a conflicting description is
refused. Changing the caller's buffer afterward does not change accepted data.

A bounded creator slot is charged before the admission operation is issued. The trusted
platform adapter binds the original gate before `AdmissionFinished` can allow payload
creation. No profile or kernel resource creation is permitted by that admission ticket
alone. A declared admission refusal closes this request; a later positive cannot retry
it under new authority. Malformed or contradictory adapter ordering quarantines the
occupied slot rather than inventing resource absence.

One initial creator is supported per work in this slice. Its lease covers every subordinate
creation and mutation it starts. Stop does not excuse late resource ownership reports.
`CreatorFinished` must attest actual cessation and distinguish a captured initial process
or scope, definite absence, and an unknown result. Dropping a lease or reaching a timeout
is not cessation. Unknown resources remain visibly blocked and owned for the enclosing
cleanup boundary, not silently forgotten or replaced.

The first slice validated executable, argv, environment and cwd bytes without importing
caller stream descriptors. The subsequent gateway slice now adds a bounded owned standard
stream pool and includes the actual binding in Start matching. The default internal plan
explicitly closes standard descriptors, rather than inheriting manager handles. Descriptor
numbers or equal inode metadata alone are not interchangeable stream identities. Public
import, general descriptor maps and actual launch adapter integration remain unqualified.

## Stop, exit and final state

`WorkControl::Stop` uses atomic record request bits and the existing shared gate. It has
no registry, record, admission or terminal lock, allocation, syscall or external I/O.
Every caller closes the actual gate before returning, even when another stop requester
was paused between recording its request and closing the gate. This does not perform
or acknowledge physical termination.

Initial process exit is different. It closes any remaining entry permission, but it does
not request whole scope termination. Detached descendants can remain populated after
that process is reaped. A backend must use `termination_requested`, not merely the gate's
Stopped phase, to decide whether whole work termination was requested. The older vehicle's
loop must not be copied unchanged across this distinction.

Snapshots keep independent facts for entry claim, gate closure, known stop request
sources, admission outcome, first reported launch error, initial exit/reap, scope state,
population and cleanup. An entry claim is permission, not an ordinary exec acknowledgement.
Stop sources record known requests, not an invented total ordering of physical causes.
Final record completion freezes those facts against a later harmless Stop request.
There is no physical accounting, complete stream delivery or durable result inference.

## Observation and reclamation

An authoritative population ticket is issued only after creator cessation and initial
process accounting. This excludes an Empty sample from before a late creator finishes.
The read must then use the retained exact scope and start after ticket issuance.

There is one outstanding observation and one cleanup slot per work, never overlapping.
A timed out observation invalidates its result but retains its slot until the exact late
reply or confirmed cessation arrives. Cleanup similarly retains its occupied slot after
timeout. Stale copies cannot consume newer operations. Exhaustion is visible quarantine.

Reclamation requires a closed entry gate and fresh Empty at that closed boundary. Failure
or confirmed cancellation invalidates Empty before another cleanup attempt. A matching
late Reclaimed result may still finish an owned cleanup operation. Reclaimed must attest
actual root/descendant removal and retirement of the backend scope controls. Neither a
missing path nor the disappearance of a worker is that evidence.

The adapter still performs every actual observation, kill and reclamation operation.
Registry closure and destruction request Stop, but do not prove those operations have
ceased or completed. Android's enclosing service ownership remains the backstop.

## Recording and compatibility

There are no filesystem log writes or new persistent activity records in this component.
Its raw accepted description stays only in bounded trusted memory for execution and retry
matching. Public snapshots contain metadata, not arguments, environments or output.
The [accepted recording policy](../docs/architecture.md#work-records-and-diagnostics) still
requires a separately designed minimal event catalogue and protected writer integration.
No optional durable receipt guarantee is exposed here.

The library and its host test add no product package or installed control endpoint.
Legacy `andrixd`, Console, plain/Keep behavior and the earlier passed Android vehicles
remain unchanged. A new component check cannot qualify a changed runtime integration.

## Verification and next gates

Focused controls exercise real memfd gates plus the actual registry and byte codec.
Backend resource and process facts in these tests are explicitly supplied, not measured.
They cover allocation cancellation, late completion, request replay, forgotten keys,
stream closure/reconnection, pinned handle capacity, immutable descriptions, creator
bounds, original authority refusal, natural descendant lifetime state, stale observations,
cleanup timeout/retry, unknown resources and counter exhaustion. Selected concurrent
controls include 200 duplicate/conflicting Start pairs, 200 Start/Stop races and 200 late
allocation/registry closure races. Optimized, address/undefined sanitizer and a separate
ThreadSanitizer build/run pass. These are finite executions of the selected cases, not
exhaustive scheduling, real kernel cleanup or Android caller evidence.

The first Soong host link exposed a missing codec dependency: declaring it as an ordinary
static dependency did not include its implementation in the registry archive. The codec
is now explicitly bundled in that archive. The failed native gate remains recorded;
this build correction does not weaken link checks or security policy.

The corrected source passed 423 host tests and the normal Android native build. Artifact
inspection then had to recognize that the archive contains LLVM bitcode and that a member
can contain multiple LLVM modules. Those failed inspection assumptions remain preserved.
The matching LLVM tool inspected every emitted module's ARM64 Android target, without
disabling LTO. The actual Soong host test and its dependencies were frozen and executed
successfully. Normal `andrixd` and runner binaries matched the retained normal reference
byte for byte. Framework fences passed; Core, LMKD and Soong sources stayed unchanged.
No policy build, new image or Android VM ran in this phase.

Next connect an authenticated bounded gateway and real resource backend to these leases,
with complete ordinary stream semantics. Verify every actual creator, captured handle
and completion against its original record. Repeat real process, Android identity/profile,
CE, independent Stop, descendant and cleanup controls before replacing the vehicle or
routing the public Console path through the registry.
