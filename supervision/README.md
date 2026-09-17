# Native delegated service components

**Status:** internal implementation candidates for the
[delegated supervision contract](../plans/2026-09-17-delegated-supervision-contract.md).
They are not wired into Android init, not a production control API and not a change to
ordinary owner work. The static library and link probe are not product packages.

## Responsibilities

`InstanceState` is a single owner/event loop component. It performs no I/O and verifies
no caller, credential or CE authority. The trusted adapter supplies verified facts and
retains the real process and resource objects. The state component enforces ordering:

- Immutable instance identity, issued typed tickets, bounded mutation slots, one reader
  and one cleanup step in flight. A shared allocator prevents different service slots
  from independently issuing the same boot/serial identity.
- Complete setup before one activation. Initial service process exit closes activation
  and latches Stop. Exit and actual reaping are separate facts. A definite failed start
  with no process uses an explicit absence fact, never an invented exit or wait result.
  Failure before any root allocation has a separate retirement path.
- Every mutation completion invalidates earlier population evidence. Observation tickets
  retain their issuance boundary and sequence; receipt time cannot refresh stale facts.
- Timeout does not release an occupied worker slot. Confirmed completion or acknowledged
  cessation is required before a replacement operation can start.
- Unknown or merely Removed observations do not authorize retirement. An exact cleanup
  result follows a closed mutation boundary and fresh Empty evidence. Failed cleanup
  retains ownership and requires new evidence before retry. Lost final replies have a
  separate authoritative reconciliation operation, bound to a fresh observation ticket.
- Replacement is fenced until retirement with no outstanding operations. Capacity limits
  cause backpressure; counter exhaustion cannot wrap or reuse identities and quarantines
  the instance. The small test limits are not owner resource defaults.

`CapturedCgroup` owns duplicates of the parent, root and core control descriptors. It
validates actual cgroup v2 objects and captures controls from that root. Kill uses its
captured `cgroup.kill` FD, never a reconstructed PID/PGID or pathname. Parent/root identity
and parsed population are not substitutes for caller authorization or exclusive creation.

`ReclamationCursor` removes only directories under that captured root. It checks each
entry against the opened object, rejects unexpected types/identity, and uses `openat2`
with beneath, no symlinks and no mount crossings. There is no weaker fallback if that
primitive is unavailable. Independent directory descriptions avoid sharing traversal
offsets when a cursor is dropped and resumed.

A cursor has bounded depth, cumulative directory/entry visits and total work. Each call
has a bounded operation quantum. Dropping a cursor does not reset those cumulative
limits or lose the root. Only one cursor can own traversal at a time. Errors remain
Blocked, not a false retirement or automatic retry through a new pathname.

## Private cleanup worker candidate

`cleanup_worker` provides a private local protocol for a fixed trusted cleanup process.
It accepts captured descriptor bundles, not arbitrary paths, UIDs, profiles or programs.
Every packet checks actual `SCM_CREDENTIALS` and immutable instance, worker generation
and increasing request sequence. Socketpair `SO_PEERCRED` alone would identify its
creator, not the later child sender. Extra or malformed descriptor messages are refused
and received descriptors remain owned for closure.

The candidate uses a process rather than adding filesystem work to init's critical loop.
A process can be observed dead before a new worker acquires the cleanup obligation;
a timed out thread cannot safely be assumed cancelled. The cost is another bounded
process, private IPC and descriptor/lifetime management. The Android bootstrap must
still enforce its complete trusted profile, UID/SID, FD closure and peer binding.
The host driver uses a fixed executable, empty environment and explicit descriptor
inheritance; it is not the Android implementation of those checks.

The supervisor keeps its original parent/root/kill/events descriptors across worker
loss. Transfers preserve actual descriptor identities, limits and cumulative work
accounting. A transferred bundle is accepted only from the trusted private supervisor,
not from caller supplied metadata. There must still be only one live cleanup owner;
copying descriptors does not itself enforce a lease across processes.

If the worker removed the root but its reply was lost, `ConfirmRemoved` requires the
formerly valid captured core event FD to return `ENODEV` and the owned parent entry to
be absent. Neither a missing pathname alone nor permission failure suffices. A replaced
name remains an explicit identity failure. Only the separate verified reconciliation
result, on a closed current boundary, can retire the instance without the original reply.

The [worker kernel probe](../tests/delegated-supervision/cleanup_worker_kernel.py) exercises
real descriptor transfer and a separate process. Controls include SIGSTOP while a step
is outstanding, responsive parent inspection, timeout without slot reuse, actual worker
kill/reap before replacement, partial cleanup recovery and a deliberately discarded final
reply. Captured removal reconciliation succeeds without retargeting a recreated name.
This does not prove Android init responsiveness or uninterruptible kernel I/O behavior.

## Important limits

These components still need their Android adapter and execution machinery. In particular:

- The trusted allocator must create roots exclusively and keep the parent namespace
  from being reused until retirement. Capture does not establish fresh creation.
- Reclamation requires the lifecycle controller's valid cleanup permit, closed mutators
  and stable quiescence. The cursor's additional Empty check cannot prove that no
  outside creator will later write to the scope.
- `fstatat` followed by `unlinkat` is not atomic against an actor replacing names between
  those calls. The platform must own that namespace exclusively. Deterministic identity
  mismatch tests do not qualify a hostile concurrent writer.
- Operation count is not a bound on kernel syscall duration. Run kernel I/O on the
  selected bounded cleanup lane, not directly on init's critical loop merely because
  traversal is incremental. The worker pool, deadlines and worker failure recovery
  still need implementation and qualification.
- Completion tickets correlate trusted results; they are not transferable authorization.
  The adapter must bind each ticket to the original captured resource object and verify
  actual child exit/reap and profile readiness. A pidfd does not pin a numeric PID for
  future numeric operations.
- No owner work identity, CE admission, program selection or terminal policy belongs in
  these generic service components. The factory fixture's release/authority gaps remain
  separate work, not fixed by this library.

## Checks

Standalone C++ tests cover activation/exit/reap, stale and foreign callbacks, mutation
and observation fences, timeout slot ownership, cleanup failure/retry, replacement,
shared allocation and bounded/exhausted counters. Kernel data parsing and invalid
capture inputs include descriptor leak checks. Optimized and address/undefined behavior
sanitizer runs are separate from Android compilation or execution.

The [native kernel driver](../tests/delegated-supervision/native_cleanup_kernel.py)
uses these same C++ components under one exact fresh delegated host unit. Its controls
include a manager reaped before group kill, an actual late member invalidating an earlier
Empty sample, repeated exact group kill, occupied timeout slots, cursor interruption,
independent live control responses, depth/entry/work/quantum refusal, actual `EACCES`,
and old object/name replacement rejection. Lifecycle facts in empty fault cases are
supplied by the harness; these are not Android service or MAC tests.

At `8a7ddd1`, 386 general host tests passed, alongside the focused native optimized,
sanitizer and real kernel controls. The library compiled for Android and linked into
an uninstalled ARM64 probe. Both Soong host tests ran from frozen executables with their
matching build dependencies. The first module attempt requested a nonexistent Make
phony for the uninstalled probe; a fresh attempt built its actual output target without
changing installation rules. No init implementation or policy was changed.

Source selection, native compilation, host kernel behavior, Android init integration,
worker isolation and phone qualification remain distinct gates. Do not promote a host
success into the combined contract or install the link/test drivers as product services.
