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
  and latches Stop. Exit and actual reaping are separate facts.
- Every mutation completion invalidates earlier population evidence. Observation tickets
  retain their issuance boundary and sequence; receipt time cannot refresh stale facts.
- Timeout does not release an occupied worker slot. Confirmed completion or acknowledged
  cessation is required before a replacement operation can start.
- Unknown or merely Removed observations do not authorize retirement. An exact cleanup
  result follows a closed mutation boundary and fresh Empty evidence. Failed cleanup
  retains ownership and requires new evidence before retry.
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

Source selection, native compilation, host kernel behavior, Android init integration,
worker isolation and phone qualification remain distinct gates. Do not promote a host
success into the combined contract or install the link/test drivers as product services.
