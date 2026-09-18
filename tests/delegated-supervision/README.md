# Delegated supervision contract models

This directory checks ordering obligations from the
[draft contract](../../plans/2026-09-17-delegated-supervision-contract.md). It is not an
Android supervisor, service protocol, resource controller or production API.

`model.py` models one captured service instance's startup and retirement, including:

- Complete setup before activation.
- Stop winning over a late creation or readiness result.
- Ownership of late resources even when activation is forbidden.
- An empty population read not being enough while a creator can still mutate the tree.
- Unknown observations, interrupted cleanup and a replacement fence until retirement.
- Old instance references not controlling a replacement.

The model receives facts from tests. Its identity values are not real capabilities or
caller authentication. It does not perform cgroup operations, start or signal processes,
apply credentials, observe Android/CE state or run concurrent threads. Pre-root failure
recovery, exact descriptor handoff, deadlines and actual cleanup worker recovery still
need their own implementations and tests.

The host suite exercises sixteen cases, including all 40320 sequential orderings of eight
selected events. That enumeration is not a proof of arbitrary thread interleavings or
the combined platform contract.

Two model defects were found despite earlier test passes. The first eight-case version
retained an Empty observation across mutation completion. The eleven-case correction
then still allowed activation after the initial service process exited. The model now
requires fresh emptiness after boundary changes, and service process exit latches Stop
and ends Active. This is the managed service process, not an owner shell whose exit
must leave detached work alone.

Population queries also carry instance, boundary and sequence tickets. A delayed Empty
sample from before mutation closure cannot become fresh merely because it arrives later.
Invalidating a query does not free its occupied slot until its result is consumed, and
an old/foreign reply cannot consume a current query. Observations before root capture
remain Unknown. A checked model can still be the wrong model; compare
it with source, kernel behavior and real Android outcomes before adopting code.

Run only these checks with:

```sh
python3 -B -m unittest discover -s scripts/proof/tests -p test_delegated_supervision.py -v
```

## Captured group cleanup on the host kernel

`kernel_cleanup.py` requires its exact fresh delegated proof unit, 512 MiB, two CPUs,
128 tasks, zero job swap and core files. The existing admission helper and observer stay
outside the managed subtree. It reuses the fixed host payload/channel helpers from
`tests/work-factory/kernel_scopes.py`; it does not use Android or owner credentials.
A separate host suite case checks refusal of an undelegated invocation.

The first real kernel run observed:

- A manager exited and was actually reaped while its detached descendant remained alive
  in the captured nested scope.
- A write through the already captured `cgroup.kill` FD killed that descendant, with
  actual SIGKILL wait status. No numeric PID/PGID signal was used for that cleanup.
- Empty directory traversal/removal yielded between bounded fixture steps. An unrelated
  live process supplied 16 control responses across those steps and the other checks.
- Dropping a traversal cursor after partial removal did not lose the root handle. A
  new cursor reclaimed the remaining tree through that same captured root.
- Recreating the old root pathname produced a different inode. The old open control FD
  refused with `ENODEV`; it did not affect the live replacement.

This supports a captured-object mechanism, not a replacement for Android's existing
reap behavior. The old numeric fallback cannot be used after releasing its lifetime
pin. No real numeric PID reuse was forced here. The harness had exclusive mutation and
parent namespace ownership; fstat followed by unlink is not an atomic defense against
an outside actor replacing names. The tree was fixture bounded, not an arbitrary
production hierarchy. No claim of Android init responsiveness, MAC, asynchronous worker
recovery or combined contract qualification follows.

The subsequent [native component candidate](../../supervision/README.md) ports the
ordering and captured group mechanisms to C++. `native_cleanup_kernel.py` exercises
those actual components, including late population, occupied timeout slots, incremental
reclamation, restart fences, permission errors, limits and entry replacement. It still
uses host authority, not Android caller or MAC identity. The updated native and separate
worker probes also exercise explicit takeback of mode zero directories after Empty,
with no implicit bypass in unchanged credential mode. Their single UID cannot establish
cross UID ownership or Android MAC authority; those remain runtime gates.

Next is the corresponding optional Android service cleanup path with exact instance
ownership and restart fencing. The earlier A/B results do not qualify that new code.
