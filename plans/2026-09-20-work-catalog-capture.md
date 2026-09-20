# Catalog capture after Forget

Status: the host-reproduced wrapper recreation race is corrected. This is not an Android
scheduling result for that interleaving, and it does not replace the earlier
[known identity transport trial](2026-09-20-work-service-uncertain-replies.md).

## Finding

`WorkCatalog::Capture` created a fresh catalog `Work` with default `forgotten=false` from a
`WorkControl` obtained by `registry.Find` or an identical `Reserve` retry. Registry lookup
pins only the `Record`. If that lookup succeeds before `Forget`, then waits before taking
the catalog publication lock, another thread can `Forget`, drop remaining `WorkHandle`s
and `Collect` the canonical wrapper.

`Capture` then inserted a replacement wrapper for the now-forgotten record. After the
temporary handle dropped, `Collect` never removed it: the new wrapper was not marked
forgotten. Later `Find` and original-stream `Reserve` refused the identity, and the only
record slot stayed occupied.

A deterministic host probe paused the test allocator on `Capture`'s candidate allocation,
after registry lookup and before the catalog lock. There is no production callback. Both
`Find` and `Reserve` reproduced the pin: the delayed handle existed, the record reported
forgotten, and a replacement reservation returned Capacity.

## Correction

While holding `Catalog::mutex`, `Capture` still returns an existing canonical wrapper if
one is present. Only then does it inspect the retained control. A forgotten record is not
published again. `Collect` shares that lock, so a surviving canonical wrapper cannot
disappear between the check and insertion. Existing retained handles remain valid.

If `Reserve` obtained a control but capture refuses it because the record is now forgotten,
the reply is `Stale`. It is not `Capacity`, and that control is not Stopped.

## Evidence and limits

The unfixed probe failed as expected. After the correction, the same schedule left no late
handle and reused the slot; a `Reserve` retry returned `Stale`. Two hundred unsynchronized
Find/Reserve/Collect/Forget rounds also reused capacity. Focused service checks, AddressSanitizer,
UndefinedBehaviorSanitizer and ThreadSanitizer covered the capture binary. 435 host tests
then passed in 209.445 s.

A source review of the publication and lock order found no remaining wrapper-creation path
and no Catalog/Record inversion in the inspected functions. That review did not execute
the tests and is not clearance.

This does not claim Android scheduling of the paused allocation, loss of initial
stream/reservation identity, durable receipts or complete catalog exhaustion coverage.
A later matching `985c9a4` selected image includes this catalog correction. Normal and
selected native/policy gates passed, including the frozen Soong capture test. Binary
policy stayed identical to the first service image. The known identity transport controls
then passed on a fresh offline fixture. That Android result does not schedule the paused
allocator interleaving; it shows the corrected manager still provides the earlier finite
transport behavior.
