# Cold attachment and pending ownership

**Status:** the guarded pending-lease correction passed bounded Android checks.
This does not guarantee survival of arbitrary scheduler stalls.

## Technical finding

A received native attachment could wait for main-thread parser/UI preparation while
its lease expired. A retry could succeed without explaining or fixing that gap.
Ownership now has explicit pending and active states: ordinary renewals cover pending
preparation, input stays blocked until identity-checked promotion, and cancellation
or expiry retires ownership before local descriptor shutdown. Late replies cannot
revive an obsolete request.

## Verification

Exercise first attachment, main-thread delay, cancellation, replacement, relock and
output gaps. Use actual native lease/stream behavior and a fresh enabled/focused UI
observation before input. A successful retry does not retroactively validate the
first attempt, and UI transport completion is not command success.

See [attachment code](../owner/terminal/protocol/AttachmentLifecycle.java),
[UI-driver freshness](../scripts/proof/ui_queue.md) and [owner transport](../owner/README.md).
