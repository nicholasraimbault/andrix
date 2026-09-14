# Owner-work lifecycle groundwork

**Status:** the ordinary Android lifecycle witness was useful for observing UI/service
lifetime, relock and explicit Stop. It was not adopted as native storage-key authority.
The later [platform integration](2026-09-13-android-lifecycle.md) supplies that boundary.

## Distinct concerns

Explicit consent to retain computation, Android user/CE lifecycle, foreground terminal
read/input authority and presentation recovery are different requirements. A surviving
foreground-service process or public unlocked-state polling does not establish all four.

A directory's fscrypt policy does not prove that its key remains loaded. Console death
provides a conservative plain-session boundary, but suppressing that death cleanup
without a separate platform authority would weaken the design.

## Witness role and limits

The [ordinary witness fixture](../tests/owner-lifecycle-probe/README.md) exercises Android
application/service behavior without user/storage-management privileges. Its results
cannot substitute for key withdrawal, native whole-group cleanup or terminal parser
reconstruction. Reboot does not imply automatic owner work restart.

Native Keep, package transactions and external services require their own integration
and verification. See [retained presentation](2026-09-13-retained-terminal.md) and
[explicit Keep](2026-09-14-keep.md).
