# Signing authorization scope

Status: proposal awaiting an owner decision. The current qualified Android vehicle still
requires authentication for each individual key operation. No key policy has been changed.
The [portable recovery default](2026-09-22-installation-key-recovery.md) remains accepted;
this proposal concerns routine authorization, not recovery format or backup ownership.

## Observed constraint

The [qualified artifact vehicle](2026-09-23-protected-apk-artifact.md) deliberately used one
v2 signing operation. A separate host probe requested v2, v3 and v4 signing with the pinned
apksig implementation. It made three distinct SHA256withRSA calls for one APK and verified
the completed APK and v4 sidecar at SDK 37.

Refusing the last callback left a byte identical APK but no sidecar. That is not success for
the requested signing transaction. Both outputs must remain private staging data until all
required operations, verification and publication conditions complete.

The current AndroidKeyStore key uses authentication timeout zero. Its CryptoObject binds
one operation challenge, not the three internal signatures of that complete artifact.
Keeping that exact key operation gate means separately authenticating the required uses.
The host format probe did not exercise a different Android authentication policy. The
Cuttlefish controls also did not establish physical hardware enforcement.

## Recommendation

Make the default approval unit one complete immutable signing transaction:

- One explicit confirmation of the input artifact, key identities, purposes, formats and
  requested outputs.
- One fresh credential authentication for that transaction.
- No authority for a later request, even from the same UID or while device authentication
  remains recent.
- No partial result publication when an internal signing operation fails or is cancelled.

On the pinned AndroidKeyStore path, a short bounded authentication validity window is the
candidate mechanism for the multiple internal key operations. The isolated broker would
still enforce the concrete request and own every operation through retirement. Neither
ordinary apps nor Unix jobs would gain access to its key namespace.

This changes the hardware boundary. During that interval the key backend permits uses based
on recent authentication, rather than demanding a distinct challenge for every signature.
It does not understand the artifact transaction. A compromised broker could misuse that
window, and its expiration is not the same event as the broker closing a request. Ordinary
phone unlock can also contribute recent device authentication, so it must never be treated
as approval of a signing request. The broker must require the fresh transaction prompt and
retain its exact context independently.

The stricter alternative is to retain authentication for every backend operation and accept
multiple credential prompts for one APK. That remains a legitimate mode and the current
qualified behavior. A reusable signing or general administration session is a separate
policy, not implied by choosing one transaction as the default.

## Required qualification if accepted

The exact window duration is an unmeasured implementation parameter, not selected here.
Before promotion, tests must establish:

- Actual imported key policy and ordinary namespace isolation on the intended device.
- Refusal without concrete approval, even when a recent unlock makes the hardware key usable.
- Fresh confirmation and credential authentication of this transaction, with no grant
  borrowing by another pending request or another UID.
- Correct ownership when cancellation, expiration, caller loss or broker loss intersects
  the multiple signing operations.
- Complete APK and sidecar verification before publication, with an independently trusted
  expected signing identity and no silent partial success.

No personal identity will be provisioned and no permanent policy adopted before the owner
accepts this authorization tradeoff. The existing per operation prototype remains unchanged.
