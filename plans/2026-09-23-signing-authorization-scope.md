# Signing authorization scope

Status: proposal awaiting an owner decision on the default unit of authorization. The
mechanism is not selected. The current qualified Android vehicle still requires authentication
for each individual key operation. No key policy has been changed. The
[portable recovery default](2026-09-22-installation-key-recovery.md) remains accepted.

This concerns protected installation signing authority, not a requirement to authenticate
every ordinary application build. Ordinary application keys, platform identities and other
installation trust roles remain distinct.

## Observed constraint

The [qualified artifact vehicle](2026-09-23-protected-apk-artifact.md) deliberately used one
v2 signing operation. A separate host probe requested v2, v3 and v4 signing with the pinned
apksig implementation. It made three distinct SHA256withRSA calls for one APK and verified
the completed APK and v4 sidecar at SDK 37.

Refusing the last callback left a byte identical APK but no sidecar. That is not success for
the requested signing transaction. Both outputs must remain private staging data until all
required operations, verification and publication conditions complete.

The current AndroidKeyStore key uses authentication timeout zero. The ordinary APK prompt
path used by the proof supplies one CryptoObject operation challenge. Repeating that unchanged
path for three operations would require separate authentication interactions. This does not
establish that a complete OS must show three human prompts.

The source distinguishes operation binding from elapsed authentication age. Timeout zero
omits AUTH_TIMEOUT and selects deferred operation authentication. The reference backend
checks the operation token on subsequent calls without an elapsed age check in that branch.
Operation availability and retirement remain separate constraints. A positive timeout instead
selects cached token lookup and age checking. It changes key authorization semantics, not
just the presentation of a prompt. Cuttlefish did not establish physical hardware enforcement.

## Recommended product policy

Make the default approval unit one complete immutable signing transaction:

- One explicit confirmation of the input artifact, key identities, purposes, formats and
  requested outputs.
- One fresh credential authentication for that transaction.
- No authority for a later request, even from the same UID or while device authentication
  remains recent.
- No partial result publication when an internal signing operation fails or is cancelled.

Signing does not itself authorize installation or activation unless those effects are
explicitly part of the approved context. This default does not prohibit deliberately
approved development batches or broader administrative contexts. General arbitrary root
commands and root shells remain accepted goals, not a signing API's curated action menu.
Ordinary jobs must not silently acquire any of that authority.

## Keep policy separate from mechanism

The earlier proposal framed a short Keystore authentication window as the necessary price
of one prompt. That was too narrow for Andrix as an OS. It is a candidate for the ordinary
APK route, not an established requirement of the product.

### Timed key authentication candidate

A short bounded authentication validity window would allow multiple internal key operations.
The isolated signing service would still enforce the concrete approved transaction and own
every operation through retirement. Other requests would receive no application level grant.

This changes the key backend boundary. During that interval the backend permits uses based
on recent authentication instead of demanding a distinct authenticated challenge for every
operation. It does not understand the artifact transaction. A compromised signing service
could misuse that window. Its expiration is not the same event as closing a request or
retiring an already started operation. Ordinary phone unlock can also contribute recent
authentication, so it must never be treated as approval of a signing request.

### Platform transaction authentication candidate

The pinned SystemUI CredentialInteractor first verifies a credential, obtains a temporary
Gatekeeper password handle, requests a token for the operation challenge, and removes the
handle. LockSettingsService provides a privileged verifyGatekeeperPasswordHandle operation
which uses the supplied challenge, with explicit removal and a bounded handle lifetime.
SyntheticPasswordManager passes that challenge to Gatekeeper verification.

This is source evidence for investigating whether a trusted transaction authorization path
can issue the required challenge specific tokens after one human confirmation while retaining
per operation key checks. It is not an implemented or qualified batch authorization mechanism.
The existing method is not itself a transaction API. Do not expose its privileged handle or
credential access to ordinary callers, or treat the ability to request tokens as approval.

This candidate needs a complete design for the authorized operation set, immutable inputs,
key identities, caller and user binding, token issuance, expiry, cancellation and retirement.
Trust in the credential issuer and signing machinery remains necessary. Keeping per operation
key checks does not make the key backend understand the displayed purpose or APK contents.

Andrix should assess this route before accepting broader key usability merely to accommodate
the prototype's ordinary APK interface. The platform is ours to integrate coherently.

## Required qualification

Neither candidate is selected. The exact duration of any timed window is unmeasured. Before
promotion, tests must establish:

- Actual imported key policy and ordinary namespace isolation on the intended device.
  Passing an existing AndroidKeyStorePrivateKey back to setEntry only updates certificates;
  new KeyProtection arguments do not retrofit its authentication policy. Any policy change
  needs an explicit provisioning path and readback, not an assumed setter effect.
- Refusal without concrete approval, including after ordinary phone unlock and during any
  backend authentication validity interval.
- Fresh confirmation and credential authentication of this transaction, with no grant or
  operation token borrowing by another pending request or another UID.
- Correct ownership when cancellation, expiration, caller loss or broker loss intersects
  the multiple signing operations.
- Complete APK and sidecar verification before publication, with an independently trusted
  expected signing identity and no silent partial success.

Accepting one transaction as the default unit would not accept a timed key policy, authorize
personal key provisioning or qualify either candidate. If a weaker key boundary proves
necessary, that tradeoff must return to the owner explicitly. The existing prototype remains
unchanged while the alternatives are assessed.
