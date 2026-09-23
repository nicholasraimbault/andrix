# One protected signing request

Status: the finite disposable import and approved signing flow passed in a fresh Android
guest. Independent verification, refusal, cancellation, replay, broker replacement and
cleanup controls passed within the scope below. This is not a product custody service.

The corrected vehicle passes 509 host checks, including 400 request race rounds, public
SDK compilation and inspected APK builds. Nineteen supplied observer controls precede the
runtime. Both APKs have the expected identities and nonplatform signer, no shared UID or
debuggable flag, and only the signing APK's normal USE_BIOMETRIC permission.

The [portable recovery requirement](2026-09-22-installation-key-recovery.md) is accepted.
The [host recovery and native crypto controls](2026-09-22-signing-identity-recovery-proof.md)
do not themselves establish protected Android custody or exact request authorization.
This vehicle tests those boundaries using disposable identities, not personal keys or a
combined installer. Earlier incomplete attempts are not included in the qualified result.

## Transport and presentation constraints

The inspected `adb exec-in` client copies stdin and returns without waiting for the remote
command. Closing that legacy raw session can hang up the receiver. A successful local write
is therefore not an import acknowledgement. An earlier transport control stopped before
private key submission and did not qualify import.

The corrected transport uses the raw shell protocol with terminal processing and escape
handling disabled. Its public control verifies delayed binary consumption, separate stdin
EOF and a nonzero remote exit code before private input is sent. An unchanged initial status
is not completion, and uncertain mutation outcomes must not be replayed as new requests.

Android can bring an existing Activity forward without replacing the request it displays.
The corrected vehicle handles new presentation intents explicitly. Only a terminal view may
be replaced; a live request keeps its binding. Selecting a presentation grants no signing
authority and does not resubmit work.

Credential input requires an observed, unambiguous trusted UI. A Compose keypad is not an
ordinary editable credential field. The observer checks the actual container, unique digit
labels, clickable controls, nonoverlapping geometry and Enter within the active focused
SystemUI window. The driver also binds that prompt to the owned request. Unsupported or
ambiguous presentation must refuse before reading or entering credentials. Input geometry
alone is not a credential or an authorization grant.

These corrections address observed transport and UI assumptions. Successful import or a
partial control sequence must not be promoted into authenticated signing qualification.

## Recording correction

Earlier private captures contained reconstructable disposable setup PIN commands even
though the driver's own command log excluded them. In the inspected source, adbd independently
logs service command arguments. The earlier claim that the complete captures contained no
credential events was incorrect and has been withdrawn. Original records remain private,
sensitive and unchanged, with a separate correction. No personal credential was used.

The corrected driver keeps the ADB service command constant and sends credential dependent
commands through private stdin. It sanitizes subprocess exceptions, refuses unexpected input
debug logging rather than disabling it, and assesses the actual captures. Key codes and
credential dependent touch coordinates are secret material too. This method does not exclude
every possible logger, process inspection path or memory disclosure.

## Qualified finite runtime

The completed control established:

1. Independent recovery of a disposable key from encrypted backup after its creator exited,
   using an independently trusted expected public manifest commitment.
2. Import through private stdin with exact certificate and public key identities, unavailable
   JCA private encoding and actual per operation device credential metadata. A truncated input
   control created no key.
3. A specific unauthenticated signing refusal. A foreign APK could not access the broker,
   import channel or broker alias, while its own same-alias key had a sign/verify positive.
4. Explicit decline without a signature, followed by approval and normal SystemUI credential
   authentication of another immutable request. Its signature verified against the expected
   public identity and payload.
5. A fresh unauthenticated operation refused after that success. A completed presentation did
   not approve another pending request. Cancellation during authentication retained operation
   ownership through retirement and published no signature.
6. Broker replacement made old pending identities stale while preserving the imported key.
   The expected public identity was independently reconciled before exact logical key deletion
   and removal of the two test APKs.

Independent host verification also refused changed payload and signature controls. Framework
identity stayed stable, runtime and capture processes retired, and frozen inputs matched.
No SELinux denial was observed in the captured log. The packet capture was deliberately
filtered, not a capture of every interface or all traffic.

Captured adbd records for the corrected input route contained constant service commands, not
individual credential digit commands or taps at the observed digit centers. Detailed input
dispatch records were absent, and logging properties were not changed. These are scoped
observations, not universal secrecy or physical erasure. They do not retroactively sanitize
the earlier sensitive captures.

An observer must distinguish event occurrences from equal result values when checking order.
Correcting that assessment did not rerun signing or alter the original failure record.

Cancellation after the signer has claimed an operation, broker loss during accepted signing,
actual CE withdrawal, hardware custody, durable recovery publication and general elevation
remain separate qualification gates. The later [APK artifact extension](2026-09-23-protected-apk-artifact.md)
qualifies one ordinary package flow separately, not broader installation signing authority.
Only user0 and the declared shell requester were exercised. No personal installation identity
was provisioned.

## Scope

Use two ordinary test APKs with separate Android UIDs and no shared UID. Neither is a
factory product component, privileged APK or platform signer. The first imports one
new disposable RSA PKCS#8 key and its exact X.509 certificate into its own AndroidKeyStore
APP namespace. The second tests ordinary caller and key namespace boundaries, including
an ordinary signing positive in its own namespace.

The first APK's lab transport accepts only the actual shell Binder UID, on user0 of the
selected debug emulator product. It checks that caller before decoding requests or opening
an import pipe. This is a bounded test entry point, not the finished owner administration
interface. The native owner environment gains no new Binder or signing permission.

Import is a bounded local pipe transfer, not private material in arguments, logs, a URI or
an APK asset. Transport recording must also exclude the import stream: a packet capture of
local ADB traffic could otherwise retain the private bytes even if command logging omits
stdin. Any capture must declare its narrower scope and verify the actual filter/interface.
Independently supplied certificate and public key commitments must match the parsed material. A fixed internal challenge checks private key/certificate association.
Existing aliases are not overwritten. An import cancelled after entering the synchronous
Keystore call may still have created a key and must be inspected, not reported as never
having happened.

The imported device key requests SHA256withRSA signing, fresh device credential
authentication for every operation, and an unlocked device. No biometric enrollment is
assumed. The proof checks the actual key's authentication metadata and nonexportable JCA
interface. Reported security level is not a physical hardware assurance on Cuttlefish.

## Request and approval binding

The broker captures a bounded copy of the payload, observed requester UID/user, exact key
certificate identity, named purpose and a fresh request identity. Incoming intents cannot
replace that stored request. The UI displays those fields and requires an explicit approval
before opening the system credential prompt. The proof driver supplies fixture credentials
only to an observed active, focused Settings or SystemUI credential window. Its private
input route does not place the credential or individual key events in the request log.
Undeclared action fields and literal credential input requests are refused and redacted
before an evidence writer sees them, rather than being rejected only after recording.

Authentication and approval are separate. A successful normal unlock or an authentication
callback for a different operation must not authorize this request. A fresh Signature
operation is initialized for the captured key. BiometricPrompt receives that exact
CryptoObject. Only its successful device credential callback may claim this stored request
for signing once. There is no ambient flag saying that every program of a UID is authorized.

The plain Java request object does not authenticate callers or UI. Its transitions are
trusted broker internals, not public approval methods. Tests of two requests sharing a UID
must demonstrate that one cannot borrow the other's grant. They do not establish isolation
between arbitrary programs sharing one principal or protect against malicious signer code.

## Ownership and failure

Pending and authenticating requests can be cancelled. Cancellation during signing retains
operation ownership until the actual signer finishes or fails, and suppresses unpublished
output. Cancellation cannot undo a signature already returned. A late or duplicate callback
must not fail, replace or abort a newer operation.

An in progress Signature initialization also owns its operation slot. Cancellation does not
release that slot before initialization and any required provider abort finish. Backend calls
must not run under the request object's monitor. Reinitializing Signature to verification
asks the Android provider to abort its previous operation; the provider can log a daemon
error while dropping its reference. This is not a synchronous hardware erasure guarantee.

Accepted signing work is distinct from its Activity. UI destruction cancels unaccepted
approval, not an already claimed signature operation. Public results remain inspectable by
exact request identity within the broker process. Broker replacement creates a new epoch;
old request IDs cannot be adopted as new requests. No durable outcome recovery or automatic
resubmission after an uncertain reply is claimed.

## Source findings and controls

The pinned source supports PKCS#8 import followed by separate certificate storage. That
ordinary import path materializes private bytes in app and provider memory before passing
them to the key service. Protected device custody is not a claim of hardware only import or
complete plaintext erasure. The vehicle checks the exact certificate and SPKI against the
independently expected owner record, tests key association, and verifies the actual device
signature. Certificate metadata alone does not establish that association.

Passing an existing AndroidKeyStorePrivateKey to setEntry follows a different path: it
updates certificate subcomponents and returns, without importing new KeyProtection arguments.
That is not a way to change an existing key's authentication policy. The vehicle imports
recovered key material into an unoccupied alias and reads back its actual policy. AndroidKeyStore
cannot serialize its contents as an exportable backup. The RSA private wrapper exposes the
public modulus through RSAKey, not a private exponent or encoded key.

KeyProtection accepts authentication timeout zero with DEVICE_CREDENTIAL. The provider
binds credential only keys to the Gatekeeper user identity and requires an existing secure
lock. BiometricPrompt permits device credential authentication with a CryptoObject and
rejects a conflicting negative button configuration. Signature initialization obtains the
operation challenge before authentication. A nonzero challenge alone is not proof of an
authentication requirement, because the provider can synthesize one for other operations.
The loaded key wrapper retains a key ID, and signature initialization uses its KEY_ID
descriptor rather than resolving the alias again. This prevents that particular retargeting,
not every provisioning or replacement race.

Token ingestion into Keystore2 requires AddAuth permission. Its operation receiver routes
by challenge, but only logs SID or authenticator type mismatches before forwarding the token.
The inspected reference KeyMint backend performs the rejecting MAC, SID, authenticator type
and challenge checks. These source layers do not identify a physical backend or establish
its credential issuer and shared HMAC secret. API nonexportability also does not prove
imported plaintext erasure or physical extraction resistance. The token authenticates the
operation challenge, not the purpose or payload displayed by the broker.

Required controls include:

- Exact imported certificate/public identity and actual authentication metadata.
- A specific user authentication refusal before approval, not any generic crypto error.
- Fresh trusted confirmation and credential authentication, followed by a verified signature.
- No authorization transfer to a changed request, key, purpose or payload; stale/duplicate
  callbacks and cancellation ordering must be tested separately.
- Refused foreign APK access to the broker and import stream, with independent Keystore
  positives and the same alias resolving only within that APK's own namespace.
- Actual completion and cleanup, an inspected recording boundary, and separate corrections
  for any private material found in earlier captures.

This prototype's fresh authentication scope is conservative engineering for a finite test,
not a selected permanent UX or reusable administrator session policy. General arbitrary
root commands and shells remain accepted goals, not implemented by this one signing action.
Actual CE withdrawal, multiuser integration, durable provisioning and hardware custody need
separate controls before promotion to a product signing service.
