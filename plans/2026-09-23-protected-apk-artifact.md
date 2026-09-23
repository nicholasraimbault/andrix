# Protected signing of one APK artifact

Status: the finite version 5 protected APK flow passed in a fresh Android guest. A captured
project APK was approved, signed with the imported protected test key, verified, exported,
installed and executed under an ordinary application UID. This is not personal installation
provisioning or a system component signing service.

The vehicle has 513 host checks, public SDK compilation and inspected APK builds. Twenty
seven supplied observer controls precede the runtime. Ownership and provider loader
corrections were checked before runtime qualification. No network key service or personal
key provisioning is implied.

The [disposable credential signing flow](2026-09-22-protected-signing-request.md) established
one approved signature, not a signed Android package transaction. This step joins the
cryptographic operation to an immutable artifact and its declared signing role.

## Source and host result

The pinned apksig library exposes `KeyConfig.Kms` and `KmsSignerEngineProvider`. Despite
the name, this is a local extension interface. The default library excludes the separate
cloud provider implementations. A captive provider can supply a signing callback without
exporting a private key into apksig or adding a network service.

The default JCA engine creates and initializes its own Signature object. Passing it an
AndroidKeyStore PrivateKey alone would not reuse the already approved CryptoObject.
The callback route instead receives the data and algorithm at the signing boundary.
The factory passes the algorithm and parameters despite a stale comment saying otherwise.
Apksig verifies the returned signature against the configured certificate before accepting it.

The host probe used a new disposable key and a copy of one project owned fixture APK.
It captured its own input bytes, then changed the caller's original array. Signing used one
SHA256withRSA callback over 837 bytes for the explicitly selected v2 only, SDK 37 case.
The complete result verified with the exact expected certificate. Independent inspection
confirmed the package identity and unchanged nonsignature ZIP entry contents.

Backend refusal, an incorrect signature and a wrong operation alias each failed without
publishing an APK. Apksig had already produced 8192 local output bytes in each failure.
Those bytes were not a completed signed artifact. The wrapper retained them only in its
bounded local buffer and never published them as a result.

These are host callback and artifact observations. The software test key, thread context
and successful APK verification establish neither Android authentication nor protected
custody. The single signing scheme is a proof boundary, not a product compatibility policy.
It does not qualify persistent system APK updates, v4 sidecars or signing lineages.

## Artifact request bookkeeping

The plain Java artifact request captures and hashes its own bounded input copy. It retains
separate outer worker ownership and the exact inner signing request. Cancellation records
intent without pretending that a queued or running worker has retired. Published output
cannot be undone, and a cancelled completion withholds output while retaining the worker
ticket until explicit retirement.

Independent tests checked the model before integration. Four hundred race rounds cover
attachment versus cancellation and completion versus
cancellation. A lock ordering control also checks that waiting for child metadata does not
hold the artifact monitor. These tests establish bookkeeping only. Package metadata,
authentication, APK verification and actual executor retirement remain caller obligations.

## Candidate artifact broker

The candidate now couples the outer request to the captive apksig callback. The callback
attaches an exact inner Signature request and waits for its real operation retirement on a
separate artifact worker. The UI shows the captured APK identity and signing scope. The
key executor is separate, so waiting for approval cannot occupy the executor needed to
produce the signature.

Caller retained artifact identities include the volatile broker epoch. An identical retry
returns the retained object; changed input or signing context is refused. The key cannot be
retired while artifact work remains owned. Internal artifact signatures are withheld from
the raw signature response API, and only a completely verified APK can be exported.

The host integration uses a software stand in, not Android credentials. It verified a real
APK and exercised decline, cancellation during signing, cancellation after signature
production, changed metadata, duplicate submission, contractual executor rejection and an
executor that accepted work before throwing. The latter retained ownership until the actual
queued worker retired. Arbitrary executor failure is not a nonacceptance receipt.

A metadata review found a possible child monitor dependency under the coordinator lock.
A controlled reintroduction blocked the observer. The corrected lookup and atomic metadata
snapshot passed a separate 200 round control with explicit JSON and signer test shapes.
These are host lock and bookkeeping tests, not Android serialization or authorization proof.
Artifact inspection checked the ordinary development signer, absence of a shared UID or
debuggable flag, and the broker's normal biometric permission. The captive provider's service
descriptor and class are present in the broker APK; cloud provider classes are absent. Those
build and inspection results are separate from the actual installed execution below.

A later ownership review found that the adapter could retire its ticket before the
coordinator recorded final failure metadata. An executor could also finish a worker before
its submitting call returned. A controlled premature retirement case failed the new check.
The coordinator now owns both sides of that handoff. It retires only after worker completion,
final metadata and the executor submission outcome have settled. The signing adapter runs
inside an already claimed ticket and cannot retire that outer owner itself. Duplicate worker
callbacks do not mutate a retained result.

The host integration also exercised an executor which finished a valid artifact and then
threw to its submitter. Ownership remained held through that interval, and the completed
result survived the failed submission receipt. This is a host ownership result, not durable
recovery after broker loss.

Provider selection is also explicit. Apksig uses the thread context class loader through
ServiceLoader. A controlled host worker with no ambient provider failed at that lookup.
Selecting the captive application loader passed, and the caller's previous loader was
restored. The adapter now clears its callback context and restores the loader before
publishing a verified APK. This does not claim that a particular Android worker was observed
with the wrong loader; it removes that ambient dependency before the guest test.

## Artifact request contract

Use an ordinary disposable APK and the already qualified protected test identity mechanism.
Do not replace SystemUI, rekey an installed product or resign third party applications.

The broker must own a complete immutable input before approval. Its request must identify:

- The input APK bytes and hash, package, version and intended operation.
- The exact signing certificate and key role.
- The selected signing schemes and compatibility scope.
- The output publication and cancellation context.

The provider is selected by trusted broker code, never by APK content or an ambient plugin
configuration. A callback belongs to that concrete artifact operation. Its byte array is
captured before asynchronous approval or signing. An alias or worker thread is internal
routing, not user authorization.

The trusted UI must show the artifact context, not present an unexplained digest as though
it were permission to sign any data. The real Signature operation must be initialized before
credential authentication, and its exact CryptoObject must remain bound through completion.
Unexpected algorithms, parameters or extra signing calls must fail closed in this finite
vehicle. A real multi signature transaction needs an explicit complete approval context,
not several unrelated grants or an ambient UID cache.

## Ownership and publication

An artifact job exists before its cryptographic callback is ready. Cancellation and key
retirement must therefore account for parsing, callback preparation, pending approval,
accepted signing, output verification and publication as separate stages.

A generated signature is not yet a completed APK. Cancelling after a signature was produced
cannot claim that it never existed. It may still withhold publication of an unfinished
artifact while retaining worker and cleanup ownership until the operation actually retires.

No signed artifact is exposed until full generation and expected certificate verification
succeed. An early ZIP prefix or a callback success is not that boundary. Durable publication,
interruption recovery, a v4 pair, installed signer compatibility and activation remain
separate controls. Ordinary signing authority does not by itself grant installation or
platform privileges.

## Qualified finite runtime

The host creator exited before independent recovery of a new disposable key from the
portable encrypted backup. The trusted public role record named the project fixture APK.
Its exact certificate and public key matched the AndroidKeyStore import. Unauthenticated
signing and foreign APK access were refused, with the foreign APK's own key use as a positive.

Four captured artifact requests exercised the lifecycle:

- Decline published no APK and retained worker ownership through cancellation cleanup.
- One explicitly approved request completed after normal device credential authentication.
  Its raw inner signature remained withheld. Only the fully verified APK was exported.
- A new pending request did not borrow authority when the completed view was reopened.
  Cancellation during its authentication retired both worker and crypto operation without
  exporting an APK or making another approved signing call.
- Broker replacement refused the old pending artifact identity. The expected key was
  reconciled independently in the new epoch, not adopted from an old request.

Three invalid purpose, certificate or input commitment controls before each request left
retained requests unchanged. Retrying the completed request with its same identity returned
its retained output without another signing call. Changing that request's key context was
refused. A fresh unauthenticated operation was also refused after the successful signing.

Android installed the exported APK as a new ordinary package. Its instrumentation executed
and reported the expected PackageManager signing certificate. A separate host verification
confirmed v2 signatures at SDK 37, the exact certificate and public key, and unchanged
nonsignature ZIP contents. A modified code entry was refused by the v2 content digest check.
This independent host verification happened after the guest run; the broker and Android
installer performed their own checks before publication and installation respectively.

The exact test key was deleted and all three APK removals succeeded. The boot and system
server remained stable. All guest and capture processes stopped, volatile RAM was gone,
and frozen inputs matched. The packet capture was explicitly filtered. Its expected private
ADB exclusions held. Captured adbd logs contained constant private input service commands,
not individual credential digit commands or detailed input dispatch records. No logging
property was changed. These are scoped checks, not universal secrecy or physical erasure.

Two observation limits remain visible. The credential guard initially refused a clipped key
subtitle before reading or typing the PIN. Normal header scrolling exposed the application,
title and key together, and a fresh observation of the same operation passed. No active
input or policy was patched. The first host tamper assessor looked only at top level errors;
a separate aggregate issue assessment observed the nested v2 digest refusal. Neither record
was silently rewritten or used to replay signing work.

## Remaining gates

This result covers one project owned ordinary APK, one v2 signing operation and SDK 37,
through a user0 lab entry point. It does not qualify persistent system APK replacement,
v3 signing, v4 sidecar publication, signing lineages or installation trust personalization.
Runtime cancellation after the signer has claimed an operation, interruption during accepted signing,
durable publication, recovery enrollment, multiuser authority and hardware custody still
need separate controls. Host bookkeeping tests are not substitutes for those runtime cases.

No universal private key, new platform signing permission or permanent authentication
session policy is selected by this vehicle. The next work joins complete component signing
formats and installation trust roles to recoverable transactions without weakening the
existing activation and compatibility boundaries. A separate
[authorization scope decision](2026-09-23-signing-authorization-scope.md) accepts transaction
level approval while leaving the mechanism for multiple cryptographic operations open.
