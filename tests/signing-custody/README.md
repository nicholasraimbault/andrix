# Disposable Android signing custody vehicle

The version 2 disposable Android import and approved signature flow is qualified in the
[request plan](../../plans/2026-09-22-protected-signing-request.md). The version 4
[APK artifact extension](../../plans/2026-09-23-protected-apk-artifact.md) is a candidate with
host and public SDK checks, not an Android artifact result yet. This is not a personal key
provisioner, product signing service, general root service or installer. The earlier version 3
artifact APK build was inspected but not used for a guest trial; retirement ordering was
corrected before that runtime gate.

`AndrixSigningCustodyProof`, `AndrixSigningCustodyNegative` and `AndrixArtifactPayload` are
ordinary lab APKs. They have separate application UIDs and no shared UID. None is included in PRODUCT_PACKAGES.
The only requested permission is the signing APK's normal USE_BIOMETRIC permission.

The proof provider checks the actual Binder shell UID, debug build and user0 before decoding
requests. It imports a single disposable key through a bounded pipe. Expected public
identities are supplied independently of that stream. The key is stored in this application's
AndroidKeyStore namespace with per operation device credential authentication.

`SigningRequest` is plain Java bookkeeping, not authentication. Payload and result arrays
are copied; approval and cancellation order is explicit. Its 400 concurrent host controls
are separate from Android credential or Keystore tests. The broker binds a real CryptoObject
callback to this exact immutable request and retains in flight operation ownership until
completion. It does not publish an ambient authorization flag for an entire UID.

The separate negative APK tests provider/import refusal and APP namespace isolation. It
also creates, uses and deletes its own disposable key with the same alias to demonstrate
that a name is not cross application key authority. No existing project or personal key
should be used as this test identity.

The artifact extension uses a captive local apksig provider, not a network KMS. It parses
metadata from an owned APK snapshot, binds the generated signing data to that exact artifact,
and withholds raw inner signatures from the public response API. A complete verified output
and a retired worker are required before APK export. Retrying the same retained artifact
identity cannot create another signing worker. The payload APK only reports ordinary
installed execution and its public signing identity.

Private key bytes must not appear in test arguments, logs, source assets or public evidence.
The import frame uses an eight byte `ANDRK001` magic, big endian uint32 version 1, private
PKCS#8 length and certificate DER length, then those exact byte strings. Extra/truncated data
and changed public commitments are refused. This is a local test transport, not a replacement
for the portable encrypted recovery format.

Host state checks run through `scripts/proof/tests/test_signing_custody.py`. Compilation is
not a device result. The qualified fresh guest separately established exact import identity,
specific unauthenticated refusal before and after a successful approved signature, foreign
caller denials, decline, cancellation during authentication, completed request replay refusal,
broker replacement and cleanup. Cancellation during claimed signing and accepted operation
loss still need runtime controls. Hardware properties, actual CE withdrawal, production
administrator enrollment and durable provisioning remain outside this vehicle.

Credential dependent key codes and touch coordinates must also stay out of command records.
The earlier private driver omitted its own log, but adbd independently recorded those
arguments. Those disposable PIN captures remain private and are corrected separately.
The qualified driver used constant service commands with private stdin and scoped raw log
checks. It did not disable logging to hide the problem.
