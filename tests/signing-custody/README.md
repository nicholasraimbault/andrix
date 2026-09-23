# Disposable Android signing custody vehicle

Implementation in progress. See the
[request and qualification plan](../../plans/2026-09-22-protected-signing-request.md).
This is not a personal key provisioner, general root service or installer.

`AndrixSigningCustodyProof` and `AndrixSigningCustodyNegative` are ordinary lab APKs. They
have separate application UIDs and no shared UID. Neither is included in PRODUCT_PACKAGES.
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

Private key bytes must not appear in test arguments, logs, source assets or public evidence.
The import frame uses an eight byte `ANDRK001` magic, big endian uint32 version 1, private
PKCS#8 length and certificate DER length, then those exact byte strings. Extra/truncated data
and changed public commitments are refused. This is a local test transport, not a replacement
for the portable encrypted recovery format.

Host state checks run through `scripts/proof/tests/test_signing_custody.py`. Compiling against
public Android SDK classes is not a device result. A device trial must separately establish
specific preauthentication refusal, actual fresh credential approval, successful signing,
foreign caller denials, cancellation/replay behavior and cleanup. Hardware properties,
genuine CE withdrawal, production administrator enrollment and durable provisioning remain
outside this initial vehicle.
