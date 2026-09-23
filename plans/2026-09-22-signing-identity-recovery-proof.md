# Public signing identities and independent recovery

Status: artifact inventory, a finite host recovery vehicle and ordinary Android age
interoperability pass. No personal installation has been provisioned and no protected
Android signer is qualified.

This implements the first bounded controls under the
[accepted portable recovery default](2026-09-22-installation-key-recovery.md).

## Observe identities before assigning authority

The selected image was inspected without reading existing private keys. A small Java probe
uses the pinned apksig verifier at SDK 37 and returns the actual signer certificates and
SubjectPublicKeyInfo encodings. It does not treat a valid signature as proof that the owner
controls that signer. Manifest and MAC policy observations are declarations, not a complete
runtime permission or credential result.

The inventory found 147 APKs and 94 APEX containers outside APEX payloads, with 56 distinct
container/APK certificate identities and 43 declared APEX payload key identities. Sixty of
those artifacts use the platform certificate, including SystemUI. The same certificate
also appears in the platform MAC selector. The inspected `/usr` APEX has separate container
and payload identities. The OTA certificate and four vbmeta signing key observations are
recorded separately.

The first root vbmeta check verified its signature but refused to continue without chain
expectations. That failed command remains recorded. A separate check followed the chained
images and verified their signatures, parent key bindings and image hashes/trees. This is
image consistency, not proof of the firmware's trusted key or hardware rollback state.

The inventory does not yet include APKs inside APEX payloads, complete signer rotation
lineages or actual device key ownership. It is not a complete personalization or rekeying
plan. In particular, do not replace every observed third party identity indiscriminately.

## Recovery vehicle

`scripts/proof/signing_recovery.py` uses maintained implementations rather than a new
cryptographic construction:

- age v1.3.2 supplies the encrypted file container and complete payload authentication.
- OpenSSL checks private keys and derives public keys and certificate associations.
- The pinned avbtool derives the AVB public representation.
- A versioned public manifest binds installation identity, generation, exact public
  representations and named signing uses to key slots.

The age implementation was built from pinned source using the existing compiler, a local
module proxy and upstream dependency checksums. Its upstream tests passed. This was not
an independent sum database check or a claim of equivalence to the upstream release binary.
Native recovery credentials are supported by the vehicle, not arbitrary plugins or SSH
identities. The real controls used the native hybrid recipient. Credential presentation
and the final supported recovery format still need product integration.

### Decryption is not sender authentication

Anyone who knows a recipient's public key can encrypt a new file to it. Successful age
decryption therefore does not prove that the file contains the installation the owner
intended to recover.

The caller must supply an **independently trusted public manifest commitment**. Taking that
commitment from the untrusted backup or an equally replaceable sibling file would not
establish authority. A recovery kit must preserve this binding alongside the owner's
recovery information. This is distinct from selecting a convenient file name or key alias.

The manifest keeps X.509 certificate identity, SubjectPublicKeyInfo and AVB public key
encoding distinct. Even the same private key with a newly generated certificate is not
necessarily the same Android signer identity. Exact certificate bytes matter.

After complete decryption, the vehicle requires the expected manifest, an exact private
key set, valid private keys, matching public keys, matching certificates and matching AVB
representations. Every declared signing use must refer to the appropriate public encoding
of its selected key. No material is returned before the entire set passes.

### Streaming and publication

Authenticated file encryption can emit valid early plaintext chunks and later reject a
bad final chunk. The raw age control actually returned 196,608 plaintext bytes before
reporting the damaged end. Those bytes were neither published nor saved in the evidence.
The recovery vehicle waits for complete successful decryption before parsing any output.

This vehicle returns checked material to its caller. It does not implement durable atomic
provisioning, import into a device key store or installation activation. A partial transferred
backup is refused; that is not a crash consistency proof for a future provisioner.

## Why not use the pinned PKCS#12 API as the entire bundle?

The reviewed BoringSSL API accepts one private key, certificates and optional chain
certificates. It rejects a second private key, does not represent Android signing purposes,
and does not prove that an expected installation key set is complete. Friendly names and
password verification do not replace that binding. Its compatibility defaults and accepted
legacy encodings also need explicit policy rather than accidental inheritance.

This is a limitation of the inspected API, not a claim that the PKCS#12 standard universally
permits only one private key. PKCS#8 remains useful as the individual private key encoding.
Parsing need not happen off the device; AndroidKeyStore's inability to deserialize a backup
stream does not prohibit a separate protected parser and import path.

## Observed controls

A disposable provisioner created five keys with six named uses and exited. A separate
process recovered them using only the encrypted bundle, native recovery credential and
public owner record. All five recovered keys signed a challenge which verified with the
expected public keys.

Seventeen real negative controls were refused: wrong recovery identity or public
commitment, truncation, partial transfer, corrupt final authentication, trailing data,
missing/extra/substituted/invalid private keys, changed purpose or generation, unsupported
container version, a replacement certificate around the same key, inconsistent certificate
or AVB public records, and an authenticated prefix with an invalid end.

The generated recovery credential was retired after the two processes had exited. Existing
project keys were not accessed. No plaintext installation private keys or raw decrypted
payloads were saved in the evidence. Process exit and logical file removal do not prove
physical erasure. Python memory in this host vehicle is not a protected secret heap.

The full host suite passed 494 checks, including 18 supplied identity/manifest controls.
Two initial model fixture errors were retained and corrected. Supplied records, artifact
verification, real encryption/signing tests and future Android runtime tests remain separate.

## Ordinary Android execution

The same age source compiled as Android ARM64 PIE executables using the Android linker.
A fresh guest ran age and age-keygen through the existing ordinary owner work service.
There was no policy change, package installation or reboot in this control.

A checked ordinary owner profile compiled a bounded input receiver. An exact private ADB
reverse mapping and host loopback listener delivered only the frozen public tool archive;
its hash was checked before extraction. The mapping and server thread were then retired.
Seven supplied observer checks and five real Linux transfer controls preceded this run.

Eight actual tool jobs completed. Disposable native hybrid identities enabled encryption
on Android and decryption on the host, then encryption on the host and decryption on
Android. The 168 byte test payload included NUL and other binary bytes. Wrong recipient
and corrupt ciphertext controls exited with their intended cryptographic errors, while the
prior successful plaintext hash remained unchanged. The disposable device credential was
logically removed, all opened caller and work service environments retired, and the final
owned hierarchy was empty.
No private credential or raw key payload was recorded. The host equality check was recorded
without retaining its private decryption identity for a later repeat of that operation.

Two limits are explicit:

- Log review found 90 directory search denials across the compiler, linker, profile,
  receiver and age executables. Matching denials are present in the earlier package
  regression. The source contains matching test directory probes during linker
  configuration selection; no syscall stack was captured. The first assessment's broad
  zero denial assertion failed and is retained. A separate scoped assessment records the
  denials while qualifying the successful crypto controls. No permission was added or log
  suppressed. This is not a denial free runtime result.
- The initial copy stage recorded requested resource limits but missed actual cgroup
  readback before its unit disappeared. A separate complete staged input verification ran
  under measured limits before launch. This does not invent the missing historical
  measurement. Runtime resource readback and closure were captured separately.

The result establishes ordinary native interoperability, not AndroidKeyStore import,
protected private material, trusted signing approval or durable provisioning. Those are
still distinct gates.

## Remaining gates

- Complete the relevant installation trust inventory, including selected nested APKs and
  key rotation relationships, before personalizing a whole installation.
- Verify device import, signing algorithms and public identity preservation through the
  [protected request vehicle](2026-09-22-protected-signing-request.md). Prove ordinary callers
  cannot borrow signing authority.
- Bind authorization to the exact operation and artifacts, separately from cryptographic
  key recovery. Define complete administrative context and lifetime behavior.
- Design durable provisioning and recovery publication, cancellation and interrupted write
  handling before treating this codec as an installer.
- Qualify device custody and hardware claims independently. These host results do not
  establish physical tamper resistance, user data recovery or safe live rekeying.
