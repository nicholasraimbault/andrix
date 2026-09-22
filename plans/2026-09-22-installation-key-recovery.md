# Installation signing identity and recovery

Status: proposed default awaiting an owner decision. No personal installation keys have
been generated or provisioned. This is a decision under the accepted
[authority and signing contract](2026-09-21-owner-authority.md), not a request for permission
to run another laboratory test.

## Decision needed

Should the recommended personal installation support recovering the same signing identity
from an owner held encrypted backup, or deliberately bind that identity to one device
without a recoverable private key copy?

**Recommendation: require a portable encrypted recovery bundle by default**, with a
separately protected signing copy on the device. A device bound mode could remain a later
advanced choice. The backup would contain high authority key material, never a universal
project private key and never plaintext material silently placed in an ordinary home.

This decides the recovery requirement before implementing the personal key provisioner and
backup format. It does not decide every UI, encryption parameter or hardware backend.

## The alternatives

### Portable identity with an owner held encrypted backup

The owner can restore the same signing authority after reinstalling, losing a device or
moving an installation identity. A protected device copy can still use supported hardware
for signing; portability does not require ordinary programs to read the private material.
The portable copy must be created and protected as part of provisioning rather than
assuming it can later be exported from a hardware key store.

The cost is a valuable recovery object outside the original hardware boundary. Its
confidentiality and integrity, recovery authentication and loss handling become part of
the design. Losing every usable device copy and the backup or recovery secret still loses
that authority. No Andrix service should be needed to approve recovery.

### Device bound identity without an exportable copy

A supported hardware backend can create and retain a private key without offering an
export API. This reduces the need to keep a portable copy of that material. It does not
itself define backup or recovery.

Losing the hardware can mean losing the signing identity. Recovery then needs a previously
authorized alternative identity, a planned rotation/migration mechanism, or a new
installation. Compatibility with existing package signatures and shared UIDs cannot be
assumed after changing keys. A recovery route that depends on the lost key is not recovery.

## Important distinctions

The recovery contract covers a set of installation authorities, not an indiscriminate
single key for everything:

- APK and platform signer identities, including shared UID and privileged permission
  relationships.
- APEX payload verification and APK container signatures.
- OTA verification and boot verification relationships.
- Ordinary third party and owner application developer keys, which must not silently
  receive platform authority or be replaced by the installation key set.

A portable signing identity is not a backup of CE storage keys, authentication state,
hardware bound application secrets or user data. It does not establish migration without
data loss. Signing provenance, installation authorization and boot trust remain distinct.

The pinned Android Keystore provider's key wrapper returns `null` from `getFormat` and
`getEncoded`, explicitly declining to export key material. Its private key entry path also
supports importing PKCS#8 material. That permits a design with an independently protected
backup and an imported device copy; it does not imply export of a hardware generated key.
Hardware support and assurance still require separate qualification. Cuttlefish does not
establish those hardware properties.

## Work that can proceed independently

Component source/artifact manifests, compatibility checks, operation ownership, staged
session observation and explicit interruption/recovery transactions can use an opaque
signing identity without deciding its custody. The completed development key proofs
remain useful, but do not choose this personal installation policy.

The choice becomes necessary for the next implementation step that creates long lived
personal installation identities and determines what a recovery bundle can restore.
Default recoverability should not be decided accidentally by whichever key generation API
is easiest to call first.
