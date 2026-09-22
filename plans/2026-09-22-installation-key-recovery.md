# Installation signing identity and recovery

Status: accepted default on 2026-09-22 under the
[authority and signing contract](2026-09-21-owner-authority.md). Provisioning remains to be
implemented. No personal installation keys have been generated or provisioned.

## Accepted decision

**The recommended personal installation provides a portable encrypted recovery bundle
under the owner's control, with a separately protected signing copy on the device.**
Recovery of the same installation signing identity must not depend on the original device
remaining usable or on approval from Andrix or a vendor service.

Daily programs do not receive platform signing material or authority merely because they
run in an owner's account. Signing and deployment require deliberate administrative
authorization. The recovery bundle contains high authority material, never a universal
project private key and never plaintext material silently placed in an ordinary home.

This is the recommended recovery policy, not a prohibition on an owner choosing a device
bound mode later. It selects the recovery requirement before the personal key provisioner
and backup format. UI details, encryption parameters, hardware backends and recovery
verification remain engineering work rather than capabilities inferred from this decision.

## Rationale

The owner should retain practical authority to maintain the system after hardware loss or
reinstallation. Preserving signing identity also avoids making every recovery depend on
unqualified key rotation across Android's different package and boot trust relationships.
The cost is a valuable backup outside the original hardware boundary, whose protection and
loss behavior must be designed and tested explicitly.

This combines established ownership patterns rather than requiring a new cryptographic
primitive: owner controlled boot and package trust, protected routine use and independent
recovery. The Android implementation must still respect its actual identity and authority
relationships.

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

## Next implementation gates

Component source/artifact manifests, compatibility checks, operation ownership, staged
session observation and explicit interruption/recovery transactions can use an opaque
signing identity. The completed development key proofs remain separate from personal key
custody qualification.

The first [identity and recovery vehicle](2026-09-22-signing-identity-recovery-proof.md)
observes selected artifact identities and tests independent host recovery with age, OpenSSL
and the pinned AVB encoder. A public manifest commitment binds exact identities and signing
uses; decryption alone does not establish which installation the owner intended to recover.
The host result is not protected device custody or a complete installation trust inventory.

Complete the relevant trust inventory and qualify device import, protected signing and
durable provisioning against the accepted requirements. Do not invent cryptography or
assume hardware generated keys can be exported later.

Use disposable development identities to test provisioning, independent recovery to the
same public identities, wrong credentials, corrupt or incomplete bundles, interrupted
writes and refused ordinary callers. Recovery tests must not depend on retaining the
original signer process or device storage. Personal keys, credentials and raw recovery
material must never enter source control or public evidence.

Successful recovery of private material does not authorize installation or activation.
Initial personalization and any later key migration still need their own compatibility,
interruption and recovery checks. No live rekeying or user data recovery is qualified by
accepting this default.
