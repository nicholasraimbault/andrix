# APEX payloads and nested APK signing identities

Status: the selected image's 94 APEX payloads and 33 nested regular APKs were inspected
without private key access. Available signing lineages were observed through successful
SDK 37 verification. The host suite passes 520 checks. This is not a personalization plan
or proof that the owner possesses every observed key.

This extends the [initial public identity inventory](2026-09-22-signing-identity-recovery-proof.md)
before broader component signing and installation identity provisioning.

## Payload and container binding

Each APEX container still matches the frozen image and earlier verified certificate
observation. Its payload was extracted into bounded temporary storage. The pinned AVB
implementation verified the payload signature, filesystem hash tree and exact binary public
key against that container's `apex_pubkey` declaration. Zeroed hash trees were not accepted.
All 94 payload checks passed: 93 ext4 filesystems and one EROFS filesystem.

The public container signature and payload signature remain different identities and roles.
Matching the payload key to the signed container establishes this artifact relationship,
not firmware trust, rollback state, runtime activation or private key ownership.

A wrong expected payload key was specifically refused. Changing filesystem data preserved
the vbmeta signature but failed the hash tree check. The first pilot called the command line
wrapper class instead of the core verification API and failed before cryptographic checking.
That record remains separate from the corrected positive and negative controls.

## Nested APK and lineage observations

The expanded inventory contains:

- 147 APK files outside APEX payloads and 33 inside them, for 180 APK files.
- 94 independently signed APEX containers.
- 72 distinct certificate identities and 72 SubjectPublicKeyInfo identities across those
  APKs and containers. There remain 43 declared APEX payload key identities.
- 178 distinct APK package declarations. Two names occur in alternative product and vendor
  overlay files with matching signer identities. File counts are not active package counts.
- 63 artifacts using the platform certificate. Three were newly observed nested APKs:
  Device Lock Controller, On Device Personalization and Permission Controller.

Every nested APK verified at SDK 37. The probe also observed available combined and per
signer lineages, SDK targeting and lineage capability flags. No lineage or hybrid signer
record was exposed by these successful verifications. That does not prove the absence of
other platform selections, past installed signer history or identities embedded in other
container formats.

Signing scheme flags describe which scheme the verifier actually checked at the requested
SDK. They are not an inventory of every signing block present in the file. Certificate,
SPKI and AVB encoding hashes remain distinct. Shared UID declarations and lineage
capabilities do not themselves establish runtime credentials or permissions.

## Method and limits

The ext4 directory reader uses the observed pinned debugfs output. It distinguishes regular
files, directories, symlinks and other entries. Tool errors are not treated as empty
directories merely because the command exited zero. Unsupported names or malformed records
fail rather than becoming command syntax. Payload symlinks are not followed into the host.
The EROFS payload was extracted by the pinned filesystem tool into a private temporary tree.

The inventory retained nested public APKs, public identities and raw verification records.
Only new public temporary payload and extraction copies were removed after tool processes
exited. Canonical images, prior records and existing keys were preserved. Limits were read
back, no swap or core dumps were allowed, and scratch storage was bounded. Sampling is not
a filesystem quota or proof that all other writers ceased.

This observes the selected image and regular APK files inside its APEX filesystems. It does
not enumerate every possible executable container inside a virtual machine image, qualify
firmware keys, identify active APEX variants or establish historical installation state.
The inventory is evidence for assigning signing roles, not permission to resign every
observed third party artifact.

## Next gate

Use these explicit certificate, shared UID, MAC selector and payload relationships when
building the owner signing role map. Preserve independent developer identities unless a
particular owner controlled fork or replacement is deliberately selected. Complete component
signing formats, recovery publication and installed compatibility remain separate from
observing the current public identities.
