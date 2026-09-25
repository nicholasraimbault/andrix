# Native identity slot storage component

Status: implemented storage/record component with host checks and an actual Android module build.
It is not yet the PMS consumer,
allocator recovery integration or native account activation. The existing adapted manager still
uses `packages.xml` until its migration is connected and qualified. This is implementation of the
[recovery boundary](2026-09-25-native-recovery-boundary.md), not a second UID allocator or grant
store.

## Ownership and records

`NativeIdentityRecords` defines immutable bounded values and a private canonical binary format:

- A header carries a lineage, the issued principal ID counter and a small slot index.
- A slot carries its app ID, package, stored signer set, generation and user/incarnation/retirement
  records. An empty slot body is a tombstone, not a free UID.
- A checksum detects damage but does not authenticate a writer. Filesystem ownership and platform
  policy must protect the store before it is used.

The codec uses fixed width integers, explicit version/type/length, strict ordering and bounds.
It rejects noncanonical data rather than sorting malformed wire input. Its IDs are the separately
defined positive signed PMS principal identifiers, not native work IDs. The latter keep their
full nonzero unsigned 64 bit range. Format bounds are not permanent product quotas.

`NativeIdentityStore` owns the storage protocol. Stable `slots/<appId>` names survive rewriting
the rich body. The header index also retains IDs whose entire slot directory is unavailable.
Every decodable header copy and every valid slot name may contribute a **negative** hold. They
are never unioned into positive identity or permission.

## Read and write rules

The custom reader never invokes the ordinary resilient reader's destructive fallback. A present
backup has precedence. A damaged backup does not fall through to a possibly unconfirmed omission.
Without a backup, an intact main or reserve can supply metadata; two different valid copies are
a conflict. Reads never delete or repair files.

Before writing, the store preserves its chosen valid base with a checked seed writing descriptor,
atomic rename to the preferred backup and directory sync. This matters when the chosen base came
from reserve: blindly starting the ordinary writer could rename a corrupt main to backup and
then delete the only good reserve.

The strict canonical writer checks the actual main and reserve writing descriptors, removes the
backup only afterward, and syncs the directory. Readback supplements those acknowledgements; it
does not replace them. Cross-file preconditions are confirmed through checked rewrites of the
exact bytes, or directory sync for namespace changes, not by syncing reopened reading descriptors.

A first record is published as a complete checked preferred backup before the canonical writer
runs. Interruption yields no published record or complete pending metadata, not a torn preferred
record. A fresh store is built as a complete empty sibling and renamed without replacement to its
canonical name. Failed unpublished initialization names remain visible as maintenance references;
no directory name is authority to adopt or delete it.

## Bounded recovery and retirement

Discovery records all numeric slot holds before decoding bodies. Incomplete enumeration disables
positive eligibility. Cross-record checks compare location, known lineages, known counters,
creation proofs, package/incarnation uniqueness and the current user 0 adapter bound.

A bad header blocks new issuance and final release bookkeeping. It does not by itself discard an
intact existing binding. Such a binding still requires full consistency with every known source,
fresh designation rebinding, actual PMS signer/UID verification and the authoritative user serial.
No counter is rebuilt from the largest surviving ID. Restored bindings are pending or retiring,
never active from disk alone.

Existing slot mutations can confirm metadata, mark retirement or omit an already retiring entry
without creating another identity. They cannot change signers or binding fields, clear retirement,
add a user without an issuance proof, or resurrect a tombstone. While any known header lists a
slot as CREATING, omission is refused: complete its bookkeeping to LIVE before creating a tombstone.

Final deletion requires a confirmed RELEASING transaction. The enclosing account authority must
first own complete producer/work/API/key/data retirement and the owner's disposition decision.
Removing the directory and removing the index entry are separate checked steps. Unknown outcomes
retain the original operation and holds.

**CREATING is not permanent proof that nothing was exposed.** A good slot may have been rebound
while its header was damaged. A later missing record, empty directory or inode therefore cannot
justify automatic cleanup. Cancellation needs an actual owned never-exposed creation operation,
or full retirement authority. That consumer is not supplied by this component.

## Verification

Actual Java tests cover immutable values, golden encodings, checksum and parser negatives,
truncation, duplicate/order/range checks and 40,000 deterministic resealed mutations. Accepted
mutations must encode back to exactly the same bytes.

The actual store runs on host files with the guarded framework `ResilientAtomicFile` source and
Android API facades. Checks cover negative holds, damaged and conflicting copies, lost directories,
first-write interruption, incomplete initialization, header-only damage, retirement monotonicity,
released-ID addition refusal, namespace aliases, foreign files and separate index omission.
These are not power-loss, Android ABX/fs-verity, SELinux, PMS or device lifecycle qualification.

The combined focused suite runs 21 checks, including the existing manager/allocator/strict writer
checks and unchanged CE, package verification and disabled native entry guards.

The actual Android `services.core` target built successfully from `3ee50f3`, with both helpers and
their nested classes in its final jar. The initial artifact collector looked for a javac output
instead of the final combined jar; that collection failure is retained separately from the
successful compile. The correct artifact was then captured and verified against that build's
source and time boundaries. The exact native adaptation was reverted afterward, preserving the
existing CE and Package Installer changes. No image, emulator or physical device ran this store.

## Next integration boundary

Before switching the PMS consumer:

- Keep counter availability separate from existing reservation lookup/rebinding.
- Load negative holds before scanning can allocate IDs.
- Restore an empty held allocator slot only through an exact verified ownership path.
- Preserve explicit registration/replacement fences and distinguish reserved from duplicate.
- Prevent both APK deletion and CE/DE purge or migration during native recovery refusal.
- Keep store I/O outside the PMS state lock and all work control lanes, then revalidate before
  activation or release.
- Enforce a private namespace, including initialization siblings, and qualify actual Android I/O.

No factory, public Binder endpoint, package designation shortcut, UID partition, key clearing or
work lifetime change is enabled by these classes.
