# Package Manager native principal reservations

Status: internal implementation and host checks, not native account activation. The
[slot storage component](../../plans/2026-09-25-native-identity-store.md) compiled in the real
Android `services.core` module at `3ee50f3`. Its subsequent
[PMS consumer integration](../../plans/2026-09-26-native-store-pms-consumer.md) has separate
verification status. No Binder endpoint, manifest declaration, signer or ordinary installation
can designate a native account. The first adapter supports user 0 and ordinary internal packages.

This extends Package Manager's UID lifetime machinery. It does not allocate another UID space,
maintain fictional installed state, store permission grants or appoint an APK as a login. It is
one prerequisite for the [ordinary principal launch path](../principal-entry.md).

## Selection and durable prior identity

`NativePrincipalManager` is an internal system_server API. A trusted account authority validates
owner designation before calling it. `select` captures the exact installed object, actual app ID,
user serial, version and immutable current signer set. Selection grants nothing and reserves no UID.

`prepare` rechecks that selection under the package mutation locks. A replaced package object or
changed signer/version/user cannot inherit it merely by using the same numbers. A retired selection
cannot create a new account. A restored binding must also match the **stored prior signer set and
lineage**, not just today's APK. Missing prior identity does not get filled from a current selection.

The initial subject excludes shared UID, archive, instant, system, updated system, APEX, external,
SDK and static library roles. These are bounded adapter gates, not permanent native account policy.
Other Android users need the real UserManager deletion/reuse barrier before admission.

## Handles and phases

`NativePrincipalPins` holds exact owned handles:

| State or step | Meaning |
| --- | --- |
| PENDING | The app ID is held immediately. Persistence and current identity still need confirmation. |
| ACTIVE | The reservation is durably confirmed and the installed subject revalidated. This is not CE, execution or foreground authority. |
| RETIRING | New activation is closed irreversibly in memory. Its durable marker must be confirmed before destructive retirement proceeds. |
| Final omission | Only after actual producer/work/API/key/data retirement and owner disposition may this exact binding be omitted. Other accounts remain held. |
| RETIRED | Only after checked store release may the memory pin finish. Its old handle cannot target a replacement. |

Lost writes or replies keep the original handle and obligations. No GC, death, timeout or label
releases a reservation. Restored records are PENDING or RETIRING, never ACTIVE.

Counter availability is distinct from binding availability. Independently verified existing
records can be restored without a usable issuance counter. Existing handles can still be found,
confirmed or retired through exact slot operations; new issuance and whole counter snapshots
refuse. Nothing reconstructs the counter from the largest surviving ID. One registry instance
holds one lineage, and counter repair cannot silently retarget existing handles.

## Separate store and actual allocator

`NativeIdentityRecords` and `NativeIdentityStore` implement the private slot/header format and
checked persistence protocol. Numeric slot names and the index retain negative app ID occupancy
when rich metadata is damaged. They are not positive owner identity. A good slot retains package,
signer, user, incarnation and retirement metadata for verification against the real platform.

`NativeIdentityPersistence` performs exact reserve/publish/retire/release transactions. Header
reservation includes all pending identities before advancing the counter, so commit in a different order
does not strand an earlier prepared identity. A creation not yet published already retiring in
memory still needs its own durable hold and marker, not omission from reservation bookkeeping.

The real PMS allocator skips the union of every store footprint and every memory pin, in holes
and appended slots. An unavailable or reduced later read cannot forget a previous hold. Explicit
registration/replacement fences remain; a held empty slot is not an ordinary duplicate setting.
The store supplies no automatic fresh UID reassignment or installed PackageSetting.

The old embedded `packages.xml` implementation was module qualified at `5284ca9`. The new consumer
removes that native section and its global write/read coupling. The legacy codec remains as a
historical host component, not a second active store.

## Persistence and lock discipline

The store reader never calls the resilient reader's destructive fallback. A preferred backup
cannot be skipped merely because it is unreadable. Different valid copies are a conflict.

Before rewriting, a checked seed preserves the chosen valid base. This prevents a corrupt main
from becoming the preferred backup while the only intact reserve is deleted. First publication
also uses a complete checked seed. Actual writing descriptors, atomic namespace changes and
required directory syncs establish the acknowledgements. Readback is supplemental, not a
substitute for the writer's result. Cross file prerequisites use checked confirmations too.

Runtime I/O runs under the install lock but outside the PMS state lock and all work control lanes.
Inputs are captured first and platform facts revalidated afterward. The boot store read precedes
the constructor's package lock block; holds are applied after ordinary settings load and before
scan allocation.

## Recovery does not mean deletion or execution

`NativePrincipalRecovery` is an immutable negative view for scan, storage, preparation and key
cleanup threads. It retains names and actual code paths without asserting installation or granting
anything. App directory ownership is used only to withhold deletion or ownership change.

Recovery refusal must preserve APK files, CE/DE data, metadata and UID keyed resources. It must also
prevent foreign or mismatched code from running at the held ID. Guarding only APK deletion, or only
keystore clearing, is insufficient. The consumer plan records the affected cleanup and admission
paths and remaining qualification gates.

A missing installed mapping is currently quarantined. Restoring its exact old UID requires a
separate verified ownership operation with an unambiguous captured candidate. A current APK,
directory owner or guessed allocator floor cannot supply that proof.

CREATING is not permanent proof that nothing was exposed: an intact binding might have been
rebound while the header was damaged. No generic CREATING cleanup or key clear on enable exists.
Retained UID dependent data or keys keep the reservation.

## Verification boundary

Host tests run actual Java records, storage, transactions and manager logic with explicit Android
and PMS facades. They cover strict codec negatives, actual file operations, unknown write outcomes,
retirement order, prior signer continuity, unknown counters, immutable recovery views and allocator
holds. They do not establish Android boot, filesystem power loss, permissions or lifecycle behavior.

The digest guarded adaptation and profile are in
[`native-principal-pins.patch`](../../patches/grapheneos-2026081300/native-principal-pins.patch).
The guard accepts only exact pinned source and reviewed candidate bytes, together with the existing
CE and Package Installer companions. The actual `AppIdSettingMap` and `ResilientAtomicFile` sources
remain guarded host fixtures, not parallel rewrites.

Owner designation, factory specialization, live user/CE authority, home provenance, UID policy,
resource participation, API binding and presentation still have to be connected and qualified.
General owner administration remains possible, but changing these assumptions changes the guarantees.
