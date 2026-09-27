# Preserving a creation's prior binding

Status: unused codec extension and a conservative store gate, with host verification, a normal
Android image build and bounded disposable reader observations. No version 2 publication,
restored creation admission, cancellation or UID release is enabled.
This follows the [real writer qualification](2026-09-26-native-writer-qualification.md).

## The remaining gap

The version 1 CREATING header reserves an app ID and native principal ID with a package name.
Before the slot body exists, the prior user serial and signer set live only in the original
handle. Losing that process leaves a held, unavailable tail. The current APK cannot supply its
missing history. A separate native incarnation is already named by the store lineage and
principal ID, so this step does not invent another identity allocator or designation ID.

## Inactive representation

An explicit version 2 header can carry an immutable `CreationBinding`: user ID, user serial and
canonical signer certificate digests. Together with the existing app ID, creation ID and package,
this represents the fields needed for the future body. The header retains its declared wire
version, including in equality and compare and set checks. Only CREATING entries may carry the
binding. A tagged absent binding preserves a legacy incomplete entry without inventing fields.
It is not permission for a new writer to omit the prior binding.

Existing constructors still produce version 1. Version 1 header and slot bytes are unchanged,
including header only holds with no slot directory. Slots remain version 1. Both header versions
are decoded, but neither is implicitly upgraded or downgraded. The existing byte and collection
bounds remain. A richer header can exhaust its byte bound before its slot count, so future
admission must check the prospective encoding before issuing a native ID.

## The store must not use a codec it cannot yet interpret safely

Codec support alone would let the old storage protocol load version 2 and then rebuild it as
version 1, ignore the new binding, or erase a hold present only in an unselected copy. The store
therefore classifies any recognized version 2 header copy as UNSUPPORTED. Every decoded app ID
still contributes to the reservation union, including a header only hold. Binding eligibility,
new issuance and all applicable writer operations remain closed for that state. No reader deletes
or repairs these files.

Five isolated controls failed against the old store with the new codec: header relabeling,
released state confirmation, directory removal, initialization with a hidden newer hold, and
rewriting a selected version 1 header over an unselected version 2 hold. They passed with the
explicit refusal gate. Additional checks require unchanged file footprints and metadata through
mixed version reads and writes, including a missing slot directory tree.

The codec tests retain frozen complete version 1 records, canonical layouts, strict parsing,
immutability, version sensitive equality, mutation controls and exact maximum length boundaries.
The full gated host suites pass. A normal image then built from `e3ad881`, with the creation
binding codec present and the lab writer route absent from its actual services jar.

## Disposable reader observations

The normal image completed these controls on one fresh guest:

- A version 2 CREATING header retained A's UID even when there was no numeric slot directory
  and a preferred, valid version 1 backup contained no holds. PMS reported UNSUPPORTED,
  withheld counter and binding eligibility, and kept A's setting, code and canaries. The peer's
  original key and install-existing completion remained usable.
- A matching valid version 1 slot body beneath the version 2 header still supplied no memory pin
  or code admission. The future binding representation did not become authority by itself.
- Replacing only the controlled header metadata with version 1 restored healthy admission.
  Both original keys signed fresh host verified challenges, and the original canary identity,
  UID, user serial and signer matched. The existing body bytes and file identities were kept.

The fixture did not restore app data or a keystore database, rerun key initialization, enable
version 2 writing, or implement automatic format migration. All guest scopes were retired.
The image and input tree are separately sealed. Raw captures and operating paths remain private.

The image producer is `e3ad881` and fixture producer is `9de256a`. The services jar SHA-256 is
`1f6ad3910e75f410eda4c76c622670764dfbcf78b206bf8ea187e4c5754ff54e`.
Its image seal is
`18ef943803334fe069b6ea3d8631b73bfb8129b697ea7e6f0240ee07cbe8a5a9`.
The header only hold, valid body quarantine and version 1 restoration phase seals are
`0164d467da41796d235dead386d479ea23a9dffce354dc97114f707a9d3d545d`,
`01f2413234dbd26d5e23ebe91472abb19f20d721678c645db9b42d5b9abb8ea0` and
`a0e3b2a258628b160391e286962c48d7814b468f33c6fb894c80826dd1f4b347`.

## Before version 2 may be used

The future writer must preserve the complete original binding before advancing the counter,
match every field during publication, preserve the header version through every transition and
admit encoded size before ID issuance. Existing pending operations whose binding is unavailable
remain held; no current package value may fill that gap.

Older readers cannot decode version 2 header only holds. Publication therefore also needs a
supported reader and rollback contract, or another stable negative footprint visible to those
readers. The [newer frame preservation layer](2026-09-27-native-format-preservation.md) now has
bounded source and host checks across slot and staging copies. Its framing, readability and
rollback limits remain explicit. It is not general unknown version safety.

Metadata still grants no live authority. An account controller owns designation and operation
policy through a serialized interface, while PMS owns bindings, counters and holds. Separate hot
work and API journals do not imply a second native identity database.

Cancellation remains a different join. Even a creation with no native execution may have an
installed APK, UID addressed keys, data and producers. Dropping its native designation cannot
release the UID dependency. Real disposition and retirement evidence are still required; neither
CREATING nor an exposure flag substitutes for them.
