# Preserving newer native identity formats

Status: source implementation with independent review and bounded host checks. No new format
writer, identity admission, retirement authority or native execution is enabled.

## Why the older writer must refuse

A valid older copy must not hide an intact newer record. Previously, an unsupported version read
as generic damage. The selected older copy could then overwrite the newer main, reserve, backup
or staging seed. A confirmed RELEASING marker could also lead the old code to remove a newer slot
whose body it could not understand.

The codec now has private framing probes. They validate the existing size bound, magic, record
type, exact length and checksum before reporting a declared version. They do not interpret an
unknown body, invent an app ID or recover a counter. The public codec surface and version 1 bytes
remain unchanged. The checksum is still damage detection, not authentication.

Any recognized newer main, reserve or backup marks its record UNSUPPORTED, even beside a selected
older copy. Decodable siblings retain their negative holds. Their claims also remain negative
evidence against a colliding valid package or incarnation. A classification change cannot make
that collider newly eligible. A seed is never positive history; an intact newer seed only blocks
mutation and creation.

Every native store writer checks all known header and slot record locations before its first
effect. A recognized newer footprint makes the whole native store read only. Incomplete slot
namespace enumeration also refuses writes. Per record checks are repeated at the write or removal
boundary. This does not freeze unrelated Android package operations or introduce another allocator.

## What remains usable

Binding eligibility and writer availability are different facts. An unrelated intact version 1
body may remain eligible metadata while an unsupported slot or seed blocks all store mutation.
The manager still needs its exact designation, publication and lifecycle checks. A newer header
withdraws binding eligibility for the store. No restored metadata is an execution grant.

The availability cost is deliberate: the current writer cannot know how a newer protocol relates
its records. It refuses confirmation, retirement and release too, rather than overwriting unknown
state. A supported newer reader or owned repair must resolve that state. Torn or matching version 1
seeds retain the existing owned retry behavior.

## Host controls

The original store failed 159 of the 381 independently executed format controls. They included
actual loss of newer bytes, writes through a newer footprint, late refusal after a header rewrite,
and incorrect classification. The healthy and malformed checksum controls remained valid.
The initial candidate passed all 381 under a primary controlled resource scope.

Independent review found that taking a record out of the valid set could accidentally remove its
negative uniqueness evidence. The corrected source retains that evidence. Three additional checks
cover conflicting packages, conflicting principal IDs and an unrelated healthy binding. The final
matrix has 384 passing checks. The original candidate fails the two collision controls.

A separate real host permission control makes the slot namespace unlistable while a newer seed
exists in another slot. The original candidate wrote in that situation. The corrected gate refuses
before mutation. This check requires an unprivileged process; it does not count a privileged bypass
of directory permissions as coverage.

The full focused host suites also cover version 1 stores, persistence, manager admission and original
handle retries. A stale expected test count failed after the three controls were added; that failed
run remains separate from the corrected run. Worker results were rerun under actual 2 GiB memory,
2 CPU, zero swap and bounded task scopes. These are not Android or physical storage observations.

## Limits and future format rules

This is preservation of recognized frames, not universal future reader compatibility:

- Future records must retain the envelope magic and type, remain within the current byte bound,
  and change the semantic version when their meaning changes. Larger records are still damage.
- Every UID hold must remain decodable by a supported rollback reader or have a stable negative
  footprint that reader can recognize. An unknown header body cannot reveal its missing holds.
- Do not place unique state only in staging seeds or new file names the old protocol does not know.
- Version 1 only images do not acquire this protection retroactively. Each publication requires a
  supported reader and rollback contract.
- Read and stat errors still need a separate presence and absence audit. An unavailable path must
  not become an acknowledged absence. The new gate does not claim to solve every unreadable file.
- The diagnostic dump does not yet expose the new footprint flag directly.

Version 2 publication remains disabled until complete binding preservation, transition checks,
encoded size admission, supported readers and explicit recovery ownership are joined.
