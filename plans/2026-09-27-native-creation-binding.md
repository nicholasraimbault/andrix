# Complete original creation bindings and exact header admission

Status: inactive implementation with independent review, guarded host qualification and Android
compilation at `0018a1d`. The first run, fixture path failure and later negative evidence correction
remain separately recorded. Version 1 stays the only production format. Version 2 is constructed
only by host tests. No activation, repair, cancellation or release authority is added. This follows the
[header footprint correction](2026-09-27-native-header-footprint.md) and the
[creation binding codec](2026-09-26-native-creation-binding-codec.md).

## The gap

A version 1 CREATING entry keeps only the app ID, creation ID and package. Until the slot body is
published, the user, serial and signer set of the creation live only in the issuing handle. The
codec already had a version 2 entry that can carry them, but no writer could use it safely:
nothing preserved the original binding before the counter advanced, admission did not measure
bytes, and every header copy rule assumed one version.

## Creation plans

A reservation now takes a `CreationPlan`: the complete core snapshot and a signer row for each
record whose issuance the calling manager owns. The plan is immutable, validated data. Rows must
name records of the snapshot and hold 1 to 32 lowercase SHA-256 digests. There is no Snapshot
overload left beside it.

The manager builds the plan under the PMS lock. A row comes only from a pin whose `Issuance`
belongs to this manager, using the signer set its original selection captured, after record and
provenance equality checks. A proposal in `prepare` supplies its own selection's set before any ID
is issued. Nothing comes from the current `PackageSetting`, the handle index, a remembered binding
or another manager. Admission stays a pure projection over the cached view. Commit and retirement
build the same kind of plan under the PMS lock and write outside it. An invalid signer set,
including more than 32 signers, now throws `IllegalArgumentException` before issuance. Previously
that case could issue a pin and fail during later publication. No ID is consumed by the new refusal.

The one shared projection treats each record in one of three ways. None of them infers history
from an APK:

- A selected entry is copied unchanged. A CREATING entry must be this record's creation ID and
  package. With a complete binding it must also name the record's user and serial, and the plan's
  row when there is one. A missing row never strands it. A restored pin has no issuance, even
  after an explicit rebind, and keeps its durable entry.
- An unselected addition keeps its exact original entry, a missing binding included, under the
  same checks. Legacy null stays null, also after a restart.
- Any other record is truly new and needs its owned row. The version 1 format writes it as
  before. The version 2 format writes the record's user, serial and the original signer set.

## Store formats

`NativeIdentityStore` has a closed `Format` enum, `V1(1, 1)` and `V2(2, 2)`: the readable header
ceiling and the version a truly new bound reservation writes. It is fixed by the one constructor.
The only production construction, in the Settings adaptation, passes the literal `Format.V1`. A
pure source guard refuses any other production construction, `Format.V2`, `valueOf`, `values`
or reflection selection, and ignores comments and the enum's own constants.

The ceiling applies to every header copy, seed, write gate and writer. Slots and slot seeds stay
version 1 in both formats. Under V1 a version 2 copy stays an unsupported footprint with its
holds, as before. Under V2 versions 3 and above are the footprints. Initialization still writes an
empty version 1 header, so no version 2 bytes appear before a new bound reservation.

## Exact byte admission

`NativeIdentityRecords.encodedHeaderLength` returns the length of the encoder's own output, frame
and checksum included. The projection measures its exact chosen version and entries before it
constructs any header, and refuses a proposal above MAX_SLOTS or MAX_BYTES. Admission therefore
refuses before an ID is issued, and the writer refuses before any effect, instead of meeting the
constructor's exception after issuance. Version 1 encodings are unchanged; the tests compare them
with bytes computed independently from the documented layout.

## Version and copy rules

The B0 conservation rules stay, and the store's writer adds version rules at the lowest level:

- A header never exceeds the format's ceiling or falls below the selected version.
- A version 1 header becomes version 2 only through a pure reservation that adds at least one
  truly new bound entry. Restatements alone keep version 1, also when written directly.
- Under V2 a truly new entry must be a complete binding in a version 2 header. An incomplete
  version 2 entry is only ever an exact restatement.
- Phase changes, markers and omissions keep the header's version.

Copies relate across versions in one shape only: a version 1 copy below a version 2 selection's
counter, which must be a predecessor of that protected reservation. A newer copy, an older copy at
or above the counter, or any other version is incompatible, so writes refuse and a new registry
restores no counter. The shared `HeaderCopies` facts and the `selectionCovers` test take no
writer format. A protected version 2 target beside its predecessors restores only the selected
counter.

## Negative binding checks

A complete binding is checked only negatively. Load, resume, publication and the completion to
LIVE require exactly one body user with the creation ID, the binding's user and serial, and exactly
its signer set. The retiring flag may be either. A mismatch makes the slot a CONFLICT that keeps
its holds and supplies no usable binding. It does not discard unrelated eligible bindings.
Nor does it make an otherwise conflicting sibling usable. The binding is checked on its own in
every decoded header copy of the slot's lineage that lists the entry. When it fails anywhere, every
decoded slot copy of the record stays negative package and principal evidence before the duplicate
checks, like the copies of unsupported and unavailable records, also when an ordinary reason
conflicts too. The record keeps its CONFLICT status and supplies no identity or counter. An
ordinary conflict alone still gives no evidence, so an unbound version 1 record keeps its earlier
treatment. A bound layout's usable set is therefore a subset of its unbound twin's, not always
equal. A CREATING entry without a binding keeps its earlier checks.

## Earlier evidence and its adaptation

The archived B0 suite is unchanged in Git at `c9264e4`. Because the store constructor and
reservation API changed, the current copies of that suite call a host only `NativeHeaderApi`
adapter with an explicit signer row for every snapshot record. The baseline adapter maps to the
old Snapshot and static calls of `c9264e4` and `d104e15`. The B1 adapter uses plans and `Format.V1`.

The guarded runner builds both baselines from exact Git objects and pinned hashes. It requires
the adapted suite to equal the archived suite on each baseline: 53 and 27 passes on `c9264e4`,
and exactly the same 41 and 18 failures on `d104e15`. It then requires the same 53 and 27 passes on
the B1 sources. A compile failure is a harness failure, never an expected red result. The predicted
`d104e15` failure sets, traced case by case against its store, are recorded separately in
`scripts/proof/native_creation_binding_predictions.json`. They are predictions, not results.

On the B1 sources the projection reuses the exact durable addition before the copy rule compares
it. The B0 defect that compares additions by app ID only is therefore no longer reachable from the
B0 suite. It moved, with both replacements, to the B1 mutant set and a direct writer case. The
other 12 store and facade defects and both fragment defects stay with the B0 suite.

## Controls

The focused matrix has 80 cases, the fault matrix 53, and the reader check 47 layouts. Sixteen
focused cases and three layouts cover the negative evidence correction and stale slot copies:

- Plan validation, missing provenance under V1, rows for held entries and additions, another
  manager's unreserved pin, a late preparation failure, and golden version 1 and 2 bytes.
- Exact lengths for version 1 and 2 headers, and a MAX_BYTES projection written by the same
  projection that admitted it, with its one byte larger twin refused before issuance. They use
  32 signer, 255 character bindings, legacy absent tags, LIVE entries and an unpublished RETIRING
  pin.
- Upgrades beside legacy B in both commit orders, restatement staying version 1, pending and
  RETIRING pins together, held and added bindings, and the low level version rules.
- Cross version predecessors, incompatible version 1 copies and an interrupted publication before a
  protected upgrade.
- Body mismatches of serial, signer subset, superset and disjoint sets, zero and two users and
  another user, at every gate, and matching bodies retiring or not.
- A restored R beside a new N, R's changed APK signer, and a mismatched body.
- Signer mutation: P's replaced signer refuses P before I/O while Q reserves P with its original
  set, then P retires with its historical binding. A variant first makes P's reservation durable
  through a real permission refusal of the slot write.
- Version 2 gates for versions 3 and 65535 in every position, malformed and damaged version 2
  frames, version 2 slot frames under both formats, initialization bytes, and the whole presence
  matrix repeated under V2.
- Eight step fault sweeps of a fresh upgrade, legacy B with bound C in both orders, restatement
  alone, restatement then upgrade, pending and RETIRING pins, and version 2 publication, marker,
  omission and confirmation ordering.
- A separately compiled version 1 reader, from the B1 sources and from `c9264e4`, over every
  emitted version 2 layout: read only, every known hold kept, no counter, and no binding beside a
  version 2 header copy. Three constructed bound collision layouts also require CONFLICT for both
  slots from both readers.
- Binding conflict evidence. Each layout is read bound under V2 and as its bindings cleared twin
  under V1, then reopened in a host Settings facade. R fails its binding beside an N that shares
  its package, its principal, both or neither, by serial, as a tombstone, with swapped app IDs,
  and only in unselected main and reserve copies beside a matching preferred backup, which also
  withholds the counter. A matching binding keeps ordinary duplicates. When R's header names
  another package than its body, V1 keeps N usable as before, and V2 withdraws N because the same
  R also fails its binding. The production V1 format reads the bound collisions as unsupported
  and read only, with the CONFLICT statuses of `c9264e4`. Every bound usable set is within its
  twin's, with equal holds and no greater creation or counter readiness, and N fares the same
  when R has no ordinary conflict and its slot copies agree. Compatible layouts reopen with counter
  2 and no conflicting pin. Separate stale main and reserve controls require every decoded copy
  after a binding failure, while a matching binding leaves the sibling usable. Restored R must
  still equal its selected backup, never its stale package or principal.

Twenty one B1 mutants must compile and be caught: missing version relaxation, a permissive version 1
successor, filling legacy B, upgrading on restatement at the projection and at the writer, the
wrong or no byte measure, current package signers, omitted RETIRING rows, a withPhase downgrade,
incomplete new entries under V2 at the projection and at the writer, rows required for held
entries, additions compared by app ID only, unchecked body bindings at load, dropped binding
conflict evidence, evidence from every CONFLICT record, the binding checked only in the selected
header copy, evidence only when the binding is the sole cause, and taking only the first or last
slot copy as evidence. The source guard catches
production V2 construction and value based format selection.

## Host checks

The initial implementation did not run a JVM without the required controls. Primary qualification
then compiled the actual sources with JDK 25, `--release 17 -Xlint:all -Werror` and assertions enabled,
under 2 GiB resident memory, zero swap and core dumps, 2 CPUs and 256 tasks.

- Source guards and regenerated framework outputs passed. Only Settings changed; the other nine
  outputs remain identical. The host admission method is checked against the actual fragment.
- Archived and adapted B0 cases both passed 53/27 on `c9264e4` and reproduced exactly the recorded
  41/18 failures on `d104e15`. B1 V1 passed the same 53/27 cases.
- B1 passed 64 focused and 53 fault cases. All 15 B1 mutants were caught. Both V1 readers passed
  all 44 emitted layouts. Existing store, persistence, manager, admission, recovery and writer
  regressions passed without skips.
- That complete run was nevertheless FAILED: the long evidence path exceeded the Unix socket
  fixture's path limit in two V2 presence cases. A separately owned short path run then passed all
  93 cases, including both actual socket cases and the unprivileged DAC controls. The path guard
  and the special node locations were not weakened.

The reusable runner now uses a short fixture root, records compile and run diagnostics, checks exit
status and exact case names, and enforces the baseline failure sets. It no longer issues and ignores
an invalid extra reader invocation. Run
`python3 -B scripts/proof/native_creation_binding.py --evidence NEW_PATH` inside the required
bounded scope with a JDK on PATH. Without those bounds it reports NOT_RUN and starts nothing.

## Negative evidence correction

The primary then reproduced a defect on those sources with constructed host evidence. The earlier
candidate and its results remain separate. Under counter 2, R at app ID 10000 is
CREATING with creation 1 of `dev.andrix.r`, and N at 10001 is LIVE. V2 binds R to user 0, serial 7
and signer set S0, and V1 leaves it unbound. R's body has user 0, serial 7, ID 1, R's package and
signer set S1. N's body shares R's package and ID, only the package, or only the ID. Each record
has equal main and reserve copies and no backup. For each variant V1 gave R and N CONFLICT with N
unusable. V2 gave R CONFLICT but N VALID and usable, and every hold stayed. The binding check had
removed R from the duplicate checks, so it made a conflicting sibling usable. This is host
evidence, not an Android exploit or a production V2 claim.

`load()` now checks a complete binding as its own step in every decoded header copy of the slot's
lineage that lists the entry. It remembers each VALID record whose binding fails, and adds all of
its decoded slot copies to the existing negative evidence, also when an ordinary reason conflicts
too. Independent review set that boundary, since it only restricts corrupt bound states further.
An earlier revision fed only records withdrawn by the binding alone. It was never run, and its
mixed cause case and mutant asserted the opposite; both are removed. The record keeps its
CONFLICT status, no status or hold is added, nothing is marked unavailable, no counter is rebuilt
and no writer changes. Only a sibling that collides with its copies becomes a CONFLICT. An
ordinary conflict alone still gives no evidence, so unbound V1 handling is unchanged.
`binding-unchecked-on-load` is anchored on the separated binding check and keeps its expected
failures. Predictions for the twelve new cases and three layouts, on the sources before the
correction, the earlier revision and this one, and under each related mutant, are in the
predictions file under `negative_evidence_follow_up_r3`.

The revised product source then passed a complete guarded run: 78 focused cases, 53 fault cases,
all 20 mutants then present, 93 V2 presence cases, 47 layouts through each V1 reader, and the
unchanged B0 comparisons and regressions without skips. Primary then strengthened the stale copy
controls to distinguish main, reserve and backup, added matching binding controls and a first copy
only mutant. All 80 focused cases passed and both first and last copy mutants were caught. The
independent original three collision reproductions also turned green.

After explicit integration, the reusable runner passed all 80 focused and 53 fault cases, all 21
mutants, all 93 V2 presence cases and 47 layouts through each V1 reader. The exact B0 comparisons,
all existing regression suites and nine pure source tests passed without skips. Earlier runs on
disk backed host files and the integrated runner's temporary filesystem remain host checks, not
Android writer, filesystem durability or activation qualification.

## Android artifact checkpoint

The normal `0018a1d` image compiled in 9 minutes 48 seconds under the 54 GiB, 8 CPU build scope,
with a 33.1 GiB peak and zero swap or core dumps. Final DEX contains the actual Settings
construction with `Format.V1`, the corrected negative sibling evidence pass, the counter withholding
path and the Package Installer writing descriptor sync. Compiler output also contains the original
issuance signer plan and exact byte measure before header construction. R8 removes those inactive
creation paths from the normal DEX. The source adaptations were reverted after captured producer
retirement, preserving the accepted CE and verity companions.

A fresh disposable guest also booted this normal image and completed a clean reboot. Two ordinary
APK controls kept their original UIDs, paths, bytes, dummy keystore keys, canaries and complete PMS
maps. The native store stayed MISSING and the lab writer command stayed absent. Inputs had an
explicit setup sync. No key initialization or installation was replayed.

This adds normal startup and ordinary app continuity evidence, not an Android execution result for
the B1 writer, an unclean storage or power loss result, version 2 publication, or positive historical
recovery from a header.

## Limits

- Host facades and injected failures are not Android crash, power loss, storage or SELinux
  evidence. The normal image build does not qualify the inactive writing protocol at runtime.
- Version 2 remains disabled in production. Before a reviewed enable, Android readers, rollback,
  recovery ownership and a real image need their own qualification.
- The reader check covers the B1 V1 format and `c9264e4` sources. Earlier readers without the
  explicit version gate may treat V2 as damage and overwrite it. This is not universal rollback
  compatibility.
- A tombstone body under a bound CREATING entry is a CONFLICT. No current writer leaves one.
- A restored pin without issuance cannot supply a row, so a restored creation that is not yet
  reserved cannot be reserved again. Restored pins come only from published bodies today.
- No restored creation admission, recovery join, cancellation or UID release is added.
- A record whose binding fails contributes every decoded slot copy, not only the selected one, also
  beside an ordinary conflict. V2 can then withdraw a sibling that V1 keeps. That is stricter, never
  usable history. The ordinary conflict control covers one such case; stale unselected slot copies
  beside a present backup have no control yet.
- A V1 reader of a V2 layout also checks the decoded bindings. Beside an ordinary conflict, a
  failed binding then withdraws a sibling's status where `c9264e4` kept it VALID. No binding is
  usable there in either reader, and the bound collision layouts keep exact parity.
