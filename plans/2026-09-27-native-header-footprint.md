# Native header footprints and protected reservation writes

Status: revised version 1 correction with independent review, guarded host qualification, Android
compilation and bounded reader controls at `c9264e4`. Production writer crash durability remains
unqualified. It follows the
[presence correction](2026-09-27-native-store-presence.md). No version 2
publication, format selector, restored creation admission, initializer replay, repair, cancellation or
UID release is added. Native execution stays disabled.

## Two observed problems

A preferred valid backup outranks a newer main or reserve. That selection rule is kept. An older writer
could therefore stop with its new copies complete while the backup still held the prior header. A
constructed host layout had an empty backup with counter 0, and main and reserve copies with a CREATING
entry for B at app ID 10000, creation ID 1 and no slot directory. The store selected the backup, reported
creation as ready and kept B's app ID as a hold. The admission projection and every header writer looked
only at the selected header. A proposal for C at app ID 10001 received creation ID 1 again, and the actual
manager overwrote B's copies through its ordinary path. A reopened host Settings then lost B's hold.

A first fence required every header write to restate such an unselected addition, which blocked that
loss. The primary then injected an IOException immediately after the strict writer's destructive
startWrite, during the exact owned retry that restated B. The writer had preserved the selected prior as
the preferred backup, and startWrite had already removed main and reserve. No copy of B remained, with the
earlier sources and with the first fence alike. A fence checked before a write does not keep a footprint
through the write. Both were constructed host results, not Android crash observations.

## Compatible header copies

Every decodable copy is compared with the selected valid header by structure alone. Nothing is ordered by
timestamps, and the selection is unchanged. A compatible copy has the same version and lineage, and:

- An app ID both list is equal, or one phase ahead in the copy: CREATING to LIVE, or LIVE to RELEASING.
  Same phase tuple or binding changes, backward phases and skipped phases are incompatible.
- An entry only the selection lists is RELEASING, omitted by the copy, or CREATING above the copy's
  counter. The latter copy predates a protected reservation.
- An entry only the copy lists is CREATING above the selected counter and at most the copy's counter.
  This is an unselected addition that an older writer left behind. It is a known negative hold, never
  positive history, and must be conserved exactly.
- A higher copy counter comes only with such an addition, and a lower one only with such a newer selected
  reservation. Otherwise the counters are equal. A counter only difference is incompatible.
- Additions in different copies must be identical for the same app ID and must not share a creation ID.

## Header writes

Every header write, and reservation admission on the cached view, applies one pure rule before any effect
or issued ID. Every copy must be compatible. The proposed header must be compatible with the selection
too. It must restate each unselected addition exactly: app ID, phase, creation ID, package and binding.
Its counter must cover the largest counter of any copy. A new CREATING entry at or below that observed
counter must be a known addition, not a new identity in that range. The observed counter is only a refusal
constraint. Nothing restores, issues or derives allocator state from it.

Only a pure reservation advances the counter: every selected entry unchanged and at least one new CREATING
entry above the selected counter. Counter only advances and reservations combined with phase changes or
omissions refuse. The earlier low level writer accepted such constructed values. The owned manager flow
never needed them, because each reservation covers every pending pin of its full snapshot.

A pure reservation, classified against the fresh selection, now publishes its own target as the preferred
backup before main and reserve are touched. It uses the same seed, writing descriptor sync, exact
readback, atomic backup replacement and directory sync as before. An existing backup must already be the
target or the selected prior. Only then may startWrite remove main and reserve. Exact retries,
confirmations, phase changes and omissions keep their prior as the backup until their final step, as
before. First writes keep their existing behavior. The strict writer and slot writes are unchanged.

Each destructive step keeps a durable witness of every known hold:

- While the target seed is staged, main and reserve still hold every older copy, including an unselected
  addition.
- After the backup replacement and directory sync, the backup holds the target, which restates every
  addition and keeps every selected entry.
- After startWrite empties main and reserve, the backup still holds the target.
- Main and reserve are completed through their writing descriptors before the backup is removed.

A failure after the replacement leaves the target selected, and older copies become its compatible
predecessors. The same original handle's retry then confirms the target. A phase change, omission or
confirmation has no addition to carry, and it keeps the older state until its final step.

## Boot and live registries

A new registry restores the selected counter only when every copy is compatible and the selection covers
every addition and counter. That includes the protected target beside its predecessors. Otherwise the
Settings boot fragment restores every hold and eligible binding without a counter, so new issuance
refuses. The host Settings facade runs the same fragment. This is no global Android allocator freeze.

A live registry keeps its own counter. Its full pin snapshot and counter already cover its own writes, so
its exact retries and later issuance continue. Unrelated header transitions wait until an unselected
addition's owner restates it. A later reduced view still cannot remove a cached hold. After a restart no
owner can restate an older writer's addition. Its header then stays read only for transitions until an
owned repair exists. Existing holds, bindings, slot confirmations and markers remain.

## Controls

A focused host matrix isolates 53 cases in fresh stores. It covers the reported store and manager
reproductions and every header confirmation caller. It also covers transitions beside additions, torn
siblings, disagreeing or colliding additions, substituted fields, other lineages and reopened registries.
Same manager retries use constructed older writer layouts. The compatibility cases cover predecessors,
dropped reservations, counter only copies and writes, mixed writes and six incompatible copy kinds. They
also cover new identities inside an observed counter and restatements that must cover it. A header
conservation refusal leaves that step's bytes, file identities and modification times unchanged. A
multi-step retirement may already have committed its owned tombstone before the header step refuses;
the controls assert that progress and the retained holds explicitly.

A fault test inserts a host only seam into copies of the store and strict writer sources, and production
sources contain none. It injects I/O failures at 8 steps: after the seed sync, after the backup rename,
after its directory sync, after startWrite, after the main sync, after the reserve sync, at the backup
unlink and after it. It covers 27 cases: the reported owned retry, legacy and fresh reservations at every
step, and prior ordering for publication, release marker, omission and confirmation at every step. It also
covers chained protected targets, B and C in both commit orders, a retiring B, an interrupted publication
before a protected reservation, and a preferred backup changed during the write. Each case checks that
its step was reached, that every hold survives a reload and a reopened host Settings, and that the same
original handle finishes without another ID.

Store assertions check the rule directly, including a version 2 binding, which no version 1 writer can
construct. The boot fragment test runs the actual adapted fragment. Thirteen store or facade defects and
two fragment defects are expected to be caught:

- prior protection for additions;
- target protection for every header write;
- a lost conservation fence;
- a writer fence without the confirmation fence;
- missing predecessor acceptance;
- a predecessor accepted without its counter test;
- a counter only advance;
- an accepted foreign backup;
- a boot counter restored beside footprints, or guessed from the largest copy;
- app ID only matching;
- an ignored surviving copy;
- phase differences treated as additions.

The worker could not establish the required resource controls and started no JVM. The primary's first
run exposed a duplicate host logging facade in the new harness. That failed run was retained. The
corrected harness selects the reviewed facade and refuses any new duplicate class.

Actual guarded qualification passed all 53 focused and 27 fault cases, with the boot fragment control.
The earlier `d104e15` sources failed exactly the predicted 41 focused and 18 fault cases, plus the boot
control. The remaining 12 focused and 9 fault cases are controls against overblocking, not sensitivity
claims. All 13 store or facade mutants and both fragment mutants were caught. The existing future
format, presence, persistence, manager, preparation and lab writer regressions passed without skips.
The scope used JDK 25, 2 GiB resident memory, zero swap and core dumps, 2 CPUs and 256 tasks.

A separate primary control repeated the originally observed failure after `startWrite`. The old source
lost B. The correction returned false with the target backup, counter 1 and B's hold retained through
reloading; the original handle then completed without another ID. None of this is an Android crash or
physical power loss result.

## Android artifact checkpoint

The normal `c9264e4` image compiled in 9 minutes 33 seconds, under the 54 GiB and 8 CPU build
scope, with a 27.6 GiB peak and zero swap or core dumps. Final DEX inspection verified the loaded
footprint flag, `counterRestorable()` and the actual Settings branch that restores bindings without
a counter. The protective header write also exists in the compiler output, but the inactive write
paths are removed from the normal DEX by R8. The Package Installer writing descriptor sync remains
present. Source adaptations were reverted only after captured producer retirement, preserving the
accepted CE and verity companions.

The [controlled header reader inputs](../tests/native-identity/README.md#header-copy-reader-inputs)
prepare separate legacy addition and protected predecessor layouts. Generating them is not a
runtime result, designation, repair or proof of writer durability. Native execution, factory entry,
version 2 publication and the lab writer route remain disabled in this image.

## Android reader controls

A fresh disposable guest exercised both layouts through actual cold boot and PMS loading. The
fixture used an observed unused app ID, a fixed uninstalled test package and no slot body. It did
not create a `PackageSetting`. Two ordinary APKs retained their original UIDs, paths, bytes,
dummy keystore keys and canaries. Complete package and shared UID maps stayed unchanged.

- The legacy addition layout retained its header bytes and negative hold. The header was VALID,
  enumeration was complete, and `counter_known` and `creation_ready` were false.
- The protected backup beside its predecessors retained the same hold. Both internal counter and
  creation readiness fields were true, while the body stayed MISSING and no memory pin or binding
  appeared. These fields are not native execution authority.
- Both layouts kept `unidentified_code=true`. An unmapped held UID deliberately triggers this
  conservative code preservation in `seedNativeRecoveryLPw`. The first observer wrongly expected
  false and stopped before its key bookends or another publication. That failed trial remains
  separate from the corrected controls. No protection was removed to obtain a pass.

The controller captured PMS writer quiescence before changing the controlled metadata. It used
writing descriptor sync, a directory sync after each rename and an explicit setup sync. These are
prepared reader inputs, not an observed production writer interruption. No app data, keys or package
settings were restored, and no installation or initialization was replayed. All VM scopes closed.

## Limits

- Host facades, constructed layouts and injected I/O failures are not Android crash, power loss, storage
  or SELinux qualification. A process killed between steps is expected to leave the same durable files,
  but that is not observed here.
- A new reservation present only in an unpublished target seed supplies no durable binding or counter.
  Its owner keeps the pin and retries. Any already known footprint in main or reserve remains intact
  during this staging step; it is not disposed of by the seed's status.
- The compared prior V1 implementation, `d104e15`, still selects the protected backup and keeps its
  holds. It does not withhold its counter beside an older writer's unselected addition. This is not a
  promise about every earlier Android image or reader.
- After a restart an older writer's addition keeps header transitions read only until an owned repair
  exists. No repair, selection or recovery policy is added here.
- The diagnostic dump reports the withheld counter but not which copy caused it.
