# One historical native identity view and exact restored creation rebinding

Status: inactive implementation on the B1 sources at `0018a1d`, independently reviewed and
qualified on the host. Both the original and hardened matrices ran under the required bounds;
see [the revision](#revision-after-the-primary-qualification). The normal `89491b9` Android image
also compiled. Version 1 stays the only production format. No public API, policy default, activation, repair,
cancellation, release or initializer authority is added. This follows the
[creation binding step](2026-09-27-native-creation-binding.md).

## The gap

B1 preserves the complete original binding of a new creation in a version 2 header. Nothing read
it positively. After a restart a selected CREATING entry whose slot was missing stayed a held,
unavailable tail: no pin, no rebind, and its mapped package deferred at boot. That held whether
its body was never published or was published and later lost. The published
body path had its own separate restore loop, scan rule and recovery seeding, each reading
`bindingUsable` directly.

## One shared history view

`NativeIdentityStore.History` is an immutable value with a lineage, app ID, package, principal
ID, user, serial, signer set, retiring flag and `Source`, which is `BODY` or `RESERVATION`. Only
the store builds it. `Loaded` computes the whole map once, from its own immutable data and with no
I/O, and offers `history(appId)` and `histories()`.

A `BODY` history exists exactly where `bindingUsable` holds, for the slot's one user. That is the
eligibility restoration always used. The retiring flag is kept, and no stricter gate is added. A
tombstone, a conflicting, damaged, unsupported or unavailable body, or a body that fails its
binding gives none.

A `RESERVATION` history exists only when all of these hold:

- The view is creation ready: complete enumeration, a valid header, and no creation block or
  unsupported or unavailable footprint, seeds included.
- The header copies have `HeaderCopies` facts.
- The selected header entry is CREATING with a complete creation binding for user 0.
- The slot read result is genuinely MISSING, not unavailable. A missing directory, an empty
  directory or a torn seed qualifies. A seed is never read as history.
- Every decoded header copy lists exactly that entry, or omits it with a counter below the
  creation ID. A LIVE or RELEASING copy withdraws it, even where B0 finds that copy compatible.
- No other app ID claims its package or principal ID. Every decoded slot copy there, whatever its
  status, supplies its package and each user ID. Every CREATING entry there, in every decoded
  header copy, supplies its package and creation ID. The claim location is the slot's physical
  app ID, never the body's own app ID field. Two reservations of one package both withdraw.

A claim withdraws only the reservation. It never changes a body or its status. The history is
the entry's own app ID, creation ID, package, user and serial, with the selected binding's signer
set. Nothing comes from seeds, unselected additions, entries without a binding, LIVE or RELEASING
entries, a counter or current APK signers.

`RESERVATION` says only that the selected complete header supplies this view's history, because
the view has no eligible published body and the slot is genuinely missing. It is no proof that a
body never existed. One may have been published and lost before a restart. The retirement rule
below does not rely on that difference.

A published body with more than one user, or with only a nonzero user, gives no history. The
codec keeps user IDs strictly ascending and load reads a nonzero user as an UNSUPPORTED slot, as
`0018a1d` does, so a usable body with more than one user is unreachable. The `BODY` guard for
exactly one user stays, and source checks pin it with those two facts. Such a body's decoded
copies still claim their package and every principal ID against reservations elsewhere.

## Restoration, scanning and seeding use it

`NativeIdentityPersistence.restoration(histories)` turns the map into sorted core records and
retiring IDs, for real Settings and the host facade alike. Body records are exactly the former
loop's. A reservation record is added only when it relates to every other history as
`NativePrincipalPins.restore` requires: its own app ID key, user 0, and an ID, package and app ID
no other history has. Otherwise this backstop withdraws it, reports its app ID and never repairs,
merges or fabricates anything. The store's claim rules already withdraw every such reservation,
so a store view needs no backstop. The `restore-capacity` fragment is byte identical, including
its overcapacity, selected counter and unknown counter branches.

`NativeIdentityPersistence.scanOwner` is the one scan rule. It takes the cached history of the
candidate's app ID, the candidate's package, app ID and shared flag, the existing mapping's
package and shared flag, and the current user 0 serial. It returns the history only when the
candidate and the existing mapping are both that package, neither is shared, the serial matches
and the history is not retiring. Settings compares the APK's signers with the history's recorded
set through the existing `signerDigests`. It creates no PackageSetting, mapping or UID and takes
no history from the APK. Boot recovery seeding reads the same view. A mapped package with its own
body or reservation stays recoverable. An unmapped history, or a missing, different or shared
mapping, is deferred with unidentified code as before. Every hold, code, data and keystore fence
remains.

## Stored histories and handles

`mNativeRememberedBindings` now remembers a `History`, first seen, and only when a core pin with
exactly its record exists. `nativePrincipalStoredHistoryLPr` returns it only for a record whose
ID, package, app ID, user and serial all match. A restored handle takes its lineage, signers and
an immutable prior source from that stored history, under the PMS lock. An issuance handle keeps
its original selection instead. `requirePublishedBinding`, `nativePrincipalBindingLPr`,
`currentIdentity`, `persistence.binding`, `publish` and every writer stay body only and unchanged,
so a header only reservation is never an ACTIVE or current identity.

## Rebind and publication

A complete header creation restores PENDING, with no issuance. An explicit designation rebinds it
through the existing `prepare`, which validates the actual APK, user, UID and signers against the
stored history and keeps the original ID. No row is invented for it. Its commit reserves through
the owned plan, whose held entry needs no row, then publishes the original body with the stored
signers and completes the entry to LIVE through the existing checks. The next new issuance takes
the next selected counter.

With an unknown counter, for example beside an unselected addition that has no directory, the
reservation still restores PENDING and can be rebound, but commit returns false before any write
and new issuance refuses. The addition itself is never history. A compatible protected version 2
backup beside its version 1 predecessors restores and confirms its reservation.

## Retirement keeps the body origin rule

A handle may create its own body when it has a selection, from an owned issuance or an explicit
rebind, or when its stored history was a body. `beginRetirement` refuses a handle that may not,
unless the cached view already holds its published body. It throws `IllegalStateException` before
`beginRetire`, with no pin or store effect. Creating a body from reservation only provenance without a new designation belongs
to the separate cancellation join. `persistBinding` receives the same answer and returns false
before any write when the fresh binding is absent. Commit passes true after its designation
gates. If the cached body is present but the fresh store lacks it, the pin may already be
RETIRING, nothing is written and no marker is committed, so finishing refuses. After a restart
without a durable marker the header restores PENDING again, never active.

A body origin handle keeps the B1 behavior of `0018a1d`, also when its body later goes missing
under its prior CREATING entry. The primary's read only probe of that baseline, recorded as
`BODY_ORIGIN_BASELINE`, is copied verbatim into the tests and runs unchanged against both sources.

## Framework adaptation

Only `Settings.java` changes among the ten pinned framework targets. The runner rebuilds all ten
from the canonical copies and checks that the other nine equal the `0018a1d` outputs. The patch's
Settings section is regenerated with GNU `diff -u`, which reproduces the earlier section exactly,
and the other nine sections are unchanged bytes. Four new profile fragments pin the exact Settings
text: `restore-history`, `stored-history`, `scan` and `recovery-seeding`. The host facade contains
the first three, and the existing `admission`, `restore-capacity` and `identity` fragments,
verbatim. The literal `Format.V1` construction, the Package Installer, CE and verity companions and
the lab writer profile are unchanged.

## Intended changes to B1 version 2 outcomes

No version 1 outcome changes: a version 1 header carries no binding, and a version 2 copy is
unsupported under `Format.V1`. These unchanged B1 version 2 cases now also restore PENDING
reservation pins that they do not assert on. Their own assertions are predicted to pass.

- The byte admission cases restore 48 header only creations as PENDING pins.
- The cross version target beside version 1 predecessors restores C's reservation under counter 3.
- The fault matrix's reopened registries restore the selected bound creations from the backup
  rename on: fresh B, bound C beside legacy B in both orders, C after a restatement, the pending
  and RETIRING set (with no durable marker, C restores PENDING) and the interrupted publication.

The exact list is in `scripts/proof/native_creation_history_predictions.json`.

## Controls

`NativeCreationHistoryTest` has 87 focused cases. They cover body and reservation sources, the
missing directory, empty directory and torn seed, intact seeds that never become history, the
damaged header beside an eligible body, bodies with a nonzero user, the version 1 reader and the
protected target. Nine no fallback cases cover damaged, conflicting, binding mismatched,
tombstone, future, unavailable, link, file and directory bodies. Eighteen gates cover global blocks, seeds, unindexed
directories, legacy entries under both versions, unselected additions, LIVE and RELEASING
entries and copies, incompatible copies, another lineage, counter only copies and another user.
Thirteen uniqueness cases cover valid, damaged, conflicting, unsupported, unavailable and
tombstone claims, legacy creations, unselected additions, two reservations, physical location and
an unrelated control. The rest cover restoration and its backstop, stored histories, rebinding,
body only exposure, retirement timing, the scan rule, recovery seeding with each boot observation
of data directory owners, every hold and fence, and an exact release that lifts only its own UID
hold and keystore fence. Every booted facade must restore the same core pins, phases, counter
knowledge and allocator holds as the adapted Settings text run by the harness over the same view.

`NativeCreationHistoryFaultTest` injects failures at the eight B0 writer steps in the exact header
confirmation, the first body write, the completion to LIVE, and a rebound retirement's own
publication and marker: 40 cases. A reopened registry reads the reservation until the complete
body has been moved into the preferred backup, and the body after. It restores PENDING until the
durable marker is the selected copy, and RETIRING after. The record, hold and counter are
conserved, and the same original handle converges without another ID.

`NativeHistoryParity` compares B2 with `0018a1d` through `NativeHistoryHarness`, which each side
fills with its own exact Settings text cut from its own candidate: the whole boot restoration
method, the observation, remembering and hold refresh it calls, the restore inputs, holds,
identity, path safety, scan rule and recovery seeding. No hold computation is copied by hand.
Both sides build the same bytes: 47 layouts, each with its bindings cleared twin, under both
formats. Five of them hold a body with users 0 and 1 or with only user 1, alone, beside an
unclaimed reservation with its published twin, or claiming a reservation's principal. The rules
are:

- B2's body only inputs equal the `0018a1d` restore inputs on the same bytes, everywhere.
- Every version 1 run, and every layout without a surviving reservation, equals `0018a1d`.
- Under version 2, the seven reservation layouts equal `0018a1d` on their published twins, the
  state the original writer leaves after publishing the body. That covers restoration, the
  allocator holds and pins, seeding across five mappings and six boot observations of data
  directory owners, and scanning across candidates, mappings, users and deferral.

`NativeCreationHistoryLayouts` emits 45 version 2 layouts. The unchanged B1 reader check reads them
with the B2 and `0018a1d` version 1 formats and with `c9264e4`. All three must keep them read only,
with every hold, no counter and no history.

Forty mutants must compile and be caught by complete runs. They cover each history source and
gate, corroboration, every uniqueness rule including negative copies and the physical location,
the backstop, the four scan conditions, the recovery seeding view, stored history matching, body
only bindings, seed history, fallback around damage, tombstone history and dropped retiring
history. The origin rules have a selection only guard, an always creating body, a current view
origin, a current view guard, a dropped early guard, persistence ignoring origin and current APK
signers. Four more cover trusted data owners, an ignored incomplete owner enumeration, recovery
holds that a refresh does not update, and a facade that restores differently from the adapted
Settings text. A mutant counts as caught only from a run that printed each case name exactly once
and exited 1 with failures, or a probe that failed by its own assertion.

## Host checks

Run `python3 -B scripts/proof/native_creation_history.py --evidence NEW.json --work NEW_DIR
--pinned-framework PINNED` inside the required bounded scope with a JDK on PATH. `NEW_DIR` must
resolve to at most 32 ASCII characters, such as `/srv/b2w`. The unchanged B1 regressions bind
version 1 presence sockets below `NEW_DIR/tmp`, and `NativeIdentityPresenceTest` refuses a socket
path of 100 characters or more. The runner derives that budget from the actual nested sources and
checks both Java characters and UTF-8 bytes. It never moves TMPDIR out of the work directory to
gain budget.

Without the bounds, a JDK or a short enough work path, the run reports NOT_RUN before it creates
or starts anything. Otherwise it creates files only under `NEW_DIR` and the evidence file. The
unchanged B1 runner it runs as a regression writes under `NEW_DIR/tmp` and `NEW_DIR`, except its
version 2 presence matrix, which binds its sockets in a fresh `/tmp/b1p-*` directory as before.
Unless the JDK is configured otherwise, each JVM also keeps HotSpot's transient performance data
file under `/tmp/hsperfdata_<user>` while it runs.

One report is shared by every phase before the first starts. At each phase boundary the runner
syncs its writing descriptor and directory for `NEW_DIR/progress.json`, with status RUNNING, the
finished phases and the running one. This records process interruption, not filesystem power loss. A run killed by its scope leaves that checkpoint. An exception or timeout keeps every
finished record and problem, the timed out command's decoded stdout and stderr, the unfinished
phases, status NOT_COMPLETE and exit status 1. Nothing is retried, and PASS needs every phase.

## Revision after the primary qualification

The primary archived the original 31 file handoff and qualified a frozen candidate of it on the
host, on tmpfs. It reported these actual results:

- 81 focused and 40 fault cases passed. The run was reported as 6m12 and 502 MiB.
- All 36 mutants compiled and completed with their expected exit status.
- Parity printed 85700 lines per side with no mismatch and exactly the six predicted twinned
  differences.
- The 45 layouts passed all three version 1 readers.
- The BODY origin probe printed the same 10 cases on `0018a1d`, on B2 and in the archive.
- The unchanged B1 runner reported PASS, with its 80, 53, 21 and 93 case counts and every
  regression.

No Android build of B2 ran.

The revision changes no product behavior. Its product edits are comments: `RESERVATION`, the
history derivation and the retirement guard no longer say that a body was never published. The
Settings patch section and profile were regenerated from the pinned framework for the matching
restore history fragment comment. The other nine framework outputs and the restore capacity
fragment stay byte identical. It adds:

- The work path budget, the shared checkpointed report, timeout stream retention and complete
  mutant results described above.
- A harness filled with each candidate's own boot restoration, observation, remembering and
  refresh text, instead of a hand copied hold computation, and a facade refresh that updates the
  recovery view's holds as the adapted Settings refresh does.
- A boot check that facade and harness restored the same core pins. The retirement case of a
  cached body missing from the fresh store now also requires its second call to take the early
  guard, with precise finish, commit and prepare refusals. Six new focused cases cover bodies with
  a nonzero user, four data owner seeding controls, and an exact release that lifts only its own
  hold and keystore fence without any claim about the APK or its data.
- Five parity layouts with bodies of users 0 and 1 or of user 1 alone, the data owner dimension,
  the allocator holds and pins in each seeding line, and four mutants.

For the revision the worker observed only pure checks, with its temporary files in its own
scratch directory:

- The 18 pure B2 runner tests passed, and source only mode passed with the rebuilt candidates
  changing only Settings and the B2 text checks clean.
- Eight pure B1 runner tests passed. Its `/tmp` socket path test and its JVM test did not run.
- The B0 seam agreement and the principal pins, boot fragment and writer profile tests passed.

The primary then inspected the exact revised files after the worker's deadline ended, retained
that cancellation separately, and completed qualification. The revised run passed all 87 focused
and 40 fault cases, 40 compiled mutants, 108110 parity lines per side with no mismatch and exactly
seven expected twinned differences, and 45 layouts through each of the three V1 readers. The
BODY origin probe and unchanged B1 runner also passed, as did all 18 pure runner tests. The run
took 6 minutes 25 seconds with a 523 MiB peak under 2 GiB, zero swap and core dumps, 2 CPUs and
256 tasks. The original results above are not substituted for this revised run. After explicit
integration, the complete runner and 18 pure tests passed again on Main, with all eight phases
complete and the same case, parity, reader and mutant outcomes.

## Android artifact checkpoint

The normal `89491b9` image compiled in 9 minutes 18 seconds under the 54 GiB, 8 CPU build scope,
with a 27.5 GiB peak and zero swap or core dumps. Final DEX constructs the store with literal
`Format.V1`. Boot restoration consumes the shared history map and its records and retirement IDs,
then chooses the selected counter or the existing restore without counter branch. Scan and
recovery seeding use the same view, with the recorded signer comparison. The Package Installer
writing descriptor sync remains in the final artifact.

Compiler output contains the immutable restored handle origin, the guard before retirement and
the body only published binding check. R8 removes inactive writing paths from the normal image.
The producer scope was retired before reverting the native and payload adaptations, preserving
CE and verity. No B2 Android runtime or V2 publication result follows, and the separate counter
gap below is still present in this image.

## Separate counter admission gap

An independent check also found an existing gap in `0018a1d` and this candidate. A decoded slot
ID above the selected counter can be skipped by the counter check after its body becomes
unsupported for a nonzero user. An unrelated preparation then issued that ID and its commit
left a conflicting body and a held, stranded pin. A higher ID found only in an unselected copy
of a valid body was another affected case: publication could succeed despite that decoded ID.
These checks preserved UID holds and did not establish an authority escalation. The separate
[counter admission correction](2026-09-28-native-counter-admission.md) now withholds creation in
both cases and passed its guarded host checks. Ordinary copies of another lineage outside the
existing negative evidence remain a documented residual. This history view does not rebuild
counters or add repair authority. Production V2 publication and native activation stay off.

## Limits

- Host facades are not Android boot, crash, storage or SELinux evidence. Compilation and artifact
  inspection do not qualify the header recovery path on a running Android system.
- Version 2 publication stays disabled. The reservation history exists only under the host
  version 2 format, so production behavior stays version 1.
- A never rebound reservation without a current published body cannot retire. Creating a body
  from that provenance is the separate cancellation join.
- Boot restoration, observation, refresh and recovery seeding run as exact Settings text in a
  harness, not a running PMS.
- A claim located only in an unreadable copy, or a lost body under a LIVE entry, is invisible to
  the claim rules. The store's own availability gates cover the first. The second supplies no
  history.
- The dump output format is unchanged. Under version 2 a restored reservation now shows as pinned.
