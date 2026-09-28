# Native counter admission

Status: inactive correction on the B2 sources at `89491b9`, independently reviewed and qualified
on the host. Original and strengthened controls ran under the required bounds. Android compilation
of this correction is still separate. Version 1 stays the only production format, and version 2
publication stays off. No public API, policy default, activation, repair,
cancellation, release or initializer authority is added. This follows the
[historical identity step](2026-09-28-native-creation-history.md) and its separate counter
admission gap.

## The gap

Admission of a new principal ID compared the selected header counter only with the principal
IDs of selected valid bodies. Two independently reproduced layouts, which the primary compiled
and ran against both `0018a1d` and `89491b9`, show what that missed. Both use a selected version
1 header of lineage L with counter 1 and N's app ID 10000 LIVE.

- N's body is codec valid in lineage L for package N, with user 1, serial 7 and principal ID 2.
  Load reads it as UNSUPPORTED, a user limit and not a format footprint, so the counter check
  never saw it. Creation stayed ready and the counter restorable. A new preparation for Q at app
  ID 10001 was issued ID 2. Its commit returned false and left Q PENDING and CONFLICT, N
  UNSUPPORTED, both UID holds, and a header counter of 2 with Q CREATING 2. After a restart that
  is a stranded ID, UID and app. It is no authority escalation or UID sharing.
- N's preferred backup names user 0 with ID 1, while main and reserve name user 0 with ID 2,
  all in lineage L. N was VALID and usable through the backup. Q was issued ID 2 and its commit
  succeeded with N and Q both VALID. A later release of Q would be refused by the conservative
  check for the same ID elsewhere. No current writer creates copies that change a principal, but
  a known rollback, corruption or crafted state must not lead to an ID below its own claim in the
  same lineage.

The primary's corrected probes compiled on both baselines and failed their own assertions after
these exact observations. An earlier compile of the first probe, with a mistyped constant name,
never executed and is not a red result. The probes are metadata about issuance, never positive
authority.

## The rule

When the selected header is VALID with lineage L and counter c, load sets its existing local
creation block if any principal ID in any decoded slot copy is above c and either:

- the copy has lineage L, whatever its record's status, whether it is selected, the slot's
  physical app ID or the copy's own tuple, or
- the copy's record already feeds negative incarnation evidence: it is UNSUPPORTED, unavailable
  or a failed complete creation binding, whatever the copy's lineage, as that evidence already is.

Staging seeds never count; they are never copies. Nothing raises, reconstructs or derives a
counter from such an ID, and no maximum ID is restored. Statuses, eligible body bindings, evidence
packages and IDs, held UIDs, header bytes, footprint flags and writers are unchanged.

The check is one pass inside the existing negative evidence collector. The collector now states
its evidence predicate once, applies the counter bound to every decoded copy through that
predicate or the selected lineage, and still feeds packages and IDs only when the predicate
holds. An ordinary conflict never becomes sibling evidence. The existing check of a selected valid
body against every same lineage header copy that lists it stays as it was. The correction extends
creation refusal only, never body eligibility.

## What it changes

Creation readiness and counter restorability become false beside such a copy. A boot restores
every eligible body binding without a counter, and a new preparation refuses before any ID, pin
or I/O. Existing eligible bindings still confirm, mark and retire through the unchanged writers.

In the stale backup layout, an owned write to N's existing selected body can resolve its copies.
The tested rebind commit confirms ID 1 over every copy, removing the stale decoded ID 2. A
confirmation or retirement marker can use the same existing writer contract. The store
view is then creation ready again, but that live registry keeps its unknown counter. Only a
restart restores the now coherent selected counter 1, and only then is ID 2 issued. ID 2 is never
burned permanently because of uncertain metadata, and no counter is reset or inferred inside one
instance. Nothing is repaired automatically.

The history view's creation gate composes with this rule without any B2 edit. A reservation
history already requires a creation ready view, so a counter block withdraws a complete header
reservation as every other creation block does. Its UID stays held. Body histories are exactly
as before, so a blocked view restores the same body pins as `0018a1d` and `89491b9`.

## The documented residual

A decoded copy of another lineage outside the existing negative evidence is not part of this
counter space, so it blocks nothing here. That includes an ordinary conflict and a foreign copy
behind a valid selected body. A new numeric ID can therefore meet that decoded copy. Its body then publishes, and a later release is refused by
the conservative check for a live binding of the same ID elsewhere, which strands that ID. This
is the existing residual. It is not a global creation gate, and release authority is deliberately
unchanged. A characterization case keeps it explicit.

## Intended changes to existing outcomes

One existing assertion changes. `NativeCreationBindingTest` case `binding mismatch / two users`
decodes principal ID 2 of user 10 above its version 2 counter 1 in an UNSUPPORTED record, so it
now expects creation readiness false. Its unusable binding, hold and refused completion,
publication, resume, restoration and slot publication are unchanged. A pure surface check requires
the B1 suite to differ from `89491b9` by exactly that one readiness check.

Two B1 mutants, `binding-conflict-evidence-dropped` and
`binding-conflict-evidence-every-conflict`, are anchored to the one evidence predicate. Their
defects and at least lists are unchanged.

Every other host test kept its outcomes in the complete guarded runs. The fixture audit checked
each slot body and decoded copy against its selected counter:

- `NativeIdentityStoreTest` keeps its bodies at or below their counters, and its counter ahead body
  was already blocked.
- `NativeIdentityVersionGateTest` has a user limit body of ID 2 under counter 2, and its version 2
  headers are unsupported under version 1.
- The future format and presence matrices never decode their future frames, including the hidden
  ID 9. The counter 9 copy in the presence test is a header copy, not a slot.
- Persistence, header footprint, preparation fault, principal pin and recovery boot suites keep
  the same admission and restoration outcomes. Published bodies are preceded by their reservations.
- The B1 matrices, layouts and readers keep IDs within their counters, or read version 2 as
  unsupported under version 1.
- `NativeCreationHistoryTest` places its bodies of users 0 and 1 with ID 2 under counters 2 and 3.
- All 47 `NativeHistoryParity` layouts keep their IDs at or below their counters, so the B2 parity
  against `0018a1d` and the new parity against `89491b9` were unchanged in qualification.
- The lab fixtures in `tests/native-identity` do not read load readiness.

The exact list is in `scripts/proof/native_counter_admission_predictions.json`.

## Controls

`NativeCounterAdmissionTest` has 35 cases over the actual records, store, persistence, manager and
host PMS facade. They cover:

- a nonzero user above the counter, a nonzero user within it, and a selected body above it that
  blocks as before;
- a stale copy beside a selected backup, conflicting copies without a backup, a damaged preferred
  backup beside decoded copies, and a body naming another app ID, which invents no ownership;
- an ordinary conflict of another lineage, which stays ready, the documented residual, and an
  unsupported record of another lineage, which blocks;
- a failed complete binding with a higher ID in every copy position, beside an ordinary conflict,
  in another lineage, and beside colliding and unrelated siblings whose evidence is unchanged;
- a decodable staging seed, which never counts, the middle, main only and reserve only copy
  positions, both user orders and both app ID orders, healthy copies at or below the counter, a
  Long.MAX_VALUE claim that never becomes a counter, and an ID equal to the counter, which passes
  and restores exactly that counter;
- an ordinary conflict, which gives no sibling evidence, and the composition with the history view;
- six manager cases. An unsupported higher principal refuses issuance before any effect, with
  real mappings and boot data owners that do not defer Q. A stale higher copy refuses issuance
  until N's own confirmation, which keeps the registry counter unknown until a restart. A healthy
  body rebinds, commits and retires beside a blocked store while N's hold and bytes stay unchanged,
  with synthetic quiescence only. A live registry that observes a higher copy refuses new issuance
  and an earlier unpublished commit without a write, keeping its handle, request and counter.
  Holds and refusals survive reopening, a lost reply and repeated refusals, and no snapshot or pin
  overlaps the decoded claim.

The same source compiles against the pinned `0018a1d` and `89491b9` products as baseline
controls, through only the surface all three share and each side's own `NativeHistoryHarness`,
which the runner fills from that side's own candidate Settings. No product code gains a
compatibility path. Both baselines compiled and failed exactly the same 25 cases, passing the
other ten. Each case prints OBSERVE lines of the facts the correction must not change: header, slot
statuses, eligible bindings, holds, footprint flags and body restore inputs. The runner requires
equal facts on all three sides, and readiness that differs only at the 25 predicted blocked
layouts, where the corrected sources are neither ready nor restorable and both baselines are
ready.

The primary's two probes are copied verbatim, with pinned digests. On both baselines they must
print the reported observations and fail by their own assertions. On the corrected sources they
must print the blocked view and then refuse at preparation. That refusal is recorded as an
observation, never a pass; the focused suite asserts it. `NativeHistoryParity` must print identical
output on `89491b9` and on the corrected sources.

Fifteen mutants compiled and were caught by complete runs: the rule dropped, evidence only,
first copy only, last copy only, same lineage only, every lineage, seeds included, greater or
equal, a counter restored from the largest decoded ID, a footprint flag or status instead of the
block, every ordinary conflict as evidence, binding conflicts ignored, the observed header counter
instead of the selected counter, and the smallest predecessor counter. The normalized selected
value mutant was removed because it duplicated the dropped rule. A compile failure is a harness failure, never a caught defect.

## Host checks

Run `python3 -B scripts/proof/native_counter_admission.py --evidence NEW.json --work NEW_DIR
--pinned-framework PINNED` inside the required bounded scope with a JDK on PATH. `NEW_DIR` must
resolve to at most 29 ASCII characters, such as `/srv/b3w`. The last phase runs the unchanged B2
runner with `NEW_DIR/b2` as its work directory, and that runner still needs its own 32 character
budget for the version 1 presence sockets of the B1 regressions.

Without the bounds, a JDK or a short enough work path, the run reports NOT_RUN before it creates
or starts anything. Otherwise it creates files only under `NEW_DIR` and the evidence file. The
nested B2 runner keeps its own behavior: its B1 runner binds its version 2 presence sockets in a
fresh `/tmp/b1p-*` directory. Unless the JDK is configured otherwise, each JVM also keeps HotSpot's
transient performance data file under `/tmp/hsperfdata_<user>` while it runs.

The phases are candidates, focused, baselines, probes, parity, mutants and the B2 runner. The
report is shared and checkpointed at `NEW_DIR/progress.json` at each phase boundary, as the B2
runner does. An exception or timeout keeps every finished record, the timed out command's decoded
streams, the unfinished phases, status NOT_COMPLETE and exit status 1. Nothing is retried, and PASS
needs every phase. `--source-checks-only` runs the pure checks, and with `--pinned-framework` and a
fresh `--work` it also rebuilds the ten framework outputs with `/usr/bin/patch` only.

The candidates phase requires the ten outputs to equal the `89491b9` profile candidates. Only the
Store's added source hash changes in the profile. The Settings patch section, its fragments and the
other nine outputs are unchanged bytes.

## Worker observations

The worker ran only pure checks, with temporary files in its own scratch directory:

- The runner's source checks passed. They include B2's and B1's source checks, the exact Store,
  profile, fragment and B1 surface against `89491b9`, the probe digests, mutant anchors and the
  prediction consistency.
- Source only mode with the pinned canonical framework copies rebuilt the ten outputs. They equal
  the `89491b9` profile candidates, and only Settings differs from `0018a1d`, as before.
- The 16 new pure runner tests passed, as did the 18 pure B2 runner tests, eight pure B1 runner
  tests, the B0 seam agreement and the recovery fragment and principal pin profile tests. The B1
  test that creates a directory in `/tmp`, and every JVM test, did not run.

No compiler or JVM started in that worker. The primary then ran the actual guarded qualification.
The original 31 cases passed, both baselines failed their exact 22 predicted cases, and all 14
mutants and nested regressions passed their required outcomes.

Independent review and primary additions then pinned the selected counter against a higher
unselected header counter and a lower predecessor counter, foreign slot evidence under otherwise
identical headers and its matching binding twin, and a lost BODY origin that cannot republish
while blocked. The strengthened run passed all 35 cases, the exact 25 failures on each baseline,
15 compiled mutants, unchanged B2 parity and every nested B2, B1, B0 and regression check. All 43
pure counter, history and binding runner tests passed without skips. This run took 7 minutes
14 seconds with a 643 MiB peak under 2 GiB resident memory, zero swap and core dumps, 2 CPUs and
256 tasks. After explicit integration, the complete runner and all 43 pure tests passed again on
Main, with the same exact baseline failures, mutant results and nested regression outcomes. Host
tmpfs results are not Android or power loss results.

## Limits

- Host facades are not Android boot, crash, storage or SELinux evidence, and no Android image
  contains this correction.
- The residual above remains. A claim located only in an unreadable copy is covered by the store's
  own availability gate, not by this rule.
- A blocked store refuses new issuance store wide. Only an owned write to an eligible selected
  body can resolve its own uncertain copies. Unsupported bodies and ordinary conflicts have no
  such write, so they require separately authorized recovery. Nothing here adds that authority.
- A BODY origin handle whose body is now missing cannot republish it while the counter is blocked.
  Retirement returns false without writing, retaining the original pin and obligation. Existing
  published bodies retain their previous confirmation and retirement path.
- Quiescence in the host cases is synthetic. They make no claim about native Stop, data or key
  disposal.
