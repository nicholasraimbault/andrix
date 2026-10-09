// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeLifecycleTestSupport.*;

import android.system.Os;
import com.android.server.pm.NativeIdentityPersistence.SuspensionResult;
import com.android.server.pm.NativeIdentityRecords.ActorClass;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.Lifecycle;
import com.android.server.pm.NativeIdentityRecords.LifecycleState;
import com.android.server.pm.NativeIdentityRecords.Obligation;
import com.android.server.pm.NativeIdentityRecords.ObligationKind;
import com.android.server.pm.NativeIdentityRecords.ObligationState;
import com.android.server.pm.NativeIdentityRecords.Retirement;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.Suspension;
import com.android.server.pm.NativeIdentityRecords.SuspensionReason;
import com.android.server.pm.NativeIdentityStore.Format;
import com.android.server.pm.NativeIdentityStore.History;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * The lifecycle transactions of Package Manager's native identity persistence, on the actual
 * persistence and store with host file facades. Under Format.V3, which no production text
 * constructs: suspend with one entry per actor, a repeated suspension's confirmation with a
 * distinct result when the request differs, and the explicit refusal of a fifth grant or a seventh
 * actor while the account's user keeps its place; lift of exactly the entry its actor placed,
 * never of a recovery hold, writing version 1 again after the last entry; markRetiring with a
 * retirement block that keeps every suspension entry, and a legacy marker's continuation;
 * markRetired with one receipt per retirement kind; the writer rules as invalid requests;
 * publication refusing a suspended binding before the header changes; and the version 1 marker and
 * release refusing before any effect. Under Format.V1 and V2 every lifecycle transaction refuses
 * before any effect, and the version 1 marker and release still work. Host files only, not Android
 * persistence.
 */
public final class NativeLifecycleTransactionTest {
    private static final Slot ELIGIBLE = slotA(1, Lifecycle.version1(false));
    private static final Slot LEGACY = slotA(1, Lifecycle.version1(true));
    private static final Suspension USER = byUser(SuspensionReason.USER_PAUSED);
    private static final Suspension GRANT = byGrant(1, SuspensionReason.CREDENTIAL_EXPOSED);

    private interface Result { SuspensionResult run() throws Exception; }

    // A suspension refused before any effect with exactly this result.
    private static void suspension(List<String> problems, Path root, String what, SuspensionResult expected,
            Result call) throws Exception {
        age(root);
        var before = footprint(root);
        SuspensionResult result = call.run();
        check(problems, result == expected, what + " " + result);
        check(problems, footprint(root).equals(before), what + " changed the store");
    }

    private static List<Suspension> entries(Path root) {
        Slot slot = stored(root, V3);
        return slot == null ? null : slot.users.get(0).lifecycle.suspensions;
    }

    // ------------------------------------------------------------------ suspend

    private static void suspendCases() {
        run("V3 / suspend writes the entries of the account user and of a grant", problems -> {
            Path root = layout(ELIGIBLE);
            NativeIdentityPersistence persistence = persistence(root, V3);
            check(problems, persistence.suspend(RECORD_A, SIGNERS, GRANT) == SuspensionResult.SUSPENDED,
                    "grant refused");
            check(problems, persistence.suspend(RECORD_A, SIGNERS, USER) == SuspensionResult.SUSPENDED,
                    "user refused");
            Slot expected = slotA(3, eligible(USER, GRANT));
            check(problems, expected.equals(stored(root, V3)) && holds(root, expected, 2), "wrote " + stored(root, V3));
            History history = load(root, V3).history(A);
            check(problems, history != null && history.state == LifecycleState.ELIGIBLE && !history.eligible()
                    && history.suspensions.equals(List.of(USER, GRANT)), "history " + history);
            NativeIdentityPersistence.Restoration restoration =
                    NativeIdentityPersistence.restoration(load(root, V3).histories());
            check(problems, restoration.records.size() == 1 && restoration.retiringIds.isEmpty(),
                    "a suspension restored as a pin phase");
            check(problems, expected.equals(persistence.binding(RECORD_A)), "binding " + persistence.binding(RECORD_A));
        });
        run("V3 / a repeated suspension by the same actor confirms its entry unchanged", problems -> {
            Slot durable = slotA(2, eligible(USER, GRANT));
            Path root = layout(durable);
            NativeIdentityPersistence persistence = persistence(root, V3);
            byte[] before = mainBytes(root);
            for (Suspension repeat : List.of(USER, GRANT)) {
                age(root);
                var footprint = footprint(root);
                check(problems, persistence.suspend(RECORD_A, SIGNERS, repeat) == SuspensionResult.SUSPENDED,
                        "repeat refused: " + repeat);
                check(problems, durable.equals(stored(root, V3)) && Arrays.equals(before, mainBytes(root)),
                        "the existing entries changed: " + stored(root, V3));
                // Confirmed through the checked writers, not by readback.
                check(problems, !footprint(root).equals(footprint), "the repeat was not confirmed through a write");
            }
        });
        run("V3 / a repeated suspension that differs holds the actor's entry unchanged", problems -> {
            Slot durable = slotA(2, eligible(USER, GRANT));
            Path root = layout(durable);
            NativeIdentityPersistence persistence = persistence(root, V3);
            // The same actor with another reason, a later time and a note, and the same grant
            // reference placed by another Android user or with another reason.
            List<Suspension> repeats = List.of(byUser(SuspensionReason.SUSPECTED_COMPROMISE),
                    new Suspension(ActorClass.ACCOUNT_USER, 0, 0, SERIAL, ZERO, USER.reason, TIME + 50, "9".repeat(64)),
                    NativeLifecycleTestSupport.entry(ActorClass.ADMIN_GRANT, 0, 10, 3, GRANT.grant,
                            SuspensionReason.CREDENTIAL_EXPOSED, GRANT.time),
                    byGrant(1, SuspensionReason.DATA_TRANSFER));
            for (Suspension repeat : repeats) {
                age(root);
                var footprint = footprint(root);
                check(problems, persistence.suspend(RECORD_A, SIGNERS, repeat) == SuspensionResult.HELD_UNCHANGED,
                        "repeat not held unchanged: " + repeat);
                check(problems, durable.equals(stored(root, V3)), "the entry changed for " + repeat);
                check(problems, !footprint(root).equals(footprint), "not confirmed through a write: " + repeat);
            }
            // A later writer's entry with scope bit 0 keeps its scope beside a request of this stage.
            Suspension blocking = NativeLifecycleTestSupport.entry(ActorClass.ADMIN_GRANT,
                    NativeIdentityRecords.SCOPE_BLOCKS_DISPOSITION, 0, SERIAL, grant(2), SuspensionReason.DATA_TRANSFER,
                    TIME);
            Slot scoped = slotA(2, eligible(blocking));
            Path other = layout(scoped);
            check(problems, persistence(other, V3).suspend(RECORD_A, SIGNERS, NativeLifecycleTestSupport.entry(
                    ActorClass.ADMIN_GRANT, 0, 0, SERIAL, grant(2), SuspensionReason.DATA_TRANSFER, TIME))
                    == SuspensionResult.HELD_UNCHANGED && scoped.equals(stored(other, V3)), "another scope");
        });
        run("V3 / a fifth grant is full beside the account user's place and applies once a grant is lifted",
                problems -> {
            Path root = layout(ELIGIBLE);
            NativeIdentityPersistence persistence = persistence(root, V3);
            List<Suspension> grants = new ArrayList<>();
            for (int grant = 1; grant <= 4; grant++) grants.add(byGrant(grant, SuspensionReason.DATA_TRANSFER));
            for (Suspension entry : grants) {
                check(problems, persistence.suspend(RECORD_A, SIGNERS, entry) == SuspensionResult.SUSPENDED,
                        "refused " + entry);
            }
            Suspension fifth = byGrant(9, SuspensionReason.SUSPECTED_COMPROMISE);
            suspension(problems, root, "a fifth grant", SuspensionResult.FULL,
                    () -> persistence.suspend(RECORD_A, SIGNERS, fifth));
            // The account's user keeps its place beside four grants.
            check(problems, persistence.suspend(RECORD_A, SIGNERS, USER) == SuspensionResult.SUSPENDED,
                    "the account's user lost its place");
            check(problems, entries(root).size() == 5 && entries(root).contains(USER), "entries " + entries(root));
            // The pending grant applies as soon as a grant's place is free.
            check(problems, persistence.lift(RECORD_A, SIGNERS, grants.get(1)), "lift refused");
            check(problems, persistence.suspend(RECORD_A, SIGNERS, fifth) == SuspensionResult.SUSPENDED,
                    "the pending grant did not apply");
            check(problems, entries(root).contains(fifth) && entries(root).size() == 5, "entries " + entries(root));
        });
        run("V3 / a seventh actor is full beside six entries", problems -> {
            // The plan's six: the user, a recovery hold and four grants.
            Path planned = layout(slotA(2, eligible(USER, hold(0), byGrant(1, SuspensionReason.DATA_TRANSFER),
                    byGrant(2, SuspensionReason.DATA_TRANSFER), byGrant(3, SuspensionReason.DATA_TRANSFER),
                    byGrant(4, SuspensionReason.DATA_TRANSFER))));
            suspension(problems, planned, "a fifth grant", SuspensionResult.FULL, () -> persistence(planned, V3)
                    .suspend(RECORD_A, SIGNERS, byGrant(9, SuspensionReason.SUSPECTED_COMPROMISE)));
            // A later writer's six grants leave the account's user no place either.
            Suspension[] six = new Suspension[6];
            for (int i = 0; i < six.length; i++) six[i] = byGrant(i + 1, SuspensionReason.DATA_TRANSFER);
            Path later = layout(slotA(2, eligible(six)));
            suspension(problems, later, "the user beside six grants", SuspensionResult.FULL,
                    () -> persistence(later, V3).suspend(RECORD_A, SIGNERS, USER));
        });
        run("V3 / suspend refuses requests no writer writes before any effect", problems -> {
            Path root = layout(ELIGIBLE);
            NativeIdentityPersistence persistence = persistence(root, V3);
            List<Suspension> requests = List.of(
                    NativeLifecycleTestSupport.entry(ActorClass.ADMIN_GRANT, NativeIdentityRecords.SCOPE_BLOCKS_DISPOSITION,
                            0, SERIAL, grant(1), SuspensionReason.DATA_TRANSFER, TIME),
                    new Suspension(ActorClass.ADMIN_GRANT, 0, 0, SERIAL, grant(1), 0, TIME, null),
                    new Suspension(ActorClass.ACCOUNT_USER, 0, 0, SERIAL, ZERO, 8, TIME, null),
                    byGrant(1, SuspensionReason.USER_PAUSED), byUser(SuspensionReason.RECOVERY_REVIEW),
                    NativeLifecycleTestSupport.entry(ActorClass.ACCOUNT_USER, 0, 0, SERIAL + 1, ZERO,
                            SuspensionReason.USER_PAUSED, TIME),
                    NativeLifecycleTestSupport.entry(ActorClass.ACCOUNT_USER, 0, 10, SERIAL, ZERO,
                            SuspensionReason.USER_PAUSED, TIME),
                    hold(0), hold(NativeIdentityRecords.SCOPE_PRIOR_UNKNOWN));
            for (Suspension request : requests) {
                invalid(problems, root, "request " + request, () -> {
                    persistence.suspend(RECORD_A, SIGNERS, request);
                    return true;
                });
            }
        });
    }

    // ------------------------------------------------------------------ lift

    private static void liftCases() {
        run("V3 / only the actor that placed an entry lifts it", problems -> {
            Suspension second = byGrant(2, SuspensionReason.DATA_TRANSFER);
            Path root = layout(slotA(2, eligible(USER, GRANT, second)));
            NativeIdentityPersistence persistence = persistence(root, V3);
            unchanged(problems, root, "the grant by another user", () -> persistence.lift(RECORD_A, SIGNERS,
                    NativeLifecycleTestSupport.entry(ActorClass.ADMIN_GRANT, 0, 10, 3, GRANT.grant,
                            SuspensionReason.CREDENTIAL_EXPOSED, GRANT.time)));
            unchanged(problems, root, "the grant with another reason",
                    () -> persistence.lift(RECORD_A, SIGNERS, byGrant(1, SuspensionReason.DATA_TRANSFER)));
            check(problems, persistence.lift(RECORD_A, SIGNERS, GRANT), "the exact entry was not lifted");
            check(problems, List.of(USER, second).equals(entries(root)), "entries " + entries(root));
            // An actor without an entry lifts nothing of another actor.
            check(problems, persistence.lift(RECORD_A, SIGNERS, byGrant(3, SuspensionReason.DATA_TRANSFER)),
                    "an absent entry's lift was not confirmed");
            check(problems, List.of(USER, second).equals(entries(root)), "entries " + entries(root));
        });
        run("V3 / lifting the last suspension writes version 1 again", problems -> {
            Path root = layout(slotA(2, eligible(USER)));
            check(problems, persistence(root, V3).lift(RECORD_A, SIGNERS, USER), "lift refused");
            Slot plain = slotA(3, Lifecycle.version1(false));
            check(problems, plain.equals(stored(root, V3)) && holds(root, plain, 1), "wrote " + stored(root, V3));
            for (Format format : List.of(V1, V2, V3)) {
                History history = load(root, format).history(A);
                check(problems, history != null && history.eligible(), format + " history " + history);
            }
        });
        run("V3 / a lift once durable is confirmed again", problems -> {
            Path root = layout(slotA(2, eligible(USER, GRANT)));
            NativeIdentityPersistence persistence = persistence(root, V3);
            check(problems, persistence.lift(RECORD_A, SIGNERS, GRANT), "lift refused");
            Slot lifted = slotA(3, eligible(USER));
            age(root);
            var before = footprint(root);
            check(problems, persistence.lift(RECORD_A, SIGNERS, GRANT), "the retry was refused");
            check(problems, lifted.equals(stored(root, V3)) && holds(root, lifted, 2), "the retry changed the value");
            check(problems, !footprint(root).equals(before), "the retry was not confirmed through a write");
        });
        run("V3 / lift refuses a recovery hold and another user's account user entry as invalid requests",
                problems -> {
            Path root = layout(slotA(2, eligible(USER, hold(0))));
            NativeIdentityPersistence persistence = persistence(root, V3);
            invalid(problems, root, "a hold", () -> persistence.lift(RECORD_A, SIGNERS, hold(0)));
            invalid(problems, root, "an account user entry of another user", () -> persistence.lift(RECORD_A, SIGNERS,
                    NativeLifecycleTestSupport.entry(ActorClass.ACCOUNT_USER, 0, 10, SERIAL, ZERO,
                            SuspensionReason.USER_PAUSED, TIME)));
        });
    }

    // ------------------------------------------------------------------ markRetiring

    private static void retireCases() {
        run("V3 / markRetiring writes the block and keeps every suspension entry", problems -> {
            Path root = layout(slotA(2, eligible(USER, GRANT, hold(0))));
            check(problems, persistence(root, V3).markRetiring(RECORD_A, SIGNERS, byUserRetirement()), "refused");
            Slot expected = slotA(3, retiring(byUserRetirement(), USER, GRANT, hold(0)));
            check(problems, expected.equals(stored(root, V3)) && holds(root, expected, 2), "wrote " + stored(root, V3));
            History history = load(root, V3).history(A);
            check(problems, history != null && history.state == LifecycleState.RETIRING && history.retiring
                    && history.suspensions.equals(List.of(USER, GRANT, hold(0))), "history " + history);
            check(problems, NativeIdentityPersistence.restoration(load(root, V3).histories()).retiringIds
                    .equals(Set.of(ID_A)), "no RETIRING pin");
        });
        run("V3 / markRetiring confirms its own retirement and refuses any other", problems -> {
            Path root = layout(ELIGIBLE);
            NativeIdentityPersistence persistence = persistence(root, V3);
            check(problems, persistence.markRetiring(RECORD_A, SIGNERS, byUserRetirement()), "refused");
            Slot retiringA = slotA(2, retiring(byUserRetirement()));
            age(root);
            var before = footprint(root);
            check(problems, persistence.markRetiring(RECORD_A, SIGNERS, byUserRetirement()), "the retry was refused");
            check(problems, retiringA.equals(stored(root, V3)) && !footprint(root).equals(before),
                    "the retry was not a confirmation");
            unchanged(problems, root, "a grant's block", () -> persistence.markRetiring(RECORD_A, SIGNERS,
                    byGrantRetirement()));
            unchanged(problems, root, "another time", () -> persistence.markRetiring(RECORD_A, SIGNERS,
                    retirement(ActorClass.ACCOUNT_USER, 0, SERIAL, ZERO, TIME + 101)));
            check(problems, persistence.markRetired(RECORD_A, SIGNERS, receipts()), "markRetired refused");
            unchanged(problems, root, "a retired account", () -> persistence.markRetiring(RECORD_A, SIGNERS,
                    byUserRetirement()));
        });
        run("V3 / markRetiring refuses blocks no writer writes before any effect", problems -> {
            Path root = layout(ELIGIBLE);
            NativeIdentityPersistence persistence = persistence(root, V3);
            List<Retirement> blocks = List.of(retirement(ActorClass.USER_REMOVAL, 0, SERIAL, ZERO, TIME),
                    retirement(ActorClass.ACCOUNT_USER, 10, SERIAL, ZERO, TIME),
                    retirement(ActorClass.ACCOUNT_USER, 0, SERIAL + 1, ZERO, TIME), legacyMarker(),
                    NativeLifecycleTestSupport.with(byUserRetirement(),
                            obligation(ObligationKind.HOME, ObligationState.DISCHARGED, ZERO, 0, 0)));
            for (Retirement block : blocks) {
                invalid(problems, root, "block " + block, () -> persistence.markRetiring(RECORD_A, SIGNERS, block));
            }
        });
        run("V3 / a legacy marker continues once through markRetiring", problems -> {
            Path root = layout(LEGACY);
            NativeIdentityPersistence persistence = persistence(root, V3);
            unchanged(problems, root, "a new actor over the marker", () -> persistence.markRetiring(RECORD_A, SIGNERS,
                    byUserRetirement()));
            check(problems, persistence.markRetiring(RECORD_A, SIGNERS, legacyContinued()), "continuation refused");
            Slot continued = slotA(2, retiring(legacyContinued()));
            check(problems, continued.equals(stored(root, V3)) && holds(root, continued, 2),
                    "continuation wrote " + stored(root, V3));
            check(problems, persistence.markRetiring(RECORD_A, SIGNERS, legacyContinued()), "its retry was refused");
            check(problems, persistence.markRetired(RECORD_A, SIGNERS, receipts()), "markRetired refused");
            Slot retiredA = slotA(3, retired(discharged(legacyContinued(), receipts())));
            check(problems, retiredA.equals(stored(root, V3)), "retired " + stored(root, V3));
        });
        run("V3 / markRetiring never creates a legacy marker", problems -> {
            Path root = layout(ELIGIBLE);
            unchanged(problems, root, "a legacy block over an eligible account",
                    () -> persistence(root, V3).markRetiring(RECORD_A, SIGNERS, legacyContinued()));
        });
    }

    // ------------------------------------------------------------------ markRetired

    private static void retiredCases() {
        run("V3 / markRetired discharges the retirement kinds and confirms its retry", problems -> {
            Path root = layout(slotA(2, eligible(USER)));
            NativeIdentityPersistence persistence = persistence(root, V3);
            check(problems, persistence.markRetiring(RECORD_A, SIGNERS, byGrantRetirement())
                    && persistence.markRetired(RECORD_A, SIGNERS, receipts()), "refused");
            Slot retiredA = slotA(4, retired(discharged(byGrantRetirement(), receipts()), USER));
            check(problems, retiredA.equals(stored(root, V3)) && holds(root, retiredA, 2), "wrote " + stored(root, V3));
            age(root);
            var before = footprint(root);
            check(problems, persistence.markRetired(RECORD_A, SIGNERS, receipts()), "the retry was refused");
            check(problems, retiredA.equals(stored(root, V3)) && !footprint(root).equals(before),
                    "the retry was not a confirmation");
            List<Obligation> other = new ArrayList<>(receipts());
            other.set(1, obligation(ObligationKind.API_EFFECTS, ObligationState.DISCHARGED, ZERO, 77, TIME));
            unchanged(problems, root, "other receipts", () -> persistence.markRetired(RECORD_A, SIGNERS, other));
        });
        run("V3 / markRetired refuses until every retirement kind can be discharged", problems -> {
            List<Slot> durables = List.of(ELIGIBLE, slotA(2, eligible(USER)), LEGACY,
                    slotA(2, retiring(NativeLifecycleTestSupport.with(byUserRetirement(),
                            obligation(ObligationKind.WORK, ObligationState.ORPHANED_WITH_USER, ZERO, 0, 0)))),
                    slotA(2, retiring(NativeLifecycleTestSupport.with(byUserRetirement(),
                            obligation(ObligationKind.WORK, ObligationState.OUTSTANDING, "77".repeat(16), 0, 0)))));
            for (Slot durable : durables) {
                Path root = layout(durable);
                unchanged(problems, root, "durable " + durable,
                        () -> persistence(root, V3).markRetired(RECORD_A, SIGNERS, receipts()));
            }
        });
        run("V3 / markRetired refuses receipts that are not one of each retirement kind before any effect", problems -> {
            Path root = layout(slotA(2, retiring(byUserRetirement())));
            NativeIdentityPersistence persistence = persistence(root, V3);
            List<Obligation> receipts = receipts();
            List<Obligation> ten = new ArrayList<>(receipts);
            ten.add(obligation(ObligationKind.ANDROID_STATE, ObligationState.DISCHARGED, ZERO, 0, 0));
            List<Obligation> swapped = new ArrayList<>(receipts);
            swapped.set(0, receipts.get(1));
            swapped.set(1, receipts.get(0));
            List<Obligation> open = new ArrayList<>(receipts);
            open.set(4, obligation(ObligationKind.LEASE_OPERATIONS, ObligationState.OUTSTANDING, ZERO, 0, 0));
            for (List<Obligation> list : List.of(receipts.subList(0, 8), ten, swapped, open, List.<Obligation>of())) {
                invalid(problems, root, "receipts " + list, () -> persistence.markRetired(RECORD_A, SIGNERS, list));
            }
        });
        run("V3 / a retired account keeps its entries and restores a RETIRING pin", problems -> {
            Path root = layout(ELIGIBLE);
            NativeIdentityPersistence persistence = persistence(root, V3);
            check(problems, persistence.suspend(RECORD_A, SIGNERS, USER) == SuspensionResult.SUSPENDED
                    && persistence.markRetiring(RECORD_A, SIGNERS, byUserRetirement())
                    && persistence.markRetired(RECORD_A, SIGNERS, receipts()), "the flow was refused");
            History history = load(root, V3).history(A);
            check(problems, history != null && history.state == LifecycleState.RETIRED && history.retiring
                    && history.suspensions.equals(List.of(USER)), "history " + history);
            NativeIdentityPersistence.Restoration restoration =
                    NativeIdentityPersistence.restoration(load(root, V3).histories());
            check(problems, restoration.retiringIds.equals(Set.of(ID_A)) && restoration.records.size() == 1,
                    "restoration " + restoration.retiringIds);
            check(problems, NativeIdentityPersistence.scanOwner(history, PKG_A, A, false, PKG_A, false, SERIAL) == null,
                    "a retired account owns the scan");
        });
    }

    // ------------------------------------------------------------------ publication and the old path

    private static void publicationCases() {
        run("V3 / publish refuses a suspended binding before any effect", problems -> {
            Header creating = creatingA();
            Path root = store(creating);
            slot(root, slotA(1, eligible(USER)));
            NativeIdentityPersistence persistence = persistence(root, V3);
            unchanged(problems, root, "publication", () -> persistence.publish(RECORD_A, SIGNERS));
            check(problems, creating.equals(load(root, V3).header.value), "the header changed");
            // Lifted, the same binding publishes and its header completes.
            check(problems, persistence.lift(RECORD_A, SIGNERS, USER) && persistence.publish(RECORD_A, SIGNERS),
                    "the lifted binding did not publish");
            check(problems, Header.newV2(LINEAGE, ID_A, List.of(live(A))).equals(load(root, V3).header.value),
                    "header " + load(root, V3).header.value);
        });
        run("V3 / publish refuses a retiring or retired binding before any effect", problems -> {
            for (Slot body : List.of(slotA(1, retiring(byUserRetirement())),
                    slotA(1, retired(discharged(byUserRetirement(), receipts()))))) {
                Path root = store(creatingA());
                slot(root, body);
                unchanged(problems, root, "publication of " + body,
                        () -> persistence(root, V3).publish(RECORD_A, SIGNERS));
            }
        });
        run("V3 / the version 1 marker refuses before any effect", problems -> {
            for (Slot durable : List.of(ELIGIBLE, slotA(2, eligible(USER)), slotA(2, retiring(byUserRetirement())),
                    LEGACY, slotA(2, retired(discharged(byUserRetirement(), receipts()))))) {
                Path root = layout(durable);
                unchanged(problems, root, "the marker over " + durable,
                        () -> persistence(root, V3).markRetiring(RECORD_A, SIGNERS));
            }
        });
        run("V3 / the version 1 release refuses before any effect", problems -> {
            Slot ready = slotA(3, retired(allDischarged(byUserRetirement())));
            Path live = layout(ready);
            unchanged(problems, live, "release under LIVE", () -> persistence(live, V3).finishRetirement(RECORD_A,
                    LINEAGE, SIGNERS));
            Path creating = store(creatingA());
            slot(creating, slotA(1, retired(allDischarged(byUserRetirement()))));
            unchanged(problems, creating, "release under CREATING", () -> persistence(creating, V3).finishRetirement(
                    RECORD_A, LINEAGE, SIGNERS));
            Path released = store(header(ID_A));
            unchanged(problems, released, "release confirmation", () -> persistence(released, V3).finishRetirement(
                    RECORD_A, LINEAGE, SIGNERS));
        });
    }

    // ------------------------------------------------------------------ what a transaction needs

    private static void bindingCases() {
        run("V3 / every lifecycle transaction needs only an intact binding", problems -> {
            Path root = damagedHeader();
            slot(root, ELIGIBLE);
            NativeIdentityPersistence persistence = persistence(root, V3);
            check(problems, persistence.suspend(RECORD_A, SIGNERS, USER) == SuspensionResult.SUSPENDED,
                    "suspend refused");
            check(problems, persistence.suspend(RECORD_A, SIGNERS, GRANT) == SuspensionResult.SUSPENDED,
                    "a second suspend refused");
            check(problems, persistence.lift(RECORD_A, SIGNERS, GRANT), "lift refused");
            check(problems, persistence.markRetiring(RECORD_A, SIGNERS, byUserRetirement()), "markRetiring refused");
            check(problems, persistence.markRetired(RECORD_A, SIGNERS, receipts()), "markRetired refused");
            // Five writes from generation 1, with every header copy damaged throughout.
            check(problems, slotA(6, retired(discharged(byUserRetirement(), receipts()), USER)).equals(
                    stored(root, V3)) && load(root, V3).header.status == NativeIdentityStore.Status.DAMAGED,
                    "wrote " + stored(root, V3));
        });
        run("V3 / a damaged, foreign or unbound record is never written", problems -> {
            Path damaged = store(header(ID_A, live(A)));
            raw(damaged, A, new byte[] {1, 2, 3}, new byte[] {4, 5, 6});
            NativePrincipalPins.Record otherSerial = new NativePrincipalPins.Record(ID_A, PKG_A, A, 0, SERIAL + 1);
            NativePrincipalPins.Record otherUser = new NativePrincipalPins.Record(ID_A, PKG_A, A, 10, SERIAL);
            NativePrincipalPins.Record otherId = new NativePrincipalPins.Record(ID_B, PKG_A, A, 0, SERIAL);
            Path bound = layout(slotA(2, retiring(byUserRetirement(), GRANT)));
            for (Path root : List.of(damaged, bound)) {
                List<NativePrincipalPins.Record> records = root == damaged ? List.of(RECORD_A)
                        : List.of(otherSerial, otherUser, otherId);
                for (NativePrincipalPins.Record record : records) {
                    Set<String> signers = SIGNERS;
                    NativeIdentityPersistence persistence = persistence(root, V3);
                    Suspension grantEntry = byGrant(2, SuspensionReason.DATA_TRANSFER);
                    suspension(problems, root, "suspend " + record, SuspensionResult.REFUSED,
                            () -> persistence.suspend(record, signers, grantEntry));
                    unchanged(problems, root, "lift " + record, () -> persistence.lift(record, signers, GRANT));
                    unchanged(problems, root, "markRetired " + record,
                            () -> persistence.markRetired(record, signers, receipts()));
                }
            }
            NativeIdentityPersistence persistence = persistence(bound, V3);
            suspension(problems, bound, "other signers", SuspensionResult.REFUSED,
                    () -> persistence.suspend(RECORD_A, OTHER_SIGNERS, byGrant(2, SuspensionReason.DATA_TRANSFER)));
            unchanged(problems, bound, "lift with other signers", () -> persistence.lift(RECORD_A, OTHER_SIGNERS, GRANT));
            Path eligibleA = layout(ELIGIBLE);
            unchanged(problems, eligibleA, "markRetiring with other signers",
                    () -> persistence(eligibleA, V3).markRetiring(RECORD_A, OTHER_SIGNERS, byUserRetirement()));
        });
    }

    // ------------------------------------------------------------------ earlier formats

    private static void earlierCases() {
        for (Format format : EARLIER) {
            run(format + " / every lifecycle transaction refuses before any effect", problems -> {
                Path root = layout(ELIGIBLE);
                NativeIdentityPersistence persistence = persistence(root, format);
                suspension(problems, root, "suspend", SuspensionResult.REFUSED,
                        () -> persistence.suspend(RECORD_A, SIGNERS, USER));
                // No entry exists, so under the lifecycle format this lift would confirm.
                unchanged(problems, root, "lift", () -> persistence.lift(RECORD_A, SIGNERS, USER));
                unchanged(problems, root, "markRetiring", () -> persistence.markRetiring(RECORD_A, SIGNERS,
                        byUserRetirement()));
                unchanged(problems, root, "markRetired", () -> persistence.markRetired(RECORD_A, SIGNERS, receipts()));
                Path legacy = layout(LEGACY);
                NativeIdentityPersistence marked = persistence(legacy, format);
                unchanged(problems, legacy, "a continuation", () -> marked.markRetiring(RECORD_A, SIGNERS,
                        legacyContinued()));
                unchanged(problems, legacy, "a lift beside the marker", () -> marked.lift(RECORD_A, SIGNERS, USER));
                unchanged(problems, legacy, "markRetired of the marker", () -> marked.markRetired(RECORD_A, SIGNERS,
                        receipts()));
            });
            run(format + " / the version 1 marker and release still work", problems -> {
                Path root = layout(ELIGIBLE);
                NativeIdentityPersistence persistence = persistence(root, format);
                check(problems, persistence.markRetiring(RECORD_A, SIGNERS), "the marker was refused");
                check(problems, LEGACY.equals(new Slot(LINEAGE, A, PKG_A, 1, SIGNERS, stored(root, format).users))
                        && stored(root, format).generation == 2, "marked " + stored(root, format));
                check(problems, persistence.markRetiring(RECORD_A, SIGNERS), "the marker's confirmation was refused");
                check(problems, persistence.finishRetirement(RECORD_A, LINEAGE, SIGNERS), "the release was refused");
                check(problems, header(ID_A).equals(load(root, format).header.value)
                        && !Files.exists(root.resolve("slots/" + A)), "released " + load(root, format).header.value);
            });
        }
    }

    public static void main(String[] args) throws Exception {
        if (!NativeLifecycleTransactionTest.class.desiredAssertionStatus()) {
            throw new AssertionError("run with java -ea");
        }
        start(Path.of(args[0]).resolve("lifecycle-transactions"));
        suspendCases();
        liftCases();
        retireCases();
        retiredCases();
        publicationCases();
        bindingCases();
        earlierCases();
        finish(Os.allClosed());
        System.out.println("Lifecycle transactions kept the record's rules and refusals; Android unqualified");
    }
}
