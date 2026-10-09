// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeLifecycleTestSupport.*;

import android.system.Os;
import com.android.server.pm.NativeIdentityPersistence.SuspensionResult;
import com.android.server.pm.NativeIdentityRecords.ActorClass;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.HeaderEntry;
import com.android.server.pm.NativeIdentityRecords.Lifecycle;
import com.android.server.pm.NativeIdentityRecords.LifecycleState;
import com.android.server.pm.NativeIdentityRecords.Obligation;
import com.android.server.pm.NativeIdentityRecords.ObligationKind;
import com.android.server.pm.NativeIdentityRecords.ObligationState;
import com.android.server.pm.NativeIdentityRecords.Retirement;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.Suspension;
import com.android.server.pm.NativeIdentityRecords.SuspensionReason;
import com.android.server.pm.NativeIdentityRecords.UserEntry;
import com.android.server.pm.NativeIdentityStore.Format;
import com.android.server.pm.NativeIdentityStore.History;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
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
 * publication refusing a suspended binding before the header changes; the version 1 marker and
 * release refusing before any effect; the boot facts of one durable read; beginDisposition and
 * confirmDisposition only in a boot that began with the account RETIRED; restore, whose hold
 * keeps the restored record from becoming active directly; and the gated release engine, which
 * starts only in a retired boot and continues only from durable state, in a boot that began with
 * its ticketed tombstone or with its RELEASING entry and no directory. Under Format.V1 and V2 every
 * lifecycle transaction refuses before any effect, and the version 1 marker and release still work.
 * Host files only, not Android persistence.
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

    // ------------------------------------------------------------------ boot facts and disposition

    private static final int C = 10202, D = 10203, E = 10204, F = 10205, G = 10206, H = 10207;

    private static Slot tombstone(int appId, String packageName, long id, long generation) {
        return new Slot(LINEAGE, appId, packageName, generation, SIGNERS, List.of(),
                new NativeIdentityRecords.ReleaseTicket(id, 0, SERIAL, "5".repeat(31) + id));
    }

    // This header's intact frame relabeled version 3, above every format's header ceiling.
    private static byte[] newer(Header header) throws Exception {
        byte[] bytes = NativeIdentityRecords.encodeHeader(header);
        bytes[6] = 3;
        bytes[7] = 0;
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(Arrays.copyOf(bytes, bytes.length - 32));
        System.arraycopy(digest, 0, bytes, bytes.length - 32, 32);
        return bytes;
    }

    private static NativeIdentityRecords.HeaderEntry releasing(int appId) {
        return new NativeIdentityRecords.HeaderEntry(appId, NativeIdentityRecords.SlotPhase.RELEASING, 0, "");
    }

    private static void bootFactCases() {
        run("V3 / the boot facts name RETIRED accounts, ticketed tombstones and RELEASING entries without a directory",
                problems -> {
            Path root = store(header(7, live(A), live(B), live(C), releasing(D), releasing(E), live(F), releasing(G),
                    releasing(H)));
            slot(root, slotA(3, retired(retiredBlock(), USER)));
            slot(root, slotB(2, retiring(byUserRetirement())));
            Slot ticketed = tombstone(C, "dev.andrix.lifecyclec", 3, 4);
            slot(root, ticketed);
            Slot releasingTombstone = tombstone(E, "dev.andrix.lifecyclee", 5, 6);
            slot(root, releasingTombstone);
            // A tombstone without a ticket is version 1, and no fact.
            slot(root, new Slot(LINEAGE, F, "dev.andrix.lifecyclef", 2, SIGNERS, List.of()));
            // Release emptied G's directory, and D's is gone. H's copies are damage, which is no fact.
            Files.createDirectories(root.resolve("slots/" + G));
            raw(root, H, new byte[] {1}, new byte[] {2});
            NativeIdentityPersistence.BootFacts facts = facts(root);
            check(problems, facts.retired.equals(java.util.Map.of(A, RECORD_A)), "retired " + facts.retired);
            check(problems, facts.ticketedTombstones.equals(java.util.Map.of(C, ticketed, E, releasingTombstone)),
                    "tombstones " + facts.ticketedTombstones);
            check(problems, facts.releasingWithoutDirectory.equals(Set.of(D, G)),
                    "releasing " + facts.releasingWithoutDirectory);
            check(problems, facts.retiredBoot(RECORD_A) && !facts.retiredBoot(new NativePrincipalPins.Record(ID_A,
                    PKG_A, A, 0, SERIAL + 1)), "the retired boot rule");
            try {
                facts.retired.clear();
                problems.add("the facts changed");
            } catch (UnsupportedOperationException expected) {
                // Immutable.
            }
            // The earlier formats read no version 2 slot, so they give no RETIRED account or ticket.
            NativeIdentityPersistence.BootFacts earlier = NativeIdentityPersistence.bootFacts(load(root, V2));
            check(problems, earlier.retired.isEmpty() && earlier.ticketedTombstones.isEmpty(), "V2 facts");
            // A damaged RETIRED record gives no fact.
            Path damaged = store(header(ID_A, live(A)));
            raw(damaged, A, NativeIdentityRecords.encodeSlot(slotA(3, retired(retiredBlock()))), new byte[] {1});
            Files.write(damaged.resolve("slots/" + A + "/record.bin-backup"), new byte[] {2});
            check(problems, facts(damaged).retired.isEmpty(), "damage gave a fact");
        });
        run("V3 / the boot facts give no fact beside a newer header", problems -> {
            Header held = header(7, live(A), live(C));
            Path root = store(held);
            slot(root, slotA(3, retired(retiredBlock())));
            slot(root, tombstone(C, "dev.andrix.lifecyclec", 3, 4));
            check(problems, facts(root).retired.size() == 1 && facts(root).ticketedTombstones.size() == 1,
                    "the control gave no facts");
            // An intact header copy above the format's ceiling withdraws every binding and fact.
            Files.write(root.resolve("store.bin"), newer(held));
            NativeIdentityPersistence.BootFacts facts = facts(root);
            check(problems, load(root, V3).header.status == NativeIdentityStore.Status.UNSUPPORTED,
                    "the header read " + load(root, V3).header.status);
            check(problems, facts.retired.isEmpty() && facts.ticketedTombstones.isEmpty()
                    && facts.releasingWithoutDirectory.isEmpty(), "facts " + facts.retired + " "
                    + facts.ticketedTombstones);
        });
        run("V3 / the boot facts give no fact beside an unreadable header copy", problems -> {
            Header held = header(7, live(A), live(C));
            Path root = store(held);
            slot(root, slotA(3, retired(retiredBlock())));
            slot(root, tombstone(C, "dev.andrix.lifecyclec", 3, 4));
            Path backup = Files.write(root.resolve("store.bin-backup"), NativeIdentityRecords.encodeHeader(held));
            check(problems, facts(root).retired.size() == 1 && facts(root).ticketedTombstones.size() == 1,
                    "the control gave no facts");
            // A header copy whose bytes cannot be read may be newer: it withdraws every binding and fact.
            // Only the fixture's own mode changes, and it is restored even when a check fails.
            Set<PosixFilePermission> mode = Files.getPosixFilePermissions(backup, LinkOption.NOFOLLOW_LINKS);
            Files.setPosixFilePermissions(backup, PosixFilePermissions.fromString("---------"));
            try {
                NativeIdentityStore.Loaded loaded = load(root, V3);
                check(problems, loaded.header.unavailable && loaded.enumerationComplete, "the unreadable copy was read");
                NativeIdentityPersistence.BootFacts facts = NativeIdentityPersistence.bootFacts(loaded);
                check(problems, facts.retired.isEmpty() && facts.ticketedTombstones.isEmpty()
                        && facts.releasingWithoutDirectory.isEmpty(), "facts " + facts.retired + " "
                        + facts.ticketedTombstones);
            } finally {
                Files.setPosixFilePermissions(backup, mode);
            }
        });
        run("V3 / disposition waits for a boot that began with the account RETIRED", problems -> {
            Path root = layout(slotA(2, retiring(byUserRetirement())));
            // The boot facts of the boot in which the account becomes RETIRED.
            NativeIdentityPersistence.BootFacts same = facts(root);
            NativeIdentityPersistence persistence = persistence(root, V3);
            check(problems, persistence.markRetired(RECORD_A, SIGNERS, receipts()), "markRetired refused");
            unchanged(problems, root, "the deletion step in the same boot",
                    () -> persistence.beginDisposition(RECORD_A, SIGNERS, same));
            // A fresh boot began with the account RETIRED.
            NativeIdentityPersistence.BootFacts fresh = facts(root);
            check(problems, persistence(root, V3).beginDisposition(RECORD_A, SIGNERS, fresh)
                    && slotA(4, retired(disposing(retiredBlock()))).equals(stored(root, V3)), "wrote " + stored(root, V3));
            // Facts from the fresh boot never change as the record does.
            check(problems, fresh.retiredBoot(RECORD_A) && fresh.retired.size() == 1, "the facts changed");
        });
        run("V3 / beginDisposition moves every disposition kind to DISPOSING and confirms its retry", problems -> {
            Path root = layout(slotA(3, retired(retiredBlock(), USER)));
            NativeIdentityPersistence.BootFacts facts = facts(root);
            check(problems, persistence(root, V3).beginDisposition(RECORD_A, SIGNERS, facts), "refused");
            Slot expected = slotA(4, retired(disposing(retiredBlock()), USER));
            check(problems, expected.equals(stored(root, V3)) && holds(root, expected, 2), "wrote " + stored(root, V3));
            check(problems, persistence(root, V3).beginDisposition(RECORD_A, SIGNERS, facts)
                    && expected.equals(stored(root, V3)) && holds(root, expected, 2), "the retry wrote " + stored(root, V3));
            // A retry after some kinds were discharged still confirms that deletion began.
            check(problems, persistence(root, V3).confirmDisposition(RECORD_A, SIGNERS,
                    disposals(ObligationKind.HOME), facts), "the disposal was refused");
            Slot partly = slotA(5, retired(with(disposing(retiredBlock()), disposals(ObligationKind.HOME).get(0)), USER));
            check(problems, persistence(root, V3).beginDisposition(RECORD_A, SIGNERS, facts)
                    && partly.equals(stored(root, V3)), "the late retry wrote " + stored(root, V3));
        });
        run("V3 / beginDisposition refuses outside a retired boot, beside scope bit 0 and for an orphaned kind before any effect",
                problems -> {
            Slot retiredA = slotA(3, retired(retiredBlock()));
            Path root = layout(retiredA);
            NativeIdentityPersistence persistence = persistence(root, V3);
            // No account, A still RETIRING at the boot read, and only B RETIRED.
            Path retiredB = store(header(ID_B, live(B)));
            slot(retiredB, slotB(3, retired(retiredBlock())));
            for (NativeIdentityPersistence.BootFacts facts : List.of(facts(store(header(0))),
                    facts(layout(slotA(2, retiring(byUserRetirement())))), facts(retiredB))) {
                unchanged(problems, root, "outside a retired boot", () -> persistence.beginDisposition(RECORD_A,
                        SIGNERS, facts));
            }
            Suspension blocking = entry(ActorClass.ADMIN_GRANT, NativeIdentityRecords.SCOPE_BLOCKS_DISPOSITION, 0,
                    SERIAL, grant(9), SuspensionReason.DATA_TRANSFER, TIME);
            Path blocked = layout(slotA(3, retired(retiredBlock(), blocking)));
            unchanged(problems, blocked, "beside scope bit 0", () -> persistence(blocked, V3).beginDisposition(
                    RECORD_A, SIGNERS, facts(blocked)));
            Path orphaned = layout(slotA(3, retired(with(retiredBlock(), obligation(ObligationKind.DATA_DE,
                    ObligationState.ORPHANED_WITH_USER, ZERO, 0, 0)))));
            unchanged(problems, orphaned, "an orphaned kind", () -> persistence(orphaned, V3).beginDisposition(
                    RECORD_A, SIGNERS, facts(orphaned)));
            unchanged(problems, root, "other signers", () -> persistence.beginDisposition(RECORD_A, OTHER_SIGNERS,
                    facts(root)));
        });
        run("V3 / confirmDisposition discharges per kind and confirms its retry", problems -> {
            Path root = layout(slotA(4, retired(disposing(retiredBlock()), GRANT)));
            NativeIdentityPersistence.BootFacts facts = facts(root);
            List<Obligation> keys = disposals(ObligationKind.KEYSTORE, ObligationKind.DATA_CE);
            check(problems, persistence(root, V3).confirmDisposition(RECORD_A, SIGNERS, keys, facts), "refused");
            Slot expected = slotA(5, retired(with(with(disposing(retiredBlock()), keys.get(0)), keys.get(1)), GRANT));
            check(problems, expected.equals(stored(root, V3)) && holds(root, expected, 2), "wrote " + stored(root, V3));
            check(problems, persistence(root, V3).confirmDisposition(RECORD_A, SIGNERS, keys, facts)
                    && expected.equals(stored(root, V3)) && holds(root, expected, 2), "the retry wrote " + stored(root, V3));
            List<Obligation> rest = disposals(ObligationKind.ANDROID_STATE, ObligationKind.DATA_DE,
                    ObligationKind.DATA_EXTERNAL, ObligationKind.HOME, ObligationKind.MANAGED_OBJECTS);
            check(problems, persistence(root, V3).confirmDisposition(RECORD_A, SIGNERS, rest, facts), "rest refused");
            for (Obligation duty : stored(root, V3).users.get(0).lifecycle.retirement.obligations) {
                check(problems, duty.state == ObligationState.DISCHARGED, "kind " + duty);
            }
        });
        run("V3 / confirmDisposition refuses outside a retired boot and before deletion began before any effect",
                problems -> {
            Path began = layout(slotA(4, retired(disposing(retiredBlock()))));
            unchanged(problems, began, "outside a retired boot", () -> persistence(began, V3).confirmDisposition(
                    RECORD_A, SIGNERS, disposals(ObligationKind.HOME), facts(store(header(0)))));
            Path outstanding = layout(slotA(3, retired(retiredBlock())));
            unchanged(problems, outstanding, "before deletion began", () -> persistence(outstanding, V3)
                    .confirmDisposition(RECORD_A, SIGNERS, disposals(ObligationKind.HOME), facts(outstanding)));
            Path orphaned = layout(slotA(4, retired(with(disposing(retiredBlock()), obligation(ObligationKind.HOME,
                    ObligationState.ORPHANED_WITH_USER, ZERO, 0, 0)))));
            unchanged(problems, orphaned, "an orphaned kind", () -> persistence(orphaned, V3).confirmDisposition(
                    RECORD_A, SIGNERS, disposals(ObligationKind.HOME), facts(orphaned)));
            unchanged(problems, began, "other signers", () -> persistence(began, V3).confirmDisposition(RECORD_A,
                    OTHER_SIGNERS, disposals(ObligationKind.HOME), facts(began)));
        });
        run("V3 / confirmDisposition refuses receipts that are not disposal receipts before any effect", problems -> {
            Path root = layout(slotA(4, retired(disposing(retiredBlock()))));
            NativeIdentityPersistence persistence = persistence(root, V3);
            NativeIdentityPersistence.BootFacts facts = facts(root);
            Obligation work = obligation(ObligationKind.WORK, ObligationState.DISCHARGED, ZERO, 0, 0);
            Obligation still = obligation(ObligationKind.HOME, ObligationState.DISPOSING, ZERO, 0, 0);
            Obligation orphaned = obligation(ObligationKind.HOME, ObligationState.ORPHANED_WITH_USER, ZERO, 0, 0);
            List<Obligation> twice = new ArrayList<>(disposals(ObligationKind.HOME));
            twice.addAll(disposals(ObligationKind.HOME));
            for (List<Obligation> receipts : List.of(List.<Obligation>of(), List.of(work), List.of(still),
                    List.of(orphaned), twice, List.of(disposals(ObligationKind.HOME).get(0), disposals(ObligationKind.DATA_CE).get(0)))) {
                invalid(problems, root, "receipts " + receipts, () -> persistence.confirmDisposition(RECORD_A, SIGNERS,
                        receipts, facts));
            }
        });
    }

    // ------------------------------------------------------------------ restore

    private static void restoreCases() {
        run("V3 / restore writes the last known state with a recovery hold", problems -> {
            Slot newer = slotA(5, retired(retiredBlock(), USER));
            Path root = store(header(ID_A, live(A)));
            copies(root, bytes(newer), bytes(slotA(4, retiring(byUserRetirement(), USER))), torn(newer));
            check(problems, persistence(root, V3).restore(RECORD_A, LINEAGE, SIGNERS, RECOVERY), "refused");
            Slot expected = slotA(6, retired(retiredBlock(), USER, RECOVERY));
            check(problems, expected.equals(stored(root, V3)) && holds(root, expected, 2), "wrote " + stored(root, V3));
            check(problems, persistence(root, V3).restore(RECORD_A, LINEAGE, SIGNERS, RECOVERY)
                    && expected.equals(stored(root, V3)) && holds(root, expected, 2), "the retry wrote " + stored(root, V3));
            NativeIdentityPersistence.Restoration restoration =
                    NativeIdentityPersistence.restoration(load(root, V3).histories());
            check(problems, restoration.retiringIds.equals(Set.of(ID_A)), "pins " + restoration.retiringIds);
        });
        run("V3 / restore writes ELIGIBLE with scope bit 1 when the state cannot be established", problems -> {
            Path root = store(header(ID_A, live(A)));
            byte[] broken = torn(slotA(5, retired(retiredBlock())));
            copies(root, broken, broken, null);
            check(problems, persistence(root, V3).restore(RECORD_A, LINEAGE, SIGNERS, RECOVERY), "refused");
            Slot expected = slotA(1, eligible(RECOVERY_UNKNOWN));
            check(problems, expected.equals(stored(root, V3)) && holds(root, expected, 2), "wrote " + stored(root, V3));
            History history = load(root, V3).history(A);
            check(problems, history != null && history.state == LifecycleState.ELIGIBLE && !history.eligible()
                    && history.suspensions.equals(List.of(RECOVERY_UNKNOWN)), "history " + history);
        });
        run("V3 / a restored record never becomes active directly", problems -> {
            Path root = store(creatingA());
            byte[] broken = torn(ELIGIBLE);
            copies(root, broken, broken, null);
            NativeIdentityPersistence persistence = persistence(root, V3);
            check(problems, persistence.restore(RECORD_A, LINEAGE, SIGNERS, RECOVERY), "refused");
            Slot restored = stored(root, V3);
            History history = load(root, V3).history(A);
            check(problems, history != null && !history.eligible(), "history " + history);
            NativeIdentityPersistence.Restoration restoration =
                    NativeIdentityPersistence.restoration(load(root, V3).histories());
            check(problems, restoration.records.size() == 1 && restoration.retiringIds.isEmpty(),
                    "pins " + restoration.records);
            check(problems, NativeIdentityPersistence.scanOwner(history, PKG_A, A, false, PKG_A, false, SERIAL) == null,
                    "the scan admitted it");
            unchanged(problems, root, "publication", () -> persistence.publish(RECORD_A, SIGNERS));
            invalid(problems, root, "a lift of the hold", () -> persistence.lift(RECORD_A, SIGNERS, RECOVERY_UNKNOWN));
            unchanged(problems, root, "the store's lift", () -> open(root, V3).liftSuspension(restored, ID_A,
                    RECOVERY_UNKNOWN));
            check(problems, creatingA().equals(load(root, V3).header.value), "the header changed");
        });
        run("V3 / restore refuses requests no writer writes before any effect", problems -> {
            Path root = store(header(ID_A, live(A)));
            byte[] broken = torn(ELIGIBLE);
            copies(root, broken, broken, null);
            NativeIdentityPersistence persistence = persistence(root, V3);
            Suspension bit0 = entry(ActorClass.RECOVERY_HOLD, NativeIdentityRecords.SCOPE_BLOCKS_DISPOSITION, 0, SERIAL,
                    ZERO, SuspensionReason.RECOVERY_REVIEW, TIME);
            Suspension otherReason = entry(ActorClass.RECOVERY_HOLD, 0, 0, SERIAL, ZERO, SuspensionReason.DATA_TRANSFER,
                    TIME);
            Suspension unregistered = new Suspension(ActorClass.RECOVERY_HOLD, 0, 0, SERIAL, ZERO, 999, TIME, null);
            for (Suspension hold : List.of(RECOVERY_UNKNOWN, bit0, otherReason, unregistered, USER, GRANT)) {
                invalid(problems, root, "restore with " + hold, () -> persistence.restore(RECORD_A, LINEAGE, SIGNERS, hold));
            }
            invalid(problems, root, "a malformed lineage", () -> persistence.restore(RECORD_A, "x", SIGNERS, RECOVERY));
        });
        run("V3 / restore refuses another claim, lineage or counter and a missing body before any effect", problems -> {
            byte[] broken = torn(ELIGIBLE);
            Path claimed = store(header(ID_B, live(A), live(B)));
            copies(claimed, broken, broken, null);
            slot(claimed, new Slot(LINEAGE, B, PKG_A, 1, SIGNERS, List.of(new UserEntry(ID_B, 0, SERIAL, false))));
            unchanged(problems, claimed, "a claimed package", () -> persistence(claimed, V3).restore(RECORD_A, LINEAGE,
                    SIGNERS, RECOVERY));
            Path lineage = store(header(ID_A, live(A)));
            copies(lineage, broken, broken, null);
            unchanged(problems, lineage, "another lineage", () -> persistence(lineage, V3).restore(RECORD_A,
                    "d".repeat(32), SIGNERS, RECOVERY));
            Path counter = store(header(0, live(A)));
            copies(counter, broken, broken, null);
            unchanged(problems, counter, "an unissued ID", () -> persistence(counter, V3).restore(RECORD_A, LINEAGE,
                    SIGNERS, RECOVERY));
            Path missing = store(header(ID_A, live(A)));
            unchanged(problems, missing, "a missing body", () -> persistence(missing, V3).restore(RECORD_A, LINEAGE,
                    SIGNERS, RECOVERY));
            Path creating = store(creatingA());
            copies(creating, broken, broken, null);
            unchanged(problems, creating, "other signers than the creation's", () -> persistence(creating, V3)
                    .restore(RECORD_A, LINEAGE, OTHER_SIGNERS, RECOVERY));
            Path releasing = store(header(ID_A, releasing(A)));
            copies(releasing, broken, broken, null);
            unchanged(problems, releasing, "a RELEASING entry", () -> persistence(releasing, V3).restore(RECORD_A,
                    LINEAGE, SIGNERS, RECOVERY));
        });
        run("V3 / restore refuses a sibling's reservation or tombstone of its package and a damaged header before any effect",
                problems -> {
            byte[] broken = torn(ELIGIBLE);
            // Another app ID's CREATING entry for A's package, under another creation ID.
            Path reserved = store(Header.newV2(LINEAGE, ID_B, List.of(live(A), new NativeIdentityRecords.HeaderEntry(B,
                    NativeIdentityRecords.SlotPhase.CREATING, ID_B, PKG_A,
                    new NativeIdentityRecords.CreationBinding(0, SERIAL, SIGNERS)))));
            copies(reserved, broken, broken, null);
            unchanged(problems, reserved, "a sibling reservation of the package", () -> persistence(reserved, V3)
                    .restore(RECORD_A, LINEAGE, SIGNERS, RECOVERY));
            // A valid ticketed tombstone of A's package at another app ID.
            Path tombstoned = store(header(ID_B, live(A), live(B)));
            copies(tombstoned, broken, broken, null);
            slot(tombstoned, tombstone(B, PKG_A, ID_B, 3));
            unchanged(problems, tombstoned, "a sibling tombstone of the package", () -> persistence(tombstoned, V3)
                    .restore(RECORD_A, LINEAGE, SIGNERS, RECOVERY));
            // A tombstone whose ticket names A's principal ID, under another package.
            Path ticketed = store(header(ID_B, live(A), live(B)));
            copies(ticketed, broken, broken, null);
            slot(ticketed, tombstone(B, PKG_B, ID_A, 3));
            unchanged(problems, ticketed, "a sibling ticket of the principal", () -> persistence(ticketed, V3)
                    .restore(RECORD_A, LINEAGE, SIGNERS, RECOVERY));
            Path damaged = damagedHeader();
            copies(damaged, broken, broken, null);
            unchanged(problems, damaged, "a damaged header", () -> persistence(damaged, V3).restore(RECORD_A, LINEAGE,
                    SIGNERS, RECOVERY));
        });
    }

    // ------------------------------------------------------------------ release

    private static boolean release(Path root, NativePrincipalPins.Record record, NativeIdentityRecords.ReleaseTicket ticket,
            Keys keys, NativeIdentityPersistence.BootFacts facts) {
        return persistence(root, V3).release(record, LINEAGE, SIGNERS, ticket, capability(keys), facts);
    }

    private static boolean released(Path root, Header before) {
        Header expected = new Header(LINEAGE, before.lastId, List.of());
        if (before.version == 2) expected = Header.newV2(LINEAGE, before.lastId, List.of());
        return releasePhase(root).equals("omitted") && expected.equals(load(root, V3).header.value);
    }

    private static void releaseCases() {
        run("V3 / release clears the key namespace, then writes the ticketed tombstone, RELEASING and the omission",
                problems -> {
            Path root = layout(releasableA());
            NativeIdentityPersistence.BootFacts facts = facts(root);
            Keys keys = new Keys();
            List<String> seen = new ArrayList<>();
            keys.observe = () -> seen.add(releasePhase(root));
            check(problems, release(root, RECORD_A, TICKET_A, keys, facts), "refused");
            check(problems, keys.cleared.equals(List.of(A)) && seen.equals(List.of("retired")),
                    "keys " + keys.cleared + " at " + seen);
            check(problems, released(root, header(ID_A, live(A))), "left " + releasePhase(root));
            // A lost reply in the same boot: the durable omission is confirmed, never written again.
            keys.cleared.clear();
            check(problems, release(root, RECORD_A, TICKET_A, keys, facts) && keys.cleared.isEmpty(),
                    "the omission was not confirmed");
            // A later boot has no fact of the account, so nothing is confirmed there.
            unchanged(problems, root, "a confirmation without facts", () -> release(root, RECORD_A, TICKET_A,
                    new Keys(), facts(root)));
        });
        run("V3 / release completes a CREATING entry to LIVE before the key namespace and the tombstone", problems -> {
            Path root = store(creatingA());
            slot(root, releasableA());
            NativeIdentityPersistence.BootFacts facts = facts(root);
            Keys keys = new Keys();
            List<String> seen = new ArrayList<>();
            keys.observe = () -> seen.add(load(root, V3).header.value.entries.get(0).phase + " " + releasePhase(root));
            check(problems, facts.retiredBoot(RECORD_A), "no retired boot");
            check(problems, release(root, RECORD_A, TICKET_A, keys, facts), "refused");
            check(problems, seen.equals(List.of("LIVE retired")), "the keys were cleared at " + seen);
            check(problems, released(root, creatingA()), "left " + releasePhase(root));
        });
        run("V3 / release refuses outside a retired boot before any effect", problems -> {
            Path root = layout(releasableA());
            // No account, and the boot in which the account became RETIRED.
            Path retiring = layout(slotA(2, retiring(byUserRetirement())));
            Path otherSerial = layout(new Slot(LINEAGE, A, PKG_A, 3, SIGNERS, List.of(new UserEntry(ID_A, 0, SERIAL + 1,
                    retired(allDischarged(byUserRetirement()))))));
            for (NativeIdentityPersistence.BootFacts facts : List.of(facts(store(header(0))), facts(retiring),
                    facts(otherSerial))) {
                Keys keys = new Keys();
                unchanged(problems, root, "outside a retired boot", () -> release(root, RECORD_A, TICKET_A, keys, facts));
                check(problems, keys.cleared.isEmpty(), "the keys were cleared outside a retired boot");
            }
        });
        run("V3 / release refuses beside a suspension entry or an open obligation before any effect", problems -> {
            Retirement done = allDischarged(byUserRetirement());
            List<Slot> blocked = new ArrayList<>(List.of(slotA(3, retired(done, USER)), slotA(3, retired(done, GRANT)),
                    slotA(3, retired(retiredBlock())), slotA(4, retired(disposing(retiredBlock()))),
                    slotA(3, retired(with(done, obligation(ObligationKind.HOME, ObligationState.ORPHANED_WITH_USER,
                            ZERO, 0, 0)))),
                    slotA(3, retired(with(done, obligation(ObligationKind.DATA_CE, ObligationState.DISPOSING,
                            ZERO, 0, 0)))),
                    slotA(2, retiring(byUserRetirement()))));
            for (Slot durable : blocked) {
                Path root = layout(durable);
                Keys keys = new Keys();
                NativeIdentityPersistence.BootFacts facts = facts(root);
                unchanged(problems, root, "release of " + durable, () -> release(root, RECORD_A, TICKET_A, keys, facts));
                check(problems, keys.cleared.isEmpty(), "the keys were cleared for " + durable);
            }
            Path other = layout(releasableA());
            unchanged(problems, other, "other signers", () -> persistence(other, V3).release(RECORD_A, LINEAGE,
                    OTHER_SIGNERS, TICKET_A, capability(new Keys()), facts(other)));
        });
        run("V3 / release refuses tickets of another principal and unchecked users before any effect", problems -> {
            Path root = layout(releasableA());
            NativeIdentityPersistence.BootFacts facts = facts(root);
            String id = TICKET_A.ticketId;
            // User 134217728 times the per user range wraps to user 0's UID in int arithmetic.
            for (NativeIdentityRecords.ReleaseTicket ticket : List.of(
                    new NativeIdentityRecords.ReleaseTicket(ID_B, 0, SERIAL, id),
                    new NativeIdentityRecords.ReleaseTicket(ID_A, 0, SERIAL + 1, id),
                    new NativeIdentityRecords.ReleaseTicket(ID_A, 10, SERIAL, id),
                    new NativeIdentityRecords.ReleaseTicket(ID_A, 134_217_728, SERIAL, id),
                    new NativeIdentityRecords.ReleaseTicket(ID_A, Integer.MAX_VALUE, SERIAL, id))) {
                Keys keys = new Keys();
                invalid(problems, root, "a ticket " + ticket, () -> release(root, RECORD_A, ticket, keys, facts));
                check(problems, keys.cleared.isEmpty(), "the keys were cleared for " + ticket);
            }
            check(problems, NativeIdentityPersistence.ticketUid(new NativeIdentityRecords.ReleaseTicket(ID_A, 134_217_728,
                    SERIAL, id), A) == -1 && NativeIdentityPersistence.ticketUid(TICKET_A, A) == A, "ticket UIDs");
        });
        run("V3 / release refuses beside a foreign copy or another ticket's tombstone before any effect", problems -> {
            NativeIdentityRecords.ReleaseTicket other = new NativeIdentityRecords.ReleaseTicket(ID_A, 0, SERIAL,
                    "8".repeat(32));
            Slot foreign = new Slot(LINEAGE, A, PKG_A, 3, SIGNERS, List.of(new UserEntry(ID_B, 0, SERIAL,
                    retired(allDischarged(byUserRetirement())))));
            Slot otherTombstone = new Slot(LINEAGE, A, PKG_A, 4, SIGNERS, List.of(), other);
            for (Slot beside : List.of(foreign, otherTombstone)) {
                // The selected backup is A's releasable binding, and main holds the other copy.
                Path root = store(header(ID_B, live(A)));
                copies(root, bytes(beside), null, bytes(releasableA()));
                NativeIdentityPersistence.BootFacts facts = facts(root);
                check(problems, facts.retiredBoot(RECORD_A) && releasableA().equals(stored(root, V3)),
                        "no retired boot beside " + beside);
                Keys keys = new Keys();
                unchanged(problems, root, "release beside " + beside, () -> release(root, RECORD_A, TICKET_A, keys,
                        facts));
                check(problems, keys.cleared.isEmpty(), "the keys were cleared beside " + beside);
            }
        });
        run("V3 / release refuses before any effect when the key namespace is not cleared", problems -> {
            Path root = layout(releasableA());
            Keys keys = new Keys();
            keys.clear = false;
            unchanged(problems, root, "an uncleared namespace", () -> release(root, RECORD_A, TICKET_A, keys,
                    facts(root)));
            check(problems, keys.cleared.equals(List.of(A)), "keys " + keys.cleared);
        });
        run("V3 / an interrupted release continues only in a boot that began with its ticketed tombstone", problems -> {
            for (HeaderEntry entry : List.of(live(A), releasingEntry(A))) {
                Path root = store(header(ID_A, entry));
                // The boot that began with the account RETIRED wrote the tombstone, and its reply was lost.
                NativeIdentityPersistence.BootFacts same = facts(layout(releasableA()));
                slot(root, tombstoneA());
                Keys keys = new Keys();
                unchanged(problems, root, "continuation in the same boot under " + entry.phase,
                        () -> release(root, RECORD_A, TICKET_A, keys, same));
                // The next boot began with the ticketed tombstone.
                NativeIdentityPersistence.BootFacts next = facts(root);
                check(problems, next.ticketedTombstones.get(A).equals(tombstoneA()), "no tombstone fact");
                NativeIdentityRecords.ReleaseTicket other = new NativeIdentityRecords.ReleaseTicket(ID_A, 0, SERIAL,
                        "8".repeat(32));
                unchanged(problems, root, "another ticket under " + entry.phase, () -> release(root, RECORD_A, other,
                        new Keys(), next));
                check(problems, release(root, RECORD_A, TICKET_A, keys, next) && keys.cleared.isEmpty(),
                        "continuation under " + entry.phase + " refused");
                check(problems, released(root, header(ID_A, entry)), "left " + releasePhase(root));
            }
        });
        run("V3 / an interrupted release continues from RELEASING without a directory or with an emptied one",
                problems -> {
            for (String left : List.of("none", "empty", "seed", "torn seed")) {
                Path root = store(header(ID_A, releasingEntry(A)));
                Path directory = root.resolve("slots/" + A);
                if (!left.equals("none")) Files.createDirectories(directory);
                if (left.equals("seed")) Files.write(directory.resolve("record.bin-seed"), bytes(tombstoneA()));
                if (left.equals("torn seed")) Files.write(directory.resolve("record.bin-seed"), new byte[] {1, 2});
                NativeIdentityPersistence.BootFacts facts = facts(root);
                check(problems, facts.releasingWithoutDirectory.equals(Set.of(A)), left + " gave no fact");
                // The same durable state in a boot that began otherwise is not continued.
                unchanged(problems, root, "continuation without its fact, " + left, () -> release(root, RECORD_A,
                        TICKET_A, new Keys(), facts(layout(releasableA()))));
                check(problems, release(root, RECORD_A, TICKET_A, new Keys(), facts), left + " was not continued");
                check(problems, released(root, header(ID_A, releasingEntry(A))), left + " left " + releasePhase(root));
            }
        });
        run("V3 / continuation passes only the checked removal and omission", problems -> {
            // An unknown file, or a seed holding the binding, beside a directory that reads as missing.
            for (String left : List.of("unknown", "binding seed")) {
                Path root = store(header(ID_A, releasingEntry(A)));
                Path directory = Files.createDirectories(root.resolve("slots/" + A));
                if (left.equals("unknown")) Files.write(directory.resolve("other"), new byte[] {1});
                else Files.write(directory.resolve("record.bin-seed"), bytes(releasableA()));
                NativeIdentityPersistence.BootFacts facts = facts(root);
                check(problems, facts.releasingWithoutDirectory.equals(Set.of(A)), left + " gave no fact");
                check(problems, !release(root, RECORD_A, TICKET_A, new Keys(), facts), left + " was removed");
                check(problems, Files.isDirectory(directory) && load(root, V3).occupiedAppIds.contains(A),
                        left + " lost its hold");
            }
            // A tombstone copy of another ticket beside this release's own.
            Path foreign = store(header(ID_A, releasingEntry(A)));
            NativeIdentityRecords.ReleaseTicket other = new NativeIdentityRecords.ReleaseTicket(ID_A, 0, SERIAL,
                    "8".repeat(32));
            raw(foreign, A, bytes(tombstoneA()), bytes(new Slot(LINEAGE, A, PKG_A, 4, SIGNERS, List.of(), other)));
            unchanged(problems, foreign, "a copy of another ticket", () -> release(foreign, RECORD_A, TICKET_A,
                    new Keys(), facts(foreign)));
        });
        run("V3 / continuation refuses a counter that does not cover the account before any effect", problems -> {
            // The ticketed tombstone's boot, under a header whose counter is below its principal ID.
            Path root = store(header(0, live(A)));
            slot(root, tombstoneA());
            NativeIdentityPersistence.BootFacts facts = facts(root);
            check(problems, tombstoneA().equals(facts.ticketedTombstones.get(A)), "no tombstone fact");
            unchanged(problems, root, "continuation above the counter", () -> release(root, RECORD_A, TICKET_A,
                    new Keys(), facts));
        });
        run("V3 / continuation refuses a live binding of the package elsewhere before any effect", problems -> {
            // B's two copies disagree, so B is a conflict and gives no evidence to the load, yet each
            // binds A's package to a user.
            Path root = store(header(ID_B, live(A), live(B)));
            slot(root, tombstoneA());
            raw(root, B, bytes(new Slot(LINEAGE, B, PKG_A, 1, SIGNERS, List.of(new UserEntry(ID_B, 0, SERIAL, false)))),
                    bytes(new Slot(LINEAGE, B, PKG_A, 2, SIGNERS, List.of(new UserEntry(ID_B, 0, SERIAL, false)))));
            NativeIdentityPersistence.BootFacts facts = facts(root);
            check(problems, tombstoneA().equals(facts.ticketedTombstones.get(A))
                    && load(root, V3).slots.get(B).status == NativeIdentityStore.Status.CONFLICT, "no tombstone fact");
            unchanged(problems, root, "continuation beside a binding of the package", () -> release(root, RECORD_A,
                    TICKET_A, new Keys(), facts));
        });
        run("V3 / an unticketed tombstone of the version 1 release stays held", problems -> {
            for (HeaderEntry entry : List.of(live(A), releasingEntry(A))) {
                Path root = store(header(ID_A, entry));
                slot(root, new Slot(LINEAGE, A, PKG_A, 4, SIGNERS, List.of()));
                NativeIdentityPersistence.BootFacts facts = facts(root);
                check(problems, facts.ticketedTombstones.isEmpty() && facts.releasingWithoutDirectory.isEmpty(),
                        "the unticketed tombstone gave a fact");
                unchanged(problems, root, "the unticketed tombstone under " + entry.phase, () -> release(root, RECORD_A,
                        TICKET_A, new Keys(), facts));
            }
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
                // Boot facts that name the account RETIRED, as a lifecycle format boot would.
                NativeIdentityPersistence.BootFacts facts = facts(layout(slotA(3, retired(retiredBlock()))));
                unchanged(problems, root, "beginDisposition", () -> persistence.beginDisposition(RECORD_A, SIGNERS, facts));
                unchanged(problems, root, "confirmDisposition", () -> persistence.confirmDisposition(RECORD_A, SIGNERS,
                        disposals(ObligationKind.HOME), facts));
                unchanged(problems, root, "restore of an intact record", () -> persistence.restore(RECORD_A, LINEAGE,
                        SIGNERS, RECOVERY));
                Path damaged = store(header(ID_A, live(A)));
                copies(damaged, torn(ELIGIBLE), torn(ELIGIBLE), null);
                unchanged(problems, damaged, "restore of a damaged record", () -> persistence(damaged, format).restore(
                        RECORD_A, LINEAGE, SIGNERS, RECOVERY));
                // Facts that show the account RETIRED and its ticketed tombstone, as a lifecycle format boot would.
                Path ready = layout(releasableA());
                Keys keys = new Keys();
                unchanged(problems, ready, "release", () -> persistence(ready, format).release(RECORD_A, LINEAGE, SIGNERS,
                        TICKET_A, capability(keys), facts(ready)));
                Path tombstoned = layout(tombstoneA());
                unchanged(problems, tombstoned, "release from a ticketed tombstone", () -> persistence(tombstoned, format)
                        .release(RECORD_A, LINEAGE, SIGNERS, TICKET_A, capability(keys), facts(tombstoned)));
                check(problems, keys.cleared.isEmpty(), "the keys were cleared");
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
        bootFactCases();
        restoreCases();
        releaseCases();
        earlierCases();
        finish(Os.allClosed());
        System.out.println("Lifecycle transactions kept the record's rules and refusals; Android unqualified");
    }
}
