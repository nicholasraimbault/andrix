// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeLifecycleTestSupport.*;

import android.system.Os;
import com.android.server.pm.NativeIdentityRecords.ActorClass;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.Lifecycle;
import com.android.server.pm.NativeIdentityRecords.LifecycleState;
import com.android.server.pm.NativeIdentityRecords.Obligation;
import com.android.server.pm.NativeIdentityRecords.ObligationKind;
import com.android.server.pm.NativeIdentityRecords.ObligationState;
import com.android.server.pm.NativeIdentityRecords.ReleaseTicket;
import com.android.server.pm.NativeIdentityRecords.Retirement;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.Suspension;
import com.android.server.pm.NativeIdentityRecords.SuspensionReason;
import com.android.server.pm.NativeIdentityRecords.UserEntry;
import com.android.server.pm.NativeIdentityStore.Format;
import com.android.server.pm.NativeIdentityStore.History;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * The store's named lifecycle transitions and the store transition rules of the lifecycle record
 * plan, on the actual store with host file facades. Under Format.V3, which no production text
 * constructs, the suspend, lift, retire and confirm retired transitions each make only their own
 * change and apply the writer rules: scope bit 0, the reason registry and its actor classes, an
 * account user's own actor, the allotment of six entries to the account's user, a recovery hold
 * and four grants, no legacy marker or user removal written, and a reference bound once. The
 * state only moves forward, a written block never changes except a legacy marker's inventory
 * continuation, and the generic update changes no lifecycle, no user's identity and no ticket, and
 * drops no user. Under Format.V1 and V2 every transition refuses before any effect. Host files
 * only, not Android persistence.
 */
public final class NativeLifecycleStoreTest {
    private static final Slot ELIGIBLE = slotA(1, Lifecycle.version1(false));
    private static final Slot LEGACY = slotA(1, Lifecycle.version1(true));

    private interface Transition { boolean run(NativeIdentityStore store, Slot expected) throws Exception; }

    // A refusal before any effect of one transition over this durable value of A.
    private static void refused(List<String> problems, Slot durable, String what, Transition transition)
            throws Exception {
        Path root = layout(durable);
        unchanged(problems, root, what, () -> transition.run(open(root, V3), durable));
    }

    private static Transition suspend(Suspension entry) {
        return (store, expected) -> store.addSuspension(expected, ID_A, entry);
    }

    private static Transition lift(Suspension entry) {
        return (store, expected) -> store.liftSuspension(expected, ID_A, entry);
    }

    private static Transition retire(Retirement retirement) {
        return (store, expected) -> store.markSlotRetiring(expected, ID_A, retirement);
    }

    private static Transition confirm(List<Obligation> receipts) {
        return (store, expected) -> store.markSlotRetired(expected, ID_A, receipts);
    }

    private static Suspension[] plus(Suspension[] entries, Suspension... more) {
        List<Suspension> list = new ArrayList<>(List.of(entries));
        list.addAll(List.of(more));
        return list.toArray(new Suspension[0]);
    }

    // The transition is written: the durable value is exactly next, in its version's one encoding.
    private static void written(List<String> problems, Slot durable, Slot next, int version, String what,
            Transition transition) throws Exception {
        Path root = layout(durable);
        check(problems, transition.run(open(root, V3), durable), what + " refused");
        check(problems, next.equals(stored(root, V3)) && holds(root, next, version), what + " wrote "
                + stored(root, V3));
    }

    // ------------------------------------------------------------------ suspend

    private static void suspendCases() {
        run("V3 / suspend adds one entry in order and changes nothing else", problems -> {
            Path root = layout(ELIGIBLE);
            NativeIdentityStore store = open(root, V3);
            Suspension second = NativeLifecycleTestSupport.entry(ActorClass.ADMIN_GRANT, 0, 0, 2, "22".repeat(16),
                    SuspensionReason.DEVICE_HANDOVER, TIME);
            Suspension third = NativeLifecycleTestSupport.entry(ActorClass.ADMIN_GRANT, 0, 10, 3, "11".repeat(16),
                    SuspensionReason.RESOURCE_OVERUSE, TIME);
            Suspension user = byUser(SuspensionReason.USER_PAUSED);
            Slot current = ELIGIBLE;
            List<Suspension> added = new ArrayList<>();
            for (Suspension entry : List.of(third, user, second)) {
                added.add(entry);
                Slot next = slotA(current.generation + 1, eligible(added.toArray(new Suspension[0])));
                check(problems, store.addSuspension(current, ID_A, entry), "refused " + entry);
                check(problems, next.equals(stored(root, V3)) && holds(root, next, 2), "wrote " + stored(root, V3));
                current = next;
            }
            // Class, then actor serial, then grant: the serial 2 grant precedes the serial 3 one.
            check(problems, current.users.get(0).lifecycle.suspensions.equals(List.of(user, second, third)),
                    "order " + current.users.get(0).lifecycle.suspensions);
            History history = load(root, V3).history(A);
            check(problems, history != null && history.state == LifecycleState.ELIGIBLE && !history.retiring
                    && history.suspensions.size() == 3, "history " + history);
        });
        run("V3 / suspend refuses scope bit 0 before any effect", problems -> {
            int bit0 = NativeIdentityRecords.SCOPE_BLOCKS_DISPOSITION;
            for (Suspension entry : List.of(
                    NativeLifecycleTestSupport.entry(ActorClass.ADMIN_GRANT, bit0, 0, SERIAL, grant(1),
                            SuspensionReason.DATA_TRANSFER, TIME),
                    NativeLifecycleTestSupport.entry(ActorClass.ACCOUNT_USER, bit0, 0, SERIAL, ZERO,
                            SuspensionReason.DATA_TRANSFER, TIME))) {
                refused(problems, ELIGIBLE, "scope bit 0 " + entry, suspend(entry));
            }
            // The same entry without the bit is written: the refusal is the bit's.
            written(problems, ELIGIBLE, slotA(2, eligible(byGrant(1, SuspensionReason.DATA_TRANSFER))), 2,
                    "control", suspend(byGrant(1, SuspensionReason.DATA_TRANSFER)));
        });
        run("V3 / suspend refuses a reason outside the registry before any effect", problems -> {
            for (int reason : new int[] {0, 8, 999, 65535}) {
                Suspension entry = new Suspension(ActorClass.ADMIN_GRANT, 0, 0, SERIAL, grant(1), reason, TIME, null);
                refused(problems, ELIGIBLE, "reason " + reason, suspend(entry));
            }
        });
        run("V3 / suspend refuses a reason its actor class may not use before any effect", problems -> {
            refused(problems, ELIGIBLE, "a grant pausing", suspend(byGrant(1, SuspensionReason.USER_PAUSED)));
            refused(problems, ELIGIBLE, "a user in review", suspend(byUser(SuspensionReason.RECOVERY_REVIEW)));
            refused(problems, ELIGIBLE, "a grant in review", suspend(byGrant(1, SuspensionReason.RECOVERY_REVIEW)));
            written(problems, ELIGIBLE, slotA(2, eligible(byUser(SuspensionReason.USER_PAUSED))), 2,
                    "a user pausing", suspend(byUser(SuspensionReason.USER_PAUSED)));
            written(problems, ELIGIBLE, slotA(2, eligible(byGrant(1, SuspensionReason.CREDENTIAL_EXPOSED))), 2,
                    "a grant's exposure", suspend(byGrant(1, SuspensionReason.CREDENTIAL_EXPOSED)));
        });
        run("V3 / suspend refuses an account user entry of another user or serial before any effect", problems -> {
            for (Suspension entry : List.of(
                    NativeLifecycleTestSupport.entry(ActorClass.ACCOUNT_USER, 0, 0, SERIAL + 1, ZERO,
                            SuspensionReason.USER_PAUSED, TIME),
                    NativeLifecycleTestSupport.entry(ActorClass.ACCOUNT_USER, 0, 10, SERIAL, ZERO,
                            SuspensionReason.USER_PAUSED, TIME))) {
                refused(problems, ELIGIBLE, "actor " + entry, suspend(entry));
            }
        });
        run("V3 / suspend refuses a recovery hold before any effect", problems -> {
            refused(problems, ELIGIBLE, "a hold", suspend(hold(0)));
            refused(problems, ELIGIBLE, "a hold of unknown state",
                    suspend(hold(NativeIdentityRecords.SCOPE_PRIOR_UNKNOWN)));
        });
        run("V3 / suspend refuses a second entry from one actor before any effect", problems -> {
            Suspension user = byUser(SuspensionReason.USER_PAUSED);
            Suspension granted = byGrant(1, SuspensionReason.CREDENTIAL_EXPOSED);
            Slot durable = slotA(2, eligible(user, granted));
            refused(problems, durable, "the user again", suspend(byUser(SuspensionReason.SUSPECTED_COMPROMISE)));
            refused(problems, durable, "the same entry", suspend(user));
            refused(problems, durable, "the grant again", suspend(byGrant(1, SuspensionReason.RESOURCE_OVERUSE)));
            refused(problems, durable, "the grant by another user", suspend(NativeLifecycleTestSupport.entry(
                    ActorClass.ADMIN_GRANT, 0, 10, 3, grant(1), SuspensionReason.CREDENTIAL_EXPOSED, TIME)));
        });
        run("V3 / suspend refuses a seventh actor before any effect", problems -> {
            Suspension[] planned = {byUser(SuspensionReason.USER_PAUSED), hold(0),
                    byGrant(1, SuspensionReason.CREDENTIAL_EXPOSED), byGrant(2, SuspensionReason.DATA_TRANSFER),
                    byGrant(3, SuspensionReason.DEVICE_HANDOVER), byGrant(4, SuspensionReason.RESOURCE_OVERUSE)};
            refused(problems, slotA(2, eligible(planned)), "a seventh grant",
                    suspend(byGrant(9, SuspensionReason.SUSPECTED_COMPROMISE)));
            Suspension[] grants = new Suspension[6];
            for (int i = 0; i < grants.length; i++) grants[i] = byGrant(i + 1, SuspensionReason.DATA_TRANSFER);
            refused(problems, slotA(2, eligible(grants)), "the user after six grants",
                    suspend(byUser(SuspensionReason.USER_PAUSED)));
            // Five entries take a sixth.
            Suspension[] five = List.of(grants).subList(0, 5).toArray(new Suspension[0]);
            List<Suspension> six = new ArrayList<>(List.of(five));
            six.add(byUser(SuspensionReason.USER_PAUSED));
            written(problems, slotA(2, eligible(five)), slotA(3, eligible(six.toArray(new Suspension[0]))), 2,
                    "a sixth entry", suspend(byUser(SuspensionReason.USER_PAUSED)));
        });
        run("V3 / suspend allots four grant places and keeps the account user's place", problems -> {
            Suspension user = byUser(SuspensionReason.USER_PAUSED);
            Suspension[] four = new Suspension[4];
            for (int i = 0; i < four.length; i++) four[i] = byGrant(i + 1, SuspensionReason.DATA_TRANSFER);
            Suspension fifth = byGrant(5, SuspensionReason.SUSPECTED_COMPROMISE);
            refused(problems, slotA(2, eligible(four)), "a fifth grant beside the user's free place", suspend(fifth));
            refused(problems, slotA(2, eligible(plus(four, hold(0)))), "a fifth grant beside a hold", suspend(fifth));
            // The account's user keeps its place beside four grants, and beside a hold too: six entries.
            written(problems, slotA(2, eligible(four)), slotA(3, eligible(plus(four, user))), 2,
                    "the user beside four grants", suspend(user));
            written(problems, slotA(2, eligible(plus(four, hold(0)))), slotA(3, eligible(plus(four, hold(0), user))), 2,
                    "the user beside four grants and a hold", suspend(user));
            // A fourth grant has its place beside the user and a hold.
            Suspension[] three = List.of(four).subList(0, 3).toArray(new Suspension[0]);
            written(problems, slotA(2, eligible(plus(three, user, hold(0)))), slotA(3, eligible(plus(four, user, hold(0)))),
                    2, "a fourth grant", suspend(four[3]));
        });
    }

    // ------------------------------------------------------------------ lift

    private static void liftCases() {
        run("V3 / lift removes exactly its entry and the last one writes version 1", problems -> {
            Suspension user = byUser(SuspensionReason.USER_PAUSED);
            Suspension granted = byGrant(1, SuspensionReason.CREDENTIAL_EXPOSED);
            Path root = layout(slotA(2, eligible(user, granted)));
            NativeIdentityStore store = open(root, V3);
            check(problems, store.liftSuspension(slotA(2, eligible(user, granted)), ID_A, granted), "grant lift refused");
            check(problems, slotA(3, eligible(user)).equals(stored(root, V3)) && holds(root, slotA(3, eligible(user)), 2),
                    "grant lift wrote " + stored(root, V3));
            check(problems, store.liftSuspension(slotA(3, eligible(user)), ID_A, user), "last lift refused");
            Slot plain = slotA(4, Lifecycle.version1(false));
            check(problems, plain.equals(stored(root, V3)) && holds(root, plain, 1), "last lift wrote "
                    + stored(root, V3));
            // Older formats read it again as an eligible version 1 body.
            for (Format format : EARLIER) {
                check(problems, plain.equals(stored(root, format)) && load(root, format).bindingUsable(A),
                        format + " does not read the lifted body");
            }
        });
        run("V3 / lift refuses an entry the record does not hold exactly before any effect", problems -> {
            Suspension user = byUser(SuspensionReason.USER_PAUSED);
            Suspension granted = byGrant(1, SuspensionReason.CREDENTIAL_EXPOSED);
            Slot durable = slotA(2, eligible(user, granted));
            refused(problems, durable, "the grant by another user", lift(NativeLifecycleTestSupport.entry(
                    ActorClass.ADMIN_GRANT, 0, 10, 3, grant(1), SuspensionReason.CREDENTIAL_EXPOSED, TIME + 1)));
            refused(problems, durable, "the grant with another reason",
                    lift(byGrant(1, SuspensionReason.DATA_TRANSFER)));
            refused(problems, durable, "the grant at another time", lift(NativeLifecycleTestSupport.entry(
                    ActorClass.ADMIN_GRANT, 0, 0, SERIAL, grant(1), SuspensionReason.CREDENTIAL_EXPOSED, TIME)));
            refused(problems, durable, "another grant", lift(byGrant(2, SuspensionReason.CREDENTIAL_EXPOSED)));
            refused(problems, slotA(2, eligible(granted)), "an absent user entry", lift(user));
        });
        run("V3 / lift refuses a recovery hold before any effect", problems -> {
            Suspension user = byUser(SuspensionReason.USER_PAUSED);
            refused(problems, slotA(2, eligible(user, hold(0))), "a hold", lift(hold(0)));
            refused(problems, slotA(2, retiring(legacyMarker(), hold(NativeIdentityRecords.SCOPE_PRIOR_UNKNOWN))),
                    "a hold of unknown state", lift(hold(NativeIdentityRecords.SCOPE_PRIOR_UNKNOWN)));
            written(problems, slotA(2, eligible(user, hold(0))), slotA(3, eligible(hold(0))), 2, "the user beside a hold",
                    lift(user));
        });
        run("V3 / suspend and lift keep a retiring or retired account's state and block", problems -> {
            Suspension granted = byGrant(1, SuspensionReason.CREDENTIAL_EXPOSED);
            for (Lifecycle prior : List.of(retiring(byUserRetirement()), retiring(legacyMarker()),
                    retired(discharged(byGrantRetirement(), receipts())))) {
                Slot suspended = slotA(3, new Lifecycle(prior.state, List.of(granted), prior.retirement));
                written(problems, slotA(2, prior), suspended, 2, "suspension of " + prior, suspend(granted));
                Slot lifted = slotA(4, prior);
                written(problems, suspended, lifted, lifted.version, "lift of " + prior, lift(granted));
            }
        });
    }

    // ------------------------------------------------------------------ retire

    private static void retireCases() {
        run("V3 / retire writes RETIRING with its block and keeps every entry", problems -> {
            Suspension user = byUser(SuspensionReason.USER_PAUSED);
            Suspension granted = byGrant(1, SuspensionReason.CREDENTIAL_EXPOSED);
            written(problems, slotA(2, eligible(user, granted, hold(0))),
                    slotA(3, retiring(byUserRetirement(), user, granted, hold(0))), 2, "the user's retirement",
                    retire(byUserRetirement()));
            written(problems, ELIGIBLE, slotA(2, retiring(byGrantRetirement())), 2, "a grant's retirement",
                    retire(byGrantRetirement()));
        });
        run("V3 / retire refuses blocks no writer writes before any effect", problems -> {
            refused(problems, ELIGIBLE, "another user's block",
                    retire(retirement(ActorClass.ACCOUNT_USER, 10, SERIAL, ZERO, TIME)));
            refused(problems, ELIGIBLE, "another serial's block",
                    retire(retirement(ActorClass.ACCOUNT_USER, 0, SERIAL + 1, ZERO, TIME)));
            refused(problems, ELIGIBLE, "a user removal", retire(retirement(ActorClass.USER_REMOVAL, 0, SERIAL, ZERO, TIME)));
            refused(problems, ELIGIBLE, "an unknown inventory", retire(legacyMarker()));
            Obligation[] written = {
                    obligation(ObligationKind.WORK, ObligationState.DISCHARGED, ZERO, 0, 0),
                    obligation(ObligationKind.KEYSTORE, ObligationState.OUTSTANDING, "33".repeat(16), 0, 0),
                    obligation(ObligationKind.HOME, ObligationState.OUTSTANDING, ZERO, 1, 0),
                    obligation(ObligationKind.DELEGATIONS, ObligationState.OUTSTANDING, ZERO, 0, TIME),
                    obligation(ObligationKind.DATA_CE, ObligationState.ORPHANED_WITH_USER, ZERO, 0, 0)};
            for (Obligation duty : written) {
                refused(problems, ELIGIBLE, "an inventory with " + duty, retire(with(byUserRetirement(), duty)));
            }
        });
        run("V3 / retire never creates a legacy marker", problems -> {
            refused(problems, ELIGIBLE, "over an eligible body", retire(legacyContinued()));
            refused(problems, slotA(2, eligible(byUser(SuspensionReason.USER_PAUSED))), "over a suspended body",
                    retire(legacyContinued()));
        });
        run("V3 / retire never moves an account back or changes its block", problems -> {
            Slot retiringUser = slotA(2, retiring(byUserRetirement()));
            refused(problems, retiringUser, "another block", retire(byGrantRetirement()));
            refused(problems, retiringUser, "the same block again", retire(byUserRetirement()));
            refused(problems, retiringUser, "a legacy block over another block", retire(legacyContinued()));
            Slot retiredUser = slotA(3, retired(discharged(byUserRetirement(), receipts())));
            refused(problems, retiredUser, "a retired account's own block", retire(byUserRetirement()));
            refused(problems, LEGACY, "a new actor over a legacy marker", retire(byUserRetirement()));
        });
        run("V3 / a legacy marker's inventory continues once to every kind outstanding", problems -> {
            Path root = layout(LEGACY);
            NativeIdentityStore store = open(root, V3);
            Slot continued = slotA(2, retiring(legacyContinued()));
            check(problems, store.markSlotRetiring(LEGACY, ID_A, legacyContinued()), "continuation refused");
            check(problems, continued.equals(stored(root, V3)) && holds(root, continued, 2),
                    "continuation wrote " + stored(root, V3));
            unchanged(problems, root, "a second continuation", () -> store.markSlotRetiring(continued, ID_A,
                    legacyContinued()));
            // Progress after the continuation is never reset by another one.
            Retirement progressed = with(legacyContinued(),
                    obligation(ObligationKind.WORK, ObligationState.DISCHARGED, ZERO, 1, TIME));
            refused(problems, slotA(3, retiring(progressed)), "a continuation over progress", retire(legacyContinued()));
            // A held legacy marker continues with its hold.
            Suspension held = hold(NativeIdentityRecords.SCOPE_PRIOR_UNKNOWN);
            written(problems, slotA(2, retiring(legacyMarker(), held)), slotA(3, retiring(legacyContinued(), held)), 2,
                    "a held continuation", retire(legacyContinued()));
        });
    }

    // ------------------------------------------------------------------ confirm retired

    private static void confirmCases() {
        run("V3 / confirm retired discharges every retirement kind and keeps everything else", problems -> {
            Suspension user = byUser(SuspensionReason.USER_PAUSED);
            Slot durable = slotA(3, retiring(byGrantRetirement(), user));
            Slot next = slotA(4, retired(discharged(byGrantRetirement(), receipts()), user));
            written(problems, durable, next, 2, "confirmation", confirm(receipts()));
            Retirement block = next.users.get(0).lifecycle.retirement;
            for (Obligation duty : block.obligations) {
                check(problems, duty.kind.disposition() ? duty.state == ObligationState.OUTSTANDING
                        && duty.reference.equals(ZERO) : duty.state == ObligationState.DISCHARGED,
                        "obligation " + duty);
            }
            Path root = layout(durable);
            check(problems, open(root, V3).markSlotRetired(durable, ID_A, receipts()), "confirmation refused");
            History history = load(root, V3).history(A);
            check(problems, history != null && history.state == LifecycleState.RETIRED && history.retiring
                    && history.suspensions.equals(List.of(user)), "history " + history);
            check(problems, NativeIdentityPersistence.restoration(load(root, V3).histories()).retiringIds
                    .equals(Set.of(ID_A)), "a retired account does not restore a RETIRING pin");
        });
        run("V3 / confirm retired refuses an unknown inventory, an orphaned kind and incomplete receipts", problems -> {
            refused(problems, LEGACY, "a legacy marker", confirm(receipts()));
            refused(problems, slotA(2, retiring(legacyMarker(), hold(0))), "a held legacy marker", confirm(receipts()));
            Retirement orphaned = with(byUserRetirement(),
                    obligation(ObligationKind.WORK, ObligationState.ORPHANED_WITH_USER, ZERO, 0, 0));
            refused(problems, slotA(2, retiring(orphaned)), "an orphaned retirement kind", confirm(receipts()));
            Slot durable = slotA(2, retiring(byUserRetirement()));
            List<Obligation> receipts = receipts();
            refused(problems, durable, "eight receipts", confirm(receipts.subList(0, 8)));
            List<Obligation> ten = new ArrayList<>(receipts);
            ten.add(obligation(ObligationKind.ANDROID_STATE, ObligationState.DISCHARGED, ZERO, 0, 0));
            refused(problems, durable, "a disposition kind", confirm(ten));
            List<Obligation> swapped = new ArrayList<>(receipts);
            swapped.set(0, receipts.get(1));
            swapped.set(1, receipts.get(0));
            refused(problems, durable, "receipts out of order", confirm(swapped));
            List<Obligation> open = new ArrayList<>(receipts);
            open.set(2, obligation(ObligationKind.DELEGATIONS, ObligationState.OUTSTANDING, ZERO, 0, 0));
            refused(problems, durable, "an outstanding receipt", confirm(open));
            refused(problems, durable, "no receipts", confirm(List.of()));
        });
        run("V3 / confirm retired binds a reference once and keeps a discharged kind", problems -> {
            List<Obligation> receipts = receipts();
            Obligation work = receipts.get(0); // Binds a reference.
            Obligation api = receipts.get(1); // Discharges with none.
            Retirement progressed = with(with(byUserRetirement(),
                    obligation(ObligationKind.WORK, ObligationState.OUTSTANDING, work.reference, 0, 0)), api);
            Slot durable = slotA(2, retiring(progressed));
            List<Obligation> rebound = new ArrayList<>(receipts);
            rebound.set(0, obligation(ObligationKind.WORK, ObligationState.DISCHARGED, "77".repeat(16), 1, TIME));
            refused(problems, durable, "a bound reference bound again", confirm(rebound));
            List<Obligation> unbound = new ArrayList<>(receipts);
            unbound.set(0, obligation(ObligationKind.WORK, ObligationState.DISCHARGED, ZERO, 1, TIME));
            refused(problems, durable, "a bound reference of zero", confirm(unbound));
            List<Obligation> changed = new ArrayList<>(receipts);
            changed.set(1, obligation(ObligationKind.API_EFFECTS, ObligationState.DISCHARGED, ZERO, 99, TIME));
            refused(problems, durable, "a discharged kind changed", confirm(changed));
            written(problems, durable, slotA(3, retired(discharged(progressed, receipts))), 2, "consistent receipts",
                    confirm(receipts));
        });
        run("V3 / confirm retired refuses an account that is not retiring before any effect", problems -> {
            refused(problems, ELIGIBLE, "an eligible account", confirm(receipts()));
            refused(problems, slotA(2, eligible(byUser(SuspensionReason.USER_PAUSED))), "a suspended account",
                    confirm(receipts()));
            refused(problems, slotA(3, retired(discharged(byUserRetirement(), receipts()))), "a retired account",
                    confirm(receipts()));
        });
    }

    // ------------------------------------------------------------------ the generic update

    private static void genericCases() {
        run("V3 / the generic update refuses every lifecycle change", problems -> {
            Suspension user = byUser(SuspensionReason.USER_PAUSED);
            Retirement block = byUserRetirement();
            Retirement done = discharged(block, receipts());
            List<Slot[]> changes = List.of(
                    new Slot[] {ELIGIBLE, slotA(2, Lifecycle.version1(true))},
                    new Slot[] {ELIGIBLE, slotA(2, eligible(user))},
                    new Slot[] {slotA(2, eligible(user)), slotA(3, eligible())},
                    new Slot[] {slotA(3, retired(done)), slotA(4, retiring(block))},
                    new Slot[] {slotA(3, retired(done, user)), slotA(4, retiring(block, user))},
                    new Slot[] {slotA(2, retiring(block)), slotA(3, retired(done))},
                    new Slot[] {slotA(2, retiring(block)), slotA(3, retiring(byGrantRetirement()))},
                    new Slot[] {slotA(2, retiring(block)), slotA(3, eligible())},
                    new Slot[] {LEGACY, slotA(2, retiring(legacyContinued()))},
                    new Slot[] {slotA(3, retired(done)), slotA(4, retired(allDischarged(block)))});
            for (Slot[] change : changes) {
                Path root = layout(change[0]);
                unchanged(problems, root, change[0] + " to " + change[1],
                        () -> open(root, V3).updateExistingSlot(change[0], change[1]));
            }
        });
        run("V3 / the generic update never drops a user", problems -> {
            // Even RETIRED with every obligation discharged and no entry: the release engine's alone.
            Slot ready = slotA(3, retired(allDischarged(byUserRetirement())));
            for (Slot durable : List.of(ready, LEGACY, ELIGIBLE, slotA(3, retiring(byUserRetirement())))) {
                long generation = durable.generation + 1;
                for (Slot target : List.of(new Slot(LINEAGE, A, PKG_A, generation, SIGNERS, List.of()),
                        new Slot(LINEAGE, A, PKG_A, generation, SIGNERS, List.of(),
                                new ReleaseTicket(ID_A, 0, SERIAL, "66".repeat(16))))) {
                    Path root = layout(durable);
                    unchanged(problems, root, durable + " to " + target,
                            () -> open(root, V3).updateExistingSlot(durable, target));
                }
            }
        });
        run("V3 / the generic update keeps every user's identity", problems -> {
            Suspension user = byUser(SuspensionReason.USER_PAUSED);
            for (Lifecycle lifecycle : List.of(Lifecycle.version1(false), eligible(user), retiring(byUserRetirement()))) {
                Slot durable = slotA(2, lifecycle);
                // The same principal bound to another incarnation of its user, or to another user.
                for (UserEntry moved : List.of(new UserEntry(ID_A, 0, SERIAL + 1, lifecycle),
                        new UserEntry(ID_A, 10, SERIAL, lifecycle))) {
                    Slot next = new Slot(LINEAGE, A, PKG_A, 3, SIGNERS, List.of(moved));
                    Path root = layout(durable);
                    unchanged(problems, root, durable + " to " + next,
                            () -> open(root, V3).updateExistingSlot(durable, next));
                }
                // The same identity is rewritten: the refusal is the identity's.
                Path root = layout(durable);
                Slot same = slotA(3, lifecycle);
                check(problems, open(root, V3).updateExistingSlot(durable, same) && same.equals(stored(root, V3)),
                        "control " + lifecycle);
            }
        });
        run("V3 / the generic update never writes a ticket", problems -> {
            ReleaseTicket ticket = new ReleaseTicket(ID_A, 0, SERIAL, "66".repeat(16));
            Slot plain = new Slot(LINEAGE, A, PKG_A, 2, SIGNERS, List.of());
            Slot ticketed = new Slot(LINEAGE, A, PKG_A, 2, SIGNERS, List.of(), ticket);
            List<Slot[]> changes = List.of(
                    new Slot[] {plain, new Slot(LINEAGE, A, PKG_A, 3, SIGNERS, List.of(), ticket)},
                    new Slot[] {ticketed, new Slot(LINEAGE, A, PKG_A, 3, SIGNERS, List.of())},
                    new Slot[] {ticketed, new Slot(LINEAGE, A, PKG_A, 3, SIGNERS, List.of(),
                            new ReleaseTicket(ID_A, 0, SERIAL, "77".repeat(16)))});
            for (Slot[] change : changes) {
                Path root = layout(change[0]);
                unchanged(problems, root, change[0] + " to " + change[1],
                        () -> open(root, V3).updateExistingSlot(change[0], change[1]));
            }
            // The same ticket is rewritten: the refusal is the ticket's. Only the release engine
            // writes one.
            Path root = layout(ticketed);
            Slot same = new Slot(LINEAGE, A, PKG_A, 3, SIGNERS, List.of(), ticket);
            check(problems, open(root, V3).updateExistingSlot(ticketed, same) && same.equals(stored(root, V3)),
                    "control");
        });
        run("V3 / the generic update still rewrites an unchanged lifecycle", problems -> {
            Suspension user = byUser(SuspensionReason.USER_PAUSED);
            Slot durable = slotA(2, eligible(user, hold(0)));
            Slot next = slotA(3, eligible(user, hold(0)));
            Path root = layout(durable);
            check(problems, open(root, V3).updateExistingSlot(durable, next) && next.equals(stored(root, V3)),
                    "an unchanged lifecycle was refused");
        });
    }

    // ------------------------------------------------------------------ shared refusals

    private static void sharedCases() {
        List<Transition> each = List.of(suspend(byUser(SuspensionReason.USER_PAUSED)),
                lift(byUser(SuspensionReason.USER_PAUSED)), retire(byUserRetirement()), confirm(receipts()));
        run("V3 / every transition needs the fresh durable value", problems -> {
            Suspension user = byUser(SuspensionReason.USER_PAUSED);
            List<Slot> durables = List.of(slotA(5, eligible()), slotA(5, eligible(user)), slotA(5, eligible()),
                    slotA(5, retiring(byUserRetirement())));
            for (int i = 0; i < each.size(); i++) {
                Slot durable = durables.get(i);
                // The caller's stale copy names an earlier generation of the same value.
                Slot stale = slotA(durable.generation - 1, durable.users.get(0).lifecycle);
                Path root = layout(durable);
                Transition transition = each.get(i);
                unchanged(problems, root, "transition " + i, () -> transition.run(open(root, V3), stale));
            }
        });
        run("V3 / every transition refuses at the last generation before any effect", problems -> {
            Suspension user = byUser(SuspensionReason.USER_PAUSED);
            List<Slot> durables = List.of(slotA(Long.MAX_VALUE, eligible()), slotA(Long.MAX_VALUE, eligible(user)),
                    slotA(Long.MAX_VALUE, eligible()), slotA(Long.MAX_VALUE, retiring(byUserRetirement())));
            for (int i = 0; i < each.size(); i++) {
                Slot durable = durables.get(i);
                Path root = layout(durable);
                Transition transition = each.get(i);
                unchanged(problems, root, "transition " + i, () -> transition.run(open(root, V3), durable));
            }
        });
        run("V3 / every transition refuses beside a later slot version's footprint", problems -> {
            Suspension user = byUser(SuspensionReason.USER_PAUSED);
            List<Slot> durables = List.of(ELIGIBLE, slotA(2, eligible(user)), ELIGIBLE,
                    slotA(2, retiring(byUserRetirement())));
            for (int i = 0; i < each.size(); i++) {
                Slot durable = durables.get(i);
                Path root = store(header(2, live(A), live(B)));
                slot(root, durable);
                byte[] later = laterFrameB();
                raw(root, B, later, later);
                Transition transition = each.get(i);
                unchanged(problems, root, "transition " + i, () -> transition.run(open(root, V3), durable));
            }
        });
        run("V3 / a header phase change completes a suspended body", problems -> {
            Slot suspended = slotA(1, eligible(byUser(SuspensionReason.USER_PAUSED)));
            Header creating = creatingA();
            Path root = store(creating);
            slot(root, suspended);
            NativeIdentityStore store = open(root, V3);
            check(problems, store.confirmExistingSlot(suspended), "the shared confirmation refused a suspended body");
            Header live = Header.newV2(LINEAGE, ID_A, List.of(live(A)));
            check(problems, store.writeHeader(creating, live) && live.equals(load(root, V3).header.value),
                    "the header did not complete");
        });
        for (Format format : EARLIER) {
            run(format + " / every transition refuses before any effect", problems -> {
                Slot suspended = slotA(2, eligible(byUser(SuspensionReason.USER_PAUSED)));
                List<Slot> durables = List.of(ELIGIBLE, ELIGIBLE, ELIGIBLE, LEGACY);
                List<Slot> expected = List.of(ELIGIBLE, suspended, ELIGIBLE, LEGACY);
                for (int i = 0; i < each.size(); i++) {
                    Path root = layout(durables.get(i));
                    Transition transition = each.get(i);
                    Slot value = expected.get(i);
                    unchanged(problems, root, "transition " + i, () -> transition.run(open(root, format), value));
                }
                Path root = layout(LEGACY);
                unchanged(problems, root, "a continuation", () -> open(root, format).markSlotRetiring(LEGACY, ID_A,
                        legacyContinued()));
            });
        }
    }

    // An intact version 3 slot frame: B's suspended version 2 body and five bytes of a later
    // extension, relabelled and sealed again. Its stable prefix is valid, and it is a footprint in
    // every format.
    private static byte[] laterFrameB() throws Exception {
        byte[] encoded = NativeIdentityRecords.encodeSlot(slotB(1, eligible(byUser(SuspensionReason.USER_PAUSED))));
        byte[] unsealed = Arrays.copyOf(Arrays.copyOf(encoded, encoded.length - 32), encoded.length - 27);
        unsealed[6] = 3;
        unsealed[7] = 0;
        int length = unsealed.length + 32;
        for (int i = 0; i < 4; i++) unsealed[8 + i] = (byte) (length >>> (8 * i));
        byte[] record = Arrays.copyOf(unsealed, length);
        System.arraycopy(MessageDigest.getInstance("SHA-256").digest(unsealed), 0, record, unsealed.length, 32);
        if (NativeIdentityRecords.intactSlotVersion(record) != 3) throw new AssertionError("later frame");
        return record;
    }

    public static void main(String[] args) throws Exception {
        if (!NativeLifecycleStoreTest.class.desiredAssertionStatus()) throw new AssertionError("run with java -ea");
        start(Path.of(args[0]).resolve("lifecycle-store"));
        suspendCases();
        liftCases();
        retireCases();
        confirmCases();
        genericCases();
        sharedCases();
        finish(Os.allClosed());
        System.out.println("Lifecycle store transitions kept the record's store rules; Android unqualified");
    }
}
