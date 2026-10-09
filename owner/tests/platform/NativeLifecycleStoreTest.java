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
 * drops no user. The deletion or migration step moves every disposition kind to DISPOSING at once,
 * never beside scope bit 0 or an orphaned kind, and confirm disposal moves only DISPOSING to
 * DISCHARGED, a reference bound once. Restore writes the intact copy of the highest generation with a
 * recovery hold, or ELIGIBLE held with scope bit 1 when no copy is intact, never over another account
 * or a tie, and confirms its own retry. Under Format.V1 and V2 every transition and Restore refuse
 * before any effect. Host files only, not Android persistence.
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
                Path eligibleA = layout(ELIGIBLE);
                unchanged(problems, eligibleA, "the deletion step", () -> open(eligibleA, format).beginSlotDisposition(
                        ELIGIBLE, ID_A));
                unchanged(problems, eligibleA, "a disposal", () -> open(eligibleA, format).dischargeSlotDisposition(
                        ELIGIBLE, ID_A, disposals(ObligationKind.KEYSTORE)));
                unchanged(problems, eligibleA, "restore of an intact record", () -> restore(eligibleA, format, RECOVERY));
                Path damagedA = damaged(torn(ELIGIBLE), torn(ELIGIBLE), null);
                unchanged(problems, damagedA, "restore of a damaged record", () -> open(damagedA, format).restoreSlot(
                        header(ID_A, live(A)), accountA(), RECOVERY));
            });
        }
    }

    // ------------------------------------------------------------------ disposition

    private static Transition begin() {
        return (store, expected) -> store.beginSlotDisposition(expected, ID_A);
    }

    private static Transition dispose(List<Obligation> receipts) {
        return (store, expected) -> store.dischargeSlotDisposition(expected, ID_A, receipts);
    }

    private static void dispositionCases() {
        Suspension user = byUser(SuspensionReason.USER_PAUSED);
        Suspension grant = byGrant(1, SuspensionReason.CREDENTIAL_EXPOSED);
        run("V3 / the deletion step moves every disposition kind to DISPOSING at once and changes nothing else",
                problems -> {
            Slot durable = slotA(3, retired(retiredBlock(), user, grant));
            Path root = layout(durable);
            check(problems, open(root, V3).beginSlotDisposition(durable, ID_A), "the step was refused");
            Slot expected = slotA(4, retired(disposing(retiredBlock()), user, grant));
            check(problems, expected.equals(stored(root, V3)) && holds(root, expected, 2), "wrote " + stored(root, V3));
            for (Obligation duty : stored(root, V3).users.get(0).lifecycle.retirement.obligations) {
                check(problems, duty.state == (duty.kind.disposition() ? ObligationState.DISPOSING
                        : ObligationState.DISCHARGED), "kind " + duty);
            }
        });
        run("V3 / the deletion step refuses beside scope bit 0, an orphaned kind or a deletion that began before any effect", problems -> {
            Suspension blocking = entry(ActorClass.ADMIN_GRANT, NativeIdentityRecords.SCOPE_BLOCKS_DISPOSITION, 0,
                    SERIAL, grant(9), SuspensionReason.DATA_TRANSFER, TIME);
            Suspension userBlocking = entry(ActorClass.ACCOUNT_USER, NativeIdentityRecords.SCOPE_BLOCKS_DISPOSITION, 0,
                    SERIAL, ZERO, SuspensionReason.USER_PAUSED, TIME);
            refused(problems, slotA(3, retired(retiredBlock(), user, blocking)), "a grant entry with bit 0", begin());
            refused(problems, slotA(3, retired(retiredBlock(), userBlocking)), "a user entry with bit 0", begin());
            refused(problems, slotA(3, retired(with(retiredBlock(), obligation(ObligationKind.HOME,
                    ObligationState.ORPHANED_WITH_USER, ZERO, 0, 0)))), "an orphaned kind", begin());
            Retirement began = disposing(retiredBlock());
            refused(problems, slotA(4, retired(began)), "a deletion that began", begin());
            refused(problems, slotA(4, retired(with(retiredBlock(), obligation(ObligationKind.KEYSTORE,
                    ObligationState.DISPOSING, ZERO, 0, 0)))), "one kind already DISPOSING", begin());
            refused(problems, slotA(5, retired(with(began, disposals(ObligationKind.DATA_CE).get(0)))),
                    "a deletion with a discharged kind", begin());
        });
        run("V3 / the deletion step refuses an account that is not RETIRED before any effect", problems -> {
            for (Slot durable : List.of(ELIGIBLE, slotA(2, eligible(user)), slotA(2, retiring(byUserRetirement())),
                    LEGACY, slotA(2, retiring(legacyContinued())))) {
                refused(problems, durable, "the step over " + durable, begin());
            }
        });
        run("V3 / confirm disposal discharges each DISPOSING kind it names and keeps everything else", problems -> {
            Retirement began = disposing(retiredBlock());
            Slot durable = slotA(4, retired(began, user));
            Path root = layout(durable);
            NativeIdentityStore store = open(root, V3);
            List<Obligation> first = disposals(ObligationKind.KEYSTORE, ObligationKind.DATA_CE);
            check(problems, store.dischargeSlotDisposition(durable, ID_A, first), "the first receipts were refused");
            Retirement partly = with(with(began, first.get(0)), first.get(1));
            Slot expected = slotA(5, retired(partly, user));
            check(problems, expected.equals(stored(root, V3)) && holds(root, expected, 2), "wrote " + stored(root, V3));
            List<Obligation> rest = disposals(ObligationKind.ANDROID_STATE, ObligationKind.DATA_DE,
                    ObligationKind.DATA_EXTERNAL, ObligationKind.HOME, ObligationKind.MANAGED_OBJECTS);
            check(problems, store.dischargeSlotDisposition(expected, ID_A, rest), "the other receipts were refused");
            Retirement done = partly;
            for (Obligation receipt : rest) done = with(done, receipt);
            Slot last = slotA(6, retired(done, user));
            check(problems, last.equals(stored(root, V3)) && holds(root, last, 2), "wrote " + stored(root, V3));
        });
        run("V3 / confirm disposal refuses outstanding and orphaned kinds and receipts no writer writes before any effect", problems -> {
            List<Obligation> keys = disposals(ObligationKind.KEYSTORE);
            refused(problems, slotA(3, retired(retiredBlock())), "an outstanding kind", dispose(keys));
            Retirement began = disposing(retiredBlock());
            refused(problems, slotA(4, retired(with(began, obligation(ObligationKind.KEYSTORE,
                    ObligationState.ORPHANED_WITH_USER, ZERO, 0, 0)))), "an orphaned kind", dispose(keys));
            refused(problems, slotA(2, retiring(byUserRetirement())), "a retiring account", dispose(keys));
            Obligation work = obligation(ObligationKind.WORK, ObligationState.DISCHARGED, ZERO, 0, 0);
            Obligation still = obligation(ObligationKind.HOME, ObligationState.DISPOSING, ZERO, 0, 0);
            Obligation orphaned = obligation(ObligationKind.HOME, ObligationState.ORPHANED_WITH_USER, ZERO, 0, 0);
            List<Obligation> twice = new ArrayList<>(keys);
            twice.addAll(keys);
            List<Obligation> backwards = new ArrayList<>(disposals(ObligationKind.HOME, ObligationKind.DATA_CE));
            for (List<Obligation> invalid : List.of(List.<Obligation>of(), List.of(work), List.of(still),
                    List.of(orphaned), twice, backwards)) {
                refused(problems, slotA(4, retired(began)), "receipts " + invalid, dispose(invalid));
            }
        });
        run("V3 / confirm disposal binds a reference once and keeps a discharged kind", problems -> {
            String bound = "77".repeat(16);
            Retirement began = with(disposing(retiredBlock()), obligation(ObligationKind.KEYSTORE,
                    ObligationState.DISPOSING, bound, 0, 0));
            Slot durable = slotA(4, retired(began));
            Obligation other = obligation(ObligationKind.KEYSTORE, ObligationState.DISCHARGED, "78".repeat(16), 1, 2);
            Obligation zero = obligation(ObligationKind.KEYSTORE, ObligationState.DISCHARGED, ZERO, 1, 2);
            refused(problems, durable, "another reference", dispose(List.of(other)));
            refused(problems, durable, "a bound reference made zero", dispose(List.of(zero)));
            Obligation same = obligation(ObligationKind.KEYSTORE, ObligationState.DISCHARGED, bound, 1, 2);
            Path root = layout(durable);
            check(problems, open(root, V3).dischargeSlotDisposition(durable, ID_A, List.of(same)),
                    "the bound reference was refused");
            Slot discharged = slotA(5, retired(with(began, same)));
            check(problems, discharged.equals(stored(root, V3)), "wrote " + stored(root, V3));
            Obligation changed = obligation(ObligationKind.KEYSTORE, ObligationState.DISCHARGED, bound, 3, 4);
            refused(problems, discharged, "a discharged kind with another receipt", dispose(List.of(changed)));
            Obligation home = disposals(ObligationKind.HOME).get(0);
            Path again = layout(discharged);
            check(problems, open(again, V3).dischargeSlotDisposition(discharged, ID_A, List.of(same, home)),
                    "an equal discharged receipt beside a new one was refused");
            check(problems, slotA(6, retired(with(with(began, same), home))).equals(stored(again, V3)),
                    "wrote " + stored(again, V3));
        });
    }

    // ------------------------------------------------------------------ restore

    // A store whose header holds A as LIVE, with these raw copies of A.
    private static Path damaged(byte[] main, byte[] reserve, byte[] backup) throws Exception {
        Path root = store(header(ID_A, live(A)));
        copies(root, main, reserve, backup);
        return root;
    }

    private static boolean restore(Path root, Format format, Suspension hold) {
        return open(root, format).restoreSlot(load(root, format).header.value, accountA(), hold);
    }

    private static void restoreCases() {
        Suspension user = byUser(SuspensionReason.USER_PAUSED);
        run("V3 / restore writes the intact copy of the highest generation with a recovery hold", problems -> {
            Slot retiredA = slotA(5, retired(retiredBlock(), user));
            Slot retiringA = slotA(4, retiring(byUserRetirement(), user));
            // Main and reserve differ: a conflict.
            Path conflict = damaged(bytes(retiredA), bytes(retiringA), null);
            check(problems, load(conflict, V3).slots.get(A).status == NativeIdentityStore.Status.CONFLICT,
                    "not a conflict");
            check(problems, restore(conflict, V3, RECOVERY), "the conflict was not restored");
            Slot expected = slotA(6, retired(retiredBlock(), user, RECOVERY));
            check(problems, expected.equals(stored(conflict, V3)) && holds(conflict, expected, 2),
                    "restored " + stored(conflict, V3));
            // The same copies the other way round, and a torn preferred backup: damage.
            Path torn = damaged(bytes(retiringA), bytes(retiredA), torn(retiredA));
            check(problems, load(torn, V3).slots.get(A).status == NativeIdentityStore.Status.DAMAGED, "not damage");
            check(problems, restore(torn, V3, RECOVERY) && expected.equals(stored(torn, V3))
                    && holds(torn, expected, 2), "restored " + stored(torn, V3));
            // An older intact backup is selected, but the newer main is the last known state.
            Slot older = slotA(2, eligible(user));
            Slot newer = slotA(3, retiring(byUserRetirement(), user));
            Path interrupted = damaged(bytes(newer), null, bytes(older));
            check(problems, older.equals(stored(interrupted, V3)), "the backup was not selected");
            Slot fromNewer = slotA(4, retiring(byUserRetirement(), user, RECOVERY));
            check(problems, restore(interrupted, V3, RECOVERY) && fromNewer.equals(stored(interrupted, V3))
                    && holds(interrupted, fromNewer, 2), "restored " + stored(interrupted, V3));
            // An intact eligible record takes the hold beside its entries.
            Path intact = layout(slotA(2, eligible(user)));
            Slot held = slotA(3, eligible(user, RECOVERY));
            check(problems, restore(intact, V3, RECOVERY) && held.equals(stored(intact, V3)),
                    "restored " + stored(intact, V3));
        });
        run("V3 / restore writes ELIGIBLE with scope bit 1 when no copy is intact", problems -> {
            Slot unknown = slotA(1, eligible(RECOVERY_UNKNOWN));
            Slot retiredA = slotA(5, retired(retiredBlock()));
            for (Path root : List.of(damaged(torn(retiredA), torn(retiredA), null),
                    damaged(null, null, torn(retiredA)), damaged(new byte[] {1}, null, new byte[] {2}))) {
                check(problems, restore(root, V3, RECOVERY), "refused");
                check(problems, unknown.equals(stored(root, V3)) && holds(root, unknown, 2),
                        "restored " + stored(root, V3));
            }
        });
        run("V3 / restore refuses copies of another account, a tombstone, a tie at the highest generation and a full record before any effect", problems -> {
            Slot otherId = new Slot(LINEAGE, A, PKG_A, 2, SIGNERS, List.of(new UserEntry(ID_B, 0, SERIAL, false)));
            Slot otherSerial = new Slot(LINEAGE, A, PKG_A, 2, SIGNERS, List.of(new UserEntry(ID_A, 0, SERIAL + 1,
                    false)));
            Slot otherPackage = new Slot(LINEAGE, A, "dev.andrix.other", 2, SIGNERS, List.of(new UserEntry(ID_A, 0,
                    SERIAL, false)));
            Slot otherSigners = new Slot(LINEAGE, A, PKG_A, 2, OTHER_SIGNERS, List.of(new UserEntry(ID_A, 0, SERIAL,
                    false)));
            Slot otherLineage = new Slot("d".repeat(32), A, PKG_A, 2, SIGNERS, List.of(new UserEntry(ID_A, 0, SERIAL,
                    false)));
            Slot tombstone = new Slot(LINEAGE, A, PKG_A, 6, SIGNERS, List.of(), new ReleaseTicket(ID_A, 0, SERIAL,
                    "55".repeat(16)));
            Slot ours = slotA(3, retired(retiredBlock()));
            for (Slot foreign : List.of(otherId, otherSerial, otherPackage, otherSigners, otherLineage, tombstone)) {
                Path root = store(header(ID_B, live(A)));
                copies(root, bytes(ours), bytes(foreign), null);
                unchanged(problems, root, "restore beside " + foreign, () -> restore(root, V3, RECOVERY));
            }
            Path tie = damaged(bytes(slotA(3, eligible(user))), bytes(slotA(3, retiring(byUserRetirement()))), null);
            unchanged(problems, tie, "restore of a tie", () -> restore(tie, V3, RECOVERY));
            List<Suspension> grants = new ArrayList<>();
            for (int i = 1; i <= 6; i++) grants.add(byGrant(i, SuspensionReason.DATA_TRANSFER));
            Path full = damaged(bytes(slotA(2, eligible(grants.toArray(new Suspension[0])))), null, null);
            unchanged(problems, full, "restore of a full record", () -> restore(full, V3, RECOVERY));
            Path last = damaged(bytes(slotA(Long.MAX_VALUE, eligible(user))), null, null);
            unchanged(problems, last, "restore at the last generation", () -> restore(last, V3, RECOVERY));
            Path invalid = damaged(torn(ours), null, null);
            for (Suspension hold : List.of(RECOVERY_UNKNOWN, user, entry(ActorClass.RECOVERY_HOLD,
                    NativeIdentityRecords.SCOPE_BLOCKS_DISPOSITION, 0, SERIAL, ZERO, SuspensionReason.RECOVERY_REVIEW,
                    TIME), entry(ActorClass.RECOVERY_HOLD, 0, 0, SERIAL, ZERO, SuspensionReason.DATA_TRANSFER, TIME))) {
                unchanged(problems, invalid, "restore with " + hold, () -> restore(invalid, V3, hold));
            }
        });
        run("V3 / restore refuses a RELEASING or missing entry, a stale header, a footprint and a missing body before any effect", problems -> {
            byte[] broken = torn(slotA(3, retired(retiredBlock())));
            Path releasing = store(header(ID_A, new NativeIdentityRecords.HeaderEntry(A,
                    NativeIdentityRecords.SlotPhase.RELEASING, 0, "")));
            copies(releasing, broken, broken, null);
            unchanged(problems, releasing, "restore under RELEASING", () -> restore(releasing, V3, RECOVERY));
            Path absent = store(header(ID_A, live(B)));
            copies(absent, broken, broken, null);
            unchanged(problems, absent, "restore without an entry", () -> restore(absent, V3, RECOVERY));
            Path unissued = damaged(broken, broken, null);
            NativeIdentityStore store = open(unissued, V3);
            unchanged(problems, unissued, "restore against a stale header", () -> store.restoreSlot(header(ID_B,
                    live(A)), accountA(), RECOVERY));
            Path counter = store(header(0, live(A)));
            copies(counter, broken, broken, null);
            unchanged(problems, counter, "restore above the counter", () -> restore(counter, V3, RECOVERY));
            Path footprint = store(header(ID_B, live(A), live(B)));
            copies(footprint, broken, broken, null);
            byte[] later = laterFrameB();
            raw(footprint, B, later, later);
            unchanged(problems, footprint, "restore beside a later frame", () -> restore(footprint, V3, RECOVERY));
            Path empty = store(header(ID_A, live(A)));
            java.nio.file.Files.createDirectories(empty.resolve("slots/" + A));
            unchanged(problems, empty, "restore of a missing body", () -> restore(empty, V3, RECOVERY));
            Path gone = store(header(ID_A, live(A)));
            unchanged(problems, gone, "restore without a directory", () -> restore(gone, V3, RECOVERY));
            Path creating = store(creatingA());
            copies(creating, broken, broken, null);
            Slot otherSerial = new Slot(LINEAGE, A, PKG_A, 1, SIGNERS, List.of(new UserEntry(ID_A, 0, SERIAL + 1,
                    false)));
            unchanged(problems, creating, "restore of another creation", () -> open(creating, V3).restoreSlot(
                    creatingA(), otherSerial, RECOVERY));
            check(problems, open(creating, V3).restoreSlot(creatingA(), accountA(), RECOVERY)
                    && slotA(1, eligible(RECOVERY_UNKNOWN)).equals(stored(creating, V3))
                    && creatingA().equals(load(creating, V3).header.value), "the own creation was not restored");
        });
        run("V3 / restore keeps a held recovery hold and confirms its own retry", problems -> {
            Suspension earlier = new Suspension(ActorClass.RECOVERY_HOLD, 0, 0, SERIAL, ZERO,
                    SuspensionReason.RECOVERY_REVIEW.code, TIME - 1, null);
            Slot held = slotA(4, retiring(byUserRetirement(), earlier));
            Path intact = layout(held);
            age(intact);
            check(problems, restore(intact, V3, RECOVERY) && held.equals(stored(intact, V3))
                    && holds(intact, held, 2), "restored " + stored(intact, V3));
            Path conflict = damaged(bytes(held), bytes(slotA(3, retiring(byUserRetirement()))), null);
            Slot advanced = slotA(5, retiring(byUserRetirement(), earlier));
            check(problems, restore(conflict, V3, RECOVERY) && advanced.equals(stored(conflict, V3))
                    && holds(conflict, advanced, 2), "restored " + stored(conflict, V3));
            check(problems, restore(conflict, V3, RECOVERY) && advanced.equals(stored(conflict, V3)),
                    "the retry wrote " + stored(conflict, V3));
        });
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
        dispositionCases();
        restoreCases();
        finish(Os.allClosed());
        System.out.println("Lifecycle store transitions kept the record's store rules; Android unqualified");
    }
}
