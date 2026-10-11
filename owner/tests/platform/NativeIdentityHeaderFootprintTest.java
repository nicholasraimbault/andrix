// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeHeaderTestSupport.*;

import android.system.Os;
import com.android.server.LocalServices;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityStore.Status;
import com.android.server.pm.NativePrincipalPins.Record;
import com.android.server.pm.NativePrincipalPins.Snapshot;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Header copy compatibility and unselected additions. An older writer could stop with its new
 * copies complete beside a preferred backup that still held the prior header, leaving
 * reservations only an unselected copy lists. Each case isolates one constructed layout in a
 * fresh store. A header conservation refusal comes before that header step's effects, with its
 * bytes, file identities and times unchanged. Under the earlier formats the release steps, the
 * retiring flag, the user drop, RELEASING, the removal, the omission and the released
 * confirmation, are lifecycle writes and refuse before any effect, whatever the copies hold; the
 * V3 cases run those steps through the release engine's primitives beside the same copies.
 * The exact original owner's retry must still succeed, and legitimate interrupted
 * phase changes and copies that predate a protected reservation stay compatible.
 * The shared support constructs each store and host facade with an explicit format and passes
 * each reservation as a CreationPlan. The archived controls compile their own pinned copies of
 * this suite. Host facades only: not Android crash, power loss, storage or UID authority
 * qualification.
 */
public final class NativeIdentityHeaderFootprintTest {
    private static final Header OLD = header(0);
    private static final Header PENDING_B = header(1, creating(B, 1, PKG_B));
    private static final Record RECORD_B = record(1, PKG_B, B);
    private static final Snapshot REUSE = new Snapshot(1, List.of(record(1, PKG_C, C)));

    // The constructed interrupted reservation of B beside an empty preferred backup.
    private static void storeRepro() {
        run("store repro / admission refuses reuse of B's creation ID", problems -> {
            Path root = legacy(OLD, PENDING_B);
            NativeIdentityStore.Loaded loaded = loaded(root);
            check(problems, loaded.header.status == Status.VALID && OLD.equals(loaded.header.value)
                    && loaded.occupiedAppIds.equals(Set.of(B)) && loaded.creationReady(),
                    "not the constructed selection " + loaded.header.status);
            check(problems, project(persistence(root), loaded, REUSE) == null,
                    "C admitted at creation ID 1");
        });
        run("store repro / reservation refused before any effect", problems -> {
            Path root = legacy(OLD, PENDING_B);
            NativeIdentityPersistence persistence = persistence(root);
            unchanged(problems, root, "C reservation", () -> reserve(persistence, REUSE));
            check(problems, persistence.load().occupiedAppIds.equals(Set.of(B)), "B hold lost");
        });
        run("store repro / direct header write refused", problems -> {
            Path root = legacy(OLD, PENDING_B);
            NativeIdentityStore store = store(root);
            unchanged(problems, root, "C header",
                    () -> store.writeHeader(OLD, header(1, creating(C, 1, PKG_C))));
        });
        run("store repro / selected header rewrite refused", problems -> {
            Path root = legacy(OLD, PENDING_B);
            NativeIdentityStore store = store(root);
            unchanged(problems, root, "selected header", () -> store.writeHeader(OLD, OLD));
        });
    }

    // Every private header confirmation caller refuses before its first effect.
    private static void confirmationCallers() {
        Header creatingA = header(1, creating(A, 1, PKG_A));
        Header creatingAB = header(2, creating(A, 1, PKG_A), creating(B, 2, PKG_B));
        run("initializeNew refused", problems -> {
            Path root = legacy(OLD, PENDING_B);
            NativeIdentityStore store = store(root);
            unchanged(problems, root, "initialization", () -> store.initializeNew(LINEAGE));
        });
        run("ensureFreshSlot refused", problems -> {
            Path root = legacy(creatingA, creatingAB);
            NativeIdentityStore store = store(root);
            unchanged(problems, root, "fresh directory", () -> store.ensureFreshSlot(creatingA, A));
        });
        run("resumeCreatingDirectory refused", problems -> {
            Path root = legacy(creatingA, creatingAB);
            NativeIdentityStore store = store(root);
            unchanged(problems, root, "resumed directory",
                    () -> store.resumeCreatingDirectory(creatingA, A));
        });
        run("publishCreatingSlot refused", problems -> {
            Path root = legacy(creatingA, creatingAB);
            Files.createDirectory(root.resolve("slots/" + A));
            NativeIdentityStore store = store(root);
            unchanged(problems, root, "publication",
                    () -> store.publishCreatingSlot(creatingA, bound(A, PKG_A, 1, false, 1)));
        });
        // The release confirmations are lifecycle writes: under version 1 they refuse first, beside
        // an unreconciled addition and in a store of one header without one, and under Format.V2 too,
        // over a copy of the same version 1 state (refusedUnderEarlierFormats).
        run("V1 confirmReleasedSlot refused before any effect", problems -> {
            Path root = legacy(OLD, PENDING_B);
            refusedUnderEarlierFormats(problems, root, "release of B", s -> s.confirmReleasedSlot(OLD, B));
            Header omittedR = header(1);
            Path released = layout(null, bytes(omittedR), bytes(omittedR));
            refusedUnderEarlierFormats(problems, released, "released confirmation",
                    s -> s.confirmReleasedSlot(omittedR, R));
        });
        run("V1 removeReleasingSlot refused before any effect", problems -> {
            Header releasingR = header(1, releasing(R));
            Path root = legacy(releasingR, header(2, releasing(R), creating(B, 2, PKG_B)));
            slot(root, R, tombstone(R, PKG_R, 3));
            refusedUnderEarlierFormats(problems, root, "removal", s -> s.removeReleasingSlot(releasingR, R));
            Path single = layout(null, bytes(releasingR), bytes(releasingR));
            slot(single, R, tombstone(R, PKG_R, 3));
            refusedUnderEarlierFormats(problems, single, "removal beside one header",
                    s -> s.removeReleasingSlot(releasingR, R));
        });
    }

    // Unrelated transitions wait until the addition's own reservation is restated.
    private static void transitions() {
        run("CREATING to LIVE waits for reconciliation", problems -> {
            Header prior = header(1, creating(A, 1, PKG_A));
            Header next = header(2, creating(A, 1, PKG_A), creating(B, 2, PKG_B));
            Path root = legacy(prior, next);
            slot(root, A, bound(A, PKG_A, 1, false, 1));
            NativeIdentityStore store = store(root);
            unchanged(problems, root, "completion", () -> store.writeHeader(prior, header(1, live(A))));
            check(problems, store.writeHeader(prior, next), "exact reconciliation refused");
            Header completed = header(2, live(A), creating(B, 2, PKG_B));
            check(problems, store.writeHeader(next, completed), "completion after reconciliation refused");
            check(problems, completed.equals(stored(root)), "header " + stored(root));
        });
        // The release header steps refuse under version 1 before and after the reconciliation,
        // which itself still restates the addition.
        run("V1 LIVE to RELEASING refused before and after reconciliation", problems -> {
            Header prior = header(1, live(A));
            Header next = header(2, live(A), creating(B, 2, PKG_B));
            Path root = legacy(prior, next);
            slot(root, A, tombstone(A, PKG_A, 2));
            NativeIdentityStore store = store(root);
            refusedUnderEarlierFormats(problems, root, "release marker",
                    s -> s.writeHeader(prior, header(1, releasing(A))));
            check(problems, store.writeHeader(prior, next), "exact reconciliation refused");
            Header marked = header(2, releasing(A), creating(B, 2, PKG_B));
            refusedUnderEarlierFormats(problems, root, "marker after reconciliation",
                    s -> s.writeHeader(next, marked));
            check(problems, next.equals(stored(root)), "header " + stored(root));
        });
        run("V1 final omission refused before and after reconciliation", problems -> {
            Header prior = header(1, releasing(A));
            Header next = header(2, releasing(A), creating(B, 2, PKG_B));
            Path root = legacy(prior, next);
            NativeIdentityStore store = store(root);
            refusedUnderEarlierFormats(problems, root, "omission", s -> s.writeHeader(prior, header(1)));
            check(problems, store.writeHeader(prior, next), "exact reconciliation refused");
            Header omitted = header(2, creating(B, 2, PKG_B));
            refusedUnderEarlierFormats(problems, root, "omission after reconciliation",
                    s -> s.writeHeader(next, omitted));
            check(problems, next.equals(stored(root)), "header " + stored(root));
        });
        // The owned retirement's steps, its user drop to the tombstone, RELEASING and the omission,
        // each refuse with no tombstone progress.
        run("V1 owned retirement refused before any effect", problems -> {
            Header prior = header(1, live(A)), next = header(2, live(A), creating(B, 2, PKG_B));
            Path root = legacy(prior, next);
            Slot retiring = bound(A, PKG_A, 1, true, 2);
            slot(root, A, retiring);
            NativeIdentityStore store = store(root);
            Slot tombstone = new Slot(LINEAGE, A, PKG_A, 3, SIGNERS, List.of());
            refusedUnderEarlierFormats(problems, root, "tombstone",
                    s -> s.updateExistingSlot(retiring, tombstone));
            check(problems, store.writeHeader(prior, next), "exact reconciliation refused");
            refusedUnderEarlierFormats(problems, root, "release marker",
                    s -> s.writeHeader(next, header(2, releasing(A), creating(B, 2, PKG_B))));
            refusedUnderEarlierFormats(problems, root, "omission",
                    s -> s.writeHeader(next, header(2, creating(B, 2, PKG_B))));
            NativeIdentityPersistence persistence = persistence(root);
            check(problems, retiring.equals(persistence.load().slots.get(A).value), "slot changed");
            check(problems, persistence.load().occupiedAppIds.equals(Set.of(A, B)), "holds changed");
        });
    }

    // The exact original plan still restates its own addition.
    private static void ownerRetries() {
        run("exact original B retry", problems -> {
            Path root = legacy(OLD, PENDING_B);
            check(problems, reserve(persistence(root), new Snapshot(1, List.of(RECORD_B))),
                    "original retry refused");
            check(problems, PENDING_B.equals(stored(root))
                    && !Files.exists(root.resolve("store.bin-backup"), LinkOption.NOFOLLOW_LINKS),
                    "reservation " + stored(root));
        });
        run("original plan with C id2", problems -> {
            Path root = legacy(OLD, PENDING_B);
            Snapshot plan = new Snapshot(2, List.of(RECORD_B, record(2, PKG_C, C)));
            check(problems, reserve(persistence(root), plan), "plan refused");
            check(problems, header(2, creating(B, 1, PKG_B), creating(C, 2, PKG_C)).equals(stored(root)),
                    "reservation " + stored(root));
        });
        run("unpublished RETIRING B restated", problems -> {
            Path root = legacy(OLD, PENDING_B);
            check(problems, reserve(persistence(root), new Snapshot(1, List.of(RECORD_B),
                    Set.of(1L))), "retiring plan refused");
            check(problems, PENDING_B.equals(stored(root)), "reservation " + stored(root));
        });
    }

    // Unequal copies at app IDs the selected header lists are not additions.
    private static void legitimateDifferences() {
        Header creatingAC = header(2, creating(A, 1, PKG_A), creating(C, 2, PKG_C));
        Header liveAC = header(2, live(A), creating(C, 2, PKG_C));
        run("interrupted CREATING to LIVE is compatible", problems -> {
            Path root = legacy(creatingAC, liveAC);
            slot(root, A, bound(A, PKG_A, 1, false, 1));
            bootCounter(problems, root, 2);
            NativeIdentityStore store = store(root);
            check(problems, store.resumeCreatingDirectory(creatingAC, C), "unrelated creation refused");
            Path retry = legacy(creatingAC, liveAC);
            slot(retry, A, bound(A, PKG_A, 1, false, 1));
            check(problems, persistence(retry).publish(record(1, PKG_A, A), SIGNERS)
                    && liveAC.equals(stored(retry)), "exact completion retry refused");
        });
        // An interrupted release stays compatible, so boot restores its counter, but under version 1
        // its retry is a lifecycle write and refuses before any effect.
        run("V1 interrupted LIVE to RELEASING restores, and its retry refuses", problems -> {
            Header liveA = header(1, live(A)), releasingA = header(1, releasing(A));
            Path root = legacy(liveA, releasingA);
            slot(root, A, tombstone(A, PKG_A, 2));
            bootCounter(problems, root, 1);
            refusedUnderEarlierFormats(problems, root, "exact marker retry",
                    s -> s.writeHeader(liveA, releasingA));
        });
        run("V1 interrupted omission restores, and its retry refuses", problems -> {
            Header prior = header(2, live(A), releasing(R)), omitted = header(2, live(A));
            Path root = legacy(prior, omitted);
            slot(root, A, bound(A, PKG_A, 1, false, 1));
            bootCounter(problems, root, 2);
            refusedUnderEarlierFormats(problems, root, "exact omission retry",
                    s -> s.writeHeader(prior, omitted));
            refusedUnderEarlierFormats(problems, root, "released confirmation",
                    s -> s.confirmReleasedSlot(omitted, R));
        });
    }

    // One decodable unselected copy is enough, whichever position survived.
    private static void survivingCopies() {
        for (boolean mainSurvives : List.of(true, false)) {
            String name = mainSurvives ? "single intact main beside a torn reserve counts"
                    : "single intact reserve beside a torn main counts";
            run(name, problems -> {
                Path root = layout(bytes(OLD), mainSurvives ? bytes(PENDING_B) : GARBAGE,
                        mainSurvives ? GARBAGE : bytes(PENDING_B));
                NativeIdentityStore store = store(root);
                check(problems, project(new NativeIdentityPersistence(store), store.load(), REUSE) == null,
                        "C admitted at creation ID 1");
                unchanged(problems, root, "selected header", () -> store.writeHeader(OLD, OLD));
                bootCounter(problems, root, -1);
                check(problems, reserve(new NativeIdentityPersistence(store),
                        new Snapshot(1, List.of(RECORD_B))) && PENDING_B.equals(stored(root)),
                        "original retry refused");
            });
        }
    }

    // Copies that disagree cannot all be kept, so nothing is merged or chosen between them.
    private static void inconsistentCopies() {
        run("disagreeing copies of one addition refuse", problems -> {
            Path root = layout(bytes(OLD), bytes(PENDING_B), bytes(header(2, creating(B, 2, PKG_B))));
            NativeIdentityPersistence persistence = persistence(root);
            unchanged(problems, root, "main's B",
                    () -> reserve(persistence, new Snapshot(1, List.of(RECORD_B))));
            unchanged(problems, root, "reserve's B", () -> reserve(persistence,
                    new Snapshot(2, List.of(record(2, PKG_B, B)))));
            bootCounter(problems, root, -1);
        });
        run("additions sharing a creation ID refuse", problems -> {
            Path root = layout(bytes(OLD), bytes(PENDING_B), bytes(header(1, creating(D, 1, PKG_D))));
            NativeIdentityPersistence persistence = persistence(root);
            unchanged(problems, root, "B alone",
                    () -> reserve(persistence, new Snapshot(1, List.of(RECORD_B))));
            unchanged(problems, root, "D alone", () -> reserve(persistence,
                    new Snapshot(1, List.of(record(1, PKG_D, D)))));
            bootCounter(problems, root, -1);
        });
    }

    // Another app ID, creation ID or package cannot stand in for the addition.
    private static void substitutes() {
        Map<String, Snapshot> plans = new TreeMap<>();
        plans.put("app ID", new Snapshot(1, List.of(record(1, PKG_B, E))));
        plans.put("creation ID", new Snapshot(2, List.of(record(2, PKG_B, B))));
        plans.put("package", new Snapshot(1, List.of(record(1, PKG_X, B))));
        for (Map.Entry<String, Snapshot> plan : plans.entrySet()) {
            run("B not substituted by another " + plan.getKey(), problems -> {
                Path root = legacy(OLD, PENDING_B);
                NativeIdentityPersistence persistence = persistence(root);
                check(problems, project(persistence, persistence.load(),
                        plan.getValue()) == null, "substitute admitted");
                unchanged(problems, root, "substitute",
                        () -> reserve(persistence, plan.getValue()));
            });
        }
    }

    // A decodable copy of another lineage is neither merged nor overwritten.
    private static void foreignLineage() {
        Header foreignEmpty = new Header(FOREIGN, 0, List.of());
        run("addition of another lineage not reinterpreted", problems -> {
            Path root = legacy(OLD, new Header(FOREIGN, 1, List.of(creating(B, 1, PKG_B))));
            NativeIdentityPersistence persistence = persistence(root);
            Snapshot own = new Snapshot(1, List.of(RECORD_B));
            check(problems, project(persistence, persistence.load(), own) == null,
                    "foreign B admitted into this lineage");
            unchanged(problems, root, "restatement", () -> reserve(persistence, own));
            bootCounter(problems, root, -1);
        });
        run("copy of another lineage refuses writes", problems -> {
            Path root = legacy(OLD, foreignEmpty);
            NativeIdentityStore store = store(root);
            unchanged(problems, root, "selected header", () -> store.writeHeader(OLD, OLD));
            bootCounter(problems, root, -1);
        });
        run("selected backup of another lineage refuses writes", problems -> {
            Path root = legacy(foreignEmpty, OLD);
            NativeIdentityStore store = store(root);
            check(problems, foreignEmpty.equals(stored(root)), "not the constructed selection");
            unchanged(problems, root, "selected header",
                    () -> store.writeHeader(foreignEmpty, foreignEmpty));
            bootCounter(problems, root, -1);
        });
    }

    // The actual manager over a reopened PMS facade, as in the reported reproduction.
    private static void managerRepro() {
        run("manager repro / reopened PMS issues nothing", problems -> {
            Path root = legacy(OLD, PENDING_B);
            PackageManagerService pm = reopen(root, Map.of(PKG_B, B, PKG_C, C));
            check(problems, pm.mSettings.isNativePrincipalAppIdLPr(B), "B hold missing");
            check(problems, !pm.mSettings.pins.hasKnownCounter(), "selected lower counter restored");
            check(problems, !pm.mSettings.nativePrincipalCreationReadyLPr(), "issuance ready beside B");
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            age(root);
            Map<String, String> before = footprint(root);
            NativePrincipalManager.Handle issued = null;
            try {
                issued = manager.prepare(manager.select(PKG_C, 0));
            } catch (IllegalStateException refused) {
                // No ID for C while B's footprint remains.
            }
            if (issued != null) {
                problems.add("C issued ID " + manager.identity(issued).id);
                if (manager.commit(issued)) problems.add("C reservation acknowledged");
            }
            check(problems, pm.mSettings.pins.find(PKG_C, 0) == null, "C pinned");
            check(problems, footprint(root).equals(before), "store changed");
            check(problems, pm.mSettings.isNativePrincipalAppIdLPr(B), "current B hold lost");
            PackageManagerService again = reopen(root, Map.of(PKG_B, B, PKG_C, C));
            check(problems, again.mSettings.isNativePrincipalAppIdLPr(B)
                    && again.mSettings.persistence.load().occupiedAppIds.contains(B),
                    "reopened B hold lost");
            check(problems, !again.mSettings.pins.hasKnownCounter(), "reopened counter restored");
            pm.mSettings.observeNativeIdentityStoreLPw(missing());
            check(problems, pm.mSettings.isNativePrincipalAppIdLPr(B), "a reduced refresh dropped B");
        });
    }

    // The same live manager after an older writer left its reservation unselected.
    private static void legacyReservation(PackageManagerService pm, Header prior, Header next)
            throws Exception {
        copies(pm.mSettings.root, bytes(prior), bytes(next), bytes(next));
        observe(pm);
    }

    private static void sameManager() {
        run("same manager / original B retry", problems -> {
            PackageManagerService pm = livePm();
            Path root = pm.mSettings.root;
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
            check(problems, manager.identity(b).id == 1, "B was not issued ID 1");
            legacyReservation(pm, OLD, PENDING_B);
            check(problems, pm.mSettings.pins.hasKnownCounter()
                    && pm.mSettings.nativePrincipalCreationReadyLPr(), "live registry state changed");
            check(problems, manager.commit(b), "original retry refused");
            check(problems, header(1, live(B)).equals(stored(root)), "header " + stored(root));
            check(problems, pm.mSettings.pins.snapshotForWrite().lastId == 1, "another ID consumed");
        });
        for (boolean cFirst : List.of(true, false)) {
            run("same manager / C id2, " + (cFirst ? "C" : "B") + " committed first", problems -> {
                PackageManagerService pm = livePm();
                Path root = pm.mSettings.root;
                NativePrincipalManager manager = new NativePrincipalManager(pm);
                NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
                legacyReservation(pm, OLD, PENDING_B);
                NativePrincipalManager.Handle c = manager.prepare(manager.select(PKG_C, 0));
                check(problems, manager.identity(c).id == 2, "C was not issued the next ID");
                check(problems, manager.commit(cFirst ? c : b), "first commit refused");
                check(problems, manager.commit(cFirst ? b : c), "second commit refused");
                check(problems, header(2, live(B), live(C)).equals(stored(root)), "header " + stored(root));
                check(problems, pm.mSettings.pins.snapshotForWrite().lastId == 2, "another ID consumed");
            });
        }
        run("same manager / unpublished RETIRING B with C id2", problems -> {
            PackageManagerService pm = livePm();
            Path root = pm.mSettings.root;
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
            pm.mSettings.pins.beginRetire(pm.mSettings.pins.find(PKG_B, 0));
            legacyReservation(pm, OLD, PENDING_B);
            NativePrincipalManager.Handle c = manager.prepare(manager.select(PKG_C, 0));
            check(problems, manager.identity(c).id == 2 && manager.commit(c), "C refused beside B");
            check(problems, header(2, creating(B, 1, PKG_B), live(C)).equals(stored(root)),
                    "B not restated: " + stored(root));
            // B's retirement refuses under the version 1 format before any effect: B stays reserved.
            check(problems, retirementRefused(root, manager, b), "B's retirement");
            check(problems, header(2, creating(B, 1, PKG_B), live(C)).equals(stored(root)), "header " + stored(root));
        });
        run("same manager / C issued first, both restated", problems -> {
            PackageManagerService pm = livePm();
            Path root = pm.mSettings.root;
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle c = manager.prepare(manager.select(PKG_C, 0));
            NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
            legacyReservation(pm, OLD, header(2, creating(B, 2, PKG_B), creating(C, 1, PKG_C)));
            check(problems, manager.commit(c), "C retry refused");
            check(problems, manager.commit(b), "B retry refused");
            check(problems, header(2, live(B), live(C)).equals(stored(root)), "header " + stored(root));
        });
        run("same manager / B release waits for C", problems -> {
            PackageManagerService pm = livePm();
            Path root = pm.mSettings.root;
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
            check(problems, manager.commit(b), "B commit refused");
            NativePrincipalManager.Handle c = manager.prepare(manager.select(PKG_C, 0));
            legacyReservation(pm, header(1, live(B)), header(2, live(B), creating(C, 2, PKG_C)));
            // B's retirement refuses under the version 1 format before any effect, beside C's
            // unreconciled reservation as after it: nothing is released.
            check(problems, retirementRefused(root, manager, b), "B's retirement beside C");
            check(problems, manager.phase(b) == NativePrincipalPins.Phase.ACTIVE
                    && pm.mSettings.isNativePrincipalAppIdLPr(C)
                    && pm.mSettings.persistence.load().occupiedAppIds.contains(C), "holds changed");
            check(problems, manager.commit(c), "C retry refused");
            check(problems, retirementRefused(root, manager, b), "B's retirement after C");
            check(problems, header(2, live(B), live(C)).equals(stored(root)), "header " + stored(root));
        });
    }

    // A reopened registry keeps every hold and eligible LIVE binding, but not the counter.
    private static void reopened() {
        run("reopened registry keeps holds and LIVE bindings", problems -> {
            Path root = legacy(header(1, live(A)), header(2, live(A), creating(B, 2, PKG_B)));
            slot(root, A, bound(A, PKG_A, 1, false, 1));
            PackageManagerService pm = reopen(root, Map.of(PKG_A, A, PKG_B, B));
            check(problems, !pm.mSettings.pins.hasKnownCounter(), "selected lower counter restored");
            check(problems, pm.mSettings.pins.find(PKG_A, 0) != null, "LIVE binding not restored");
            check(problems, pm.mSettings.isNativePrincipalAppIdLPr(A)
                    && pm.mSettings.isNativePrincipalAppIdLPr(B), "holds");
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle a = manager.find(PKG_A, 0);
            check(problems, a != null && a == manager.prepare(manager.select(PKG_A, 0))
                    && manager.commit(a), "LIVE binding not confirmed without the counter");
        });
    }

    // Structural compatibility: what the writers can leave is accepted, nothing else is.
    private static void compatibility() {
        run("predecessor of a protected reservation is compatible", problems -> {
            Path root = layout(bytes(PENDING_B), bytes(OLD), bytes(OLD));
            bootCounter(problems, root, 1);
            check(problems, reserve(persistence(root), new Snapshot(1, List.of(RECORD_B)))
                    && PENDING_B.equals(stored(root)), "exact retry refused");
            Path later = layout(bytes(PENDING_B), bytes(OLD), bytes(OLD));
            check(problems, reserve(persistence(later), new Snapshot(2, List.of(RECORD_B,
                    record(2, PKG_C, C)))) && header(2, creating(B, 1, PKG_B), creating(C, 2, PKG_C))
                    .equals(stored(later)), "later reservation refused");
        });
        run("dropped CREATING entry is no predecessor", problems -> {
            Header creatingA = header(1, creating(A, 1, PKG_A));
            Path root = legacy(creatingA, header(1));
            NativeIdentityStore store = store(root);
            unchanged(problems, root, "selected header", () -> store.writeHeader(creatingA, creatingA));
            bootCounter(problems, root, -1);
        });
        run("lower counter without a newer reservation refuses", problems -> {
            Header selected = header(2, live(A));
            Path root = legacy(selected, header(1, live(A)));
            NativeIdentityStore store = store(root);
            unchanged(problems, root, "selected header", () -> store.writeHeader(selected, selected));
            bootCounter(problems, root, -1);
        });
        run("higher counter only copy refuses header writes", problems -> {
            Header selected = header(1, live(A));
            Path root = legacy(selected, header(3, live(A)));
            NativeIdentityStore store = store(root);
            NativeIdentityPersistence persistence = persistence(root);
            unchanged(problems, root, "selected header", () -> store.writeHeader(selected, selected));
            unchanged(problems, root, "reservation above it", () -> reserve(persistence,
                    new Snapshot(4, List.of(record(4, PKG_C, C)))));
            bootCounter(problems, root, -1);
        });
        run("counter advances only with a pure reservation", problems -> {
            Header selected = header(1, live(A));
            Path root = layout(null, bytes(selected), bytes(selected));
            NativeIdentityStore store = store(root);
            unchanged(problems, root, "counter only write",
                    () -> store.writeHeader(selected, header(3, live(A))));
            unchanged(problems, root, "counter only reservation",
                    () -> reserve(persistence(root), new Snapshot(3, List.of())));
            check(problems, store.writeHeader(selected, header(3, live(A), creating(C, 3, PKG_C))),
                    "pure reservation refused");
        });
        run("mixed phase change and reservation write refuses", problems -> {
            Header prior = header(1, creating(A, 1, PKG_A));
            Path root = layout(null, bytes(prior), bytes(prior));
            slot(root, A, bound(A, PKG_A, 1, false, 1));
            NativeIdentityStore store = store(root);
            unchanged(problems, root, "mixed write",
                    () -> store.writeHeader(prior, header(2, live(A), creating(C, 2, PKG_C))));
            check(problems, store.writeHeader(prior, header(1, live(A))), "completion refused");
            check(problems, store.writeHeader(header(1, live(A)), header(2, live(A),
                    creating(C, 2, PKG_C))), "later reservation refused");
        });
        run("mixed forward phase and addition copy needs its reservation first", problems -> {
            Header prior = header(1, creating(A, 1, PKG_A));
            Path root = legacy(prior, header(2, live(A), creating(B, 2, PKG_B)));
            slot(root, A, bound(A, PKG_A, 1, false, 1));
            NativeIdentityPersistence persistence = persistence(root);
            Record a = record(1, PKG_A, A);
            unchanged(problems, root, "completion", () -> persistence.publish(a, SIGNERS));
            check(problems, reserve(persistence, new Snapshot(2, List.of(a, record(2, PKG_B, B)))),
                    "reservation refused");
            check(problems, header(2, creating(A, 1, PKG_A), creating(B, 2, PKG_B)).equals(stored(root)),
                    "reservation " + stored(root));
            check(problems, persistence.publish(a, SIGNERS)
                    && header(2, live(A), creating(B, 2, PKG_B)).equals(stored(root)),
                    "completion after the reservation refused");
        });
        Map<String, Header[]> kinds = new TreeMap<>();
        kinds.put("backward phase", new Header[] {header(1, live(A)), header(1, creating(A, 1, PKG_A))});
        kinds.put("skipped phase", new Header[] {header(1, creating(A, 1, PKG_A)), header(1, releasing(A))});
        kinds.put("changed CREATING tuple",
                new Header[] {header(1, creating(A, 1, PKG_A)), header(1, creating(A, 1, PKG_X))});
        kinds.put("dropped LIVE entry", new Header[] {header(1, live(A)), header(1)});
        kinds.put("LIVE addition", new Header[] {header(1, live(A)), header(1, live(A), live(B))});
        kinds.put("addition at or below the counter",
                new Header[] {header(2, live(A)), header(2, live(A), creating(B, 1, PKG_B))});
        for (Map.Entry<String, Header[]> kind : kinds.entrySet()) {
            run("incompatible copy / " + kind.getKey(), problems -> {
                Header selected = kind.getValue()[0];
                Path root = legacy(selected, kind.getValue()[1]);
                NativeIdentityStore store = store(root);
                check(problems, selected.equals(stored(root)), "not the constructed selection");
                unchanged(problems, root, "selected header", () -> store.writeHeader(selected, selected));
                bootCounter(problems, root, -1);
            });
        }
        run("new entry in the observed range must be a known addition", problems -> {
            Path root = legacy(OLD, header(2, creating(B, 2, PKG_B)));
            NativeIdentityPersistence persistence = persistence(root);
            Snapshot invented = new Snapshot(3, List.of(record(1, PKG_C, C), record(2, PKG_B, B),
                    record(3, PKG_D, D)));
            check(problems, project(persistence, persistence.load(), invented) == null,
                    "new identity admitted inside the observed counter");
            unchanged(problems, root, "invented reservation", () -> reserve(persistence, invented));
            check(problems, reserve(persistence, new Snapshot(3, List.of(record(2, PKG_B, B),
                    record(3, PKG_D, D)))), "reservation above the observed counter refused");
        });
        run("restatement must cover every copy counter", problems -> {
            Path root = legacy(OLD, header(2, creating(B, 1, PKG_B)));
            NativeIdentityPersistence persistence = persistence(root);
            unchanged(problems, root, "restatement below the copy counter",
                    () -> reserve(persistence, new Snapshot(1, List.of(RECORD_B))));
            check(problems, reserve(persistence, new Snapshot(2, List.of(RECORD_B)))
                    && header(2, creating(B, 1, PKG_B)).equals(stored(root)), "covering restatement refused");
        });
    }

    // The release header steps under the lifecycle format, through the release engine's own
    // primitives, beside an older writer's unreconciled addition: the confirmation fence and the
    // reconciliation rule are the only refusals left, as the version 1 cases showed them before the
    // earlier formats stopped writing these steps.
    private static void lifecycleArms() {
        run("V3 confirmReleasedSlot cannot release an addition", problems -> {
            Path root = legacy(OLD, PENDING_B);
            NativeIdentityStore store = lifecycleStore(root);
            unchanged(problems, root, "release of B", () -> store.confirmReleasedSlot(OLD, B));
        });
        run("V3 removeReleasingSlot refused", problems -> {
            Header releasingR = header(1, releasing(R));
            Path root = legacy(releasingR, header(2, releasing(R), creating(B, 2, PKG_B)));
            slot(root, R, ticketed(R, PKG_R, 1, 3));
            NativeIdentityStore store = lifecycleStore(root);
            unchanged(problems, root, "removal", () -> store.removeReleasingSlot(releasingR, R));
        });
        run("V3 LIVE to RELEASING waits for reconciliation", problems -> {
            Header prior = header(1, live(A));
            Header next = header(2, live(A), creating(B, 2, PKG_B));
            Path root = legacy(prior, next);
            slot(root, A, ticketed(A, PKG_A, 1, 2));
            NativeIdentityStore store = lifecycleStore(root);
            unchanged(problems, root, "release marker", () -> store.markSlotReleasing(prior, A));
            check(problems, store.writeHeader(prior, next), "exact reconciliation refused");
            Header marked = header(2, releasing(A), creating(B, 2, PKG_B));
            check(problems, store.markSlotReleasing(next, A), "marker after reconciliation refused");
            check(problems, marked.equals(lifecycleStore(root).load().header.value), "header " + stored(root));
        });
        run("V3 unrelated final omission waits for reconciliation", problems -> {
            Header prior = header(1, releasing(A));
            Header next = header(2, releasing(A), creating(B, 2, PKG_B));
            Path root = legacy(prior, next);
            NativeIdentityStore store = lifecycleStore(root);
            unchanged(problems, root, "omission", () -> store.omitReleasedSlot(prior, A));
            check(problems, store.writeHeader(prior, next), "exact reconciliation refused");
            Header omitted = header(2, creating(B, 2, PKG_B));
            check(problems, store.omitReleasedSlot(next, A), "omission after reconciliation refused");
            check(problems, omitted.equals(lifecycleStore(root).load().header.value), "header " + stored(root));
        });
        run("V3 interrupted LIVE to RELEASING is compatible", problems -> {
            Header liveA = header(1, live(A)), releasingA = header(1, releasing(A));
            Path root = legacy(liveA, releasingA);
            slot(root, A, ticketed(A, PKG_A, 1, 2));
            check(problems, lifecycleStore(root).markSlotReleasing(liveA, A), "exact marker retry refused");
        });
        run("V3 interrupted omission is compatible", problems -> {
            Header prior = header(2, live(A), releasing(R)), omitted = header(2, live(A));
            Path root = legacy(prior, omitted);
            slot(root, A, bound(A, PKG_A, 1, false, 1));
            NativeIdentityStore store = lifecycleStore(root);
            check(problems, store.omitReleasedSlot(prior, R) && store.confirmReleasedSlot(omitted, R),
                    "exact omission retry refused");
        });
    }

    public static void main(String[] args) throws Exception {
        if (!NativeIdentityHeaderFootprintTest.class.desiredAssertionStatus()) {
            throw new AssertionError("run with java -ea");
        }
        if (!LINEAGE.equals(Settings.LINEAGE)) throw new AssertionError("facade lineage");
        start(Path.of(args[0]).resolve("header-footprint"));
        LocalServices.addService(UserManagerInternal.class, new UserManagerInternal());
        storeRepro();
        confirmationCallers();
        transitions();
        ownerRetries();
        legitimateDifferences();
        survivingCopies();
        inconsistentCopies();
        substitutes();
        foreignLineage();
        managerRepro();
        sameManager();
        reopened();
        compatibility();
        lifecycleArms();
        finish(Os.allClosed());
        System.out.println("Header copy compatibility and unselected additions kept by every header"
                + " writer and boot restore; Android crash recovery unqualified");
    }
}
