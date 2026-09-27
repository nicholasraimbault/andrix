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
 * bytes, file identities and times unchanged. A multi-step retirement may already have committed
 * its tombstone before the header step refuses; those cases assert that progress explicitly.
 * The exact original owner's retry must still succeed, and legitimate interrupted
 * phase changes, omissions and copies that predate a protected reservation stay compatible.
 * Only product surface that predates the correction is used, so this also runs against the
 * earlier store, manager and Settings facade as a control. Host facades only: not Android
 * crash, power loss, storage or UID authority qualification.
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
            check(problems, NativeIdentityPersistence.projectReservation(loaded, REUSE) == null,
                    "C admitted at creation ID 1");
        });
        run("store repro / reservation refused before any effect", problems -> {
            Path root = legacy(OLD, PENDING_B);
            NativeIdentityPersistence persistence = persistence(root);
            unchanged(problems, root, "C reservation", () -> persistence.reservePending(REUSE));
            check(problems, persistence.load().occupiedAppIds.equals(Set.of(B)), "B hold lost");
        });
        run("store repro / direct header write refused", problems -> {
            Path root = legacy(OLD, PENDING_B);
            NativeIdentityStore store = new NativeIdentityStore(root.toFile());
            unchanged(problems, root, "C header",
                    () -> store.writeHeader(OLD, header(1, creating(C, 1, PKG_C))));
        });
        run("store repro / selected header rewrite refused", problems -> {
            Path root = legacy(OLD, PENDING_B);
            NativeIdentityStore store = new NativeIdentityStore(root.toFile());
            unchanged(problems, root, "selected header", () -> store.writeHeader(OLD, OLD));
        });
    }

    // Every private header confirmation caller refuses before its first effect.
    private static void confirmationCallers() {
        Header creatingA = header(1, creating(A, 1, PKG_A));
        Header creatingAB = header(2, creating(A, 1, PKG_A), creating(B, 2, PKG_B));
        run("initializeNew refused", problems -> {
            Path root = legacy(OLD, PENDING_B);
            NativeIdentityStore store = new NativeIdentityStore(root.toFile());
            unchanged(problems, root, "initialization", () -> store.initializeNew(LINEAGE));
        });
        run("ensureFreshSlot refused", problems -> {
            Path root = legacy(creatingA, creatingAB);
            NativeIdentityStore store = new NativeIdentityStore(root.toFile());
            unchanged(problems, root, "fresh directory", () -> store.ensureFreshSlot(creatingA, A));
        });
        run("resumeCreatingDirectory refused", problems -> {
            Path root = legacy(creatingA, creatingAB);
            NativeIdentityStore store = new NativeIdentityStore(root.toFile());
            unchanged(problems, root, "resumed directory",
                    () -> store.resumeCreatingDirectory(creatingA, A));
        });
        run("publishCreatingSlot refused", problems -> {
            Path root = legacy(creatingA, creatingAB);
            Files.createDirectory(root.resolve("slots/" + A));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile());
            unchanged(problems, root, "publication",
                    () -> store.publishCreatingSlot(creatingA, bound(A, PKG_A, 1, false, 1)));
        });
        run("confirmReleasedSlot cannot release an addition", problems -> {
            Path root = legacy(OLD, PENDING_B);
            NativeIdentityStore store = new NativeIdentityStore(root.toFile());
            unchanged(problems, root, "release of B", () -> store.confirmReleasedSlot(OLD, B));
        });
        run("removeReleasingSlot refused", problems -> {
            Header releasingR = header(1, releasing(R));
            Path root = legacy(releasingR, header(2, releasing(R), creating(B, 2, PKG_B)));
            slot(root, R, tombstone(R, PKG_R, 3));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile());
            unchanged(problems, root, "removal", () -> store.removeReleasingSlot(releasingR, R));
        });
    }

    // Unrelated transitions wait until the addition's own reservation is restated.
    private static void transitions() {
        run("CREATING to LIVE waits for reconciliation", problems -> {
            Header prior = header(1, creating(A, 1, PKG_A));
            Header next = header(2, creating(A, 1, PKG_A), creating(B, 2, PKG_B));
            Path root = legacy(prior, next);
            slot(root, A, bound(A, PKG_A, 1, false, 1));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile());
            unchanged(problems, root, "completion", () -> store.writeHeader(prior, header(1, live(A))));
            check(problems, store.writeHeader(prior, next), "exact reconciliation refused");
            Header completed = header(2, live(A), creating(B, 2, PKG_B));
            check(problems, store.writeHeader(next, completed), "completion after reconciliation refused");
            check(problems, completed.equals(stored(root)), "header " + stored(root));
        });
        run("LIVE to RELEASING waits for reconciliation", problems -> {
            Header prior = header(1, live(A));
            Header next = header(2, live(A), creating(B, 2, PKG_B));
            Path root = legacy(prior, next);
            slot(root, A, tombstone(A, PKG_A, 2));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile());
            unchanged(problems, root, "release marker",
                    () -> store.writeHeader(prior, header(1, releasing(A))));
            check(problems, store.writeHeader(prior, next), "exact reconciliation refused");
            Header marked = header(2, releasing(A), creating(B, 2, PKG_B));
            check(problems, store.writeHeader(next, marked), "marker after reconciliation refused");
            check(problems, marked.equals(stored(root)), "header " + stored(root));
        });
        run("unrelated final omission waits for reconciliation", problems -> {
            Header prior = header(1, releasing(A));
            Header next = header(2, releasing(A), creating(B, 2, PKG_B));
            Path root = legacy(prior, next);
            NativeIdentityStore store = new NativeIdentityStore(root.toFile());
            unchanged(problems, root, "omission", () -> store.writeHeader(prior, header(1)));
            check(problems, store.writeHeader(prior, next), "exact reconciliation refused");
            Header omitted = header(2, creating(B, 2, PKG_B));
            check(problems, store.writeHeader(next, omitted), "omission after reconciliation refused");
            check(problems, omitted.equals(stored(root)), "header " + stored(root));
        });
        run("owned retirement header steps refused", problems -> {
            Path root = legacy(header(1, live(A)), header(2, live(A), creating(B, 2, PKG_B)));
            slot(root, A, bound(A, PKG_A, 1, true, 2));
            NativeIdentityPersistence persistence = persistence(root);
            age(root);
            Map<String, String> before = headerFootprint(root);
            check(problems, !persistence.finishRetirement(record(1, PKG_A, A), LINEAGE, SIGNERS),
                    "retirement acknowledged");
            check(problems, headerFootprint(root).equals(before), "header copies changed");
            NativeIdentityStore.ReadResult<Slot> progressed = persistence.load().slots.get(A);
            Slot tombstone = new Slot(LINEAGE, A, PKG_A, 3, SIGNERS, List.of());
            check(problems, progressed != null && progressed.status == Status.VALID
                    && tombstone.equals(progressed.value)
                    && progressed.decodedCopies.stream().allMatch(tombstone::equals),
                    "owned tombstone progress not retained before header refusal");
            check(problems, persistence.load().occupiedAppIds.equals(Set.of(A, B)), "holds changed");
        });
    }

    // The exact original plan still restates its own addition.
    private static void ownerRetries() {
        run("exact original B retry", problems -> {
            Path root = legacy(OLD, PENDING_B);
            check(problems, persistence(root).reservePending(new Snapshot(1, List.of(RECORD_B))),
                    "original retry refused");
            check(problems, PENDING_B.equals(stored(root))
                    && !Files.exists(root.resolve("store.bin-backup"), LinkOption.NOFOLLOW_LINKS),
                    "reservation " + stored(root));
        });
        run("original plan with C id2", problems -> {
            Path root = legacy(OLD, PENDING_B);
            Snapshot plan = new Snapshot(2, List.of(RECORD_B, record(2, PKG_C, C)));
            check(problems, persistence(root).reservePending(plan), "plan refused");
            check(problems, header(2, creating(B, 1, PKG_B), creating(C, 2, PKG_C)).equals(stored(root)),
                    "reservation " + stored(root));
        });
        run("unpublished RETIRING B restated", problems -> {
            Path root = legacy(OLD, PENDING_B);
            check(problems, persistence(root).reservePending(new Snapshot(1, List.of(RECORD_B),
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
            NativeIdentityStore store = new NativeIdentityStore(root.toFile());
            check(problems, store.resumeCreatingDirectory(creatingAC, C), "unrelated creation refused");
            Path retry = legacy(creatingAC, liveAC);
            slot(retry, A, bound(A, PKG_A, 1, false, 1));
            check(problems, persistence(retry).publish(record(1, PKG_A, A), SIGNERS)
                    && liveAC.equals(stored(retry)), "exact completion retry refused");
        });
        run("interrupted LIVE to RELEASING is compatible", problems -> {
            Header liveA = header(1, live(A)), releasingA = header(1, releasing(A));
            Path root = legacy(liveA, releasingA);
            slot(root, A, tombstone(A, PKG_A, 2));
            bootCounter(problems, root, 1);
            check(problems, new NativeIdentityStore(root.toFile()).writeHeader(liveA, releasingA),
                    "exact marker retry refused");
        });
        run("interrupted omission is compatible", problems -> {
            Header prior = header(2, live(A), releasing(R)), omitted = header(2, live(A));
            Path root = legacy(prior, omitted);
            slot(root, A, bound(A, PKG_A, 1, false, 1));
            bootCounter(problems, root, 2);
            NativeIdentityStore store = new NativeIdentityStore(root.toFile());
            check(problems, store.writeHeader(prior, omitted) && store.confirmReleasedSlot(omitted, R),
                    "exact omission retry refused");
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
                NativeIdentityStore store = new NativeIdentityStore(root.toFile());
                check(problems, NativeIdentityPersistence.projectReservation(store.load(), REUSE) == null,
                        "C admitted at creation ID 1");
                unchanged(problems, root, "selected header", () -> store.writeHeader(OLD, OLD));
                bootCounter(problems, root, -1);
                check(problems, new NativeIdentityPersistence(store).reservePending(
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
                    () -> persistence.reservePending(new Snapshot(1, List.of(RECORD_B))));
            unchanged(problems, root, "reserve's B", () -> persistence.reservePending(
                    new Snapshot(2, List.of(record(2, PKG_B, B)))));
            bootCounter(problems, root, -1);
        });
        run("additions sharing a creation ID refuse", problems -> {
            Path root = layout(bytes(OLD), bytes(PENDING_B), bytes(header(1, creating(D, 1, PKG_D))));
            NativeIdentityPersistence persistence = persistence(root);
            unchanged(problems, root, "B alone",
                    () -> persistence.reservePending(new Snapshot(1, List.of(RECORD_B))));
            unchanged(problems, root, "D alone", () -> persistence.reservePending(
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
                check(problems, NativeIdentityPersistence.projectReservation(persistence.load(),
                        plan.getValue()) == null, "substitute admitted");
                unchanged(problems, root, "substitute",
                        () -> persistence.reservePending(plan.getValue()));
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
            check(problems, NativeIdentityPersistence.projectReservation(persistence.load(), own) == null,
                    "foreign B admitted into this lineage");
            unchanged(problems, root, "restatement", () -> persistence.reservePending(own));
            bootCounter(problems, root, -1);
        });
        run("copy of another lineage refuses writes", problems -> {
            Path root = legacy(OLD, foreignEmpty);
            NativeIdentityStore store = new NativeIdentityStore(root.toFile());
            unchanged(problems, root, "selected header", () -> store.writeHeader(OLD, OLD));
            bootCounter(problems, root, -1);
        });
        run("selected backup of another lineage refuses writes", problems -> {
            Path root = legacy(foreignEmpty, OLD);
            NativeIdentityStore store = new NativeIdentityStore(root.toFile());
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
            check(problems, manager.beginRetirement(b), "B marker retry refused");
            check(problems, manager.finishRetirementAfterQuiescence(b), "B release refused");
            check(problems, header(2, live(C)).equals(stored(root)), "header " + stored(root));
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
            check(problems, manager.beginRetirement(b), "B marker refused");
            age(root);
            Map<String, String> before = headerFootprint(root);
            check(problems, !manager.finishRetirementAfterQuiescence(b), "B released beside C");
            check(problems, headerFootprint(root).equals(before), "header copies changed");
            NativeIdentityStore.ReadResult<Slot> progressed = pm.mSettings.persistence.load().slots.get(B);
            Slot tombstone = new Slot(LINEAGE, B, PKG_B, 3, SIGNERS, List.of());
            check(problems, progressed != null && progressed.status == Status.VALID
                    && tombstone.equals(progressed.value)
                    && progressed.decodedCopies.stream().allMatch(tombstone::equals),
                    "B tombstone progress not retained before header refusal");
            check(problems, manager.phase(b) == NativePrincipalPins.Phase.RETIRING
                    && pm.mSettings.isNativePrincipalAppIdLPr(C)
                    && pm.mSettings.persistence.load().occupiedAppIds.contains(C), "holds changed");
            check(problems, manager.commit(c), "C retry refused");
            check(problems, manager.finishRetirementAfterQuiescence(b), "B release refused afterwards");
            check(problems, header(2, live(C)).equals(stored(root)), "header " + stored(root));
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
            check(problems, persistence(root).reservePending(new Snapshot(1, List.of(RECORD_B)))
                    && PENDING_B.equals(stored(root)), "exact retry refused");
            Path later = layout(bytes(PENDING_B), bytes(OLD), bytes(OLD));
            check(problems, persistence(later).reservePending(new Snapshot(2, List.of(RECORD_B,
                    record(2, PKG_C, C)))) && header(2, creating(B, 1, PKG_B), creating(C, 2, PKG_C))
                    .equals(stored(later)), "later reservation refused");
        });
        run("dropped CREATING entry is no predecessor", problems -> {
            Header creatingA = header(1, creating(A, 1, PKG_A));
            Path root = legacy(creatingA, header(1));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile());
            unchanged(problems, root, "selected header", () -> store.writeHeader(creatingA, creatingA));
            bootCounter(problems, root, -1);
        });
        run("lower counter without a newer reservation refuses", problems -> {
            Header selected = header(2, live(A));
            Path root = legacy(selected, header(1, live(A)));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile());
            unchanged(problems, root, "selected header", () -> store.writeHeader(selected, selected));
            bootCounter(problems, root, -1);
        });
        run("higher counter only copy refuses header writes", problems -> {
            Header selected = header(1, live(A));
            Path root = legacy(selected, header(3, live(A)));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile());
            NativeIdentityPersistence persistence = persistence(root);
            unchanged(problems, root, "selected header", () -> store.writeHeader(selected, selected));
            unchanged(problems, root, "reservation above it", () -> persistence.reservePending(
                    new Snapshot(4, List.of(record(4, PKG_C, C)))));
            bootCounter(problems, root, -1);
        });
        run("counter advances only with a pure reservation", problems -> {
            Header selected = header(1, live(A));
            Path root = layout(null, bytes(selected), bytes(selected));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile());
            unchanged(problems, root, "counter only write",
                    () -> store.writeHeader(selected, header(3, live(A))));
            unchanged(problems, root, "counter only reservation",
                    () -> persistence(root).reservePending(new Snapshot(3, List.of())));
            check(problems, store.writeHeader(selected, header(3, live(A), creating(C, 3, PKG_C))),
                    "pure reservation refused");
        });
        run("mixed phase change and reservation write refuses", problems -> {
            Header prior = header(1, creating(A, 1, PKG_A));
            Path root = layout(null, bytes(prior), bytes(prior));
            slot(root, A, bound(A, PKG_A, 1, false, 1));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile());
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
            check(problems, persistence.reservePending(new Snapshot(2, List.of(a, record(2, PKG_B, B)))),
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
                NativeIdentityStore store = new NativeIdentityStore(root.toFile());
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
            check(problems, NativeIdentityPersistence.projectReservation(persistence.load(), invented) == null,
                    "new identity admitted inside the observed counter");
            unchanged(problems, root, "invented reservation", () -> persistence.reservePending(invented));
            check(problems, persistence.reservePending(new Snapshot(3, List.of(record(2, PKG_B, B),
                    record(3, PKG_D, D)))), "reservation above the observed counter refused");
        });
        run("restatement must cover every copy counter", problems -> {
            Path root = legacy(OLD, header(2, creating(B, 1, PKG_B)));
            NativeIdentityPersistence persistence = persistence(root);
            unchanged(problems, root, "restatement below the copy counter",
                    () -> persistence.reservePending(new Snapshot(1, List.of(RECORD_B))));
            check(problems, persistence.reservePending(new Snapshot(2, List.of(RECORD_B)))
                    && header(2, creating(B, 1, PKG_B)).equals(stored(root)), "covering restatement refused");
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
        finish(Os.allClosed());
        System.out.println("Header copy compatibility and unselected additions kept by every header"
                + " writer and boot restore; Android crash recovery unqualified");
    }
}
