// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeHeaderTestSupport.*;

import android.system.Os;
import com.android.server.LocalServices;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.Slot;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Host injected I/O failures at each step of the actual strict header writer, through the
 * actual manager, persistence and store. The harness inserts the fault seam into copies of the
 * store and strict writer sources; production sources contain none, and every case checks that
 * its step was reached. A pure reservation must keep a durable witness of every hold at each
 * step, including an unselected addition it restates, and the same original handle must then
 * finish without another ID. Other header writes keep their prior as the backup until their
 * final step. These are host injected failures, not Android crash or power loss evidence.
 */
public final class NativeHeaderWriteFaultTest {
    // Write steps in order. From backup-renamed on, a pure reservation's target is the backup.
    private static final List<String> STEPS = List.of("seed-synced", "backup-renamed",
            "backup-published", "write-started", "main-synced", "reserve-synced", "backup-unlink",
            "backup-unlinked");
    private static final String HEADER = "store.bin";
    private static final Header OLD = header(0);
    private static final Header PENDING_B = header(1, creating(B, 1, PKG_B));
    private static final Header PENDING_BC = header(2, creating(B, 1, PKG_B), creating(C, 2, PKG_C));

    private interface Transition { boolean run(NativeIdentityStore store) throws Exception; }

    // Every case disarms its seam, even when it fails before reaching it.
    private static void fault(String name, Body body) {
        run(name, problems -> {
            try {
                body.run(problems);
            } finally {
                NativeHeaderWriteFaults.disarm();
            }
        });
    }
    private static boolean protectedStep(String step) {
        return STEPS.indexOf(step) > 0;
    }
    private static void legacyReservation(PackageManagerService pm, Header prior, Header next)
            throws Exception {
        copies(pm.mSettings.root, bytes(prior), bytes(next), bytes(next));
        observe(pm);
    }

    // The reported late failure: an owned retry restating B, stopped after startWrite.
    private static void ownedRetry() {
        fault("owned retry keeps B through a failure after startWrite", problems -> {
            PackageManagerService pm = livePm();
            Path root = pm.mSettings.root;
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
            legacyReservation(pm, OLD, PENDING_B);
            NativeHeaderWriteFaults.arm("write-started", HEADER);
            check(problems, !manager.commit(b), "interrupted retry acknowledged");
            check(problems, NativeHeaderWriteFaults.reached(), "injected step not reached");
            check(problems, holds(root, "store.bin-backup", PENDING_B), "preferred backup is not the target");
            NativeIdentityStore.Loaded after = loaded(root);
            check(problems, PENDING_B.equals(after.header.value) && after.occupiedAppIds.contains(B),
                    "B not durable after reload: " + after.header.value);
            check(problems, pm.mSettings.isNativePrincipalAppIdLPr(B), "cached B hold lost");
            PackageManagerService reopened = reopen(root, Map.of(PKG_B, B));
            check(problems, reopened.mSettings.isNativePrincipalAppIdLPr(B), "reopened B hold lost");
            check(problems, reopened.mSettings.pins.hasKnownCounter()
                    && reopened.mSettings.pins.snapshotForWrite().lastId == 1, "reopened counter");
            check(problems, manager.commit(b), "same original handle retry refused");
            check(problems, header(1, live(B)).equals(stored(root)), "header " + stored(root));
            check(problems, pm.mSettings.pins.snapshotForWrite().lastId == 1, "another ID consumed");
        });
    }

    // An older writer's unselected B, restated by its owner, failing at every step.
    private static void legacyRetries() {
        for (String step : STEPS) {
            fault("legacy owned retry / " + step, problems -> {
                PackageManagerService pm = livePm();
                Path root = pm.mSettings.root;
                NativePrincipalManager manager = new NativePrincipalManager(pm);
                NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
                legacyReservation(pm, OLD, PENDING_B);
                NativeHeaderWriteFaults.arm(step, HEADER);
                check(problems, !manager.commit(b) && NativeHeaderWriteFaults.reached(), "no injected failure");
                NativeIdentityStore.Loaded after = loaded(root);
                check(problems, after.occupiedAppIds.contains(B), "durable B hold lost");
                check(problems, (protectedStep(step) ? PENDING_B : OLD).equals(after.header.value),
                        "selected " + after.header.value);
                check(problems, reopen(root, Map.of(PKG_B, B)).mSettings.isNativePrincipalAppIdLPr(B),
                        "reopened B hold lost");
                check(problems, manager.commit(b), "same original handle retry refused");
                check(problems, header(1, live(B)).equals(stored(root))
                        && pm.mSettings.pins.snapshotForWrite().lastId == 1, "retry result " + stored(root));
            });
        }
    }

    // A fresh reservation, failing at every step.
    private static void newReservations() {
        for (String step : STEPS) {
            fault("new reservation / " + step, problems -> {
                PackageManagerService pm = livePm();
                Path root = pm.mSettings.root;
                NativePrincipalManager manager = new NativePrincipalManager(pm);
                NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
                NativeHeaderWriteFaults.arm(step, HEADER);
                check(problems, !manager.commit(b) && NativeHeaderWriteFaults.reached(), "no injected failure");
                NativeIdentityStore.Loaded after = loaded(root);
                boolean target = protectedStep(step);
                check(problems, (target ? PENDING_B : OLD).equals(after.header.value)
                        && after.occupiedAppIds.contains(B) == target, "selected " + after.header.value);
                bootCounter(problems, root, target ? 1 : 0);
                check(problems, manager.commit(b), "same original handle retry refused");
                check(problems, header(1, live(B)).equals(stored(root))
                        && pm.mSettings.pins.snapshotForWrite().lastId == 1, "retry result " + stored(root));
            });
        }
    }

    // Phase changes, omissions and confirmations keep their prior as the backup until the end.
    private static void priorOrdering(String name, Header prior, Header next, int appId, Slot body,
            Transition write) {
        fault("prior ordering / " + name, problems -> {
            for (String step : STEPS) {
                Path root = layout(null, bytes(prior), bytes(prior));
                if (body != null) slot(root, appId, body);
                NativeIdentityStore store = store(root);
                NativeHeaderWriteFaults.arm(step, HEADER);
                check(problems, !write.run(store) && NativeHeaderWriteFaults.reached(),
                        step + ": no injected failure");
                NativeHeaderWriteFaults.disarm();
                boolean last = step.equals("backup-unlinked");
                check(problems, (last ? next : prior).equals(stored(root)), step + ": selected " + stored(root));
                if (protectedStep(step) && !last) {
                    check(problems, holds(root, "store.bin-backup", prior), step + ": backup is not the prior");
                }
                check(problems, write.run(store) && next.equals(stored(root)), step + ": retry refused");
            }
        });
    }

    private static void priorOrderings() {
        Header creatingA = header(1, creating(A, 1, PKG_A));
        Header liveA = header(1, live(A));
        Header releasingA = header(1, releasing(A));
        priorOrdering("publication", creatingA, liveA, A, bound(A, PKG_A, 1, false, 1),
                store -> store.writeHeader(creatingA, liveA));
        priorOrdering("release marker", liveA, releasingA, A, tombstone(A, PKG_A, 2),
                store -> store.writeHeader(liveA, releasingA));
        priorOrdering("omission", releasingA, header(1), A, null,
                store -> store.writeHeader(releasingA, header(1)));
        priorOrdering("confirmation", creatingA, creatingA, A, null,
                store -> store.ensureFreshSlot(creatingA, A));
    }

    // Protected targets may follow each other before either write finishes.
    private static void chained() {
        fault("chained protected reservations", problems -> {
            PackageManagerService pm = livePm();
            Path root = pm.mSettings.root;
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
            NativeHeaderWriteFaults.arm("backup-published", HEADER);
            check(problems, !manager.commit(b) && NativeHeaderWriteFaults.reached(), "first failure");
            check(problems, holds(root, "store.bin-backup", PENDING_B) && holds(root, HEADER, OLD),
                    "first protected layout");
            NativePrincipalManager.Handle c = manager.prepare(manager.select(PKG_C, 0));
            check(problems, manager.identity(c).id == 2, "C was not issued the next ID");
            NativeHeaderWriteFaults.arm("write-started", HEADER);
            check(problems, !manager.commit(c) && NativeHeaderWriteFaults.reached(), "second failure");
            check(problems, holds(root, "store.bin-backup", PENDING_BC), "second target not kept");
            NativeIdentityStore.Loaded after = loaded(root);
            check(problems, PENDING_BC.equals(after.header.value)
                    && after.occupiedAppIds.containsAll(Set.of(B, C)), "holds " + after.occupiedAppIds);
            bootCounter(problems, root, 2);
            check(problems, manager.commit(c) && manager.commit(b), "original retries refused");
            check(problems, header(2, live(B), live(C)).equals(stored(root))
                    && pm.mSettings.pins.snapshotForWrite().lastId == 2, "retry result " + stored(root));
        });
    }

    // An older writer's B, then C id2 from the same manager, either committed first.
    private static void legacyWithC() {
        for (boolean cFirst : List.of(true, false)) {
            fault("legacy B with C id2 / " + (cFirst ? "C" : "B") + " first", problems -> {
                PackageManagerService pm = livePm();
                Path root = pm.mSettings.root;
                NativePrincipalManager manager = new NativePrincipalManager(pm);
                NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
                legacyReservation(pm, OLD, PENDING_B);
                NativePrincipalManager.Handle c = manager.prepare(manager.select(PKG_C, 0));
                NativeHeaderWriteFaults.arm("write-started", HEADER);
                check(problems, !manager.commit(cFirst ? c : b) && NativeHeaderWriteFaults.reached(),
                        "no injected failure");
                NativeIdentityStore.Loaded after = loaded(root);
                check(problems, PENDING_BC.equals(after.header.value)
                        && after.occupiedAppIds.containsAll(Set.of(B, C)), "holds " + after.occupiedAppIds);
                check(problems, manager.commit(cFirst ? c : b) && manager.commit(cFirst ? b : c),
                        "original retries refused");
                check(problems, header(2, live(B), live(C)).equals(stored(root))
                        && pm.mSettings.pins.snapshotForWrite().lastId == 2, "retry result " + stored(root));
            });
        }
    }

    // An older writer's B whose original handle is already retiring.
    private static void retiring() {
        fault("unpublished RETIRING B", problems -> {
            PackageManagerService pm = livePm();
            Path root = pm.mSettings.root;
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
            legacyReservation(pm, OLD, PENDING_B);
            NativeHeaderWriteFaults.arm("write-started", HEADER);
            check(problems, !manager.beginRetirement(b) && NativeHeaderWriteFaults.reached()
                    && manager.phase(b) == NativePrincipalPins.Phase.RETIRING, "interrupted marker");
            check(problems, loaded(root).occupiedAppIds.contains(B)
                    && reopen(root, Map.of(PKG_B, B)).mSettings.isNativePrincipalAppIdLPr(B), "B hold lost");
            check(problems, manager.beginRetirement(b) && manager.finishRetirementAfterQuiescence(b),
                    "original retirement refused");
            check(problems, header(1).equals(stored(root))
                    && pm.mSettings.pins.snapshotForWrite().lastId == 1, "retirement result " + stored(root));
        });
    }

    // A publication an older step left forward, then a protected reservation beside it.
    private static void interruptedPublication() {
        fault("interrupted publication then protected reservation", problems -> {
            PackageManagerService pm = livePm();
            Path root = pm.mSettings.root;
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle a = manager.prepare(manager.select(PKG_A, 0));
            // A's reservation and body are durable; its completion to LIVE stopped after main.
            copies(root, bytes(header(1, creating(A, 1, PKG_A))), bytes(header(1, live(A))), null);
            slot(root, A, bound(A, PKG_A, 1, false, 1));
            observe(pm);
            NativePrincipalManager.Handle c = manager.prepare(manager.select(PKG_C, 0));
            Header target = header(2, creating(A, 1, PKG_A), creating(C, 2, PKG_C));
            NativeHeaderWriteFaults.arm("backup-published", HEADER);
            check(problems, !manager.commit(c) && NativeHeaderWriteFaults.reached(), "no injected failure");
            NativeIdentityStore.Loaded after = loaded(root);
            check(problems, target.equals(after.header.value)
                    && after.occupiedAppIds.containsAll(Set.of(A, C)), "selected " + after.header.value);
            bootCounter(problems, root, 2);
            check(problems, manager.commit(c) && manager.commit(a), "original retries refused");
            check(problems, header(2, live(A), live(C)).equals(stored(root)), "result " + stored(root));
        });
    }

    // A preferred backup that is neither the selected prior nor the target stops the writer.
    private static void foreignBackup() {
        fault("foreign preferred backup is refused unchanged", problems -> {
            PackageManagerService pm = livePm();
            Path root = pm.mSettings.root;
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
            byte[] foreign = bytes(header(5));
            NativeHeaderWriteFaults.arm("backup-guard", HEADER,
                    () -> Files.write(root.resolve("store.bin-backup"), foreign));
            check(problems, !manager.commit(b) && NativeHeaderWriteFaults.reached(),
                    "write over a changed backup acknowledged");
            check(problems, Arrays.equals(foreign, Files.readAllBytes(root.resolve("store.bin-backup")))
                    && holds(root, HEADER, OLD) && holds(root, "store.bin.reservecopy", OLD),
                    "changed backup or copies rewritten");
            Files.delete(root.resolve("store.bin-backup"));
            check(problems, manager.commit(b) && header(1, live(B)).equals(stored(root)),
                    "retry after the foreign backup was removed refused");
        });
    }

    public static void main(String[] args) throws Exception {
        if (!NativeHeaderWriteFaultTest.class.desiredAssertionStatus()) {
            throw new AssertionError("run with java -ea");
        }
        if (!LINEAGE.equals(Settings.LINEAGE)) throw new AssertionError("facade lineage");
        start(Path.of(args[0]).resolve("header-write-faults"));
        LocalServices.addService(UserManagerInternal.class, new UserManagerInternal());
        ownedRetry();
        legacyRetries();
        newReservations();
        priorOrderings();
        chained();
        legacyWithC();
        retiring();
        interruptedPublication();
        foreignBackup();
        finish(Os.allClosed());
        System.out.println("Every destructive header step kept a durable witness of every hold under"
                + " host injected failures; Android crash and power loss unqualified");
    }
}
