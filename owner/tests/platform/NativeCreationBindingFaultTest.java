// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeBindingTestSupport.*;
import static com.android.server.pm.NativeHeaderTestSupport.*;

import android.system.Os;
import com.android.server.LocalServices;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.HeaderEntry;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.SlotPhase;
import com.android.server.pm.NativeIdentityStore.Status;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Host injected I/O failures at each of the eight steps of the actual strict header writer,
 * through the actual manager, persistence and store under the version 2 host format. The
 * harness inserts the existing fault seam into copies of the store and strict writer sources;
 * production sources contain none, and every case checks that its step was reached. Before the
 * backup rename the version 1 selection stays; from the rename on, the protected version 2
 * target is selected beside its version 1 predecessors. Every known hold survives a reload and
 * a reopened registry, which restores only the selected counter, and the same original handles
 * finish without another ID. A legacy entry's missing binding stays missing throughout. Phase
 * changes, omissions and confirmations keep their prior and their version until their final
 * step. These are host injected failures, not Android crash or power loss evidence.
 */
public final class NativeCreationBindingFaultTest {
    private static final List<String> STEPS = List.of("seed-synced", "backup-renamed",
            "backup-published", "write-started", "main-synced", "reserve-synced", "backup-unlink",
            "backup-unlinked");
    private static final String HEADER = "store.bin";

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
    // From the backup rename on, a pure reservation's target is the preferred backup.
    private static boolean targetStep(String step) {
        return STEPS.indexOf(step) > 0;
    }
    // The holds survive a reload and a reopened version 2 registry, which restores exactly the
    // selected counter, or none when negative.
    private static void holdsSurvive(List<String> problems, Path root, Set<Integer> holds,
            long counter, String step) {
        NativeIdentityStore.Loaded after = loadedOf(root, V2);
        check(problems, after.occupiedAppIds.containsAll(holds), step + ": holds " + after.occupiedAppIds);
        PackageManagerService reopened = reopenOf(root, V2, Map.of());
        for (int appId : holds) {
            check(problems, reopened.mSettings.isNativePrincipalAppIdLPr(appId),
                    step + ": reopened hold " + appId);
        }
        bootCounterOf(problems, root, V2, counter);
    }
    // Wherever a decodable header copy lists B as CREATING, it has no binding.
    private static boolean legacyNull(Path root) {
        for (Header copy : loadedOf(root, V2).header.decodedCopies) {
            for (HeaderEntry entry : copy.entries) {
                if (entry.appId == B && entry.phase == SlotPhase.CREATING
                        && entry.creationBinding != null) return false;
            }
        }
        return true;
    }
    // No header path, the staging seed included, holds an intact version 2 frame.
    private static boolean noVersion2(Path root) throws Exception {
        for (String name : List.of("store.bin", "store.bin.reservecopy", "store.bin-backup",
                "store.bin-seed")) {
            Path path = root.resolve(name);
            if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                    && NativeIdentityRecords.intactHeaderVersion(Files.readAllBytes(path)) == 2) {
                return false;
            }
        }
        return true;
    }

    // A fresh bound reservation raises the empty version 1 header, failing at every step.
    private static void freshUpgrades() {
        for (String step : STEPS) {
            fault("fresh upgrade / " + step, problems -> {
                PackageManagerService pm = livePmOf(V2);
                Path root = pm.mSettings.root;
                NativePrincipalManager manager = new NativePrincipalManager(pm);
                NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
                NativeHeaderWriteFaults.arm(step, HEADER);
                check(problems, !manager.commit(b) && NativeHeaderWriteFaults.reached(),
                        "no injected failure");
                boolean target = targetStep(step);
                Header selected = storedOf(root, V2);
                check(problems, (target ? v2(1, boundCreating(B, 1, PKG_B)) : OLD).equals(selected),
                        step + ": selected " + selected);
                holdsSurvive(problems, root, target ? Set.of(B) : Set.of(), target ? 1 : 0, step);
                check(problems, manager.commit(b) && v2(1, live(B)).equals(storedOf(root, V2))
                        && pm.mSettings.pins.snapshotForWrite().lastId == 1,
                        step + ": retry " + storedOf(root, V2));
            });
        }
    }

    // An older writer's legacy B, then bound C from the same manager, either committed first.
    private static void legacyWithBoundC() {
        for (boolean cFirst : List.of(true, false)) {
            for (String step : STEPS) {
                fault("legacy B with bound C / " + (cFirst ? "C" : "B") + " first / " + step,
                        problems -> {
                    PackageManagerService pm = livePmOf(V2);
                    Path root = pm.mSettings.root;
                    NativePrincipalManager manager = new NativePrincipalManager(pm);
                    NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
                    legacyReservation(pm, OLD, PENDING_B);
                    NativePrincipalManager.Handle c = manager.prepare(manager.select(PKG_C, 0));
                    NativeHeaderWriteFaults.arm(step, HEADER);
                    check(problems, !manager.commit(cFirst ? c : b) && NativeHeaderWriteFaults.reached(),
                            "no injected failure");
                    boolean target = targetStep(step);
                    Header upgraded = v2(2, creating(B, 1, PKG_B), boundCreating(C, 2, PKG_C));
                    Header selected = storedOf(root, V2);
                    check(problems, (target ? upgraded : OLD).equals(selected), step + ": selected " + selected);
                    holdsSurvive(problems, root, target ? Set.of(B, C) : Set.of(B), target ? 2 : -1, step);
                    check(problems, legacyNull(root), step + ": B's binding was filled");
                    check(problems, manager.commit(cFirst ? c : b) && legacyNull(root),
                            step + ": first original retry refused");
                    check(problems, manager.commit(cFirst ? b : c), step + ": second retry refused");
                    check(problems, v2(2, live(B), live(C)).equals(storedOf(root, V2))
                            && pm.mSettings.pins.snapshotForWrite().lastId == 2,
                            step + ": result " + storedOf(root, V2));
                });
            }
        }
    }

    // Restating legacy B alone stays version 1 at every step, including its staged seed.
    private static void restatements() {
        for (String step : STEPS) {
            fault("version 1 restatement under version 2 / " + step, problems -> {
                PackageManagerService pm = livePmOf(V2);
                Path root = pm.mSettings.root;
                NativePrincipalManager manager = new NativePrincipalManager(pm);
                NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
                legacyReservation(pm, OLD, PENDING_B);
                NativeHeaderWriteFaults.arm(step, HEADER);
                check(problems, !manager.commit(b) && NativeHeaderWriteFaults.reached(),
                        "no injected failure");
                boolean target = targetStep(step);
                Header selected = storedOf(root, V2);
                check(problems, (target ? PENDING_B : OLD).equals(selected), step + ": selected " + selected);
                check(problems, noVersion2(root), step + ": a restatement staged or wrote version 2");
                holdsSurvive(problems, root, Set.of(B), target ? 1 : -1, step);
                check(problems, manager.commit(b) && header(1, live(B)).equals(storedOf(root, V2))
                        && pm.mSettings.pins.snapshotForWrite().lastId == 1,
                        step + ": retry " + storedOf(root, V2));
            });
        }
    }

    // After a restatement stayed version 1, new C raises the header, failing at every step.
    private static void restatementThenUpgrade() {
        for (String step : STEPS) {
            fault("restatement then upgrade / " + step, problems -> {
                PackageManagerService pm = livePmOf(V2);
                Path root = pm.mSettings.root;
                NativePrincipalManager manager = new NativePrincipalManager(pm);
                NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
                legacyReservation(pm, OLD, PENDING_B);
                check(problems, manager.commit(b) && header(1, live(B)).equals(storedOf(root, V2)),
                        "the restatement did not stay version 1");
                NativePrincipalManager.Handle c = manager.prepare(manager.select(PKG_C, 0));
                NativeHeaderWriteFaults.arm(step, HEADER);
                check(problems, !manager.commit(c) && NativeHeaderWriteFaults.reached(),
                        "no injected failure");
                boolean target = targetStep(step);
                Header selected = storedOf(root, V2);
                check(problems, (target ? v2(2, live(B), boundCreating(C, 2, PKG_C)) : header(1, live(B)))
                        .equals(selected), step + ": selected " + selected);
                holdsSurvive(problems, root, target ? Set.of(B, C) : Set.of(B), target ? 2 : 1, step);
                check(problems, manager.commit(c) && v2(2, live(B), live(C)).equals(storedOf(root, V2))
                        && pm.mSettings.pins.snapshotForWrite().lastId == 2,
                        step + ": retry " + storedOf(root, V2));
            });
        }
    }

    // Several pending pins and an unpublished RETIRING pin of one instance reserve together.
    private static void pendingAndRetiring() {
        for (String step : STEPS) {
            fault("pending and RETIRING together / " + step, problems -> {
                PackageManagerService pm = livePmOf(V2);
                Path root = pm.mSettings.root;
                NativePrincipalManager manager = new NativePrincipalManager(pm);
                NativePrincipalManager.Handle a = manager.prepare(manager.select(PKG_A, 0));
                NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
                NativePrincipalManager.Handle c = manager.prepare(manager.select(PKG_C, 0));
                pm.mSettings.pins.beginRetire(pm.mSettings.pins.find(PKG_C, 0));
                NativeHeaderWriteFaults.arm(step, HEADER);
                check(problems, !manager.commit(a) && NativeHeaderWriteFaults.reached(),
                        "no injected failure");
                boolean target = targetStep(step);
                Header all = v2(3, boundCreating(A, 1, PKG_A), boundCreating(B, 2, PKG_B),
                        boundCreating(C, 3, PKG_C));
                Header selected = storedOf(root, V2);
                check(problems, (target ? all : OLD).equals(selected), step + ": selected " + selected);
                holdsSurvive(problems, root, target ? Set.of(A, B, C) : Set.of(), target ? 3 : 0, step);
                check(problems, manager.commit(a) && manager.commit(b), step + ": pending retries refused");
                check(problems, manager.beginRetirement(c) && manager.finishRetirementAfterQuiescence(c),
                        step + ": the RETIRING creation did not retire");
                check(problems, v2(3, live(A), live(B)).equals(storedOf(root, V2))
                        && pm.mSettings.pins.snapshotForWrite().lastId == 3,
                        step + ": result " + storedOf(root, V2));
            });
        }
    }

    // Version 2 phase changes, omissions and confirmations keep their prior as the backup, and
    // their version, until the final step.
    private static void priorOrdering(String name, Header prior, Header next, int appId, Slot body,
            Transition write) {
        fault("version 2 prior ordering / " + name, problems -> {
            for (String step : STEPS) {
                Path root = layout(null, bytes(prior), bytes(prior));
                if (body != null) slot(root, appId, body);
                NativeIdentityStore store = storeOf(root, V2);
                NativeHeaderWriteFaults.arm(step, HEADER);
                check(problems, !write.run(store) && NativeHeaderWriteFaults.reached(),
                        step + ": no injected failure");
                NativeHeaderWriteFaults.disarm();
                boolean last = step.equals("backup-unlinked");
                Header selected = storedOf(root, V2);
                check(problems, (last ? next : prior).equals(selected) && selected.version == 2,
                        step + ": selected " + selected);
                if (targetStep(step) && !last) {
                    check(problems, holds(root, "store.bin-backup", prior), step + ": backup is not the prior");
                }
                check(problems, write.run(store) && next.equals(storedOf(root, V2)),
                        step + ": retry refused");
            }
        });
    }

    private static void priorOrderings() {
        Header creatingA = v2(1, boundCreating(A, 1, PKG_A));
        Header liveA = v2(1, live(A));
        Header releasingA = v2(1, releasing(A));
        priorOrdering("publication", creatingA, liveA, A, bound(A, PKG_A, 1, false, 1),
                store -> store.writeHeader(creatingA, liveA));
        priorOrdering("release marker", liveA, releasingA, A, tombstone(A, PKG_A, 2),
                store -> store.writeHeader(liveA, releasingA));
        priorOrdering("omission", releasingA, v2(1), A, null,
                store -> store.writeHeader(releasingA, v2(1)));
        priorOrdering("confirmation", creatingA, creatingA, A, null,
                store -> store.ensureFreshSlot(creatingA, A));
    }

    // A publication an older step left forward, then a protected upgrade beside it.
    private static void interruptedPublication() {
        fault("interrupted V1 publication then protected upgrade", problems -> {
            PackageManagerService pm = livePmOf(V2);
            Path root = pm.mSettings.root;
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle a = manager.prepare(manager.select(PKG_A, 0));
            // A's reservation and body are durable; its completion to LIVE stopped after main.
            copies(root, bytes(header(1, creating(A, 1, PKG_A))), bytes(header(1, live(A))), null);
            slot(root, A, bound(A, PKG_A, 1, false, 1));
            observe(pm);
            NativePrincipalManager.Handle c = manager.prepare(manager.select(PKG_C, 0));
            Header target = v2(2, creating(A, 1, PKG_A), boundCreating(C, 2, PKG_C));
            NativeHeaderWriteFaults.arm("backup-published", HEADER);
            check(problems, !manager.commit(c) && NativeHeaderWriteFaults.reached(), "no injected failure");
            NativeIdentityStore.Loaded after = loadedOf(root, V2);
            check(problems, target.equals(after.header.value) && after.occupiedAppIds.containsAll(Set.of(A, C))
                    && after.slots.get(A).status == Status.VALID, "selected " + after.header.value);
            bootCounterOf(problems, root, V2, 2);
            check(problems, manager.commit(c) && manager.commit(a), "original retries refused");
            check(problems, v2(2, live(A), live(C)).equals(storedOf(root, V2)), "result " + storedOf(root, V2));
        });
    }

    public static void main(String[] args) throws Exception {
        if (!NativeCreationBindingFaultTest.class.desiredAssertionStatus()) {
            throw new AssertionError("run with java -ea");
        }
        if (!LINEAGE.equals(Settings.LINEAGE)) throw new AssertionError("facade lineage");
        start(Path.of(args[0]).resolve("creation-binding-faults"));
        LocalServices.addService(UserManagerInternal.class, new UserManagerInternal());
        freshUpgrades();
        legacyWithBoundC();
        restatements();
        restatementThenUpgrade();
        pendingAndRetiring();
        priorOrderings();
        interruptedPublication();
        finish(Os.allClosed());
        System.out.println("Every destructive header step kept every hold and version under host"
                + " injected failures; Android crash and power loss unqualified");
    }
}
