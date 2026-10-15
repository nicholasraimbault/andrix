// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeBindingTestSupport.*;
import static com.android.server.pm.NativeHeaderTestSupport.*;
import static com.android.server.pm.NativeHistoryTestSupport.*;

import android.system.Os;
import com.android.server.LocalServices;
import com.android.server.pm.NativeIdentityStore.History;
import com.android.server.pm.NativeIdentityStore.Source;
import com.android.server.pm.NativePrincipalPins.Phase;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * Host injected I/O failures at each of the eight steps of the actual strict writer, through
 * the actual manager, persistence and store under the version 2 host format, for a restored
 * reservation R that an explicit designation rebinds. The harness inserts the existing fault
 * seam into copies of the store and strict writer sources; production sources contain none,
 * and every case checks that its step was reached. The transitions are the exact header
 * confirmation that opens the rebind commit, the first body write, the completion to LIVE, and
 * a rebound retirement's own publication and marker. A reopened registry reads R's
 * reservation until the complete body has been moved into the preferred backup, and its body
 * after. It restores PENDING until the durable marker is the selected copy, RETIRING after.
 * R's record, hold and the selected counter are conserved, and the same original handle
 * converges without another ID. A completed release keeps R held in the same Settings instance.
 * The three rebind sweeps also run under Format.V3, the production format, as twins named with a
 * V3 prefix. These are host injected failures, not Android crash or power loss evidence.
 */
public final class NativeCreationHistoryFaultTest {
    private static final List<String> STEPS = List.of("seed-synced", "backup-renamed",
            "backup-published", "write-started", "main-synced", "reserve-synced", "backup-unlink",
            "backup-unlinked");
    // The production format, which the normal image's boot read constructs.
    private static final NativeIdentityStore.Format V3 = NativeIdentityStore.Format.V3;

    private interface FormatBody {
        void run(List<String> problems, NativeIdentityStore.Format format) throws Exception;
    }

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

    // A rebind sweep's case at one step under Format.V2, as before, then its production twin under
    // Format.V3, named with a V3 prefix: the same transition, failure, reopening and convergence.
    private static void common(String name, FormatBody body) {
        fault(name, problems -> body.run(problems, V2));
        fault("V3 / " + name, problems -> body.run(problems, V3));
    }

    // A new view and a reopened registry after the failure: R's history source, its pin phase,
    // record and hold, and the selected counter.
    private static void reopened(List<String> problems, Path root, NativeIdentityStore.Format format,
            Source source, Phase phase, String step) {
        History history = loadedOf(root, format).history(R);
        check(problems, history != null && history.source == source
                && NativeIdentityPersistence.identifies(history, recordR())
                && history.signerSha256.equals(SIGNERS)
                && history.retiring == (phase == Phase.RETIRING), step + ": history " + history);
        PackageManagerService pm = reopenOf(root, format, Map.of());
        NativePrincipalPins.Pin pin = pm.mSettings.pins.find(PKG_R, 0);
        check(problems, pin != null && pin.phase() == phase && pin.record().equals(recordR())
                && pm.mSettings.isNativePrincipalAppIdLPr(R) && pm.mSettings.pins.hasKnownCounter()
                && pm.mSettings.pins.snapshotForWrite().lastId == 1, step + ": reopened " + pin);
    }

    // The same original handle finishes the rebind: its original body, LIVE, and no new ID.
    private static void converge(List<String> problems, NativeIdentityStore.Format format, PackageManagerService pm,
            NativePrincipalManager manager, NativePrincipalManager.Handle r, Path root, String step) {
        check(problems, manager.commit(r) && manager.phase(r) == Phase.ACTIVE
                && manager.identity(r).equals(recordR()) && v2(1, live(R)).equals(storedOf(root, format))
                && BODY_R.equals(loadedOf(root, format).slots.get(R).value)
                && pm.mSettings.pins.snapshotForWrite().lastId == 1, step + ": retry " + storedOf(root, format));
        History history = loadedOf(root, format).history(R);
        check(problems, history != null && history.source == Source.BODY
                && reopenedPhase(root, format, PKG_R) == Phase.PENDING, step + ": final " + history);
    }

    // A restored reservation of R with its explicit designation, not yet committed.
    private static final class Rebound {
        final Path root;
        final PackageManagerService pm;
        final NativePrincipalManager manager;
        final NativePrincipalManager.Handle handle;

        Rebound(NativeIdentityStore.Format format) throws Exception {
            root = reserved();
            pm = boot(root, format, Map.of(PKG_R, R));
            manager = new NativePrincipalManager(pm);
            handle = manager.prepare(manager.select(PKG_R, 0));
        }
    }

    // The rewrite of the unchanged header that opens the rebind commit.
    private static void exactConfirmation() {
        for (String step : STEPS) {
            common("exact header confirmation / " + step, (problems, format) -> {
                Rebound r = new Rebound(format);
                NativeHeaderWriteFaults.arm(step, "store.bin");
                check(problems, !r.manager.commit(r.handle) && NativeHeaderWriteFaults.reached(),
                        "no injected failure");
                NativeHeaderWriteFaults.disarm();
                check(problems, RESERVED_R.equals(storedOf(r.root, format)) && r.manager.phase(r.handle)
                        == Phase.PENDING, step + ": selected " + storedOf(r.root, format));
                reopened(problems, r.root, format, Source.RESERVATION, Phase.PENDING, step);
                converge(problems, format, r.pm, r.manager, r.handle, r.root, step);
            });
        }
    }

    // The first write of R's body. Only after the complete body is the preferred backup does a
    // reopened registry read the body.
    private static void firstBody() {
        for (String step : STEPS) {
            common("first body write / " + step, (problems, format) -> {
                Rebound r = new Rebound(format);
                NativeHeaderWriteFaults.arm(step, "record.bin");
                check(problems, !r.manager.commit(r.handle) && NativeHeaderWriteFaults.reached(),
                        "no injected failure");
                NativeHeaderWriteFaults.disarm();
                check(problems, RESERVED_R.equals(storedOf(r.root, format)),
                        step + ": header " + storedOf(r.root, format));
                reopened(problems, r.root, format, step.equals("seed-synced") ? Source.RESERVATION : Source.BODY,
                        Phase.PENDING, step);
                converge(problems, format, r.pm, r.manager, r.handle, r.root, step);
            });
        }
    }

    // The completion to LIVE after R's body is published. The prior stays selected until the
    // final step.
    private static void liveCompletion() {
        for (String step : STEPS) {
            common("LIVE completion / " + step, (problems, format) -> {
                Rebound r = new Rebound(format);
                NativeIdentityStore store = storeOf(r.root, format);
                check(problems, store.resumeCreatingDirectory(RESERVED_R, R)
                        && store.publishCreatingSlot(RESERVED_R, BODY_R), "fixture body");
                NativeHeaderWriteFaults.arm(step, "store.bin");
                check(problems, !r.manager.commit(r.handle) && NativeHeaderWriteFaults.reached(),
                        "no injected failure");
                NativeHeaderWriteFaults.disarm();
                boolean last = step.equals("backup-unlinked");
                check(problems, (last ? v2(1, live(R)) : RESERVED_R).equals(storedOf(r.root, format)),
                        step + ": selected " + storedOf(r.root, format));
                reopened(problems, r.root, format, Source.BODY, Phase.PENDING, step);
                converge(problems, format, r.pm, r.manager, r.handle, r.root, step);
            });
        }
    }

    // A rebound reservation's retirement refuses under Format.V2 before its publication:
    // no writer step is reached and nothing changes. The lifecycle format's sweep covers the steps.
    private static void retirementPublication() {
        for (String step : STEPS) {
            fault("rebound retirement refused before its publication / " + step, problems -> {
                Rebound r = new Rebound(V2);
                NativeHeaderWriteFaults.arm(step, "record.bin");
                check(problems, retirementRefused(r.root, r.manager, r.handle) && !NativeHeaderWriteFaults.reached()
                        && r.manager.phase(r.handle) == Phase.PENDING, step + ": the retirement was not refused");
                NativeHeaderWriteFaults.disarm();
                reopened(problems, r.root, V2, Source.RESERVATION, Phase.PENDING, step);
            });
        }
    }

    // A committed rebind's retirement refuses before its marker: the binding stays LIVE and a reopened
    // registry restores PENDING.
    private static void retirementMarker() {
        for (String step : STEPS) {
            fault("rebound retirement refused before its marker / " + step, problems -> {
                Rebound r = new Rebound(V2);
                check(problems, r.manager.commit(r.handle), "rebind refused");
                NativeHeaderWriteFaults.arm(step, "record.bin");
                check(problems, retirementRefused(r.root, r.manager, r.handle) && !NativeHeaderWriteFaults.reached(),
                        step + ": the retirement was not refused");
                NativeHeaderWriteFaults.disarm();
                check(problems, v2(1, live(R)).equals(storedOf(r.root, V2)), step + ": header " + storedOf(r.root, V2));
                reopened(problems, r.root, V2, Source.BODY, Phase.PENDING, step);
            });
        }
    }

    public static void main(String[] args) throws Exception {
        if (!NativeCreationHistoryFaultTest.class.desiredAssertionStatus()) {
            throw new AssertionError("run with java -ea");
        }
        if (!LINEAGE.equals(Settings.LINEAGE)) throw new AssertionError("facade lineage");
        start(Path.of(args[0]).resolve("creation-history-faults"));
        LocalServices.addService(UserManagerInternal.class, new UserManagerInternal());
        exactConfirmation();
        firstBody();
        liveCompletion();
        retirementPublication();
        retirementMarker();
        finish(Os.allClosed());
        System.out.println("Restored creation rebinds kept every record and hold under host injected"
                + " failures; Android crash and power loss unqualified");
    }
}
