// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeLifecycleTestSupport.*;

import android.system.Os;
import com.android.server.pm.NativeIdentityPersistence.SuspensionResult;
import com.android.server.pm.NativeIdentityRecords.ActorClass;
import com.android.server.pm.NativeIdentityRecords.Lifecycle;
import com.android.server.pm.NativeIdentityRecords.Obligation;
import com.android.server.pm.NativeIdentityRecords.ObligationKind;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.Suspension;
import com.android.server.pm.NativeIdentityRecords.SuspensionReason;
import com.android.server.pm.NativeIdentityStore.History;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * Host injected I/O failures at each of the eight steps of the actual strict slot writer, in each
 * lifecycle transaction under Format.V3: suspend, the confirmation of a repeated suspension that
 * differs from the held entry, lift of the last entry, markRetiring, a legacy marker's
 * continuation, markRetired, beginDisposition and confirmDisposition, each in a retired boot
 * whose facts come from that boot's own read, and Restore over a conflict beside a torn backup
 * and over copies none of which is intact. The harness inserts the existing fault seam into copies of the
 * store and strict writer sources; production sources contain none, and every case checks that
 * its step was reached. The preferred backup
 * keeps the prior value until the final step, so a fresh store reads the prior until the backup is
 * gone and the target after it, never anything else, with the app ID held and the binding intact.
 * The caller then retries its own durable intent through a fresh persistence and store, which
 * continue from the durable files alone, and the target is durable in its one encoding. Restore
 * publishes its target as the preferred backup first, so its target is selected from that step on. These are
 * host injected failures, not Android crash or power loss evidence.
 */
public final class NativeLifecycleFaultTest {
    private static final List<String> STEPS = List.of("seed-synced", "backup-renamed",
            "backup-published", "write-started", "main-synced", "reserve-synced", "backup-unlink",
            "backup-unlinked");
    private static final String SLOT = "record.bin";
    private static final Suspension USER = byUser(SuspensionReason.USER_PAUSED);
    private static final Suspension GRANT = byGrant(1, SuspensionReason.CREDENTIAL_EXPOSED);

    // The caller's durable intent: the record, its signers and the request, never a store value.
    private interface Call { boolean run(NativeIdentityPersistence persistence) throws Exception; }

    // Whether this view's history of A carries exactly this value's lifecycle and its pin phase.
    private static boolean historyOf(NativeIdentityStore.Loaded loaded, Slot value) {
        History history = loaded.history(A);
        Lifecycle lifecycle = value.users.get(0).lifecycle;
        Set<Long> retiring = NativeIdentityPersistence.restoration(loaded.histories()).retiringIds;
        return history != null && history.state == lifecycle.state
                && history.suspensions.equals(lifecycle.suspensions)
                && retiring.equals(history.retiring ? Set.of(ID_A) : Set.of());
    }

    private static void sweep(String name, Slot prior, Slot target, int version, Call call) {
        for (String step : STEPS) {
            run(name + " / " + step, problems -> {
                try {
                    Path root = layout(prior);
                    byte[] header = Files.readAllBytes(root.resolve("store.bin"));
                    NativeHeaderWriteFaults.arm(step, SLOT);
                    check(problems, !call.run(persistence(root, V3)) && NativeHeaderWriteFaults.reached(),
                            "no injected failure");
                    NativeHeaderWriteFaults.disarm();
                    // Only the durable files remain. The prior stays selected until its backup is gone.
                    Slot durable = step.equals("backup-unlinked") ? target : prior;
                    NativeIdentityStore.Loaded loaded = load(root, V3);
                    check(problems, durable.equals(stored(root, V3)), "durable " + stored(root, V3));
                    check(problems, loaded.occupiedAppIds.contains(A) && loaded.bindingUsable(A),
                            "the hold or binding was lost");
                    check(problems, historyOf(loaded, durable), "history " + loaded.history(A));
                    // A fresh persistence and store continue the same intent from those files alone.
                    check(problems, call.run(persistence(root, V3)), "the retry was refused");
                    check(problems, target.equals(stored(root, V3)) && holds(root, target, version),
                            "the retry left " + stored(root, V3));
                    check(problems, historyOf(load(root, V3), target), "history " + load(root, V3).history(A));
                    check(problems, Arrays.equals(header, Files.readAllBytes(root.resolve("store.bin"))),
                            "the header changed");
                } finally {
                    NativeHeaderWriteFaults.disarm();
                }
            });
        }
    }

    // Restore over these raw copies of A under a LIVE entry, failed at each writer step. Restore
    // publishes its target as the preferred backup first, so a fresh store reads the copies as before
    // only until the backup is renamed, and the target after that, with the app ID held. A retry
    // from the durable files alone confirms the target, or writes it when the seed alone was staged.
    private static void sweep(String name, byte[] main, byte[] reserve, byte[] backup, Slot target) {
        for (String step : STEPS) {
            run(name + " / " + step, problems -> {
                try {
                    Path root = store(header(ID_A, live(A)));
                    copies(root, main, reserve, backup);
                    byte[] header = Files.readAllBytes(root.resolve("store.bin"));
                    NativeIdentityStore.Loaded before = load(root, V3);
                    NativeHeaderWriteFaults.arm(step, SLOT);
                    check(problems, !persistence(root, V3).restore(RECORD_A, LINEAGE, SIGNERS, RECOVERY)
                            && NativeHeaderWriteFaults.reached(), "no injected failure");
                    NativeHeaderWriteFaults.disarm();
                    NativeIdentityStore.Loaded loaded = load(root, V3);
                    if (step.equals("seed-synced")) {
                        check(problems, loaded.slots.get(A).status == before.slots.get(A).status
                                && loaded.slots.get(A).decodedCopies.equals(before.slots.get(A).decodedCopies),
                                "the copies changed before the backup was published");
                    } else {
                        check(problems, target.equals(stored(root, V3)), "durable " + stored(root, V3));
                    }
                    check(problems, loaded.occupiedAppIds.contains(A), "the hold was lost");
                    check(problems, persistence(root, V3).restore(RECORD_A, LINEAGE, SIGNERS, RECOVERY),
                            "the retry was refused");
                    check(problems, target.equals(stored(root, V3)) && holds(root, target, 2),
                            "the retry left " + stored(root, V3));
                    check(problems, historyOf(load(root, V3), target), "history " + load(root, V3).history(A));
                    check(problems, Arrays.equals(header, Files.readAllBytes(root.resolve("store.bin"))),
                            "the header changed");
                } finally {
                    NativeHeaderWriteFaults.disarm();
                }
            });
        }
    }

    // The boot facts of a fresh boot's own read.
    private static NativeIdentityPersistence.BootFacts boot(NativeIdentityPersistence persistence) {
        return NativeIdentityPersistence.bootFacts(persistence.load());
    }

    public static void main(String[] args) throws Exception {
        if (!NativeLifecycleFaultTest.class.desiredAssertionStatus()) throw new AssertionError("run with java -ea");
        start(Path.of(args[0]).resolve("lifecycle-faults"));
        Slot eligible = slotA(1, Lifecycle.version1(false));
        Slot suspended = slotA(2, eligible(USER));
        sweep("suspend", eligible, suspended, 2,
                persistence -> persistence.suspend(RECORD_A, SIGNERS, USER) == SuspensionResult.SUSPENDED);
        // The same actor with another reason: its held entry is confirmed unchanged.
        Suspension repeated = new Suspension(ActorClass.ACCOUNT_USER, 0, 0, SERIAL, ZERO,
                SuspensionReason.SUSPECTED_COMPROMISE.code, TIME + 9, null);
        sweep("repeated suspension", suspended, suspended, 2,
                persistence -> persistence.suspend(RECORD_A, SIGNERS, repeated) == SuspensionResult.HELD_UNCHANGED);
        sweep("lift", suspended, slotA(3, Lifecycle.version1(false)), 1,
                persistence -> persistence.lift(RECORD_A, SIGNERS, USER));
        sweep("markRetiring", slotA(2, eligible(USER, GRANT)), slotA(3, retiring(byUserRetirement(), USER, GRANT)), 2,
                persistence -> persistence.markRetiring(RECORD_A, SIGNERS, byUserRetirement()));
        sweep("legacy continuation", slotA(1, Lifecycle.version1(true)), slotA(2, retiring(legacyContinued())), 2,
                persistence -> persistence.markRetiring(RECORD_A, SIGNERS, legacyContinued()));
        sweep("markRetired", slotA(2, retiring(byGrantRetirement(), USER)),
                slotA(3, retired(discharged(byGrantRetirement(), receipts()), USER)), 2,
                persistence -> persistence.markRetired(RECORD_A, SIGNERS, receipts()));
        Slot retiredA = slotA(3, retired(retiredBlock(), USER));
        Slot began = slotA(4, retired(disposing(retiredBlock()), USER));
        sweep("beginDisposition", retiredA, began, 2,
                persistence -> persistence.beginDisposition(RECORD_A, SIGNERS, boot(persistence)));
        List<Obligation> keys = disposals(ObligationKind.KEYSTORE, ObligationKind.HOME);
        sweep("confirmDisposition", began, slotA(5, retired(with(with(disposing(retiredBlock()), keys.get(0)),
                keys.get(1)), USER)), 2,
                persistence -> persistence.confirmDisposition(RECORD_A, SIGNERS, keys, boot(persistence)));
        // A conflict of two intact copies beside a torn preferred backup: the newer copy is restored.
        Slot newer = slotA(5, retired(retiredBlock(), USER));
        sweep("restore", bytes(newer), bytes(slotA(4, retiring(byUserRetirement(), USER))), torn(newer),
                slotA(6, retired(retiredBlock(), USER, RECOVERY)));
        sweep("restore without an intact copy", torn(newer), torn(newer), null, slotA(1, eligible(RECOVERY_UNKNOWN)));
        finish(Os.allClosed());
        System.out.println("Every lifecycle transaction continued from durable state after host injected"
                + " failures; Android crash and power loss unqualified");
    }
}
