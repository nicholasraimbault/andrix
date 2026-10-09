// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeLifecycleTestSupport.*;

import com.android.server.LocalServices;
import com.android.server.pm.NativeIdentityPersistence.SuspensionResult;
import com.android.server.pm.NativeIdentityRecords.ActorClass;
import com.android.server.pm.NativeIdentityRecords.CreationBinding;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.HeaderEntry;
import com.android.server.pm.NativeIdentityRecords.Lifecycle;
import com.android.server.pm.NativeIdentityRecords.LifecycleState;
import com.android.server.pm.NativeIdentityRecords.Obligation;
import com.android.server.pm.NativeIdentityRecords.ObligationKind;
import com.android.server.pm.NativeIdentityRecords.ObligationState;
import com.android.server.pm.NativeIdentityRecords.Retirement;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.SlotPhase;
import com.android.server.pm.NativeIdentityRecords.Suspension;
import com.android.server.pm.NativeIdentityRecords.SuspensionReason;
import com.android.server.pm.NativeIdentityRecords.UserEntry;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Emits the store layouts that the lifecycle record's writers leave under Format.V3, for readers
 * compiled from other sources: each lifecycle state, entry class, scope bit and noted entry, both
 * inventories, RETIRED, DISPOSING and the maximum record, tombstones with and without a ticket,
 * RELEASING beside its tombstone and without a directory, the durable state at every writer step
 * of each persistence transaction and of each manager operation, the retirement families that the
 * binding and history emitters wrote under the old retirement, and three companions: a version 2
 * slot beside a bound reservation, beside a valid sibling naming the same package or principal,
 * and with its package's mapping lost.
 *
 * <p>The actual writers produce every value they can. Values no writer of this stage writes, scope
 * bit 0, the Android user removal class, orphaned obligations, version 1 values that only older
 * images write and the maximum record, are written through the codec, as durable state that a later
 * writer or an older image may leave. Their layout names begin with "value-". The harness inserts
 * the existing host write fault seam into copies of the store and strict writer sources.
 *
 * <p>Each layout records three files beside its store tree. "holds" lists the app IDs that Format.V3
 * reads as held, which every reader must keep. "kind" names the companion, or "slot" when an intact
 * version 2 slot frame is present in any slot file, staging seeds included, and "version1" when
 * none is, then the highest intact header version among the header copies, the main, the reserve
 * and the backup, or 0 when none is intact. "packages" maps each package the store names at a held
 * app ID to the app ID that Package Manager maps it at, or to "lost" when that mapping is lost. Host files only, not Android
 * storage.
 */
public final class NativeLifecycleLayouts {
    private static final List<String> STEPS = List.of("seed-synced", "backup-renamed",
            "backup-published", "write-started", "main-synced", "reserve-synced", "backup-unlink",
            "backup-unlinked");
    private static final String SLOT = "record.bin";
    private static final String HEADER = "store.bin";
    private static final Pattern NAME = Pattern.compile("[a-z0-9]+(-[a-z0-9]+)*");
    private static final Set<String> KINDS = Set.of("slot", "version1", "reservation", "sibling", "lost");
    private static final Suspension USER = byUser(SuspensionReason.USER_PAUSED);
    private static final Suspension GRANT = byGrant(1, SuspensionReason.CREDENTIAL_EXPOSED);
    private static final String NOTE = "5a".repeat(32);
    // The reservation companion's account, and the sibling's.
    private static final int R = 10210, S = 10211;
    private static final long ID_R = 3, ID_S = 4;
    private static final String PKG_R = "dev.andrix.lifecycler", PKG_S = "dev.andrix.lifecycles";
    // The installed host package's signer set: the facade's PackageSetting signs with one fixed key.
    private static final Set<String> INSTALLED = NativePrincipalManager.signerDigests(
            new PackageSetting(PKG_A).getSigningDetails());

    private static Path out;
    private static final List<String> emitted = new ArrayList<>();

    private interface Call { boolean run() throws Exception; }

    // A transaction over the persistence of the store at root, with that store's own durable read for its boot facts.
    private interface Writer { boolean run(NativeIdentityPersistence persistence, Path root) throws Exception; }

    private static void require(boolean ok, String what) {
        if (!ok) throw new AssertionError(what);
    }

    private static Map<String, String> mapped(String name, int appId) {
        return Map.of(name, String.valueOf(appId));
    }

    // The header copies: the main, its reserve and the preferred backup. A staging seed is no copy.
    private static final List<String> HEADER_COPIES = List.of(HEADER, HEADER + ".reservecopy", HEADER + "-backup");

    /** The highest intact header version among the header copies, or 0 when none is intact. */
    private static int headerVersion(Path root) throws Exception {
        int version = 0;
        for (String name : HEADER_COPIES) {
            Path file = root.resolve(name);
            if (Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                version = Math.max(version, NativeIdentityRecords.intactHeaderVersion(Files.readAllBytes(file)));
            }
        }
        return version;
    }

    /** The highest intact slot version among every file of one slot directory, its staging seed included. */
    private static int highest(Path directory) throws Exception {
        int version = 0;
        List<Path> files;
        try (var list = Files.list(directory)) {
            files = list.sorted().toList();
        }
        for (Path file : files) {
            if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)
                    || !file.getFileName().toString().startsWith(SLOT)) continue;
            version = Math.max(version, NativeIdentityRecords.intactSlotVersion(Files.readAllBytes(file)));
        }
        return version;
    }

    /** The highest intact slot version among every file of every slot directory. */
    private static int slotVersion(Path root) throws Exception {
        int version = 0;
        Path slots = root.resolve("slots");
        if (!Files.isDirectory(slots, LinkOption.NOFOLLOW_LINKS)) return version;
        List<Path> directories;
        try (var list = Files.list(slots)) {
            directories = list.sorted().toList();
        }
        for (Path directory : directories) {
            if (Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) version = Math.max(version, highest(directory));
        }
        return version;
    }

    // Copies the store tree and records what every reader must keep and how its packages are mapped.
    private static void emit(String name, Path root, String kind, Map<String, String> packages) throws Exception {
        require(NAME.matcher(name).matches() && !emitted.contains(name), "layout name " + name);
        require(KINDS.contains(kind), name + " kind " + kind);
        boolean versionTwo = slotVersion(root) == 2;
        require(versionTwo == !kind.equals("version1"), name + " is " + kind + " with slot version "
                + slotVersion(root));
        int header = headerVersion(root);
        Set<Integer> holds = new TreeSet<>(load(root, V3).occupiedAppIds);
        // Only a package mapped at a held app ID is named by the store. A write interrupted before its
        // first durable copy, such as a reservation staged only in a header seed, names nothing yet.
        Map<String, String> named = new TreeMap<>();
        for (Map.Entry<String, String> entry : packages.entrySet()) {
            if (entry.getValue().equals("lost") || holds.contains(Integer.parseInt(entry.getValue()))) {
                named.put(entry.getKey(), entry.getValue());
            }
        }
        Path target = Files.createDirectories(out.resolve(name));
        List<Path> paths;
        try (var walk = Files.walk(root)) {
            paths = walk.toList();
        }
        for (Path path : paths) {
            Path destination = target.resolve("store").resolve(root.relativize(path).toString());
            if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                Files.createDirectories(destination);
            } else {
                Files.copy(path, destination);
            }
        }
        Files.writeString(target.resolve("kind"), kind + " " + header + "\n");
        Files.writeString(target.resolve("holds"), holds.stream().map(String::valueOf)
                .collect(Collectors.joining("\n", "", holds.isEmpty() ? "" : "\n")));
        Files.writeString(target.resolve("packages"), named.entrySet().stream()
                .map(entry -> entry.getKey() + " " + entry.getValue() + "\n").collect(Collectors.joining()));
        emitted.add(name);
    }

    // The fault at this step of the skip-th strict write of this file name: earlier writes pass.
    private static void arm(String step, String file, int skip) {
        if (skip == 0) NativeHeaderWriteFaults.arm(step, file);
        else NativeHeaderWriteFaults.arm(step, file, () -> arm(step, file, skip - 1));
    }

    // One call failed at this step of its skip-th strict write of file: refused, with the step reached.
    private static void interrupted(String what, String step, String file, int skip, Call call) throws Exception {
        arm(step, file, skip);
        try {
            boolean acknowledged;
            try {
                acknowledged = call.run();
            } catch (IllegalStateException refused) {
                acknowledged = false;
            }
            require(!acknowledged && NativeHeaderWriteFaults.reached(), what + " not interrupted at " + step);
        } finally {
            NativeHeaderWriteFaults.disarm();
        }
    }

    private static String dashed(String text) {
        return text.toLowerCase().replace(' ', '-');
    }

    // The boot facts of a fresh boot's own durable read of root.
    private static NativeIdentityPersistence.BootFacts boot(Path root) {
        return facts(root);
    }

    private static boolean release(Path root, NativeIdentityPersistence.BootFacts facts) {
        return persistence(root, V3).release(RECORD_A, LINEAGE, SIGNERS, TICKET_A, capability(new Keys()), facts);
    }

    // ------------------------------------------------------------------ states through the writers

    private static void written(String name, Slot prior, Writer writer) throws Exception {
        Path root = layout(prior);
        require(writer.run(persistence(root, V3), root), name + " refused");
        emit(name, root, "slot", mapped(PKG_A, A));
    }

    private static Slot eligibleA() {
        return slotA(1, Lifecycle.version1(false));
    }

    private static void states() throws Exception {
        written("state-suspended-user", eligibleA(),
                (persistence, at) -> persistence.suspend(RECORD_A, SIGNERS, USER) == SuspensionResult.SUSPENDED);
        written("state-suspended-grant", eligibleA(),
                (persistence, at) -> persistence.suspend(RECORD_A, SIGNERS, GRANT) == SuspensionResult.SUSPENDED);
        Suspension noted = new Suspension(ActorClass.ACCOUNT_USER, 0, 0, SERIAL, ZERO,
                SuspensionReason.DEVICE_HANDOVER.code, TIME + 1, NOTE);
        written("state-suspended-noted", eligibleA(),
                (persistence, at) -> persistence.suspend(RECORD_A, SIGNERS, noted) == SuspensionResult.SUSPENDED);
        // Six entries, the bound of this record version: the account's user, four grants and, from
        // the recovery route, a hold.
        Path six = layout(eligibleA());
        require(persistence(six, V3).suspend(RECORD_A, SIGNERS, USER) == SuspensionResult.SUSPENDED, "user");
        for (int grant = 1; grant <= 4; grant++) {
            require(persistence(six, V3).suspend(RECORD_A, SIGNERS, byGrant(grant, SuspensionReason.DATA_TRANSFER))
                    == SuspensionResult.SUSPENDED, "grant " + grant);
        }
        require(persistence(six, V3).restore(RECORD_A, LINEAGE, SIGNERS, RECOVERY), "the recovery hold");
        require(stored(six, V3).users.get(0).lifecycle.suspensions.size() == 6, "six entries");
        emit("state-six-entries", six, "slot", mapped(PKG_A, A));
        // Restore over copies none of which is intact: ELIGIBLE with scope bit 1.
        Slot newer = slotA(5, retired(retiredBlock(), USER));
        Path unknown = store(header(ID_A, live(A)));
        copies(unknown, torn(newer), torn(newer), null);
        require(persistence(unknown, V3).restore(RECORD_A, LINEAGE, SIGNERS, RECOVERY), "restore unknown");
        emit("state-recovery-prior-unknown", unknown, "slot", mapped(PKG_A, A));
        // Restore over a conflict: the newest intact copy with a hold.
        Path known = store(header(ID_A, live(A)));
        copies(known, bytes(newer), bytes(slotA(4, retiring(byUserRetirement(), USER))), torn(newer));
        require(persistence(known, V3).restore(RECORD_A, LINEAGE, SIGNERS, RECOVERY), "restore known");
        emit("state-recovery-retired", known, "slot", mapped(PKG_A, A));
        written("state-retiring-user", eligibleA(),
                (persistence, at) -> persistence.markRetiring(RECORD_A, SIGNERS, byUserRetirement()));
        written("state-retiring-grant", slotA(2, eligible(USER)),
                (persistence, at) -> persistence.markRetiring(RECORD_A, SIGNERS, byGrantRetirement()));
        written("state-legacy-continued", slotA(1, Lifecycle.version1(true)),
                (persistence, at) -> persistence.markRetiring(RECORD_A, SIGNERS, legacyContinued()));
        written("state-legacy-suspended", slotA(1, Lifecycle.version1(true)),
                (persistence, at) -> persistence.suspend(RECORD_A, SIGNERS, USER) == SuspensionResult.SUSPENDED);
        written("state-retired", slotA(2, retiring(byUserRetirement())),
                (persistence, at) -> persistence.markRetired(RECORD_A, SIGNERS, receipts()));
        written("state-retired-suspended", slotA(2, retiring(byGrantRetirement(), USER)),
                (persistence, at) -> persistence.markRetired(RECORD_A, SIGNERS, receipts()));
        written("state-disposing", slotA(3, retired(retiredBlock())),
                (persistence, at) -> persistence.beginDisposition(RECORD_A, SIGNERS,
                        facts(at)));
        written("state-disposal-confirmed", slotA(4, retired(disposing(retiredBlock()))),
                (persistence, at) -> persistence.confirmDisposition(RECORD_A, SIGNERS,
                        disposals(ObligationKind.KEYSTORE, ObligationKind.HOME),
                        facts(at)));
        written("state-releasable", slotA(4, retired(disposing(retiredBlock()))),
                (persistence, at) -> persistence.confirmDisposition(RECORD_A, SIGNERS, disposals(dispositionKinds()),
                        facts(at)));
        // The lift of the last entry writes version 1 again: older images admit the account again.
        Path lifted = layout(slotA(2, eligible(USER)));
        require(persistence(lifted, V3).lift(RECORD_A, SIGNERS, USER), "lift");
        emit("state-lifted", lifted, "version1", mapped(PKG_A, A));
        // Release from LIVE, stopped after its tombstone, after RELEASING and after the directory.
        Path tombstone = layout(releasableA());
        interrupted("release", "seed-synced", HEADER, 0, () -> release(tombstone, boot(tombstone)));
        require(releasePhase(tombstone).equals("tombstone"), "tombstone " + releasePhase(tombstone));
        emit("state-tombstone-ticketed", tombstone, "slot", mapped(PKG_A, A));
        Path releasing = layout(releasableA());
        interrupted("release", "seed-synced", HEADER, 1, () -> release(releasing, boot(releasing)));
        require(releasePhase(releasing).equals("releasing"), "releasing " + releasePhase(releasing));
        emit("state-releasing-tombstone", releasing, "slot", mapped(PKG_A, A));
        Path gone = layout(releasableA());
        interrupted("release", "seed-synced", HEADER, 2, () -> release(gone, boot(gone)));
        require(releasePhase(gone).equals("gone"), "gone " + releasePhase(gone));
        emit("state-releasing-without-directory", gone, "version1", Map.of());
        Path omitted = layout(releasableA());
        require(release(omitted, boot(omitted)) && releasePhase(omitted).equals("omitted"), "release");
        emit("state-released", omitted, "version1", Map.of());
    }

    // ------------------------------------------------------------------ values no writer of this stage writes

    private static Retirement block(ActorClass actorClass, int user, long serial, String grant,
            List<Obligation> obligations) {
        return new Retirement(actorClass, user, serial, grant, actorClass == ActorClass.LEGACY_MARKER ? 0 : TIME,
                obligations);
    }

    private static List<Obligation> orphaned(boolean retired) {
        List<Obligation> list = new ArrayList<>();
        for (ObligationKind kind : ObligationKind.values()) {
            ObligationState state = kind.disposition() ? ObligationState.ORPHANED_WITH_USER
                    : retired ? ObligationState.DISCHARGED : ObligationState.ORPHANED_WITH_USER;
            list.add(obligation(kind, state, ZERO, 0, 0));
        }
        return list;
    }

    private static void value(String name, Slot value, String kind) throws Exception {
        emit(name, layout(value), kind, mapped(value.packageName, value.appId));
    }

    /** The largest value: 64 users, each with six noted entries and a full retirement block. */
    static Slot maximum() {
        Set<String> signers = new TreeSet<>();
        for (int i = 0; i < 32; i++) signers.add(String.format("%064x", i + 1));
        List<UserEntry> users = new ArrayList<>();
        for (int user = 0; user < 64; user++) {
            long serial = 100 + user;
            List<Suspension> entries = new ArrayList<>();
            entries.add(new Suspension(ActorClass.ACCOUNT_USER, 0, user, serial, ZERO,
                    SuspensionReason.USER_PAUSED.code, TIME, NOTE));
            for (int grant = 1; grant <= 4; grant++) {
                entries.add(new Suspension(ActorClass.ADMIN_GRANT, 0, 0, 7, grant(grant),
                        SuspensionReason.SUSPECTED_COMPROMISE.code, TIME + grant, NOTE));
            }
            entries.add(new Suspension(ActorClass.RECOVERY_HOLD, NativeIdentityRecords.SCOPE_PRIOR_UNKNOWN, 0, 7, ZERO,
                    SuspensionReason.RECOVERY_REVIEW.code, TIME + 9, NOTE));
            entries.sort(NativeIdentityRecords::order);
            users.add(new UserEntry(1 + user, user, serial, new Lifecycle(LifecycleState.RETIRING, entries,
                    block(ActorClass.ACCOUNT_USER, user, serial, ZERO, outstanding()))));
        }
        return new Slot(LINEAGE, A, "a." + "b".repeat(253), 2, signers, users);
    }

    private static void values() throws Exception {
        Suspension blocks = new Suspension(ActorClass.ACCOUNT_USER, NativeIdentityRecords.SCOPE_BLOCKS_DISPOSITION, 0,
                SERIAL, ZERO, SuspensionReason.DATA_TRANSFER.code, TIME, null);
        value("value-scope-blocks-disposition", slotA(2, eligible(blocks)), "slot");
        Suspension both = new Suspension(ActorClass.RECOVERY_HOLD, NativeIdentityRecords.SCOPE_BLOCKS_DISPOSITION
                | NativeIdentityRecords.SCOPE_PRIOR_UNKNOWN, 0, SERIAL, ZERO, SuspensionReason.RECOVERY_REVIEW.code,
                TIME, null);
        value("value-hold-both-scope-bits", slotA(2, eligible(both)), "slot");
        value("value-user-removal-retiring", slotA(3, retiring(block(ActorClass.USER_REMOVAL, 0, SERIAL, ZERO,
                orphaned(false)))), "slot");
        value("value-orphaned-disposition", slotA(4, retired(block(ActorClass.ACCOUNT_USER, 0, SERIAL, ZERO,
                orphaned(true)))), "slot");
        value("value-maximum", maximum(), "slot");
        Lifecycle second = retiring(block(ActorClass.ACCOUNT_USER, 10, 11, ZERO, outstanding()));
        value("value-two-users", new Slot(LINEAGE, A, PKG_A, 2, SIGNERS, List.of(
                new UserEntry(ID_A, 0, SERIAL, eligible(USER)), new UserEntry(ID_B, 10, 11, second))), "slot");
        value("value-legacy-marker", slotA(1, Lifecycle.version1(true)), "version1");
        emit("value-tombstone-without-ticket", layout(new Slot(LINEAGE, A, PKG_A, 4, SIGNERS, List.of())),
                "version1", mapped(PKG_A, A));
        // A tombstone without a ticket under RELEASING, as the old release path left it.
        Path old = store(header(ID_A, releasingEntry(A)));
        slot(old, new Slot(LINEAGE, A, PKG_A, 4, SIGNERS, List.of()));
        emit("value-releasing-tombstone-without-ticket", old, "version1", mapped(PKG_A, A));
    }

    // ------------------------------------------------------------------ every persistence writer step

    private static void sweep(String kind, Slot prior, Writer writer) throws Exception {
        for (String step : STEPS) {
            Path root = layout(prior);
            interrupted(kind, step, SLOT, 0, () -> writer.run(persistence(root, V3), root));
            emit("step-" + dashed(kind) + "-" + step, root, slotVersion(root) == 2 ? "slot" : "version1",
                    mapped(PKG_A, A));
        }
    }

    private static void sweep(String kind, byte[] main, byte[] reserve, byte[] backup) throws Exception {
        for (String step : STEPS) {
            Path root = store(header(ID_A, live(A)));
            copies(root, main, reserve, backup);
            interrupted(kind, step, SLOT, 0,
                    () -> persistence(root, V3).restore(RECORD_A, LINEAGE, SIGNERS, RECOVERY));
            emit("step-" + dashed(kind) + "-" + step, root, slotVersion(root) == 2 ? "slot" : "version1",
                    mapped(PKG_A, A));
        }
    }

    private static void sweep(String kind, Header header, String file, int skip) throws Exception {
        for (String step : STEPS) {
            Path root = store(header);
            slot(root, releasableA());
            NativeIdentityPersistence.BootFacts facts = boot(root);
            interrupted(kind, step, file, skip, () -> release(root, facts));
            boolean directory = Files.isDirectory(root.resolve("slots/" + A), LinkOption.NOFOLLOW_LINKS);
            emit("step-" + dashed(kind) + "-" + step, root, slotVersion(root) == 2 ? "slot" : "version1",
                    directory ? mapped(PKG_A, A) : Map.of());
        }
    }

    /** The prior and call of each transaction as the fault sweeps run them. */
    private static void steps() throws Exception {
        Slot eligible = eligibleA();
        Slot suspended = slotA(2, eligible(USER));
        sweep("suspend", eligible, (persistence, at) -> persistence.suspend(RECORD_A, SIGNERS, USER)
                == SuspensionResult.SUSPENDED);
        Suspension repeated = new Suspension(ActorClass.ACCOUNT_USER, 0, 0, SERIAL, ZERO,
                SuspensionReason.SUSPECTED_COMPROMISE.code, TIME + 9, null);
        sweep("repeated suspension", suspended, (persistence, at) -> persistence.suspend(RECORD_A, SIGNERS, repeated)
                == SuspensionResult.HELD_UNCHANGED);
        sweep("lift", suspended, (persistence, at) -> persistence.lift(RECORD_A, SIGNERS, USER));
        sweep("markRetiring", slotA(2, eligible(USER, GRANT)),
                (persistence, at) -> persistence.markRetiring(RECORD_A, SIGNERS, byUserRetirement()));
        sweep("legacy continuation", slotA(1, Lifecycle.version1(true)),
                (persistence, at) -> persistence.markRetiring(RECORD_A, SIGNERS, legacyContinued()));
        sweep("markRetired", slotA(2, retiring(byGrantRetirement(), USER)),
                (persistence, at) -> persistence.markRetired(RECORD_A, SIGNERS, receipts()));
        sweep("beginDisposition", slotA(3, retired(retiredBlock(), USER)),
                (persistence, at) -> persistence.beginDisposition(RECORD_A, SIGNERS,
                        facts(at)));
        sweep("confirmDisposition", slotA(4, retired(disposing(retiredBlock()), USER)),
                (persistence, at) -> persistence.confirmDisposition(RECORD_A, SIGNERS,
                        disposals(ObligationKind.KEYSTORE, ObligationKind.HOME),
                        facts(at)));
        Slot newer = slotA(5, retired(retiredBlock(), USER));
        sweep("restore", bytes(newer), bytes(slotA(4, retiring(byUserRetirement(), USER))), torn(newer));
        sweep("restore without an intact copy", torn(newer), torn(newer), null);
        Header live = header(ID_A, live(A));
        sweep("release tombstone", live, SLOT, 0);
        sweep("release tombstone confirmation", live, SLOT, 1);
        sweep("release RELEASING", live, HEADER, 0);
        sweep("release RELEASING confirmation", live, HEADER, 1);
        sweep("release omission", live, HEADER, 2);
        sweep("release completion confirmation", creatingA(), SLOT, 0);
        sweep("release completion", creatingA(), HEADER, 0);
    }

    // ------------------------------------------------------------------ every manager writer step

    /** A's account at this generation with the installed package's signers. */
    private static Slot account(long generation, Lifecycle lifecycle) {
        return new Slot(LINEAGE, A, PKG_A, generation, INSTALLED, List.of(new UserEntry(ID_A, 0, SERIAL, lifecycle)));
    }

    /** One Settings instance over root, with A mapped when it is not retired. */
    private static NativePrincipalManager manager(Path root, boolean mapped) {
        PackageManagerService pm = new PackageManagerService(root, false, V3);
        if (mapped) pm.mSettings.add(PKG_A, A);
        pm.mSettings.restoreAfterPackageSettings();
        return new NativePrincipalManager(pm);
    }

    private interface Operation {
        boolean run(NativePrincipalManager manager, NativePrincipalManager.Handle handle) throws Exception;
    }

    // One manager operation over A's account in a fresh instance, failed at each step of its skip-th
    // strict write of file. Committed first when the operation needs the published binding.
    private static void managerSweep(String operation, Slot prior, boolean active, String file, int skip,
            Operation call) throws Exception {
        for (String step : STEPS) {
            Path root = layout(prior);
            NativePrincipalManager manager = manager(root, prior.users.get(0).lifecycle.state == LifecycleState.ELIGIBLE);
            NativePrincipalManager.Handle handle = manager.find(PKG_A, 0);
            require(handle != null, operation + " has no handle");
            if (active) {
                require(manager.prepare(manager.select(PKG_A, 0)) == handle && manager.commit(handle),
                        operation + " is not active");
            }
            interrupted("manager " + operation, step, file, skip, () -> call.run(manager, handle));
            boolean directory = Files.isDirectory(root.resolve("slots/" + A), LinkOption.NOFOLLOW_LINKS);
            emit("manager-" + dashed(operation) + "-" + step, root, slotVersion(root) == 2 ? "slot" : "version1",
                    directory ? mapped(PKG_A, A) : Map.of());
        }
    }

    private static void managerSteps() throws Exception {
        managerSweep("suspend", account(1, Lifecycle.version1(false)), false, SLOT, 0,
                (manager, handle) -> manager.suspend(handle, USER) == SuspensionResult.SUSPENDED);
        managerSweep("lift", account(2, eligible(USER)), false, SLOT, 0,
                (manager, handle) -> manager.lift(handle, USER));
        managerSweep("beginRetirement", account(1, Lifecycle.version1(false)), true, SLOT, 0,
                (manager, handle) -> manager.beginRetirement(handle, byUserRetirement()));
        managerSweep("confirmRetired", account(2, retiring(byUserRetirement())), false, SLOT, 0,
                (manager, handle) -> manager.confirmRetired(handle, receipts()));
        managerSweep("beginDisposition", account(3, retired(retiredBlock())), false, SLOT, 0,
                (manager, handle) -> manager.beginDisposition(handle));
        managerSweep("confirmDisposition", account(4, retired(disposing(retiredBlock()))), false, SLOT, 0,
                (manager, handle) -> manager.confirmDisposition(handle,
                        disposals(ObligationKind.KEYSTORE, ObligationKind.HOME)));
        Slot releasable = account(3, retired(allDischarged(byUserRetirement())));
        Operation release = (manager, handle) -> manager.releaseUid(handle, capability(new Keys()));
        managerSweep("releaseUid tombstone", releasable, false, SLOT, 0, release);
        managerSweep("releaseUid tombstone confirmation", releasable, false, SLOT, 1, release);
        managerSweep("releaseUid RELEASING", releasable, false, HEADER, 0, release);
        managerSweep("releaseUid RELEASING confirmation", releasable, false, HEADER, 1, release);
        managerSweep("releaseUid omission", releasable, false, HEADER, 2, release);
    }

    // ------------------------------------------------------------------ the moved retirement families

    /** A bound reservation of A, restored in a fresh instance with A mapped. */
    private static Path reservedA() throws Exception {
        Header reserved = Header.newV2(LINEAGE, ID_A, List.of(new HeaderEntry(A, SlotPhase.CREATING, ID_A, PKG_A,
                new CreationBinding(0, SERIAL, INSTALLED))));
        return store(reserved);
    }

    private static void moved() throws Exception {
        for (String step : STEPS) {
            // The retirement of a reservation that has not published its body: the first slot write
            // is the body's publication.
            Path publication = reservedA();
            NativePrincipalManager first = manager(publication, true);
            NativePrincipalManager.Handle pending = first.prepare(first.select(PKG_A, 0));
            interrupted("retirement publication", step, SLOT, 0,
                    () -> first.beginRetirement(pending, byUserRetirement()));
            emit("moved-retirement-publication-" + step, publication,
                    slotVersion(publication) == 2 ? "slot" : "version1", mapped(PKG_A, A));
            // The retirement block of a published account: the first slot write is the block.
            Path marker = reservedA();
            NativePrincipalManager second = manager(marker, true);
            NativePrincipalManager.Handle committed = second.prepare(second.select(PKG_A, 0));
            require(second.commit(committed), "publication refused");
            interrupted("retirement block", step, SLOT, 0,
                    () -> second.beginRetirement(committed, byUserRetirement()));
            emit("moved-retirement-block-" + step, marker, slotVersion(marker) == 2 ? "slot" : "version1",
                    mapped(PKG_A, A));
            // A reservation interrupted at each header step while another account is retiring.
            PackageManagerService several = new PackageManagerService(fresh(), true, V3);
            several.mSettings.add(PKG_B, B);
            several.mSettings.add(PKG_A, A);
            NativePrincipalManager third = new NativePrincipalManager(several);
            NativePrincipalManager.Handle retiring = third.prepare(third.select(PKG_B, 0));
            require(third.commit(retiring) && third.beginRetirement(retiring, byUserRetirement()), "B not retiring");
            interrupted("reservation beside a retiring account", step, HEADER, 0, () -> {
                NativePrincipalManager.Handle reservation = third.prepare(third.select(PKG_A, 0));
                return reservation != null && third.commit(reservation);
            });
            Map<String, String> both = new TreeMap<>(mapped(PKG_A, A));
            both.put(PKG_B, String.valueOf(B));
            emit("moved-pending-retiring-" + step, several.mSettings.root, "slot", both);
        }
        // The account released through the lifecycle path: retired, disposed in a retired boot, then
        // released in another, with its entry omitted and its directory gone.
        Path released = reservedA();
        NativePrincipalManager owner = manager(released, true);
        NativePrincipalManager.Handle handle = owner.prepare(owner.select(PKG_A, 0));
        require(owner.commit(handle) && owner.beginRetirement(handle, byUserRetirement())
                && owner.confirmRetired(handle, receipts()), "retirement refused");
        NativePrincipalManager disposer = manager(released, false);
        NativePrincipalManager.Handle retired = disposer.find(PKG_A, 0);
        require(disposer.beginDisposition(retired)
                && disposer.confirmDisposition(retired, disposals(dispositionKinds())), "disposition refused");
        NativePrincipalManager releaser = manager(released, false);
        require(releaser.releaseUid(releaser.find(PKG_A, 0), capability(new Keys())), "release refused");
        emit("moved-final-released", released, "version1", Map.of());
    }

    // ------------------------------------------------------------------ companions

    private static Header besideReservation(long lastId, HeaderEntry... more) {
        List<HeaderEntry> entries = new ArrayList<>(List.of(more));
        entries.add(new HeaderEntry(R, SlotPhase.CREATING, ID_R, PKG_R, new CreationBinding(0, SERIAL, SIGNERS)));
        entries.sort((first, second) -> Integer.compare(first.appId, second.appId));
        return Header.newV2(LINEAGE, lastId, entries);
    }

    private static void companions() throws Exception {
        Map<String, Slot> accounts = new LinkedHashMap<>();
        accounts.put("suspended", slotA(2, eligible(USER)));
        accounts.put("retiring", slotA(2, retiring(byUserRetirement())));
        accounts.put("retired", slotA(3, retired(retiredBlock(), USER)));
        for (Map.Entry<String, Slot> account : accounts.entrySet()) {
            Slot value = account.getValue();
            // A version 2 slot beside a bound reservation of another package elsewhere in the store.
            Path reservation = store(besideReservation(ID_R, live(A)));
            slot(reservation, value);
            Map<String, String> packages = new TreeMap<>(mapped(PKG_A, A));
            packages.put(PKG_R, String.valueOf(R));
            emit("companion-reservation-" + account.getKey(), reservation, "reservation", packages);
            // A version 2 slot beside a valid sibling naming the same package, which Package Manager
            // maps at the sibling's app ID.
            Path sibling = store(header(ID_S, live(A), live(S)));
            slot(sibling, value);
            slot(sibling, new Slot(LINEAGE, S, PKG_A, 1, SIGNERS, List.of(new UserEntry(ID_S, 0, SERIAL,
                    Lifecycle.version1(false)))));
            emit("companion-sibling-package-" + account.getKey(), sibling, "sibling", mapped(PKG_A, S));
            // A version 2 slot alone, whose package's mapping is lost.
            emit("companion-lost-" + account.getKey(), layout(value), "lost", Map.of(PKG_A, "lost"));
        }
        // A sibling of another package naming the version 2 slot's principal.
        Path principal = store(header(ID_S, live(A), live(S)));
        slot(principal, slotA(2, eligible(USER)));
        slot(principal, new Slot(LINEAGE, S, PKG_S, 1, SIGNERS, List.of(new UserEntry(ID_A, 0, SERIAL,
                Lifecycle.version1(false)))));
        emit("companion-sibling-principal-suspended", principal, "sibling", mapped(PKG_S, S));
        // The reservation beside a tombstone with its ticket, under LIVE.
        Path ticketed = store(besideReservation(ID_R, live(A)));
        slot(ticketed, tombstoneA());
        Map<String, String> packages = new TreeMap<>(mapped(PKG_A, A));
        packages.put(PKG_R, String.valueOf(R));
        emit("companion-reservation-tombstone", ticketed, "reservation", packages);
    }

    private interface Group { void run() throws Exception; }

    /**
     * Arguments: a fresh output directory, a state directory and, optionally, a comma separated
     * list of groups to emit, by default all of them in this order.
     */
    public static void main(String[] args) throws Exception {
        if (!NativeLifecycleLayouts.class.desiredAssertionStatus()) throw new AssertionError("run with java -ea");
        out = Path.of(args[0]);
        if (Files.exists(out, LinkOption.NOFOLLOW_LINKS)) throw new AssertionError("fresh output required");
        Map<String, Group> groups = new LinkedHashMap<>();
        groups.put("states", NativeLifecycleLayouts::states);
        groups.put("values", NativeLifecycleLayouts::values);
        groups.put("steps", NativeLifecycleLayouts::steps);
        groups.put("manager", NativeLifecycleLayouts::managerSteps);
        groups.put("moved", NativeLifecycleLayouts::moved);
        groups.put("companions", NativeLifecycleLayouts::companions);
        List<String> selected = args.length > 2 ? List.of(args[2].split(",")) : List.copyOf(groups.keySet());
        require(!selected.isEmpty() && groups.keySet().containsAll(selected), "groups " + selected);
        Files.createDirectories(out);
        start(Path.of(args[1]).resolve("lifecycle-layouts"));
        LocalServices.addService(UserManagerInternal.class, new UserManagerInternal());
        for (String group : selected) groups.get(group).run();
        for (String name : emitted) System.out.println("LAYOUT " + name);
        System.out.println(emitted.size() + " lifecycle layouts emitted under Format.V3; Android storage unqualified");
    }
}
