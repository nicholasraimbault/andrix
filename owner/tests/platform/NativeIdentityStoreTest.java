// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import android.system.Os;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.HeaderEntry;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.SlotPhase;
import com.android.server.pm.NativeIdentityRecords.UserEntry;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Set;

/** Actual store I/O with Android API facades, not device persistence or UID authority proof. */
public final class NativeIdentityStoreTest {
    private static final String LINEAGE = "0123456789abcdef0123456789abcdef";
    private static final Set<String> SIGNERS = Set.of("a".repeat(64));
    private static final int APP = 10123;
    private static final String PACKAGE = "dev.andrix.account";
    private static HeaderEntry entry(int id, SlotPhase phase) {
        return new HeaderEntry(id, phase, phase == SlotPhase.CREATING ? 1 : 0,
                phase == SlotPhase.CREATING ? PACKAGE : "");
    }
    private static Slot slot(long generation, List<UserEntry> users) {
        return new Slot(LINEAGE, APP, PACKAGE, generation, SIGNERS, users);
    }
    private static Path main(Path root, int id) {
        return root.resolve("slots/" + id + "/record.bin");
    }
    private static void write(Path file, byte[] bytes) throws Exception {
        Files.deleteIfExists(file); Files.write(file, bytes);
    }
    // Every path below root with its bytes.
    private static java.util.Map<String, String> contents(Path root) throws Exception {
        java.util.Map<String, String> result = new java.util.TreeMap<>();
        try (var walk = Files.walk(root)) {
            for (Path path : walk.toList()) {
                result.put(root.relativize(path).toString(), Files.isRegularFile(path)
                        ? java.util.Base64.getEncoder().encodeToString(Files.readAllBytes(path)) : "directory");
            }
        }
        return result;
    }
    private static int twins;

    // A lifecycle write under version 1: false, before any effect. So it is under Format.V2, which
    // reads this version 1 state as it is, over a copy of the same bytes.
    private static boolean refused(Path root, java.util.function.Predicate<NativeIdentityStore> write)
            throws Exception {
        java.util.Map<String, String> before = contents(root);
        if (write.test(new NativeIdentityStore(root.toFile(), NativeIdentityStore.Format.V1))
                || !contents(root).equals(before)) {
            return false;
        }
        Path copy = root.resolveSibling(root.getFileName() + "-twin-" + ++twins);
        for (java.util.Map.Entry<String, String> entry : before.entrySet()) {
            Path target = copy.resolve(entry.getKey());
            if (entry.getValue().equals("directory")) Files.createDirectories(target);
            else Files.write(target, java.util.Base64.getDecoder().decode(entry.getValue()));
        }
        return !write.test(new NativeIdentityStore(copy.toFile(), NativeIdentityStore.Format.V2))
                && contents(copy).equals(before);
    }
    public static void main(String[] args) throws Exception {
        if (!NativeIdentityStoreTest.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        Path root = Path.of(args[0]).resolve("store");
        NativeIdentityStore store = new NativeIdentityStore(root.toFile(), NativeIdentityStore.Format.V1);
        assert store.load().creationBlocked && !Files.exists(root);
        Os.failSync = true;
        assert !store.initializeNew(LINEAGE);
        Os.failSync = false;
        assert !Files.exists(root); // Incomplete layout never takes the canonical name.
        assert store.pendingInitializationNames().size() == 1;
        assert store.initializeNew(LINEAGE);
        assert store.initializeNew(LINEAGE); // Exact same-lineage empty-result retry.
        assert !store.initializeNew("b".repeat(32)); // No unknown store adoption.
        Header empty = new Header(LINEAGE, 0, List.of());
        assert store.load().header.value.equals(empty) && !store.load().creationBlocked;
        Header creating = new Header(LINEAGE, 1, List.of(entry(APP, SlotPhase.CREATING)));
        assert store.writeHeader(empty, creating);
        assert store.load().occupiedAppIds.equals(Set.of(APP));
        assert !store.load().bindingUsable(APP);
        assert store.ensureFreshSlot(creating, APP);
        assert !store.ensureFreshSlot(creating, APP);
        assert store.resumeCreatingDirectory(creating, APP);
        Path unknownCreationFile = main(root, APP).getParent().resolve("unknown");
        Files.writeString(unknownCreationFile, "not owned by the creation");
        assert !store.resumeCreatingDirectory(creating, APP);
        assert Files.exists(unknownCreationFile);
        Files.delete(unknownCreationFile);
        Header live = new Header(LINEAGE, 1, List.of(entry(APP, SlotPhase.LIVE)));
        assert !store.writeHeader(creating, live); // No record, no publication.
        Slot pending = slot(1, List.of(new UserEntry(1, 0, 7, false)));
        // A torn unpublished seed is MISSING, not a torn authoritative main.
        Path creationSeed = Path.of(main(root, APP) + "-seed");
        Files.write(creationSeed, NativeIdentityRecords.encodeSlot(new Slot("f".repeat(32), APP,
                PACKAGE, 1, SIGNERS, pending.users)));
        assert !store.resumeCreatingDirectory(creating, APP);
        Files.write(creationSeed, new byte[]{1, 2});
        assert store.resumeCreatingDirectory(creating, APP);
        assert store.load().slots.get(APP).status == NativeIdentityStore.Status.MISSING;
        Os.syncCalls = 0; Os.failSyncAt = 5;
        assert !store.publishCreatingSlot(creating, pending);
        Os.failSyncAt = 0;
        assert !Files.exists(main(root, APP));
        assert NativeIdentityRecords.decodeSlot(Files.readAllBytes(
                Path.of(main(root, APP) + "-backup"))).equals(pending);
        // Only pending metadata is recoverable here, never a restored active grant.
        assert store.publishCreatingSlot(creating, pending);
        assert store.writeHeader(creating, live);
        assert store.load().bindingUsable(APP);
        assert !store.writeHeader(empty, creating); // Stale expected base.
        assert !store.writeHeader(live, new Header(LINEAGE, 1, List.of()));
        assert !store.writeHeader(live, new Header(LINEAGE, 1,
                List.of(entry(APP, SlotPhase.RELEASING))));
        assert !store.writeHeader(live, creating);
        assert !store.updateExistingSlot(pending, slot(2, List.of())); // No omission of nonretiring entry.

        Path file = main(root, APP), reserve = Path.of(file + ".reservecopy"), backup = Path.of(file + "-backup");
        byte[] bad = {1, 2, 3};
        write(file, bad);
        assert store.load().bindingUsable(APP); // Intact reserve, no automatic deletion of bad main.
        assert java.util.Arrays.equals(Files.readAllBytes(file), bad);
        // A version 1 retiring body, which older writers left and this one only reads: the retiring
        // flag is a lifecycle write, refused before any effect.
        Slot retiring = slot(2, List.of(new UserEntry(1, 0, 7, true)));
        Slot touched = slot(2, pending.users);
        assert refused(root, s -> s.updateExistingSlot(pending, retiring));
        // Backup preparation must preserve the valid reserve BEFORE startWrite
        // can rename the corrupt main and remove the only good recovery body.
        Os.failSync = true;
        assert !store.updateExistingSlot(pending, touched);
        Os.failSync = false;
        assert Files.exists(backup);
        assert NativeIdentityRecords.decodeSlot(Files.readAllBytes(backup)).equals(pending);
        assert store.load().slots.get(APP).value.equals(pending);
        assert store.updateExistingSlot(pending, touched);
        assert store.load().slots.get(APP).value.equals(touched);
        assert !Files.exists(backup);
        assert refused(root, s -> s.updateExistingSlot(touched, slot(3, retiring.users)));
        write(file, NativeIdentityRecords.encodeSlot(retiring));
        write(reserve, NativeIdentityRecords.encodeSlot(retiring));
        assert refused(root, s -> s.updateExistingSlot(retiring, slot(3, pending.users)));

        // Copy conflict is not a positive union. The UID remains occupied.
        write(reserve, NativeIdentityRecords.encodeSlot(pending));
        assert store.load().slots.get(APP).status == NativeIdentityStore.Status.CONFLICT;
        assert store.load().occupiedAppIds.equals(Set.of(APP));
        assert !store.load().bindingUsable(APP);
        write(reserve, NativeIdentityRecords.encodeSlot(retiring));
        write(backup, bad);
        assert store.load().slots.get(APP).status == NativeIdentityStore.Status.DAMAGED;
        assert Files.exists(backup); // Never failRead/delete, never skip a bad preferred backup.
        Files.delete(backup);
        write(file, bad); write(reserve, bad);
        assert store.load().slots.get(APP).status == NativeIdentityStore.Status.DAMAGED;
        assert store.load().occupiedAppIds.equals(Set.of(APP));
        assert !store.load().bindingUsable(APP) && !store.load().creationBlocked;
        write(file, NativeIdentityRecords.encodeSlot(retiring));
        write(reserve, NativeIdentityRecords.encodeSlot(retiring));

        // The durable index retains an ID even when its whole slot directory is lost.
        Files.delete(file); Files.delete(reserve); Files.delete(file.getParent());
        assert store.load().occupiedAppIds.equals(Set.of(APP));
        assert store.load().slots.get(APP).status == NativeIdentityStore.Status.MISSING;
        Files.createDirectory(file.getParent());
        write(file, NativeIdentityRecords.encodeSlot(retiring));
        write(reserve, NativeIdentityRecords.encodeSlot(retiring));

        Path header = root.resolve("store.bin"), headerReserve = root.resolve("store.bin.reservecopy");
        write(header, bad); write(headerReserve, bad);
        assert store.load().creationBlocked;
        assert store.load().occupiedAppIds.equals(Set.of(APP));
        assert store.load().bindingUsable(APP); // Existing binding does not need a new counter.
        assert !store.load().creationReady();
        assert store.confirmExistingSlot(retiring);
        write(file, NativeIdentityRecords.encodeSlot(pending));
        write(reserve, NativeIdentityRecords.encodeSlot(pending));
        assert store.updateExistingSlot(pending, touched);
        assert store.load().slots.get(APP).value.equals(touched);
        write(file, NativeIdentityRecords.encodeSlot(retiring));
        write(reserve, NativeIdentityRecords.encodeSlot(retiring));
        assert !store.removeReleasingSlot(new Header(LINEAGE, 1,
                List.of(entry(APP, SlotPhase.RELEASING))), APP);
        assert !store.initializeNew("1".repeat(32));
        write(header, NativeIdentityRecords.encodeHeader(live));
        write(headerReserve, NativeIdentityRecords.encodeHeader(live));

        // Cross-record checks are not codec checks: valid bytes from another
        // slot/lineage/counter do not become a positive binding here.
        Slot wrongId = new Slot(LINEAGE, APP + 1, PACKAGE, 2, SIGNERS, retiring.users);
        write(file, NativeIdentityRecords.encodeSlot(wrongId));
        write(reserve, NativeIdentityRecords.encodeSlot(wrongId));
        assert store.load().slots.get(APP).status == NativeIdentityStore.Status.CONFLICT;
        Slot wrongLineage = new Slot("f".repeat(32), APP, PACKAGE, 2, SIGNERS, retiring.users);
        write(file, NativeIdentityRecords.encodeSlot(wrongLineage));
        write(reserve, NativeIdentityRecords.encodeSlot(wrongLineage));
        assert !store.load().bindingUsable(APP);
        Slot counterAhead = slot(2, List.of(new UserEntry(2, 0, 7, true)));
        write(file, NativeIdentityRecords.encodeSlot(counterAhead));
        write(reserve, NativeIdentityRecords.encodeSlot(counterAhead));
        assert store.load().creationBlocked && !store.load().bindingUsable(APP);
        Slot unsupported = slot(2, List.of(new UserEntry(1, 10, 7, true)));
        write(file, NativeIdentityRecords.encodeSlot(unsupported));
        write(reserve, NativeIdentityRecords.encodeSlot(unsupported));
        assert store.load().slots.get(APP).status == NativeIdentityStore.Status.UNSUPPORTED;
        write(file, NativeIdentityRecords.encodeSlot(retiring));
        write(reserve, NativeIdentityRecords.encodeSlot(retiring));

        // Divergent valid header copies contribute only negative holds.
        Header foreignIndex = new Header(LINEAGE, 1, List.of(entry(APP + 1, SlotPhase.LIVE)));
        write(headerReserve, NativeIdentityRecords.encodeHeader(foreignIndex));
        assert store.load().header.status == NativeIdentityStore.Status.CONFLICT;
        assert store.load().creationBlocked && !store.load().bindingUsable(APP);
        assert store.load().occupiedAppIds.equals(Set.of(APP, APP + 1));
        write(headerReserve, NativeIdentityRecords.encodeHeader(live));

        // Duplicate package or incarnation bindings fence both participants,
        // without inventing a winning record from valid but conflicting bytes.
        Path peer = main(root, APP + 1); Files.createDirectory(peer.getParent());
        Header two = new Header(LINEAGE, 2,
                List.of(entry(APP, SlotPhase.LIVE), entry(APP + 1, SlotPhase.LIVE)));
        write(header, NativeIdentityRecords.encodeHeader(two));
        write(headerReserve, NativeIdentityRecords.encodeHeader(two));
        Slot duplicatePackage = new Slot(LINEAGE, APP + 1, PACKAGE, 1, SIGNERS,
                List.of(new UserEntry(2, 0, 7, false)));
        write(peer, NativeIdentityRecords.encodeSlot(duplicatePackage));
        assert !store.load().bindingUsable(APP) && !store.load().bindingUsable(APP + 1);
        Slot duplicateId = new Slot(LINEAGE, APP + 1, "dev.andrix.peer", 1, SIGNERS,
                List.of(new UserEntry(1, 0, 7, false)));
        write(peer, NativeIdentityRecords.encodeSlot(duplicateId));
        assert store.load().slots.get(APP).status == NativeIdentityStore.Status.CONFLICT;
        assert store.load().slots.get(APP + 1).status == NativeIdentityStore.Status.CONFLICT;
        Files.delete(peer); Files.delete(peer.getParent());
        write(header, NativeIdentityRecords.encodeHeader(live));
        write(headerReserve, NativeIdentityRecords.encodeHeader(live));

        // Unrelated damaged slots keep their own hold; they don't invalidate
        // an otherwise known native identity or erase ordinary package state.
        Files.createDirectory(root.resolve("slots/10124"));
        write(root.resolve("slots/10124/record.bin"), bad);
        assert store.load().bindingUsable(APP);
        assert store.load().occupiedAppIds.equals(Set.of(APP, 10124));
        assert !store.load().creationReady();
        assert !store.writeHeader(live, new Header(LINEAGE, 2, live.entries));
        assert !store.writeHeader(live, new Header(LINEAGE, 2, List.of(
                entry(APP, SlotPhase.LIVE), new HeaderEntry(10125, SlotPhase.CREATING, 2,
                "dev.andrix.fresh"))));
        Files.delete(root.resolve("slots/10124/record.bin"));
        Files.delete(root.resolve("slots/10124"));

        // Filesystem aliases are refused, with a conservative negative hold.
        Path elsewhere = root.getParent().resolve("elsewhere"); Files.createDirectory(elsewhere);
        Files.createSymbolicLink(root.resolve("slots/10125"), elsewhere);
        assert store.load().occupiedAppIds.contains(10125);
        assert store.load().slots.get(10125).status == NativeIdentityStore.Status.DAMAGED;
        Files.delete(root.resolve("slots/10125"));

        // The release's steps are lifecycle writes, each refused before any effect: the user drop
        // to the tombstone, RELEASING, the removal, the omission and the released confirmation.
        // The release engine takes them under the lifecycle format alone.
        Slot tombstone = slot(3, List.of());
        assert refused(root, s -> s.updateExistingSlot(retiring, tombstone));
        assert store.load().bindingUsable(APP);
        Header releasing = new Header(LINEAGE, 1, List.of(entry(APP, SlotPhase.RELEASING)));
        assert refused(root, s -> s.writeHeader(live, releasing));
        Header released = new Header(LINEAGE, 1, List.of());
        assert refused(root, s -> s.writeHeader(live, released));
        // An older writer's release, written as its bytes: RELEASING beside its tombstone.
        write(file, NativeIdentityRecords.encodeSlot(tombstone));
        write(reserve, NativeIdentityRecords.encodeSlot(tombstone));
        write(header, NativeIdentityRecords.encodeHeader(releasing));
        write(headerReserve, NativeIdentityRecords.encodeHeader(releasing));
        assert !store.load().bindingUsable(APP);
        assert refused(root, s -> s.updateExistingSlot(tombstone, slot(4, pending.users)));
        assert refused(root, s -> s.removeReleasingSlot(releasing, APP));
        assert refused(root, s -> s.writeHeader(releasing, released));
        assert refused(root, s -> s.confirmReleasedSlot(releasing, APP));
        assert store.load().occupiedAppIds.equals(Set.of(APP)) && Files.exists(file);
        // Its finished release, as bytes: the slot directory removed and the index omitted.
        Files.delete(file); Files.delete(reserve); Files.delete(file.getParent());
        write(header, NativeIdentityRecords.encodeHeader(released));
        write(headerReserve, NativeIdentityRecords.encodeHeader(released));
        assert store.load().occupiedAppIds.isEmpty() && store.load().header.value.lastId == 1;
        assert refused(root, s -> s.confirmReleasedSlot(released, APP));
        // A released principal ID cannot be smuggled into a new user entry just
        // because it is below the counter. Additions need an issuance proof.
        Header anotherCreating = new Header(LINEAGE, 2, List.of(
                new HeaderEntry(APP, SlotPhase.CREATING, 2, PACKAGE)));
        assert store.writeHeader(released, anotherCreating);
        assert store.ensureFreshSlot(anotherCreating, APP);
        Slot another = slot(1, List.of(new UserEntry(2, 0, 7, false)));
        assert store.publishCreatingSlot(anotherCreating, another);
        Header anotherLive = new Header(LINEAGE, 2, List.of(entry(APP, SlotPhase.LIVE)));
        assert store.writeHeader(anotherCreating, anotherLive);
        Slot reusedId = slot(2, List.of(new UserEntry(2, 0, 7, false),
                new UserEntry(1, 10, 9, false)));
        assert !store.updateExistingSlot(another, reusedId);
        assert store.load().slots.get(APP).value.equals(another);
        NativeIdentityStore.Loaded good = store.load();
        NativeIdentityStore.Loaded incomplete = new NativeIdentityStore.Loaded(good.header,
                good.slots, good.occupiedAppIds, true, false);
        assert !incomplete.bindingUsable(APP) && !incomplete.creationReady();
        // The retiring flag refuses under version 1 on a CREATING entry and after it completes to
        // LIVE alike; the lifecycle format's release completes a CREATING entry to LIVE first.
        Path interruptedRoot = root.getParent().resolve("creating-retirement-case");
        NativeIdentityStore interrupted = new NativeIdentityStore(interruptedRoot.toFile(),
                NativeIdentityStore.Format.V1);
        assert interrupted.initializeNew(LINEAGE);
        assert interrupted.writeHeader(empty, creating);
        assert interrupted.ensureFreshSlot(creating, APP);
        assert interrupted.publishCreatingSlot(creating, pending);
        assert refused(interruptedRoot, s -> s.updateExistingSlot(pending, retiring));
        assert interrupted.writeHeader(creating, live);
        assert refused(interruptedRoot, s -> s.updateExistingSlot(pending, retiring));

        // I/O unavailability is its own fact, neither absence nor parser damage. It withholds
        // writers and creation; only an unreadable header copy withdraws every binding.
        NativeIdentityStore.Loaded unavailableStore = new NativeIdentityStore.Loaded(good.header,
                good.slots, good.occupiedAppIds, false, true, false, true);
        assert unavailableStore.unavailableFootprint && unavailableStore.creationBlocked;
        assert !unavailableStore.creationReady() && unavailableStore.bindingUsable(APP);
        NativeIdentityStore.Loaded unavailableHeader = new NativeIdentityStore.Loaded(
                new NativeIdentityStore.ReadResult<>(NativeIdentityStore.Status.DAMAGED, null,
                        good.header.decodedCopies, true), good.slots, good.occupiedAppIds,
                true, true, false, true);
        assert !unavailableHeader.bindingUsable(APP) && unavailableHeader.occupiedAppIds.contains(APP);
        Path unreadableCopy = Path.of(main(root, APP) + ".reservecopy");
        Set<PosixFilePermission> copyMode = Files.getPosixFilePermissions(unreadableCopy);
        Files.setPosixFilePermissions(unreadableCopy, PosixFilePermissions.fromString("-w-------"));
        NativeIdentityStore.Loaded unreadable;
        try {
            unreadable = store.load();
        } finally {
            Files.setPosixFilePermissions(unreadableCopy, copyMode);
        }
        assert unreadable.unavailableFootprint : "unreadable copy control requires unprivileged DAC";
        assert unreadable.slots.get(APP).unavailable
                && unreadable.slots.get(APP).status == NativeIdentityStore.Status.DAMAGED;
        assert !unreadable.bindingUsable(APP) && unreadable.occupiedAppIds.contains(APP);
        assert !store.load().unavailableFootprint && store.load().bindingUsable(APP);

        // Header copies must be compatible with the selection, as the writers leave them. An
        // unselected addition is restated exactly, with its binding, under a counter covering every
        // copy. It is no creation block, only no counter for a new registry.
        HeaderEntry addition = new HeaderEntry(APP + 1, SlotPhase.CREATING, 2, "dev.andrix.pending");
        Header selectedIndex = new Header(LINEAGE, 1, List.of(entry(APP, SlotPhase.LIVE)));
        Header unselectedIndex = new Header(LINEAGE, 2, List.of(entry(APP, SlotPhase.LIVE), addition));
        NativeIdentityStore.ReadResult<Header> indexCopies = new NativeIdentityStore.ReadResult<>(
                NativeIdentityStore.Status.VALID, selectedIndex,
                List.of(unselectedIndex, unselectedIndex, selectedIndex));
        assert NativeIdentityStore.keepsHeaderCopies(indexCopies, unselectedIndex,
                NativeIdentityStore.Format.V1);
        assert !NativeIdentityStore.keepsHeaderCopies(indexCopies, selectedIndex,
                NativeIdentityStore.Format.V1);
        assert !NativeIdentityStore.keepsHeaderCopies(indexCopies, new Header(LINEAGE, 2, List.of(
                entry(APP, SlotPhase.LIVE), new HeaderEntry(APP + 1, SlotPhase.CREATING, 2, PACKAGE))),
                NativeIdentityStore.Format.V1);
        assert !NativeIdentityStore.keepsHeaderCopies(indexCopies, Header.newV2(LINEAGE, 2, List.of(
                entry(APP, SlotPhase.LIVE), new HeaderEntry(APP + 1, SlotPhase.CREATING, 2,
                "dev.andrix.pending", new NativeIdentityRecords.CreationBinding(0, 7, SIGNERS)))),
                NativeIdentityStore.Format.V1);
        assert !NativeIdentityStore.keepsHeaderCopies(indexCopies,
                new Header("f".repeat(32), 2, unselectedIndex.entries),
                NativeIdentityStore.Format.V1);
        // The largest observed counter is only a floor for the next header. Inside it a new
        // entry must be a known addition; a new identity lies above it.
        Header wideIndex = new Header(LINEAGE, 3, List.of(entry(APP, SlotPhase.LIVE), addition));
        NativeIdentityStore.ReadResult<Header> wideCopies = new NativeIdentityStore.ReadResult<>(
                NativeIdentityStore.Status.VALID, selectedIndex, List.of(wideIndex, selectedIndex));
        assert !NativeIdentityStore.keepsHeaderCopies(wideCopies, unselectedIndex,
                NativeIdentityStore.Format.V1);
        assert NativeIdentityStore.keepsHeaderCopies(wideCopies, wideIndex,
                NativeIdentityStore.Format.V1);
        assert !NativeIdentityStore.keepsHeaderCopies(wideCopies, new Header(LINEAGE, 3, List.of(
                entry(APP, SlotPhase.LIVE), addition,
                new HeaderEntry(APP + 2, SlotPhase.CREATING, 3, "dev.andrix.later"))),
                NativeIdentityStore.Format.V1);
        assert NativeIdentityStore.keepsHeaderCopies(wideCopies, new Header(LINEAGE, 4, List.of(
                entry(APP, SlotPhase.LIVE), addition,
                new HeaderEntry(APP + 2, SlotPhase.CREATING, 4, "dev.andrix.later"))),
                NativeIdentityStore.Format.V1);
        // A higher counter without a new reservation is incompatible, and no write produces one.
        Header counterOnlyIndex = new Header(LINEAGE, 3, selectedIndex.entries);
        NativeIdentityStore.ReadResult<Header> selectedAlone = new NativeIdentityStore.ReadResult<>(
                NativeIdentityStore.Status.VALID, selectedIndex, List.of(selectedIndex));
        assert !NativeIdentityStore.keepsHeaderCopies(new NativeIdentityStore.ReadResult<>(
                NativeIdentityStore.Status.VALID, selectedIndex, List.of(counterOnlyIndex, selectedIndex)),
                counterOnlyIndex,
                NativeIdentityStore.Format.V1);
        assert !NativeIdentityStore.keepsHeaderCopies(selectedAlone, counterOnlyIndex,
                NativeIdentityStore.Format.V1);
        assert NativeIdentityStore.keepsHeaderCopies(selectedAlone, unselectedIndex,
                NativeIdentityStore.Format.V1);
        // Backward, skipped or dropped entries are incompatible, and so is a copy that lacks a
        // selected reservation its own counter already covers.
        Header creatingIndex = new Header(LINEAGE, 1, List.of(entry(APP, SlotPhase.CREATING)));
        Header skippedIndex = new Header(LINEAGE, 1, List.of(entry(APP, SlotPhase.RELEASING)));
        for (Header[] pair : List.of(new Header[] {selectedIndex, creatingIndex},
                new Header[] {selectedIndex, new Header(LINEAGE, 1, List.of())},
                new Header[] {creatingIndex, skippedIndex},
                new Header[] {unselectedIndex, new Header(LINEAGE, 2, selectedIndex.entries)})) {
            assert !NativeIdentityStore.keepsHeaderCopies(new NativeIdentityStore.ReadResult<>(
                    NativeIdentityStore.Status.VALID, pair[0], List.of(pair[1], pair[0])), pair[0],
                    NativeIdentityStore.Format.V1);
        }
        // A copy that predates a protected reservation, below its counter, is compatible.
        NativeIdentityStore.ReadResult<Header> protectedCopies = new NativeIdentityStore.ReadResult<>(
                NativeIdentityStore.Status.VALID, unselectedIndex, List.of(selectedIndex, unselectedIndex));
        assert NativeIdentityStore.keepsHeaderCopies(protectedCopies, unselectedIndex,
                NativeIdentityStore.Format.V1);
        NativeIdentityStore.Loaded predecessor = new NativeIdentityStore.Loaded(protectedCopies,
                java.util.Map.of(), Set.of(APP, APP + 1), false, true);
        assert !predecessor.unselectedFootprint && predecessor.counterRestorable();
        // Only a pure reservation advances the counter: no phase change rides along.
        NativeIdentityStore.ReadResult<Header> creatingAlone = new NativeIdentityStore.ReadResult<>(
                NativeIdentityStore.Status.VALID, creatingIndex, List.of(creatingIndex));
        assert !NativeIdentityStore.keepsHeaderCopies(creatingAlone, new Header(LINEAGE, 2, List.of(
                entry(APP, SlotPhase.LIVE), addition)),
                NativeIdentityStore.Format.V1);
        assert NativeIdentityStore.keepsHeaderCopies(creatingAlone, new Header(LINEAGE, 2, List.of(
                entry(APP, SlotPhase.CREATING), addition)),
                NativeIdentityStore.Format.V1);
        NativeIdentityStore.Loaded withAddition = new NativeIdentityStore.Loaded(indexCopies,
                java.util.Map.of(), Set.of(APP, APP + 1), false, true);
        assert withAddition.unselectedFootprint && withAddition.creationReady()
                && !withAddition.counterRestorable();
        Header otherLineageIndex = new Header("f".repeat(32), 1, List.of(entry(APP, SlotPhase.LIVE)));
        assert new NativeIdentityStore.Loaded(new NativeIdentityStore.ReadResult<>(
                NativeIdentityStore.Status.VALID, selectedIndex, List.of(otherLineageIndex, selectedIndex)),
                java.util.Map.of(), Set.of(APP), false, true).unselectedFootprint;
        Header markedIndex = new Header(LINEAGE, 1, List.of(entry(APP, SlotPhase.RELEASING)));
        NativeIdentityStore.Loaded phaseOnly = new NativeIdentityStore.Loaded(
                new NativeIdentityStore.ReadResult<>(NativeIdentityStore.Status.VALID, selectedIndex,
                        List.of(markedIndex, markedIndex, selectedIndex)), java.util.Map.of(), Set.of(APP),
                false, true);
        assert !phaseOnly.unselectedFootprint && phaseOnly.counterRestorable();
        assert Os.allClosed();
        System.out.println("Native identity slot storage/recovery/retirement passed; Android unqualified");
    }
}
