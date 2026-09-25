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
    public static void main(String[] args) throws Exception {
        if (!NativeIdentityStoreTest.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        Path root = Path.of(args[0]).resolve("store");
        NativeIdentityStore store = new NativeIdentityStore(root.toFile());
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
        Header live = new Header(LINEAGE, 1, List.of(entry(APP, SlotPhase.LIVE)));
        assert !store.writeHeader(creating, live); // No record, no publication.
        Slot pending = slot(1, List.of(new UserEntry(1, 0, 7, false)));
        // A torn unpublished seed is MISSING, not a torn authoritative main.
        Files.write(Path.of(main(root, APP) + "-seed"), new byte[]{1, 2});
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
        Slot retiring = slot(2, List.of(new UserEntry(1, 0, 7, true)));
        // Backup preparation must preserve the valid reserve BEFORE startWrite
        // can rename the corrupt main and remove the only good recovery body.
        Os.failSync = true;
        assert !store.updateExistingSlot(pending, retiring);
        Os.failSync = false;
        assert Files.exists(backup);
        assert NativeIdentityRecords.decodeSlot(Files.readAllBytes(backup)).equals(pending);
        assert store.load().slots.get(APP).value.equals(pending);
        assert store.updateExistingSlot(pending, retiring);
        assert store.load().slots.get(APP).value.equals(retiring);
        assert !Files.exists(backup);
        assert !store.updateExistingSlot(retiring, slot(3, List.of(new UserEntry(1, 0, 7, false))));

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
        assert store.updateExistingSlot(pending, retiring);
        assert store.load().slots.get(APP).value.equals(retiring);
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
        Files.delete(root.resolve("slots/10124/record.bin"));
        Files.delete(root.resolve("slots/10124"));

        // Filesystem aliases are refused, with a conservative negative hold.
        Path elsewhere = root.getParent().resolve("elsewhere"); Files.createDirectory(elsewhere);
        Files.createSymbolicLink(root.resolve("slots/10125"), elsewhere);
        assert store.load().occupiedAppIds.contains(10125);
        assert store.load().slots.get(10125).status == NativeIdentityStore.Status.DAMAGED;
        Files.delete(root.resolve("slots/10125"));

        Slot tombstone = slot(3, List.of());
        assert store.updateExistingSlot(retiring, tombstone);
        assert !store.load().bindingUsable(APP);
        assert !store.updateExistingSlot(tombstone, slot(4, List.of(new UserEntry(1, 0, 7, false))));
        Header releasing = new Header(LINEAGE, 1, List.of(entry(APP, SlotPhase.RELEASING)));
        assert store.writeHeader(live, releasing);
        Path foreign = file.getParent().resolve("not-store-owned");
        Files.writeString(foreign, "owner data control");
        assert !store.removeReleasingSlot(releasing, APP);
        assert Files.exists(foreign) && Files.exists(file);
        Files.delete(foreign);
        assert store.removeReleasingSlot(releasing, APP);
        assert store.removeReleasingSlot(releasing, APP); // Exact filesystem continuation.
        assert store.load().occupiedAppIds.equals(Set.of(APP)); // Index omission is separate.
        Header released = new Header(LINEAGE, 1, List.of());
        assert store.writeHeader(releasing, released);
        assert store.load().occupiedAppIds.isEmpty() && store.load().header.value.lastId == 1;
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
        // A known CREATING entry must first complete to LIVE, even if it was
        // already marked retiring. Omission there would strand a tombstone.
        NativeIdentityStore interrupted = new NativeIdentityStore(
                root.getParent().resolve("creating-retirement-case").toFile());
        assert interrupted.initializeNew(LINEAGE);
        assert interrupted.writeHeader(empty, creating);
        assert interrupted.ensureFreshSlot(creating, APP);
        assert interrupted.publishCreatingSlot(creating, pending);
        assert interrupted.updateExistingSlot(pending, retiring);
        assert !interrupted.updateExistingSlot(retiring, tombstone);
        assert interrupted.writeHeader(creating, live);
        assert interrupted.updateExistingSlot(retiring, tombstone);
        assert Os.allClosed();
        System.out.println("Native identity slot storage/recovery/retirement passed; Android unqualified");
    }
}
