// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import com.android.server.pm.NativeIdentityRecords.CreationBinding;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.HeaderEntry;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.SlotPhase;
import com.android.server.pm.NativeIdentityRecords.UserEntry;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.LinkOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/** The future codec is not permission for an old storage protocol to use its fields. */
public final class NativeIdentityVersionGateTest {
    private static final String LINEAGE = "a".repeat(32), PACKAGE = "dev.andrix.versiongate";
    private static final Set<String> SIGNERS = Set.of("b".repeat(64));
    private static final int A = 10123, B = 10124;
    private static Map<String, String> footprint(Path root) throws Exception {
        Map<String, String> result = new TreeMap<>();
        try (var paths = Files.walk(root)) {
            for (Path path : paths.toList()) {
                var attrs = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                result.put(root.relativize(path).toString(), attrs.fileKey() + ":" + attrs.lastModifiedTime()
                        + ":" + (attrs.isRegularFile() ? Base64.getEncoder().encodeToString(Files.readAllBytes(path)) : "directory"));
            }
        }
        return result;
    }
    private static void pair(Path path, byte[] bytes) throws Exception {
        Files.write(path, bytes); Files.write(Path.of(path + ".reservecopy"), bytes);
    }
    private static void heldOnly(NativeIdentityStore store) {
        NativeIdentityStore.Loaded loaded = store.load();
        assert loaded.header.status == NativeIdentityStore.Status.UNSUPPORTED : loaded.header.status;
        assert loaded.header.value == null && !loaded.header.decodedCopies.isEmpty();
        assert loaded.occupiedAppIds.equals(Set.of(A, B)) : loaded.occupiedAppIds;
        assert !loaded.creationReady() && loaded.creationBlocked;
        assert !loaded.bindingUsable(A) && !loaded.bindingUsable(B);
    }
    private static void isolated(Path parent, String kind) throws Exception {
        Path root = parent.resolve("isolated-" + kind);
        NativeIdentityStore store = new NativeIdentityStore(root.toFile());
        assert store.initializeNew(LINEAGE);
        Header empty = new Header(LINEAGE, 0, List.of());
        Path header = root.resolve("store.bin");
        Header selected;
        if (kind.equals("relabel")) {
            selected = new Header(LINEAGE, 1, List.of(new HeaderEntry(A, SlotPhase.CREATING, 1, PACKAGE)));
            assert store.writeHeader(empty, selected);
            Map<String, String> before = footprint(root);
            assert !store.writeHeader(selected, Header.newV2(LINEAGE, 1, selected.entries));
            assert footprint(root).equals(before);
        } else if (kind.equals("released")) {
            selected = Header.newV2(LINEAGE, 1, List.of());
            pair(header, NativeIdentityRecords.encodeHeader(selected));
            Map<String, String> before = footprint(root);
            assert !store.confirmReleasedSlot(selected, A);
            assert footprint(root).equals(before);
        } else if (kind.equals("removal")) {
            selected = Header.newV2(LINEAGE, 1, List.of(new HeaderEntry(A, SlotPhase.RELEASING, 0, "")));
            pair(header, NativeIdentityRecords.encodeHeader(selected));
            Path directory = Files.createDirectory(root.resolve("slots/" + A));
            pair(directory.resolve("record.bin"), NativeIdentityRecords.encodeSlot(new Slot(LINEAGE, A,
                    PACKAGE, 2, SIGNERS, List.of())));
            Map<String, String> before = footprint(root);
            assert !store.removeReleasingSlot(selected, A);
            assert footprint(root).equals(before);
        } else if (kind.equals("initialization") || kind.equals("mixed")) {
            Header future = Header.newV2(LINEAGE, 1, List.of(new HeaderEntry(B, SlotPhase.CREATING, 1,
                    PACKAGE, new CreationBinding(0, 7, SIGNERS))));
            pair(header, NativeIdentityRecords.encodeHeader(future));
            Files.write(root.resolve("store.bin-backup"), NativeIdentityRecords.encodeHeader(empty));
            Map<String, String> before = footprint(root);
            if (kind.equals("initialization")) assert !store.initializeNew(LINEAGE);
            else assert !store.writeHeader(empty, empty);
            assert footprint(root).equals(before);
            assert store.load().occupiedAppIds.equals(Set.of(B));
        } else throw new IllegalArgumentException("test case");
    }

    public static void main(String[] args) throws Exception {
        if (!NativeIdentityVersionGateTest.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        if (args.length == 2) { isolated(Path.of(args[0]), args[1]); return; }
        Path root = Path.of(args[0]).resolve("version-gate");
        NativeIdentityStore store = new NativeIdentityStore(root.toFile());
        assert store.initializeNew(LINEAGE);
        Header empty = new Header(LINEAGE, 0, List.of());
        Header legacy = new Header(LINEAGE, 1, List.of(new HeaderEntry(A, SlotPhase.CREATING, 1, PACKAGE)));
        assert store.writeHeader(empty, legacy);
        // A v1 header-only hold must remain known, even without a slot directory.
        assert store.load().header.status == NativeIdentityStore.Status.VALID;
        assert store.load().occupiedAppIds.equals(Set.of(A)) && !Files.exists(root.resolve("slots/" + A));
        Header v2 = Header.newV2(LINEAGE, 2, List.of(new HeaderEntry(A, SlotPhase.LIVE, 0, ""),
                new HeaderEntry(B, SlotPhase.CREATING, 2, PACKAGE + "other", new CreationBinding(0, 7, SIGNERS))));
        Map<String, String> before = footprint(root);
        assert !store.writeHeader(legacy, Header.newV2(LINEAGE, 1, legacy.entries));
        assert !store.writeHeader(legacy, v2); // Do not start a format migration in this writer.
        assert footprint(root).equals(before);
        Path header = root.resolve("store.bin"), reserve = root.resolve("store.bin.reservecopy"), backup = root.resolve("store.bin-backup");
        pair(header, NativeIdentityRecords.encodeHeader(v2));
        before = footprint(root); heldOnly(store); assert footprint(root).equals(before);
        // V2's header-only creation is retained although no directory could reveal B.
        assert !Files.exists(root.resolve("slots/" + B));
        Path slotDirectory = Files.createDirectory(root.resolve("slots/" + A));
        Slot a = new Slot(LINEAGE, A, PACKAGE, 1, SIGNERS, List.of(new UserEntry(1, 0, 7, false)));
        Slot retiring = new Slot(LINEAGE, A, PACKAGE, 2, SIGNERS, List.of(new UserEntry(1, 0, 7, true)));
        Slot b = new Slot(LINEAGE, B, PACKAGE + "other", 1, SIGNERS, List.of(new UserEntry(2, 0, 7, false)));
        pair(slotDirectory.resolve("record.bin"), NativeIdentityRecords.encodeSlot(a));
        heldOnly(store);
        assert store.load().slots.get(A).status == NativeIdentityStore.Status.VALID;
        before = footprint(root);
        assert !store.initializeNew(LINEAGE);
        assert !store.writeHeader(v2, v2) && !store.writeHeader(v2, legacy);
        assert !store.ensureFreshSlot(v2, B) && !store.resumeCreatingDirectory(v2, B);
        assert !store.publishCreatingSlot(v2, b) && !store.confirmExistingSlot(a);
        assert !store.updateExistingSlot(a, retiring);
        Header releasing = Header.newV2(LINEAGE, 2, List.of(new HeaderEntry(A, SlotPhase.RELEASING, 0, "")));
        assert !store.removeReleasingSlot(releasing, A) && !store.confirmReleasedSlot(Header.newV2(LINEAGE, 2, List.of()), A);
        assert footprint(root).equals(before);
        // A preferred or unselected copy cannot hide a recognized unsupported footprint.
        Files.write(backup, NativeIdentityRecords.encodeHeader(legacy));
        before = footprint(root); heldOnly(store);
        assert !store.writeHeader(legacy, legacy) && !store.confirmExistingSlot(a);
        assert !store.updateExistingSlot(a, retiring) && !store.ensureFreshSlot(legacy, A);
        assert !store.resumeCreatingDirectory(legacy, A) && !store.publishCreatingSlot(legacy, a);
        assert footprint(root).equals(before);
        pair(header, NativeIdentityRecords.encodeHeader(legacy));
        Files.write(backup, NativeIdentityRecords.encodeHeader(v2));
        before = footprint(root); heldOnly(store); assert footprint(root).equals(before);
        Files.delete(backup); Files.write(reserve, NativeIdentityRecords.encodeHeader(v2));
        before = footprint(root); heldOnly(store);
        assert !store.writeHeader(legacy, legacy) && !store.confirmExistingSlot(a);
        assert !store.updateExistingSlot(a, retiring) && !store.ensureFreshSlot(legacy, A);
        assert !store.resumeCreatingDirectory(legacy, A) && !store.publishCreatingSlot(legacy, a);
        assert footprint(root).equals(before);
        // The incomplete-layout early return also keeps all decoded header holds.
        Files.delete(slotDirectory.resolve("record.bin")); Files.delete(slotDirectory.resolve("record.bin.reservecopy"));
        Files.delete(slotDirectory); Files.delete(root.resolve("slots"));
        before = footprint(root); heldOnly(store); assert footprint(root).equals(before);
        assert !store.load().enumerationComplete;
        for (String kind : List.of("relabel", "released", "removal", "initialization", "mixed")) {
            isolated(Path.of(args[0]), kind);
        }
        System.out.println("Version 2 hold-only refusal and unchanged version 1 compatibility passed; Android unqualified");
    }
}
