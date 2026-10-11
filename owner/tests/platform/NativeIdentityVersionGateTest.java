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
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.Arrays;
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
        assert loaded.unsupportedFootprint;
        assert loaded.header.value == null && !loaded.header.decodedCopies.isEmpty();
        assert loaded.occupiedAppIds.equals(Set.of(A, B)) : loaded.occupiedAppIds;
        assert !loaded.creationReady() && loaded.creationBlocked;
        assert !loaded.bindingUsable(A) && !loaded.bindingUsable(B);
    }
    private static void isolated(Path parent, String kind) throws Exception {
        Path root = parent.resolve("isolated-" + kind);
        NativeIdentityStore store = new NativeIdentityStore(root.toFile(), NativeIdentityStore.Format.V1);
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

    // The earlier formats' refusal of every lifecycle write, the control that keeps the gate rows from
    // masking it. Each layout is healthy under the format and takes a write no format refuses, a
    // generation step or a header retry, after the refusal. The retiring flag, the user drop, the
    // RELEASING and omission header writes, the removal and the released confirmation each refuse
    // before any effect, with every byte, file identity and time, every hold, every binding and the
    // creation counter unchanged. So the version 2 header rows show only the gate for the writes the
    // earlier formats still take, and for the release primitives under Format.V1 they repeat this
    // refusal: the lifecycle format's gate is lifecycleGate's.
    private static void formatRefusals(Path parent, NativeIdentityStore.Format format) throws Exception {
        boolean v2 = format == NativeIdentityStore.Format.V2;
        HeaderEntry liveA = new HeaderEntry(A, SlotPhase.LIVE, 0, ""), releasingA = new HeaderEntry(A, SlotPhase.RELEASING, 0, "");
        Slot a = new Slot(LINEAGE, A, PACKAGE, 1, SIGNERS, List.of(new UserEntry(1, 0, 7, false)));
        Slot touched = new Slot(LINEAGE, A, PACKAGE, 2, SIGNERS, a.users);
        Slot retiring = new Slot(LINEAGE, A, PACKAGE, 2, SIGNERS, List.of(new UserEntry(1, 0, 7, true)));
        Slot tombstone = new Slot(LINEAGE, A, PACKAGE, 3, SIGNERS, List.of());
        for (String kind : List.of("retiring flag", "user drop", "release marker", "omission", "removal",
                "released confirmation")) {
            Header live = v2 ? Header.newV2(LINEAGE, 1, List.of(liveA)) : new Header(LINEAGE, 1, List.of(liveA));
            Header releasing = v2 ? Header.newV2(LINEAGE, 1, List.of(releasingA))
                    : new Header(LINEAGE, 1, List.of(releasingA));
            Header released = v2 ? Header.newV2(LINEAGE, 1, List.of()) : new Header(LINEAGE, 1, List.of());
            Header selected = switch (kind) {
                case "retiring flag", "user drop", "release marker" -> live;
                case "omission", "removal" -> releasing;
                default -> released;
            };
            Slot body = switch (kind) {
                case "retiring flag" -> a;
                case "user drop" -> retiring;
                case "release marker", "removal" -> tombstone;
                default -> null;
            };
            Path root = parent.resolve("format-refusal-" + format + "-" + kind.replace(' ', '-'));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            assert store.initializeNew(LINEAGE) : kind;
            pair(root.resolve("store.bin"), NativeIdentityRecords.encodeHeader(selected));
            if (body != null) {
                pair(Files.createDirectory(root.resolve("slots/" + A)).resolve("record.bin"),
                        NativeIdentityRecords.encodeSlot(body));
            }
            NativeIdentityStore.Loaded healthy = store.load();
            assert healthy.header.status == NativeIdentityStore.Status.VALID && !healthy.unsupportedFootprint
                    && healthy.enumerationComplete && healthy.creationReady() : format + " " + kind;
            Map<String, String> before = footprint(root);
            boolean written = switch (kind) {
                case "retiring flag" -> store.updateExistingSlot(a, retiring);
                case "user drop" -> store.updateExistingSlot(retiring, tombstone);
                case "release marker" -> store.writeHeader(live, releasing);
                case "omission" -> store.writeHeader(releasing, released);
                case "removal" -> store.removeReleasingSlot(releasing, A);
                default -> store.confirmReleasedSlot(released, A);
            };
            NativeIdentityStore.Loaded after = store.load();
            assert !written && footprint(root).equals(before) : format + " " + kind;
            assert after.occupiedAppIds.equals(healthy.occupiedAppIds) && after.creationReady()
                    && after.bindingUsable(A) == healthy.bindingUsable(A)
                    && after.header.value.equals(selected) : format + " " + kind;
            boolean control = kind.equals("retiring flag") ? store.updateExistingSlot(a, touched)
                    : store.writeHeader(selected, selected);
            assert control : "the healthy layout refused a write the format takes: " + format + " " + kind;
        }
        System.out.println("PASS " + format + " / every lifecycle write refused on a healthy layout");
    }

    // The same bytes under another declared version, still an intact frame.
    private static byte[] relabeled(byte[] record, int version) throws Exception {
        byte[] bytes = record.clone();
        bytes[6] = (byte) version; bytes[7] = (byte) (version >>> 8);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(Arrays.copyOf(bytes, bytes.length - 32));
        System.arraycopy(digest, 0, bytes, bytes.length - 32, 32);
        return bytes;
    }

    // The lifecycle format's arm of the release primitive rows: under Format.V3 a header above its
    // header ceiling is an unsupported footprint, and the release engine's primitives refuse beside
    // it before any effect, as the version 1 writers refuse beside a version 2 header. A slot
    // directory that cannot be searched refuses the removal there too.
    private static void lifecycleGate(Path parent) throws Exception {
        Slot ticketed = new Slot(LINEAGE, A, PACKAGE, 2, SIGNERS, List.of(),
                new NativeIdentityRecords.ReleaseTicket(1, 0, 7, "7".repeat(32)));
        Header released = Header.newV2(LINEAGE, 1, List.of());
        Header releasing = Header.newV2(LINEAGE, 1, List.of(new HeaderEntry(A, SlotPhase.RELEASING, 0, "")));
        Header live = Header.newV2(LINEAGE, 1, List.of(new HeaderEntry(A, SlotPhase.LIVE, 0, "")));
        for (String kind : List.of("released", "removal", "omission", "release marker")) {
            Path root = parent.resolve("lifecycle-gate-" + kind.replace(' ', '-'));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), NativeIdentityStore.Format.V3);
            assert store.initializeNew(LINEAGE);
            Header selected = kind.equals("released") ? released : kind.equals("release marker") ? live : releasing;
            pair(root.resolve("store.bin"), relabeled(NativeIdentityRecords.encodeHeader(selected), 3));
            if (!kind.equals("released") && !kind.equals("omission")) {
                Path directory = Files.createDirectory(root.resolve("slots/" + A));
                pair(directory.resolve("record.bin"), NativeIdentityRecords.encodeSlot(ticketed));
            }
            assert store.load().header.status == NativeIdentityStore.Status.UNSUPPORTED : kind;
            Map<String, String> before = footprint(root);
            boolean written = switch (kind) {
                case "released" -> store.confirmReleasedSlot(selected, A);
                case "removal" -> store.removeReleasingSlot(selected, A);
                case "omission" -> store.omitReleasedSlot(selected, A);
                default -> store.markSlotReleasing(selected, A);
            };
            assert !written && footprint(root).equals(before) : kind;
        }
        // The availability guard: an unsearchable slot directory refuses the removal before any effect.
        Path root = parent.resolve("lifecycle-gate-unsearchable");
        NativeIdentityStore store = new NativeIdentityStore(root.toFile(), NativeIdentityStore.Format.V3);
        assert store.initializeNew(LINEAGE);
        pair(root.resolve("store.bin"), NativeIdentityRecords.encodeHeader(releasing));
        Path directory = Files.createDirectory(root.resolve("slots/" + A));
        pair(directory.resolve("record.bin"), NativeIdentityRecords.encodeSlot(ticketed));
        Map<String, String> before = footprint(root);
        Path slots = root.resolve("slots");
        Files.setPosixFilePermissions(slots, PosixFilePermissions.fromString("--x------"));
        boolean removed;
        try {
            removed = store.removeReleasingSlot(releasing, A);
        } finally {
            Files.setPosixFilePermissions(slots, PosixFilePermissions.fromString("rwx------"));
        }
        assert !removed && footprint(root).equals(before);
        // With the directory searchable again, the same removal goes ahead: the guard, not the
        // setup, refused it.
        assert store.removeReleasingSlot(releasing, A) && !Files.exists(directory);
    }

    // Store availability is reported apart from each slot's binding eligibility. A seed or an
    // unrelated slot withholds writes and creation, not A's intact binding. A user limit or a
    // bad checksum is not a format footprint.
    private static void availability(Path parent) throws Exception {
        Header live = new Header(LINEAGE, 2, List.of(new HeaderEntry(A, SlotPhase.LIVE, 0, ""),
                new HeaderEntry(B, SlotPhase.LIVE, 0, "")));
        Slot a = new Slot(LINEAGE, A, PACKAGE, 1, SIGNERS, List.of(new UserEntry(1, 0, 7, false)));
        Slot b = new Slot(LINEAGE, B, PACKAGE + "other", 1, SIGNERS, List.of(new UserEntry(2, 0, 7, false)));
        byte[] headerBytes = NativeIdentityRecords.encodeHeader(live);
        String[] kinds = {"healthy", "header copy", "header seed", "slot seed", "unrelated slot",
                "bad checksum", "user limit", "incomplete layout"};
        for (String kind : kinds) {
            Path root = parent.resolve("availability-" + kind.replace(' ', '-'));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), NativeIdentityStore.Format.V1);
            assert store.initializeNew(LINEAGE);
            pair(root.resolve("store.bin"), headerBytes);
            Path slotA = Files.createDirectory(root.resolve("slots/" + A)).resolve("record.bin");
            Path slotB = Files.createDirectory(root.resolve("slots/" + B)).resolve("record.bin");
            pair(slotA, NativeIdentityRecords.encodeSlot(a));
            pair(slotB, NativeIdentityRecords.encodeSlot(b));
            boolean flagged = true, usableA = true, usableB = true;
            if (kind.equals("healthy")) {
                flagged = false;
            } else if (kind.equals("header copy")) {
                Files.write(root.resolve("store.bin.reservecopy"), relabeled(headerBytes, 3));
                usableA = usableB = false;
            } else if (kind.equals("header seed")) {
                Files.write(root.resolve("store.bin-seed"), relabeled(headerBytes, 3));
            } else if (kind.equals("slot seed")) {
                Files.write(Path.of(slotA + "-seed"), relabeled(NativeIdentityRecords.encodeSlot(a), 2));
            } else if (kind.equals("unrelated slot")) {
                Files.write(slotB, relabeled(NativeIdentityRecords.encodeSlot(b), 2));
                usableB = false;
            } else if (kind.equals("bad checksum")) {
                byte[] damaged = relabeled(headerBytes, 3);
                damaged[damaged.length - 1] ^= 1;
                Files.write(root.resolve("store.bin.reservecopy"), damaged);
                flagged = false;
            } else if (kind.equals("user limit")) {
                pair(slotB, NativeIdentityRecords.encodeSlot(new Slot(LINEAGE, B, PACKAGE + "other", 1,
                        SIGNERS, List.of(new UserEntry(2, 10, 7, false)))));
                flagged = usableB = false;
            } else {
                Files.write(root.resolve("store.bin-seed"), relabeled(headerBytes, 3));
                for (Path file : List.of(slotA, slotB)) {
                    Files.delete(file); Files.delete(Path.of(file + ".reservecopy")); Files.delete(file.getParent());
                }
                Files.delete(root.resolve("slots"));
                usableA = usableB = false;
            }
            Map<String, String> before = footprint(root);
            NativeIdentityStore.Loaded loaded = store.load();
            assert loaded.unsupportedFootprint == flagged : kind;
            assert loaded.creationReady() == !flagged && loaded.creationBlocked == flagged : kind;
            assert loaded.bindingUsable(A) == usableA && loaded.bindingUsable(B) == usableB : kind;
            assert loaded.occupiedAppIds.equals(Set.of(A, B)) : kind;
            assert loaded.enumerationComplete == !kind.equals("incomplete layout") : kind;
            if (flagged) {
                assert !store.confirmExistingSlot(a) && !store.writeHeader(live, live) : kind;
                assert footprint(root).equals(before) : kind;
            } else {
                assert store.confirmExistingSlot(a) && store.writeHeader(live, live) : kind;
            }
        }
        // A slot namespace that cannot be listed: the flag survives the incomplete view, and a
        // writer refuses before header confirmation, including a footprint in
        // another slot. This qualification requires real unprivileged DAC refusal. Under Format.V1
        // the removal also refuses as a lifecycle write (formatRefusals), so the header retry, which
        // the format takes, keeps the guard's own refusal in view.
        Header releasing = new Header(LINEAGE, 1, List.of(new HeaderEntry(A, SlotPhase.RELEASING, 0, "")));
        Slot tombstone = new Slot(LINEAGE, A, PACKAGE, 2, SIGNERS, List.of());
        for (String kind : List.of("header seed", "target seed", "other seed")) {
            Path root = parent.resolve("unlistable-" + kind.replace(' ', '-'));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), NativeIdentityStore.Format.V1);
            assert store.initializeNew(LINEAGE);
            pair(root.resolve("store.bin"), NativeIdentityRecords.encodeHeader(releasing));
            Path slotA = Files.createDirectory(root.resolve("slots/" + A)).resolve("record.bin");
            pair(slotA, NativeIdentityRecords.encodeSlot(tombstone));
            Path newer = kind.equals("header seed") ? root.resolve("store.bin-seed") : Path.of(slotA + "-seed");
            if (kind.equals("other seed")) {
                Path other = Files.createDirectory(root.resolve("slots/" + B));
                newer = other.resolve("record.bin-seed");
            }
            Files.write(newer, kind.equals("header seed")
                    ? relabeled(NativeIdentityRecords.encodeHeader(releasing), 3)
                    : relabeled(NativeIdentityRecords.encodeSlot(tombstone), 2));
            Map<String, String> before = footprint(root);
            Path slots = root.resolve("slots");
            Files.setPosixFilePermissions(slots, PosixFilePermissions.fromString("--x------"));
            NativeIdentityStore.Loaded loaded;
            boolean removed, retried;
            try {
                loaded = store.load();
                removed = store.removeReleasingSlot(releasing, A);
                retried = store.writeHeader(releasing, releasing);
            } finally {
                Files.setPosixFilePermissions(slots, PosixFilePermissions.fromString("rwx------"));
            }
            assert !removed && !retried && footprint(root).equals(before) : kind;
            assert !loaded.enumerationComplete : "unlistable control requires unprivileged DAC: " + kind;
            // Without a listing only the header's own seed is visible to load().
            assert loaded.unsupportedFootprint == kind.equals("header seed") : kind;
            assert loaded.occupiedAppIds.contains(A) && !loaded.creationReady() : kind;
        }

        System.out.println("Unlistable namespace DAC control exercised for header, target and unrelated seed");
        NativeIdentityStore.Loaded synthetic = new NativeIdentityStore.Loaded(
                new NativeIdentityStore.ReadResult<>(NativeIdentityStore.Status.VALID, live, List.of(live)),
                Map.of(), Set.of(), false, true);
        assert !synthetic.unsupportedFootprint && !synthetic.creationBlocked;
        NativeIdentityStore.Loaded flagged = new NativeIdentityStore.Loaded(synthetic.header,
                Map.of(), Set.of(), false, true, true);
        assert flagged.unsupportedFootprint && flagged.creationBlocked && !flagged.creationReady();
    }

    public static void main(String[] args) throws Exception {
        if (!NativeIdentityVersionGateTest.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        if (args.length == 2 && args[1].equals("V3")) {
            // The lifecycle format's arm: its own entry point, run as its own step under its own label.
            lifecycleGate(Path.of(args[0]));
            System.out.println("Lifecycle format refusal of the release primitives beside a later header and an"
                    + " unsearchable slot directory passed; Android unqualified");
            return;
        }
        if (args.length == 2 && args[1].equals("V2")) {
            // The production format's refusal controls: their own entry point, run under their own label.
            formatRefusals(Path.of(args[0]), NativeIdentityStore.Format.V2);
            return;
        }
        if (args.length == 2) { isolated(Path.of(args[0]), args[1]); return; }
        Path root = Path.of(args[0]).resolve("version-gate");
        NativeIdentityStore store = new NativeIdentityStore(root.toFile(), NativeIdentityStore.Format.V1);
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
        // The gate rows' slot update is a generation step, which the earlier formats take; the retiring
        // flag is a lifecycle write, refused by the format itself (formatRefusals).
        Slot touched = new Slot(LINEAGE, A, PACKAGE, 2, SIGNERS, List.of(new UserEntry(1, 0, 7, false)));
        Slot b = new Slot(LINEAGE, B, PACKAGE + "other", 1, SIGNERS, List.of(new UserEntry(2, 0, 7, false)));
        pair(slotDirectory.resolve("record.bin"), NativeIdentityRecords.encodeSlot(a));
        heldOnly(store);
        assert store.load().slots.get(A).status == NativeIdentityStore.Status.VALID;
        before = footprint(root);
        assert !store.initializeNew(LINEAGE);
        assert !store.writeHeader(v2, v2) && !store.writeHeader(v2, legacy);
        assert !store.ensureFreshSlot(v2, B) && !store.resumeCreatingDirectory(v2, B);
        assert !store.publishCreatingSlot(v2, b) && !store.confirmExistingSlot(a);
        assert !store.updateExistingSlot(a, touched);
        Header releasing = Header.newV2(LINEAGE, 2, List.of(new HeaderEntry(A, SlotPhase.RELEASING, 0, "")));
        assert !store.removeReleasingSlot(releasing, A) && !store.confirmReleasedSlot(Header.newV2(LINEAGE, 2, List.of()), A);
        assert footprint(root).equals(before);
        // A preferred or unselected copy cannot hide a recognized unsupported footprint.
        Files.write(backup, NativeIdentityRecords.encodeHeader(legacy));
        before = footprint(root); heldOnly(store);
        assert !store.writeHeader(legacy, legacy) && !store.confirmExistingSlot(a);
        assert !store.updateExistingSlot(a, touched) && !store.ensureFreshSlot(legacy, A);
        assert !store.resumeCreatingDirectory(legacy, A) && !store.publishCreatingSlot(legacy, a);
        assert footprint(root).equals(before);
        pair(header, NativeIdentityRecords.encodeHeader(legacy));
        Files.write(backup, NativeIdentityRecords.encodeHeader(v2));
        before = footprint(root); heldOnly(store); assert footprint(root).equals(before);
        Files.delete(backup); Files.write(reserve, NativeIdentityRecords.encodeHeader(v2));
        before = footprint(root); heldOnly(store);
        assert !store.writeHeader(legacy, legacy) && !store.confirmExistingSlot(a);
        assert !store.updateExistingSlot(a, touched) && !store.ensureFreshSlot(legacy, A);
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
        formatRefusals(Path.of(args[0]), NativeIdentityStore.Format.V1);
        availability(Path.of(args[0]));
        System.out.println("Version 2 hold-only refusal and unchanged version 1 compatibility passed; Android unqualified");
    }
}
