// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import android.system.Os;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.HeaderEntry;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.SlotPhase;
import com.android.server.pm.NativeIdentityRecords.UserEntry;
import com.android.server.pm.NativeIdentityStore.Status;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Intact records of versions this store does not write, beside healthy version 1 state. Each
 * case isolates one otherwise valid writer call in a fresh store. Its healthy state succeeds.
 * An intact newer frame in one main, reserve, backup or staging seed refuses that call before
 * any effect: the bytes, file identities and every hold stay. The same frame with a bad
 * checksum stays ordinary damage: load() reports it as it reports garbage there, and the
 * writer does what it does over such damage. Slot frames here are above version 2, the newest
 * the codec decodes. Such a copy whose stable prefix is valid gives that prefix's package and
 * principal as negative evidence only, and a broken prefix gives none: either way the frame
 * stays an unsupported footprint. A staging seed gives no evidence. Only store and codec
 * surface which predates the gate is used for writes. Host facades only, not Android
 * persistence, UID authority or a format migration.
 */
public final class NativeIdentityFutureFormatTest {
    private static final String LINEAGE = "c".repeat(32);
    private static final Set<String> SIGNERS = Set.of("d".repeat(64));
    // HIDDEN and PKG_HIDDEN appear only inside bodies no reader may decode. PKG_HIDDEN and
    // principal 9 are also the stable prefix of later slot frames: negative evidence only.
    private static final int A = 10123, B = 10124, C = 10200, HIDDEN = 10300, KNOWN_V2 = 10301;
    private static final String PKG_A = "dev.andrix.futurea", PKG_B = "dev.andrix.futureb",
            PKG_C = "dev.andrix.futurec", PKG_HIDDEN = "dev.andrix.hidden";
    private static final int MAGIC = 0x44495841, TYPE_HEADER = 1, TYPE_SLOT = 2, CHECKSUM = 32;
    private static final int MAX_BYTES = NativeIdentityRecords.MAX_BYTES;
    private static final byte[] GARBAGE = {1, 2, 3};
    private static final byte[] EXTENSION = {0x33, 0x33, 0x33, 0x33};
    private static final Slot SLOT_A = bound(A, PKG_A, 1, false, 1);
    private static final Slot RETIRING_A = bound(A, PKG_A, 1, true, 2);
    // The version 1 rows' slot update: a generation step without a lifecycle change. The retiring
    // flag is a lifecycle write, which the earlier formats refuse before any effect.
    private static final Slot TOUCHED_A = bound(A, PKG_A, 1, false, 2);
    private static final Slot SLOT_B = bound(B, PKG_B, 2, false, 1);
    private static final Slot TOMBSTONE_B = new Slot(LINEAGE, B, PKG_B, 3, SIGNERS, List.of());
    private static final Slot SLOT_C = bound(C, PKG_C, 3, false, 1);
    private static final Slot TOMBSTONE_C = new Slot(LINEAGE, C, PKG_C, 3, SIGNERS, List.of());

    private enum At { MAIN, RESERVE, BACKUP, SEED }

    private interface Action { boolean run(NativeIdentityStore store) throws Exception; }
    private interface Body { void run(List<String> problems) throws Exception; }

    private static final List<String> failures = new ArrayList<>();
    private static int passed, directories;
    // The format of every store the matrix opens: Format.V1, or Format.V3 for the lifecycle rows.
    private static NativeIdentityStore.Format matrixFormat = NativeIdentityStore.Format.V1;

    private static Slot bound(int appId, String name, long id, boolean retiring, long generation) {
        return new Slot(LINEAGE, appId, name, generation, SIGNERS,
                List.of(new UserEntry(id, 0, 7, retiring)));
    }
    private static HeaderEntry live(int appId) { return new HeaderEntry(appId, SlotPhase.LIVE, 0, ""); }
    private static HeaderEntry releasing(int appId) {
        return new HeaderEntry(appId, SlotPhase.RELEASING, 0, "");
    }
    private static HeaderEntry creating(int appId, long id, String name) {
        return new HeaderEntry(appId, SlotPhase.CREATING, id, name);
    }
    private static Header header(long lastId, HeaderEntry... entries) {
        return new Header(LINEAGE, lastId, List.of(entries));
    }

    // Little endian, as the record format.
    private static byte[] put(byte[] bytes, int at, int width, long value) {
        for (int i = 0; i < width; i++) bytes[at + i] = (byte) (value >>> (8 * i));
        return bytes;
    }
    private static byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }
    private static byte[] sealed(byte[] unsealed) throws Exception {
        return concat(unsealed, MessageDigest.getInstance("SHA-256").digest(unsealed));
    }
    // An intact frame, whatever it declares: magic, type, version and exact length, the body,
    // then the SHA-256 of all of it.
    private static byte[] frame(int magic, int type, int version, byte[] body) throws Exception {
        byte[] unsealed = new byte[12 + body.length];
        put(unsealed, 0, 4, magic);
        put(unsealed, 4, 2, type);
        put(unsealed, 6, 2, version);
        put(unsealed, 8, 4, unsealed.length + CHECKSUM);
        System.arraycopy(body, 0, unsealed, 12, body.length);
        return sealed(unsealed);
    }
    private static byte[] frame(int type, int version, byte[] body) throws Exception {
        return frame(MAGIC, type, version, body);
    }
    private static byte[] body(byte[] record) {
        return Arrays.copyOfRange(record, 12, record.length - CHECKSUM);
    }
    // A body which a version 1 parser would read as a hold of HIDDEN. Version 2 reads its
    // CREATING entry as missing its binding tag.
    private static byte[] headerBody() {
        return body(NativeIdentityRecords.encodeHeader(header(7, live(A),
                creating(HIDDEN, 7, PKG_HIDDEN))));
    }
    private static byte[] slotBody(int appId) {
        return body(NativeIdentityRecords.encodeSlot(bound(appId, PKG_HIDDEN, 9, true, 5)));
    }
    // Intact frames this protocol does not write, rotated over the cases and positions. A slot
    // frame is above version 2: a version 3 frame whose prefix breaks off in its package name, or
    // a version 3 or 65535 frame of a relabeled one user version 1 body with an extension, whose
    // stable prefix is valid.
    private static byte[] future(Integer target, int variant) throws Exception {
        if (target == null) {
            switch (variant % 3) {
                // The lifecycle format reads version 2 headers, so its first later header is version 3.
                case 0: return matrixFormat.headerCeiling >= 2 ? frame(TYPE_HEADER, 3, headerBody())
                        : frame(TYPE_HEADER, 2, headerBody());
                case 1: return frame(TYPE_HEADER, 3, concat(headerBody(), EXTENSION));
                default: return frame(TYPE_HEADER, 0xffff, concat(headerBody(), EXTENSION));
            }
        }
        switch (variant % 3) {
            case 0: return frame(TYPE_SLOT, 3, Arrays.copyOf(slotBody(target), 40));
            case 1: return frame(TYPE_SLOT, 3, concat(slotBody(target), EXTENSION));
            default: return frame(TYPE_SLOT, 0xffff, concat(slotBody(target), EXTENSION));
        }
    }
    // The negative evidence such a frame gives as a copy: its valid prefix's package, or nothing.
    private static Set<String> evidence(Integer target, int variant) {
        return target != null && variant % 3 != 0 ? Set.of(PKG_HIDDEN) : Set.of();
    }

    // A store as its own writers leave it: main and reserve of the header and of each slot, a
    // body only in main, or an empty directory before a creation publishes its body. The files
    // are written directly, without the writers' syncs, to keep the matrix light on real disks.
    // Readers do not depend on how a layout was made; initializeNew has its own cases.
    private static final class Layout {
        final byte[] header;
        final Map<Integer, Slot> bodies = new TreeMap<>();
        final Map<Integer, Slot> sole = new TreeMap<>();
        final Set<Integer> empty = new TreeSet<>();
        Layout(Header header) { this(NativeIdentityRecords.encodeHeader(header)); }
        Layout(byte[] header) { this.header = header; }
        Layout slot(int appId, Slot body) { bodies.put(appId, body); return this; }
        Layout sole(int appId, Slot body) { sole.put(appId, body); return this; }
        Layout empty(int appId) { empty.add(appId); return this; }
        Path build(Path root) throws Exception {
            Files.createDirectories(root.resolve("slots"));
            pair(root.resolve("store.bin"), header);
            for (Map.Entry<Integer, Slot> body : bodies.entrySet()) {
                Path directory = Files.createDirectory(root.resolve("slots/" + body.getKey()));
                pair(directory.resolve("record.bin"), NativeIdentityRecords.encodeSlot(body.getValue()));
            }
            for (Map.Entry<Integer, Slot> body : sole.entrySet()) {
                Path directory = Files.createDirectory(root.resolve("slots/" + body.getKey()));
                Files.write(directory.resolve("record.bin"), NativeIdentityRecords.encodeSlot(body.getValue()));
            }
            for (int appId : empty) Files.createDirectory(root.resolve("slots/" + appId));
            return root;
        }
    }

    // One otherwise valid writer call. A null target is the header record.
    private static final class Case {
        final String name;
        final Layout layout;
        final Integer target;
        final Action action;
        Case(String name, Layout layout, Integer target, Action action) {
            this.name = name;
            this.layout = layout;
            this.target = target;
            this.action = action;
        }
    }

    // What load() reports before a writer runs, and that writer's result.
    private static final class Seen {
        final Status header, target;
        final boolean creationReady;
        final Set<Integer> occupied = new TreeSet<>(), usable = new TreeSet<>();
        // Package names that stable prefixes of later slot frames give, in any record.
        final Set<String> evidence = new TreeSet<>();
        final boolean invented;
        Boolean result;
        Seen(NativeIdentityStore.Loaded loaded, Integer target) {
            header = loaded.header.status;
            NativeIdentityStore.ReadResult<Slot> slot = target == null ? null : loaded.slots.get(target);
            this.target = slot == null ? null : slot.status;
            creationReady = loaded.creationReady();
            occupied.addAll(loaded.occupiedAppIds);
            for (int appId : List.of(A, B, C)) if (loaded.bindingUsable(appId)) usable.add(appId);
            boolean found = false;
            for (Header copy : loaded.header.decodedCopies) {
                for (HeaderEntry entry : copy.entries) found |= entry.appId == HIDDEN;
            }
            for (NativeIdentityStore.ReadResult<Slot> copies : loaded.slots.values()) {
                for (Slot copy : copies.decodedCopies) found |= copy.packageName.equals(PKG_HIDDEN);
                for (NativeIdentityRecords.SlotPrefix prefix : copies.prefixes) {
                    evidence.add(prefix.packageName);
                }
            }
            invented = found || occupied.contains(HIDDEN);
        }
        String view() {
            return "header=" + header + " slot=" + target + " ready=" + creationReady + " holds="
                    + occupied + " usable=" + usable + " evidence=" + evidence;
        }
        @Override public String toString() {
            return view() + " result=" + result;
        }
    }

    private static List<Case> cases() {
        Header liveA = header(1, live(A));
        Header creatingB = header(2, live(A), creating(B, 2, PKG_B));
        Header liveAB = header(2, live(A), live(B));
        Header creatingC = header(3, live(A), live(B), creating(C, 3, PKG_C));
        List<Case> cases = new ArrayList<>();
        // The header record's copies and staging seed, beside the expected version 1 header,
        // under each writer. Slot writers are included: the header is the store's index.
        cases.add(new Case("header retry", new Layout(liveA).slot(A, SLOT_A), null,
                store -> store.writeHeader(liveA, liveA)));
        cases.add(new Case("header creation", new Layout(liveA).slot(A, SLOT_A), null,
                store -> store.writeHeader(liveA, creatingB)));
        cases.add(new Case("header completion", new Layout(creatingB).slot(A, SLOT_A)
                .slot(B, SLOT_B), null, store -> store.writeHeader(creatingB, liveAB)));
        cases.add(new Case("header fresh directory", new Layout(creatingB).slot(A, SLOT_A), null,
                store -> store.ensureFreshSlot(creatingB, B)));
        cases.add(new Case("header resume", new Layout(creatingB).slot(A, SLOT_A).empty(B), null,
                store -> store.resumeCreatingDirectory(creatingB, B)));
        cases.add(new Case("header publish", new Layout(creatingB).slot(A, SLOT_A).empty(B), null,
                store -> store.publishCreatingSlot(creatingB, SLOT_B)));
        cases.add(new Case("header update", new Layout(liveA).slot(A, SLOT_A), null,
                store -> store.updateExistingSlot(SLOT_A, TOUCHED_A)));
        cases.add(new Case("header confirm", new Layout(liveA).slot(A, SLOT_A), null,
                store -> store.confirmExistingSlot(SLOT_A)));
        cases.add(new Case("header initialization", new Layout(header(0)), null,
                store -> store.initializeNew(LINEAGE)));
        // One slot record's copies and staging seed, under each writer of that slot. An
        // unreadable header leaves only the exact existing binding writers.
        cases.add(new Case("slot update", new Layout(liveA).slot(A, SLOT_A), A,
                store -> store.updateExistingSlot(SLOT_A, TOUCHED_A)));
        cases.add(new Case("slot confirm", new Layout(liveA).slot(A, SLOT_A), A,
                store -> store.confirmExistingSlot(SLOT_A)));
        cases.add(new Case("slot unknown counter update", new Layout(GARBAGE).slot(A, SLOT_A), A,
                store -> store.updateExistingSlot(SLOT_A, TOUCHED_A)));
        cases.add(new Case("slot unknown counter confirm", new Layout(GARBAGE).slot(A, SLOT_A), A,
                store -> store.confirmExistingSlot(SLOT_A)));
        cases.add(new Case("slot completion", new Layout(creatingB).slot(A, SLOT_A)
                .slot(B, SLOT_B), B, store -> store.writeHeader(creatingB, liveAB)));
        cases.add(new Case("slot resume", new Layout(creatingB).slot(A, SLOT_A).empty(B), B,
                store -> store.resumeCreatingDirectory(creatingB, B)));
        cases.add(new Case("slot resume retry", new Layout(creatingB).slot(A, SLOT_A)
                .slot(B, SLOT_B), B, store -> store.resumeCreatingDirectory(creatingB, B)));
        cases.add(new Case("slot publish", new Layout(creatingB).slot(A, SLOT_A).empty(B), B,
                store -> store.publishCreatingSlot(creatingB, SLOT_B)));
        cases.add(new Case("slot publish retry", new Layout(creatingB).slot(A, SLOT_A)
                .slot(B, SLOT_B), B, store -> store.publishCreatingSlot(creatingB, SLOT_B)));
        // Store availability: a footprint in unrelated slot B refuses every other writer too.
        cases.add(new Case("unrelated update", new Layout(liveAB).slot(A, SLOT_A).slot(B, SLOT_B),
                B, store -> store.updateExistingSlot(SLOT_A, TOUCHED_A)));
        cases.add(new Case("unrelated confirm", new Layout(liveAB).slot(A, SLOT_A).slot(B, SLOT_B),
                B, store -> store.confirmExistingSlot(SLOT_A)));
        cases.add(new Case("unrelated header retry", new Layout(liveAB).slot(A, SLOT_A)
                .slot(B, SLOT_B), B, store -> store.writeHeader(liveAB, liveAB)));
        cases.add(new Case("unrelated creation", new Layout(liveAB).slot(A, SLOT_A)
                .slot(B, SLOT_B), B, store -> store.writeHeader(liveAB, creatingC)));
        cases.add(new Case("unrelated fresh directory", new Layout(creatingC).slot(A, SLOT_A)
                .slot(B, SLOT_B), B, store -> store.ensureFreshSlot(creatingC, C)));
        cases.add(new Case("unrelated resume", new Layout(creatingC).slot(A, SLOT_A)
                .slot(B, SLOT_B).empty(C), B, store -> store.resumeCreatingDirectory(creatingC, C)));
        cases.add(new Case("unrelated publish", new Layout(creatingC).slot(A, SLOT_A)
                .slot(B, SLOT_B).empty(C), B, store -> store.publishCreatingSlot(creatingC, SLOT_C)));
        return cases;
    }

    // The version 1 rows of the release steps, RELEASING, the omission, the removal and the released
    // confirmation: lifecycle writes, which the earlier formats refuse before any effect on a healthy
    // layout. The lifecycle entry point runs them through the release engine's primitives beside
    // every later frame.
    private static List<Case> releaseCases() {
        Header liveAB = header(2, live(A), live(B));
        Header releasingB = header(2, live(A), releasing(B));
        Header releasedB = header(2, live(A));
        Header lastReleasing = header(2, releasing(B));
        Header releasingC = header(3, live(A), live(B), releasing(C));
        Header releasedC = header(3, live(A), live(B));
        List<Case> cases = new ArrayList<>();
        cases.add(new Case("header release marker", new Layout(liveAB).slot(A, SLOT_A)
                .slot(B, TOMBSTONE_B), null, store -> store.writeHeader(liveAB, releasingB)));
        cases.add(new Case("header omission", new Layout(releasingB).slot(A, SLOT_A), null,
                store -> store.writeHeader(releasingB, releasedB)));
        cases.add(new Case("header released", new Layout(releasedB).slot(A, SLOT_A), null,
                store -> store.confirmReleasedSlot(releasedB, B)));
        cases.add(new Case("header removal", new Layout(releasingB).slot(A, SLOT_A)
                .slot(B, TOMBSTONE_B), null, store -> store.removeReleasingSlot(releasingB, B)));
        cases.add(new Case("slot release marker", new Layout(liveAB).slot(A, SLOT_A)
                .slot(B, TOMBSTONE_B), B, store -> store.writeHeader(liveAB, releasingB)));
        cases.add(new Case("slot tombstone removal", new Layout(releasingB).slot(A, SLOT_A)
                .slot(B, TOMBSTONE_B), B, store -> store.removeReleasingSlot(releasingB, B)));
        cases.add(new Case("last slot removal", new Layout(lastReleasing).sole(B, TOMBSTONE_B), B,
                store -> store.removeReleasingSlot(lastReleasing, B)));
        cases.add(new Case("unrelated omission", new Layout(releasingC).slot(A, SLOT_A)
                .slot(B, SLOT_B), B, store -> store.writeHeader(releasingC, releasedC)));
        cases.add(new Case("unrelated removal", new Layout(releasingC).slot(A, SLOT_A)
                .slot(B, SLOT_B).slot(C, TOMBSTONE_C), B,
                store -> store.removeReleasingSlot(releasingC, C)));
        cases.add(new Case("unrelated released", new Layout(releasedC).slot(A, SLOT_A)
                .slot(B, SLOT_B), B, store -> store.confirmReleasedSlot(releasedC, C)));
        return cases;
    }

    private static void releaseRefusals(Path parent) throws Exception {
        for (Case c : releaseCases()) {
            run(c.name + " refused before any effect under V1 and V2", problems -> {
                // Under each earlier format, which reads these version 1 layouts as they are.
                for (NativeIdentityStore.Format format : List.of(matrixFormat, NativeIdentityStore.Format.V2)) {
                    Path root = c.layout.build(fresh(parent));
                    NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
                    Map<String, String> footprint = footprint(root);
                    check(problems, !c.action.run(store), format + " writer accepted");
                    check(problems, footprint(root).equals(footprint), format + " store footprint changed");
                }
            });
        }
    }

    private static void pair(Path main, byte[] bytes) throws Exception {
        Files.write(main, bytes);
        Files.write(Path.of(main + ".reservecopy"), bytes);
    }
    private static Path at(Path root, Integer target, At at) {
        String main = target == null ? "store.bin" : "slots/" + target + "/record.bin";
        switch (at) {
            case MAIN: return root.resolve(main);
            case RESERVE: return root.resolve(main + ".reservecopy");
            case BACKUP: return root.resolve(main + "-backup");
            default: return root.resolve(main + "-seed");
        }
    }
    // Content, file identity and modification time of every path, as in the version gate test.
    private static Map<String, String> footprint(Path root) throws Exception {
        Map<String, String> result = new TreeMap<>();
        try (var paths = Files.walk(root)) {
            for (Path path : paths.toList()) {
                var attrs = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                result.put(root.relativize(path).toString(), attrs.fileKey() + ":"
                        + attrs.lastModifiedTime() + ":" + (attrs.isRegularFile()
                        ? Base64.getEncoder().encodeToString(Files.readAllBytes(path)) : "directory"));
            }
        }
        return result;
    }
    private static Path fresh(Path parent) {
        return parent.resolve("case-" + ++directories);
    }
    private static void check(List<String> problems, boolean ok, String problem) {
        if (!ok) problems.add(problem);
    }
    private static void run(String name, Body body) {
        List<String> problems = new ArrayList<>();
        try {
            body.run(problems);
        } catch (Exception | AssertionError error) {
            problems.add("error " + error);
        }
        if (problems.isEmpty()) {
            ++passed;
            System.out.println("PASS " + name);
        } else {
            failures.add(name);
            System.out.println("FAIL " + name + ": " + String.join("; ", problems));
        }
    }

    private static Seen healthy(Path parent, Case c) {
        Seen[] seen = new Seen[1];
        run(c.name + " / healthy", problems -> {
            Path root = c.layout.build(fresh(parent));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), matrixFormat);
            seen[0] = new Seen(store.load(), c.target);
            seen[0].result = c.action.run(store);
            check(problems, seen[0].result, "otherwise valid writer refused");
            check(problems, !seen[0].invented, "hidden hold");
            check(problems, seen[0].evidence.isEmpty(), "evidence without a later frame");
        });
        return seen[0];
    }

    // A recognized footprint: refused before any effect, holds and file identities kept, no
    // value read from it. A copy withdraws its record's eligibility; a seed does not. A copy
    // gives exactly the evidence of its valid stable prefix; a seed gives none.
    private static void unsupported(Path parent, Case c, Seen healthy, At at, byte[] bytes,
            String name, Set<String> evidence) {
        run(name, problems -> {
            if (healthy == null || !Boolean.TRUE.equals(healthy.result)) throw new AssertionError("healthy control failed");
            Path root = c.layout.build(fresh(parent));
            Path file = at(root, c.target, at);
            Files.write(file, bytes);
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), matrixFormat);
            Seen before = new Seen(store.load(), c.target);
            Map<String, String> footprint = footprint(root);
            boolean result = c.action.run(store);
            Seen after = new Seen(store.load(), c.target);
            check(problems, !result, "writer accepted");
            check(problems, Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)
                    && Arrays.equals(Files.readAllBytes(file), bytes), "newer bytes lost");
            check(problems, footprint(root).equals(footprint), "store footprint changed");
            check(problems, before.occupied.containsAll(healthy.occupied)
                    && after.occupied.equals(before.occupied), "holds changed " + after.occupied);
            check(problems, !before.invented && !after.invented, "hold invented from newer body");
            check(problems, !before.creationReady, "creation ready");
            boolean copy = at != At.SEED;
            Set<String> given = copy ? evidence : Set.of();
            check(problems, before.evidence.equals(given) && after.evidence.equals(given),
                    "evidence " + before.evidence);
            Status header = c.target == null && copy ? Status.UNSUPPORTED : healthy.header;
            check(problems, before.header == header, "header " + before.header);
            if (c.target != null) {
                Status slot = copy ? Status.UNSUPPORTED : healthy.target;
                check(problems, before.target == slot, "slot " + before.target);
            }
            Set<Integer> usable = new TreeSet<>(healthy.usable);
            if (copy && c.target == null) usable.clear();
            if (copy && c.target != null) usable.remove(c.target);
            check(problems, before.usable.equals(usable), "eligible " + before.usable);
        });
    }

    // The load view with these bytes in one position, and the writer's result if it runs.
    private static Seen outcome(Path parent, Case c, At at, byte[] bytes, boolean write)
            throws Exception {
        Path root = c.layout.build(fresh(parent));
        Files.write(at(root, c.target, at), bytes);
        NativeIdentityStore store = new NativeIdentityStore(root.toFile(), matrixFormat);
        Seen seen = new Seen(store.load(), c.target);
        if (write) seen.result = c.action.run(store);
        return seen;
    }

    // Not recognized: load() reports what it reports for garbage in that position. Where no
    // reader can see such damage, the writer's result is the healthy one. Otherwise it is the
    // result over garbage, which then runs too.
    private static void damaged(Path parent, Case c, Seen healthy, At at, byte[] bytes,
            String name) {
        run(name, problems -> {
            if (healthy == null || !Boolean.TRUE.equals(healthy.result)) throw new AssertionError("healthy control failed");
            Seen damaged = outcome(parent, c, at, bytes, true);
            Seen garbage = outcome(parent, c, at, GARBAGE, false);
            check(problems, damaged.view().equals(garbage.view()),
                    "damaged " + damaged.view() + " unlike garbage " + garbage.view());
            Boolean expected = garbage.view().equals(healthy.view()) ? healthy.result
                    : outcome(parent, c, at, GARBAGE, true).result;
            check(problems, damaged.result.equals(expected),
                    "writer " + damaged.result + " over damage, " + expected + " otherwise");
            check(problems, damaged.header != Status.UNSUPPORTED
                    && damaged.target != Status.UNSUPPORTED, "damage read as unsupported");
            check(problems, !damaged.invented, "hold invented from damaged body");
            check(problems, damaged.evidence.isEmpty(), "evidence from a damaged frame");
        });
    }

    private static byte[] badChecksum(byte[] record) {
        byte[] result = record.clone();
        result[result.length - 1] ^= 1;
        return result;
    }

    // Every case, every position: healthy, one rotated newer frame and its bad checksum twin.
    private static void matrix(Path parent) throws Exception {
        List<Case> cases = cases();
        for (int i = 0; i < cases.size(); i++) {
            Case c = cases.get(i);
            Seen healthy = healthy(parent, c);
            for (At at : At.values()) {
                byte[] newer = future(c.target, i + at.ordinal());
                String name = c.name + " / " + at + " v" + ((newer[6] & 0xff) | (newer[7] & 0xff) << 8);
                unsupported(parent, c, healthy, at, newer, name, evidence(c.target, i + at.ordinal()));
                damaged(parent, c, healthy, at, badChecksum(newer), name + " bad checksum");
            }
        }
    }

    private static Case named(String name) {
        for (Case c : cases()) if (c.name.equals(name)) return c;
        throw new AssertionError("no case " + name);
    }

    // Frame bounds on one header path and two slot paths, one position each.
    private static void bounds(Path parent) throws Exception {
        // The slot frame bounds on the update's reserve copy. The last slot's removal is a release
        // step, refused under version 1; the lifecycle entry point runs its later frames.
        Case header = named("header retry"), slot = named("slot update");
        Map<String, byte[]> recognized = new TreeMap<>(), damage = new TreeMap<>();
        byte[] v3 = frame(TYPE_HEADER, 3, concat(headerBody(), EXTENSION));
        recognized.put("v2 without a v2 body", frame(TYPE_HEADER, 2, headerBody()));
        recognized.put("v3", v3);
        recognized.put("v3 empty body", frame(TYPE_HEADER, 3, new byte[0]));
        recognized.put("v32767", frame(TYPE_HEADER, 0x7fff, headerBody()));
        recognized.put("v65535", frame(TYPE_HEADER, 0xffff, headerBody()));
        recognized.put("v3 at MAX_BYTES", frame(TYPE_HEADER, 3, new byte[MAX_BYTES - 44]));
        damage.put("v0", frame(TYPE_HEADER, 0, headerBody()));
        damage.put("v1 with trailing body", frame(TYPE_HEADER, 1, concat(headerBody(), EXTENSION)));
        damage.put("other magic", frame(MAGIC + 1, TYPE_HEADER, 3, headerBody()));
        damage.put("slot type", frame(TYPE_SLOT, 3, headerBody()));
        for (int type : new int[] {0, 3, 0xffff}) damage.put("type " + type, frame(type, 3, headerBody()));
        damage.put("bad checksum", badChecksum(v3));
        damage.put("truncated", Arrays.copyOf(v3, v3.length - 1));
        damage.put("extended", concat(v3, new byte[1]));
        byte[] unsealed = Arrays.copyOf(v3, v3.length - CHECKSUM);
        damage.put("length field", sealed(put(unsealed, 8, 4, v3.length + 1)));
        damage.put("above MAX_BYTES", frame(TYPE_HEADER, 3, new byte[MAX_BYTES - 43]));
        Seen healthy = healthy(parent, header);
        for (Map.Entry<String, byte[]> entry : recognized.entrySet()) {
            unsupported(parent, header, healthy, At.RESERVE, entry.getValue(),
                    "header bounds / " + entry.getKey(), Set.of());
        }
        for (Map.Entry<String, byte[]> entry : damage.entrySet()) {
            damaged(parent, header, healthy, At.RESERVE, entry.getValue(),
                    "header bounds / " + entry.getKey());
        }
        // A decodable version 2 copy is the known hold only case: its holds are kept.
        byte[] knownV2 = NativeIdentityRecords.encodeHeader(Header.newV2(LINEAGE, 7, List.of(
                live(A), creating(KNOWN_V2, 7, "dev.andrix.knownv2"))));
        unsupported(parent, header, healthy, At.RESERVE, knownV2, "header bounds / known v2", Set.of());
        run("header bounds / known v2 hold kept", problems -> {
            Path root = header.layout.build(fresh(parent));
            Files.write(at(root, null, At.RESERVE), knownV2);
            check(problems, new NativeIdentityStore(root.toFile(), NativeIdentityStore.Format.V1).load().occupiedAppIds
                    .equals(Set.of(A, KNOWN_V2)), "known version 2 hold lost");
        });

        // A decodable version 2 slot copy is a footprint under this format, and only negative
        // evidence: it withdraws its record and contradicts a sibling naming its package.
        Slot suspendedA = new Slot(LINEAGE, A, PKG_A, 2, SIGNERS, List.of(new UserEntry(1, 0, 7,
                new NativeIdentityRecords.Lifecycle(NativeIdentityRecords.LifecycleState.ELIGIBLE,
                        List.of(new NativeIdentityRecords.Suspension(
                                NativeIdentityRecords.ActorClass.ACCOUNT_USER, 0, 0, 7, "0".repeat(32), 1,
                                1_700_000_000_000L, null)), null))));
        byte[] knownSlot = NativeIdentityRecords.encodeSlot(suspendedA);
        if (knownSlot[6] != 2) throw new AssertionError("known version 2 slot fixture");
        slotBounds(parent, slot, At.RESERVE, knownSlot);
        run("known v2 slot copy is negative evidence", problems -> {
            Header liveAB = header(2, live(A), live(B));
            Slot sibling = bound(B, PKG_A, 2, false, 1);
            for (boolean decodable : new boolean[] {true, false}) {
                Path root = new Layout(liveAB).slot(B, sibling).build(fresh(parent));
                Path directory = Files.createDirectory(root.resolve("slots/" + A));
                // The control has a version 3 frame whose prefix breaks off: no evidence.
                pair(directory.resolve("record.bin"), decodable ? knownSlot
                        : frame(TYPE_SLOT, 3, Arrays.copyOf(body(knownSlot), 40)));
                NativeIdentityStore.Loaded loaded =
                        new NativeIdentityStore(root.toFile(), NativeIdentityStore.Format.V1).load();
                NativeIdentityStore.ReadResult<Slot> read = loaded.slots.get(A);
                check(problems, read.status == Status.UNSUPPORTED && read.prefixes.isEmpty()
                        && read.decodedCopies.equals(decodable ? List.of(suspendedA, suspendedA) : List.of()),
                        "version 2 copies " + read.decodedCopies);
                check(problems, !loaded.bindingUsable(A) && loaded.history(A) == null, "version 2 value used");
                check(problems, loaded.slots.get(B).status == (decodable ? Status.CONFLICT : Status.VALID),
                        "sibling " + loaded.slots.get(B).status + " beside decodable " + decodable);
                check(problems, loaded.occupiedAppIds.equals(Set.of(A, B)), "holds " + loaded.occupiedAppIds);
            }
        });
        // A numeric directory holds its ID even when its only record is a newer one.
        run("newer sole record keeps its directory hold", problems -> {
            Path root = new Layout(header(2, live(A))).slot(A, SLOT_A).build(fresh(parent));
            Path directory = Files.createDirectory(root.resolve("slots/" + B));
            Files.write(directory.resolve("record.bin"), frame(TYPE_SLOT, 3, slotBody(B)));
            NativeIdentityStore.Loaded loaded = new NativeIdentityStore(root.toFile(), NativeIdentityStore.Format.V1).load();
            check(problems, loaded.occupiedAppIds.equals(Set.of(A, B)), "holds " + loaded.occupiedAppIds);
            check(problems, loaded.slots.get(B).status == Status.UNSUPPORTED, "status");
            check(problems, loaded.bindingUsable(A) && !loaded.bindingUsable(B), "eligibility");
            check(problems, loaded.slots.get(B).prefixes.size() == 1
                    && loaded.slots.get(B).prefixes.get(0).packageName.equals(PKG_HIDDEN), "prefix evidence");
        });
    }

    // The slot frame bounds at one position of this case's target record. Above the format's slot
    // ceiling a frame is a recognized later footprint: a valid stable prefix gives PKG_HIDDEN as
    // evidence, and a broken one gives nothing. Anything malformed is damage. Under the lifecycle
    // format version 2 is a slot version it decodes, so a version 1 body framed as version 2 is
    // damage there, and a known version 2 copy is no footprint.
    private static void slotBounds(Path parent, Case target, At at, byte[] knownSlot) throws Exception {
        int appId = target.target;
        boolean lifecycle = matrixFormat.slotCeiling >= 2;
        Map<String, byte[]> recognized = new TreeMap<>(), damage = new TreeMap<>();
        Set<String> prefixed = Set.of("v3", "v3 version 1 body", "v65535");
        byte[] slotV3 = frame(TYPE_SLOT, 3, concat(slotBody(appId), EXTENSION));
        (lifecycle ? damage : recognized).put("v2 version 1 body", frame(TYPE_SLOT, 2, slotBody(appId)));
        recognized.put("v3", slotV3);
        recognized.put("v3 empty body", frame(TYPE_SLOT, 3, new byte[0]));
        recognized.put("v3 version 1 body", frame(TYPE_SLOT, 3, slotBody(appId)));
        recognized.put("v3 broken prefix", frame(TYPE_SLOT, 3, Arrays.copyOf(slotBody(appId), 40)));
        recognized.put("v65535", frame(TYPE_SLOT, 0xffff, slotBody(appId)));
        recognized.put("v3 at MAX_BYTES", frame(TYPE_SLOT, 3, new byte[MAX_BYTES - 44]));
        damage.put("v0", frame(TYPE_SLOT, 0, slotBody(appId)));
        damage.put("v1 with trailing body", frame(TYPE_SLOT, 1, concat(slotBody(appId), EXTENSION)));
        damage.put("other magic", frame(MAGIC ^ 0x100, TYPE_SLOT, 3, slotBody(appId)));
        damage.put("header type", frame(TYPE_HEADER, 3, slotBody(appId)));
        for (int type : new int[] {0, 3, 0xffff}) damage.put("type " + type, frame(type, 3, slotBody(appId)));
        damage.put("bad checksum", badChecksum(slotV3));
        damage.put("truncated", Arrays.copyOf(slotV3, slotV3.length - 1));
        damage.put("extended", concat(slotV3, new byte[1]));
        byte[] unsealed = Arrays.copyOf(slotV3, slotV3.length - CHECKSUM);
        damage.put("length field", sealed(put(unsealed, 8, 4, slotV3.length - 1)));
        damage.put("above MAX_BYTES", frame(TYPE_SLOT, 3, new byte[MAX_BYTES - 43]));
        Seen seen = healthy(parent, target);
        for (Map.Entry<String, byte[]> entry : recognized.entrySet()) {
            unsupported(parent, target, seen, at, entry.getValue(), target.name + " bounds / " + entry.getKey(),
                    prefixed.contains(entry.getKey()) ? Set.of(PKG_HIDDEN) : Set.of());
        }
        if (knownSlot != null) {
            unsupported(parent, target, seen, at, knownSlot, target.name + " bounds / known v2", Set.of());
        }
        for (Map.Entry<String, byte[]> entry : damage.entrySet()) {
            damaged(parent, target, seen, at, entry.getValue(), target.name + " bounds / " + entry.getKey());
        }
    }

    // Decodable older copies of an unsupported record still contradict a related
    // binding. Withdrawing one record's eligibility must not promote its collider. So does
    // the stable prefix of a later slot frame, when no decodable copy remains.
    private static void relatedBindings(Path parent) throws Exception {
        byte[] later = frame(TYPE_SLOT, 3, concat(body(NativeIdentityRecords.encodeSlot(SLOT_A)), EXTENSION));
        for (String kind : List.of("package", "incarnation", "unrelated")) {
            run("later prefix retains negative " + kind + " evidence", problems -> {
                Slot second = bound(B, kind.equals("package") ? PKG_A : PKG_B,
                        kind.equals("incarnation") ? 1 : 2, false, 1);
                Path root = new Layout(header(2, live(A), live(B))).slot(B, second).build(fresh(parent));
                pair(Files.createDirectory(root.resolve("slots/" + A)).resolve("record.bin"), later);
                NativeIdentityStore.Loaded loaded = new NativeIdentityStore(root.toFile(),
                        NativeIdentityStore.Format.V1).load();
                boolean unrelated = kind.equals("unrelated");
                NativeIdentityStore.ReadResult<Slot> read = loaded.slots.get(A);
                check(problems, read.status == Status.UNSUPPORTED && read.decodedCopies.isEmpty()
                        && read.prefixes.size() == 2, "later frame read " + read.status);
                check(problems, loaded.slots.get(B).status == (unrelated ? Status.VALID : Status.CONFLICT),
                        "related binding became usable");
                check(problems, loaded.bindingUsable(B) == unrelated, "negative evidence ignored");
                check(problems, loaded.occupiedAppIds.equals(Set.of(A, B)), "known holds changed");
            });
        }
        for (String kind : List.of("package", "incarnation", "unrelated")) {
            run("unsupported copy retains negative " + kind + " evidence", problems -> {
                Slot second = bound(B, kind.equals("package") ? PKG_A : PKG_B,
                        kind.equals("incarnation") ? 1 : 2, false, 1);
                Path root = new Layout(header(2, live(A), live(B))).slot(A, SLOT_A).slot(B, second).build(fresh(parent));
                NativeIdentityStore store = new NativeIdentityStore(root.toFile(), NativeIdentityStore.Format.V1);
                boolean unrelated = kind.equals("unrelated");
                check(problems, store.load().bindingUsable(B) == unrelated, "invalid healthy collision control");
                Files.write(root.resolve("slots/" + A + "/record.bin"), future(A, 0));
                Map<String, String> before = footprint(root);
                NativeIdentityStore.Loaded loaded = store.load();
                check(problems, loaded.slots.get(A).status == Status.UNSUPPORTED, "newer slot not unsupported");
                check(problems, loaded.slots.get(B).status == (unrelated ? Status.VALID : Status.CONFLICT), "related binding became usable");
                check(problems, loaded.bindingUsable(B) == unrelated, "negative evidence ignored");
                check(problems, loaded.occupiedAppIds.equals(Set.of(A, B)), "known holds changed");
                check(problems, before.equals(footprint(root)), "read changed metadata");
            });
        }
    }

    // This store's own staging: torn or matching version 1 seeds keep their existing retry.
    // The release engine's ticketed tombstone of principal id, as the lifecycle format writes it.
    private static Slot ticketed(int appId, String name, long id) {
        return new Slot(LINEAGE, appId, name, 3, SIGNERS, List.of(),
                new NativeIdentityRecords.ReleaseTicket(id, 0, 7, "7".repeat(32)));
    }

    // The account user's retirement block with every kind outstanding.
    private static NativeIdentityRecords.Retirement block() {
        List<NativeIdentityRecords.Obligation> outstanding = new ArrayList<>();
        for (NativeIdentityRecords.ObligationKind kind : NativeIdentityRecords.ObligationKind.values()) {
            outstanding.add(new NativeIdentityRecords.Obligation(kind,
                    NativeIdentityRecords.ObligationState.OUTSTANDING, NativeIdentityRecords.NO_REFERENCE, 0, 0));
        }
        return new NativeIdentityRecords.Retirement(NativeIdentityRecords.ActorClass.ACCOUNT_USER, 0, 7,
                NativeIdentityRecords.NO_REFERENCE, 1_700_000_000_100L, outstanding);
    }

    // The lifecycle writer rows under Format.V3: the version 1 retiring flag, release marker, omission,
    // removal and released confirmation rows, written by the lifecycle writers and the release
    // engine's primitives, each with its healthy control and the same later frames beside it.
    private static List<Case> lifecycleCases() {
        Header liveA = header(1, live(A));
        Header liveAB = header(2, live(A), live(B));
        Header releasingB = header(2, live(A), releasing(B));
        Header releasedB = header(2, live(A));
        Header lastReleasing = header(2, releasing(B));
        Header releasingC = header(3, live(A), live(B), releasing(C));
        Header releasedC = header(3, live(A), live(B));
        Slot ticketedB = ticketed(B, PKG_B, 2), ticketedC = ticketed(C, PKG_C, 3);
        List<Case> cases = new ArrayList<>();
        cases.add(new Case("V3 header release marker", new Layout(liveAB).slot(A, SLOT_A).slot(B, ticketedB), null,
                store -> store.markSlotReleasing(liveAB, B)));
        cases.add(new Case("V3 header omission", new Layout(releasingB).slot(A, SLOT_A), null,
                store -> store.omitReleasedSlot(releasingB, B)));
        cases.add(new Case("V3 header released", new Layout(releasedB).slot(A, SLOT_A), null,
                store -> store.confirmReleasedSlot(releasedB, B)));
        cases.add(new Case("V3 header removal", new Layout(releasingB).slot(A, SLOT_A).slot(B, ticketedB), null,
                store -> store.removeReleasingSlot(releasingB, B)));
        cases.add(new Case("V3 header update", new Layout(liveA).slot(A, SLOT_A), null,
                store -> store.markSlotRetiring(SLOT_A, 1, block())));
        cases.add(new Case("V3 slot update", new Layout(liveA).slot(A, SLOT_A), A,
                store -> store.markSlotRetiring(SLOT_A, 1, block())));
        // An unreadable header leaves only the exact existing binding writers: the retirement needs
        // only an intact binding.
        cases.add(new Case("V3 slot unknown counter update", new Layout(GARBAGE).slot(A, SLOT_A), A,
                store -> store.markSlotRetiring(SLOT_A, 1, block())));
        cases.add(new Case("V3 slot release marker", new Layout(liveAB).slot(A, SLOT_A).slot(B, ticketedB), B,
                store -> store.markSlotReleasing(liveAB, B)));
        cases.add(new Case("V3 slot tombstone removal", new Layout(releasingB).slot(A, SLOT_A).slot(B, ticketedB), B,
                store -> store.removeReleasingSlot(releasingB, B)));
        cases.add(new Case("V3 last slot removal", new Layout(lastReleasing).sole(B, ticketedB), B,
                store -> store.removeReleasingSlot(lastReleasing, B)));
        cases.add(new Case("V3 unrelated update", new Layout(liveAB).slot(A, SLOT_A).slot(B, SLOT_B), B,
                store -> store.markSlotRetiring(SLOT_A, 1, block())));
        cases.add(new Case("V3 unrelated omission", new Layout(releasingC).slot(A, SLOT_A).slot(B, SLOT_B), B,
                store -> store.omitReleasedSlot(releasingC, C)));
        cases.add(new Case("V3 unrelated removal", new Layout(releasingC).slot(A, SLOT_A).slot(B, SLOT_B)
                .slot(C, ticketedC), B, store -> store.removeReleasingSlot(releasingC, C)));
        cases.add(new Case("V3 unrelated released", new Layout(releasedC).slot(A, SLOT_A).slot(B, SLOT_B), B,
                store -> store.confirmReleasedSlot(releasedC, C)));
        return cases;
    }

    // The lifecycle rows' matrix: each healthy control, then each later frame and its damaged twin in
    // every position of the row's record, as the version 1 matrix runs them.
    private static void lifecycleMatrix(Path parent) throws Exception {
        List<Case> cases = lifecycleCases();
        for (int i = 0; i < cases.size(); i++) {
            Case c = cases.get(i);
            Seen healthy = healthy(parent, c);
            for (At at : At.values()) {
                byte[] newer = future(c.target, i + at.ordinal());
                String name = c.name + " / " + at + " v" + ((newer[6] & 0xff) | (newer[7] & 0xff) << 8);
                unsupported(parent, c, healthy, at, newer, name, evidence(c.target, i + at.ordinal()));
                damaged(parent, c, healthy, at, badChecksum(newer), name + " bad checksum");
            }
        }
        // The last slot's frame bounds at its sole main copy, which the version 1 entry point no
        // longer runs: under the earlier formats the removal is a release step, refused.
        for (Case c : cases) {
            if (c.name.equals("V3 last slot removal")) slotBounds(parent, c, At.MAIN, null);
        }
        // The owned staging retries of the removal and the retirement over a torn seed of their own.
        Header liveA = header(1, live(A));
        Header releasingB = header(2, live(A), releasing(B));
        Slot ticketedB = ticketed(B, PKG_B, 2);
        List<Case> owned = List.of(
                new Case("V3 owned torn seed removal", new Layout(releasingB).slot(A, SLOT_A).slot(B, ticketedB), B,
                        store -> store.removeReleasingSlot(releasingB, B)),
                new Case("V3 owned torn seed update", new Layout(liveA).slot(A, SLOT_A), A,
                        store -> store.markSlotRetiring(SLOT_A, 1, block())));
        List<byte[]> seeds = List.of(Arrays.copyOf(NativeIdentityRecords.encodeSlot(ticketedB), 60),
                Arrays.copyOf(NativeIdentityRecords.encodeSlot(SLOT_A), 90));
        for (int i = 0; i < owned.size(); i++) {
            Case c = owned.get(i);
            byte[] seed = seeds.get(i);
            run(c.name, problems -> {
                Seen seen = outcome(parent, c, At.SEED, seed, true);
                check(problems, seen.result, "owned staging retry refused: " + seen);
            });
        }
    }

    private static void ownedSeeds(Path parent) throws Exception {
        Header liveA = header(1, live(A));
        Header creatingB = header(2, live(A), creating(B, 2, PKG_B));
        Header releasingB = header(2, live(A), releasing(B));
        byte[] tornB = Arrays.copyOf(NativeIdentityRecords.encodeSlot(SLOT_B), 40);
        byte[] tornA = Arrays.copyOf(NativeIdentityRecords.encodeSlot(SLOT_A), 90);
        byte[] tornHeader = Arrays.copyOf(NativeIdentityRecords.encodeHeader(liveA), 50);
        List<Case> owned = List.of(
                new Case("owned torn seed resume", new Layout(creatingB).slot(A, SLOT_A).empty(B), B,
                        store -> store.resumeCreatingDirectory(creatingB, B)),
                new Case("owned torn seed publish", new Layout(creatingB).slot(A, SLOT_A).empty(B), B,
                        store -> store.resumeCreatingDirectory(creatingB, B)
                                && store.publishCreatingSlot(creatingB, SLOT_B)),
                new Case("owned torn seed update", new Layout(liveA).slot(A, SLOT_A), A,
                        store -> store.updateExistingSlot(SLOT_A, TOUCHED_A)),
                new Case("owned torn header seed retry", new Layout(liveA).slot(A, SLOT_A), null,
                        store -> store.writeHeader(liveA, liveA)));
        List<byte[]> seeds = List.of(tornB, tornB, tornA, tornHeader);
        for (int i = 0; i < owned.size(); i++) {
            Case c = owned.get(i);
            byte[] seed = seeds.get(i);
            run(c.name, problems -> {
                Seen seen = outcome(parent, c, At.SEED, seed, true);
                check(problems, seen.result, "owned staging retry refused: " + seen);
            });
        }
        run("owned matching seed publish", problems -> {
            Case c = owned.get(1);
            Seen seen = outcome(parent, c, At.SEED, NativeIdentityRecords.encodeSlot(SLOT_B), true);
            check(problems, seen.result, "matching version 1 seed refused: " + seen);
        });
        // The removal's own torn seed: under version 1 the removal is a release step, refused
        // before any effect, so the seed stays as it is.
        Case removal = new Case("owned torn seed removal", new Layout(releasingB).slot(A, SLOT_A)
                .slot(B, TOMBSTONE_B), B, store -> store.removeReleasingSlot(releasingB, B));
        byte[] tornTombstone = Arrays.copyOf(NativeIdentityRecords.encodeSlot(TOMBSTONE_B), 60);
        run("owned torn seed removal refused before any effect under V1 and V2", problems -> {
            for (NativeIdentityStore.Format format : List.of(matrixFormat, NativeIdentityStore.Format.V2)) {
                Path root = removal.layout.build(fresh(parent));
                Files.write(at(root, B, At.SEED), tornTombstone);
                NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
                Map<String, String> footprint = footprint(root);
                check(problems, !removal.action.run(store), format + " removal accepted");
                check(problems, footprint(root).equals(footprint), format + " store footprint changed");
            }
        });
    }

    public static void main(String[] args) throws Exception {
        if (!NativeIdentityFutureFormatTest.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        if (args.length == 2 && args[1].equals("V3")) {
            // The lifecycle rows' own entry point, run as its own step with its own limit.
            matrixFormat = NativeIdentityStore.Format.V3;
            lifecycleMatrix(Files.createDirectories(Path.of(args[0]).resolve("future-format-lifecycle")));
            if (!Os.allClosed()) failures.add("open descriptors");
            System.out.println(passed + " passed, " + failures.size() + " failed");
            if (!failures.isEmpty()) throw new AssertionError("failed: " + failures);
            System.out.println("Unsupported format footprints preserved by the lifecycle writers and the release"
                    + " engine's primitives; Android unqualified");
            return;
        }
        Path parent = Files.createDirectories(Path.of(args[0]).resolve("future-format"));
        matrix(parent);
        bounds(parent);
        releaseRefusals(parent);
        ownedSeeds(parent);
        relatedBindings(parent);
        if (!Os.allClosed()) failures.add("open descriptors");
        System.out.println(passed + " passed, " + failures.size() + " failed");
        if (!failures.isEmpty()) throw new AssertionError("failed: " + failures);
        System.out.println("Unsupported format footprints preserved by every store writer;"
                + " Android unqualified");
    }
}
