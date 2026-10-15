// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import android.system.Os;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.HeaderEntry;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.SlotPhase;
import com.android.server.pm.NativeIdentityRecords.UserEntry;
import com.android.server.pm.NativeIdentityStore.Status;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
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
 * Exact filesystem presence on actual host files. Only a genuine ENOENT may continue an owned
 * transaction as absence. A path that cannot be stat'ed or read is unknown: an otherwise valid
 * writer refuses before any effect, keeps every byte, file identity and known hold, and grants
 * no eligibility or counter from around it. Links and special nodes are refused and never
 * followed. Each case isolates one store and restricts exactly one fixture path with real
 * unprivileged permissions, restoring that path's own mode afterwards. A run uses one store
 * format: the legacy version 1 by default, the previous V2, which repeats every case with
 * version 2 headers whose CREATING entries carry the complete binding of their slot bodies, or the
 * lifecycle format V3, which repeats them again with the release engine's omission and the
 * lifecycle retirement. Under the earlier formats the release steps and the retiring flag are
 * lifecycle writes: on its healthy layout each refuses before any effect, while the read side of
 * every restricted and unreadable position stays checked, and the slot update rows take a
 * generation step without a lifecycle change. Host facades only, not Android persistence, SELinux
 * or I/O error qualification.
 */
public final class NativeIdentityPresenceTest {
    private static final String LINEAGE = "e".repeat(32);
    private static final Set<String> SIGNERS = Set.of("f".repeat(64));
    // HIDDEN and PKG_HIDDEN appear only inside bytes no reader may use.
    private static final int A = 10123, B = 10124, SPECIAL = 10125, C = 10200, HIDDEN = 10300;
    private static final String PKG_A = "dev.andrix.presencea", PKG_B = "dev.andrix.presenceb",
            PKG_C = "dev.andrix.presencec", PKG_HIDDEN = "dev.andrix.hidden";
    private static final int MAGIC = 0x44495841, TYPE_HEADER = 1, TYPE_SLOT = 2, CHECKSUM = 32;
    private static final byte[] GARBAGE = {1, 2, 3};
    private static final byte[] EXTENSION = {0x33, 0x33, 0x33, 0x33};
    // A file that cannot be read but can still be replaced, truncated or unlinked.
    private static final String UNREADABLE = "-w-------";
    // A directory that can be listed, but whose entries cannot be stat'ed or opened.
    private static final String UNSEARCHABLE = "rw-------";
    // A directory whose entries can be stat'ed and read, but not added or removed.
    private static final String READ_ONLY = "r-x------";
    // Fixtures are aged, so any later write, rename or unlink shows in the footprint.
    private static final FileTime AGED = FileTime.fromMillis(86_400_000L);

    private static final Slot SLOT_A = bound(A, PKG_A, 1, false, 1);
    private static final Slot RETIRING_A = bound(A, PKG_A, 1, true, 2);
    // A's next generation without a lifecycle change: the only slot update the earlier formats take.
    private static final Slot TOUCHED_A = bound(A, PKG_A, 1, false, 2);
    private static final Slot SLOT_B = bound(B, PKG_B, 2, false, 1);
    private static final Slot TOMBSTONE_B = new Slot(LINEAGE, B, PKG_B, 3, SIGNERS, List.of());
    private static final Slot SLOT_C = bound(C, PKG_C, 3, false, 1);
    // This run's store format and its header values, assigned by main before any case.
    private static NativeIdentityStore.Format format = NativeIdentityStore.Format.V1;
    private static Header LIVE_A, CREATING_B, LIVE_AB, RELEASING_B, RELEASED_B, CREATING_C, LIVE_ABC;
    private static final String SEED_B = "slots/" + B + "/record.bin-seed";
    private static final String SEED_C = "slots/" + C + "/record.bin-seed";
    private static final byte[] TORN_B = Arrays.copyOf(NativeIdentityRecords.encodeSlot(TOMBSTONE_B), 60);
    private static final byte[] TORN_C = Arrays.copyOf(NativeIdentityRecords.encodeSlot(SLOT_C), 40);

    private enum At { MAIN, RESERVE, BACKUP, SEED }

    private interface Action { boolean run(NativeIdentityStore store) throws Exception; }
    private interface Body { void run(List<String> problems) throws Exception; }
    private interface Call<T> { T run() throws Exception; }
    private interface Extra { void check(View healthy, View during, List<String> problems); }
    private static final Extra NOTHING = (healthy, during, problems) -> { };

    private static final List<String> failures = new ArrayList<>();
    private static int passed, cases;
    private static Path parent;

    private static Slot bound(int appId, String name, long id, boolean retiring, long generation) {
        return new Slot(LINEAGE, appId, name, generation, SIGNERS,
                List.of(new UserEntry(id, 0, 7, retiring)));
    }
    private static HeaderEntry live(int appId) { return new HeaderEntry(appId, SlotPhase.LIVE, 0, ""); }
    private static HeaderEntry releasing(int appId) {
        return new HeaderEntry(appId, SlotPhase.RELEASING, 0, "");
    }
    // Under V2 and V3 a CREATING entry carries the complete binding its slot body will have.
    private static HeaderEntry creating(int appId, long id, String name) {
        return new HeaderEntry(appId, SlotPhase.CREATING, id, name,
                format != NativeIdentityStore.Format.V1
                        ? new NativeIdentityRecords.CreationBinding(0, 7, SIGNERS) : null);
    }
    private static Header header(long lastId, HeaderEntry... entries) {
        return format != NativeIdentityStore.Format.V1 ? Header.newV2(LINEAGE, lastId, List.of(entries))
                : new Header(LINEAGE, lastId, List.of(entries));
    }
    // Whether this run's format is one of the earlier ones, which write no lifecycle change.
    private static boolean earlier() {
        return format != NativeIdentityStore.Format.V3;
    }
    // The release omission of this run's format: the version 1 header write under the earlier formats,
    // where it refuses, and under Format.V3 the release engine's omission.
    private static boolean omission(NativeIdentityStore store) {
        return format == NativeIdentityStore.Format.V3 ? store.omitReleasedSlot(RELEASING_B, B)
                : store.writeHeader(RELEASING_B, RELEASED_B);
    }
    // The slot update of this run's format: under the earlier formats a generation step without a
    // lifecycle change, and under Format.V3 the lifecycle retirement.
    private static boolean update(NativeIdentityStore store) {
        return format == NativeIdentityStore.Format.V3 ? store.markSlotRetiring(SLOT_A, 1, block())
                : store.updateExistingSlot(SLOT_A, TOUCHED_A);
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
    private static void headers() {
        LIVE_A = header(1, live(A));
        CREATING_B = header(2, live(A), creating(B, 2, PKG_B));
        LIVE_AB = header(2, live(A), live(B));
        RELEASING_B = header(2, live(A), releasing(B));
        RELEASED_B = header(2, live(A));
        CREATING_C = header(3, live(A), live(B), creating(C, 3, PKG_C));
        LIVE_ABC = header(3, live(A), live(B), live(C));
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
    private static byte[] body(byte[] record) {
        return Arrays.copyOfRange(record, 12, record.length - CHECKSUM);
    }
    // An intact frame, whatever it declares: magic, type, version and exact length, the body,
    // then the SHA-256 of all of it.
    private static byte[] frame(int type, int version, byte[] body) throws Exception {
        byte[] unsealed = new byte[12 + body.length];
        put(unsealed, 0, 4, MAGIC);
        put(unsealed, 4, 2, type);
        put(unsealed, 6, 2, version);
        put(unsealed, 8, 4, unsealed.length + CHECKSUM);
        System.arraycopy(body, 0, unsealed, 12, body.length);
        return concat(unsealed, MessageDigest.getInstance("SHA-256").digest(unsealed));
    }
    // An intact record of a version this protocol does not write. It decodes to nothing.
    private static byte[] future(Integer target) throws Exception {
        if (target == null) {
            return frame(TYPE_HEADER, 3, concat(body(NativeIdentityRecords.encodeHeader(
                    header(9, live(A), live(HIDDEN)))), EXTENSION));
        }
        // The lifecycle format reads version 2 slots, so its newer slot frame is version 3.
        return frame(TYPE_SLOT, format.slotCeiling + 1, concat(body(NativeIdentityRecords.encodeSlot(
                bound(target, PKG_HIDDEN, 9, true, 5))), EXTENSION));
    }

    private static void pair(Path main, byte[] bytes) throws Exception {
        Files.write(main, bytes);
        Files.write(Path.of(main + ".reservecopy"), bytes);
    }

    // A store as its own writers leave it: main and reserve of the header and of each slot,
    // or an empty directory before a creation publishes its body, plus any extra file.
    private static final class Layout {
        final Header header;
        final Map<Integer, Slot> bodies = new TreeMap<>();
        final Set<Integer> empty = new TreeSet<>();
        final Map<String, byte[]> files = new TreeMap<>();
        Layout(Header header) { this.header = header; }
        Layout slot(int appId, Slot body) { bodies.put(appId, body); return this; }
        Layout empty(int appId) { empty.add(appId); return this; }
        Layout file(String relative, byte[] bytes) { files.put(relative, bytes); return this; }
        Path build(Path root) throws Exception {
            Files.createDirectories(root.resolve("slots"));
            pair(root.resolve("store.bin"), NativeIdentityRecords.encodeHeader(header));
            for (Map.Entry<Integer, Slot> body : bodies.entrySet()) {
                Path directory = Files.createDirectory(root.resolve("slots/" + body.getKey()));
                pair(directory.resolve("record.bin"), NativeIdentityRecords.encodeSlot(body.getValue()));
            }
            for (int appId : empty) Files.createDirectory(root.resolve("slots/" + appId));
            for (Map.Entry<String, byte[]> file : files.entrySet()) {
                Files.write(root.resolve(file.getKey()), file.getValue());
            }
            return root;
        }
    }

    // One otherwise valid writer call. A null target is the header record. A lifecycle call is a
    // release step, which under the earlier formats refuses on its healthy layout too.
    private static final class Case {
        final String name;
        final Layout layout;
        final Integer target;
        final Action action;
        final boolean lifecycle;
        Case(String name, Layout layout, Integer target, Action action) {
            this(name, layout, target, action, false);
        }
        Case(String name, Layout layout, Integer target, Action action, boolean lifecycle) {
            this.name = name;
            this.layout = layout;
            this.target = target;
            this.action = action;
            this.lifecycle = lifecycle;
        }
    }

    // What load() reports, reduced to the facts these cases compare.
    private static final class View {
        final Status header;
        final Map<Integer, Status> slots = new TreeMap<>();
        final Set<Integer> holds = new TreeSet<>(), usable = new TreeSet<>();
        final boolean ready, complete;
        View(NativeIdentityStore.Loaded loaded) {
            header = loaded.header.status;
            for (Map.Entry<Integer, NativeIdentityStore.ReadResult<Slot>> entry
                    : loaded.slots.entrySet()) {
                slots.put(entry.getKey(), entry.getValue().status);
            }
            holds.addAll(loaded.occupiedAppIds);
            for (int appId : List.of(A, B, C)) if (loaded.bindingUsable(appId)) usable.add(appId);
            ready = loaded.creationReady();
            complete = loaded.enumerationComplete;
        }
        @Override public String toString() {
            return "header=" + header + " slots=" + slots + " holds=" + holds + " usable=" + usable
                    + " ready=" + ready + " complete=" + complete;
        }
        @Override public boolean equals(Object other) {
            return other instanceof View && toString().equals(other.toString());
        }
        @Override public int hashCode() {
            return toString().hashCode();
        }
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

    // Type, file identity, modification time, mode and content of every path below top, taken
    // while every fixture permission is intact.
    private static Map<String, String> footprint(Path top) throws Exception {
        Map<String, String> result = new TreeMap<>();
        try (var paths = Files.walk(top)) {
            for (Path path : paths.toList()) {
                BasicFileAttributes attrs = Files.readAttributes(path, BasicFileAttributes.class,
                        LinkOption.NOFOLLOW_LINKS);
                String kind;
                if (attrs.isSymbolicLink()) {
                    kind = "link " + Files.readSymbolicLink(path);
                } else {
                    kind = PosixFilePermissions.toString(Files.getPosixFilePermissions(path,
                            LinkOption.NOFOLLOW_LINKS)) + (attrs.isRegularFile()
                            ? " " + Base64.getEncoder().encodeToString(Files.readAllBytes(path))
                            : attrs.isDirectory() ? " directory" : " special");
                }
                result.put(top.relativize(path).toString(), attrs.fileKey() + " "
                        + attrs.lastModifiedTime() + " " + kind);
            }
        }
        return result;
    }
    private static void age(Path top) throws Exception {
        List<Path> paths;
        try (var walk = Files.walk(top)) {
            paths = walk.toList();
        }
        for (Path path : paths) {
            BasicFileAttributes attrs = Files.readAttributes(path, BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS);
            if (attrs.isRegularFile() || attrs.isDirectory()) Files.setLastModifiedTime(path, AGED);
        }
    }

    // Only this fixture path's own mode changes, only for the call, and it is restored even
    // when the call fails.
    private static <T> T restricted(Path path, String mode, Call<T> call) throws Exception {
        Set<PosixFilePermission> original = Files.getPosixFilePermissions(path,
                LinkOption.NOFOLLOW_LINKS);
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(mode));
        try {
            return call.run();
        } finally {
            Files.setPosixFilePermissions(path, original);
        }
    }

    // A Unix domain socket: a special node made without privilege or another process.
    private static void socket(Path path) throws Exception {
        if (path.toString().length() >= 100) {
            throw new AssertionError("special node fixture path too long: " + path);
        }
        try (ServerSocketChannel channel = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            channel.bind(UnixDomainSocketAddress.of(path));
        }
        if (!Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)
                .isOther()) {
            throw new AssertionError("special node fixture");
        }
    }

    private static Path fresh() throws Exception {
        return Files.createDirectory(parent.resolve("c" + ++cases));
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

    // Unprivileged discretionary access control must refuse both accesses these cases rely on.
    // A root or capability bypass would make every restricted case vacuous.
    private static boolean refusedAccess(Call<?> access) throws Exception {
        try {
            access.run();
            return false;
        } catch (AccessDeniedException expected) {
            return true;
        }
    }
    private static void requireDac() throws Exception {
        Path probe = Files.createDirectory(parent.resolve("dac-probe"));
        Path file = Files.write(probe.resolve("file"), GARBAGE);
        Path directory = Files.createDirectory(probe.resolve("directory"));
        Path child = Files.write(directory.resolve("child"), GARBAGE);
        boolean unreadable = restricted(file, UNREADABLE,
                () -> refusedAccess(() -> Files.readAllBytes(file)));
        boolean unsearchable = restricted(directory, UNSEARCHABLE, () -> refusedAccess(
                () -> Files.readAttributes(child, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)));
        if (!unreadable || !unsearchable) {
            throw new AssertionError("presence controls need unprivileged DAC; a root or capability"
                    + " bypass is not coverage");
        }
        System.out.println("Unprivileged DAC refused the unreadable file and unsearchable directory probes");
    }

    private static List<Case> matrixCases() {
        List<Case> result = new ArrayList<>();
        // The header record, under header and slot writers: the header is the store's index.
        result.add(new Case("header retry", new Layout(LIVE_A).slot(A, SLOT_A), null,
                store -> store.writeHeader(LIVE_A, LIVE_A)));
        result.add(new Case("header creation", new Layout(LIVE_A).slot(A, SLOT_A), null,
                store -> store.writeHeader(LIVE_A, CREATING_B)));
        result.add(new Case("header omission", new Layout(RELEASING_B).slot(A, SLOT_A), null,
                store -> omission(store), true));
        result.add(new Case("header released", new Layout(RELEASED_B).slot(A, SLOT_A), null,
                store -> store.confirmReleasedSlot(RELEASED_B, B), true));
        result.add(new Case("header binding update", new Layout(LIVE_A).slot(A, SLOT_A), null,
                store -> update(store)));
        // The target slot record under each of its writers.
        result.add(new Case("slot update", new Layout(LIVE_A).slot(A, SLOT_A), A,
                store -> update(store)));
        result.add(new Case("slot confirm", new Layout(LIVE_A).slot(A, SLOT_A), A,
                store -> store.confirmExistingSlot(SLOT_A)));
        result.add(new Case("slot removal", new Layout(RELEASING_B).slot(A, SLOT_A)
                .slot(B, TOMBSTONE_B), B, store -> store.removeReleasingSlot(RELEASING_B, B), true));
        result.add(new Case("slot resume", new Layout(CREATING_C).slot(A, SLOT_A).slot(B, SLOT_B)
                .empty(C), C, store -> store.resumeCreatingDirectory(CREATING_C, C)));
        result.add(new Case("slot publish", new Layout(CREATING_C).slot(A, SLOT_A).slot(B, SLOT_B)
                .empty(C), C, store -> store.publishCreatingSlot(CREATING_C, SLOT_C)));
        // Store availability: unknown bytes in unrelated slot B refuse other writers too.
        result.add(new Case("unrelated update", new Layout(LIVE_AB).slot(A, SLOT_A)
                .slot(B, SLOT_B), B, store -> update(store)));
        result.add(new Case("unrelated creation", new Layout(LIVE_AB).slot(A, SLOT_A)
                .slot(B, SLOT_B), B, store -> store.writeHeader(LIVE_AB, CREATING_C)));
        return result;
    }

    private static View healthy(Case c) {
        if (c.lifecycle && earlier()) return healthyRefusal(c);
        View[] seen = new View[1];
        run(c.name + " / healthy", problems -> {
            Path root = c.layout.build(fresh().resolve("store"));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            View view = new View(store.load());
            boolean result = c.action.run(store);
            check(problems, result, "otherwise valid writer refused " + view);
            if (result) seen[0] = view;
        });
        return seen[0];
    }

    // A release step under an earlier format, on its healthy layout: it refuses before any effect,
    // with every byte, file identity, time and mode and the whole view unchanged. Its unreadable
    // positions then check the read side against this view.
    private static View healthyRefusal(Case c) {
        View[] seen = new View[1];
        run(format + " / " + c.name + " refused on its healthy layout", problems -> {
            Path top = fresh();
            Path root = c.layout.build(top.resolve("store"));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            age(top);
            Map<String, String> before = footprint(top);
            View view = new View(store.load());
            boolean result = c.action.run(store);
            check(problems, !result, "lifecycle write acknowledged under " + format);
            check(problems, footprint(top).equals(before), "store footprint changed");
            check(problems, new View(store.load()).equals(view), "view changed " + new View(store.load()));
            check(problems, !view.slots.containsValue(Status.UNSUPPORTED) && view.header == Status.VALID
                    && view.complete, "layout not healthy " + view);
            if (!result) seen[0] = view;
        });
        return seen[0];
    }

    // An intact newer frame in one position, unreadable while load() and the writer run. The
    // writer refuses before any effect. The newer bytes, every file identity and every known
    // hold stay, no creation is ready, and a copy position withdraws its record's eligibility.
    private static void unreadable(Case c, View healthy, At at) {
        run(c.name + " / unreadable newer " + at, problems -> {
            if (healthy == null) throw new AssertionError("healthy control failed");
            Path top = fresh();
            Path root = c.layout.build(top.resolve("store"));
            Path file = at(root, c.target, at);
            byte[] bytes = future(c.target);
            Files.write(file, bytes);
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            age(top);
            Map<String, String> before = footprint(top);
            View during = restricted(file, UNREADABLE, () -> new View(store.load()));
            boolean result = restricted(file, UNREADABLE, () -> c.action.run(store));
            check(problems, !result, "writer accepted beside unreadable bytes");
            check(problems, footprint(top).equals(before), "store footprint changed");
            check(problems, Arrays.equals(Files.readAllBytes(file), bytes), "newer bytes lost");
            check(problems, during.holds.equals(healthy.holds), "holds " + during.holds);
            check(problems, !during.ready, "creation ready beside unreadable bytes");
            boolean copy = at != At.SEED;
            Set<Integer> usable = new TreeSet<>(healthy.usable);
            if (copy && c.target == null) usable.clear();
            if (copy && c.target != null) usable.remove(c.target);
            check(problems, during.usable.equals(usable), "eligible " + during.usable);
            Status status = c.target == null ? during.header : during.slots.get(c.target);
            if (copy) {
                check(problems, status != Status.VALID && status != Status.MISSING,
                        "record read as " + status);
            }
            // Readable again, the same bytes are a recognized newer footprint.
            check(problems, store.load().unsupportedFootprint, "fixture is not an intact newer frame");
        });
    }

    private static void matrix() {
        for (Case c : matrixCases()) {
            View healthy = healthy(c);
            for (At at : At.values()) unreadable(c, healthy, at);
        }
        if (earlier()) retiringFlag();
    }

    // The version 1 retiring flag, a lifecycle write the earlier formats refuse on a healthy layout
    // before any effect. The generation step that follows shows that the layout takes updates.
    private static void retiringFlag() {
        run(format + " / retiring flag refused on its healthy layout", problems -> {
            Path top = fresh();
            Path root = new Layout(LIVE_A).slot(A, SLOT_A).build(top.resolve("store"));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            age(top);
            Map<String, String> before = footprint(top);
            View view = new View(store.load());
            check(problems, !store.updateExistingSlot(SLOT_A, RETIRING_A), "retiring flag written under " + format);
            check(problems, footprint(top).equals(before), "store footprint changed");
            check(problems, new View(store.load()).equals(view), "view changed");
            check(problems, update(store) && store.load().slots.get(A).value.equals(TOUCHED_A),
                    "generation step refused");
        });
    }

    // A release flow under an earlier format, on the layout where Format.V3 takes it: every step
    // refuses before any effect, with every byte, file identity, time and mode and the whole view
    // unchanged.
    private static void releaseRefused(String name, Layout layout, Action... steps) {
        releaseRefused(name, layout, null, null, steps);
    }

    // The same, with each step also called while one fixture path is restricted, as the Format.V3
    // case restricts it.
    private static void releaseRefused(String name, Layout layout, String restrict, String mode, Action... steps) {
        run(format + " / " + name + " refused before any effect", problems -> {
            Path top = fresh();
            Path root = layout.build(top.resolve("store"));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            age(top);
            Map<String, String> before = footprint(top);
            View view = new View(store.load());
            for (int i = 0; i < steps.length; i++) {
                Action step = steps[i];
                check(problems, !step.run(store), "step " + i + " acknowledged under " + format);
                if (restrict != null) {
                    check(problems, !restricted(root.resolve(restrict), mode, () -> step.run(store)),
                            "step " + i + " acknowledged under a restricted path");
                }
            }
            check(problems, footprint(top).equals(before), "store footprint changed");
            check(problems, new View(store.load()).equals(view), "view changed " + new View(store.load()));
        });
    }

    // One writer call while exactly one fixture path is restricted. It refuses before any
    // effect. Every known hold stays visible and no creation is ready while it is restricted.
    private static void refused(String name, Layout layout, String restrict, String mode,
            Action action, Extra extra) {
        refused(name, layout, restrict, mode, action, extra, false);
    }

    // A lifecycle call refuses under the earlier formats whatever the restriction: there it is
    // first called with nothing restricted, as the format refusal control, so that the restricted
    // call's refusal is not taken for the restriction's.
    private static void refused(String name, Layout layout, String restrict, String mode,
            Action action, Extra extra, boolean lifecycle) {
        run(name, problems -> {
            Path top = fresh();
            Path root = layout.build(top.resolve("store"));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            View healthy = new View(store.load());
            age(top);
            Map<String, String> before = footprint(top);
            if (lifecycle && earlier()) {
                check(problems, !action.run(store) && footprint(top).equals(before)
                        && new View(store.load()).equals(healthy), "no format refusal under " + format);
            }
            Path path = root.resolve(restrict);
            View during = restricted(path, mode, () -> new View(store.load()));
            boolean result = restricted(path, mode, () -> action.run(store));
            check(problems, !result, "acknowledged through an unobservable path");
            check(problems, footprint(top).equals(before), "store footprint changed");
            check(problems, during.holds.equals(healthy.holds), "holds " + during.holds);
            check(problems, !during.ready, "creation ready while a path is unobservable " + during);
            extra.check(healthy, during, problems);
        });
    }

    // A listable namespace or slot whose entries cannot be stat'ed. The previous store read
    // that as absence, acknowledged the RELEASING directory removal and omitted its entry.
    private static void unsearchable() {
        Layout releasing = new Layout(RELEASING_B).slot(A, SLOT_A).slot(B, TOMBSTONE_B);
        Extra neither = (healthy, during, problems) -> {
            for (int appId : List.of(A, B)) {
                Status status = during.slots.get(appId);
                check(problems, status != Status.VALID && status != Status.MISSING,
                        appId + " read as " + status);
            }
        };
        refused("unsearchable namespace / RELEASING removal", releasing, "slots", UNSEARCHABLE,
                store -> store.removeReleasingSlot(RELEASING_B, B), neither, true);
        refused("unsearchable namespace / RELEASING omission", releasing, "slots", UNSEARCHABLE,
                store -> omission(store), neither, true);
        refused("unsearchable namespace / release confirmation",
                new Layout(RELEASED_B).slot(A, SLOT_A).slot(B, TOMBSTONE_B), "slots", UNSEARCHABLE,
                store -> store.confirmReleasedSlot(RELEASED_B, B), neither, true);
        refused("unsearchable namespace / creation directory",
                new Layout(CREATING_C).slot(A, SLOT_A).slot(B, SLOT_B), "slots", UNSEARCHABLE,
                store -> store.ensureFreshSlot(CREATING_C, C), NOTHING);
        refused("unsearchable namespace / creation reservation",
                new Layout(LIVE_AB).slot(A, SLOT_A).slot(B, SLOT_B), "slots", UNSEARCHABLE,
                store -> store.writeHeader(LIVE_AB, CREATING_C), NOTHING);
        refused("unsearchable slot / RELEASING removal", releasing, "slots/" + B, UNSEARCHABLE,
                store -> store.removeReleasingSlot(RELEASING_B, B), (healthy, during, problems) -> {
                    Status status = during.slots.get(B);
                    check(problems, status != Status.VALID && status != Status.MISSING,
                            "slot read as " + status);
                    check(problems, during.usable.equals(Set.of(A)), "eligible " + during.usable);
                }, true);
        refused("unsearchable slot / unrelated update",
                new Layout(LIVE_AB).slot(A, SLOT_A).slot(B, SLOT_B), "slots/" + B, UNSEARCHABLE,
                store -> update(store), (healthy, during, problems) ->
                check(problems, during.usable.equals(Set.of(A)), "eligible " + during.usable));
        run("unsearchable root / not a missing store", problems -> {
            Path top = fresh();
            Path root = new Layout(LIVE_A).slot(A, SLOT_A).build(top.resolve("store"));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            age(top);
            Map<String, String> before = footprint(top);
            View during = restricted(root, UNSEARCHABLE, () -> new View(store.load()));
            boolean initialized = restricted(root, UNSEARCHABLE, () -> store.initializeNew(LINEAGE));
            boolean updated = restricted(root, UNSEARCHABLE,
                    () -> update(store));
            check(problems, during.header != Status.MISSING && during.header != Status.VALID,
                    "header read as " + during.header);
            check(problems, !during.complete && !during.ready && during.usable.isEmpty(),
                    "view " + during);
            check(problems, !initialized && !updated, "writer acknowledged through an unsearchable root");
            check(problems, footprint(top).equals(before), "store footprint changed");
        });
    }

    // Write permission refused, stat and read allowed: genuine absence still continues, and
    // a failed effect is never acknowledged or left partial. Under the earlier formats the release
    // steps refuse on these layouts before any effect, restricted or not.
    private static void readOnly() {
        if (earlier()) {
            releaseRefused("read-only namespace / genuine absence", new Layout(RELEASING_B).slot(A, SLOT_A),
                    "slots", READ_ONLY, store -> store.removeReleasingSlot(RELEASING_B, B), store -> omission(store));
        } else run("read-only namespace / genuine absence continues", problems -> {
            Path root = new Layout(RELEASING_B).slot(A, SLOT_A).build(fresh().resolve("store"));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            boolean removed = restricted(root.resolve("slots"), READ_ONLY,
                    () -> store.removeReleasingSlot(RELEASING_B, B));
            check(problems, removed, "genuine ENOENT refused under a read-only namespace");
            check(problems, omission(store), "omission refused");
            check(problems, new View(store.load()).holds.equals(Set.of(A)), "holds");
        });
        run("read-only namespace / creation directory refused", problems -> {
            Path top = fresh();
            Path root = new Layout(CREATING_C).slot(A, SLOT_A).slot(B, SLOT_B)
                    .build(top.resolve("store"));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            age(top);
            Path slots = root.resolve("slots");
            Map<String, String> before = footprint(slots);
            boolean made = restricted(slots, READ_ONLY, () -> store.ensureFreshSlot(CREATING_C, C));
            check(problems, !made, "creation acknowledged without its directory");
            check(problems, footprint(slots).equals(before), "slot namespace changed");
            check(problems, store.ensureFreshSlot(CREATING_C, C), "writable retry refused");
        });
        if (earlier()) {
            releaseRefused("read-only slot / removal", new Layout(RELEASING_B).slot(A, SLOT_A).slot(B, TOMBSTONE_B),
                    "slots/" + B, READ_ONLY, store -> store.removeReleasingSlot(RELEASING_B, B));
        } else run("read-only slot / removal keeps every copy", problems -> {
            Path top = fresh();
            Path root = new Layout(RELEASING_B).slot(A, SLOT_A).slot(B, TOMBSTONE_B)
                    .build(top.resolve("store"));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            age(top);
            Path slots = root.resolve("slots");
            Map<String, String> before = footprint(slots);
            boolean removed = restricted(slots.resolve(Integer.toString(B)), READ_ONLY,
                    () -> store.removeReleasingSlot(RELEASING_B, B));
            check(problems, !removed, "removal acknowledged without unlinking");
            check(problems, footprint(slots).equals(before), "slot copies changed");
            check(problems, store.removeReleasingSlot(RELEASING_B, B), "writable retry refused");
        });
    }

    // A real ENOENT: each owned transaction continues after a lost reply. Under the earlier formats
    // the release flows refuse before any effect on the same layouts.
    private static void genuineAbsence() {
        if (earlier()) {
            releaseRefused("genuine absence / RELEASING continuation", new Layout(RELEASING_B).slot(A, SLOT_A),
                    store -> store.removeReleasingSlot(RELEASING_B, B), store -> omission(store),
                    store -> store.confirmReleasedSlot(RELEASED_B, B));
            releaseRefused("genuine absence / owned retirement",
                    new Layout(RELEASING_B).slot(A, SLOT_A).slot(B, TOMBSTONE_B),
                    store -> store.removeReleasingSlot(RELEASING_B, B), store -> omission(store),
                    store -> store.confirmReleasedSlot(RELEASED_B, B));
        } else {
            run("genuine absence / RELEASING continuation", problems -> {
                Path root = new Layout(RELEASING_B).slot(A, SLOT_A).build(fresh().resolve("store"));
                NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
                check(problems, store.removeReleasingSlot(RELEASING_B, B), "absent directory not continued");
                check(problems, store.removeReleasingSlot(RELEASING_B, B), "retry not continued");
                check(problems, omission(store), "omission refused");
                check(problems, store.confirmReleasedSlot(RELEASED_B, B), "release not confirmed");
                View after = new View(store.load());
                check(problems, after.holds.equals(Set.of(A)) && after.ready, "view " + after);
            });
            run("genuine absence / owned retirement", problems -> {
                Path root = new Layout(RELEASING_B).slot(A, SLOT_A).slot(B, TOMBSTONE_B)
                        .build(fresh().resolve("store"));
                NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
                check(problems, store.removeReleasingSlot(RELEASING_B, B), "tombstone not removed");
                check(problems, !Files.exists(root.resolve("slots/" + B), LinkOption.NOFOLLOW_LINKS),
                        "directory remains");
                check(problems, store.removeReleasingSlot(RELEASING_B, B), "retry not continued");
                check(problems, omission(store), "omission refused");
                check(problems, store.confirmReleasedSlot(RELEASED_B, B), "release not confirmed");
                check(problems, new View(store.load()).holds.equals(Set.of(A)), "holds");
            });
        }
        ownedTransactions();
    }

    // The owned creation and initialization, which no format refuses, continue after a lost reply.
    private static void ownedTransactions() {
        run("genuine absence / owned creation", problems -> {
            Path root = new Layout(CREATING_C).slot(A, SLOT_A).slot(B, SLOT_B)
                    .build(fresh().resolve("store"));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            check(problems, store.resumeCreatingDirectory(CREATING_C, C), "absent directory not created");
            check(problems, store.publishCreatingSlot(CREATING_C, SLOT_C), "publication refused");
            check(problems, store.writeHeader(CREATING_C, LIVE_ABC), "completion refused");
            check(problems, new View(store.load()).usable.contains(C), "binding not usable");
        });
        run("genuine absence / store initialization", problems -> {
            Path root = fresh().resolve("store");
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            check(problems, store.initializeNew(LINEAGE), "absent root not initialized");
            check(problems, store.initializeNew(LINEAGE), "exact retry refused");
            View after = new View(store.load());
            check(problems, after.header == Status.VALID && after.ready && after.holds.isEmpty(),
                    "view " + after);
        });
    }

    // Links and special nodes are refused and never followed. A path below a file is ENOTDIR,
    // which is not absence, and a store root that is not a real directory is not missing.
    private static void aliases() {
        run("linked RELEASING slot / never followed", problems -> {
            Path top = fresh();
            Path root = new Layout(RELEASING_B).slot(A, SLOT_A).build(top.resolve("store"));
            Path foreign = Files.createDirectories(top.resolve("foreign/" + B));
            pair(foreign.resolve("record.bin"), NativeIdentityRecords.encodeSlot(TOMBSTONE_B));
            Path link = Files.createSymbolicLink(root.resolve("slots/" + B), foreign);
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            age(top);
            Map<String, String> outside = footprint(top.resolve("foreign"));
            check(problems, !store.removeReleasingSlot(RELEASING_B, B), "removal through a link");
            check(problems, !omission(store), "omission beside a link");
            View view = new View(store.load());
            check(problems, view.holds.contains(B) && view.slots.get(B) == Status.DAMAGED,
                    "view " + view);
            check(problems, footprint(top.resolve("foreign")).equals(outside), "foreign records changed");
            check(problems, Files.readSymbolicLink(link).equals(foreign), "link changed");
        });
        run("dangling RELEASING slot link / not absence", problems -> {
            Path top = fresh();
            Path root = new Layout(RELEASING_B).slot(A, SLOT_A).build(top.resolve("store"));
            Path nowhere = top.resolve("nowhere");
            Path link = Files.createSymbolicLink(root.resolve("slots/" + B), nowhere);
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            check(problems, !store.removeReleasingSlot(RELEASING_B, B), "dangling link read as removed");
            check(problems, !omission(store), "omission beside a dangling link");
            check(problems, Files.isSymbolicLink(link)
                    && !Files.exists(nowhere, LinkOption.NOFOLLOW_LINKS), "link or target changed");
            check(problems, new View(store.load()).holds.contains(B), "hold lost");
        });
        run("linked record copy / never followed", problems -> {
            Path top = fresh();
            Path root = new Layout(LIVE_A).slot(A, SLOT_A).build(top.resolve("store"));
            Path foreign = Files.createDirectories(top.resolve("foreign"));
            Files.write(foreign.resolve("record.bin"), NativeIdentityRecords.encodeSlot(SLOT_A));
            Path main = root.resolve("slots/" + A + "/record.bin");
            Files.delete(main);
            Files.createSymbolicLink(main, foreign.resolve("record.bin"));
            Files.write(Path.of(main + ".reservecopy"), GARBAGE);
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            age(top);
            Map<String, String> before = footprint(top);
            View view = new View(store.load());
            check(problems, view.slots.get(A) == Status.DAMAGED && !view.usable.contains(A),
                    "read through a link " + view);
            check(problems, !update(store), "wrote beside a linked copy");
            check(problems, footprint(top).equals(before), "store footprint changed");
        });
        run("special seed / never opened", problems -> {
            Path top = fresh();
            Path root = new Layout(LIVE_A).slot(A, SLOT_A).build(top.resolve("store"));
            socket(root.resolve("slots/" + A + "/record.bin-seed"));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            age(top);
            Map<String, String> before = footprint(top);
            View view = new View(store.load());
            check(problems, view.usable.contains(A), "a special seed withdrew the binding " + view);
            check(problems, !update(store), "wrote through a special seed");
            check(problems, footprint(top).equals(before), "store footprint changed");
        });
        run("special slot entry / ordinary damage", problems -> {
            Path root = new Layout(LIVE_A).slot(A, SLOT_A).build(fresh().resolve("store"));
            socket(root.resolve("slots/" + SPECIAL));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            View view = new View(store.load());
            check(problems, view.holds.contains(SPECIAL) && view.slots.get(SPECIAL) == Status.DAMAGED
                    && !view.ready && view.usable.contains(A), "view " + view);
            check(problems, update(store), "unrelated damage froze writers");
        });
        run("file slot entry / refused, never read below", problems -> {
            Path top = fresh();
            Path root = new Layout(RELEASING_B).slot(A, SLOT_A).build(top.resolve("store"));
            Files.write(root.resolve("slots/" + B), NativeIdentityRecords.encodeSlot(TOMBSTONE_B));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            age(top);
            Map<String, String> before = footprint(root.resolve("slots"));
            check(problems, !store.removeReleasingSlot(RELEASING_B, B), "removal through a file entry");
            check(problems, !omission(store), "omission beside a file entry");
            View view = new View(store.load());
            check(problems, view.holds.contains(B) && view.slots.get(B) == Status.DAMAGED,
                    "view " + view);
            check(problems, footprint(root.resolve("slots")).equals(before), "slot entry changed");
        });
        run("namespace is a file / ENOTDIR is not absence", problems -> {
            Path top = fresh();
            Path root = Files.createDirectories(top.resolve("store"));
            pair(root.resolve("store.bin"), NativeIdentityRecords.encodeHeader(RELEASED_B));
            Files.write(root.resolve("slots"), GARBAGE);
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            age(top);
            Map<String, String> before = footprint(top);
            View view = new View(store.load());
            check(problems, !view.complete && !view.ready && view.holds.equals(Set.of(A)),
                    "view " + view);
            check(problems, !store.confirmReleasedSlot(RELEASED_B, B), "absence acknowledged below a file");
            check(problems, !store.writeHeader(RELEASED_B, RELEASED_B), "header written beside a file");
            check(problems, footprint(top).equals(before), "store footprint changed");
        });
        run("store root is a file / not a missing store", problems -> {
            Path top = fresh();
            Path root = Files.write(top.resolve("store"), NativeIdentityRecords.encodeHeader(LIVE_A));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            age(top);
            Map<String, String> before = footprint(top);
            View view = new View(store.load());
            check(problems, view.header == Status.DAMAGED, "header read as " + view.header);
            check(problems, !view.complete && !view.ready && view.holds.isEmpty(), "view " + view);
            check(problems, !store.initializeNew(LINEAGE), "initialized over a file");
            check(problems, footprint(top).equals(before), "store footprint changed");
        });
        run("store root is a link / never followed", problems -> {
            Path top = fresh();
            Path elsewhere = new Layout(LIVE_A).slot(A, SLOT_A).build(top.resolve("elsewhere"));
            Path root = Files.createSymbolicLink(top.resolve("store"), elsewhere);
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            age(top);
            Map<String, String> before = footprint(top);
            View view = new View(store.load());
            check(problems, view.header == Status.DAMAGED, "header read as " + view.header);
            check(problems, view.holds.isEmpty() && view.usable.isEmpty() && !view.ready,
                    "followed a linked store " + view);
            check(problems, !store.initializeNew(LINEAGE), "initialized through a link");
            check(problems, !update(store), "wrote through a linked store");
            check(problems, footprint(top).equals(before), "store footprint changed");
        });
    }

    // Parser damage in this store's own staging keeps its owned retry. The same torn bytes
    // that cannot be read are unknown: they may be newer, so they block instead.
    private static void seeds() {
        Layout creation = new Layout(CREATING_C).slot(A, SLOT_A).slot(B, SLOT_B).empty(C)
                .file(SEED_C, TORN_C);
        Layout removal = new Layout(RELEASING_B).slot(A, SLOT_A).slot(B, TOMBSTONE_B)
                .file(SEED_B, TORN_B);
        run("readable torn seed / owned creation retry", problems -> {
            Path root = creation.build(fresh().resolve("store"));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            check(problems, store.resumeCreatingDirectory(CREATING_C, C), "torn owned seed refused");
            check(problems, store.publishCreatingSlot(CREATING_C, SLOT_C), "owned publication refused");
            check(problems, new View(store.load()).slots.get(C) == Status.VALID, "publication missing");
        });
        refused("unreadable torn seed / creation resume", creation, SEED_C, UNREADABLE,
                store -> store.resumeCreatingDirectory(CREATING_C, C), NOTHING);
        refused("unreadable torn seed / creation publish", creation, SEED_C, UNREADABLE,
                store -> store.publishCreatingSlot(CREATING_C, SLOT_C), NOTHING);
        if (earlier()) {
            releaseRefused("readable torn seed / RELEASING removal", removal,
                    store -> store.removeReleasingSlot(RELEASING_B, B));
        } else run("readable torn seed / RELEASING removal", problems -> {
            Path root = removal.build(fresh().resolve("store"));
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            check(problems, store.removeReleasingSlot(RELEASING_B, B), "torn seed stopped owned removal");
            check(problems, !Files.exists(root.resolve("slots/" + B), LinkOption.NOFOLLOW_LINKS),
                    "directory remains");
        });
        refused("unreadable torn seed / RELEASING removal", removal, SEED_B, UNREADABLE,
                store -> store.removeReleasingSlot(RELEASING_B, B), NOTHING, true);
    }

    // An unreadable index copy may carry holds and a counter nobody can see. Neither a
    // readable older copy nor this writer may invent them or allocate below them.
    private static void nothingInvented() {
        run("unreadable index copy / no counter or hold from around it", problems -> {
            Path top = fresh();
            Path root = new Layout(LIVE_A).slot(A, SLOT_A).file("store.bin",
                    NativeIdentityRecords.encodeHeader(header(9, live(A), live(HIDDEN))))
                    .build(top.resolve("store"));
            Path main = root.resolve("store.bin");
            NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
            age(top);
            Map<String, String> before = footprint(top);
            View during = restricted(main, UNREADABLE, () -> new View(store.load()));
            boolean reserved = restricted(main, UNREADABLE, () -> store.writeHeader(LIVE_A, CREATING_B));
            check(problems, during.holds.equals(Set.of(A)), "holds " + during.holds);
            check(problems, during.header != Status.VALID && !during.ready && during.usable.isEmpty(),
                    "counter or binding from beside unknown bytes " + during);
            check(problems, !reserved, "reserved an ID below an unknown counter");
            check(problems, footprint(top).equals(before), "store footprint changed");
            check(problems, new View(store.load()).holds.equals(Set.of(A, HIDDEN)), "readable holds");
        });
    }

    // A record withdrawn for unreadable bytes keeps its decodable copies as negative evidence.
    // Leaving the valid set must not make a colliding binding usable, or withdraw another.
    private static void relatedBindings() {
        for (String kind : List.of("package", "incarnation", "unrelated")) {
            run("unreadable copy keeps negative " + kind + " evidence", problems -> {
                boolean unrelated = kind.equals("unrelated");
                Slot second = bound(B, kind.equals("package") ? PKG_A : PKG_B,
                        kind.equals("incarnation") ? 1 : 2, false, 1);
                Path root = new Layout(LIVE_AB).slot(A, SLOT_A).slot(B, second)
                        .build(fresh().resolve("store"));
                NativeIdentityStore store = new NativeIdentityStore(root.toFile(), format);
                View healthy = new View(store.load());
                View during = restricted(root.resolve("slots/" + A + "/record.bin"), UNREADABLE,
                        () -> new View(store.load()));
                check(problems, healthy.usable.contains(B) == unrelated, "collision control " + healthy);
                check(problems, during.usable.equals(unrelated ? Set.of(B) : Set.<Integer>of()),
                        "eligible " + during.usable);
                check(problems, during.slots.get(B) == (unrelated ? Status.VALID : Status.CONFLICT),
                        "slot read as " + during.slots.get(B));
                check(problems, during.holds.equals(Set.of(A, B)), "holds " + during.holds);
            });
        }
    }

    public static void main(String[] args) throws Exception {
        if (!NativeIdentityPresenceTest.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        if (args.length > 2 || (args.length == 2 && !args[1].equals("V1") && !args[1].equals("V2")
                && !args[1].equals("V3"))) {
            throw new IllegalArgumentException("usage: directory [V1|V2|V3]");
        }
        format = args.length == 2 ? NativeIdentityStore.Format.valueOf(args[1]) : NativeIdentityStore.Format.V1;
        headers();
        parent = Files.createDirectories(Path.of(args[0]).resolve("presence-" + format));
        requireDac();
        matrix();
        unsearchable();
        readOnly();
        genuineAbsence();
        aliases();
        seeds();
        nothingInvented();
        relatedBindings();
        if (!Os.allClosed()) failures.add("open descriptors");
        System.out.println(passed + " passed, " + failures.size() + " failed");
        if (!failures.isEmpty()) throw new AssertionError("failed: " + failures);
        System.out.println("Exact presence, unavailable bytes and aliases refused on unprivileged"
                + " host files under store format " + format + "; Android unqualified");
    }
}
