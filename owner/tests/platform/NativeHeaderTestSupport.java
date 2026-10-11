// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.HeaderEntry;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.SlotPhase;
import com.android.server.pm.NativeIdentityRecords.UserEntry;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Current host fixtures of the header fence tests: values, raw layouts, full file footprints and
 * explicit store and Package Manager formats. Reservations use CreationPlan with one signer row
 * per record. No historical API adapter is in the living assembly. Pinned older fixtures remain
 * separate controls. These files qualify host behavior, not Android persistence.
 */
final class NativeHeaderTestSupport {
    static final String LINEAGE = "0123456789abcdef0123456789abcdef";
    static final String FOREIGN = "fedcba9876543210fedcba9876543210";
    static final int B = 10000, C = 10001, A = 10002, R = 10003, D = 10004, E = 10005;
    static final String PKG_B = "dev.andrix.b", PKG_C = "dev.andrix.c", PKG_A = "dev.andrix.a",
            PKG_R = "dev.andrix.r", PKG_D = "dev.andrix.d", PKG_X = "dev.andrix.x";
    static final long SERIAL = 7;
    // The host facade's installed signer, so a restored binding can be rebound.
    static final Set<String> SIGNERS =
            Set.of("039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81");
    static final byte[] GARBAGE = {1, 2, 3};
    // Fixtures are aged, so any later write, rename or unlink shows in the footprint.
    private static final FileTime AGED = FileTime.fromMillis(86_400_000L);

    interface Body { void run(List<String> problems) throws Exception; }
    interface Write { boolean run() throws Exception; }

    private static final List<String> failures = new ArrayList<>();
    private static int passed, cases;
    private static Path base;

    static void start(Path directory) throws Exception {
        base = Files.createDirectories(directory);
    }

    static void run(String name, Body body) {
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

    /** Prints the totals and fails the run when any case failed. */
    static void finish(boolean descriptorsClosed) {
        if (!descriptorsClosed) failures.add("open descriptors");
        System.out.println(passed + " passed, " + failures.size() + " failed");
        if (!failures.isEmpty()) throw new AssertionError("failed: " + failures);
    }

    static void check(List<String> problems, boolean ok, String problem) {
        if (!ok) problems.add(problem);
    }

    // Entries in app ID order, as the codec requires, whatever order a case lists them in.
    static Header header(long lastId, HeaderEntry... entries) {
        List<HeaderEntry> sorted = new ArrayList<>(List.of(entries));
        sorted.sort(java.util.Comparator.comparingInt(entry -> entry.appId));
        return new Header(LINEAGE, lastId, sorted);
    }
    static HeaderEntry creating(int appId, long id, String name) {
        return new HeaderEntry(appId, SlotPhase.CREATING, id, name);
    }
    static HeaderEntry live(int appId) { return new HeaderEntry(appId, SlotPhase.LIVE, 0, ""); }
    static HeaderEntry releasing(int appId) { return new HeaderEntry(appId, SlotPhase.RELEASING, 0, ""); }
    static Slot bound(int appId, String name, long id, boolean retiring, long generation) {
        return new Slot(LINEAGE, appId, name, generation, SIGNERS,
                List.of(new UserEntry(id, 0, SERIAL, retiring)));
    }
    static Slot tombstone(int appId, String name, long generation) {
        return new Slot(LINEAGE, appId, name, generation, SIGNERS, List.of());
    }
    // The release engine's ticketed tombstone of principal id, as the lifecycle format writes it.
    static Slot ticketed(int appId, String name, long id, long generation) {
        return new Slot(LINEAGE, appId, name, generation, SIGNERS, List.of(),
                new NativeIdentityRecords.ReleaseTicket(id, 0, SERIAL, "7".repeat(32)));
    }
    static NativeIdentityStore lifecycleStore(Path root) {
        return new NativeIdentityStore(root.toFile(), NativeIdentityStore.Format.V3);
    }
    // The account user's retirement block with every kind outstanding, as the lifecycle writers write it.
    static NativeIdentityRecords.Retirement retirementBlock() {
        List<NativeIdentityRecords.Obligation> outstanding = new java.util.ArrayList<>();
        for (NativeIdentityRecords.ObligationKind kind : NativeIdentityRecords.ObligationKind.values()) {
            outstanding.add(new NativeIdentityRecords.Obligation(kind,
                    NativeIdentityRecords.ObligationState.OUTSTANDING, NativeIdentityRecords.NO_REFERENCE, 0, 0));
        }
        return new NativeIdentityRecords.Retirement(NativeIdentityRecords.ActorClass.ACCOUNT_USER, 0, SERIAL,
                NativeIdentityRecords.NO_REFERENCE, 1_700_000_000_100L, outstanding);
    }
    static final String FORMAT_REFUSAL = "Native lifecycle records need the lifecycle format";
    // The earlier formats, each of which refuses every lifecycle write.
    static final List<NativeIdentityStore.Format> EARLIER =
            List.of(NativeIdentityStore.Format.V1, NativeIdentityStore.Format.V2);
    private static int twins;

    // Retirement under an earlier format: the lifecycle record's retirement, the one that survives,
    // refuses with the format refusal before any effect, with every byte, file identity and time of the
    // store and the pin's phase unchanged. So does the same account's under each earlier format, on a
    // copy of this state (twinsRefused).
    static boolean retirementRefused(Path root, NativePrincipalManager manager, NativePrincipalManager.Handle handle)
            throws Exception {
        age(root);
        Map<String, String> before = footprint(root);
        NativePrincipalPins.Phase phase = manager.phase(handle);
        NativePrincipalPins.Record identity = manager.identity(handle);
        try {
            manager.beginRetirement(handle, retirementBlock());
            return false;
        } catch (IllegalStateException refused) {
            if (!FORMAT_REFUSAL.equals(refused.getMessage()) || !footprint(root).equals(before)
                    || manager.phase(handle) != phase) {
                return false;
            }
        }
        return twinsRefused(root, identity);
    }

    interface StoreWrite { boolean run(NativeIdentityStore store) throws Exception; }

    // A lifecycle write under the earlier formats: on this version 1 state it refuses before any
    // effect, with every byte, file identity and time unchanged, and so it does under Format.V2, which
    // reads the same state as it is, on a copy of its bytes.
    static void refusedUnderEarlierFormats(List<String> problems, Path root, String what, StoreWrite write)
            throws Exception {
        Path copy = twin(root, NativeIdentityStore.Format.V2);
        unchanged(problems, root, what, () -> write.run(store(root)));
        age(copy);
        Map<String, String> before = footprint(copy);
        check(problems, !write.run(new NativeIdentityStore(copy.toFile(), earlier(NativeIdentityStore.Format.V2))),
                what + " acknowledged under Format.V2");
        check(problems, footprint(copy).equals(before), what + " changed the Format.V2 twin");
    }

    // A copy of this state for a twin under an earlier format. Version 1 reads no version 2 header,
    // so under Format.V1 each version 2 header copy is relabeled as version 1, its creation bindings
    // dropped: the state a version 1 writer would have left. Slot bodies stay as they are.
    private static NativeIdentityStore.Format earlier(NativeIdentityStore.Format format) {
        if (format != NativeIdentityStore.Format.V1 && format != NativeIdentityStore.Format.V2) {
            throw new IllegalArgumentException("refusal twins are earlier formats only");
        }
        return format;
    }

    static Path twin(Path root, NativeIdentityStore.Format format) throws Exception {
        Path copy = root.resolveSibling(root.getFileName() + "-twin" + ++twins + "-" + format);
        List<Path> paths;
        try (var walk = Files.walk(root)) {
            paths = walk.toList();
        }
        for (Path path : paths) {
            Path target = copy.resolve(root.relativize(path).toString());
            if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) Files.createDirectories(target);
            else if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) Files.copy(path, target);
            else throw new AssertionError("a refusal twin copies files and directories only: " + path);
        }
        if (format == NativeIdentityStore.Format.V1) {
            for (String name : List.of("store.bin", "store.bin.reservecopy", "store.bin-backup", "store.bin-seed")) {
                Path file = copy.resolve(name);
                if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) continue;
                Header header;
                try {
                    header = NativeIdentityRecords.decodeHeader(Files.readAllBytes(file));
                } catch (RuntimeException damage) {
                    continue;
                }
                if (header.version == 1) continue;
                List<HeaderEntry> entries = new ArrayList<>();
                for (HeaderEntry entry : header.entries) {
                    entries.add(new HeaderEntry(entry.appId, entry.phase, entry.creationId, entry.creationPackage));
                }
                Files.write(file, NativeIdentityRecords.encodeHeader(
                        new Header(header.lineage, header.lastId, entries)));
            }
        }
        return copy;
    }

    // The same account under each earlier format, reopened on a copy of this state: where that format
    // restores its pin, its retirement refuses with the format refusal before any effect, with every
    // byte, file identity and time of the copy and the twin pin's phase unchanged. An account that has
    // no published body restores no pin under a format that reads no history for it, such as a
    // reservation under Format.V1: no retirement exists there to refuse, and the twin says so. One
    // with a published body always restores its pin.
    static boolean twinsRefused(Path root, NativePrincipalPins.Record identity) throws Exception {
        for (NativeIdentityStore.Format format : EARLIER) {
            Path copy = twin(root, format);
            age(copy);
            Map<String, String> beforeRestore = footprint(copy);
            PackageManagerService pm = new PackageManagerService(copy, false, earlier(format));
            pm.mSettings.restoreAfterPackageSettings();
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle handle = manager.find(identity.packageName, identity.userId);
            if (handle == null) {
                NativeIdentityStore.ReadResult<Slot> body =
                        new NativeIdentityStore(copy.toFile(), earlier(format)).load().slots.get(identity.appId);
                if (body != null && body.status == NativeIdentityStore.Status.VALID) {
                    System.out.println("twin " + format + ": no pin beside a published body of "
                            + identity.packageName);
                    return false;
                }
                if (!footprint(copy).equals(beforeRestore)) {
                    System.out.println("twin " + format + ": no pin but store changed for " + identity.packageName);
                    return false;
                }
                System.out.println("twin " + format + ": no pin and no store write for " + identity.packageName);
                continue;
            }
            age(copy);
            Map<String, String> before = footprint(copy);
            NativePrincipalPins.Phase phase = manager.phase(handle);
            try {
                manager.beginRetirement(handle, retirementBlock());
                System.out.println("twin " + format + ": retirement accepted for " + identity.packageName);
                return false;
            } catch (IllegalStateException refused) {
                if (!FORMAT_REFUSAL.equals(refused.getMessage()) || !footprint(copy).equals(before)
                        || manager.phase(handle) != phase) {
                    System.out.println("twin " + format + ": not refused before any effect: " + refused.getMessage());
                    return false;
                }
            }
            System.out.println("twin " + format + ": refused for " + identity.packageName);
        }
        return true;
    }
    static NativePrincipalPins.Record record(long id, String name, int appId) {
        return new NativePrincipalPins.Record(id, name, appId, 0, SERIAL);
    }
    // An explicit owned signer row for every record of the snapshot: the B0 equivalent plan.
    static Map<Long, Set<String>> rows(NativePrincipalPins.Snapshot snapshot) {
        Map<Long, Set<String>> rows = new TreeMap<>();
        for (NativePrincipalPins.Record record : snapshot.records) rows.put(record.id, SIGNERS);
        return rows;
    }
    static Header project(NativeIdentityPersistence persistence, NativeIdentityStore.Loaded loaded,
            NativePrincipalPins.Snapshot snapshot) {
        return persistence.projectReservation(loaded,
                new NativeIdentityPersistence.CreationPlan(snapshot, rows(snapshot)));
    }
    static boolean reserve(NativeIdentityPersistence persistence,
            NativePrincipalPins.Snapshot snapshot) {
        return persistence.reservePending(
                new NativeIdentityPersistence.CreationPlan(snapshot, rows(snapshot)));
    }
    static byte[] bytes(Header header) { return NativeIdentityRecords.encodeHeader(header); }

    static Path fresh() throws Exception {
        return Files.createDirectory(base.resolve("c" + ++cases)).resolve("store");
    }
    // A store with these header copies and no slot. A null copy is absent.
    static Path layout(byte[] backup, byte[] main, byte[] reserve) throws Exception {
        Path root = fresh();
        Files.createDirectories(root.resolve("slots"));
        copies(root, backup, main, reserve);
        return root;
    }
    // Replaces the header copies of an existing store. A null copy is removed.
    static void copies(Path root, byte[] backup, byte[] main, byte[] reserve) throws Exception {
        Map<String, byte[]> files = new TreeMap<>();
        files.put("store.bin", main);
        files.put("store.bin.reservecopy", reserve);
        files.put("store.bin-backup", backup);
        for (Map.Entry<String, byte[]> file : files.entrySet()) {
            Path path = root.resolve(file.getKey());
            Files.deleteIfExists(path);
            if (file.getValue() != null) Files.write(path, file.getValue());
        }
    }
    // What an older writer leaves when its write of next over the selected prior stopped
    // once both new copies were complete: the preferred backup still holds prior.
    static Path legacy(Header prior, Header next) throws Exception {
        return layout(bytes(prior), bytes(next), bytes(next));
    }
    static void slot(Path root, int appId, Slot body) throws Exception {
        Path directory = Files.createDirectory(root.resolve("slots/" + appId));
        Files.write(directory.resolve("record.bin"), NativeIdentityRecords.encodeSlot(body));
        Files.write(directory.resolve("record.bin.reservecopy"), NativeIdentityRecords.encodeSlot(body));
    }
    static NativeIdentityStore store(Path root) {
        return new NativeIdentityStore(root.toFile(), NativeIdentityStore.Format.V1);
    }
    // The host facade under Format.V1, which these fixtures write, never the facade's default.
    static PackageManagerService legacyPm(Path root, boolean initialize) {
        return new PackageManagerService(root, initialize, NativeIdentityStore.Format.V1);
    }
    static NativeIdentityPersistence persistence(Path root) {
        return new NativeIdentityPersistence(store(root));
    }
    static NativeIdentityStore.Loaded loaded(Path root) {
        return store(root).load();
    }
    static Header stored(Path root) {
        return loaded(root).header.value;
    }
    static boolean holds(Path root, String name, Header header) throws Exception {
        Path path = root.resolve(name);
        return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                && Arrays.equals(Files.readAllBytes(path), bytes(header));
    }

    static void age(Path root) throws Exception {
        List<Path> paths;
        try (var walk = Files.walk(root)) {
            paths = walk.toList();
        }
        for (Path path : paths) {
            BasicFileAttributes attrs = Files.readAttributes(path, BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS);
            if (attrs.isRegularFile() || attrs.isDirectory()) Files.setLastModifiedTime(path, AGED);
        }
    }
    // Content, file identity and modification time of every path below root.
    static Map<String, String> footprint(Path root) throws Exception {
        Map<String, String> result = new TreeMap<>();
        List<Path> paths;
        try (var walk = Files.walk(root)) {
            paths = walk.toList();
        }
        for (Path path : paths) {
            BasicFileAttributes attrs = Files.readAttributes(path, BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS);
            result.put(root.relativize(path).toString(), attrs.fileKey() + " "
                    + attrs.lastModifiedTime() + " " + (attrs.isRegularFile()
                    ? Base64.getEncoder().encodeToString(Files.readAllBytes(path)) : "directory"));
        }
        return result;
    }
    // The store root entry and its header record paths only.
    static Map<String, String> headerFootprint(Path root) throws Exception {
        Map<String, String> result = new TreeMap<>(footprint(root));
        result.keySet().removeIf(name -> !name.isEmpty() && !name.startsWith("store.bin"));
        return result;
    }
    // Refused before any effect: false, and every byte, file identity and time unchanged.
    static void unchanged(List<String> problems, Path root, String what, Write write)
            throws Exception {
        age(root);
        Map<String, String> before = footprint(root);
        boolean result = write.run();
        check(problems, !result, what + " acknowledged");
        check(problems, footprint(root).equals(before), what + " changed the store");
    }

    // A new PMS over the same files: ordinary package settings first, then the store restore.
    static PackageManagerService reopen(Path root, Map<String, Integer> packages) {
        PackageManagerService pm = legacyPm(root, false);
        for (Map.Entry<String, Integer> entry : packages.entrySet()) {
            pm.mSettings.add(entry.getKey(), entry.getValue());
        }
        pm.mSettings.restoreAfterPackageSettings();
        return pm;
    }
    // A reopened registry restores exactly this counter, or none when counter is negative.
    static void bootCounter(List<String> problems, Path root, long counter) {
        PackageManagerService pm = reopen(root, Map.of());
        boolean known = pm.mSettings.pins.hasKnownCounter();
        if (counter < 0) {
            check(problems, !known, "a reopened registry restored a counter");
        } else {
            check(problems, known && pm.mSettings.pins.snapshotForWrite().lastId == counter,
                    "a reopened registry did not restore counter " + counter);
        }
        check(problems, pm.mSettings.nativePrincipalCreationReadyLPr() == (counter >= 0),
                "reopened creation readiness " + (counter < 0));
    }
    // A live PMS over a new store, with the subject packages installed.
    static PackageManagerService livePm() throws Exception {
        PackageManagerService pm = legacyPm(fresh(), true);
        pm.mSettings.add(PKG_B, B);
        pm.mSettings.add(PKG_C, C);
        pm.mSettings.add(PKG_A, A);
        return pm;
    }
    // Reads the store again into the live facade, as the manager does after each write.
    static void observe(PackageManagerService pm) {
        pm.mSettings.observeNativeIdentityStoreLPw(pm.mSettings.persistence.load());
    }
    static NativeIdentityStore.Loaded missing() {
        return new NativeIdentityStore.Loaded(new NativeIdentityStore.ReadResult<>(
                NativeIdentityStore.Status.MISSING, null, List.of()), Map.of(), Set.of(), true, false);
    }

    private NativeHeaderTestSupport() {}
}
