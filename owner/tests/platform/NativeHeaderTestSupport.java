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
 * Shared host fixtures of the header footprint tests: values, direct store layouts, exact file
 * footprints and a reopened host Package Manager facade. It uses only store, manager and
 * facade surface that predates the header footprint correction, so the same tests also run
 * against earlier sources as controls. Host files only, not Android persistence.
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
    static NativePrincipalPins.Record record(long id, String name, int appId) {
        return new NativePrincipalPins.Record(id, name, appId, 0, SERIAL);
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
    static NativeIdentityPersistence persistence(Path root) {
        return new NativeIdentityPersistence(new NativeIdentityStore(root.toFile()));
    }
    static NativeIdentityStore.Loaded loaded(Path root) {
        return new NativeIdentityStore(root.toFile()).load();
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
        PackageManagerService pm = new PackageManagerService(root, false);
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
        PackageManagerService pm = new PackageManagerService(fresh(), true);
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
