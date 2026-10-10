// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.nativelab;

import com.android.server.pm.NativeIdentityRecords;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Stream;

/**
 * Controlled lab input and byte predictions for the optional header only recovery rehearsal,
 * through the actual record codec only. It generates one empty version 1 store with a fresh
 * lineage, as the store's own initialization encodes it, or three predicted records in files
 * that are not a store layout. It is no initializer, designation, PackageSetting, UID allocation,
 * user data, key file or publication. Its output is lab input or prediction, never authority.
 *
 * <p>It also generates the store layouts that the lifecycle record's guest rows start from: the
 * subject's retiring version 1 body, the subject's version 2 slot, a version 2 slot of another
 * package beside the subject's bound reservation, and a version 2 slot naming the subject beside the
 * subject's valid body. Each is lab input for a staged guest boot, never a writer's output.
 */
public final class LabHistoryStore {
    /** The writer fixture's fixed subject. */
    public static final String SUBJECT = "dev.andrix.proof.principalclosed";
    /** The writer fixture's fixed development signer digest. */
    public static final String FIXTURE_SIGNER =
            "874cedf46661e33d62b711b266c96e629d1f64007e55350a59a167c9c23183d3";
    /** The only user the manager supports. */
    public static final int USER = 0;
    /** The first principal ID a fresh lineage issues. */
    public static final long FIRST_ID = 1;
    static final String HEADER = "store.bin";
    static final String RESERVE = "store.bin.reservecopy";
    static final String SLOTS = "slots";
    static final String MANIFEST = "prediction.json";
    static final String CREATING = "v2-creating-header.bin";
    static final String LIVE = "v2-live-header.bin";
    static final String BODY = "v2-slot-body.bin";
    /** The lifecycle guest layouts, by mode. */
    public static final Set<String> LIFECYCLE_MODES = Set.of("retiring-v1", "v2-slot", "v2-beside-reservation",
            "v2-beside-sibling");
    /** The other account's package in the reservation companion. */
    public static final String OTHER = "dev.andrix.proof.lifecycleother";
    /** USER_PAUSED in the suspension reason registry. */
    static final int USER_PAUSED = 1;
    /** The suspension's fixed wall clock time, informational. */
    static final long SUSPENDED_AT = 1_700_000_000_000L;
    private static final String DIRECTORY_MODE = "rwx------";
    private static final String FILE_MODE = "rw-------";

    private LabHistoryStore() {}

    /** Exactly 32 lowercase hex digits, or IllegalArgumentException. */
    public static String lineage(String value) {
        if (value == null || !value.matches("[0-9a-f]{32}")) {
            throw new IllegalArgumentException("lineage of 32 lowercase hex digits required");
        }
        return value;
    }

    /** An ordinary app ID from 10000 to 19999 in canonical decimal, or IllegalArgumentException. */
    public static int appId(String value) {
        if (value == null || !value.matches("1[0-9]{4}")) {
            throw new IllegalArgumentException("ordinary app ID required");
        }
        return Integer.parseInt(value);
    }

    /** A user serial in canonical decimal, not negative, or IllegalArgumentException. */
    public static long serial(String value) {
        if (value == null || !value.matches("0|[1-9][0-9]{0,18}")) {
            throw new IllegalArgumentException("user serial required");
        }
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException overflow) {
            throw new IllegalArgumentException("user serial required");
        }
    }

    /** The first principal ID of a fresh lineage, exactly "1", or IllegalArgumentException. */
    public static long principal(String value) {
        if (!"1".equals(value)) {
            throw new IllegalArgumentException("principal ID 1 of a fresh lineage required");
        }
        return FIRST_ID;
    }

    /** The empty version 1 header that initialization writes for this lineage. */
    public static byte[] emptyHeader(String lineage) {
        return NativeIdentityRecords.encodeHeader(
                new NativeIdentityRecords.Header(lineage(lineage), 0, List.of()));
    }

    /** The predicted version 2 header of the first creation, with its complete binding. */
    public static byte[] creatingHeader(String lineage, int appId, long serial, Set<String> signers) {
        return NativeIdentityRecords.encodeHeader(NativeIdentityRecords.Header.newV2(lineage(lineage),
                FIRST_ID, List.of(new NativeIdentityRecords.HeaderEntry(appId,
                        NativeIdentityRecords.SlotPhase.CREATING, FIRST_ID, SUBJECT,
                        new NativeIdentityRecords.CreationBinding(USER, serial, signers)))));
    }

    /** The predicted version 2 header after publication: the same entry LIVE, counter 1. */
    public static byte[] liveHeader(String lineage, int appId) {
        return NativeIdentityRecords.encodeHeader(NativeIdentityRecords.Header.newV2(lineage(lineage),
                FIRST_ID, List.of(new NativeIdentityRecords.HeaderEntry(appId,
                        NativeIdentityRecords.SlotPhase.LIVE, 0, ""))));
    }

    /** The predicted generation 1 body of the first creation. */
    public static byte[] body(String lineage, int appId, long serial, Set<String> signers) {
        return NativeIdentityRecords.encodeSlot(new NativeIdentityRecords.Slot(lineage(lineage), appId,
                SUBJECT, 1, signers, List.of(new NativeIdentityRecords.UserEntry(FIRST_ID, USER, serial,
                        false))));
    }

    /** The subject's version 1 body with its retiring flag: a legacy marker. */
    public static NativeIdentityRecords.Slot retiringBody(String lineage, int appId, long serial, Set<String> signers) {
        return new NativeIdentityRecords.Slot(lineage(lineage), appId, SUBJECT, 1, signers,
                List.of(new NativeIdentityRecords.UserEntry(FIRST_ID, USER, serial, true)));
    }

    /** A version 2 slot suspended by its own user, at generation 2. */
    public static NativeIdentityRecords.Slot suspended(String lineage, int appId, String packageName, long principal,
            long serial, Set<String> signers) {
        NativeIdentityRecords.Suspension entry = new NativeIdentityRecords.Suspension(
                NativeIdentityRecords.ActorClass.ACCOUNT_USER, 0, USER, serial, "0".repeat(32), USER_PAUSED,
                SUSPENDED_AT, null);
        return new NativeIdentityRecords.Slot(lineage(lineage), appId, packageName, 2, signers,
                List.of(new NativeIdentityRecords.UserEntry(principal, USER, serial, new NativeIdentityRecords.Lifecycle(
                        NativeIdentityRecords.LifecycleState.ELIGIBLE, List.of(entry), null))));
    }

    /**
     * The files of one lifecycle guest layout, by path relative to the store, through the actual codec.
     * otherAppId is used by the two companion modes only.
     */
    public static Map<String, byte[]> lifecycleLayout(String mode, String lineage, int appId, int otherAppId,
            long serial, Set<String> signers) {
        if (!LIFECYCLE_MODES.contains(mode) || signers == null || signers.size() != 1) {
            throw new IllegalArgumentException("lifecycle mode and one signer required");
        }
        boolean companion = mode.startsWith("v2-beside-");
        if (companion && (otherAppId == appId || otherAppId < 10000 || otherAppId > 19999)) {
            throw new IllegalArgumentException("another ordinary app ID required");
        }
        Map<Integer, NativeIdentityRecords.HeaderEntry> entries = new TreeMap<>();
        Map<Integer, NativeIdentityRecords.Slot> slots = new TreeMap<>();
        NativeIdentityRecords.Header header;
        switch (mode) {
            case "retiring-v1" -> slots.put(appId, retiringBody(lineage, appId, serial, signers));
            case "v2-slot" -> slots.put(appId, suspended(lineage, appId, SUBJECT, FIRST_ID, serial, signers));
            case "v2-beside-reservation" -> {
                entries.put(appId, new NativeIdentityRecords.HeaderEntry(appId, NativeIdentityRecords.SlotPhase.CREATING,
                        FIRST_ID, SUBJECT, new NativeIdentityRecords.CreationBinding(USER, serial, signers)));
                slots.put(otherAppId, suspended(lineage, otherAppId, OTHER, FIRST_ID + 1, serial, signers));
            }
            default -> {
                slots.put(appId, NativeIdentityRecords.decodeSlot(body(lineage, appId, serial, signers)));
                slots.put(otherAppId, suspended(lineage, otherAppId, SUBJECT, FIRST_ID + 1, serial, signers));
            }
        }
        for (int id : slots.keySet()) {
            entries.putIfAbsent(id, new NativeIdentityRecords.HeaderEntry(id, NativeIdentityRecords.SlotPhase.LIVE, 0, ""));
        }
        long lastId = companion ? FIRST_ID + 1 : FIRST_ID;
        List<NativeIdentityRecords.HeaderEntry> list = List.copyOf(entries.values());
        header = mode.equals("v2-beside-reservation")
                ? NativeIdentityRecords.Header.newV2(lineage(lineage), lastId, list)
                : new NativeIdentityRecords.Header(lineage(lineage), lastId, list);
        Map<String, byte[]> files = new TreeMap<>();
        byte[] headerBytes = NativeIdentityRecords.encodeHeader(header);
        files.put(HEADER, headerBytes);
        files.put(RESERVE, headerBytes);
        for (Map.Entry<Integer, NativeIdentityRecords.Slot> slot : slots.entrySet()) {
            byte[] bytes = NativeIdentityRecords.encodeSlot(slot.getValue());
            files.put(SLOTS + "/" + slot.getKey() + "/record.bin", bytes);
            files.put(SLOTS + "/" + slot.getKey() + "/record.bin.reservecopy", bytes);
        }
        return files;
    }

    /**
     * One fresh lifecycle guest layout: the header pair and each slot's main and reserve, directories
     * 0700 and files 0600, and its manifest as the return value.
     */
    public static String generateLifecycle(Path output, String mode, String lineage, int appId, int otherAppId,
            long serial) throws IOException {
        Map<String, byte[]> files = lifecycleLayout(mode, lineage, appId, otherAppId, serial, Set.of(FIXTURE_SIGNER));
        fresh(output.toString());
        directory(output);
        Path slots = output.resolve(SLOTS);
        directory(slots);
        Set<String> top = new TreeSet<>(Set.of(SLOTS));
        Set<String> slotNames = new TreeSet<>();
        StringBuilder listed = new StringBuilder();
        for (Map.Entry<String, byte[]> file : files.entrySet()) {
            Path path = output.resolve(file.getKey());
            if (!Files.isDirectory(path.getParent(), LinkOption.NOFOLLOW_LINKS)) directory(path.getParent());
            write(path, file.getValue());
            if (file.getKey().startsWith(SLOTS + "/")) slotNames.add(file.getKey().split("/")[1]);
            else top.add(file.getKey());
            listed.append(listed.length() == 0 ? "" : ",").append(entry(file.getKey(), file.getValue()));
        }
        for (String slot : slotNames) {
            sync(slots.resolve(slot));
            exact(slots.resolve(slot), Set.of("record.bin", "record.bin.reservecopy"));
        }
        sync(slots);
        sync(output);
        sync(output.getParent());
        exact(output, top);
        exact(slots, slotNames);
        boolean companion = mode.startsWith("v2-beside-");
        return "{\"version\":1,\"mode\":\"" + mode + "\",\"lab_input_only\":true,\"authority\":false,\"subject\":\""
                + SUBJECT + "\",\"lineage\":\"" + lineage + "\",\"app_id\":" + appId + ",\"other_app_id\":"
                + (companion ? String.valueOf(otherAppId) : "null") + ",\"user_id\":" + USER + ",\"user_serial\":"
                + serial + ",\"files\":{" + listed + "}}";
    }

    /** Lowercase hex SHA-256 of these bytes. */
    public static String sha256(byte[] data) {
        try {
            return hex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 unavailable", error);
        }
    }

    /**
     * Refuses anything but a fresh absolute normalized path whose existing parent is a real
     * directory reached without a link. Nothing is created here.
     */
    public static Path fresh(String value) throws IOException {
        if (value == null || value.isEmpty()) throw new IllegalArgumentException("fresh output required");
        Path output = Path.of(value);
        Path parent = output.getParent();
        if (!output.isAbsolute() || !output.normalize().equals(output) || parent == null
                || output.getFileName() == null
                || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)
                || !parent.toRealPath().equals(parent)
                || Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("fresh normalized output with an existing real parent required");
        }
        return output;
    }

    /**
     * One fresh empty version 1 store: the header pair and an empty slots directory, directories
     * 0700 and files 0600. A failure leaves any partial output for inspection; a later call with
     * the same path refuses it rather than reuse or overwrite it.
     */
    public static String generate(Path output, String lineage) throws IOException {
        byte[] header = emptyHeader(lineage);
        fresh(output.toString());
        directory(output);
        Path slots = output.resolve(SLOTS);
        directory(slots);
        write(output.resolve(HEADER), header);
        write(output.resolve(RESERVE), header);
        sync(slots);
        sync(output);
        sync(output.getParent());
        exact(output, Set.of(SLOTS, HEADER, RESERVE));
        exact(slots, Set.of());
        return "{\"version\":1,\"mode\":\"empty-v1\",\"format\":\"V1\",\"lab_input_only\":true,"
                + "\"authority\":false,\"lineage\":\"" + lineage + "\",\"header_sha256\":\""
                + sha256(header) + "\",\"header_bytes\":" + header.length + ",\"entries\":[\""
                + SLOTS + "\",\"" + HEADER + "\",\"" + RESERVE + "\"]}";
    }

    /**
     * The three predicted records of the first creation and a manifest, in a fresh directory that
     * is no store layout. The caller validates the lineage, app ID, user serial, principal ID and
     * signer set from its own issued ledger; the lab command line always uses FIXTURE_SIGNER.
     */
    public static String predict(Path output, String lineage, int appId, long serial, long id,
            Set<String> signers) throws IOException {
        if (id != FIRST_ID || signers == null || signers.size() != 1) {
            throw new IllegalArgumentException("first principal ID and one signer required");
        }
        String signer = signers.iterator().next();
        byte[] creating = creatingHeader(lineage, appId, serial, signers);
        byte[] live = liveHeader(lineage, appId);
        byte[] body = body(lineage, appId, serial, signers);
        fresh(output.toString());
        String manifest = "{\"version\":1,\"mode\":\"predict-v2\",\"format\":\"V2\",\"prediction_only\":true,"
                + "\"authority\":false,\"subject\":\"" + SUBJECT + "\",\"signer_sha256\":\"" + signer
                + "\",\"lineage\":\"" + lineage + "\",\"app_id\":" + appId + ",\"user_id\":" + USER
                + ",\"user_serial\":" + serial + ",\"principal_id\":" + id + ",\"files\":{"
                + entry(CREATING, creating) + "," + entry(LIVE, live) + "," + entry(BODY, body) + "}}";
        directory(output);
        write(output.resolve(CREATING), creating);
        write(output.resolve(LIVE), live);
        write(output.resolve(BODY), body);
        write(output.resolve(MANIFEST), (manifest + "\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        sync(output);
        sync(output.getParent());
        exact(output, Set.of(CREATING, LIVE, BODY, MANIFEST));
        return manifest;
    }

    /**
     * Command line: {@code empty-v1 OUTPUT}, {@code predict-v2 OUTPUT LINEAGE APP_ID USER_SERIAL 1},
     * {@code retiring-v1|v2-slot OUTPUT LINEAGE APP_ID USER_SERIAL} or
     * {@code v2-beside-reservation|v2-beside-sibling OUTPUT LINEAGE APP_ID OTHER_APP_ID USER_SERIAL}.
     * Every argument is validated with explicit checks before any file is created, also when Java
     * assertions are disabled. Any other mode refuses.
     */
    public static void main(String[] args) throws IOException {
        if (args.length == 2 && "empty-v1".equals(args[0])) {
            Path output = fresh(args[1]);
            System.out.println(generate(output, freshLineage()));
        } else if (args.length == 6 && "predict-v2".equals(args[0])) {
            String lineage = lineage(args[2]);
            int appId = appId(args[3]);
            long serial = serial(args[4]);
            long id = principal(args[5]);
            Path output = fresh(args[1]);
            System.out.println(predict(output, lineage, appId, serial, id, Set.of(FIXTURE_SIGNER)));
        } else if (args.length == 5 && ("retiring-v1".equals(args[0]) || "v2-slot".equals(args[0]))) {
            String lineage = lineage(args[2]);
            int appId = appId(args[3]);
            long serial = serial(args[4]);
            Path output = fresh(args[1]);
            System.out.println(generateLifecycle(output, args[0], lineage, appId, appId, serial));
        } else if (args.length == 6 && ("v2-beside-reservation".equals(args[0])
                || "v2-beside-sibling".equals(args[0]))) {
            String lineage = lineage(args[2]);
            int appId = appId(args[3]);
            int otherAppId = appId(args[4]);
            long serial = serial(args[5]);
            if (otherAppId == appId) throw new IllegalArgumentException("another ordinary app ID required");
            Path output = fresh(args[1]);
            System.out.println(generateLifecycle(output, args[0], lineage, appId, otherAppId, serial));
        } else {
            throw new IllegalArgumentException("usage: empty-v1 OUTPUT | predict-v2 OUTPUT LINEAGE APP_ID USER_SERIAL 1"
                    + " | retiring-v1|v2-slot OUTPUT LINEAGE APP_ID USER_SERIAL"
                    + " | v2-beside-reservation|v2-beside-sibling OUTPUT LINEAGE APP_ID OTHER_APP_ID USER_SERIAL");
        }
    }

    static String freshLineage() {
        byte[] bytes = new byte[16];
        new SecureRandom().nextBytes(bytes);
        return hex(bytes);
    }

    private static String hex(byte[] bytes) {
        StringBuilder value = new StringBuilder(2 * bytes.length);
        for (byte item : bytes) {
            value.append(Character.forDigit((item & 255) >>> 4, 16));
            value.append(Character.forDigit(item & 15, 16));
        }
        return value.toString();
    }

    private static String entry(String name, byte[] data) {
        return "\"" + name + "\":{\"sha256\":\"" + sha256(data) + "\",\"bytes\":" + data.length + "}";
    }

    // Refuses any existing path, including a link or a prior partial attempt.
    private static void directory(Path path) throws IOException {
        Files.createDirectory(path, PosixFilePermissions.asFileAttribute(
                PosixFilePermissions.fromString(DIRECTORY_MODE)));
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(DIRECTORY_MODE));
    }

    private static void write(Path path, byte[] data) throws IOException {
        try (FileChannel channel = FileChannel.open(path,
                Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(FILE_MODE)))) {
            ByteBuffer buffer = ByteBuffer.wrap(data);
            while (buffer.hasRemaining()) channel.write(buffer);
            channel.force(true);
        }
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(FILE_MODE));
    }

    private static void sync(Path directory) throws IOException {
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        }
    }

    // Exactly these entries, each a real file or directory, and nothing else.
    private static void exact(Path directory, Set<String> expected) throws IOException {
        Set<String> found = new TreeSet<>();
        try (Stream<Path> entries = Files.list(directory)) {
            for (Path entry : entries.toList()) {
                BasicFileAttributes attributes = Files.readAttributes(entry, BasicFileAttributes.class,
                        LinkOption.NOFOLLOW_LINKS);
                if (!attributes.isRegularFile() && !attributes.isDirectory()) {
                    throw new IllegalStateException("unexpected lab output node");
                }
                found.add(entry.getFileName().toString());
            }
        }
        if (!found.equals(new TreeSet<>(expected))) {
            throw new IllegalStateException("unexpected lab output entries");
        }
    }
}
