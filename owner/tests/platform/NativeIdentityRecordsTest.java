// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.HeaderEntry;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.SlotPhase;
import com.android.server.pm.NativeIdentityRecords.UserEntry;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.UnaryOperator;

// Host checks of the record values and their encoding alone. Store files, recovery copies,
// reconciliation across records, PMS integration and Android runtime behavior are outside it.
public final class NativeIdentityRecordsTest {
    private static final String LINEAGE = "00112233445566778899aabbccddeeff";
    private static final String OTHER_LINEAGE = "ffeeddccbbaa99887766554433221100";
    private static final String APP = "dev.andrix.principal";
    private static final String LONGEST = "a." + "b".repeat(253);
    private static final String LOW = "0f".repeat(32);
    private static final String HIGH = "aa".repeat(32);
    private static final int CHECKSUM = 32;

    // Version 1 bytes of goldenHeader() and goldenSlot(), written by hand without the SHA-256.
    private static final String HEADER_LAYOUT = "41584944 0100 0100 67000000"
            + " 00112233445566778899aabbccddeeff 0700000000000000 0200"
            + " 8b270000 02 0000000000000000 0000"
            + " d8270000 01 0700000000000000 0300 612e62";
    private static final String SLOT_LAYOUT = "41584944 0200 0100 bb000000"
            + " 00112233445566778899aabbccddeeff 8b270000 0200000000000000 0300 612e62"
            + " 0200 " + LOW + " " + HIGH
            + " 0200 0300000000000000 00000000 0500000000000000 00"
            + " 0400000000000000 0a000000 0600000000000000 01";
    // Offsets within those layouts, and within one header entry or slot user.
    private static final int TYPE = 4, VERSION = 6, LENGTH = 8;
    private static final int LAST_ID = 28, ENTRY_COUNT = 36, ENTRY_1 = 38, ENTRY_2 = 53;
    private static final int PHASE = 4, CREATION_ID = 5, CREATION_PACKAGE = 13;
    private static final int APP_ID = 28, GENERATION = 32, PACKAGE = 40, SIGNER_COUNT = 45;
    private static final int SIGNER_1 = 47, USER_COUNT = 111, USER_1 = 113, USER_2 = 134;
    private static final int USER_ID = 8, SERIAL = 12, FLAGS = 20;

    private static void requireAssertions() {
        if (!NativeIdentityRecordsTest.class.desiredAssertionStatus()) {
            throw new AssertionError("run with java -ea");
        }
    }

    private static String invalid(Runnable action) {
        try {
            action.run();
        } catch (IllegalArgumentException expected) {
            return String.valueOf(expected.getMessage());
        }
        throw new AssertionError("accepted invalid input");
    }

    private static void missing(Runnable action) {
        try { action.run(); } catch (NullPointerException expected) { return; }
        throw new AssertionError("accepted null");
    }

    private static void unsupported(Runnable action) {
        try { action.run(); } catch (UnsupportedOperationException expected) { return; }
        throw new AssertionError("changed an immutable value");
    }

    private static void refusedHeader(String change, byte[] record) {
        try {
            NativeIdentityRecords.decodeHeader(record);
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("accepted header change: " + change);
    }

    private static void refusedSlot(String change, byte[] record) {
        try {
            NativeIdentityRecords.decodeSlot(record);
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("accepted slot change: " + change);
    }

    private static Header goldenHeader() {
        return new Header(LINEAGE, 7, List.of(new HeaderEntry(10123, SlotPhase.LIVE, 0, ""),
                new HeaderEntry(10200, SlotPhase.CREATING, 7, "a.b")));
    }

    private static Slot goldenSlot() {
        return new Slot(LINEAGE, 10123, "a.b", 2, Set.of(HIGH, LOW),
                List.of(new UserEntry(3, 0, 5, false), new UserEntry(4, 10, 6, true)));
    }

    // A valid digest whose 32 bytes all equal the index.
    private static String signer(int index) {
        return String.format("%02x", index).repeat(32);
    }

    private static Header roundTrip(Header value) {
        byte[] record = NativeIdentityRecords.encodeHeader(value);
        assert record.length <= NativeIdentityRecords.MAX_BYTES;
        Header decoded = NativeIdentityRecords.decodeHeader(record);
        assert decoded != value && decoded.equals(value) && value.equals(decoded);
        assert decoded.hashCode() == value.hashCode();
        assert Arrays.equals(NativeIdentityRecords.encodeHeader(decoded), record);
        return decoded;
    }

    private static Slot roundTrip(Slot value) {
        byte[] record = NativeIdentityRecords.encodeSlot(value);
        assert record.length <= NativeIdentityRecords.MAX_BYTES;
        Slot decoded = NativeIdentityRecords.decodeSlot(record);
        assert decoded != value && decoded.equals(value) && value.equals(decoded);
        assert decoded.hashCode() == value.hashCode();
        assert Arrays.equals(NativeIdentityRecords.encodeSlot(decoded), record);
        return decoded;
    }

    private static byte[] hex(String layout) {
        String digits = layout.replace(" ", "");
        byte[] bytes = new byte[digits.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(digits.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }

    private static byte[] ascii(String text) {
        return text.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] withChecksum(byte[] unsealed) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(unsealed);
            byte[] record = Arrays.copyOf(unsealed, unsealed.length + CHECKSUM);
            System.arraycopy(digest, 0, record, unsealed.length, CHECKSUM);
            return record;
        } catch (NoSuchAlgorithmException error) {
            throw new AssertionError(error);
        }
    }

    // Changes the bytes before the checksum, then corrects the length field and the checksum.
    // A refusal of the result therefore comes from the parser, not from the checksum.
    private static byte[] changed(byte[] record, UnaryOperator<byte[]> change) {
        byte[] unsealed = change.apply(Arrays.copyOf(record, record.length - CHECKSUM));
        put(unsealed, LENGTH, 4, unsealed.length + CHECKSUM);
        return withChecksum(unsealed);
    }

    // Little endian.
    private static byte[] put(byte[] bytes, int at, int width, long value) {
        for (int i = 0; i < width; i++) bytes[at + i] = (byte) (value >>> (8 * i));
        return bytes;
    }

    // Replaces bytes from..to with the replacement.
    private static byte[] splice(byte[] bytes, int from, int to, byte[] replacement) {
        return concat(Arrays.copyOf(bytes, from), replacement,
                Arrays.copyOfRange(bytes, to, bytes.length));
    }

    private static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) length += part.length;
        byte[] result = new byte[length];
        int at = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, result, at, part.length);
            at += part.length;
        }
        return result;
    }

    // The format is pinned byte for byte, including a SHA-256 over every preceding byte.
    private static void goldenLayouts() {
        byte[] header = withChecksum(hex(HEADER_LAYOUT));
        byte[] slot = withChecksum(hex(SLOT_LAYOUT));
        assert header.length == 103 && slot.length == 187;
        assert Arrays.equals(NativeIdentityRecords.encodeHeader(goldenHeader()), header);
        assert Arrays.equals(NativeIdentityRecords.encodeSlot(goldenSlot()), slot);
        assert NativeIdentityRecords.decodeHeader(header).equals(goldenHeader());
        assert NativeIdentityRecords.decodeSlot(slot).equals(goldenSlot());
        // The mutation helper reproduces an unchanged record exactly.
        assert Arrays.equals(changed(header, bytes -> bytes), header);
        assert Arrays.equals(changed(slot, bytes -> bytes), slot);
    }

    private static void roundTrips() {
        // An empty header still carries its lineage and counter.
        Header empty = roundTrip(new Header(LINEAGE, 0, List.of()));
        assert empty.entries.isEmpty() && NativeIdentityRecords.encodeHeader(empty).length == 70;
        roundTrip(new Header(OTHER_LINEAGE, Long.MAX_VALUE, List.of()));
        roundTrip(new Header(LINEAGE, Long.MAX_VALUE, List.of(
                new HeaderEntry(10000, SlotPhase.RELEASING, 0, ""),
                new HeaderEntry(10001, SlotPhase.CREATING, Long.MAX_VALUE, LONGEST),
                new HeaderEntry(10002, SlotPhase.CREATING, 1, "A.b_9"),
                new HeaderEntry(19999, SlotPhase.LIVE, 0, ""))));
        List<HeaderEntry> full = new ArrayList<>();
        for (int i = 0; i < NativeIdentityRecords.MAX_SLOTS; i++) {
            full.add(new HeaderEntry(19936 + i, SlotPhase.CREATING, Long.MAX_VALUE - i, LONGEST));
        }
        byte[] largest = NativeIdentityRecords.encodeHeader(
                roundTrip(new Header(LINEAGE, Long.MAX_VALUE, full)));
        assert largest.length == 12 + 16 + 8 + 2 + 64 * (15 + 255) + CHECKSUM;

        // A tombstone has no users and still names the app ID it holds.
        Slot tombstone = roundTrip(new Slot(LINEAGE, 19999, APP, 1, Set.of(LOW), List.of()));
        assert tombstone.users.isEmpty() && tombstone.appId == 19999;

        // One package with a principal for each of several users, up to the largest UID.
        // Principal IDs need not follow user order.
        List<UserEntry> users = List.of(new UserEntry(9, 0, 0, false),
                new UserEntry(2, 10, 3, true),
                new UserEntry(Long.MAX_VALUE, 11, Long.MAX_VALUE, false),
                new UserEntry(5, 21474, 1, true));
        Slot shared = roundTrip(new Slot(LINEAGE, 19999, APP, Long.MAX_VALUE,
                Set.of(HIGH, LOW), users));
        assert shared.users.equals(users) && shared.packageName.equals(APP);
        assert shared.users.get(3).userId * 100_000 + shared.appId == 2_147_419_999;

        Set<String> signers = new HashSet<>();
        for (int i = 0; i < NativeIdentityRecords.MAX_SIGNERS; i++) signers.add(signer(255 - i));
        List<UserEntry> many = new ArrayList<>();
        for (int i = 0; i < NativeIdentityRecords.MAX_USERS; i++) {
            many.add(new UserEntry(Long.MAX_VALUE - i, i * 340, Long.MAX_VALUE, i % 2 == 0));
        }
        byte[] widest = NativeIdentityRecords.encodeSlot(
                roundTrip(new Slot(OTHER_LINEAGE, 10000, LONGEST, 1, signers, many)));
        assert widest.length == 12 + 16 + 4 + 8 + 2 + 255 + 2 + 32 * 32 + 2 + 64 * 21 + CHECKSUM;
    }

    private static void determinism() {
        Slot slot = goldenSlot();
        byte[] first = NativeIdentityRecords.encodeSlot(slot);
        byte[] second = NativeIdentityRecords.encodeSlot(slot);
        assert first != second && Arrays.equals(first, second);
        Arrays.fill(first, (byte) 0); // Each result belongs to its caller.
        assert Arrays.equals(NativeIdentityRecords.encodeSlot(slot), second);

        // Neither the order nor the type of the signer input reaches the value or its bytes.
        TreeSet<String> reversed = new TreeSet<>(Collections.reverseOrder());
        reversed.addAll(List.of(LOW, HIGH));
        for (Set<String> signers : List.of(new LinkedHashSet<>(List.of(HIGH, LOW)),
                new LinkedHashSet<>(List.of(LOW, HIGH)), new HashSet<>(List.of(HIGH, LOW)),
                reversed)) {
            Slot same = new Slot(LINEAGE, 10123, "a.b", 2, signers, slot.users);
            assert same.equals(slot) && same.hashCode() == slot.hashCode();
            assert new ArrayList<>(same.signerSha256).equals(List.of(LOW, HIGH));
            assert Arrays.equals(NativeIdentityRecords.encodeSlot(same), second);
        }

        // Equality and the encoding cover every field.
        List<UserEntry> users = slot.users;
        Set<String> both = Set.of(LOW, HIGH);
        List<Slot> slots = List.of(new Slot(OTHER_LINEAGE, 10123, "a.b", 2, both, users),
                new Slot(LINEAGE, 10124, "a.b", 2, both, users),
                new Slot(LINEAGE, 10123, "a.c", 2, both, users),
                new Slot(LINEAGE, 10123, "a.b", 3, both, users),
                new Slot(LINEAGE, 10123, "a.b", 2, Set.of(LOW), users),
                new Slot(LINEAGE, 10123, "a.b", 2, both, users.subList(0, 1)),
                new Slot(LINEAGE, 10123, "a.b", 2, both,
                        List.of(users.get(0), new UserEntry(4, 10, 6, false))));
        for (Slot other : slots) {
            assert !other.equals(slot) && !slot.equals(other);
            assert !Arrays.equals(NativeIdentityRecords.encodeSlot(other), second);
        }
        UserEntry user = new UserEntry(3, 0, 5, false);
        for (UserEntry other : List.of(new UserEntry(4, 0, 5, false),
                new UserEntry(3, 1, 5, false), new UserEntry(3, 0, 6, false),
                new UserEntry(3, 0, 5, true))) {
            assert !other.equals(user) && !user.equals(other);
        }
        Header header = goldenHeader();
        HeaderEntry live = header.entries.get(0);
        HeaderEntry creating = header.entries.get(1);
        byte[] headerBytes = NativeIdentityRecords.encodeHeader(header);
        for (Header other : List.of(new Header(OTHER_LINEAGE, 7, header.entries),
                new Header(LINEAGE, 8, header.entries),
                new Header(LINEAGE, 7, List.of(creating)),
                new Header(LINEAGE, 7, List.of(
                        new HeaderEntry(10123, SlotPhase.RELEASING, 0, ""), creating)),
                new Header(LINEAGE, 7, List.of(
                        live, new HeaderEntry(10200, SlotPhase.CREATING, 6, "a.b"))),
                new Header(LINEAGE, 7, List.of(
                        live, new HeaderEntry(10200, SlotPhase.CREATING, 7, "a.c"))))) {
            assert !other.equals(header) && !header.equals(other);
            assert !Arrays.equals(NativeIdentityRecords.encodeHeader(other), headerBytes);
        }
        Header again = NativeIdentityRecords.decodeHeader(headerBytes);
        assert again != header && again.equals(header) && again.hashCode() == header.hashCode();
    }

    private static void immutability() {
        HeaderEntry live = new HeaderEntry(10123, SlotPhase.LIVE, 0, "");
        List<HeaderEntry> entries = new ArrayList<>(List.of(live));
        Header header = new Header(LINEAGE, 0, entries);
        entries.add(new HeaderEntry(10124, SlotPhase.LIVE, 0, ""));
        entries.set(0, new HeaderEntry(10000, SlotPhase.LIVE, 0, ""));
        assert header.entries.equals(List.of(live)); // Copied, not shared.
        unsupported(() -> header.entries.add(live));
        unsupported(() -> header.entries.set(0, live));
        unsupported(() -> header.entries.remove(0));
        unsupported(() -> header.entries.clear());

        Set<String> signers = new HashSet<>(Set.of(LOW, HIGH));
        List<UserEntry> users = new ArrayList<>(goldenSlot().users);
        Slot slot = new Slot(LINEAGE, 10123, "a.b", 2, signers, users);
        signers.remove(LOW);
        users.remove(1);
        assert slot.equals(goldenSlot());
        unsupported(() -> slot.signerSha256.add(signer(1)));
        unsupported(() -> slot.signerSha256.remove(LOW));
        unsupported(() -> slot.signerSha256.clear());
        unsupported(() -> slot.signerSha256.removeIf(digest -> true));
        unsupported(() -> {
            Iterator<String> digests = slot.signerSha256.iterator();
            digests.next();
            digests.remove();
        });
        unsupported(() -> slot.users.add(new UserEntry(9, 20, 0, false)));
        unsupported(() -> slot.users.set(0, slot.users.get(1)));
        unsupported(() -> slot.users.remove(0));
        unsupported(() -> slot.users.clear());
        assert slot.equals(goldenSlot());

        // Decoding copies its input. Later writes to that array change nothing.
        byte[] record = NativeIdentityRecords.encodeSlot(goldenSlot());
        Slot decoded = NativeIdentityRecords.decodeSlot(record);
        Arrays.fill(record, (byte) 0);
        assert decoded.equals(goldenSlot());
    }

    private static void rangeBounds() {
        Set<String> signers = Set.of(LOW);
        int[] appIds = {Integer.MIN_VALUE, -1, 0, 1000, 9999, 20000, 99999, Integer.MAX_VALUE};
        for (int appId : appIds) {
            invalid(() -> new HeaderEntry(appId, SlotPhase.LIVE, 0, ""));
            invalid(() -> new Slot(LINEAGE, appId, APP, 1, signers, List.of()));
        }
        roundTrip(new Slot(LINEAGE, 10000, APP, 1, signers, List.of()));
        String[] lineages = {"", "0", LINEAGE.substring(1), LINEAGE + "0", LINEAGE.toUpperCase(),
            LINEAGE.replace('f', 'g'), " " + LINEAGE.substring(1),
            LINEAGE.replace('0', (char) 0x660)}; // An Arabic-Indic digit is still not hex.
        for (String lineage : lineages) {
            invalid(() -> new Header(lineage, 0, List.of()));
            invalid(() -> new Slot(lineage, 10123, APP, 1, signers, List.of()));
        }
        missing(() -> new Header(null, 0, List.of()));
        missing(() -> new Slot(null, 10123, APP, 1, signers, List.of()));
        for (long lastId : new long[] {Long.MIN_VALUE, -1}) {
            invalid(() -> new Header(LINEAGE, lastId, List.of()));
        }
        for (long generation : new long[] {Long.MIN_VALUE, -1, 0}) {
            invalid(() -> new Slot(LINEAGE, 10123, APP, generation, signers, List.of()));
        }
        for (long id : new long[] {Long.MIN_VALUE, -1, 0}) {
            invalid(() -> new UserEntry(id, 0, 0, false));
        }
        for (int userId : new int[] {Integer.MIN_VALUE, -1}) {
            invalid(() -> new UserEntry(1, userId, 0, false));
        }
        for (long serial : new long[] {Long.MIN_VALUE, -1}) {
            invalid(() -> new UserEntry(1, 0, serial, false));
        }
        // A UID must fit in an int. 21474 is the largest user for every valid app ID.
        for (int userId : new int[] {21475, Integer.MAX_VALUE}) {
            UserEntry user = new UserEntry(1, userId, 0, false); // No app ID yet.
            invalid(() -> new Slot(LINEAGE, 10000, APP, 1, signers, List.of(user)));
        }
        roundTrip(new Slot(LINEAGE, 19999, APP, 1, signers,
                List.of(new UserEntry(1, 21474, 0, false))));

        String[] malformed = {
            "", "a", "android", ".", "..", "a.", ".a", ".a.b", "a..b", "a.b.", "1a.b", "a.1b",
            "_a.b", "a._b", "a-b.c", "a.b-c", "a b.c", "a.b ", "a/b.c", "a.b:c", "a.b\n", "a.b\0",
            (char) 0xe9 + ".b", "a." + (char) 0x430, LONGEST + "b",
        };
        for (String name : malformed) {
            invalid(() -> new Slot(LINEAGE, 10123, name, 1, signers, List.of()));
            invalid(() -> new HeaderEntry(10123, SlotPhase.CREATING, 1, name));
        }
        missing(() -> new Slot(LINEAGE, 10123, null, 1, signers, List.of()));
        for (String name : new String[] {"a.b", "Z9_.y_1.x", LONGEST}) {
            roundTrip(new Slot(LINEAGE, 10123, name, 1, signers, List.of()));
            roundTrip(new Header(LINEAGE, 1,
                    List.of(new HeaderEntry(10123, SlotPhase.CREATING, 1, name))));
        }

        List<Set<String>> badSigners = List.of(Set.of(), Set.of(LOW.substring(1)),
                Set.of(LOW + "0"), Set.of(HIGH.toUpperCase()), Set.of(LOW.replace('f', 'g')),
                Set.of(LOW, "sha256:" + HIGH.substring(7)));
        for (Set<String> bad : badSigners) {
            invalid(() -> new Slot(LINEAGE, 10123, APP, 1, bad, List.of()));
        }
        Set<String> tooMany = new HashSet<>();
        for (int i = 0; i <= NativeIdentityRecords.MAX_SIGNERS; i++) tooMany.add(signer(i));
        invalid(() -> new Slot(LINEAGE, 10123, APP, 1, tooMany, List.of()));
        tooMany.remove(signer(0));
        assert new Slot(LINEAGE, 10123, APP, 1, tooMany, List.of()).signerSha256.size() == 32;
        missing(() -> new Slot(LINEAGE, 10123, APP, 1, null, List.of()));
        Set<String> withNull = new HashSet<>(Arrays.asList(LOW, null));
        missing(() -> new Slot(LINEAGE, 10123, APP, 1, withNull, List.of()));

        List<UserEntry> users = new ArrayList<>();
        for (int i = 0; i <= NativeIdentityRecords.MAX_USERS; i++) {
            users.add(new UserEntry(i + 1, i, 0, false));
        }
        invalid(() -> new Slot(LINEAGE, 10123, APP, 1, signers, users));
        assert new Slot(LINEAGE, 10123, APP, 1, signers, users.subList(0, 64)).users.size() == 64;
        missing(() -> new Slot(LINEAGE, 10123, APP, 1, signers, null));
        missing(() -> new Slot(LINEAGE, 10123, APP, 1, signers,
                Arrays.asList(users.get(0), null)));
        List<HeaderEntry> entries = new ArrayList<>();
        for (int i = 0; i <= NativeIdentityRecords.MAX_SLOTS; i++) {
            entries.add(new HeaderEntry(10000 + i, SlotPhase.LIVE, 0, ""));
        }
        invalid(() -> new Header(LINEAGE, 0, entries));
        assert new Header(LINEAGE, 0, entries.subList(0, 64)).entries.size() == 64;
        missing(() -> new Header(LINEAGE, 0, null));
        missing(() -> new Header(LINEAGE, 0, Arrays.asList(entries.get(0), null)));
    }

    // Only CREATING carries a creation proof: an issued ID and a valid package.
    private static void creationProofShape() {
        for (long id : new long[] {Long.MIN_VALUE, -1, 0}) {
            invalid(() -> new HeaderEntry(10123, SlotPhase.CREATING, id, APP));
        }
        invalid(() -> new HeaderEntry(10123, SlotPhase.CREATING, 1, ""));
        missing(() -> new HeaderEntry(10123, SlotPhase.CREATING, 1, null));
        missing(() -> new HeaderEntry(10123, null, 0, ""));
        for (SlotPhase phase : List.of(SlotPhase.LIVE, SlotPhase.RELEASING)) {
            invalid(() -> new HeaderEntry(10123, phase, 1, ""));
            invalid(() -> new HeaderEntry(10123, phase, -1, ""));
            invalid(() -> new HeaderEntry(10123, phase, 0, APP));
            invalid(() -> new HeaderEntry(10123, phase, 1, APP));
            missing(() -> new HeaderEntry(10123, phase, 0, null));
            HeaderEntry plain = new HeaderEntry(10123, phase, 0, "");
            assert plain.creationId == 0 && plain.creationPackage.isEmpty();
        }
        // The creation ID was issued, so it is at most lastId, and no two creations share it.
        HeaderEntry first = new HeaderEntry(10123, SlotPhase.CREATING, 5, APP);
        invalid(() -> new Header(LINEAGE, 4, List.of(first)));
        invalid(() -> new Header(LINEAGE, 0, List.of(first)));
        assert roundTrip(new Header(LINEAGE, 5, List.of(first))).entries.get(0).equals(first);
        HeaderEntry shared = new HeaderEntry(10124, SlotPhase.CREATING, 5, "a.b");
        invalid(() -> new Header(LINEAGE, 9, List.of(first, shared)));
        roundTrip(new Header(LINEAGE, 9, List.of(first,
                new HeaderEntry(10124, SlotPhase.CREATING, 6, "a.b"))));
    }

    // Lists are validated in the order given, never sorted for the caller.
    private static void orderAndDuplicates() {
        HeaderEntry low = new HeaderEntry(10123, SlotPhase.LIVE, 0, "");
        HeaderEntry high = new HeaderEntry(10200, SlotPhase.RELEASING, 0, "");
        invalid(() -> new Header(LINEAGE, 0, List.of(high, low)));
        invalid(() -> new Header(LINEAGE, 0, List.of(low, low)));
        invalid(() -> new Header(LINEAGE, 0,
                List.of(low, new HeaderEntry(10123, SlotPhase.RELEASING, 0, ""))));
        UserEntry first = new UserEntry(3, 0, 5, false);
        UserEntry second = new UserEntry(4, 10, 6, true);
        Set<String> signers = Set.of(LOW);
        invalid(() -> new Slot(LINEAGE, 10123, APP, 1, signers, List.of(second, first)));
        invalid(() -> new Slot(LINEAGE, 10123, APP, 1, signers, List.of(first, first)));
        // Two principals cannot share a user, and one principal ID cannot serve two users.
        invalid(() -> new Slot(LINEAGE, 10123, APP, 1, signers,
                List.of(first, new UserEntry(4, 0, 6, false))));
        invalid(() -> new Slot(LINEAGE, 10123, APP, 1, signers,
                List.of(first, new UserEntry(3, 10, 6, false))));
        // A set with its own notion of identity cannot bring in a duplicate digest.
        Set<String> identity = Collections.newSetFromMap(new IdentityHashMap<>());
        identity.add(new String(LOW));
        identity.add(new String(LOW));
        assert identity.size() == 2;
        invalid(() -> new Slot(LINEAGE, 10123, APP, 1, identity, List.of()));
    }

    // The type field keeps one record kind from being read as the other.
    private static void crossType() {
        byte[] header = NativeIdentityRecords.encodeHeader(goldenHeader());
        byte[] slot = NativeIdentityRecords.encodeSlot(goldenSlot());
        invalid(() -> NativeIdentityRecords.decodeSlot(header));
        invalid(() -> NativeIdentityRecords.decodeHeader(slot));
        byte[] headerAsSlot = changed(header, bytes -> put(bytes, TYPE, 2, 2));
        byte[] slotAsHeader = changed(slot, bytes -> put(bytes, TYPE, 2, 1));
        for (byte[] record : List.of(headerAsSlot, slotAsHeader)) {
            invalid(() -> NativeIdentityRecords.decodeHeader(record));
            invalid(() -> NativeIdentityRecords.decodeSlot(record));
        }
        // A well formed slot of another app ID or lineage still decodes. The codec cannot know
        // where a record came from. The store compares both with the slot location and header.
        Slot moved = NativeIdentityRecords.decodeSlot(
                changed(slot, bytes -> put(bytes, APP_ID, 4, 10124)));
        assert moved.appId == 10124 && moved.lineage.equals(LINEAGE);
        Slot foreign = NativeIdentityRecords.decodeSlot(
                changed(slot, bytes -> splice(bytes, 12, 28, hex(OTHER_LINEAGE))));
        assert foreign.lineage.equals(OTHER_LINEAGE) && foreign.appId == 10123;
    }

    // Without a corrected checksum, every change to a record is refused.
    private static void damagedRecords() {
        missing(() -> NativeIdentityRecords.decodeHeader(null));
        missing(() -> NativeIdentityRecords.decodeSlot(null));
        missing(() -> NativeIdentityRecords.encodeHeader(null));
        missing(() -> NativeIdentityRecords.encodeSlot(null));
        for (int length : new int[] {0, 1, 43, 44, 70, NativeIdentityRecords.MAX_BYTES + 1}) {
            byte[] zeros = new byte[length];
            invalid(() -> NativeIdentityRecords.decodeHeader(zeros));
            invalid(() -> NativeIdentityRecords.decodeSlot(zeros));
        }
        byte[] header = NativeIdentityRecords.encodeHeader(goldenHeader());
        byte[] slot = NativeIdentityRecords.encodeSlot(goldenSlot());
        for (int bit = 0; bit < 8 * header.length; bit++) {
            byte[] flipped = header.clone();
            flipped[bit / 8] ^= (byte) (1 << (bit % 8));
            invalid(() -> NativeIdentityRecords.decodeHeader(flipped));
        }
        for (int bit = 0; bit < 8 * slot.length; bit++) {
            byte[] flipped = slot.clone();
            flipped[bit / 8] ^= (byte) (1 << (bit % 8));
            invalid(() -> NativeIdentityRecords.decodeSlot(flipped));
        }
        for (int length = 0; length < header.length; length++) {
            byte[] truncated = Arrays.copyOf(header, length);
            invalid(() -> NativeIdentityRecords.decodeHeader(truncated));
        }
        for (int length = 0; length < slot.length; length++) {
            byte[] truncated = Arrays.copyOf(slot, length);
            invalid(() -> NativeIdentityRecords.decodeSlot(truncated));
        }
        for (byte[] extended : List.of(Arrays.copyOf(header, header.length + 1),
                concat(header, header), concat(header, slot))) {
            invalid(() -> NativeIdentityRecords.decodeHeader(extended));
        }
        for (byte[] extended : List.of(Arrays.copyOf(slot, slot.length + 1),
                concat(slot, slot), concat(slot, header))) {
            invalid(() -> NativeIdentityRecords.decodeSlot(extended));
        }
        // A length field which matches the extension still fails the original checksum.
        invalid(() -> NativeIdentityRecords.decodeSlot(put(Arrays.copyOf(slot, slot.length + 1),
                LENGTH, 4, slot.length + 1)));
    }

    // Each change below has a corrected length and checksum, so only the parser can refuse it.
    private static void headerParserRefusals() {
        byte[] base = NativeIdentityRecords.encodeHeader(goldenHeader());
        refusedHeader("magic", changed(base, b -> put(b, 3, 1, 'E')));
        refusedHeader("version 0", changed(base, b -> put(b, VERSION, 2, 0)));
        refusedHeader("version 2", changed(base, b -> put(b, VERSION, 2, 2)));
        refusedHeader("type 0", changed(base, b -> put(b, TYPE, 2, 0)));
        refusedHeader("type 3", changed(base, b -> put(b, TYPE, 2, 3)));
        refusedHeader("length field", withChecksum(put(Arrays.copyOf(base, base.length - CHECKSUM),
                LENGTH, 4, base.length + 1)));
        refusedHeader("negative lastId", changed(base, b -> put(b, LAST_ID, 8, -1)));
        refusedHeader("lowest lastId", changed(base, b -> put(b, LAST_ID, 8, Long.MIN_VALUE)));
        refusedHeader("lastId below a creation", changed(base, b -> put(b, LAST_ID, 8, 6)));
        refusedHeader("count past the end", changed(base, b -> put(b, ENTRY_COUNT, 2, 3)));
        refusedHeader("count short of the end", changed(base, b -> put(b, ENTRY_COUNT, 2, 1)));
        refusedHeader("count above MAX_SLOTS", changed(base, b -> put(b, ENTRY_COUNT, 2, 65)));
        refusedHeader("largest count", changed(base, b -> put(b, ENTRY_COUNT, 2, 0xffff)));
        for (int code : new int[] {0, 4, 0x80, 0xff}) {
            refusedHeader("phase " + code, changed(base, b -> put(b, ENTRY_1 + PHASE, 1, code)));
        }
        refusedHeader("CREATING without a proof",
                changed(base, b -> put(b, ENTRY_1 + PHASE, 1, 1)));
        refusedHeader("LIVE with a proof", changed(base, b -> put(b, ENTRY_2 + PHASE, 1, 2)));
        refusedHeader("RELEASING with a proof",
                changed(base, b -> put(b, ENTRY_2 + PHASE, 1, 3)));
        refusedHeader("LIVE with a creation ID",
                changed(base, b -> put(b, ENTRY_1 + CREATION_ID, 8, 1)));
        refusedHeader("LIVE with a package", changed(base,
                b -> splice(b, ENTRY_1 + CREATION_PACKAGE, ENTRY_2, hex("0300 612e62"))));
        refusedHeader("zero creation ID",
                changed(base, b -> put(b, ENTRY_2 + CREATION_ID, 8, 0)));
        refusedHeader("negative creation ID",
                changed(base, b -> put(b, ENTRY_2 + CREATION_ID, 8, -7)));
        refusedHeader("duplicate app ID", changed(base, b -> put(b, ENTRY_2, 4, 10123)));
        refusedHeader("descending app IDs", changed(base, b -> put(b, ENTRY_2, 4, 10122)));
        refusedHeader("swapped entries", changed(base, b -> concat(Arrays.copyOf(b, ENTRY_1),
                Arrays.copyOfRange(b, ENTRY_2, b.length),
                Arrays.copyOfRange(b, ENTRY_1, ENTRY_2))));
        refusedHeader("app ID below range", changed(base, b -> put(b, ENTRY_1, 4, 9999)));
        refusedHeader("app ID above range", changed(base, b -> put(b, ENTRY_2, 4, 20000)));
        int name = ENTRY_2 + CREATION_PACKAGE;
        refusedHeader("non-ASCII package", changed(base, b -> put(b, name + 2, 1, 0xe1)));
        refusedHeader("package grammar", changed(base, b -> put(b, name + 3, 1, '-')));
        refusedHeader("empty creation package",
                changed(base, b -> splice(b, name, b.length, hex("0000"))));
        refusedHeader("short package length", changed(base, b -> put(b, name, 2, 2)));
        refusedHeader("long package length", changed(base, b -> put(b, name, 2, 4)));
        refusedHeader("package above 255", changed(base, b -> splice(b, name, b.length,
                concat(hex("0001"), ascii("a." + "b".repeat(254))))));
        refusedHeader("trailing byte", changed(base, b -> Arrays.copyOf(b, b.length + 1)));
        refusedHeader("padded to MAX_BYTES", changed(base,
                b -> Arrays.copyOf(b, NativeIdentityRecords.MAX_BYTES - CHECKSUM)));
        refusedHeader("above MAX_BYTES", changed(base,
                b -> Arrays.copyOf(b, NativeIdentityRecords.MAX_BYTES - CHECKSUM + 1)));
        // Entry 1 becomes a second creation. A shared creation ID is refused, a fresh one is not.
        refusedHeader("shared creation ID", changed(base, b -> splice(
                put(put(b, ENTRY_1 + PHASE, 1, 1), ENTRY_1 + CREATION_ID, 8, 7),
                ENTRY_1 + CREATION_PACKAGE, ENTRY_2, hex("0300 612e62"))));
        Header distinct = NativeIdentityRecords.decodeHeader(changed(base, b -> splice(
                put(put(b, ENTRY_1 + PHASE, 1, 1), ENTRY_1 + CREATION_ID, 8, 6),
                ENTRY_1 + CREATION_PACKAGE, ENTRY_2, hex("0300 612e62"))));
        assert distinct.entries.get(0).equals(new HeaderEntry(10123, SlotPhase.CREATING, 6, "a.b"));
        // Nearby valid changes decode to the changed value.
        assert NativeIdentityRecords.decodeHeader(changed(base,
                b -> put(b, LAST_ID, 8, Long.MAX_VALUE))).lastId == Long.MAX_VALUE;
        assert NativeIdentityRecords.decodeHeader(changed(base,
                b -> put(b, ENTRY_2, 4, 10124))).entries.get(1).appId == 10124;
        assert NativeIdentityRecords.decodeHeader(changed(base,
                b -> put(b, ENTRY_1 + PHASE, 1, 3))).entries.get(0).phase == SlotPhase.RELEASING;
    }

    private static void slotParserRefusals() {
        byte[] base = NativeIdentityRecords.encodeSlot(goldenSlot());
        refusedSlot("magic", changed(base, b -> put(b, 0, 1, 'a')));
        refusedSlot("version 2", changed(base, b -> put(b, VERSION, 2, 2)));
        refusedSlot("type 3", changed(base, b -> put(b, TYPE, 2, 3)));
        refusedSlot("app ID below range", changed(base, b -> put(b, APP_ID, 4, 9999)));
        refusedSlot("app ID above range", changed(base, b -> put(b, APP_ID, 4, 20000)));
        refusedSlot("negative app ID", changed(base, b -> put(b, APP_ID, 4, -10123)));
        refusedSlot("zero generation", changed(base, b -> put(b, GENERATION, 8, 0)));
        refusedSlot("negative generation", changed(base, b -> put(b, GENERATION, 8, -1)));
        refusedSlot("empty package",
                changed(base, b -> splice(b, PACKAGE, SIGNER_COUNT, hex("0000"))));
        refusedSlot("one segment",
                changed(base, b -> splice(b, PACKAGE, SIGNER_COUNT, hex("0100 61"))));
        refusedSlot("non-ASCII package", changed(base, b -> put(b, PACKAGE + 2, 1, 0xc3)));
        refusedSlot("package grammar", changed(base, b -> put(b, PACKAGE + 4, 1, '.')));
        refusedSlot("package past the end", changed(base, b -> put(b, PACKAGE, 2, 0xffff)));
        refusedSlot("no signers",
                changed(base, b -> splice(b, SIGNER_COUNT, USER_COUNT, hex("0000"))));
        refusedSlot("signer count short", changed(base, b -> put(b, SIGNER_COUNT, 2, 1)));
        refusedSlot("signer count long", changed(base, b -> put(b, SIGNER_COUNT, 2, 3)));
        refusedSlot("descending signers",
                changed(base, b -> splice(b, SIGNER_1, USER_COUNT, hex(HIGH + LOW))));
        refusedSlot("duplicate signer",
                changed(base, b -> splice(b, SIGNER_1, USER_COUNT, hex(LOW + LOW))));
        StringBuilder digests = new StringBuilder();
        for (int i = 0; i < NativeIdentityRecords.MAX_SIGNERS; i++) digests.append(signer(i));
        byte[] widest = changed(base, b -> splice(put(b, SIGNER_COUNT, 2, 32), SIGNER_1,
                USER_COUNT, hex(digests.toString())));
        assert NativeIdentityRecords.decodeSlot(widest).signerSha256.size() == 32;
        refusedSlot("33 signers", changed(base, b -> splice(put(b, SIGNER_COUNT, 2, 33),
                SIGNER_1, USER_COUNT, hex(digests + signer(32)))));
        refusedSlot("user count short", changed(base, b -> put(b, USER_COUNT, 2, 1)));
        refusedSlot("user count long", changed(base, b -> put(b, USER_COUNT, 2, 3)));
        refusedSlot("user count above MAX_USERS", changed(base, b -> put(b, USER_COUNT, 2, 65)));
        refusedSlot("swapped users", changed(base, b -> concat(Arrays.copyOf(b, USER_1),
                Arrays.copyOfRange(b, USER_2, b.length), Arrays.copyOfRange(b, USER_1, USER_2))));
        refusedSlot("duplicate user", changed(base, b -> put(b, USER_2 + USER_ID, 4, 0)));
        refusedSlot("duplicate principal ID", changed(base, b -> put(b, USER_2, 8, 3)));
        refusedSlot("zero principal ID", changed(base, b -> put(b, USER_1, 8, 0)));
        refusedSlot("negative principal ID",
                changed(base, b -> put(b, USER_1, 8, Long.MIN_VALUE)));
        refusedSlot("negative user", changed(base, b -> put(b, USER_1 + USER_ID, 4, -1)));
        refusedSlot("UID above the int range",
                changed(base, b -> put(b, USER_2 + USER_ID, 4, 21475)));
        refusedSlot("negative serial", changed(base, b -> put(b, USER_1 + SERIAL, 8, -1)));
        for (int flags : new int[] {2, 3, 0x80, 0xff}) {
            refusedSlot("flags " + flags, changed(base, b -> put(b, USER_1 + FLAGS, 1, flags)));
        }
        refusedSlot("trailing byte", changed(base, b -> Arrays.copyOf(b, b.length + 1)));
        refusedSlot("half a user", changed(base, b -> Arrays.copyOf(b, b.length - 10)));
        // Nearby valid changes decode to the changed value.
        Slot retiring = NativeIdentityRecords.decodeSlot(
                changed(base, b -> put(b, USER_1 + FLAGS, 1, 1)));
        assert retiring.users.get(0).retiring && retiring.users.get(1).retiring;
        Slot serial = NativeIdentityRecords.decodeSlot(
                changed(base, b -> put(b, USER_1 + SERIAL, 8, 9)));
        assert serial.users.get(0).userSerial == 9;
        // Removing every user leaves a valid tombstone which still names the app ID.
        Slot tombstone = NativeIdentityRecords.decodeSlot(
                changed(base, b -> put(Arrays.copyOf(b, USER_1), USER_COUNT, 2, 0)));
        assert tombstone.users.isEmpty() && tombstone.appId == 10123;
    }

    private static byte[] mutate(byte[] bytes, Random random) {
        int changes = 1 + random.nextInt(3);
        for (int i = 0; i < changes; i++) {
            int at = random.nextInt(bytes.length);
            switch (random.nextInt(4)) {
                case 0:
                    bytes[at] ^= (byte) (1 << random.nextInt(8));
                    break;
                case 1:
                    bytes[at] = (byte) random.nextInt(256);
                    break;
                case 2:
                    bytes = splice(bytes, at, at, new byte[] {(byte) random.nextInt(256)});
                    break;
                default:
                    bytes = splice(bytes, at, at + 1, new byte[0]);
                    break;
            }
        }
        return bytes;
    }

    // Random changes with a corrected checksum. Each result is refused, or it is exactly the one
    // encoding of the value it decodes to. The fixed seed repeats the same inputs on every run.
    private static void mutationsRefusedOrCanonical() {
        byte[][] samples = {
            NativeIdentityRecords.encodeHeader(goldenHeader()),
            NativeIdentityRecords.encodeSlot(goldenSlot()),
            NativeIdentityRecords.encodeHeader(new Header(LINEAGE, 12, List.of(
                    new HeaderEntry(10001, SlotPhase.CREATING, 11, "a.b"),
                    new HeaderEntry(10002, SlotPhase.RELEASING, 0, ""),
                    new HeaderEntry(10003, SlotPhase.CREATING, 12, APP)))),
            NativeIdentityRecords.encodeSlot(new Slot(LINEAGE, 10001, APP, 1, Set.of(LOW),
                    List.of())),
        };
        Random random = new Random(20260925L);
        int accepted = 0;
        int refused = 0;
        for (int round = 0; round < 40_000; round++) {
            byte[] candidate = changed(samples[round % 4], bytes -> mutate(bytes, random));
            try {
                byte[] again = round % 2 == 0
                        ? NativeIdentityRecords.encodeHeader(
                                NativeIdentityRecords.decodeHeader(candidate))
                        : NativeIdentityRecords.encodeSlot(
                                NativeIdentityRecords.decodeSlot(candidate));
                assert Arrays.equals(again, candidate) : "second encoding in round " + round;
                ++accepted;
            } catch (IllegalArgumentException expected) {
                ++refused;
            }
        }
        assert accepted > 1_000 && refused > 1_000 : accepted + " accepted, " + refused;
        System.out.println("Resealed mutations: " + accepted + " canonical, " + refused
                + " refused");
    }

    // Values print without lineage or digests, and refusals do not repeat input values.
    private static void noInputInText() {
        String text = goldenHeader().toString() + goldenSlot();
        assert !text.contains(LINEAGE) && !text.contains(LOW) && !text.contains(HIGH) : text;
        assert text.contains("a.b") && text.contains("CREATING");
        byte[] slot = NativeIdentityRecords.encodeSlot(goldenSlot());
        List<String> messages = List.of(
                invalid(() -> new Slot(LINEAGE, 10123, "a.Secret-9", 1, Set.of(LOW), List.of())),
                invalid(() -> new HeaderEntry(10123, SlotPhase.CREATING, 1, "a.Secret-9")),
                invalid(() -> new Slot(LINEAGE, 10123, APP, 1, Set.of("Secret-9"), List.of())),
                invalid(() -> new Header("Secret-9", 0, List.of())),
                invalid(() -> NativeIdentityRecords.decodeSlot(changed(slot, b -> splice(b,
                        PACKAGE, SIGNER_COUNT, concat(hex("0a00"), ascii("a.Secret-9")))))),
                invalid(() -> new HeaderEntry(12345678, SlotPhase.LIVE, 0, "")),
                invalid(() -> new UserEntry(-987654321, 0, 0, false)));
        for (String message : messages) {
            assert !message.contains("Secret") && !message.contains("12345678")
                    && !message.contains("987654321") : message;
        }
    }

    // No authority, allocation or alternative encoding path is public.
    private static void closedSurface() throws IllegalAccessException {
        Class<?> codec = NativeIdentityRecords.class;
        assert Modifier.isFinal(codec.getModifiers()) && codec.getConstructors().length == 0;
        Set<String> methods = new HashSet<>();
        for (Method method : codec.getDeclaredMethods()) {
            if (!Modifier.isPublic(method.getModifiers())) continue;
            assert Modifier.isStatic(method.getModifiers()) : method;
            methods.add(method.getName());
        }
        assert methods.equals(Set.of("encodeHeader", "decodeHeader", "encodeSlot", "decodeSlot"))
                : methods;
        Set<String> constants = new HashSet<>();
        for (Field field : codec.getFields()) {
            int modifiers = field.getModifiers();
            assert Modifier.isStatic(modifiers) && Modifier.isFinal(modifiers) : field;
            constants.add(field.getName() + "=" + field.getInt(null));
        }
        assert constants.equals(Set.of("MAX_BYTES=65536", "MAX_SLOTS=64", "MAX_USERS=64",
                "MAX_SIGNERS=32")) : constants;
        assert Set.of(codec.getClasses()).equals(Set.of(SlotPhase.class, HeaderEntry.class,
                Header.class, UserEntry.class, Slot.class));
        assert Arrays.asList(SlotPhase.values())
                .equals(List.of(SlotPhase.CREATING, SlotPhase.LIVE, SlotPhase.RELEASING));
        for (Class<?> type : List.of(HeaderEntry.class, Header.class, UserEntry.class,
                Slot.class)) {
            assert Modifier.isFinal(type.getModifiers()) : type;
            assert !Serializable.class.isAssignableFrom(type) : type;
            assert type.getConstructors().length == 1 : type;
            for (Field field : type.getDeclaredFields()) {
                int modifiers = field.getModifiers();
                assert Modifier.isPublic(modifiers) && Modifier.isFinal(modifiers)
                        && !Modifier.isStatic(modifiers) : field;
            }
            for (Method method : type.getDeclaredMethods()) {
                assert !Modifier.isPublic(method.getModifiers())
                        || Set.of("equals", "hashCode", "toString").contains(method.getName())
                        : method;
            }
        }
    }

    public static void main(String[] args) throws Exception {
        requireAssertions();
        goldenLayouts();
        roundTrips();
        determinism();
        immutability();
        rangeBounds();
        creationProofShape();
        orderAndDuplicates();
        crossType();
        damagedRecords();
        headerParserRefusals();
        slotParserRefusals();
        mutationsRefusedOrCanonical();
        noInputInText();
        closedSurface();
        System.out.println("Native identity record values and codec checks passed;"
                + " host JVM only, store I/O, PMS integration and Android unqualified");
    }
}
