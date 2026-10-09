// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import com.android.server.pm.NativeIdentityRecords.CreationBinding;
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
import java.util.Map;
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

    // Version 2 bytes of goldenV2Header(), written by hand without the SHA-256. Entry 1 is LIVE,
    // entry 2 a bound CREATING entry and entry 3 a CREATING entry without a binding.
    private static final String V2_HEADER_LAYOUT = "41584944 0100 0200 c9000000"
            + " 00112233445566778899aabbccddeeff 0700000000000000 0300"
            + " 8b270000 02 0000000000000000 0000"
            + " d8270000 01 0700000000000000 0300 612e62"
            + " 01 0a000000 0600000000000000 0200 " + LOW + " " + HIGH
            + " d9270000 01 0600000000000000 0300 612e63 00";
    // Offsets within that layout. ENTRY_1 and ENTRY_2 are the same as in version 1.
    private static final int V2_TAG = 71, V2_USER = 72, V2_SERIAL = 76, V2_SIGNER_COUNT = 84;
    private static final int V2_SIGNER_1 = 86, V2_ENTRY_3 = 150, V2_LEGACY_TAG = 168;

    // Complete records written by the original version 1 codec at d315361, before version 2
    // existed. They never change: stored version 1 records stay readable and rewrite unchanged.
    private static final String V1_GOLDEN_HEADER = ""
            + "41584944010001006700000000112233445566778899aabbccddeeff07000000"
            + "0000000002008b2700000200000000000000000000d827000001070000000000"
            + "00000300612e623430d3dd2438102c09227a3c928fb34086db0f3888bfa92dd1"
            + "954576b24317b1";
    private static final String V1_GOLDEN_SLOT = ""
            + "4158494402000100bb00000000112233445566778899aabbccddeeff8b270000"
            + "02000000000000000300612e6202000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"
            + "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0faaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0200030000000000000000000000050000"
            + "00000000000004000000000000000a0000000600000000000000010e04697ba0"
            + "bcf97ab71a919b3707583748db4bce6f8a9deb2a781780b811ee2d";
    private static final String V1_EMPTY_HEADER = ""
            + "41584944010001004600000000112233445566778899aabbccddeeff00000000"
            + "0000000000003ba8011033c82db4233dc502393025924ba79d47ad94e22d2753"
            + "8720294fb621";
    private static final String V1_HOLDS_HEADER = ""
            + "41584944010001008a000000ffeeddccbbaa99887766554433221100ffffffff"
            + "ffffff7f04001027000003000000000000000000001127000001ffffffffffff"
            + "ff7f0300612e62122700000101000000000000000500412e625f391f4e000002"
            + "0000000000000000000046a22f14e66112f563c834627da77c96b56c5c2db8fe"
            + "f5e98cb2917be94e6719";
    private static final String V1_TOMBSTONE_SLOT = ""
            + "41584944020001008200000000112233445566778899aabbccddeeff1f4e0000"
            + "010000000000000014006465762e616e647269782e7072696e636970616c0100"
            + "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"
            + "00009f7faf32aa0d47010557bc033ae9596c64016eb720d84837f158f5315bb6"
            + "fac2";
    private static final String V1_EXTREME_SLOT = ""
            + "4158494402000100c1000000ffeeddccbbaa998877665544332211001f4e0000"
            + "ffffffffffffff7f09005a395f2e795f312e7802000000000000000000000000"
            + "000000000000000000000000000000000000000000ffffffffffffffffffffff"
            + "ffffffffffffffffffffffffffffffffffffffffff0200ffffffffffffff7f00"
            + "0000000000000000000000000100000000000000e2530000ffffffffffffff7f"
            + "01068f0e13554bcd1e19a4d583b26e69406d4cbdafe3ecf8c47fc8cc086d3138"
            + "29";

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

    private static CreationBinding goldenBinding() {
        return new CreationBinding(10, 6, Set.of(HIGH, LOW));
    }

    private static Header goldenV2Header() {
        return Header.newV2(LINEAGE, 7, List.of(new HeaderEntry(10123, SlotPhase.LIVE, 0, ""),
                new HeaderEntry(10200, SlotPhase.CREATING, 7, "a.b", goldenBinding()),
                new HeaderEntry(10201, SlotPhase.CREATING, 6, "a.c")));
    }

    // Every phase, with header only CREATING holds and the largest IDs.
    private static Header holdsHeader() {
        return new Header(OTHER_LINEAGE, Long.MAX_VALUE, List.of(
                new HeaderEntry(10000, SlotPhase.RELEASING, 0, ""),
                new HeaderEntry(10001, SlotPhase.CREATING, Long.MAX_VALUE, "a.b"),
                new HeaderEntry(10002, SlotPhase.CREATING, 1, "A.b_9"),
                new HeaderEntry(19999, SlotPhase.LIVE, 0, "")));
    }

    private static Set<String> widestSigners() {
        Set<String> signers = new HashSet<>();
        for (int i = 0; i < NativeIdentityRecords.MAX_SIGNERS; i++) signers.add(signer(255 - i));
        return signers;
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

    // Records of the original version 1 codec still decode to version 1 values without bindings,
    // including header only CREATING holds, and those values still encode to the same bytes.
    private static void frozenV1Records() {
        assert Arrays.equals(withChecksum(hex(HEADER_LAYOUT)), hex(V1_GOLDEN_HEADER));
        assert Arrays.equals(withChecksum(hex(SLOT_LAYOUT)), hex(V1_GOLDEN_SLOT));
        Map<String, Header> headers = Map.of(V1_GOLDEN_HEADER, goldenHeader(),
                V1_EMPTY_HEADER, new Header(LINEAGE, 0, List.of()),
                V1_HOLDS_HEADER, holdsHeader());
        for (Map.Entry<String, Header> frozen : headers.entrySet()) {
            byte[] record = hex(frozen.getKey());
            Header decoded = NativeIdentityRecords.decodeHeader(record);
            assert decoded.equals(frozen.getValue()) && decoded.version == 1;
            for (HeaderEntry entry : decoded.entries) assert entry.creationBinding == null;
            assert Arrays.equals(NativeIdentityRecords.encodeHeader(decoded), record);
            assert Arrays.equals(NativeIdentityRecords.encodeHeader(frozen.getValue()), record);
            assert roundTrip(frozen.getValue()).version == 1;
        }
        Header holds = NativeIdentityRecords.decodeHeader(hex(V1_HOLDS_HEADER));
        assert holds.lastId == Long.MAX_VALUE && holds.entries.size() == 4;
        assert holds.entries.get(1).equals(
                new HeaderEntry(10001, SlotPhase.CREATING, Long.MAX_VALUE, "a.b", null));
        assert holds.entries.get(2).equals(new HeaderEntry(10002, SlotPhase.CREATING, 1, "A.b_9"));
        Map<String, Slot> slots = Map.of(V1_GOLDEN_SLOT, goldenSlot(),
                V1_TOMBSTONE_SLOT, new Slot(LINEAGE, 19999, APP, 1, Set.of(LOW), List.of()),
                V1_EXTREME_SLOT, new Slot(OTHER_LINEAGE, 19999, "Z9_.y_1.x", Long.MAX_VALUE,
                        Set.of(signer(255), signer(0)), List.of(
                                new UserEntry(Long.MAX_VALUE, 0, 0, false),
                                new UserEntry(1, 21474, Long.MAX_VALUE, true))));
        for (Map.Entry<String, Slot> frozen : slots.entrySet()) {
            byte[] record = hex(frozen.getKey());
            Slot decoded = NativeIdentityRecords.decodeSlot(record);
            assert decoded.equals(frozen.getValue());
            assert Arrays.equals(NativeIdentityRecords.encodeSlot(decoded), record);
            assert Arrays.equals(NativeIdentityRecords.encodeSlot(frozen.getValue()), record);
        }
    }

    // The version 2 format is pinned byte for byte. Only CREATING entries differ from version 1:
    // the LIVE entry's bytes are unchanged and each CREATING entry adds its binding tag.
    private static void goldenV2Layout() {
        byte[] record = withChecksum(hex(V2_HEADER_LAYOUT));
        assert record.length == 201;
        assert Arrays.equals(NativeIdentityRecords.encodeHeader(goldenV2Header()), record);
        Header decoded = NativeIdentityRecords.decodeHeader(record);
        assert decoded.equals(goldenV2Header()) && decoded.version == 2;
        assert decoded.entries.get(0).creationBinding == null;
        assert decoded.entries.get(1).creationBinding.equals(goldenBinding());
        assert decoded.entries.get(2).phase == SlotPhase.CREATING
                && decoded.entries.get(2).creationBinding == null;
        byte[] v1 = hex(V1_GOLDEN_HEADER);
        assert Arrays.equals(Arrays.copyOfRange(record, ENTRY_1, ENTRY_2),
                Arrays.copyOfRange(v1, ENTRY_1, ENTRY_2));
        assert Arrays.equals(changed(record, bytes -> bytes), record);
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

    // A header keeps its version. The same entries in the other version are another value with
    // another encoding. Neither encoding nor decoding converts one version into the other.
    private static void versionsStayDistinct() {
        List<Header> v1Headers = List.of(new Header(LINEAGE, 0, List.of()), goldenHeader(),
                holdsHeader(), new Header(LINEAGE, 3, List.of(
                        new HeaderEntry(10005, SlotPhase.LIVE, 0, ""),
                        new HeaderEntry(10006, SlotPhase.RELEASING, 0, ""))));
        for (Header v1 : v1Headers) {
            Header v2 = Header.newV2(v1.lineage, v1.lastId, v1.entries);
            assert v1.version == 1 && v2.version == 2 && v2.entries.equals(v1.entries);
            assert !v1.equals(v2) && !v2.equals(v1);
            byte[] one = NativeIdentityRecords.encodeHeader(v1);
            byte[] two = NativeIdentityRecords.encodeHeader(v2);
            assert !Arrays.equals(one, two) && one[VERSION] == 1 && two[VERSION] == 2;
            assert NativeIdentityRecords.decodeHeader(one).equals(v1);
            assert NativeIdentityRecords.decodeHeader(two).equals(v2);
            // An explicit version 2 copy keeps every hold. Its CREATING entries stay unbound.
            for (HeaderEntry entry : roundTrip(v2).entries) assert entry.creationBinding == null;
        }
        // Without CREATING entries the bodies are the same. With one, version 2 adds its tag.
        byte[] one = NativeIdentityRecords.encodeHeader(v1Headers.get(3));
        byte[] two = NativeIdentityRecords.encodeHeader(
                Header.newV2(LINEAGE, 3, v1Headers.get(3).entries));
        assert Arrays.equals(Arrays.copyOf(two, two.length - CHECKSUM),
                put(Arrays.copyOf(one, one.length - CHECKSUM), VERSION, 2, 2));
        assert NativeIdentityRecords.encodeHeader(Header.newV2(LINEAGE, 7, goldenHeader().entries))
                .length == hex(V1_GOLDEN_HEADER).length + 1;
        // Version 1 cannot hold a binding. It is refused as a value, never dropped on encoding.
        HeaderEntry bound = new HeaderEntry(10200, SlotPhase.CREATING, 7, "a.b", goldenBinding());
        invalid(() -> new Header(LINEAGE, 7, List.of(bound)));
        invalid(() -> new Header(LINEAGE, 7, goldenV2Header().entries));
        assert Header.newV2(LINEAGE, 7, List.of(bound)).entries.get(0).equals(bound);
    }

    private static void v2RoundTrips() {
        Header empty = roundTrip(Header.newV2(LINEAGE, 0, List.of()));
        assert empty.version == 2 && NativeIdentityRecords.encodeHeader(empty).length == 70;
        roundTrip(Header.newV2(OTHER_LINEAGE, Long.MAX_VALUE, List.of()));

        // Every phase, bound and unbound creations and the field extremes.
        Header rich = roundTrip(Header.newV2(LINEAGE, Long.MAX_VALUE, List.of(
                new HeaderEntry(10000, SlotPhase.RELEASING, 0, ""),
                new HeaderEntry(10001, SlotPhase.CREATING, Long.MAX_VALUE, LONGEST,
                        new CreationBinding(0, 0, Set.of(LOW))),
                new HeaderEntry(10002, SlotPhase.CREATING, 1, "A.b_9"),
                new HeaderEntry(10003, SlotPhase.CREATING, 2, APP,
                        new CreationBinding(21474, Long.MAX_VALUE, widestSigners())),
                new HeaderEntry(19999, SlotPhase.LIVE, 0, ""))));
        CreationBinding widest = rich.entries.get(3).creationBinding;
        assert widest.userId == 21474 && widest.userSerial == Long.MAX_VALUE;
        List<String> ordered = new ArrayList<>(widest.signerSha256);
        assert ordered.size() == NativeIdentityRecords.MAX_SIGNERS;
        for (int i = 1; i < ordered.size(); i++) {
            assert ordered.get(i - 1).compareTo(ordered.get(i)) < 0;
        }
        assert rich.entries.get(1).creationBinding.equals(new CreationBinding(0, 0, Set.of(LOW)));
        assert rich.entries.get(2).creationBinding == null;
        assert rich.entries.get(0).creationBinding == null
                && rich.entries.get(4).creationBinding == null;
        assert NativeIdentityRecords.encodeHeader(rich).length == 70 + 15 + (30 + 255 + 32)
                + (16 + 5) + (30 + 20 + 32 * 32) + 15;

        // Only unbound creations: incomplete entries kept as they are.
        Header kept = roundTrip(Header.newV2(LINEAGE, 12, List.of(
                new HeaderEntry(10001, SlotPhase.CREATING, 11, "a.b"),
                new HeaderEntry(10003, SlotPhase.CREATING, 12, APP, null))));
        for (HeaderEntry entry : kept.entries) {
            assert entry.phase == SlotPhase.CREATING && entry.creationBinding == null;
        }
        // The highest UID fits: user 21474 with app ID 19999.
        roundTrip(Header.newV2(LINEAGE, 1, List.of(new HeaderEntry(19999, SlotPhase.CREATING, 1,
                APP, new CreationBinding(21474, 0, Set.of(LOW))))));
        // The unbound constructor and an explicit null make the same entry.
        assert new HeaderEntry(10001, SlotPhase.CREATING, 11, "a.b", null)
                .equals(new HeaderEntry(10001, SlotPhase.CREATING, 11, "a.b"));
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

    // Equality and the encoding cover the version and every binding field. Signer input order
    // and set type reach neither.
    private static void bindingEquality() {
        Header header = goldenV2Header();
        byte[] bytes = NativeIdentityRecords.encodeHeader(header);
        HeaderEntry live = header.entries.get(0);
        HeaderEntry bound = header.entries.get(1);
        HeaderEntry unbound = header.entries.get(2);
        CreationBinding binding = goldenBinding();
        List<CreationBinding> others = List.of(new CreationBinding(11, 6, Set.of(HIGH, LOW)),
                new CreationBinding(10, 7, Set.of(HIGH, LOW)),
                new CreationBinding(10, 6, Set.of(LOW)),
                new CreationBinding(10, 6, Set.of(LOW, signer(1))));
        List<Header> headers = new ArrayList<>();
        for (CreationBinding other : others) {
            assert !other.equals(binding) && !binding.equals(other);
            headers.add(Header.newV2(LINEAGE, 7, List.of(live,
                    new HeaderEntry(10200, SlotPhase.CREATING, 7, "a.b", other), unbound)));
        }
        headers.add(Header.newV2(LINEAGE, 7, List.of(live,
                new HeaderEntry(10200, SlotPhase.CREATING, 7, "a.b"), unbound)));
        headers.add(Header.newV2(LINEAGE, 7, List.of(live, bound,
                new HeaderEntry(10201, SlotPhase.CREATING, 6, "a.c", binding))));
        headers.add(Header.newV2(LINEAGE, 7, List.of(live,
                new HeaderEntry(10200, SlotPhase.CREATING, 6, "a.b", binding),
                new HeaderEntry(10201, SlotPhase.CREATING, 7, "a.c"))));
        headers.add(Header.newV2(LINEAGE, 7, List.of(live,
                new HeaderEntry(10200, SlotPhase.CREATING, 7, "a.d", binding), unbound)));
        headers.add(Header.newV2(LINEAGE, 7, List.of(live,
                new HeaderEntry(10202, SlotPhase.CREATING, 7, "a.b", binding))));
        headers.add(Header.newV2(OTHER_LINEAGE, 7, header.entries));
        headers.add(Header.newV2(LINEAGE, 8, header.entries));
        for (Header other : headers) {
            assert !other.equals(header) && !header.equals(other) : other;
            assert !Arrays.equals(NativeIdentityRecords.encodeHeader(other), bytes) : other;
        }
        assert !bound.equals(new HeaderEntry(10200, SlotPhase.CREATING, 7, "a.b"));
        assert !new HeaderEntry(10200, SlotPhase.CREATING, 7, "a.b").equals(bound);

        TreeSet<String> reversed = new TreeSet<>(Collections.reverseOrder());
        reversed.addAll(List.of(LOW, HIGH));
        for (Set<String> signers : List.of(new LinkedHashSet<>(List.of(HIGH, LOW)),
                new LinkedHashSet<>(List.of(LOW, HIGH)), new HashSet<>(List.of(HIGH, LOW)),
                reversed)) {
            CreationBinding same = new CreationBinding(10, 6, signers);
            assert same.equals(binding) && same.hashCode() == binding.hashCode();
            assert new ArrayList<>(same.signerSha256).equals(List.of(LOW, HIGH));
            Header again = Header.newV2(LINEAGE, 7, List.of(live,
                    new HeaderEntry(10200, SlotPhase.CREATING, 7, "a.b", same), unbound));
            assert again.equals(header) && again.hashCode() == header.hashCode();
            assert Arrays.equals(NativeIdentityRecords.encodeHeader(again), bytes);
        }
        Header decoded = NativeIdentityRecords.decodeHeader(bytes);
        assert decoded != header && decoded.equals(header);
        assert decoded.hashCode() == header.hashCode();
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

    private static void bindingImmutability() {
        Set<String> signers = new HashSet<>(Set.of(LOW, HIGH));
        CreationBinding binding = new CreationBinding(10, 6, signers);
        signers.remove(LOW);
        signers.add(signer(1));
        assert binding.equals(goldenBinding()); // Copied, not shared.
        unsupported(() -> binding.signerSha256.add(signer(1)));
        unsupported(() -> binding.signerSha256.remove(LOW));
        unsupported(() -> binding.signerSha256.clear());
        unsupported(() -> binding.signerSha256.removeIf(digest -> true));
        unsupported(() -> {
            Iterator<String> digests = binding.signerSha256.iterator();
            digests.next();
            digests.remove();
        });
        assert binding.equals(goldenBinding());

        List<HeaderEntry> entries = new ArrayList<>(goldenV2Header().entries);
        Header header = Header.newV2(LINEAGE, 7, entries);
        entries.remove(1);
        entries.set(0, new HeaderEntry(10000, SlotPhase.LIVE, 0, ""));
        assert header.equals(goldenV2Header());
        HeaderEntry live = header.entries.get(0);
        unsupported(() -> header.entries.add(live));
        unsupported(() -> header.entries.set(0, live));
        unsupported(() -> header.entries.remove(0));
        unsupported(() -> header.entries.clear());

        byte[] record = NativeIdentityRecords.encodeHeader(goldenV2Header());
        Header decoded = NativeIdentityRecords.decodeHeader(record);
        Arrays.fill(record, (byte) 0);
        assert decoded.equals(goldenV2Header());
        Set<String> decodedSigners = decoded.entries.get(1).creationBinding.signerSha256;
        unsupported(() -> decodedSigners.clear());
        unsupported(() -> decodedSigners.add(signer(1)));
        assert decoded.equals(goldenV2Header());
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

    // Only CREATING carries a binding. The binding follows the slot's rules for users, serials,
    // UIDs and signers, and a bound entry still needs its creation proof.
    private static void creationBindingShape() {
        CreationBinding binding = goldenBinding();
        for (SlotPhase phase : List.of(SlotPhase.LIVE, SlotPhase.RELEASING)) {
            invalid(() -> new HeaderEntry(10123, phase, 0, "", binding));
            invalid(() -> new HeaderEntry(10123, phase, 1, APP, binding));
            HeaderEntry plain = new HeaderEntry(10123, phase, 0, "", null);
            assert plain.creationBinding == null
                    && plain.equals(new HeaderEntry(10123, phase, 0, ""));
        }
        for (long id : new long[] {Long.MIN_VALUE, -1, 0}) {
            invalid(() -> new HeaderEntry(10123, SlotPhase.CREATING, id, APP, binding));
        }
        invalid(() -> new HeaderEntry(10123, SlotPhase.CREATING, 1, "", binding));
        invalid(() -> new HeaderEntry(10123, SlotPhase.CREATING, 1, "a..b", binding));
        invalid(() -> new HeaderEntry(9999, SlotPhase.CREATING, 1, APP, binding));
        invalid(() -> new HeaderEntry(20000, SlotPhase.CREATING, 1, APP, binding));
        missing(() -> new HeaderEntry(10123, SlotPhase.CREATING, 1, null, binding));
        missing(() -> new HeaderEntry(10123, null, 1, APP, binding));

        for (int userId : new int[] {Integer.MIN_VALUE, -1}) {
            invalid(() -> new CreationBinding(userId, 0, Set.of(LOW)));
        }
        for (long serial : new long[] {Long.MIN_VALUE, -1}) {
            invalid(() -> new CreationBinding(0, serial, Set.of(LOW)));
        }
        CreationBinding lowest = new CreationBinding(0, 0, Set.of(LOW));
        assert lowest.userId == 0 && lowest.userSerial == 0;
        // A UID must fit in an int. 21474 is the largest user for every valid app ID.
        for (int userId : new int[] {21475, Integer.MAX_VALUE}) {
            CreationBinding high = new CreationBinding(userId, 0, Set.of(LOW)); // No app ID yet.
            invalid(() -> new HeaderEntry(10000, SlotPhase.CREATING, 1, APP, high));
        }
        CreationBinding top = new CreationBinding(21474, Long.MAX_VALUE, Set.of(LOW));
        assert new HeaderEntry(19999, SlotPhase.CREATING, 1, APP, top).creationBinding == top;

        List<Set<String>> badSigners = List.of(Set.of(), Set.of(LOW.substring(1)),
                Set.of(LOW + "0"), Set.of(HIGH.toUpperCase()), Set.of(LOW.replace('f', 'g')),
                Set.of(LOW, "sha256:" + HIGH.substring(7)),
                Set.of(LOW.replace('0', (char) 0x660)));
        for (Set<String> bad : badSigners) invalid(() -> new CreationBinding(0, 0, bad));
        Set<String> tooMany = new HashSet<>();
        for (int i = 0; i <= NativeIdentityRecords.MAX_SIGNERS; i++) tooMany.add(signer(i));
        invalid(() -> new CreationBinding(0, 0, tooMany));
        tooMany.remove(signer(0));
        assert new CreationBinding(0, 0, tooMany).signerSha256.size() == 32;
        missing(() -> new CreationBinding(0, 0, null));
        missing(() -> new CreationBinding(0, 0, new HashSet<>(Arrays.asList(LOW, null))));
        Set<String> identity = Collections.newSetFromMap(new IdentityHashMap<>());
        identity.add(new String(LOW));
        identity.add(new String(LOW));
        invalid(() -> new CreationBinding(0, 0, identity));

        // The header's rules apply to bound entries in the same way.
        HeaderEntry first = new HeaderEntry(10123, SlotPhase.CREATING, 5, APP, binding);
        HeaderEntry second = new HeaderEntry(10124, SlotPhase.CREATING, 6, "a.b", binding);
        invalid(() -> Header.newV2(LINEAGE, 4, List.of(first)));
        invalid(() -> Header.newV2(LINEAGE, 9,
                List.of(first, new HeaderEntry(10124, SlotPhase.CREATING, 5, "a.b"))));
        invalid(() -> Header.newV2(LINEAGE, 9, List.of(second, first)));
        invalid(() -> Header.newV2(LINEAGE, 9, List.of(first, first)));
        roundTrip(Header.newV2(LINEAGE, 6, List.of(first, second)));
        for (String lineage : new String[] {"", LINEAGE.substring(1), LINEAGE.toUpperCase()}) {
            invalid(() -> Header.newV2(lineage, 0, List.of()));
        }
        invalid(() -> Header.newV2(LINEAGE, -1, List.of()));
        missing(() -> Header.newV2(null, 0, List.of()));
        missing(() -> Header.newV2(LINEAGE, 0, null));
        missing(() -> Header.newV2(LINEAGE, 6, Arrays.asList(first, null)));
        List<HeaderEntry> entries = new ArrayList<>();
        for (int i = 0; i <= NativeIdentityRecords.MAX_SLOTS; i++) {
            entries.add(new HeaderEntry(10000 + i, SlotPhase.LIVE, 0, ""));
        }
        invalid(() -> Header.newV2(LINEAGE, 0, entries));
        assert Header.newV2(LINEAGE, 0, entries.subList(0, 64)).entries.size() == 64;
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
        // A version 2 header is no slot, and a version 1 slot relabeled as a version 2 header,
        // or as a version 2 slot, is no version 2 body. Each is refused.
        byte[] v2 = NativeIdentityRecords.encodeHeader(goldenV2Header());
        invalid(() -> NativeIdentityRecords.decodeSlot(v2));
        byte[] v2AsSlot = changed(v2, bytes -> put(bytes, TYPE, 2, 2));
        byte[] slotAsV2 = changed(slot, bytes -> put(put(bytes, TYPE, 2, 1), VERSION, 2, 2));
        for (byte[] record : List.of(headerAsSlot, slotAsHeader, v2AsSlot, slotAsV2)) {
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

    // The same damage checks for a version 2 header, including every bit of its bindings.
    private static void v2DamagedRecords() {
        byte[] header = NativeIdentityRecords.encodeHeader(goldenV2Header());
        byte[] slot = NativeIdentityRecords.encodeSlot(goldenSlot());
        for (int bit = 0; bit < 8 * header.length; bit++) {
            byte[] flipped = header.clone();
            flipped[bit / 8] ^= (byte) (1 << (bit % 8));
            invalid(() -> NativeIdentityRecords.decodeHeader(flipped));
        }
        for (int length = 0; length < header.length; length++) {
            byte[] truncated = Arrays.copyOf(header, length);
            invalid(() -> NativeIdentityRecords.decodeHeader(truncated));
        }
        for (byte[] extended : List.of(Arrays.copyOf(header, header.length + 1),
                concat(header, header), concat(header, slot))) {
            invalid(() -> NativeIdentityRecords.decodeHeader(extended));
        }
        invalid(() -> NativeIdentityRecords.decodeHeader(put(
                Arrays.copyOf(header, header.length + 1), LENGTH, 4, header.length + 1)));
    }

    // Each change below has a corrected length and checksum, so only the parser can refuse it.
    private static void headerParserRefusals() {
        byte[] base = NativeIdentityRecords.encodeHeader(goldenHeader());
        refusedHeader("magic", changed(base, b -> put(b, 3, 1, 'E')));
        refusedHeader("version 0", changed(base, b -> put(b, VERSION, 2, 0)));
        refusedHeader("version 3", changed(base, b -> put(b, VERSION, 2, 3)));
        refusedHeader("largest version", changed(base, b -> put(b, VERSION, 2, 0xffff)));
        // Version 2 is a header version, but this CREATING entry has no binding tag.
        refusedHeader("version 1 body as version 2", changed(base, b -> put(b, VERSION, 2, 2)));
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

    // Each change below has a corrected length and checksum, so only the parser can refuse it.
    private static void v2ParserRefusals() {
        byte[] base = NativeIdentityRecords.encodeHeader(goldenV2Header());
        assert Arrays.equals(base, withChecksum(hex(V2_HEADER_LAYOUT)));
        refusedHeader("version 3", changed(base, b -> put(b, VERSION, 2, 3)));
        refusedHeader("largest version", changed(base, b -> put(b, VERSION, 2, 0xffff)));
        refusedHeader("version 0", changed(base, b -> put(b, VERSION, 2, 0)));
        // Version 1 reads each binding tag as the start of the next entry.
        refusedHeader("version 2 body as version 1", changed(base, b -> put(b, VERSION, 2, 1)));
        for (int tag : new int[] {2, 3, 0x80, 0xff}) {
            refusedHeader("binding tag " + tag, changed(base, b -> put(b, V2_TAG, 1, tag)));
            refusedHeader("absent binding tag " + tag,
                    changed(base, b -> put(b, V2_LEGACY_TAG, 1, tag)));
        }
        refusedHeader("absent tag before binding bytes", changed(base, b -> put(b, V2_TAG, 1, 0)));
        refusedHeader("present tag without a binding",
                changed(base, b -> put(b, V2_LEGACY_TAG, 1, 1)));
        refusedHeader("no binding tag",
                changed(base, b -> splice(b, V2_TAG, V2_TAG + 1, new byte[0])));
        refusedHeader("no final binding tag", changed(base, b -> Arrays.copyOf(b, V2_LEGACY_TAG)));
        refusedHeader("tag after LIVE", changed(base, b -> splice(b, ENTRY_2, ENTRY_2, hex("00"))));
        refusedHeader("bound entry as LIVE", changed(base, b -> put(b, ENTRY_2 + PHASE, 1, 2)));
        refusedHeader("bound entry as RELEASING",
                changed(base, b -> put(b, ENTRY_2 + PHASE, 1, 3)));
        refusedHeader("LIVE as CREATING", changed(base, b -> put(b, ENTRY_1 + PHASE, 1, 1)));
        refusedHeader("negative user", changed(base, b -> put(b, V2_USER, 4, -1)));
        refusedHeader("lowest user", changed(base, b -> put(b, V2_USER, 4, Integer.MIN_VALUE)));
        refusedHeader("UID above the int range", changed(base, b -> put(b, V2_USER, 4, 21475)));
        refusedHeader("negative serial", changed(base, b -> put(b, V2_SERIAL, 8, -1)));
        refusedHeader("lowest serial", changed(base, b -> put(b, V2_SERIAL, 8, Long.MIN_VALUE)));
        refusedHeader("no signers",
                changed(base, b -> splice(b, V2_SIGNER_COUNT, V2_ENTRY_3, hex("0000"))));
        refusedHeader("signer count short", changed(base, b -> put(b, V2_SIGNER_COUNT, 2, 1)));
        refusedHeader("signer count long", changed(base, b -> put(b, V2_SIGNER_COUNT, 2, 3)));
        refusedHeader("signer count above MAX_SIGNERS",
                changed(base, b -> put(b, V2_SIGNER_COUNT, 2, 33)));
        refusedHeader("largest signer count",
                changed(base, b -> put(b, V2_SIGNER_COUNT, 2, 0xffff)));
        refusedHeader("descending signers",
                changed(base, b -> splice(b, V2_SIGNER_1, V2_ENTRY_3, hex(HIGH + LOW))));
        refusedHeader("duplicate signer",
                changed(base, b -> splice(b, V2_SIGNER_1, V2_ENTRY_3, hex(LOW + LOW))));
        StringBuilder digests = new StringBuilder();
        for (int i = 0; i < NativeIdentityRecords.MAX_SIGNERS; i++) digests.append(signer(i));
        Header widest = NativeIdentityRecords.decodeHeader(changed(base, b -> splice(
                put(b, V2_SIGNER_COUNT, 2, 32), V2_SIGNER_1, V2_ENTRY_3, hex(digests.toString()))));
        assert widest.entries.get(1).creationBinding.signerSha256.size() == 32;
        refusedHeader("33 signers", changed(base, b -> splice(put(b, V2_SIGNER_COUNT, 2, 33),
                V2_SIGNER_1, V2_ENTRY_3, hex(digests + signer(32)))));
        refusedHeader("half a binding", changed(base, b -> Arrays.copyOf(b, V2_SIGNER_1 + 16)));
        refusedHeader("trailing byte", changed(base, b -> Arrays.copyOf(b, b.length + 1)));
        refusedHeader("padded to MAX_BYTES", changed(base,
                b -> Arrays.copyOf(b, NativeIdentityRecords.MAX_BYTES - CHECKSUM)));
        refusedHeader("shared creation ID",
                changed(base, b -> put(b, V2_ENTRY_3 + CREATION_ID, 8, 7)));
        refusedHeader("creation ID above lastId", changed(base, b -> put(b, LAST_ID, 8, 6)));

        // Nearby valid changes decode to the changed value.
        Header user = NativeIdentityRecords.decodeHeader(
                changed(base, b -> put(b, V2_USER, 4, 21474)));
        assert user.entries.get(1).creationBinding.userId == 21474;
        Header serial = NativeIdentityRecords.decodeHeader(
                changed(base, b -> put(b, V2_SERIAL, 8, Long.MAX_VALUE)));
        assert serial.entries.get(1).creationBinding.userSerial == Long.MAX_VALUE;
        // A binding can be added to or removed from a CREATING entry by anyone who can
        // recompute the checksum. The checksum detects damage and does not authenticate.
        Header added = NativeIdentityRecords.decodeHeader(changed(base, b -> concat(
                Arrays.copyOf(b, V2_LEGACY_TAG), hex("01 00000000 0000000000000000 0100" + LOW))));
        assert added.entries.get(2).creationBinding.equals(new CreationBinding(0, 0, Set.of(LOW)));
        Header dropped = NativeIdentityRecords.decodeHeader(
                changed(base, b -> splice(b, V2_TAG, V2_ENTRY_3, hex("00"))));
        assert dropped.version == 2 && dropped.entries.get(1).creationBinding == null;
        // A version 1 body without CREATING entries is also a version 2 body. Relabeled, it
        // decodes to a different value, the version 2 header with the same entries.
        Header liveOnly = new Header(LINEAGE, 3, List.of(new HeaderEntry(10005, SlotPhase.LIVE,
                0, "")));
        Header relabeled = NativeIdentityRecords.decodeHeader(changed(
                NativeIdentityRecords.encodeHeader(liveOnly), b -> put(b, VERSION, 2, 2)));
        assert relabeled.equals(Header.newV2(LINEAGE, 3, liveOnly.entries))
                && !relabeled.equals(liveOnly);
    }

    // The store's view of a frame: the declared version when the size bound, magic, type,
    // length field and checksum are intact, otherwise -1. The body is not parsed, so an unknown
    // version is told apart from damage. Decoding still accepts only the versions it knows.
    private static void frameClassification() {
        byte[] header = NativeIdentityRecords.encodeHeader(goldenHeader());
        byte[] v2 = NativeIdentityRecords.encodeHeader(goldenV2Header());
        byte[] slot = NativeIdentityRecords.encodeSlot(goldenSlot());
        assert NativeIdentityRecords.intactHeaderVersion(header) == 1;
        assert NativeIdentityRecords.intactHeaderVersion(v2) == 2;
        assert NativeIdentityRecords.intactSlotVersion(slot) == 1;
        assert NativeIdentityRecords.intactHeaderVersion(slot) == -1;
        assert NativeIdentityRecords.intactSlotVersion(header) == -1;
        assert NativeIdentityRecords.intactSlotVersion(v2) == -1;
        for (int version : new int[] {0, 2, 3, 0x7fff, 0xffff}) {
            byte[] h = changed(header, b -> put(b, VERSION, 2, version));
            byte[] s = changed(slot, b -> put(b, VERSION, 2, version));
            assert NativeIdentityRecords.intactHeaderVersion(h) == version;
            assert NativeIdentityRecords.intactSlotVersion(s) == version;
            // A version 1 body under version 2 has no binding tags, and no lifecycle blocks for
            // a slot, so it does not decode either.
            refusedHeader("version " + version, h);
            refusedSlot("version " + version, s);
            // Every single bit of such a frame is covered, including its version field.
            for (byte[] frame : List.of(h, s)) {
                for (int bit = 0; bit < 8 * frame.length; bit++) {
                    byte[] flipped = frame.clone();
                    flipped[bit / 8] ^= (byte) (1 << (bit % 8));
                    assert NativeIdentityRecords.intactHeaderVersion(flipped) == -1
                            && NativeIdentityRecords.intactSlotVersion(flipped) == -1 : bit;
                }
            }
        }
        // Nothing after the frame is read: an empty body, or any body, of an unknown version.
        byte[] bare = withChecksum(hex("41584944 0100 0300 2c000000"));
        assert bare.length == 44 && NativeIdentityRecords.intactHeaderVersion(bare) == 3;
        byte[] slotBare = withChecksum(hex("41584944 0200 0200 2c000000"));
        assert NativeIdentityRecords.intactSlotVersion(slotBare) == 2;
        byte[] v3 = changed(header, b -> put(concat(b, ascii("future")), VERSION, 2, 3));
        assert NativeIdentityRecords.intactHeaderVersion(v3) == 3;
        refusedHeader("version 3 with a longer body", v3);
        // The size bound is the codec's MAX_BYTES, unchanged, at both ends.
        byte[] largest = changed(v3, b -> Arrays.copyOf(b, NativeIdentityRecords.MAX_BYTES
                - CHECKSUM));
        assert largest.length == NativeIdentityRecords.MAX_BYTES
                && NativeIdentityRecords.intactHeaderVersion(largest) == 3;
        byte[] above = changed(v3, b -> Arrays.copyOf(b, NativeIdentityRecords.MAX_BYTES
                - CHECKSUM + 1));
        assert NativeIdentityRecords.intactHeaderVersion(above) == -1;
        // Damage and foreign frames are not an unknown version.
        List<byte[]> notIntact = new ArrayList<>(List.of(
                changed(v3, b -> put(b, 0, 1, 'B')),
                changed(v3, b -> put(b, TYPE, 2, 0)),
                changed(v3, b -> put(b, TYPE, 2, 3)),
                changed(v3, b -> put(b, TYPE, 2, 0xffff)),
                withChecksum(put(Arrays.copyOf(v3, v3.length - CHECKSUM), LENGTH, 4,
                        v3.length + 1)),
                Arrays.copyOf(v3, v3.length - 1), Arrays.copyOf(v3, v3.length + 1),
                concat(v3, v3), Arrays.copyOf(v3, 43), new byte[44], new byte[0]));
        byte[] badChecksum = v3.clone();
        badChecksum[badChecksum.length - 1] ^= 1;
        notIntact.add(badChecksum);
        for (byte[] record : notIntact) {
            assert NativeIdentityRecords.intactHeaderVersion(record) == -1;
            assert NativeIdentityRecords.intactSlotVersion(record) == -1;
        }
        // The input is read, not kept or changed.
        byte[] input = v3.clone();
        NativeIdentityRecords.intactHeaderVersion(input);
        NativeIdentityRecords.intactSlotVersion(input);
        assert Arrays.equals(input, v3);
        missing(() -> NativeIdentityRecords.intactHeaderVersion(null));
        missing(() -> NativeIdentityRecords.intactSlotVersion(null));
    }

    // Large bindings can pass MAX_BYTES below MAX_SLOTS entries. Such a header is refused as a
    // value, before any encoding or I/O. The bound itself is unchanged.
    private static void maxBytesBound() {
        assert NativeIdentityRecords.MAX_BYTES == 65536;
        CreationBinding big = new CreationBinding(0, 0, widestSigners());
        // Each bound entry takes 4 + 1 + 8 + 2 + package + 1 + 4 + 8 + 2 + 32 * 32 bytes, which
        // is 1309 with the longest package. Fifty such entries fit, fifty one do not.
        List<HeaderEntry> entries = new ArrayList<>();
        for (int i = 0; i < 49; i++) {
            entries.add(new HeaderEntry(10000 + i, SlotPhase.CREATING, i + 1, LONGEST, big));
        }
        entries.add(new HeaderEntry(10049, SlotPhase.CREATING, 50, LONGEST.substring(0, 252),
                big));
        entries.add(new HeaderEntry(10050, SlotPhase.CREATING, 51, "a.b"));
        Header largest = roundTrip(Header.newV2(LINEAGE, 51, entries));
        byte[] record = NativeIdentityRecords.encodeHeader(largest);
        assert record.length == NativeIdentityRecords.MAX_BYTES;
        entries.set(50, new HeaderEntry(10050, SlotPhase.CREATING, 51, "a.bc"));
        invalid(() -> Header.newV2(LINEAGE, 51, entries));
        entries.set(50, new HeaderEntry(10050, SlotPhase.CREATING, 51, "a.b",
                new CreationBinding(0, 0, Set.of(LOW))));
        invalid(() -> Header.newV2(LINEAGE, 51, entries));
        refusedHeader("one byte above MAX_BYTES", changed(record,
                b -> Arrays.copyOf(b, b.length + 1)));

        // MAX_SLOTS entries with MAX_SIGNERS each are refused even with short packages.
        List<HeaderEntry> full = new ArrayList<>();
        for (int i = 0; i < NativeIdentityRecords.MAX_SLOTS; i++) {
            full.add(new HeaderEntry(10000 + i, SlotPhase.CREATING, i + 1, "a.b", big));
        }
        invalid(() -> Header.newV2(LINEAGE, 64, full));
        // With one signer each, MAX_SLOTS entries with the longest package fit.
        CreationBinding small = new CreationBinding(21474, Long.MAX_VALUE, Set.of(LOW));
        for (int i = 0; i < NativeIdentityRecords.MAX_SLOTS; i++) {
            full.set(i, new HeaderEntry(10000 + i, SlotPhase.CREATING, i + 1, LONGEST, small));
        }
        assert NativeIdentityRecords.encodeHeader(roundTrip(Header.newV2(LINEAGE, 64, full)))
                .length == 70 + 64 * (30 + 255 + 32);
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

        // The same property for version 2 headers, with their own seed so that the version 1
        // inputs above stay exactly as they were.
        byte[][] v2Samples = {
            NativeIdentityRecords.encodeHeader(goldenV2Header()),
            NativeIdentityRecords.encodeHeader(Header.newV2(LINEAGE, 12, List.of(
                    new HeaderEntry(10001, SlotPhase.CREATING, 11, "a.b",
                            new CreationBinding(0, 3, Set.of(LOW))),
                    new HeaderEntry(10002, SlotPhase.RELEASING, 0, ""),
                    new HeaderEntry(10003, SlotPhase.CREATING, 12, APP)))),
            NativeIdentityRecords.encodeHeader(Header.newV2(LINEAGE, 3, List.of(
                    new HeaderEntry(10005, SlotPhase.LIVE, 0, "")))),
        };
        Random v2Random = new Random(20260926L);
        int v2Accepted = 0;
        int v2Refused = 0;
        for (int round = 0; round < 30_000; round++) {
            byte[] candidate = changed(v2Samples[round % 3], bytes -> mutate(bytes, v2Random));
            try {
                byte[] again = NativeIdentityRecords.encodeHeader(
                        NativeIdentityRecords.decodeHeader(candidate));
                assert Arrays.equals(again, candidate) : "second v2 encoding in round " + round;
                ++v2Accepted;
            } catch (IllegalArgumentException expected) {
                ++v2Refused;
            }
        }
        assert v2Accepted > 1_000 && v2Refused > 1_000 : v2Accepted + " accepted, " + v2Refused;
        System.out.println("Resealed version 2 mutations: " + v2Accepted + " canonical, "
                + v2Refused + " refused");
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

        // Bindings print their user, serial and signer count, never a digest.
        String v2Text = goldenV2Header().toString() + goldenBinding();
        assert !v2Text.contains(LINEAGE) && !v2Text.contains(LOW) && !v2Text.contains(HIGH)
                : v2Text;
        assert v2Text.contains("version=2") && v2Text.contains("user=10")
                && v2Text.contains("serial=6") && v2Text.contains("signers=2") : v2Text;
        assert goldenHeader().toString().contains("version=1");
        List<HeaderEntry> oversized = new ArrayList<>();
        CreationBinding big = new CreationBinding(0, 0, widestSigners());
        for (int i = 0; i < NativeIdentityRecords.MAX_SLOTS; i++) {
            oversized.add(new HeaderEntry(12345 + i, SlotPhase.CREATING, 987654321L + i,
                    "a.Secret9", big));
        }
        List<String> bindingMessages = List.of(
                invalid(() -> new CreationBinding(-987654321, 0, Set.of(LOW))),
                invalid(() -> new CreationBinding(0, -987654321, Set.of(LOW))),
                invalid(() -> new CreationBinding(0, 0, Set.of("Secret-9"))),
                invalid(() -> new HeaderEntry(12345678, SlotPhase.CREATING, 1, APP, big)),
                invalid(() -> new HeaderEntry(10000, SlotPhase.LIVE, 0, "", big)),
                invalid(() -> new HeaderEntry(10000, SlotPhase.CREATING, 1, APP,
                        new CreationBinding(987654321, 0, Set.of(LOW)))),
                invalid(() -> new Header(LINEAGE, 1, List.of(
                        new HeaderEntry(12345, SlotPhase.CREATING, 1, "a.Secret9", big)))),
                invalid(() -> Header.newV2(LINEAGE, Long.MAX_VALUE, oversized)));
        for (String message : bindingMessages) {
            assert !message.contains("Secret") && !message.contains("12345")
                    && !message.contains("987654321") && !message.contains(LOW) : message;
        }
    }

    // No authority, allocation or alternative encoding path is public. The only additions for
    // version 2 headers are the binding value, an entry constructor with it and Header.newV2.
    // Version 2 slots add the lifecycle values and their enums, a user entry constructor with a
    // lifecycle and a slot constructor with a ticket. The prefix reader stays with the store.
    private static void closedSurface() throws ReflectiveOperationException {
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
        assert Set.of(codec.getClasses()).equals(Set.of(SlotPhase.class, CreationBinding.class,
                HeaderEntry.class, Header.class, UserEntry.class, Slot.class,
                NativeIdentityRecords.LifecycleState.class, NativeIdentityRecords.ActorClass.class,
                NativeIdentityRecords.SuspensionReason.class,
                NativeIdentityRecords.ObligationKind.class,
                NativeIdentityRecords.ObligationState.class, NativeIdentityRecords.Suspension.class,
                NativeIdentityRecords.Obligation.class, NativeIdentityRecords.Retirement.class,
                NativeIdentityRecords.Lifecycle.class, NativeIdentityRecords.ReleaseTicket.class));
        assert Arrays.asList(SlotPhase.values())
                .equals(List.of(SlotPhase.CREATING, SlotPhase.LIVE, SlotPhase.RELEASING));
        Map<Class<?>, Integer> constructors = Map.ofEntries(Map.entry(CreationBinding.class, 1),
                Map.entry(HeaderEntry.class, 2), Map.entry(Header.class, 1),
                Map.entry(UserEntry.class, 2), Map.entry(Slot.class, 2),
                Map.entry(NativeIdentityRecords.Suspension.class, 1),
                Map.entry(NativeIdentityRecords.Obligation.class, 1),
                Map.entry(NativeIdentityRecords.Retirement.class, 1),
                Map.entry(NativeIdentityRecords.Lifecycle.class, 1),
                Map.entry(NativeIdentityRecords.ReleaseTicket.class, 1));
        for (Map.Entry<Class<?>, Integer> value : constructors.entrySet()) {
            Class<?> type = value.getKey();
            assert Modifier.isFinal(type.getModifiers()) : type;
            assert !Serializable.class.isAssignableFrom(type) : type;
            assert type.getConstructors().length == value.getValue() : type;
            for (Field field : type.getDeclaredFields()) {
                int modifiers = field.getModifiers();
                assert Modifier.isPublic(modifiers) && Modifier.isFinal(modifiers)
                        && !Modifier.isStatic(modifiers) : field;
            }
            for (Method method : type.getDeclaredMethods()) {
                int modifiers = method.getModifiers();
                boolean newV2 = type == Header.class && method.getName().equals("newV2")
                        && Modifier.isStatic(modifiers) && method.getReturnType() == Header.class;
                assert !Modifier.isPublic(modifiers) || newV2
                        || Set.of("equals", "hashCode", "toString").contains(method.getName())
                        : method;
            }
        }
        HeaderEntry.class.getConstructor(int.class, SlotPhase.class, long.class, String.class);
        HeaderEntry.class.getConstructor(int.class, SlotPhase.class, long.class, String.class,
                CreationBinding.class);
        Header.class.getConstructor(String.class, long.class, List.class);
        Header.class.getMethod("newV2", String.class, long.class, List.class);
        CreationBinding.class.getConstructor(int.class, long.class, Set.class);
        UserEntry.class.getConstructor(long.class, int.class, long.class, boolean.class);
        UserEntry.class.getConstructor(long.class, int.class, long.class,
                NativeIdentityRecords.Lifecycle.class);
        Slot.class.getConstructor(String.class, int.class, String.class, long.class, Set.class,
                List.class);
        Slot.class.getConstructor(String.class, int.class, String.class, long.class, Set.class,
                List.class, NativeIdentityRecords.ReleaseTicket.class);
    }

    public static void main(String[] args) throws Exception {
        requireAssertions();
        goldenLayouts();
        frozenV1Records();
        goldenV2Layout();
        roundTrips();
        versionsStayDistinct();
        v2RoundTrips();
        determinism();
        bindingEquality();
        immutability();
        bindingImmutability();
        rangeBounds();
        creationProofShape();
        creationBindingShape();
        orderAndDuplicates();
        crossType();
        damagedRecords();
        v2DamagedRecords();
        headerParserRefusals();
        slotParserRefusals();
        v2ParserRefusals();
        frameClassification();
        maxBytesBound();
        mutationsRefusedOrCanonical();
        noInputInText();
        closedSurface();
        System.out.println("Native identity record values and codec checks passed;"
                + " host JVM only, store I/O, PMS integration and Android unqualified");
    }
}
