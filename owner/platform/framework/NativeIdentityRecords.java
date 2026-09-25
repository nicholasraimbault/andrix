// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Immutable records of Package Manager's native identity store and their binary encoding.
 *
 * <p>The intended store keeps one {@link Slot} for each app ID it holds, plus one {@link Header}
 * which lists every held slot and the principal ID counter. Package Manager owns the files,
 * recovery copies and write protocol. A listed entry or a slot holds its app ID, and a slot
 * without users is a tombstone which still holds it. Principal IDs are PMS principal
 * identifiers, not native work IDs.
 *
 * <p>This class only defines values and bytes. It performs no I/O, allocates no app ID, UID or
 * principal ID, checks no caller and grants no authority. Nothing here releases, expires or
 * times out. A decoded record is well formed, not current or trusted. The caller compares a
 * slot's lineage and app ID with the header and the slot's location, matches creation proofs and
 * counters across records, and revalidates Package Manager and user state before it relies on a
 * binding. A record that fails to decode, or an unknown file, is no evidence that an app ID is
 * free. Its hold remains.
 *
 * <p>Version 1 layout. Integers are fixed width and little endian. A string is a u16 length and
 * that many ASCII bytes. The lineage and signer digests are raw bytes.
 * <pre>
 * record  u32 magic 0x44495841 ("AXID"), u16 type (1 header, 2 slot), u16 version (1),
 *         u32 total length, body, then the SHA-256 of all preceding bytes
 * header  lineage[16], i64 lastId, u16 count, then count entries in app ID order:
 *         i32 appId, u8 phase (1 CREATING, 2 LIVE, 3 RELEASING), i64 creationId,
 *         string creationPackage
 * slot    lineage[16], i32 appId, i64 generation, string packageName,
 *         u16 count, then count signer digests[32] in ascending order,
 *         u16 count, then count users in user ID order: i64 id, i32 userId,
 *         i64 userSerial, u8 flags (bit 0 retiring, other bits reserved and zero)
 * </pre>
 * Each valid value has exactly one encoding, and decoding accepts nothing else. Before it
 * returns a value, it checks the size, frame, checksum, strict ASCII, every field rule and
 * bound, strict ordering without duplicates, reserved bits and the absence of trailing bytes. It
 * never reorders or repairs input. Malformed input throws {@link IllegalArgumentException}, null
 * input throws {@link NullPointerException}, and no call returns partial output. Messages do not
 * repeat input values.
 *
 * <p>The checksum detects accidental damage, such as a torn, truncated or extended write. It is
 * not authenticity: whoever can write a record can recompute it. The store's protection rests on
 * Package Manager's own files and policy. This format is private to this framework and is not a
 * public ABI. A layout change needs a new version and an explicit migration. The MAX constants
 * are initial parser bounds, not product quotas.
 */
public final class NativeIdentityRecords {
    /** Largest accepted encoding of either record, in bytes. */
    public static final int MAX_BYTES = 65536;
    /** Most entries in one header. */
    public static final int MAX_SLOTS = 64;
    /** Most users in one slot. */
    public static final int MAX_USERS = 64;
    /** Most signer digests in one slot. */
    public static final int MAX_SIGNERS = 32;

    private static final int MAGIC = 0x44495841; // "AXID" in file order.
    private static final int VERSION = 1;
    private static final int TYPE_HEADER = 1;
    private static final int TYPE_SLOT = 2;
    private static final int LENGTH_OFFSET = 8;
    private static final int FRAME_BYTES = 12;
    private static final int CHECKSUM_BYTES = 32;
    private static final int LINEAGE_BYTES = 16;
    private static final int SIGNER_BYTES = 32;
    private static final int PHASE_CREATING = 1;
    private static final int PHASE_LIVE = 2;
    private static final int PHASE_RELEASING = 3;
    private static final int FLAG_RETIRING = 1;
    private static final int FIRST_APP_ID = 10_000;
    private static final int LAST_APP_ID = 19_999;
    private static final int PER_USER_RANGE = 100_000;
    private static final int MAX_PACKAGE_NAME_LENGTH = 255;
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    /** Stage of one held slot, as listed by the header. Every phase keeps the app ID held. */
    public enum SlotPhase {
        /** The slot is being created. Only this phase carries a creation proof. */
        CREATING,
        /** The slot record is established. */
        LIVE,
        /** Removal of the slot has begun. */
        RELEASING
    }

    /** One held slot as listed by the header. The constructor validates every field. */
    public static final class HeaderEntry {
        /** Held app ID, from 10000 to 19999. */
        public final int appId;
        public final SlotPhase phase;
        /**
         * CREATING only: the positive principal ID issued for this creation, at most the
         * header's lastId. Zero in every other phase.
         */
        public final long creationId;
        /** CREATING only: the package the slot is created for. Empty in every other phase. */
        public final String creationPackage;

        /**
         * @throws IllegalArgumentException for an invalid app ID or creation proof
         * @throws NullPointerException for a null phase or creation package
         */
        public HeaderEntry(int appId, SlotPhase phase, long creationId, String creationPackage) {
            checkAppId(appId);
            Objects.requireNonNull(phase, "phase");
            Objects.requireNonNull(creationPackage, "creationPackage");
            if (phase == SlotPhase.CREATING) {
                if (creationId <= 0) throw invalid("CREATING needs a positive creation ID");
                if (!isPackageName(creationPackage)) {
                    throw invalid("CREATING needs a valid creation package");
                }
            } else if (creationId != 0 || !creationPackage.isEmpty()) {
                throw invalid("only CREATING carries a creation proof");
            }
            this.appId = appId;
            this.phase = phase;
            this.creationId = creationId;
            this.creationPackage = creationPackage;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) return true;
            if (!(other instanceof HeaderEntry)) return false;
            HeaderEntry entry = (HeaderEntry) other;
            return appId == entry.appId && phase == entry.phase && creationId == entry.creationId
                    && creationPackage.equals(entry.creationPackage);
        }

        @Override
        public int hashCode() {
            // The ordinal keeps the hash stable across runs, unlike the enum's identity hash.
            return Objects.hash(appId, phase.ordinal(), creationId, creationPackage);
        }

        @Override
        public String toString() {
            return "HeaderEntry{appId=" + appId + ", " + phase + (phase == SlotPhase.CREATING
                    ? ", creationId=" + creationId + ", package=" + creationPackage : "") + "}";
        }
    }

    /** The store's list of held slots and its principal ID counter. */
    public static final class Header {
        /** Store lineage, 32 lowercase hex digits (128 bits). */
        public final String lineage;
        /** Highest principal ID issued in this lineage, including released IDs. Not negative. */
        public final long lastId;
        /**
         * Unmodifiable list of at most {@link #MAX_SLOTS} entries in strictly ascending app ID
         * order. The creation IDs of CREATING entries are distinct and at most lastId.
         */
        public final List<HeaderEntry> entries;

        /**
         * Copies the entries, which must already be in strictly ascending app ID order.
         *
         * @throws IllegalArgumentException for an invalid lineage, counter, count, order or
         *     creation ID
         * @throws NullPointerException for a null lineage, list or entry
         */
        public Header(String lineage, long lastId, List<HeaderEntry> entries) {
            checkHex(lineage, 2 * LINEAGE_BYTES, "lineage");
            if (lastId < 0) throw invalid("negative lastId");
            List<HeaderEntry> copy = List.copyOf(Objects.requireNonNull(entries, "entries"));
            if (copy.size() > MAX_SLOTS) throw invalid("more than MAX_SLOTS entries");
            Set<Long> creations = new HashSet<>();
            for (int i = 0; i < copy.size(); i++) {
                HeaderEntry entry = copy.get(i);
                if (i > 0 && entry.appId <= copy.get(i - 1).appId) {
                    throw invalid("entries not in strictly ascending app ID order");
                }
                if (entry.phase != SlotPhase.CREATING) continue;
                if (entry.creationId > lastId) throw invalid("creation ID above lastId");
                if (!creations.add(entry.creationId)) throw invalid("duplicate creation ID");
            }
            this.lineage = lineage;
            this.lastId = lastId;
            this.entries = copy;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) return true;
            if (!(other instanceof Header)) return false;
            Header header = (Header) other;
            return lastId == header.lastId && lineage.equals(header.lineage)
                    && entries.equals(header.entries);
        }

        @Override
        public int hashCode() {
            return Objects.hash(lineage, lastId, entries);
        }

        @Override
        public String toString() {
            return "Header{lastId=" + lastId + ", entries=" + entries + "}";
        }
    }

    /** The principal of a slot's package for one Android user. */
    public static final class UserEntry {
        /** Positive PMS principal ID. Not a native work ID. */
        public final long id;
        /** Android user ID, not negative. The slot checks that the resulting UID fits an int. */
        public final int userId;
        /** Serial number of this incarnation of the user. Not negative. */
        public final long userSerial;
        /** Durable retirement marker. It releases nothing by itself. */
        public final boolean retiring;

        /** @throws IllegalArgumentException for a nonpositive ID or a negative user or serial */
        public UserEntry(long id, int userId, long userSerial, boolean retiring) {
            if (id <= 0) throw invalid("principal ID must be positive");
            if (userId < 0) throw invalid("negative user ID");
            if (userSerial < 0) throw invalid("negative user serial");
            this.id = id;
            this.userId = userId;
            this.userSerial = userSerial;
            this.retiring = retiring;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) return true;
            if (!(other instanceof UserEntry)) return false;
            UserEntry user = (UserEntry) other;
            return id == user.id && userId == user.userId && userSerial == user.userSerial
                    && retiring == user.retiring;
        }

        @Override
        public int hashCode() {
            return Objects.hash(id, userId, userSerial, retiring);
        }

        @Override
        public String toString() {
            return "UserEntry{id=" + id + ", user=" + userId + ", serial=" + userSerial
                    + (retiring ? ", retiring}" : "}");
        }
    }

    /** One held app ID bound to a package, its signers and its principal for each user. */
    public static final class Slot {
        /** Store lineage, 32 lowercase hex digits. The caller compares it with the header. */
        public final String lineage;
        /** Held app ID, from 10000 to 19999. The caller compares it with the slot location. */
        public final int appId;
        /** ASCII package name with two or more segments and at most 255 characters. */
        public final String packageName;
        /** Positive persistence generation of this record, assigned by the store. */
        public final long generation;
        /**
         * Unmodifiable set of 1 to {@link #MAX_SIGNERS} SHA-256 signer certificate digests, each
         * 64 lowercase hex digits. It iterates in ascending order.
         */
        public final Set<String> signerSha256;
        /**
         * Unmodifiable list of at most {@link #MAX_USERS} principals in strictly ascending user
         * ID order, with distinct principal IDs. An empty list marks a tombstone, which still
         * holds the app ID.
         */
        public final List<UserEntry> users;

        /**
         * Copies the signer set in ascending order. Copies the users, which must already be in
         * strictly ascending user ID order.
         *
         * @throws IllegalArgumentException for an invalid field, count, digest, order, duplicate
         *     or a UID above {@link Integer#MAX_VALUE}
         * @throws NullPointerException for a null argument or element
         */
        public Slot(String lineage, int appId, String packageName, long generation,
                Set<String> signerSha256, List<UserEntry> users) {
            checkHex(lineage, 2 * LINEAGE_BYTES, "lineage");
            checkAppId(appId);
            Objects.requireNonNull(packageName, "packageName");
            if (!isPackageName(packageName)) throw invalid("malformed package name");
            if (generation <= 0) throw invalid("generation must be positive");
            Set<String> signers = sortedSigners(signerSha256);
            List<UserEntry> copy = List.copyOf(Objects.requireNonNull(users, "users"));
            if (copy.size() > MAX_USERS) throw invalid("more than MAX_USERS users");
            Set<Long> ids = new HashSet<>();
            for (int i = 0; i < copy.size(); i++) {
                UserEntry user = copy.get(i);
                if (i > 0 && user.userId <= copy.get(i - 1).userId) {
                    throw invalid("users not in strictly ascending user ID order");
                }
                if ((long) user.userId * PER_USER_RANGE + appId > Integer.MAX_VALUE) {
                    throw invalid("UID above Integer.MAX_VALUE");
                }
                if (!ids.add(user.id)) throw invalid("duplicate principal ID");
            }
            this.lineage = lineage;
            this.appId = appId;
            this.packageName = packageName;
            this.generation = generation;
            this.signerSha256 = signers;
            this.users = copy;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) return true;
            if (!(other instanceof Slot)) return false;
            Slot slot = (Slot) other;
            return appId == slot.appId && generation == slot.generation
                    && lineage.equals(slot.lineage) && packageName.equals(slot.packageName)
                    && signerSha256.equals(slot.signerSha256) && users.equals(slot.users);
        }

        @Override
        public int hashCode() {
            return Objects.hash(lineage, appId, packageName, generation, signerSha256, users);
        }

        @Override
        public String toString() {
            return "Slot{appId=" + appId + ", package=" + packageName + ", generation="
                    + generation + ", signers=" + signerSha256.size() + ", users=" + users + "}";
        }
    }

    private NativeIdentityRecords() {}

    /** Returns the one encoding of a header, in a new array. */
    public static byte[] encodeHeader(Header header) {
        Objects.requireNonNull(header, "header");
        Output out = new Output(TYPE_HEADER);
        out.hex(header.lineage);
        out.i64(header.lastId);
        out.u16(header.entries.size());
        for (HeaderEntry entry : header.entries) {
            out.i32(entry.appId);
            out.u8(phaseCode(entry.phase));
            out.i64(entry.creationId);
            out.ascii(entry.creationPackage);
        }
        return out.seal();
    }

    /**
     * Decodes one complete header encoding. The input is copied and not retained.
     *
     * @throws IllegalArgumentException for any damaged, malformed or unsupported input
     * @throws NullPointerException for null
     */
    public static Header decodeHeader(byte[] record) {
        Input in = Input.open(record, TYPE_HEADER);
        String lineage = in.hex(LINEAGE_BYTES);
        long lastId = in.i64();
        int count = in.count(MAX_SLOTS);
        List<HeaderEntry> entries = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            int appId = in.i32();
            SlotPhase phase = phase(in.u8());
            long creationId = in.i64();
            String creationPackage = in.ascii();
            if (i > 0 && appId <= entries.get(i - 1).appId) throw invalid("entries out of order");
            entries.add(new HeaderEntry(appId, phase, creationId, creationPackage));
        }
        in.finish();
        return new Header(lineage, lastId, entries);
    }

    /** Returns the one encoding of a slot, in a new array. */
    public static byte[] encodeSlot(Slot slot) {
        Objects.requireNonNull(slot, "slot");
        Output out = new Output(TYPE_SLOT);
        out.hex(slot.lineage);
        out.i32(slot.appId);
        out.i64(slot.generation);
        out.ascii(slot.packageName);
        out.u16(slot.signerSha256.size());
        for (String digest : slot.signerSha256) out.hex(digest); // Ascending order.
        out.u16(slot.users.size());
        for (UserEntry user : slot.users) {
            out.i64(user.id);
            out.i32(user.userId);
            out.i64(user.userSerial);
            out.u8(user.retiring ? FLAG_RETIRING : 0);
        }
        return out.seal();
    }

    /**
     * Decodes one complete slot encoding. The input is copied and not retained.
     *
     * @throws IllegalArgumentException for any damaged, malformed or unsupported input
     * @throws NullPointerException for null
     */
    public static Slot decodeSlot(byte[] record) {
        Input in = Input.open(record, TYPE_SLOT);
        String lineage = in.hex(LINEAGE_BYTES);
        int appId = in.i32();
        long generation = in.i64();
        String packageName = in.ascii();
        int signerCount = in.count(MAX_SIGNERS);
        List<String> signers = new ArrayList<>(signerCount);
        for (int i = 0; i < signerCount; i++) {
            String digest = in.hex(SIGNER_BYTES);
            // Checked before any set exists, which would silently merge a duplicate.
            if (i > 0 && digest.compareTo(signers.get(i - 1)) <= 0) {
                throw invalid("signer digests out of order");
            }
            signers.add(digest);
        }
        int userCount = in.count(MAX_USERS);
        List<UserEntry> users = new ArrayList<>(userCount);
        for (int i = 0; i < userCount; i++) {
            long id = in.i64();
            int userId = in.i32();
            long userSerial = in.i64();
            int flags = in.u8();
            if ((flags & ~FLAG_RETIRING) != 0) throw invalid("reserved user flags set");
            if (i > 0 && userId <= users.get(i - 1).userId) throw invalid("users out of order");
            users.add(new UserEntry(id, userId, userSerial, flags == FLAG_RETIRING));
        }
        in.finish();
        return new Slot(lineage, appId, packageName, generation, new LinkedHashSet<>(signers),
                users);
    }

    // Builds one record: frame, body, then the checksum.
    private static final class Output {
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream(256);

        Output(int type) {
            i32(MAGIC);
            u16(type);
            u16(VERSION);
            i32(0); // Total length, set by seal.
        }

        void u8(int value) {
            bytes.write(value);
        }

        void u16(int value) {
            u8(value);
            u8(value >>> 8);
        }

        void i32(int value) {
            u16(value);
            u16(value >>> 16);
        }

        void i64(long value) {
            i32((int) value);
            i32((int) (value >>> 32));
        }

        // Validated lowercase hex, written as raw bytes.
        void hex(String digits) {
            for (int i = 0; i < digits.length(); i += 2) {
                u8((Character.digit(digits.charAt(i), 16) << 4)
                        | Character.digit(digits.charAt(i + 1), 16));
            }
        }

        // Validated ASCII.
        void ascii(String value) {
            u16(value.length());
            byte[] text = value.getBytes(StandardCharsets.US_ASCII);
            bytes.write(text, 0, text.length);
        }

        byte[] seal() {
            int length = bytes.size() + CHECKSUM_BYTES;
            // The value bounds keep every record far smaller. This is only a guard.
            if (length > MAX_BYTES) throw new IllegalStateException("record exceeds MAX_BYTES");
            byte[] record = Arrays.copyOf(bytes.toByteArray(), length);
            for (int i = 0; i < 4; i++) record[LENGTH_OFFSET + i] = (byte) (length >>> (8 * i));
            byte[] checksum = sha256(record, length - CHECKSUM_BYTES);
            System.arraycopy(checksum, 0, record, length - CHECKSUM_BYTES, CHECKSUM_BYTES);
            return record;
        }
    }

    // Reads the body of one record whose frame and checksum were verified. Reads stop at the
    // body's end.
    private static final class Input {
        private final byte[] bytes;
        private final int end;
        private int position = FRAME_BYTES;

        private Input(byte[] bytes, int end) {
            this.bytes = bytes;
            this.end = end;
        }

        // Verifies a private copy, so later writes to the caller's array cannot race the checks.
        static Input open(byte[] record, int type) {
            Objects.requireNonNull(record, "record");
            if (record.length > MAX_BYTES) throw invalid("record exceeds MAX_BYTES");
            if (record.length < FRAME_BYTES + CHECKSUM_BYTES) throw invalid("record too short");
            byte[] bytes = record.clone();
            if (i32At(bytes, 0) != MAGIC) throw invalid("not a native identity record");
            if (u16At(bytes, 6) != VERSION) throw invalid("unsupported record version");
            if (u16At(bytes, 4) != type) throw invalid("wrong record type");
            if (i32At(bytes, LENGTH_OFFSET) != bytes.length) throw invalid("wrong record length");
            int end = bytes.length - CHECKSUM_BYTES;
            if (!MessageDigest.isEqual(sha256(bytes, end),
                    Arrays.copyOfRange(bytes, end, bytes.length))) {
                throw invalid("record checksum mismatch");
            }
            return new Input(bytes, end);
        }

        private int take(int count) {
            if (count > end - position) throw invalid("truncated record");
            int at = position;
            position += count;
            return at;
        }

        int u8() {
            return bytes[take(1)] & 0xff;
        }

        int u16() {
            return u16At(bytes, take(2));
        }

        int i32() {
            return i32At(bytes, take(4));
        }

        long i64() {
            int at = take(8);
            return (i32At(bytes, at) & 0xffffffffL) | ((long) i32At(bytes, at + 4) << 32);
        }

        int count(int max) {
            int count = u16();
            if (count > max) throw invalid("count above its bound");
            return count;
        }

        String hex(int count) {
            int at = take(count);
            char[] digits = new char[2 * count];
            for (int i = 0; i < count; i++) {
                digits[2 * i] = HEX[(bytes[at + i] & 0xff) >>> 4];
                digits[2 * i + 1] = HEX[bytes[at + i] & 0xf];
            }
            return new String(digits);
        }

        // Strict ASCII. The value's constructor checks its grammar.
        String ascii() {
            int length = u16();
            if (length > MAX_PACKAGE_NAME_LENGTH) throw invalid("string too long");
            int at = take(length);
            for (int i = at; i < at + length; i++) {
                if (bytes[i] < 0) throw invalid("non-ASCII byte");
            }
            return new String(bytes, at, length, StandardCharsets.US_ASCII);
        }

        void finish() {
            if (position != end) throw invalid("trailing bytes");
        }
    }

    private static int u16At(byte[] bytes, int at) {
        return (bytes[at] & 0xff) | ((bytes[at + 1] & 0xff) << 8);
    }

    private static int i32At(byte[] bytes, int at) {
        return u16At(bytes, at) | (u16At(bytes, at + 2) << 16);
    }

    private static byte[] sha256(byte[] bytes, int length) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(bytes, 0, length);
            return digest.digest();
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 unavailable", error);
        }
    }

    private static int phaseCode(SlotPhase phase) {
        switch (phase) {
            case CREATING:
                return PHASE_CREATING;
            case LIVE:
                return PHASE_LIVE;
            case RELEASING:
                return PHASE_RELEASING;
        }
        throw new IllegalStateException("slot phase without an encoding");
    }

    private static SlotPhase phase(int code) {
        switch (code) {
            case PHASE_CREATING:
                return SlotPhase.CREATING;
            case PHASE_LIVE:
                return SlotPhase.LIVE;
            case PHASE_RELEASING:
                return SlotPhase.RELEASING;
            default:
                throw invalid("unknown slot phase");
        }
    }

    private static void checkAppId(int appId) {
        if (appId < FIRST_APP_ID || appId > LAST_APP_ID) {
            throw invalid("app ID outside " + FIRST_APP_ID + ".." + LAST_APP_ID);
        }
    }

    private static void checkHex(String value, int digits, String field) {
        Objects.requireNonNull(value, field);
        boolean valid = value.length() == digits;
        for (int i = 0; valid && i < digits; i++) {
            char c = value.charAt(i);
            valid = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        }
        if (!valid) throw invalid(field + " is not " + digits + " lowercase hex digits");
    }

    // One snapshot of the caller's set, validated, then sorted into an unmodifiable copy.
    private static Set<String> sortedSigners(Set<String> input) {
        List<String> digests = new ArrayList<>(Objects.requireNonNull(input, "signerSha256"));
        if (digests.isEmpty() || digests.size() > MAX_SIGNERS) {
            throw invalid("signer count outside 1..MAX_SIGNERS");
        }
        for (String digest : digests) checkHex(digest, 2 * SIGNER_BYTES, "signer digest");
        Collections.sort(digests);
        for (int i = 1; i < digests.size(); i++) {
            if (digests.get(i).equals(digests.get(i - 1))) throw invalid("duplicate signer digest");
        }
        return Collections.unmodifiableSet(new LinkedHashSet<>(digests));
    }

    // Dot separated ASCII segments. Each starts with a letter, then letters, digits or '_'.
    private static boolean isPackageName(String name) {
        int length = name.length();
        if (length > MAX_PACKAGE_NAME_LENGTH) return false;
        int segments = 1;
        boolean segmentStart = true;
        for (int i = 0; i < length; i++) {
            char c = name.charAt(i);
            boolean letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
            boolean trailing = (c >= '0' && c <= '9') || c == '_';
            if (letter || (trailing && !segmentStart)) {
                segmentStart = false;
            } else if (c == '.' && !segmentStart) {
                ++segments;
                segmentStart = true;
            } else {
                return false;
            }
        }
        return !segmentStart && segments >= 2;
    }

    private static IllegalArgumentException invalid(String reason) {
        return new IllegalArgumentException(reason);
    }
}
