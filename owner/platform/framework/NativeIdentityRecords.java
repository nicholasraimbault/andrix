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
 * <p>Layout. Integers are fixed width and little endian. A string is a u16 length and that many
 * ASCII bytes. The lineage and signer digests are raw bytes. A slot has version 1. A header has
 * version 1 or 2, which differ only in their CREATING entries.
 * <pre>
 * record  u32 magic 0x44495841 ("AXID"), u16 type (1 header, 2 slot), u16 version,
 *         u32 total length, body, then the SHA-256 of all preceding bytes
 * header  lineage[16], i64 lastId, u16 count, then count entries in app ID order:
 *         i32 appId, u8 phase (1 CREATING, 2 LIVE, 3 RELEASING), i64 creationId,
 *         string creationPackage, then only in a version 2 CREATING entry:
 *         u8 binding (0 absent, 1 present), and if present: i32 userId,
 *         i64 userSerial, u16 count, then count signer digests[32] in ascending order
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
 * <p>The frame is the size bound, magic, type, length field and checksum. Decoding verifies it
 * before it checks the version. The store can therefore tell an intact record of a version it
 * does not support from damage, without parsing that record's body. Such a record is a
 * footprint to preserve, never a value: it yields no app ID, binding or counter.
 *
 * <p>A header keeps the version it was built or decoded with, and encodes with it. Equality
 * compares versions, so comparing a header with an expected one compares them too. The public
 * constructor makes version 1 and {@link Header#newV2} makes version 2. Nothing converts one into
 * the other. Only a version 2 CREATING entry can carry a {@link CreationBinding}. A version 2
 * CREATING entry without one is an incomplete entry kept from an older writer. It keeps its
 * hold, and it is no grant to create anything.
 *
 * <p>The checksum detects accidental damage, such as a torn, truncated or extended write. It is
 * not authenticity: whoever can write a record can recompute it. The store's protection rests on
 * Package Manager's own files and policy. This format is private to this framework and is not a
 * public ABI. A layout change needs a new version and an explicit migration. The MAX constants
 * are initial parser bounds, not product quotas. Large creation bindings can take a version 2
 * header above MAX_BYTES before it reaches MAX_SLOTS entries. Its constructor refuses such a
 * header, so every valid value has an encoding.
 */
public final class NativeIdentityRecords {
    /** Largest accepted encoding of either record, in bytes. */
    public static final int MAX_BYTES = 65536;
    /** Most entries in one header. */
    public static final int MAX_SLOTS = 64;
    /** Most users in one slot. */
    public static final int MAX_USERS = 64;
    /** Most signer digests in one slot or creation binding. */
    public static final int MAX_SIGNERS = 32;

    private static final int MAGIC = 0x44495841; // "AXID" in file order.
    private static final int VERSION_1 = 1;
    private static final int VERSION_2 = 2; // Headers only.
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
    private static final int BINDING_ABSENT = 0;
    private static final int BINDING_PRESENT = 1;
    private static final int FLAG_RETIRING = 1;
    private static final int FIRST_APP_ID = 10_000;
    private static final int LAST_APP_ID = 19_999;
    private static final int PER_USER_RANGE = 100_000;
    private static final int MAX_PACKAGE_NAME_LENGTH = 255;
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    /** Stage of one held slot, as listed by the header. Every phase keeps the app ID held. */
    public enum SlotPhase {
        /**
         * The slot is being created. Only this phase carries a creation proof and, in a version
         * 2 header, a creation binding.
         */
        CREATING,
        /** The slot record is established. */
        LIVE,
        /** Removal of the slot has begun. */
        RELEASING
    }

    /**
     * The user, user serial and signer set that a CREATING entry was reserved for. With the
     * entry's app ID, creation ID and package it names the complete binding of the slot being
     * created. Only a version 2 header carries it. It records what its writer checked. It does
     * not show that the user, serial or signers are still current, and it grants nothing. The
     * constructor validates every field.
     */
    public static final class CreationBinding {
        /** Android user ID, not negative. The entry checks that the resulting UID fits an int. */
        public final int userId;
        /** Serial number of this incarnation of the user. Not negative. */
        public final long userSerial;
        /**
         * Unmodifiable set of 1 to {@link #MAX_SIGNERS} SHA-256 signer certificate digests, each
         * 64 lowercase hex digits. It iterates in ascending order.
         */
        public final Set<String> signerSha256;

        /**
         * Copies the signer set in ascending order.
         *
         * @throws IllegalArgumentException for a negative user or serial, or an invalid signer
         *     count, digest or duplicate
         * @throws NullPointerException for a null set or digest
         */
        public CreationBinding(int userId, long userSerial, Set<String> signerSha256) {
            checkUser(userId, userSerial);
            this.userId = userId;
            this.userSerial = userSerial;
            this.signerSha256 = sortedSigners(signerSha256);
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) return true;
            if (!(other instanceof CreationBinding)) return false;
            CreationBinding binding = (CreationBinding) other;
            return userId == binding.userId && userSerial == binding.userSerial
                    && signerSha256.equals(binding.signerSha256);
        }

        @Override
        public int hashCode() {
            return Objects.hash(userId, userSerial, signerSha256);
        }

        @Override
        public String toString() {
            return "CreationBinding{user=" + userId + ", serial=" + userSerial + ", signers="
                    + signerSha256.size() + "}";
        }
    }

    /** One held slot as listed by the header. The constructors validate every field. */
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
         * CREATING only, and only in a version 2 header: the user, serial and signers of this
         * creation, or null. Null in every other phase. A CREATING entry without a binding is
         * incomplete. It keeps its hold, and nothing may fill in current values for it. The
         * codec cannot tell a kept entry from a new one, so binding each new reservation is the
         * writer's duty.
         */
        public final CreationBinding creationBinding;

        /**
         * An entry without a creation binding.
         *
         * @throws IllegalArgumentException for an invalid app ID or creation proof
         * @throws NullPointerException for a null phase or creation package
         */
        public HeaderEntry(int appId, SlotPhase phase, long creationId, String creationPackage) {
            this(appId, phase, creationId, creationPackage, null);
        }

        /**
         * An entry with an optional creation binding, which only CREATING may carry. The
         * binding's user and this app ID must give a UID that fits an int.
         *
         * @throws IllegalArgumentException for an invalid app ID, creation proof or binding
         * @throws NullPointerException for a null phase or creation package
         */
        public HeaderEntry(int appId, SlotPhase phase, long creationId, String creationPackage,
                CreationBinding creationBinding) {
            checkAppId(appId);
            Objects.requireNonNull(phase, "phase");
            Objects.requireNonNull(creationPackage, "creationPackage");
            if (phase == SlotPhase.CREATING) {
                if (creationId <= 0) throw invalid("CREATING needs a positive creation ID");
                if (!isPackageName(creationPackage)) {
                    throw invalid("CREATING needs a valid creation package");
                }
                if (creationBinding != null) checkUid(creationBinding.userId, appId);
            } else if (creationId != 0 || !creationPackage.isEmpty()) {
                throw invalid("only CREATING carries a creation proof");
            } else if (creationBinding != null) {
                throw invalid("only CREATING carries a creation binding");
            }
            this.appId = appId;
            this.phase = phase;
            this.creationId = creationId;
            this.creationPackage = creationPackage;
            this.creationBinding = creationBinding;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) return true;
            if (!(other instanceof HeaderEntry)) return false;
            HeaderEntry entry = (HeaderEntry) other;
            return appId == entry.appId && phase == entry.phase && creationId == entry.creationId
                    && creationPackage.equals(entry.creationPackage)
                    && Objects.equals(creationBinding, entry.creationBinding);
        }

        @Override
        public int hashCode() {
            // The ordinal keeps the hash stable across runs, unlike the enum's identity hash.
            return Objects.hash(appId, phase.ordinal(), creationId, creationPackage,
                    creationBinding);
        }

        @Override
        public String toString() {
            return "HeaderEntry{appId=" + appId + ", " + phase + (phase == SlotPhase.CREATING
                    ? ", creationId=" + creationId + ", package=" + creationPackage
                    + (creationBinding == null ? "" : ", " + creationBinding) : "") + "}";
        }
    }

    /** The store's list of held slots and its principal ID counter. */
    public static final class Header {
        /**
         * Wire version: 1 from the public constructor, 2 from {@link #newV2}. The encoding uses
         * it and equality compares it. Only version 2 carries creation bindings.
         */
        public final int version;
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
         * A version 1 header. Copies the entries, which must already be in strictly ascending
         * app ID order and carry no creation binding.
         *
         * @throws IllegalArgumentException for an invalid lineage, counter, count, order or
         *     creation ID, or a creation binding
         * @throws NullPointerException for a null lineage, list or entry
         */
        public Header(String lineage, long lastId, List<HeaderEntry> entries) {
            this(VERSION_1, lineage, lastId, entries);
        }

        /**
         * A version 2 header, whose CREATING entries may carry creation bindings. Copies the
         * entries, which must already be in strictly ascending app ID order. This only builds a
         * value. It restores no pending pin, creates no package setting, initializes no store,
         * cancels no creation, admits no tombstone, releases no UID and makes no record or
         * reference an authority.
         *
         * @throws IllegalArgumentException for an invalid lineage, counter, count, order or
         *     creation ID, or an encoding larger than {@link #MAX_BYTES}
         * @throws NullPointerException for a null lineage, list or entry
         */
        public static Header newV2(String lineage, long lastId, List<HeaderEntry> entries) {
            return new Header(VERSION_2, lineage, lastId, entries);
        }

        private Header(int version, String lineage, long lastId, List<HeaderEntry> entries) {
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
                if (version == VERSION_1 && entry.creationBinding != null) {
                    throw invalid("version 1 carries no creation binding");
                }
            }
            // Measured by the encoder itself, so every valid header has its encoding.
            if (headerBody(version, lineage, lastId, copy).length() > MAX_BYTES) {
                throw invalid("header encoding above MAX_BYTES");
            }
            this.version = version;
            this.lineage = lineage;
            this.lastId = lastId;
            this.entries = copy;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) return true;
            if (!(other instanceof Header)) return false;
            Header header = (Header) other;
            return version == header.version && lastId == header.lastId
                    && lineage.equals(header.lineage) && entries.equals(header.entries);
        }

        @Override
        public int hashCode() {
            return Objects.hash(version, lineage, lastId, entries);
        }

        @Override
        public String toString() {
            return "Header{version=" + version + ", lastId=" + lastId + ", entries=" + entries
                    + "}";
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
            checkUser(userId, userSerial);
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
                checkUid(user.userId, appId);
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

    /** Returns the one encoding of a header, with its own version, in a new array. */
    public static byte[] encodeHeader(Header header) {
        Objects.requireNonNull(header, "header");
        return headerBody(header.version, header.lineage, header.lastId, header.entries).seal();
    }

    // Everything before the checksum. The Header constructor measures this too.
    private static Output headerBody(int version, String lineage, long lastId,
            List<HeaderEntry> entries) {
        Output out = new Output(TYPE_HEADER, version);
        out.hex(lineage);
        out.i64(lastId);
        out.u16(entries.size());
        for (HeaderEntry entry : entries) {
            out.i32(entry.appId);
            out.u8(phaseCode(entry.phase));
            out.i64(entry.creationId);
            out.ascii(entry.creationPackage);
            CreationBinding binding = entry.creationBinding;
            if (version == VERSION_1 || entry.phase != SlotPhase.CREATING) {
                // The constructors refuse this. A binding is never dropped silently.
                if (binding != null) throw new IllegalStateException("binding without an encoding");
            } else if (binding == null) {
                out.u8(BINDING_ABSENT);
            } else {
                out.u8(BINDING_PRESENT);
                out.i32(binding.userId);
                out.i64(binding.userSerial);
                out.signers(binding.signerSha256);
            }
        }
        return out;
    }

    /**
     * For the store only. Returns the declared version of an intact header frame, or -1 for any
     * other input. See {@link #intactSlotVersion}.
     *
     * @throws NullPointerException for null
     */
    static int intactHeaderVersion(byte[] record) {
        return intactVersion(record, TYPE_HEADER);
    }

    /**
     * For the store only. Returns the declared version of an intact slot frame, or -1 for any
     * other input. A frame is intact when the record is within the size bounds, starts with the
     * magic and this record type, and its length field and SHA-256 match. The version itself is
     * returned unchecked, and nothing after the frame is parsed. The result is no value and
     * grants nothing. A version this codec cannot decode yields no app ID, binding or counter.
     *
     * @throws NullPointerException for null
     */
    static int intactSlotVersion(byte[] record) {
        return intactVersion(record, TYPE_SLOT);
    }

    private static int intactVersion(byte[] record, int type) {
        Objects.requireNonNull(record, "record");
        try {
            return frame(bounded(record).clone(), type);
        } catch (IllegalArgumentException notIntact) {
            return -1;
        }
    }

    /**
     * Decodes one complete header encoding of version 1 or 2. The value keeps that version. The
     * input is copied and not retained.
     *
     * @throws IllegalArgumentException for any damaged, malformed or unsupported input
     * @throws NullPointerException for null
     */
    public static Header decodeHeader(byte[] record) {
        Input in = Input.open(record, TYPE_HEADER, VERSION_2);
        String lineage = in.hex(LINEAGE_BYTES);
        long lastId = in.i64();
        int count = in.count(MAX_SLOTS);
        List<HeaderEntry> entries = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            int appId = in.i32();
            SlotPhase phase = phase(in.u8());
            long creationId = in.i64();
            String creationPackage = in.ascii();
            CreationBinding binding = in.version == VERSION_2 && phase == SlotPhase.CREATING
                    ? in.creationBinding() : null;
            if (i > 0 && appId <= entries.get(i - 1).appId) throw invalid("entries out of order");
            entries.add(new HeaderEntry(appId, phase, creationId, creationPackage, binding));
        }
        in.finish();
        return in.version == VERSION_1 ? new Header(lineage, lastId, entries)
                : Header.newV2(lineage, lastId, entries);
    }

    /** Returns the one encoding of a slot, in a new array. */
    public static byte[] encodeSlot(Slot slot) {
        Objects.requireNonNull(slot, "slot");
        Output out = new Output(TYPE_SLOT, VERSION_1);
        out.hex(slot.lineage);
        out.i32(slot.appId);
        out.i64(slot.generation);
        out.ascii(slot.packageName);
        out.signers(slot.signerSha256);
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
        Input in = Input.open(record, TYPE_SLOT, VERSION_1);
        String lineage = in.hex(LINEAGE_BYTES);
        int appId = in.i32();
        long generation = in.i64();
        String packageName = in.ascii();
        Set<String> signers = in.signers();
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
        return new Slot(lineage, appId, packageName, generation, signers, users);
    }

    // Builds one record: frame, body, then the checksum.
    private static final class Output {
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream(256);

        Output(int type, int version) {
            i32(MAGIC);
            u16(type);
            u16(version);
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

        // A validated set, which iterates in ascending order.
        void signers(Set<String> digests) {
            u16(digests.size());
            for (String digest : digests) hex(digest);
        }

        // The length of the sealed record.
        int length() {
            return bytes.size() + CHECKSUM_BYTES;
        }

        byte[] seal() {
            int length = length();
            // Value construction enforces the bound; keep the final guard too.
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
        // The record's verified version.
        final int version;
        private int position = FRAME_BYTES;

        private Input(byte[] bytes, int end, int version) {
            this.bytes = bytes;
            this.end = end;
            this.version = version;
        }

        // Verifies a private copy, so later writes to the caller's array cannot race the checks.
        // The frame is verified first. Accepts versions 1 to newest.
        static Input open(byte[] record, int type, int newest) {
            byte[] bytes = bounded(record).clone();
            int version = frame(bytes, type);
            if (version < VERSION_1 || version > newest) {
                throw invalid("unsupported record version");
            }
            return new Input(bytes, bytes.length - CHECKSUM_BYTES, version);
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

        // A count, then strictly ascending digests. The value's constructor checks the set.
        Set<String> signers() {
            int count = count(MAX_SIGNERS);
            List<String> digests = new ArrayList<>(count);
            for (int i = 0; i < count; i++) {
                String digest = hex(SIGNER_BYTES);
                // Checked before any set exists, which would silently merge a duplicate.
                if (i > 0 && digest.compareTo(digests.get(i - 1)) <= 0) {
                    throw invalid("signer digests out of order");
                }
                digests.add(digest);
            }
            return new LinkedHashSet<>(digests);
        }

        // A version 2 CREATING entry's tag, then its binding if present.
        CreationBinding creationBinding() {
            int tag = u8();
            if (tag == BINDING_ABSENT) return null;
            if (tag != BINDING_PRESENT) throw invalid("unknown creation binding tag");
            int userId = i32();
            long userSerial = i64();
            return new CreationBinding(userId, userSerial, signers());
        }

        void finish() {
            if (position != end) throw invalid("trailing bytes");
        }
    }

    // Refuses null and a size outside the frame bounds, before anything is copied.
    private static byte[] bounded(byte[] record) {
        Objects.requireNonNull(record, "record");
        if (record.length > MAX_BYTES) throw invalid("record exceeds MAX_BYTES");
        if (record.length < FRAME_BYTES + CHECKSUM_BYTES) throw invalid("record too short");
        return record;
    }

    // Verifies the magic, type, length field and checksum of a bounded private copy. Returns the
    // declared version, which the caller checks.
    private static int frame(byte[] bytes, int type) {
        if (i32At(bytes, 0) != MAGIC) throw invalid("not a native identity record");
        if (u16At(bytes, 4) != type) throw invalid("wrong record type");
        if (i32At(bytes, LENGTH_OFFSET) != bytes.length) throw invalid("wrong record length");
        int end = bytes.length - CHECKSUM_BYTES;
        if (!MessageDigest.isEqual(sha256(bytes, end),
                Arrays.copyOfRange(bytes, end, bytes.length))) {
            throw invalid("record checksum mismatch");
        }
        return u16At(bytes, 6);
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

    // Shared by slot users and creation bindings.
    private static void checkUser(int userId, long userSerial) {
        if (userId < 0) throw invalid("negative user ID");
        if (userSerial < 0) throw invalid("negative user serial");
    }

    private static void checkUid(int userId, int appId) {
        if ((long) userId * PER_USER_RANGE + appId > Integer.MAX_VALUE) {
            throw invalid("UID above Integer.MAX_VALUE");
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
