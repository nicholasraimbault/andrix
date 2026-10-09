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
 * ASCII bytes. The lineage, signer digests, references and digests are raw bytes. A header has
 * version 1 or 2, which differ only in their CREATING entries. A slot has version 1 or 2.
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
 *         u16 count, then in version 1 count users in user ID order: i64 id,
 *         i32 userId, i64 userSerial, u8 flags (bit 0 retiring, other bits reserved and zero)
 * slot 2  the same fields through the user count, then count user identities in user ID
 *         order: i64 id, i32 userId, i64 userSerial. That is the stable prefix. Then one
 *         lifecycle block for each user in the same order, and only when count is 0 the
 *         release ticket: i64 lastId, i32 userId, i64 userSerial, ticket[16]
 * block   u8 state (1 ELIGIBLE, 2 RETIRING, 3 RETIRED), u8 count (0 to 6), then count
 *         suspension entries in ascending (class, actor serial, grant) order: u8 class
 *         (1 ACCOUNT_USER, 2 ADMIN_GRANT, 3 RECOVERY_HOLD), u8 scope (bit 0 blocks deletion
 *         and migration, bit 1 prior state unknown, other bits zero), i32 actorUser,
 *         i64 actorSerial, grant[16], u16 reason, i64 time, u8 note (0 none, 1 present),
 *         and if present the note's salted SHA-256[32]. Then, exactly when the state is
 *         RETIRING or RETIRED, the retirement: u8 class (1 ACCOUNT_USER, 2 ADMIN_GRANT,
 *         4 USER_REMOVAL, 5 LEGACY_MARKER), i32 actorUser, i64 actorSerial, grant[16],
 *         i64 time, u8 inventory (0 unknown, 1 known), u8 count (0 for inventory 0, 16 for
 *         inventory 1), then count obligations in kind order: u8 kind (1 to 16), u8 state
 *         (1 OUTSTANDING, 2 DISPOSING, 3 DISCHARGED, 4 ORPHANED_WITH_USER), reference[16],
 *         u8 code, i64 time
 * </pre>
 * Each valid value has exactly one encoding, and decoding accepts nothing else. Before it
 * returns a value, it checks the size, frame, checksum, strict ASCII, every field rule and
 * bound, strict ordering without duplicates, reserved bits and the absence of trailing bytes. It
 * never reorders or repairs input. Malformed input throws {@link IllegalArgumentException}, null
 * input throws {@link NullPointerException}, and no call returns partial output. Messages do not
 * repeat input values.
 *
 * <p>A slot's version follows from its value. It is version 1 exactly when it has users and every
 * user is either ELIGIBLE with no suspension entry, or the legacy retirement marker: RETIRING by
 * LEGACY_MARKER with no actor, grant, time, obligation or suspension entry. A tombstone without a
 * release ticket is version 1 too. Every other value is version 2, and the version 2 decoder
 * refuses a value that version 1 can express, so one value never has two encodings. Version 1
 * keeps its own layout, in which each user's flag byte follows that user's identity, and its
 * bytes do not change. Strict fields refuse unknown values: the state, the classes, the scope,
 * the inventory, and each obligation's kind and state. The reason, the times and the obligation
 * code are informational. They accept any value and decide nothing, so they never carry
 * authorization, expiry or discharge. The decoder also refuses values no writer can produce:
 * DISPOSING on a retirement kind or outside RETIRED, RETIRED with an unknown inventory or with a
 * retirement kind not DISCHARGED, and a second entry from one actor. Scope bit 0 decodes; only
 * the writers that set it are withheld. The largest version 2 slot takes 1,357 bytes for its
 * fixed part and 931 for each of 64 users, 60,941 bytes in all, so every valid slot encodes.
 *
 * <p>The stable prefix is frozen. Every later slot version starts with it, with the same bounds:
 * at most 64 users and 32 signers, a package name of at most 255 characters and an app ID in
 * the application range. Its reader also enforces the prefix's other rules, which bind every
 * later version just as the bounds do: a positive generation, a package name of the package
 * grammar, at least one signer digest in strictly ascending order, users in strictly ascending
 * user ID order, each with a positive principal ID, a user and serial that are not negative and
 * a UID that fits an int, and no principal ID twice. A reader that does not understand a later
 * version can still take that version's package name and principal IDs from it, as negative
 * evidence only. It yields no lifecycle state, binding, counter or hold, and a prefix that fails
 * any of its rules yields nothing. The reason codes form a registry with no catch-all: see
 * {@link SuspensionReason}.
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
 * header, so every valid value has an encoding. {@link #encodedHeaderLength} measures a
 * proposed header with the encoder itself, so a writer can refuse it before issuing anything.
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
    /** Most suspension entries of one user in a version 2 slot. A bound of that version only. */
    static final int MAX_SUSPENSIONS = 6;
    /** Suspension scope bit 0: the entry blocks deletion and migration. No writer sets it yet. */
    static final int SCOPE_BLOCKS_DISPOSITION = 1;
    /** Suspension scope bit 1: the prior lifecycle state is unknown. Recovery holds only. */
    static final int SCOPE_PRIOR_UNKNOWN = 2;
    /** The all zero reference: no grant, an unbound obligation, never a ticket. */
    static final String NO_REFERENCE = "0".repeat(32);

    private static final int MAGIC = 0x44495841; // "AXID" in file order.
    private static final int VERSION_1 = 1;
    private static final int VERSION_2 = 2;
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
    private static final int REFERENCE_BYTES = 16;
    private static final int NOTE_BYTES = 32;
    private static final int NOTE_ABSENT = 0;
    private static final int NOTE_PRESENT = 1;
    private static final int INVENTORY_UNKNOWN = 0;
    private static final int INVENTORY_KNOWN = 1;
    private static final int OBLIGATION_KINDS = 16;
    private static final int MAX_CODE = 0xff;
    private static final int MAX_REASON = 0xffff;
    // The stable prefix's bounds, frozen with it for every later slot version: these two, the
    // application app ID range and the package name length below. MAX_USERS and MAX_SIGNERS
    // may change with a later version; these do not.
    private static final int PREFIX_MAX_USERS = 64;
    private static final int PREFIX_MAX_SIGNERS = 32;
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

    /** Lifecycle state of one account in a slot. No state releases anything by itself. */
    public enum LifecycleState {
        /** The account may be designated, unless a suspension entry holds it. */
        ELIGIBLE(1),
        /** Retirement began. Its obligations are recorded before quiescence starts. */
        RETIRING(2),
        /** Every retirement obligation is discharged. Disposition obligations may remain. */
        RETIRED(3);

        final int code;

        LifecycleState(int code) {
            this.code = code;
        }
    }

    /**
     * Who acted on an account. A suspension entry is ACCOUNT_USER, ADMIN_GRANT or RECOVERY_HOLD,
     * and a retirement is ACCOUNT_USER, ADMIN_GRANT, USER_REMOVAL or LEGACY_MARKER. Installation,
     * signing and Android user administration are not actor classes.
     */
    public enum ActorClass {
        /** The account's own Android user. */
        ACCOUNT_USER(1),
        /** An administration grant, named by its opaque grant reference. */
        ADMIN_GRANT(2),
        /** The independent recovery route. Suspension entries only. */
        RECOVERY_HOLD(3),
        /** The Android user removal path. Retirements only. */
        USER_REMOVAL(4),
        /**
         * A version 1 retirement marker, whose actor and inventory are unknown. Retirements only,
         * and only as decoded from a version 1 retiring flag or as its continuation.
         */
        LEGACY_MARKER(5);

        final int code;

        ActorClass(int code) {
            this.code = code;
        }
    }

    /**
     * The registry of suspension reason codes. Each names one specific cause, and there is no
     * catch-all code. Each also names the actor classes whose entries may carry it. The account's
     * user and the grant holders in scope see each entry's actor and reason. Writers refuse a code
     * outside this registry, and a code its entry's actor class may not use. The record field is
     * informational: the decoder keeps any code, a reader shows an unregistered code as unknown,
     * and a new code needs no new slot version. A reason never carries authorization, expiry or
     * discharge. Code 0 is never assigned, and once B1's image ships a code's number is never
     * reused for another reason, because records written with it stay readable.
     */
    public enum SuspensionReason {
        /** The account's user paused the account. The account's user only. */
        USER_PAUSED(1, ActorClass.ACCOUNT_USER),
        /** The account's credential may be known to someone else. */
        CREDENTIAL_EXPOSED(2, ActorClass.ACCOUNT_USER, ActorClass.ADMIN_GRANT),
        /** The account, or software in it, may be under someone else's control. */
        SUSPECTED_COMPROMISE(3, ActorClass.ACCOUNT_USER, ActorClass.ADMIN_GRANT),
        /** The account uses storage, power or other resources that the phone cannot spare. */
        RESOURCE_OVERUSE(4, ActorClass.ACCOUNT_USER, ActorClass.ADMIN_GRANT),
        /** The phone is lent, shared or away for repair, and the account stays closed meanwhile. */
        DEVICE_HANDOVER(5, ActorClass.ACCOUNT_USER, ActorClass.ADMIN_GRANT),
        /** The account's data is being copied or moved elsewhere, and must not change meanwhile. */
        DATA_TRANSFER(6, ActorClass.ACCOUNT_USER, ActorClass.ADMIN_GRANT),
        /**
         * Recovery restored the account, which waits for review before it runs again. Recovery
         * holds only.
         */
        RECOVERY_REVIEW(7, ActorClass.RECOVERY_HOLD);

        /** The code a suspension entry stores. */
        final int code;
        /** Unmodifiable: the suspension actor classes whose entries may carry this reason. */
        final Set<ActorClass> actors;

        SuspensionReason(int code, ActorClass... actors) {
            this.code = code;
            this.actors = Set.of(actors);
        }

        /** The registered reason of this code, or null for a code outside the registry. */
        static SuspensionReason registered(int code) {
            for (SuspensionReason reason : values()) {
                if (reason.code == code) return reason;
            }
            return null;
        }
    }

    /**
     * The kinds of a retiring account's obligations. Kinds 1 to 9 are retirement kinds and kinds 10
     * to 16 disposition kinds. Each owner discharges its own kind on its own evidence.
     */
    public enum ObligationKind {
        WORK(1), API_EFFECTS(2), DELEGATIONS(3), PUBLICATIONS(4), LEASE_OPERATIONS(5),
        MAINTENANCE(6), ERASERS(7), RESTRICTED_SUBJECTS(8), PACKAGE_CHANGES(9),
        ANDROID_STATE(10), KEYSTORE(11), DATA_CE(12), DATA_DE(13), DATA_EXTERNAL(14), HOME(15),
        MANAGED_OBJECTS(16);

        final int code;

        ObligationKind(int code) {
            this.code = code;
        }

        /** Whether deletion or migration discharges this kind, rather than retirement. */
        public boolean disposition() {
            return code > PACKAGE_CHANGES.code;
        }
    }

    /** Progress of one obligation. */
    public enum ObligationState {
        OUTSTANDING(1),
        /** Deletion or migration began. Disposition kinds only, and only under RETIRED. */
        DISPOSING(2),
        DISCHARGED(3),
        /** Its record died with the Android user, bound to that user's old serial. */
        ORPHANED_WITH_USER(4);

        final int code;

        ObligationState(int code) {
            this.code = code;
        }
    }

    /**
     * One suspension entry: who suspended the account and why. An entry closes activation; it
     * releases, deletes and expires nothing. The constructor validates every field rule.
     */
    public static final class Suspension {
        /** ACCOUNT_USER, ADMIN_GRANT or RECOVERY_HOLD. */
        public final ActorClass actorClass;
        /**
         * Scope bits. Bit 0 blocks deletion and migration: it decodes, and no writer sets it yet.
         * Bit 1 says the prior lifecycle state is unknown, on a recovery hold only. Others are 0.
         */
        public final int scope;
        /** The Android user that acted, or that ran recovery. Not negative. */
        public final int actorUserId;
        /** That user's serial. Not negative. */
        public final long actorSerial;
        /** The opaque grant reference, 32 lowercase hex digits, nonzero exactly for ADMIN_GRANT. */
        public final String grant;
        /** The reason code, 0 to 65535. Informational: see {@link SuspensionReason}. */
        public final int reason;
        /** Wall clock milliseconds. Informational, never an expiry. */
        public final long time;
        /**
         * The salted SHA-256 that names the suspender's private note, 64 lowercase hex digits, or
         * null. The note and its salt stay in the suspender's credential encrypted storage.
         */
        public final String noteDigest;

        /**
         * @throws IllegalArgumentException for a class other than ACCOUNT_USER, ADMIN_GRANT or
         *     RECOVERY_HOLD, an unknown scope bit, bit 1 outside a recovery hold, a negative actor
         *     user or serial, a malformed grant or one that is zero exactly for ADMIN_GRANT, a
         *     reason outside 0..65535 or a malformed note digest
         * @throws NullPointerException for a null class or grant
         */
        public Suspension(ActorClass actorClass, int scope, int actorUserId, long actorSerial,
                String grant, int reason, long time, String noteDigest) {
            Objects.requireNonNull(actorClass, "actorClass");
            if (actorClass != ActorClass.ACCOUNT_USER && actorClass != ActorClass.ADMIN_GRANT
                    && actorClass != ActorClass.RECOVERY_HOLD) {
                throw invalid("not a suspension actor class");
            }
            if ((scope & ~(SCOPE_BLOCKS_DISPOSITION | SCOPE_PRIOR_UNKNOWN)) != 0) {
                throw invalid("unknown scope bits");
            }
            if ((scope & SCOPE_PRIOR_UNKNOWN) != 0 && actorClass != ActorClass.RECOVERY_HOLD) {
                throw invalid("prior state unknown only on a recovery hold");
            }
            checkUser(actorUserId, actorSerial);
            checkGrant(actorClass, grant);
            if (reason < 0 || reason > MAX_REASON) throw invalid("reason code outside its range");
            if (noteDigest != null) checkHex(noteDigest, 2 * NOTE_BYTES, "note digest");
            this.actorClass = actorClass;
            this.scope = scope;
            this.actorUserId = actorUserId;
            this.actorSerial = actorSerial;
            this.grant = grant;
            this.reason = reason;
            this.time = time;
            this.noteDigest = noteDigest;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) return true;
            if (!(other instanceof Suspension)) return false;
            Suspension entry = (Suspension) other;
            return actorClass == entry.actorClass && scope == entry.scope
                    && actorUserId == entry.actorUserId && actorSerial == entry.actorSerial
                    && grant.equals(entry.grant) && reason == entry.reason && time == entry.time
                    && Objects.equals(noteDigest, entry.noteDigest);
        }

        @Override
        public int hashCode() {
            return Objects.hash(actorClass.code, scope, actorUserId, actorSerial, grant, reason, time,
                    noteDigest);
        }

        @Override
        public String toString() {
            return "Suspension{" + actorClass + ", scope=" + scope + ", actor=" + actorUserId + "/"
                    + actorSerial + ", reason=" + reason + (noteDigest == null ? "}" : ", note}");
        }
    }

    /** One obligation of a retiring account. The constructor validates every field rule. */
    public static final class Obligation {
        public final ObligationKind kind;
        public final ObligationState state;
        /** The owner's record ID, 32 lowercase hex digits, all zero until bound. */
        public final String reference;
        /** Method or evidence, 0 to 255. Informational. */
        public final int code;
        /** Wall clock milliseconds. Informational. */
        public final long time;

        /**
         * @throws IllegalArgumentException for a malformed reference, a code outside 0..255 or
         *     DISPOSING on a retirement kind
         * @throws NullPointerException for a null kind, state or reference
         */
        public Obligation(ObligationKind kind, ObligationState state, String reference, int code,
                long time) {
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(state, "state");
            checkHex(reference, 2 * REFERENCE_BYTES, "reference");
            if (code < 0 || code > MAX_CODE) throw invalid("obligation code outside its range");
            if (state == ObligationState.DISPOSING && !kind.disposition()) {
                throw invalid("DISPOSING only on a disposition kind");
            }
            this.kind = kind;
            this.state = state;
            this.reference = reference;
            this.code = code;
            this.time = time;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) return true;
            if (!(other instanceof Obligation)) return false;
            Obligation obligation = (Obligation) other;
            return kind == obligation.kind && state == obligation.state
                    && reference.equals(obligation.reference) && code == obligation.code
                    && time == obligation.time;
        }

        @Override
        public int hashCode() {
            return Objects.hash(kind.code, state.code, reference, code, time);
        }

        @Override
        public String toString() {
            return kind + " " + state + (reference.equals(NO_REFERENCE) ? "" : " bound");
        }
    }

    /**
     * The retirement block of a RETIRING or RETIRED account: who retired it and which duties
     * remain. It releases nothing. The constructor validates every field rule.
     */
    public static final class Retirement {
        /** ACCOUNT_USER, ADMIN_GRANT, USER_REMOVAL or LEGACY_MARKER. */
        public final ActorClass actorClass;
        /** The Android user that acted. Not negative, and zero for LEGACY_MARKER. */
        public final int actorUserId;
        /** That user's serial. Not negative, and zero for LEGACY_MARKER. */
        public final long actorSerial;
        /** The opaque grant reference, nonzero exactly for ADMIN_GRANT. */
        public final String grant;
        /** Wall clock milliseconds. Informational, and zero for LEGACY_MARKER. */
        public final long time;
        /** 1 when this design's 16 kinds are listed, 0 when unknown: a legacy marker only. */
        public final int inventory;
        /**
         * Unmodifiable: every kind once, in kind order, under inventory 1. Empty under inventory 0,
         * where every kind counts as outstanding.
         */
        public final List<Obligation> obligations;

        /**
         * A retirement whose inventory follows from its obligations: 16, one of each kind in
         * order, or none for a legacy marker's unknown inventory.
         *
         * @throws IllegalArgumentException for RECOVERY_HOLD, a negative actor user or serial, a
         *     LEGACY_MARKER with an actor, grant or time, a malformed grant or one that is zero
         *     exactly for ADMIN_GRANT, no obligations without a legacy marker, or any other list
         *     than every kind once in order
         * @throws NullPointerException for a null class, grant, list or element
         */
        public Retirement(ActorClass actorClass, int actorUserId, long actorSerial, String grant,
                long time, List<Obligation> obligations) {
            Objects.requireNonNull(actorClass, "actorClass");
            if (actorClass == ActorClass.RECOVERY_HOLD) throw invalid("not a retirement actor class");
            checkUser(actorUserId, actorSerial);
            checkGrant(actorClass, grant);
            if (actorClass == ActorClass.LEGACY_MARKER
                    && (actorUserId != 0 || actorSerial != 0 || time != 0)) {
                throw invalid("a legacy marker records no actor or time");
            }
            List<Obligation> copy = List.copyOf(Objects.requireNonNull(obligations, "obligations"));
            if (copy.isEmpty()) {
                if (actorClass != ActorClass.LEGACY_MARKER) {
                    throw invalid("an unknown inventory only for a legacy marker");
                }
            } else if (copy.size() != OBLIGATION_KINDS) {
                throw invalid("an inventory lists every kind once");
            }
            for (int i = 0; i < copy.size(); i++) {
                if (copy.get(i).kind.code != i + 1) {
                    throw invalid("obligations not every kind once in kind order");
                }
            }
            this.actorClass = actorClass;
            this.actorUserId = actorUserId;
            this.actorSerial = actorSerial;
            this.grant = grant;
            this.time = time;
            this.inventory = copy.isEmpty() ? INVENTORY_UNKNOWN : INVENTORY_KNOWN;
            this.obligations = copy;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) return true;
            if (!(other instanceof Retirement)) return false;
            Retirement retirement = (Retirement) other;
            return actorClass == retirement.actorClass && actorUserId == retirement.actorUserId
                    && actorSerial == retirement.actorSerial && grant.equals(retirement.grant)
                    && time == retirement.time && obligations.equals(retirement.obligations);
        }

        @Override
        public int hashCode() {
            return Objects.hash(actorClass.code, actorUserId, actorSerial, grant, time, obligations);
        }

        @Override
        public String toString() {
            return "Retirement{" + actorClass + (actorClass == ActorClass.LEGACY_MARKER ? ""
                    : ", actor=" + actorUserId + "/" + actorSerial) + ", inventory=" + inventory
                    + (obligations.isEmpty() ? "}" : ", " + obligations + "}");
        }
    }

    /**
     * The lifecycle of one account in a slot: its state, its suspension entries and, while it is
     * RETIRING or RETIRED, its retirement. It is data for the account authority's own checks and
     * grants nothing. The constructor validates the entry rules and the decoder invariants.
     */
    public static final class Lifecycle {
        public final LifecycleState state;
        /**
         * Unmodifiable: at most six entries in strictly ascending (class, actor serial, grant)
         * order. One entry per actor: at most one for the account's user, one for each grant
         * reference whatever its actor fields, and one recovery hold.
         */
        public final List<Suspension> suspensions;
        /** Present exactly when the state is RETIRING or RETIRED, otherwise null. */
        public final Retirement retirement;

        /**
         * @throws IllegalArgumentException for more than six entries, entries out of order or a
         *     second entry from one actor, a retirement absent from RETIRING or RETIRED or present
         *     in ELIGIBLE, an unknown inventory outside RETIRING, DISPOSING outside RETIRED, or
         *     RETIRED with a retirement kind not DISCHARGED
         * @throws NullPointerException for a null state, list or element
         */
        public Lifecycle(LifecycleState state, List<Suspension> suspensions, Retirement retirement) {
            Objects.requireNonNull(state, "state");
            List<Suspension> copy = List.copyOf(Objects.requireNonNull(suspensions, "suspensions"));
            if (copy.size() > MAX_SUSPENSIONS) throw invalid("more than MAX_SUSPENSIONS entries");
            Set<String> grants = new HashSet<>();
            for (int i = 0; i < copy.size(); i++) {
                Suspension entry = copy.get(i);
                if (i > 0 && order(copy.get(i - 1), entry) >= 0) {
                    throw invalid("suspension entries not in strictly ascending order");
                }
                // Ordered by class first, so a second entry of one class follows the first.
                boolean repeated = entry.actorClass == ActorClass.ADMIN_GRANT
                        ? !grants.add(entry.grant)
                        : i > 0 && copy.get(i - 1).actorClass == entry.actorClass;
                if (repeated) throw invalid("two suspension entries from one actor");
            }
            if ((retirement == null) != (state == LifecycleState.ELIGIBLE)) {
                throw invalid("a retirement exactly when RETIRING or RETIRED");
            }
            if (retirement != null) {
                if (retirement.inventory == INVENTORY_UNKNOWN && state != LifecycleState.RETIRING) {
                    throw invalid("an unknown inventory only while RETIRING");
                }
                for (Obligation obligation : retirement.obligations) {
                    if (obligation.state == ObligationState.DISPOSING
                            && state != LifecycleState.RETIRED) {
                        throw invalid("DISPOSING only under RETIRED");
                    }
                    if (state == LifecycleState.RETIRED && !obligation.kind.disposition()
                            && obligation.state != ObligationState.DISCHARGED) {
                        throw invalid("RETIRED with a retirement kind not DISCHARGED");
                    }
                }
            }
            this.state = state;
            this.suspensions = copy;
            this.retirement = retirement;
        }

        /** The two lifecycles a version 1 flag byte expresses: ELIGIBLE, or the legacy marker. */
        static Lifecycle version1(boolean retiring) {
            return retiring ? LEGACY_RETIRING : ELIGIBLE_ONLY;
        }

        /** Whether version 1 can express this lifecycle. */
        boolean isVersion1() {
            return equals(ELIGIBLE_ONLY) || equals(LEGACY_RETIRING);
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) return true;
            if (!(other instanceof Lifecycle)) return false;
            Lifecycle lifecycle = (Lifecycle) other;
            return state == lifecycle.state && suspensions.equals(lifecycle.suspensions)
                    && Objects.equals(retirement, lifecycle.retirement);
        }

        @Override
        public int hashCode() {
            return Objects.hash(state.code, suspensions, retirement);
        }

        @Override
        public String toString() {
            return state + (suspensions.isEmpty() ? "" : ", suspensions=" + suspensions)
                    + (retirement == null ? "" : ", " + retirement);
        }
    }

    // The version 1 lifecycles. Shared, as every value is immutable.
    private static final Lifecycle ELIGIBLE_ONLY = new Lifecycle(LifecycleState.ELIGIBLE,
            List.of(), null);
    private static final Lifecycle LEGACY_RETIRING = new Lifecycle(LifecycleState.RETIRING,
            List.of(), new Retirement(ActorClass.LEGACY_MARKER, 0, 0, NO_REFERENCE, 0, List.of()));

    /** The principal of a slot's package for one Android user. */
    public static final class UserEntry {
        /** Positive PMS principal ID. Not a native work ID. */
        public final long id;
        /** Android user ID, not negative. The slot checks that the resulting UID fits an int. */
        public final int userId;
        /** Serial number of this incarnation of the user. Not negative. */
        public final long userSerial;
        /** The account's lifecycle record. Never null. */
        public final Lifecycle lifecycle;
        /**
         * Whether the lifecycle is RETIRING or RETIRED: the durable retirement marker. It
         * releases nothing by itself.
         */
        public final boolean retiring;

        /**
         * One of the two version 1 values: ELIGIBLE with no suspension entry, or the legacy
         * retirement marker when retiring.
         *
         * @throws IllegalArgumentException for a nonpositive ID or a negative user or serial
         */
        public UserEntry(long id, int userId, long userSerial, boolean retiring) {
            this(id, userId, userSerial, Lifecycle.version1(retiring));
        }

        /**
         * @throws IllegalArgumentException for a nonpositive ID or a negative user or serial
         * @throws NullPointerException for a null lifecycle
         */
        public UserEntry(long id, int userId, long userSerial, Lifecycle lifecycle) {
            if (id <= 0) throw invalid("principal ID must be positive");
            checkUser(userId, userSerial);
            this.id = id;
            this.userId = userId;
            this.userSerial = userSerial;
            this.lifecycle = Objects.requireNonNull(lifecycle, "lifecycle");
            this.retiring = lifecycle.state != LifecycleState.ELIGIBLE;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) return true;
            if (!(other instanceof UserEntry)) return false;
            UserEntry user = (UserEntry) other;
            return id == user.id && userId == user.userId && userSerial == user.userSerial
                    && lifecycle.equals(user.lifecycle);
        }

        @Override
        public int hashCode() {
            return Objects.hash(id, userId, userSerial, lifecycle);
        }

        @Override
        public String toString() {
            return "UserEntry{id=" + id + ", user=" + userId + ", serial=" + userSerial
                    + (lifecycle.isVersion1() ? (retiring ? ", retiring}" : "}")
                    : ", " + lifecycle + "}");
        }
    }

    /**
     * The release ticket of a version 2 tombstone: the last principal, user and serial the slot
     * held, and a ticket ID that gives an interrupted release an owner after a restart. It
     * releases nothing by itself. The constructor validates every field rule.
     */
    public static final class ReleaseTicket {
        /** The last principal ID. Positive. */
        public final long lastId;
        /** Its Android user. Not negative. */
        public final int userId;
        /** That user's serial. Not negative. */
        public final long userSerial;
        /** The ticket ID, 32 lowercase hex digits, never all zero. */
        public final String ticketId;

        /**
         * @throws IllegalArgumentException for a nonpositive ID, a negative user or serial, or a
         *     malformed or zero ticket ID
         * @throws NullPointerException for a null ticket ID
         */
        public ReleaseTicket(long lastId, int userId, long userSerial, String ticketId) {
            if (lastId <= 0) throw invalid("ticket principal ID must be positive");
            checkUser(userId, userSerial);
            checkHex(ticketId, 2 * REFERENCE_BYTES, "ticket ID");
            if (ticketId.equals(NO_REFERENCE)) throw invalid("zero ticket ID");
            this.lastId = lastId;
            this.userId = userId;
            this.userSerial = userSerial;
            this.ticketId = ticketId;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) return true;
            if (!(other instanceof ReleaseTicket)) return false;
            ReleaseTicket ticket = (ReleaseTicket) other;
            return lastId == ticket.lastId && userId == ticket.userId
                    && userSerial == ticket.userSerial && ticketId.equals(ticket.ticketId);
        }

        @Override
        public int hashCode() {
            return Objects.hash(lastId, userId, userSerial, ticketId);
        }

        @Override
        public String toString() {
            return "ReleaseTicket{lastId=" + lastId + ", user=" + userId + ", serial=" + userSerial
                    + "}";
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
         * A tombstone's release ticket, or null. Only a tombstone carries one, and a tombstone
         * with a ticket is version 2.
         */
        public final ReleaseTicket ticket;
        /**
         * Wire version, which follows from the value: 1 exactly when version 1 can express it,
         * otherwise 2. See the class description. The encoding uses it.
         */
        public final int version;

        /**
         * A slot without a release ticket. Copies the signer set in ascending order. Copies the
         * users, which must already be in strictly ascending user ID order.
         *
         * @throws IllegalArgumentException for an invalid field, count, digest, order, duplicate
         *     or a UID above {@link Integer#MAX_VALUE}
         * @throws NullPointerException for a null argument or element
         */
        public Slot(String lineage, int appId, String packageName, long generation,
                Set<String> signerSha256, List<UserEntry> users) {
            this(lineage, appId, packageName, generation, signerSha256, users, null);
        }

        /**
         * A slot with an optional release ticket, which only a tombstone may carry. Copies the
         * signer set in ascending order. Copies the users, which must already be in strictly
         * ascending user ID order.
         *
         * @throws IllegalArgumentException for an invalid field, count, digest, order, duplicate,
         *     a UID above {@link Integer#MAX_VALUE} or a ticket beside users
         * @throws NullPointerException for a null argument other than the ticket, or element
         */
        public Slot(String lineage, int appId, String packageName, long generation,
                Set<String> signerSha256, List<UserEntry> users, ReleaseTicket ticket) {
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
            if (ticket != null && !copy.isEmpty()) throw invalid("only a tombstone carries a ticket");
            // At most 1,357 + 64 * 931 = 60,941 bytes, so every valid slot has its encoding.
            boolean version1 = ticket == null;
            for (UserEntry user : copy) version1 &= user.lifecycle.isVersion1();
            this.lineage = lineage;
            this.appId = appId;
            this.packageName = packageName;
            this.generation = generation;
            this.signerSha256 = signers;
            this.users = copy;
            this.ticket = ticket;
            this.version = version1 ? VERSION_1 : VERSION_2;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) return true;
            if (!(other instanceof Slot)) return false;
            Slot slot = (Slot) other;
            return appId == slot.appId && generation == slot.generation
                    && lineage.equals(slot.lineage) && packageName.equals(slot.packageName)
                    && signerSha256.equals(slot.signerSha256) && users.equals(slot.users)
                    && Objects.equals(ticket, slot.ticket);
        }

        @Override
        public int hashCode() {
            return Objects.hash(lineage, appId, packageName, generation, signerSha256, users,
                    ticket);
        }

        @Override
        public String toString() {
            return "Slot{appId=" + appId + ", package=" + packageName + ", generation="
                    + generation + ", signers=" + signerSha256.size() + ", users=" + users
                    + (ticket == null ? "}" : ", " + ticket + "}");
        }
    }

    /**
     * For the store only. The stable prefix of an intact slot frame of a version above 2, which
     * this codec cannot decode: the package name and principal IDs that frame names. It is
     * negative evidence only, as a decoded copy of an unsupported record is. It carries no
     * lifecycle state, signer set, binding, counter or hold, and it is never a value of any
     * record. Only {@link #decodeSlotPrefix} builds it, after the prefix's frozen rules hold.
     */
    static final class SlotPrefix {
        /** The declared slot version, above 2. */
        final int version;
        /** The package name the frame names. */
        final String packageName;
        /** Unmodifiable: the principal IDs the frame names, in its user order. */
        final List<Long> principalIds;

        private SlotPrefix(int version, String packageName, List<Long> principalIds) {
            this.version = version;
            this.packageName = packageName;
            this.principalIds = List.copyOf(principalIds);
        }

        @Override
        public String toString() {
            return "SlotPrefix{version=" + version + ", package=" + packageName + ", ids="
                    + principalIds + "}";
        }
    }

    private NativeIdentityRecords() {}

    /** Returns the one encoding of a header, with its own version, in a new array. */
    public static byte[] encodeHeader(Header header) {
        Objects.requireNonNull(header, "header");
        return headerBody(header.version, header.lineage, header.lastId, header.entries).seal();
    }

    /**
     * For the store only. The exact length in bytes, frame and checksum included, of the header
     * encoding these fields would have, measured by the encoder that the Header constructor and
     * {@link #encodeHeader} use. It constructs no Header, so a writer can refuse a proposal
     * above {@link #MAX_BYTES} before it issues an ID, rather than meet the constructor's
     * refusal afterwards. The lineage and entries must already be valid, and the count at most
     * {@link #MAX_SLOTS}. A version 1 measure of an entry carrying a creation binding throws,
     * as the encoder never drops a binding. This measures bytes only: it validates no counter,
     * order or creation ID, and is no admission decision.
     *
     * @throws IllegalArgumentException for a version other than 1 or 2, an invalid lineage or
     *     more than MAX_SLOTS entries
     * @throws IllegalStateException for a binding that version 1 cannot encode
     * @throws NullPointerException for a null lineage, list or entry
     */
    static int encodedHeaderLength(int version, String lineage, long lastId,
            List<HeaderEntry> entries) {
        if (version != VERSION_1 && version != VERSION_2) throw invalid("unsupported header version");
        checkHex(lineage, 2 * LINEAGE_BYTES, "lineage");
        List<HeaderEntry> copy = List.copyOf(Objects.requireNonNull(entries, "entries"));
        if (copy.size() > MAX_SLOTS) throw invalid("more than MAX_SLOTS entries");
        return headerBody(version, lineage, lastId, copy).length();
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

    /** Returns the one encoding of a slot, with the version its value has, in a new array. */
    public static byte[] encodeSlot(Slot slot) {
        Objects.requireNonNull(slot, "slot");
        return slotBody(slot).seal();
    }

    /**
     * For the store only. The exact length in bytes, frame and checksum included, of this slot's
     * one encoding, measured by the encoder that {@link #encodeSlot} uses. Every valid slot has
     * an encoding within {@link #MAX_BYTES}, at most 60,941 bytes, so a writer measures it to
     * know the size before it writes, never to refuse a valid value.
     *
     * @throws NullPointerException for null
     */
    static int encodedSlotLength(Slot slot) {
        Objects.requireNonNull(slot, "slot");
        return slotBody(slot).length();
    }

    // Everything before the checksum, in the slot's own version.
    private static Output slotBody(Slot slot) {
        Output out = new Output(TYPE_SLOT, slot.version);
        out.hex(slot.lineage);
        out.i32(slot.appId);
        out.i64(slot.generation);
        out.ascii(slot.packageName);
        out.signers(slot.signerSha256);
        out.u16(slot.users.size());
        if (slot.version == VERSION_1) {
            for (UserEntry user : slot.users) {
                out.i64(user.id);
                out.i32(user.userId);
                out.i64(user.userSerial);
                out.u8(user.retiring ? FLAG_RETIRING : 0);
            }
            return out;
        }
        // Version 2: the identities complete the stable prefix. The lifecycle blocks follow in
        // the same user order, then a tombstone's ticket, which every version 2 tombstone has.
        for (UserEntry user : slot.users) {
            out.i64(user.id);
            out.i32(user.userId);
            out.i64(user.userSerial);
        }
        for (UserEntry user : slot.users) out.lifecycle(user.lifecycle);
        if (slot.ticket != null) out.ticket(slot.ticket);
        return out;
    }

    /**
     * Decodes one complete slot encoding of version 1 or 2. The input is copied and not
     * retained.
     *
     * @throws IllegalArgumentException for any damaged, malformed or unsupported input, and for
     *     a version 2 encoding of a value that version 1 can express
     * @throws NullPointerException for null
     */
    public static Slot decodeSlot(byte[] record) {
        Input in = Input.open(record, TYPE_SLOT, VERSION_2);
        if (in.version == VERSION_2) return decodeSlotV2(in);
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

    // The stable prefix, one lifecycle block for each user, then a tombstone's ticket.
    private static Slot decodeSlotV2(Input in) {
        Prefix prefix = in.prefix();
        List<UserEntry> users = new ArrayList<>(prefix.ids.length);
        for (int i = 0; i < prefix.ids.length; i++) {
            users.add(new UserEntry(prefix.ids[i], prefix.userIds[i], prefix.serials[i],
                    in.lifecycle()));
        }
        ReleaseTicket ticket = users.isEmpty() ? in.ticket() : null;
        in.finish();
        Slot slot = new Slot(prefix.lineage, prefix.appId, prefix.packageName, prefix.generation,
                prefix.signers, users, ticket);
        // One encoding per value: version 1 keeps every value it can express.
        if (slot.version != VERSION_2) throw invalid("version 1 value in a version 2 record");
        return slot;
    }

    /**
     * For the store only. The stable prefix of one intact slot frame of a version above 2, as
     * negative evidence: see {@link SlotPrefix}. The frame is verified before anything else, then
     * every prefix field against the prefix's frozen bounds and rules, which the class
     * description lists and which bind every later version. Nothing after the prefix is read,
     * and the body is never checked for an end, so a later version may change all that follows
     * the prefix. Frames of version 1 and 2 are refused: this codec decodes those in full, and a
     * version 2 frame that fails to decode gives no prefix either.
     *
     * @throws IllegalArgumentException for a frame that is not intact, a version up to 2 or a
     *     prefix that breaks a rule
     * @throws NullPointerException for null
     */
    static SlotPrefix decodeSlotPrefix(byte[] record) {
        Input in = Input.openLater(record);
        Prefix prefix = in.prefix();
        List<Long> ids = new ArrayList<>(prefix.ids.length);
        for (long id : prefix.ids) ids.add(id);
        return new SlotPrefix(in.version, prefix.packageName, ids);
    }

    // The stable prefix of one version 2 or later slot record, each field within its frozen rule.
    private static final class Prefix {
        final String lineage;
        final int appId;
        final long generation;
        final String packageName;
        final Set<String> signers;
        final long[] ids;
        final int[] userIds;
        final long[] serials;

        Prefix(String lineage, int appId, long generation, String packageName, Set<String> signers,
                long[] ids, int[] userIds, long[] serials) {
            this.lineage = lineage;
            this.appId = appId;
            this.generation = generation;
            this.packageName = packageName;
            this.signers = signers;
            this.ids = ids;
            this.userIds = userIds;
            this.serials = serials;
        }
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

        // A version 2 lifecycle block of a validated value.
        void lifecycle(Lifecycle lifecycle) {
            u8(lifecycle.state.code);
            u8(lifecycle.suspensions.size());
            for (Suspension entry : lifecycle.suspensions) {
                u8(entry.actorClass.code);
                u8(entry.scope);
                i32(entry.actorUserId);
                i64(entry.actorSerial);
                hex(entry.grant);
                u16(entry.reason);
                i64(entry.time);
                if (entry.noteDigest == null) {
                    u8(NOTE_ABSENT);
                } else {
                    u8(NOTE_PRESENT);
                    hex(entry.noteDigest);
                }
            }
            Retirement retirement = lifecycle.retirement;
            if (retirement == null) return;
            u8(retirement.actorClass.code);
            i32(retirement.actorUserId);
            i64(retirement.actorSerial);
            hex(retirement.grant);
            i64(retirement.time);
            u8(retirement.inventory);
            u8(retirement.obligations.size());
            for (Obligation obligation : retirement.obligations) {
                u8(obligation.kind.code);
                u8(obligation.state.code);
                hex(obligation.reference);
                u8(obligation.code);
                i64(obligation.time);
            }
        }

        // A version 2 tombstone's release ticket, of a validated value.
        void ticket(ReleaseTicket ticket) {
            i64(ticket.lastId);
            i32(ticket.userId);
            i64(ticket.userSerial);
            hex(ticket.ticketId);
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

        // A private copy of a slot frame of a version above 2, for its stable prefix alone. The
        // frame is verified first. Its body is never finished: a later version owns what follows.
        static Input openLater(byte[] record) {
            byte[] bytes = bounded(record).clone();
            int version = frame(bytes, TYPE_SLOT);
            if (version <= VERSION_2) throw invalid("no stable prefix reading of this version");
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
            return signers(MAX_SIGNERS);
        }

        Set<String> signers(int max) {
            int count = count(max);
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

        // The stable prefix of version 2 and of every later version: the version 1 fields through
        // the user count, then each user's identity, all within the prefix's own frozen bounds.
        // The order and duplicates are checked before any set exists.
        Prefix prefix() {
            String lineage = hex(LINEAGE_BYTES);
            int appId = i32();
            checkAppId(appId);
            long generation = i64();
            if (generation <= 0) throw invalid("generation must be positive");
            String packageName = ascii();
            if (!isPackageName(packageName)) throw invalid("malformed package name");
            Set<String> signers = signers(PREFIX_MAX_SIGNERS);
            if (signers.isEmpty()) throw invalid("a prefix names at least one signer");
            int count = count(PREFIX_MAX_USERS);
            long[] ids = new long[count];
            int[] userIds = new int[count];
            long[] serials = new long[count];
            Set<Long> distinct = new HashSet<>();
            for (int i = 0; i < count; i++) {
                ids[i] = i64();
                userIds[i] = i32();
                serials[i] = i64();
                if (ids[i] <= 0) throw invalid("principal ID must be positive");
                checkUser(userIds[i], serials[i]);
                if (i > 0 && userIds[i] <= userIds[i - 1]) throw invalid("identities out of order");
                checkUid(userIds[i], appId);
                if (!distinct.add(ids[i])) throw invalid("duplicate principal ID");
            }
            return new Prefix(lineage, appId, generation, packageName,
                    Collections.unmodifiableSet(signers), ids, userIds, serials);
        }

        // One version 2 lifecycle block. The value's constructors check every rule.
        Lifecycle lifecycle() {
            LifecycleState state = lifecycleState(u8());
            int count = u8();
            if (count > MAX_SUSPENSIONS) throw invalid("suspension count above its bound");
            List<Suspension> entries = new ArrayList<>(count);
            for (int i = 0; i < count; i++) entries.add(suspension());
            Retirement retirement = state == LifecycleState.ELIGIBLE ? null : retirement();
            return new Lifecycle(state, entries, retirement);
        }

        Suspension suspension() {
            ActorClass actorClass = actorClass(u8());
            int scope = u8();
            int actorUserId = i32();
            long actorSerial = i64();
            String grant = hex(REFERENCE_BYTES);
            int reason = u16();
            long time = i64();
            int note = u8();
            if (note != NOTE_ABSENT && note != NOTE_PRESENT) throw invalid("unknown note tag");
            String digest = note == NOTE_PRESENT ? hex(NOTE_BYTES) : null;
            return new Suspension(actorClass, scope, actorUserId, actorSerial, grant, reason, time,
                    digest);
        }

        // The count must be the inventory's: 16 when known, none when unknown.
        Retirement retirement() {
            ActorClass actorClass = actorClass(u8());
            int actorUserId = i32();
            long actorSerial = i64();
            String grant = hex(REFERENCE_BYTES);
            long time = i64();
            int inventory = u8();
            int count = u8();
            if (inventory != INVENTORY_UNKNOWN && inventory != INVENTORY_KNOWN) {
                throw invalid("unknown inventory");
            }
            if (count != (inventory == INVENTORY_KNOWN ? OBLIGATION_KINDS : 0)) {
                throw invalid("obligation count differs from the inventory");
            }
            List<Obligation> obligations = new ArrayList<>(count);
            for (int i = 0; i < count; i++) {
                ObligationKind kind = obligationKind(u8());
                ObligationState state = obligationState(u8());
                String reference = hex(REFERENCE_BYTES);
                int code = u8();
                long at = i64();
                obligations.add(new Obligation(kind, state, reference, code, at));
            }
            return new Retirement(actorClass, actorUserId, actorSerial, grant, time, obligations);
        }

        ReleaseTicket ticket() {
            long lastId = i64();
            int userId = i32();
            long userSerial = i64();
            return new ReleaseTicket(lastId, userId, userSerial, hex(REFERENCE_BYTES));
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

    private static LifecycleState lifecycleState(int code) {
        for (LifecycleState state : LifecycleState.values()) {
            if (state.code == code) return state;
        }
        throw invalid("unknown lifecycle state");
    }

    private static ActorClass actorClass(int code) {
        for (ActorClass actorClass : ActorClass.values()) {
            if (actorClass.code == code) return actorClass;
        }
        throw invalid("unknown actor class");
    }

    private static ObligationKind obligationKind(int code) {
        for (ObligationKind kind : ObligationKind.values()) {
            if (kind.code == code) return kind;
        }
        throw invalid("unknown obligation kind");
    }

    private static ObligationState obligationState(int code) {
        for (ObligationState state : ObligationState.values()) {
            if (state.code == code) return state;
        }
        throw invalid("unknown obligation state");
    }

    // The order of suspension entries: class, then actor serial, then grant reference. Lowercase
    // hex compares as the unsigned bytes it encodes.
    private static int order(Suspension first, Suspension second) {
        int order = Integer.compare(first.actorClass.code, second.actorClass.code);
        if (order == 0) order = Long.compare(first.actorSerial, second.actorSerial);
        return order != 0 ? order : first.grant.compareTo(second.grant);
    }

    // A 16 byte grant reference, nonzero exactly for an ADMIN_GRANT actor.
    private static void checkGrant(ActorClass actorClass, String grant) {
        checkHex(grant, 2 * REFERENCE_BYTES, "grant");
        if ((actorClass == ActorClass.ADMIN_GRANT) == grant.equals(NO_REFERENCE)) {
            throw invalid("a grant reference exactly for ADMIN_GRANT");
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
