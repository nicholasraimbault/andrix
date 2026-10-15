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
import java.util.ArrayList;
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
 *
 * <p>The reader step of the normal image adds the layouts its guest stage reads: every lifecycle
 * state and entry class, the scope bits, a noted entry, the maximum record, tombstones and the
 * RELEASING tail, interrupted copies, three records the reader must read as damaged, later slot
 * versions, the serial control and the lift at a later boot. Every valid record comes from the
 * actual codec. The damaged and later version records are fixture assembly: a bounded edit of the
 * codec's own bytes for a named field, framed again with its length and SHA-256, so the frame is
 * intact and only the named rule or the version refuses it. The generator never writes a value
 * the codec would decode as valid this way.
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
    /**
     * The lifecycle guest layouts, by mode: six of the earlier guest rows, three of the subject
     * alone and three with a second app ID, then the reader step's 27, one with a second app ID.
     * eligible-v1 is the healthy control of the retiring layout, and v2-beside-unrelated-body the
     * control of the sibling layout, whose unsupported body names another package and principal.
     */
    public static final Set<String> LIFECYCLE_MODES = Set.of("retiring-v1", "v2-slot", "eligible-v1",
            "v2-beside-reservation", "v2-beside-sibling", "v2-beside-unrelated-body", "v2-grant", "v2-scope-1",
            "v2-recovery-hold", "v2-recovery-scope-2", "v2-recovery-scope-3", "v2-noted", "v2-retiring",
            "v2-retired", "v2-disposing", "v2-legacy-suspended", "legacy-continuation-interrupted",
            "mixed-suspend-backup", "mixed-lift-backup", "mixed-suspend-conflict", "mixed-lift-conflict",
            "tombstone-live", "tombstone-releasing", "releasing-without-directory", "maximum-beside-eligible",
            "damaged-v2-of-v1", "damaged-retired-unknown-inventory", "damaged-disposing-work", "v3-prefix-valid",
            "v3-prefix-broken", "reservation", "reservation-wrong-serial", "lift-v1");
    /** The modes with a second app ID, which the command line takes before the serial. */
    public static final Set<String> COMPANION_MODES = Set.of("v2-beside-reservation", "v2-beside-sibling",
            "v2-beside-unrelated-body", "maximum-beside-eligible");
    /** The maximum record's package: 255 characters, the bound of the stable prefix. */
    public static final String MAXIMUM_PACKAGE = "dev.andrix.proof.maximum." + "m".repeat(230);
    /** The other account's package in the reservation companion. */
    public static final String OTHER = "dev.andrix.proof.lifecycleother";
    /** USER_PAUSED in the suspension reason registry. */
    static final int USER_PAUSED = 1;
    /** The suspension's fixed wall clock time, informational. */
    static final long SUSPENDED_AT = 1_700_000_000_000L;
    // Further codes of the suspension reason registry, each for an actor class that may use it.
    static final int CREDENTIAL_EXPOSED = 2;
    static final int SUSPECTED_COMPROMISE = 3;
    static final int DEVICE_HANDOVER = 5;
    static final int DATA_TRANSFER = 6;
    static final int RECOVERY_REVIEW = 7;
    static final String NO_REFERENCE = "0".repeat(32);
    /** The grant reference of the grant mode's entry, never zero. */
    static final String GRANT = "47".repeat(16);
    /** A noted entry's salted SHA-256: a fixed digest, no note behind it. */
    static final String NOTE = "5a".repeat(32);
    /** The ticket ID of the tombstone modes, never zero. */
    static final String TICKET = "54".repeat(16);
    // The fixed slot frame: magic, type, version and length, and the SHA-256 at the end.
    private static final int FRAME = 12;
    private static final int CHECKSUM = 32;
    private static final int SLOT_TYPE = 2;
    private static final int MAGIC = 0x44495841;
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
     * otherAppId is used by the companion modes only.
     */
    public static Map<String, byte[]> lifecycleLayout(String mode, String lineage, int appId, int otherAppId,
            long serial, Set<String> signers) {
        if (!LIFECYCLE_MODES.contains(mode) || signers == null || signers.size() != 1) {
            throw new IllegalArgumentException("lifecycle mode and one signer required");
        }
        boolean companion = COMPANION_MODES.contains(mode);
        if (companion && (otherAppId == appId || otherAppId < 10000 || otherAppId > 19999)) {
            throw new IllegalArgumentException("another ordinary app ID required");
        }
        if (!mode.equals("eligible-v1") && !mode.equals("retiring-v1") && !mode.equals("v2-slot")
                && !mode.startsWith("v2-beside-")) {
            return guestLayout(mode, lineage(lineage), appId, otherAppId, serial, signers);
        }
        Map<Integer, NativeIdentityRecords.HeaderEntry> entries = new TreeMap<>();
        Map<Integer, NativeIdentityRecords.Slot> slots = new TreeMap<>();
        NativeIdentityRecords.Header header;
        switch (mode) {
            case "retiring-v1" -> slots.put(appId, retiringBody(lineage, appId, serial, signers));
            case "eligible-v1" -> slots.put(appId,
                    NativeIdentityRecords.decodeSlot(body(lineage, appId, serial, signers)));
            case "v2-slot" -> slots.put(appId, suspended(lineage, appId, SUBJECT, FIRST_ID, serial, signers));
            case "v2-beside-reservation" -> {
                entries.put(appId, new NativeIdentityRecords.HeaderEntry(appId, NativeIdentityRecords.SlotPhase.CREATING,
                        FIRST_ID, SUBJECT, new NativeIdentityRecords.CreationBinding(USER, serial, signers)));
                slots.put(otherAppId, suspended(lineage, otherAppId, OTHER, FIRST_ID + 1, serial, signers));
            }
            case "v2-beside-sibling" -> {
                slots.put(appId, NativeIdentityRecords.decodeSlot(body(lineage, appId, serial, signers)));
                slots.put(otherAppId, suspended(lineage, otherAppId, SUBJECT, FIRST_ID + 1, serial, signers));
            }
            case "v2-beside-unrelated-body" -> {
                slots.put(appId, NativeIdentityRecords.decodeSlot(body(lineage, appId, serial, signers)));
                slots.put(otherAppId, suspended(lineage, otherAppId, OTHER, FIRST_ID + 1, serial, signers));
            }
            default -> throw new IllegalArgumentException("lifecycle mode");
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

    // ------------------------------------------------------------------ the reader step's layouts

    private static NativeIdentityRecords.Suspension entry(NativeIdentityRecords.ActorClass actor, int scope,
            long serial, String grant, int reason, long time, String note) {
        return new NativeIdentityRecords.Suspension(actor, scope, USER, serial, grant, reason, time, note);
    }

    private static NativeIdentityRecords.Lifecycle lifecycle(NativeIdentityRecords.LifecycleState state,
            List<NativeIdentityRecords.Suspension> entries, NativeIdentityRecords.Retirement retirement) {
        return new NativeIdentityRecords.Lifecycle(state, entries, retirement);
    }

    /** The subject's slot at this generation: principal ID 1 of user 0, with this lifecycle. */
    private static NativeIdentityRecords.Slot subject(String lineage, int appId, long generation, long serial,
            Set<String> signers, NativeIdentityRecords.Lifecycle lifecycle) {
        return new NativeIdentityRecords.Slot(lineage, appId, SUBJECT, generation, signers,
                List.of(new NativeIdentityRecords.UserEntry(FIRST_ID, USER, serial, lifecycle)));
    }

    /** The subject's eligible version 1 body at this generation: the lift of a later boot at 3. */
    private static NativeIdentityRecords.Slot eligibleAt(String lineage, int appId, long generation, long serial,
            Set<String> signers) {
        return new NativeIdentityRecords.Slot(lineage, appId, SUBJECT, generation, signers,
                List.of(new NativeIdentityRecords.UserEntry(FIRST_ID, USER, serial, false)));
    }

    /**
     * The plan's 16 kinds in kind order, each kind's code its position from 1. Retirement kinds, 1
     * to 9, are in the first state; disposition kinds in the second. A DISCHARGED kind carries its
     * receipt: odd kinds bound to a reference, even kinds with none, as a receipt for nothing to do
     * may.
     */
    private static List<NativeIdentityRecords.Obligation> inventory(NativeIdentityRecords.ObligationState retirement,
            NativeIdentityRecords.ObligationState disposition) {
        List<NativeIdentityRecords.Obligation> list = new ArrayList<>();
        for (NativeIdentityRecords.ObligationKind kind : NativeIdentityRecords.ObligationKind.values()) {
            int code = kind.ordinal() + 1;
            NativeIdentityRecords.ObligationState state = kind.disposition() ? disposition : retirement;
            boolean receipt = state == NativeIdentityRecords.ObligationState.DISCHARGED;
            list.add(new NativeIdentityRecords.Obligation(kind, state, receipt && code % 2 == 1
                    ? String.format("%02x", 0x10 + code).repeat(16) : NO_REFERENCE, receipt ? code : 0,
                    receipt ? SUSPENDED_AT + code : 0));
        }
        return list;
    }

    /** The account user's retirement with this inventory. */
    private static NativeIdentityRecords.Retirement byUser(long serial, List<NativeIdentityRecords.Obligation> duties) {
        return new NativeIdentityRecords.Retirement(NativeIdentityRecords.ActorClass.ACCOUNT_USER, USER, serial,
                NO_REFERENCE, SUSPENDED_AT + 100, duties);
    }

    /** A legacy marker's retirement: no actor, grant or time, with every kind or with none. */
    private static NativeIdentityRecords.Retirement legacy(List<NativeIdentityRecords.Obligation> duties) {
        return new NativeIdentityRecords.Retirement(NativeIdentityRecords.ActorClass.LEGACY_MARKER, 0, 0,
                NO_REFERENCE, 0, duties);
    }

    /**
     * The largest value: 64 users of the maximum package, signed by 32 signers, each user with six
     * noted entries, its own, four grants' and a recovery hold, and every kind outstanding in its
     * retirement. User 0 has the guest's serial, the others serials from 101; their principal IDs
     * follow the subject's, 2 to 65. 1,357 bytes for the fixed part and 931 for each user.
     */
    private static NativeIdentityRecords.Slot maximum(String lineage, int appId, long serial) {
        Set<String> signers = new TreeSet<>();
        for (int i = 1; i <= NativeIdentityRecords.MAX_SIGNERS; i++) signers.add(String.format("%064x", i));
        List<NativeIdentityRecords.UserEntry> users = new ArrayList<>();
        for (int user = 0; user < NativeIdentityRecords.MAX_USERS; user++) {
            long userSerial = user == 0 ? serial : 100 + user;
            List<NativeIdentityRecords.Suspension> entries = new ArrayList<>();
            entries.add(new NativeIdentityRecords.Suspension(NativeIdentityRecords.ActorClass.ACCOUNT_USER, 0, user,
                    userSerial, NO_REFERENCE, USER_PAUSED, SUSPENDED_AT, NOTE));
            for (int grant = 1; grant <= 4; grant++) {
                entries.add(entry(NativeIdentityRecords.ActorClass.ADMIN_GRANT, 0, serial,
                        String.format("%02x", 0x40 + grant).repeat(16), SUSPECTED_COMPROMISE, SUSPENDED_AT + grant,
                        NOTE));
            }
            entries.add(entry(NativeIdentityRecords.ActorClass.RECOVERY_HOLD, 2, serial, NO_REFERENCE,
                    RECOVERY_REVIEW, SUSPENDED_AT + 9, NOTE));
            users.add(new NativeIdentityRecords.UserEntry(FIRST_ID + 1 + user, user, userSerial, lifecycle(
                    NativeIdentityRecords.LifecycleState.RETIRING, entries, new NativeIdentityRecords.Retirement(
                            NativeIdentityRecords.ActorClass.ACCOUNT_USER, user, userSerial, NO_REFERENCE,
                            SUSPENDED_AT + 100, inventory(NativeIdentityRecords.ObligationState.OUTSTANDING,
                                    NativeIdentityRecords.ObligationState.OUTSTANDING)))));
        }
        return new NativeIdentityRecords.Slot(lineage, appId, MAXIMUM_PACKAGE, 2, signers, users);
    }

    /** A version 1 header of LIVE or RELEASING entries at these app IDs, in app ID order. */
    private static byte[] header(String lineage, long lastId, NativeIdentityRecords.SlotPhase phase, int... appIds) {
        List<NativeIdentityRecords.HeaderEntry> entries = new ArrayList<>();
        for (int appId : new TreeSet<>(java.util.Arrays.stream(appIds).boxed().toList())) {
            entries.add(new NativeIdentityRecords.HeaderEntry(appId, phase, 0, ""));
        }
        return NativeIdentityRecords.encodeHeader(new NativeIdentityRecords.Header(lineage, lastId, entries));
    }

    // Where the stable prefix of this value's record ends: the frame, the lineage, app ID,
    // generation, package, signers and user count, then each user's identity.
    private static int prefixEnd(NativeIdentityRecords.Slot slot) {
        return FRAME + 16 + 4 + 8 + 2 + slot.packageName.length() + 2 + 32 * slot.signerSha256.size() + 2
                + 20 * slot.users.size();
    }

    // Fixture assembly: a slot frame of this version around this body, with its length and SHA-256.
    private static byte[] framed(int version, byte[] body) {
        int length = FRAME + body.length + CHECKSUM;
        ByteBuffer record = ByteBuffer.allocate(length).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        record.putInt(MAGIC).putShort((short) SLOT_TYPE).putShort((short) version).putInt(length).put(body);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(record.array(), 0, length - CHECKSUM);
            record.put(digest.digest());
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 unavailable", error);
        }
        return record.array();
    }

    // The body of a record the codec wrote: everything between the frame and the checksum.
    private static byte[] body(byte[] record) {
        return java.util.Arrays.copyOfRange(record, FRAME, record.length - CHECKSUM);
    }

    // Fixture assembly: the codec's version 2 record with one byte changed from the codec's value
    // to another, framed again. Refuses unless the codec wrote the expected value there.
    private static byte[] edited(byte[] record, int at, int expected, int value) {
        if ((record[at] & 0xff) != expected) throw new IllegalStateException("fixture assembly drift");
        byte[] copy = record.clone();
        copy[at] = (byte) value;
        return framed(2, body(copy));
    }

    // Fixture assembly is never a valid value: the codec refuses it, or the assembly is wrong.
    private static byte[] undecodable(byte[] record) {
        try {
            NativeIdentityRecords.decodeSlot(record);
        } catch (IllegalArgumentException refused) {
            return record;
        }
        throw new IllegalStateException("fixture assembly decodes as a valid record");
    }

    private static void slotFiles(Map<String, byte[]> files, int appId, byte[] main, byte[] reserve, byte[] backup) {
        String directory = SLOTS + "/" + appId + "/";
        files.put(directory + "record.bin", main);
        files.put(directory + "record.bin.reservecopy", reserve);
        if (backup != null) files.put(directory + "record.bin-backup", backup);
    }

    /**
     * The layouts the reader step of the normal image adds, by path relative to the store. Each has
     * equal header copies. Valid records are the codec's; see the class description for the damaged
     * and later version records.
     */
    private static Map<String, byte[]> guestLayout(String mode, String lineage, int appId, int otherAppId,
            long serial, Set<String> signers) {
        Map<String, byte[]> files = new TreeMap<>();
        NativeIdentityRecords.SlotPhase live = NativeIdentityRecords.SlotPhase.LIVE;
        byte[] header = header(lineage, FIRST_ID, live, appId);
        byte[] eligible = body(lineage, appId, serial, signers);
        byte[] suspended = NativeIdentityRecords.encodeSlot(
                suspended(lineage, appId, SUBJECT, FIRST_ID, serial, signers));
        byte[] lifted = NativeIdentityRecords.encodeSlot(eligibleAt(lineage, appId, 3, serial, signers));
        NativeIdentityRecords.LifecycleState state = NativeIdentityRecords.LifecycleState.ELIGIBLE;
        NativeIdentityRecords.Slot value = null;
        switch (mode) {
            case "v2-grant" -> value = subject(lineage, appId, 2, serial, signers, lifecycle(state, List.of(entry(
                    NativeIdentityRecords.ActorClass.ADMIN_GRANT, 0, serial, GRANT, CREDENTIAL_EXPOSED, SUSPENDED_AT,
                    null)), null));
            case "v2-scope-1" -> value = subject(lineage, appId, 2, serial, signers, lifecycle(state, List.of(entry(
                    NativeIdentityRecords.ActorClass.ACCOUNT_USER, 1, serial, NO_REFERENCE, DATA_TRANSFER,
                    SUSPENDED_AT, null)), null));
            case "v2-recovery-hold", "v2-recovery-scope-2", "v2-recovery-scope-3" -> value = subject(lineage, appId,
                    2, serial, signers, lifecycle(state, List.of(entry(NativeIdentityRecords.ActorClass.RECOVERY_HOLD,
                            mode.equals("v2-recovery-hold") ? 0 : mode.endsWith("2") ? 2 : 3, serial, NO_REFERENCE,
                            RECOVERY_REVIEW, SUSPENDED_AT, null)), null));
            case "v2-noted" -> value = subject(lineage, appId, 2, serial, signers, lifecycle(state, List.of(entry(
                    NativeIdentityRecords.ActorClass.ACCOUNT_USER, 0, serial, NO_REFERENCE, DEVICE_HANDOVER,
                    SUSPENDED_AT, NOTE)), null));
            case "v2-retiring" -> value = subject(lineage, appId, 2, serial, signers, lifecycle(
                    NativeIdentityRecords.LifecycleState.RETIRING, List.of(), byUser(serial, inventory(
                            NativeIdentityRecords.ObligationState.OUTSTANDING,
                            NativeIdentityRecords.ObligationState.OUTSTANDING))));
            case "v2-retired" -> value = subject(lineage, appId, 3, serial, signers, lifecycle(
                    NativeIdentityRecords.LifecycleState.RETIRED, List.of(), byUser(serial, inventory(
                            NativeIdentityRecords.ObligationState.DISCHARGED,
                            NativeIdentityRecords.ObligationState.OUTSTANDING))));
            case "v2-disposing" -> value = disposing(lineage, appId, serial, signers);
            case "v2-legacy-suspended" -> value = legacySuspended(lineage, appId, serial, signers);
            case "legacy-continuation-interrupted" -> {
                // The continuation's main and reserve, written before the backup of the version 1
                // marker it continues was removed.
                byte[] continued = NativeIdentityRecords.encodeSlot(subject(lineage, appId, 2, serial, signers,
                        lifecycle(NativeIdentityRecords.LifecycleState.RETIRING, List.of(), legacy(inventory(
                                NativeIdentityRecords.ObligationState.OUTSTANDING,
                                NativeIdentityRecords.ObligationState.OUTSTANDING)))));
                slotFiles(files, appId, continued, continued,
                        NativeIdentityRecords.encodeSlot(retiringBody(lineage, appId, serial, signers)));
            }
            case "mixed-suspend-backup" -> slotFiles(files, appId, suspended, suspended, eligible);
            case "mixed-lift-backup" -> slotFiles(files, appId, lifted, lifted, suspended);
            case "mixed-suspend-conflict" -> slotFiles(files, appId, suspended, eligible, null);
            case "mixed-lift-conflict" -> slotFiles(files, appId, lifted, suspended, null);
            case "tombstone-live", "tombstone-releasing" -> {
                value = new NativeIdentityRecords.Slot(lineage, appId, SUBJECT, 4, signers, List.of(),
                        new NativeIdentityRecords.ReleaseTicket(FIRST_ID, USER, serial, TICKET));
                if (mode.equals("tombstone-releasing")) {
                    header = header(lineage, FIRST_ID, NativeIdentityRecords.SlotPhase.RELEASING, appId);
                }
            }
            case "releasing-without-directory" -> header = header(lineage, FIRST_ID,
                    NativeIdentityRecords.SlotPhase.RELEASING, appId);
            case "maximum-beside-eligible" -> {
                header = header(lineage, FIRST_ID + NativeIdentityRecords.MAX_USERS, live, appId, otherAppId);
                slotFiles(files, appId, eligible, eligible, null);
                byte[] largest = NativeIdentityRecords.encodeSlot(maximum(lineage, otherAppId, serial));
                slotFiles(files, otherAppId, largest, largest, null);
            }
            case "damaged-v2-of-v1" -> {
                // The version 2 encoding of the eligible version 1 value: the identity's flag byte
                // becomes the block of an ELIGIBLE user with no entry.
                byte[] flags = body(eligible);
                if (flags[flags.length - 1] != 0) throw new IllegalStateException("fixture assembly drift");
                byte[] block = java.util.Arrays.copyOf(flags, flags.length + 1);
                block[flags.length - 1] = 1;
                byte[] record = undecodable(framed(2, block));
                slotFiles(files, appId, record, record, null);
            }
            case "damaged-retired-unknown-inventory" -> {
                // Its valid twin, v2-legacy-suspended, with the state RETIRING made RETIRED.
                NativeIdentityRecords.Slot twin = legacySuspended(lineage, appId, serial, signers);
                byte[] record = undecodable(edited(NativeIdentityRecords.encodeSlot(twin), prefixEnd(twin), 2, 3));
                slotFiles(files, appId, record, record, null);
            }
            case "damaged-disposing-work" -> {
                // Its valid twin, v2-disposing, with WORK, a retirement kind, DISPOSING. The block
                // has no entry: state and count, then 39 retirement bytes, then WORK's kind and
                // state.
                NativeIdentityRecords.Slot twin = disposing(lineage, appId, serial, signers);
                byte[] bytes = NativeIdentityRecords.encodeSlot(twin);
                int at = prefixEnd(twin) + 2 + 39;
                if (bytes[at] != 1) throw new IllegalStateException("fixture assembly drift");
                byte[] record = undecodable(edited(bytes, at + 1, 3, 2));
                slotFiles(files, appId, record, record, null);
            }
            case "v3-prefix-valid", "v3-prefix-broken" -> {
                // The stable prefix of the subject's suspended record, then a tail of a later
                // version, as slot version 3. The broken prefix names principal ID 0.
                NativeIdentityRecords.Slot source = suspended(lineage, appId, SUBJECT, FIRST_ID, serial, signers);
                byte[] prefix = java.util.Arrays.copyOfRange(NativeIdentityRecords.encodeSlot(source), FRAME,
                        prefixEnd(source));
                if (mode.equals("v3-prefix-broken")) {
                    int at = prefix.length - 20;
                    if (ByteBuffer.wrap(prefix, at, 8).order(java.nio.ByteOrder.LITTLE_ENDIAN).getLong() != FIRST_ID) {
                        throw new IllegalStateException("fixture assembly drift");
                    }
                    java.util.Arrays.fill(prefix, at, at + 8, (byte) 0);
                }
                byte[] tail = "a later slot version tail".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
                byte[] all = java.util.Arrays.copyOf(prefix, prefix.length + tail.length);
                System.arraycopy(tail, 0, all, prefix.length, tail.length);
                byte[] record = undecodable(framed(3, all));
                slotFiles(files, appId, record, record, null);
            }
            case "reservation" -> header = creatingHeader(lineage, appId, serial, signers);
            case "reservation-wrong-serial" -> {
                if (serial == Long.MAX_VALUE) throw new IllegalArgumentException("a serial below the largest required");
                header = creatingHeader(lineage, appId, serial + 1, signers);
            }
            case "lift-v1" -> slotFiles(files, appId, lifted, lifted, null);
            default -> throw new IllegalArgumentException("lifecycle mode");
        }
        if (value != null) {
            byte[] bytes = NativeIdentityRecords.encodeSlot(value);
            slotFiles(files, appId, bytes, bytes, null);
        }
        files.put(HEADER, header);
        files.put(RESERVE, header);
        return files;
    }

    /** The subject RETIRED with every disposition kind DISPOSING, at generation 4. */
    private static NativeIdentityRecords.Slot disposing(String lineage, int appId, long serial, Set<String> signers) {
        return subject(lineage, appId, 4, serial, signers, lifecycle(NativeIdentityRecords.LifecycleState.RETIRED,
                List.of(), byUser(serial, inventory(NativeIdentityRecords.ObligationState.DISCHARGED,
                        NativeIdentityRecords.ObligationState.DISPOSING))));
    }

    /** The subject's legacy marker, RETIRING with an unknown inventory, suspended by its user. */
    private static NativeIdentityRecords.Slot legacySuspended(String lineage, int appId, long serial,
            Set<String> signers) {
        return subject(lineage, appId, 2, serial, signers, lifecycle(NativeIdentityRecords.LifecycleState.RETIRING,
                List.of(entry(NativeIdentityRecords.ActorClass.ACCOUNT_USER, 0, serial, NO_REFERENCE, USER_PAUSED,
                        SUSPENDED_AT, null)), legacy(List.of())));
    }

    /**
     * One fresh lifecycle guest layout: the header pair and each slot's copies, directories 0700
     * and files 0600, and its manifest as the return value.
     */
    public static String generateLifecycle(Path output, String mode, String lineage, int appId, int otherAppId,
            long serial) throws IOException {
        Map<String, byte[]> files = lifecycleLayout(mode, lineage, appId, otherAppId, serial, Set.of(FIXTURE_SIGNER));
        fresh(output.toString());
        directory(output);
        Path slots = output.resolve(SLOTS);
        directory(slots);
        Set<String> top = new TreeSet<>(Set.of(SLOTS));
        Map<String, Set<String>> slotNames = new TreeMap<>();
        StringBuilder listed = new StringBuilder();
        for (Map.Entry<String, byte[]> file : files.entrySet()) {
            Path path = output.resolve(file.getKey());
            if (!Files.isDirectory(path.getParent(), LinkOption.NOFOLLOW_LINKS)) directory(path.getParent());
            write(path, file.getValue());
            String[] parts = file.getKey().split("/");
            if (parts[0].equals(SLOTS)) slotNames.computeIfAbsent(parts[1], key -> new TreeSet<>()).add(parts[2]);
            else top.add(file.getKey());
            listed.append(listed.length() == 0 ? "" : ",").append(entry(file.getKey(), file.getValue()));
        }
        for (Map.Entry<String, Set<String>> slot : slotNames.entrySet()) {
            sync(slots.resolve(slot.getKey()));
            exact(slots.resolve(slot.getKey()), slot.getValue());
        }
        sync(slots);
        sync(output);
        sync(output.getParent());
        exact(output, top);
        exact(slots, slotNames.keySet());
        boolean companion = COMPANION_MODES.contains(mode);
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
     * Command line: {@code empty-v1 OUTPUT},
     * {@code predict-v2 OUTPUT LINEAGE APP_ID USER_SERIAL 1},
     * {@code MODE OUTPUT LINEAGE APP_ID USER_SERIAL} for a lifecycle mode without a second app ID,
     * such as retiring-v1, v2-slot or eligible-v1, or
     * {@code MODE OUTPUT LINEAGE APP_ID OTHER_APP_ID USER_SERIAL} for one of COMPANION_MODES, such
     * as v2-beside-reservation, v2-beside-sibling or v2-beside-unrelated-body. Every argument is
     * validated with explicit checks before any file is created, also when Java assertions are
     * disabled. Any other mode refuses.
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
        } else if (args.length == 5 && LIFECYCLE_MODES.contains(args[0]) && !COMPANION_MODES.contains(args[0])) {
            String lineage = lineage(args[2]);
            int appId = appId(args[3]);
            long serial = serial(args[4]);
            if ("reservation-wrong-serial".equals(args[0]) && serial == Long.MAX_VALUE) {
                throw new IllegalArgumentException("a serial below the largest required");
            }
            Path output = fresh(args[1]);
            System.out.println(generateLifecycle(output, args[0], lineage, appId, appId, serial));
        } else if (args.length == 6 && COMPANION_MODES.contains(args[0])) {
            String lineage = lineage(args[2]);
            int appId = appId(args[3]);
            int otherAppId = appId(args[4]);
            long serial = serial(args[5]);
            if (otherAppId == appId) throw new IllegalArgumentException("another ordinary app ID required");
            Path output = fresh(args[1]);
            System.out.println(generateLifecycle(output, args[0], lineage, appId, otherAppId, serial));
        } else {
            throw new IllegalArgumentException("usage: empty-v1 OUTPUT | predict-v2 OUTPUT LINEAGE APP_ID USER_SERIAL 1"
                    + " | MODE OUTPUT LINEAGE APP_ID USER_SERIAL | COMPANION_MODE OUTPUT LINEAGE APP_ID"
                    + " OTHER_APP_ID USER_SERIAL");
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
