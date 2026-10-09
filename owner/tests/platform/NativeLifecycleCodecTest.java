// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import com.android.server.pm.NativeIdentityRecords.ActorClass;
import com.android.server.pm.NativeIdentityRecords.Lifecycle;
import com.android.server.pm.NativeIdentityRecords.LifecycleState;
import com.android.server.pm.NativeIdentityRecords.Obligation;
import com.android.server.pm.NativeIdentityRecords.ObligationKind;
import com.android.server.pm.NativeIdentityRecords.ObligationState;
import com.android.server.pm.NativeIdentityRecords.ReleaseTicket;
import com.android.server.pm.NativeIdentityRecords.Retirement;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.SlotPrefix;
import com.android.server.pm.NativeIdentityRecords.Suspension;
import com.android.server.pm.NativeIdentityRecords.SuspensionReason;
import com.android.server.pm.NativeIdentityRecords.UserEntry;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Consumer;

/**
 * Host checks of the version 2 slot codec, the account lifecycle values and the stable prefix
 * reader of later slot versions, as the native account lifecycle record plan defines them. The
 * codec's bytes are compared with layouts written here by hand, with an independent raw writer of
 * the same layout, and, through the runner, with an independent Python encoder: each golden's
 * length and SHA-256 are pinned below, and the run writes each golden to the directory it is
 * given so the runner can compare the bytes. Version 1 values keep their version 1 bytes. Every
 * strict field, bound and decoder invariant is refused when broken, with a valid twin accepted.
 * Host JVM only, no store I/O: not PMS, Android, storage or authority evidence.
 */
public final class NativeLifecycleCodecTest {
    private static final String LINEAGE = "00112233445566778899aabbccddeeff";
    private static final String OTHER_LINEAGE = "ffeeddccbbaa99887766554433221100";
    private static final String LOW = "0f".repeat(32);
    private static final String HIGH = "aa".repeat(32);
    private static final String ZERO = "0".repeat(32);
    private static final String LONGEST = "a." + "b".repeat(253);
    private static final long TIME = 1_700_000_000_000L;
    private static final int MAGIC = 0x44495841, TYPE_SLOT = 2, CHECKSUM = 32;

    // The version 2 goldens: length and SHA-256 of the whole record, computed by the runner's
    // independent encoder from the plan's layout alone.
    private static final int GOLDEN_SUSPENDED_BYTES = 176;
    private static final String GOLDEN_SUSPENDED_SHA256 = "160fb3c1b00f2e25132671f89e6042871b9e18423463b57ece352cfcde937582";
    private static final int GOLDEN_HOLDS_BYTES = 412;
    private static final String GOLDEN_HOLDS_SHA256 = "6a9f04924546138a6dd16d9d011d21b2d715847e07587cd6781fdc1310a03ded";
    private static final int GOLDEN_RETIRING_BYTES = 622;
    private static final String GOLDEN_RETIRING_SHA256 = "08b196deaf47aff6c5b0c4e34680f87cfca7ef444490447e47765fc1d38dfb15";
    private static final int GOLDEN_RETIRED_BYTES = 662;
    private static final String GOLDEN_RETIRED_SHA256 = "dcf3ecbf1a3525856c6f77163fcace5b89326bc1725ff79a2eb61264827b2c1a";
    private static final int GOLDEN_LEGACY_CONTINUED_BYTES = 620;
    private static final String GOLDEN_LEGACY_CONTINUED_SHA256 = "52f94713179ebb28423cc2d69c7bb0265d9c68ef82a3060db094da63d76be78c";
    private static final int GOLDEN_LEGACY_SUSPENDED_BYTES = 227;
    private static final String GOLDEN_LEGACY_SUSPENDED_SHA256 = "d1a7f1247f4cc95c9c8656a9abbc02df6926c517d0249a469759f1ff0f47b5d0";
    private static final int GOLDEN_TWO_USERS_BYTES = 244;
    private static final String GOLDEN_TWO_USERS_SHA256 = "6b80e29a3485ca7842bcd8b74bf19040e5a27cab5679fa2361c626c6998b0792";
    private static final int GOLDEN_TICKET_BYTES = 165;
    private static final String GOLDEN_TICKET_SHA256 = "735555c75d0579dfd9b74f12675e0d9a9f8de8ad996883cf4b944aaaf621f192";
    private static final int GOLDEN_MAXIMUM_BYTES = 60941;
    private static final String GOLDEN_MAXIMUM_SHA256 = "0481574f619b2a6235020ce92a20d23da77ee687d8eff572b44f44c99bea2875";

    // The suspended golden written by hand, field by field, without its SHA-256.
    private static final String SUSPENDED_LAYOUT = "41584944 0200 0200 b0000000"
            + " 00112233445566778899aabbccddeeff 8b270000 0200000000000000 0300 612e62"
            + " 0100 " + LOW
            + " 0100 0300000000000000 00000000 0500000000000000"
            + " 01 01"
            + " 01 00 00000000 0500000000000000 " + ZERO + " 0100 0068e5cf8b010000 00";
    // Version 1 bytes from the original codec, as NativeIdentityRecordsTest pins them.
    private static final String V1_GOLDEN_SLOT = ""
            + "4158494402000100bb00000000112233445566778899aabbccddeeff8b270000"
            + "02000000000000000300612e6202000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"
            + "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0faaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0200030000000000000000000000050000"
            + "00000000000004000000000000000a0000000600000000000000010e04697ba0"
            + "bcf97ab71a919b3707583748db4bce6f8a9deb2a781780b811ee2d";
    private static final String V1_TOMBSTONE_SLOT = ""
            + "41584944020001008200000000112233445566778899aabbccddeeff1f4e0000"
            + "010000000000000014006465762e616e647269782e7072696e636970616c0100"
            + "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"
            + "00009f7faf32aa0d47010557bc033ae9596c64016eb720d84837f158f5315bb6"
            + "fac2";

    private interface Body { void run(List<String> problems) throws Exception; }

    private static final List<String> failures = new ArrayList<>();
    private static int passed;

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

    private static void check(List<String> problems, boolean ok, String problem) {
        if (!ok) problems.add(problem);
    }

    // ------------------------------------------------------------------ values

    private static String hex2(int value) {
        return String.format("%02x", value);
    }

    private static Suspension entry(ActorClass actor, int scope, int user, long serial, String grant,
            int reason, long time, String note) {
        return new Suspension(actor, scope, user, serial, grant, reason, time, note);
    }

    private interface Each { Obligation of(int code, ObligationKind kind); }

    // Every kind once, in kind order.
    private static List<Obligation> inventory(Each each) {
        List<Obligation> list = new ArrayList<>();
        for (ObligationKind kind : ObligationKind.values()) list.add(each.of(list.size() + 1, kind));
        return list;
    }

    private static Obligation outstanding(int code, ObligationKind kind) {
        return new Obligation(kind, ObligationState.OUTSTANDING, ZERO, 0, 0);
    }

    private static Lifecycle lifecycle(LifecycleState state, List<Suspension> entries, Retirement retirement) {
        return new Lifecycle(state, entries, retirement);
    }

    private static Retirement legacy() {
        return new Retirement(ActorClass.LEGACY_MARKER, 0, 0, ZERO, 0, List.of());
    }

    private static Slot one(int appId, String name, long generation, Set<String> signers, long id, int user,
            long serial, Lifecycle lifecycle) {
        return new Slot(LINEAGE, appId, name, generation, signers, List.of(new UserEntry(id, user, serial, lifecycle)));
    }

    private static final List<String> GOLDEN_ORDER = List.of("SUSPENDED", "HOLDS", "RETIRING", "RETIRED",
            "LEGACY_CONTINUED", "LEGACY_SUSPENDED", "TWO_USERS", "TICKET", "MAXIMUM");

    // Every golden value its constructors accept, in order. A rule that refuses one leaves it out,
    // and each case that needs it then fails by itself, so every run completes with every case.
    private static Map<String, Slot> goldens() {
        Map<String, Slot> goldens = new LinkedHashMap<>();
        for (String name : GOLDEN_ORDER) {
            try {
                goldens.put(name, golden(name));
            } catch (RuntimeException refused) {
                // Left out: the cases that need it fail.
            }
        }
        return goldens;
    }

    private static Slot golden(String name) {
        switch (name) {
            case "SUSPENDED":
                return one(10123, "a.b", 2, Set.of(LOW), 3, 0, 5, lifecycle(LifecycleState.ELIGIBLE,
                List.of(entry(ActorClass.ACCOUNT_USER, 0, 0, 5, ZERO, 1, TIME, null)), null));
            case "HOLDS":
                return one(10124, "dev.andrix.principal", 3, Set.of(LOW, HIGH), 7, 0, 9,
                // The plan's entry order is class, then actor serial, then grant: the grant entry
                // of serial 2 precedes that of serial 3 though its grant reference is the larger.
                lifecycle(LifecycleState.ELIGIBLE, List.of(
                        entry(ActorClass.ACCOUNT_USER, 0, 0, 9, ZERO, 2, 1, "ab".repeat(32)),
                        entry(ActorClass.ADMIN_GRANT, 0, 0, 2, "22".repeat(16), 999, 3, null),
                        entry(ActorClass.ADMIN_GRANT, 1, 0, 3, "11".repeat(16), 4, 2, null),
                        entry(ActorClass.RECOVERY_HOLD, 3, 0, 1, ZERO, 7, -1, "cd".repeat(32))), null));
            case "RETIRING":
                return one(10125, "dev.andrix.retiring", 4, Set.of(LOW), 11, 0, 2,
                lifecycle(LifecycleState.RETIRING, List.of(), new Retirement(ActorClass.ACCOUNT_USER, 0, 2, ZERO,
                        TIME + 100, inventory((code, kind) -> code <= 3
                                ? new Obligation(kind, ObligationState.DISCHARGED, hex2(code).repeat(16), code,
                                TIME + code) : outstanding(code, kind)))));
            case "RETIRED":
                return one(10126, "dev.andrix.retired", 9, Set.of(HIGH), 12, 0, 4,
                lifecycle(LifecycleState.RETIRED, List.of(entry(ActorClass.ACCOUNT_USER, 0, 0, 4, ZERO, 6, 6, null)),
                        new Retirement(ActorClass.ADMIN_GRANT, 0, 3, "33".repeat(16), 5, inventory((code, kind) -> {
                            if (code <= 9) {
                                return new Obligation(kind, ObligationState.DISCHARGED, hex2(code).repeat(16), code,
                                        TIME + code);
                            }
                            ObligationState state = code <= 12 ? ObligationState.DISPOSING
                                    : code == 13 ? ObligationState.ORPHANED_WITH_USER
                                    : code == 14 ? ObligationState.DISCHARGED : ObligationState.OUTSTANDING;
                            return new Obligation(kind, state, code <= 14 ? hex2(code).repeat(16) : ZERO, 0, 0);
                        }))));
            case "LEGACY_CONTINUED":
                return one(10127, "dev.andrix.legacy", 5, Set.of(LOW), 13, 0, 1,
                lifecycle(LifecycleState.RETIRING, List.of(), new Retirement(ActorClass.LEGACY_MARKER, 0, 0, ZERO, 0,
                        inventory(NativeLifecycleCodecTest::outstanding))));
            case "LEGACY_SUSPENDED":
                return one(10128, "dev.andrix.held", 6, Set.of(LOW), 14, 0, 1,
                lifecycle(LifecycleState.RETIRING, List.of(entry(ActorClass.RECOVERY_HOLD, 2, 0, 1, ZERO, 7, 8, null)),
                        legacy()));
            case "TWO_USERS":
                return new Slot(LINEAGE, 10129, "dev.andrix.shared", 7, Set.of(LOW, HIGH), List.of(
                new UserEntry(15, 0, 1, false),
                new UserEntry(16, 10, 2, lifecycle(LifecycleState.ELIGIBLE, List.of(entry(ActorClass.ADMIN_GRANT, 0,
                        0, 1, "44".repeat(16), 3, 9, null)), null))));
            case "TICKET":
                return new Slot(LINEAGE, 10130, "dev.andrix.released", 8, Set.of(LOW), List.of(),
                new ReleaseTicket(17, 0, 3, "55".repeat(16)));
            case "MAXIMUM":
                return maximum();
            default:
                throw new AssertionError("no golden " + name);
        }
    }

    // The largest value: 64 users, each with six noted entries and a retirement listing every kind,
    // the longest package and 32 signers. 1,357 + 64 * 931 = 60,941 bytes.
    private static Slot maximum() {
        Set<String> signers = new HashSet<>();
        for (int i = 0; i < 32; i++) signers.add(hex2(255 - i).repeat(32));
        List<UserEntry> users = new ArrayList<>();
        for (int i = 0; i < 64; i++) {
            int user = i * 340;
            List<Suspension> entries = new ArrayList<>();
            entries.add(entry(ActorClass.ACCOUNT_USER, 0, user, i, ZERO, 1, TIME, hex2(i).repeat(32)));
            for (int grant = 0; grant < 4; grant++) {
                entries.add(entry(ActorClass.ADMIN_GRANT, grant == 0 ? 1 : 0, 0, 1,
                        hex2(16 * grant + 1).repeat(15) + hex2(i), 2 + grant, TIME + grant, hex2(255 - i).repeat(32)));
            }
            entries.add(entry(ActorClass.RECOVERY_HOLD, 2, 0, 1, ZERO, 7, -1, "cd".repeat(32)));
            Retirement retirement = new Retirement(ActorClass.USER_REMOVAL, 0, 1, ZERO, TIME, inventory((code, kind) ->
                    new Obligation(kind, code <= 9 ? ObligationState.DISCHARGED : ObligationState.DISPOSING,
                            hex2(code).repeat(16), code, TIME + code)));
            users.add(new UserEntry(i + 1, user, i, lifecycle(LifecycleState.RETIRED, entries, retirement)));
        }
        return new Slot(OTHER_LINEAGE, 19999, LONGEST, Long.MAX_VALUE, signers, users);
    }

    private static Map<String, Object[]> goldenPins() {
        Map<String, Object[]> pins = new LinkedHashMap<>();
        pins.put("SUSPENDED", new Object[] {GOLDEN_SUSPENDED_BYTES, GOLDEN_SUSPENDED_SHA256});
        pins.put("HOLDS", new Object[] {GOLDEN_HOLDS_BYTES, GOLDEN_HOLDS_SHA256});
        pins.put("RETIRING", new Object[] {GOLDEN_RETIRING_BYTES, GOLDEN_RETIRING_SHA256});
        pins.put("RETIRED", new Object[] {GOLDEN_RETIRED_BYTES, GOLDEN_RETIRED_SHA256});
        pins.put("LEGACY_CONTINUED", new Object[] {GOLDEN_LEGACY_CONTINUED_BYTES, GOLDEN_LEGACY_CONTINUED_SHA256});
        pins.put("LEGACY_SUSPENDED", new Object[] {GOLDEN_LEGACY_SUSPENDED_BYTES, GOLDEN_LEGACY_SUSPENDED_SHA256});
        pins.put("TWO_USERS", new Object[] {GOLDEN_TWO_USERS_BYTES, GOLDEN_TWO_USERS_SHA256});
        pins.put("TICKET", new Object[] {GOLDEN_TICKET_BYTES, GOLDEN_TICKET_SHA256});
        pins.put("MAXIMUM", new Object[] {GOLDEN_MAXIMUM_BYTES, GOLDEN_MAXIMUM_SHA256});
        return pins;
    }

    // ------------------------------------------------------------------ bytes

    private static byte[] hex(String layout) {
        String digits = layout.replace(" ", "");
        byte[] bytes = new byte[digits.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(digits.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }

    private static byte[] sha256(byte[] bytes) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(bytes);
    }

    private static String sha256Hex(byte[] bytes) throws Exception {
        StringBuilder text = new StringBuilder();
        for (byte b : sha256(bytes)) text.append(hex2(b & 0xff));
        return text.toString();
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) out.write(part, 0, part.length);
        return out.toByteArray();
    }

    private static byte[] withChecksum(byte[] unsealed) throws Exception {
        return concat(unsealed, sha256(unsealed));
    }

    // An intact frame with this version and body.
    private static byte[] frame(int version, byte[] body) throws Exception {
        return new Raw().i32(MAGIC).u16(TYPE_SLOT).u16(version).i32(12 + body.length + CHECKSUM).bytes(body)
                .sealed();
    }

    private static byte[] body(byte[] record) {
        return Arrays.copyOfRange(record, 12, record.length - CHECKSUM);
    }

    private static byte[] relabeled(byte[] record, int version) throws Exception {
        return frame(version, body(record));
    }

    // An independent little endian writer of raw fields.
    private static final class Raw {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        Raw u8(int value) {
            out.write(value);
            return this;
        }
        Raw u16(int value) { return u8(value).u8(value >>> 8); }
        Raw i32(int value) { return u16(value).u16(value >>> 16); }
        Raw i64(long value) { return i32((int) value).i32((int) (value >>> 32)); }
        Raw hex(String digits) {
            for (int i = 0; i < digits.length(); i += 2) u8(Integer.parseInt(digits.substring(i, i + 2), 16));
            return this;
        }
        Raw text(String value) {
            u16(value.length());
            for (int i = 0; i < value.length(); i++) u8(value.charAt(i));
            return this;
        }
        Raw bytes(byte[] value) {
            out.write(value, 0, value.length);
            return this;
        }
        byte[] toBytes() { return out.toByteArray(); }
        byte[] sealed() throws Exception { return withChecksum(toBytes()); }
    }

    // The raw fields of a version 2 slot. They need not form a valid value: each is written
    // exactly as set, counts and tags included.
    private static final class RawEntry {
        int actor, scope, user, reason, noteTag;
        long serial, time;
        String grant, note;
    }

    private static final class RawDuty {
        int kind, state, code;
        String reference;
        long time;
    }

    private static final class RawRetirement {
        int actor, user, inventory, count;
        long serial, time;
        String grant;
        List<RawDuty> duties = new ArrayList<>();
    }

    private static final class RawUser {
        long id, serial;
        int user, state, count;
        List<RawEntry> entries = new ArrayList<>();
        RawRetirement retirement;
    }

    private static final class RawSlot {
        int version = 2, appId;
        String lineage, pkg;
        long generation;
        List<String> signers;
        List<RawUser> users = new ArrayList<>();
        boolean ticket;
        long lastId, ticketSerial;
        int ticketUser;
        String ticketId;
        byte[] tail = new byte[0];
    }

    private static RawSlot raw(Slot slot) {
        RawSlot raw = new RawSlot();
        raw.lineage = slot.lineage;
        raw.appId = slot.appId;
        raw.generation = slot.generation;
        raw.pkg = slot.packageName;
        raw.signers = new ArrayList<>(new TreeSet<>(slot.signerSha256));
        for (UserEntry user : slot.users) {
            RawUser person = new RawUser();
            person.id = user.id;
            person.user = user.userId;
            person.serial = user.userSerial;
            Lifecycle lifecycle = user.lifecycle;
            person.state = lifecycle.state.ordinal() + 1;
            for (Suspension suspension : lifecycle.suspensions) {
                RawEntry entry = new RawEntry();
                entry.actor = suspension.actorClass.ordinal() + 1;
                entry.scope = suspension.scope;
                entry.user = suspension.actorUserId;
                entry.serial = suspension.actorSerial;
                entry.grant = suspension.grant;
                entry.reason = suspension.reason;
                entry.time = suspension.time;
                entry.noteTag = suspension.noteDigest == null ? 0 : 1;
                entry.note = suspension.noteDigest;
                person.entries.add(entry);
            }
            person.count = person.entries.size();
            Retirement retirement = lifecycle.retirement;
            if (retirement != null) {
                RawRetirement block = new RawRetirement();
                block.actor = retirement.actorClass.ordinal() + 1;
                block.user = retirement.actorUserId;
                block.serial = retirement.actorSerial;
                block.grant = retirement.grant;
                block.time = retirement.time;
                block.inventory = retirement.obligations.isEmpty() ? 0 : 1;
                for (Obligation obligation : retirement.obligations) {
                    RawDuty duty = new RawDuty();
                    duty.kind = obligation.kind.ordinal() + 1;
                    duty.state = obligation.state.ordinal() + 1;
                    duty.reference = obligation.reference;
                    duty.code = obligation.code;
                    duty.time = obligation.time;
                    block.duties.add(duty);
                }
                block.count = block.duties.size();
                person.retirement = block;
            }
            raw.users.add(person);
        }
        if (slot.ticket != null) {
            raw.ticket = true;
            raw.lastId = slot.ticket.lastId;
            raw.ticketUser = slot.ticket.userId;
            raw.ticketSerial = slot.ticket.userSerial;
            raw.ticketId = slot.ticket.ticketId;
        }
        return raw;
    }

    // The version 2 layout of raw fields: the stable prefix, the blocks, then the ticket if set.
    private static byte[] bytes(RawSlot raw) throws Exception {
        Raw out = new Raw().hex(raw.lineage).i32(raw.appId).i64(raw.generation).text(raw.pkg);
        out.u16(raw.signers.size());
        for (String signer : raw.signers) out.hex(signer);
        out.u16(raw.users.size());
        for (RawUser user : raw.users) out.i64(user.id).i32(user.user).i64(user.serial);
        for (RawUser user : raw.users) {
            out.u8(user.state).u8(user.count);
            for (RawEntry entry : user.entries) {
                out.u8(entry.actor).u8(entry.scope).i32(entry.user).i64(entry.serial).hex(entry.grant)
                        .u16(entry.reason).i64(entry.time).u8(entry.noteTag);
                if (entry.note != null) out.hex(entry.note);
            }
            RawRetirement block = user.retirement;
            if (block == null) continue;
            out.u8(block.actor).i32(block.user).i64(block.serial).hex(block.grant).i64(block.time)
                    .u8(block.inventory).u8(block.count);
            for (RawDuty duty : block.duties) {
                out.u8(duty.kind).u8(duty.state).hex(duty.reference).u8(duty.code).i64(duty.time);
            }
        }
        if (raw.ticket) out.i64(raw.lastId).i32(raw.ticketUser).i64(raw.ticketSerial).hex(raw.ticketId);
        out.bytes(raw.tail);
        return frame(raw.version, out.toBytes());
    }

    private static boolean refused(byte[] record) {
        try {
            NativeIdentityRecords.decodeSlot(record);
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }

    private static boolean invalid(Runnable action) {
        try {
            action.run();
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }

    private static boolean missing(Runnable action) {
        try {
            action.run();
            return false;
        } catch (NullPointerException expected) {
            return true;
        }
    }

    // One broken field of a valid golden: the valid twin decodes to its value, the broken record
    // is refused.
    private static void broken(List<String> problems, String what, Slot valid, Consumer<RawSlot> change)
            throws Exception {
        byte[] twin = bytes(raw(valid));
        if (!Arrays.equals(twin, NativeIdentityRecords.encodeSlot(valid))
                || !NativeIdentityRecords.decodeSlot(twin).equals(valid)) {
            problems.add("invalid twin for " + what);
            return;
        }
        RawSlot raw = raw(valid);
        change.accept(raw);
        check(problems, refused(bytes(raw)), "accepted " + what);
    }

    private static RawUser first(RawSlot raw) {
        return raw.users.get(0);
    }

    private static RawEntry copy(RawEntry entry) {
        RawEntry copy = new RawEntry();
        copy.actor = entry.actor;
        copy.scope = entry.scope;
        copy.user = entry.user;
        copy.serial = entry.serial;
        copy.grant = entry.grant;
        copy.reason = entry.reason;
        copy.time = entry.time;
        copy.noteTag = entry.noteTag;
        copy.note = entry.note;
        return copy;
    }

    // ------------------------------------------------------------------ cases

    private static void goldenCases(Path out) throws Exception {
        Map<String, Slot> goldens = goldens();
        Map<String, Object[]> pins = goldenPins();
        run("golden / version 1 values built from lifecycles keep their version 1 bytes", problems -> {
            Slot v1 = new Slot(LINEAGE, 10123, "a.b", 2, Set.of(HIGH, LOW), List.of(
                    new UserEntry(3, 0, 5, lifecycle(LifecycleState.ELIGIBLE, List.of(), null)),
                    new UserEntry(4, 10, 6, lifecycle(LifecycleState.RETIRING, List.of(), legacy()))));
            check(problems, v1.version == 1 && v1.equals(new Slot(LINEAGE, 10123, "a.b", 2, Set.of(HIGH, LOW),
                    List.of(new UserEntry(3, 0, 5, false), new UserEntry(4, 10, 6, true)))), "value");
            check(problems, Arrays.equals(NativeIdentityRecords.encodeSlot(v1), hex(V1_GOLDEN_SLOT)), "bytes");
            Slot tombstone = new Slot(LINEAGE, 19999, "dev.andrix.principal", 1, Set.of(LOW), List.of());
            check(problems, tombstone.version == 1 && tombstone.ticket == null
                    && Arrays.equals(NativeIdentityRecords.encodeSlot(tombstone), hex(V1_TOMBSTONE_SLOT)), "tombstone");
            check(problems, NativeIdentityRecords.decodeSlot(hex(V1_GOLDEN_SLOT)).equals(v1), "decode");
            Slot retiring = NativeIdentityRecords.decodeSlot(hex(V1_GOLDEN_SLOT));
            check(problems, retiring.users.get(1).retiring && retiring.users.get(1).lifecycle.retirement.actorClass
                    == ActorClass.LEGACY_MARKER && retiring.users.get(1).lifecycle.retirement.inventory == 0,
                    "a version 1 retiring flag decodes to the legacy marker");
        });
        for (String name : GOLDEN_ORDER) {
            run("golden / " + name.toLowerCase().replace('_', ' '), problems -> {
                Slot value = golden(name);
                byte[] encoded = NativeIdentityRecords.encodeSlot(value);
                Object[] pin = pins.get(name);
                check(problems, value.version == 2 && encoded[6] == 2 && encoded[7] == 0, "version");
                check(problems, encoded.length == (int) pin[0], "length " + encoded.length);
                check(problems, sha256Hex(encoded).equals(pin[1]), "SHA-256 " + sha256Hex(encoded));
                check(problems, Arrays.equals(bytes(raw(value)), encoded), "independent raw writer differs");
                check(problems, NativeIdentityRecords.encodedSlotLength(value) == encoded.length, "measured length");
                Slot decoded = NativeIdentityRecords.decodeSlot(encoded);
                check(problems, decoded != value && decoded.equals(value) && decoded.hashCode() == value.hashCode()
                        && Arrays.equals(NativeIdentityRecords.encodeSlot(decoded), encoded), "round trip");
                Files.write(out.resolve(name + ".bin"), encoded);
            });
        }
        run("golden / suspended layout written by hand", problems -> {
            byte[] layout = withChecksum(hex(SUSPENDED_LAYOUT));
            check(problems, layout.length == GOLDEN_SUSPENDED_BYTES, "hand layout length " + layout.length);
            check(problems, Arrays.equals(NativeIdentityRecords.encodeSlot(goldens.get("SUSPENDED")), layout),
                    "encoding differs from the hand layout");
            check(problems, NativeIdentityRecords.decodeSlot(layout).equals(goldens.get("SUSPENDED")), "decode");
        });
    }

    private static void versionCases() throws Exception {
        Map<String, Slot> goldens = goldens();
        run("version / each value has the version its lifecycle needs", problems -> {
            for (Slot slot : goldens.values()) check(problems, slot.version == 2, "not version 2: " + slot);
            Lifecycle eligible = lifecycle(LifecycleState.ELIGIBLE, List.of(), null);
            check(problems, eligible.isVersion1() && lifecycle(LifecycleState.RETIRING, List.of(), legacy()).isVersion1(),
                    "version 1 lifecycles");
            Slot plain = one(10123, "a.b", 1, Set.of(LOW), 1, 0, 0, eligible);
            check(problems, plain.version == 1 && NativeIdentityRecords.encodeSlot(plain)[6] == 1, "eligible");
            // One user beyond version 1 makes the whole slot version 2, its other users included.
            Slot mixed = goldens.get("TWO_USERS");
            check(problems, mixed.users.get(0).lifecycle.isVersion1() && mixed.version == 2, "mixed");
            check(problems, new Slot(LINEAGE, 10130, "a.b", 1, Set.of(LOW), List.of()).version == 1, "tombstone");
            check(problems, goldens.get("TICKET").version == 2, "ticketed tombstone");
            check(problems, !goldens.get("LEGACY_CONTINUED").users.get(0).lifecycle.isVersion1()
                    && !goldens.get("LEGACY_SUSPENDED").users.get(0).lifecycle.isVersion1(), "legacy variants");
            check(problems, goldens.get("RETIRED").users.get(0).retiring && goldens.get("RETIRING").users.get(0).retiring
                    && !goldens.get("SUSPENDED").users.get(0).retiring, "retiring follows the state");
        });
        run("one encoding / every version 1 value is refused in version 2", problems -> {
            List<Slot> values = List.of(
                    one(10123, "a.b", 1, Set.of(LOW), 1, 0, 0, Lifecycle.version1(false)),
                    one(10123, "a.b", 2, Set.of(LOW), 1, 0, 0, Lifecycle.version1(true)),
                    new Slot(LINEAGE, 10123, "a.b", 2, Set.of(HIGH, LOW), List.of(new UserEntry(3, 0, 5, false),
                            new UserEntry(4, 10, 6, true))),
                    new Slot(LINEAGE, 19999, LONGEST, Long.MAX_VALUE, Set.of(LOW), List.of(
                            new UserEntry(Long.MAX_VALUE, 0, 0, false), new UserEntry(1, 21474, Long.MAX_VALUE, true))));
            for (Slot value : values) {
                check(problems, value.version == 1, "fixture not version 1");
                check(problems, refused(bytes(raw(value))), "version 2 encoding of a version 1 value accepted");
            }
            // A tombstone without a ticket has no version 2 encoding at all.
            Slot tombstone = new Slot(LINEAGE, 10123, "a.b", 1, Set.of(LOW), List.of());
            check(problems, refused(bytes(raw(tombstone))), "ticketless version 2 tombstone accepted");
        });
        run("one encoding / confirming a legacy marker rewrites version 1 bytes", problems -> {
            Slot marker = NativeIdentityRecords.decodeSlot(NativeIdentityRecords.encodeSlot(
                    one(10123, "a.b", 2, Set.of(LOW), 1, 0, 7, Lifecycle.version1(true))));
            Slot rebuilt = one(10123, "a.b", 2, Set.of(LOW), 1, 0, 7, lifecycle(LifecycleState.RETIRING, List.of(),
                    new Retirement(ActorClass.LEGACY_MARKER, 0, 0, ZERO, 0, List.of())));
            check(problems, marker.equals(rebuilt) && rebuilt.version == 1, "legacy marker value");
            check(problems, NativeIdentityRecords.encodeSlot(rebuilt)[6] == 1, "legacy marker not version 1");
            Slot continued = one(10123, "a.b", 2, Set.of(LOW), 1, 0, 7, lifecycle(LifecycleState.RETIRING, List.of(),
                    new Retirement(ActorClass.LEGACY_MARKER, 0, 0, ZERO, 0,
                            inventory(NativeLifecycleCodecTest::outstanding))));
            check(problems, continued.version == 2, "a legacy continuation with its inventory is version 2");
        });
    }

    private static void sizeCases() throws Exception {
        Map<String, Slot> goldens = goldens();
        run("size / the largest record takes 60,941 bytes", problems -> {
            Slot largest = goldens.get("MAXIMUM");
            int fixed = 12 + 16 + 4 + 8 + 2 + 255 + 2 + 32 * 32 + 2 + CHECKSUM;
            int user = 20 + 2 + 6 * 73 + 39 + 16 * 27;
            check(problems, fixed == 1357 && user == 931 && fixed + 64 * user == 60941, "arithmetic");
            check(problems, NativeIdentityRecords.encodedSlotLength(largest) == 60941, "measured");
            check(problems, NativeIdentityRecords.encodeSlot(largest).length == 60941, "encoded");
            check(problems, 60941 < NativeIdentityRecords.MAX_BYTES, "bound");
            Slot one = one(10123, "a.b", 1, Set.of(LOW), 1, 0, 0, lifecycle(LifecycleState.ELIGIBLE, List.of(
                    entry(ActorClass.ACCOUNT_USER, 0, 0, 0, ZERO, 1, 0, null)), null));
            Slot noted = one(10123, "a.b", 1, Set.of(LOW), 1, 0, 0, lifecycle(LifecycleState.ELIGIBLE, List.of(
                    entry(ActorClass.ACCOUNT_USER, 0, 0, 0, ZERO, 1, 0, "00".repeat(32))), null));
            Slot bare = one(10123, "a.b", 1, Set.of(LOW), 1, 0, 0, lifecycle(LifecycleState.RETIRING, List.of(
                    entry(ActorClass.ACCOUNT_USER, 0, 0, 0, ZERO, 1, 0, null)), legacy()));
            int base = NativeIdentityRecords.encodedSlotLength(one) - 41;
            check(problems, NativeIdentityRecords.encodedSlotLength(noted) == base + 73, "noted entry");
            check(problems, NativeIdentityRecords.encodedSlotLength(bare) == base + 41 + 39, "unknown inventory");
        });
        run("size / the measure equals every encoding", problems -> {
            List<Slot> slots = new ArrayList<>(goldens.values());
            slots.add(NativeIdentityRecords.decodeSlot(hex(V1_GOLDEN_SLOT)));
            slots.add(NativeIdentityRecords.decodeSlot(hex(V1_TOMBSTONE_SLOT)));
            for (Slot slot : slots) {
                check(problems, NativeIdentityRecords.encodedSlotLength(slot)
                        == NativeIdentityRecords.encodeSlot(slot).length, "measure of " + slot.appId);
            }
            check(problems, missing(() -> NativeIdentityRecords.encodedSlotLength(null)), "null measured");
        });
    }

    private static void decoderCases() throws Exception {
        Map<String, Slot> goldens = goldens();
        Slot suspended = goldens.get("SUSPENDED"), holds = goldens.get("HOLDS");
        Slot retiring = goldens.get("RETIRING"), retired = goldens.get("RETIRED");
        Slot legacyHeld = goldens.get("LEGACY_SUSPENDED"), ticket = goldens.get("TICKET");
        run("decoder accepts / scope bit 0, unknown reasons, notes and any times", problems -> {
            for (int index = 0; index < 4; index++) {
                final int at = index;
                RawSlot raw = raw(holds);
                RawEntry entry = first(raw).entries.get(at);
                entry.scope |= 1;
                entry.reason = new int[] {0, 8, 0xffff, 1000}[at];
                entry.time = at % 2 == 0 ? Long.MIN_VALUE : Long.MAX_VALUE;
                Slot decoded = NativeIdentityRecords.decodeSlot(bytes(raw));
                Suspension kept = decoded.users.get(0).lifecycle.suspensions.get(at);
                check(problems, (kept.scope & NativeIdentityRecords.SCOPE_BLOCKS_DISPOSITION) != 0
                        && kept.reason == entry.reason && kept.time == entry.time, "entry " + at);
                check(problems, SuspensionReason.registered(kept.reason) == null, "unknown reason kept " + at);
                check(problems, Arrays.equals(NativeIdentityRecords.encodeSlot(decoded), bytes(raw)), "re-encoding");
            }
            RawSlot raw = raw(retired);
            RawDuty duty = first(raw).retirement.duties.get(15);
            duty.code = 255;
            duty.time = Long.MIN_VALUE;
            check(problems, NativeIdentityRecords.decodeSlot(bytes(raw)).users.get(0).lifecycle.retirement.obligations
                    .get(15).code == 255, "obligation code");
            Suspension noted = holds.users.get(0).lifecycle.suspensions.get(0);
            check(problems, noted.noteDigest.equals("ab".repeat(32)), "note digest kept");
        });
        run("decoder refuses / unknown lifecycle states", problems -> {
            for (int state : new int[] {0, 4, 0xff}) {
                broken(problems, "state " + state, suspended, raw -> first(raw).state = state);
            }
        });
        run("decoder refuses / more than six entries", problems -> {
            List<Suspension> six = new ArrayList<>();
            six.add(entry(ActorClass.ACCOUNT_USER, 0, 0, 5, ZERO, 1, 0, null));
            for (int grant = 1; grant <= 4; grant++) {
                six.add(entry(ActorClass.ADMIN_GRANT, 0, 0, 1, hex2(grant).repeat(16), 4, 0, null));
            }
            six.add(entry(ActorClass.RECOVERY_HOLD, 0, 0, 1, ZERO, 7, 0, null));
            Slot full = one(10123, "a.b", 1, Set.of(LOW), 3, 0, 5, lifecycle(LifecycleState.ELIGIBLE, six, null));
            broken(problems, "a seventh actor", full, raw -> {
                RawEntry extra = copy(first(raw).entries.get(4));
                extra.grant = hex2(5).repeat(16);
                first(raw).entries.add(5, extra);
                first(raw).count = 7;
            });
            broken(problems, "a count of 7 over six entries", full, raw -> first(raw).count = 7);
            broken(problems, "a count of 255", suspended, raw -> first(raw).count = 255);
        });
        run("decoder refuses / suspension classes outside entries", problems -> {
            for (int actor : new int[] {0, 4, 5, 6, 0xff}) {
                broken(problems, "entry class " + actor, suspended, raw -> first(raw).entries.get(0).actor = actor);
            }
        });
        run("decoder refuses / unknown scope bits and bit 1 outside a recovery hold", problems -> {
            for (int bit = 2; bit < 8; bit++) {
                final int scope = 1 << bit;
                broken(problems, "scope bit " + bit, suspended, raw -> first(raw).entries.get(0).scope = scope);
            }
            broken(problems, "bit 1 on the account's user", suspended, raw -> first(raw).entries.get(0).scope = 2);
            broken(problems, "bit 1 on a grant", holds, raw -> first(raw).entries.get(2).scope = 2);
            broken(problems, "bits 0 and 1 on a grant", holds, raw -> first(raw).entries.get(1).scope = 3);
        });
        run("decoder refuses / grants that are zero exactly for ADMIN_GRANT broken", problems -> {
            broken(problems, "a zero grant on ADMIN_GRANT", holds, raw -> first(raw).entries.get(1).grant = ZERO);
            broken(problems, "a grant on ACCOUNT_USER", suspended, raw -> first(raw).entries.get(0).grant = "01" + "0".repeat(30));
            broken(problems, "a grant on RECOVERY_HOLD", holds, raw -> first(raw).entries.get(3).grant = "ff".repeat(16));
        });
        run("decoder refuses / unknown note tags", problems -> {
            for (int tag : new int[] {2, 3, 0x80, 0xff}) {
                broken(problems, "note tag " + tag, suspended, raw -> first(raw).entries.get(0).noteTag = tag);
            }
            broken(problems, "note present without its digest", suspended, raw -> first(raw).entries.get(0).noteTag = 1);
            broken(problems, "note tag 2 before a digest", holds, raw -> first(raw).entries.get(0).noteTag = 2);
            broken(problems, "a digest without its tag", holds, raw -> first(raw).entries.get(0).noteTag = 0);
        });
        run("decoder refuses / entries out of order or two from one actor", problems -> {
            broken(problems, "grant entries out of actor serial order", holds, raw -> {
                List<RawEntry> entries = first(raw).entries;
                entries.add(1, entries.remove(2));
            });
            broken(problems, "the recovery hold first", holds, raw -> {
                List<RawEntry> entries = first(raw).entries;
                entries.add(0, entries.remove(3));
            });
            broken(problems, "two entries of the account's user", holds, raw -> {
                RawEntry again = copy(first(raw).entries.get(0));
                again.serial = 10;
                first(raw).entries.add(1, again);
                first(raw).count++;
            });
            broken(problems, "two recovery holds", holds, raw -> {
                RawEntry again = copy(first(raw).entries.get(3));
                again.serial = 2;
                first(raw).entries.add(again);
                first(raw).count++;
            });
            broken(problems, "one grant under two actors", holds, raw -> {
                RawEntry again = copy(first(raw).entries.get(1));
                again.serial = 4;
                first(raw).entries.add(3, again);
                first(raw).count++;
            });
            broken(problems, "an exact duplicate", holds, raw -> {
                first(raw).entries.add(2, copy(first(raw).entries.get(1)));
                first(raw).count++;
            });
        });
        run("decoder orders / entries by class, then actor serial, then grant", problems -> {
            // Serial order and grant order disagree, and the actor serial decides. With equal
            // serials the grant decides, and the class decides before both: the account's user
            // has the highest serial and the recovery hold the lowest.
            Suspension user = entry(ActorClass.ACCOUNT_USER, 0, 0, 9, ZERO, 1, 0, null);
            Suspension serialTwo = entry(ActorClass.ADMIN_GRANT, 0, 0, 2, "ff".repeat(16), 3, 0, null);
            Suspension serialThree = entry(ActorClass.ADMIN_GRANT, 0, 0, 3, "01".repeat(16), 3, 0, null);
            Suspension lowGrant = entry(ActorClass.ADMIN_GRANT, 0, 0, 5, "10".repeat(16), 4, 0, null);
            Suspension highGrant = entry(ActorClass.ADMIN_GRANT, 0, 0, 5, "20".repeat(16), 4, 0, null);
            Suspension hold = entry(ActorClass.RECOVERY_HOLD, 0, 0, 1, ZERO, 7, 0, null);
            List<Suspension> ordered = List.of(user, serialTwo, serialThree, lowGrant, highGrant, hold);
            Slot slot = one(10123, "a.b", 1, Set.of(LOW), 9, 0, 9,
                    lifecycle(LifecycleState.ELIGIBLE, ordered, null));
            byte[] encoded = NativeIdentityRecords.encodeSlot(slot);
            check(problems, Arrays.equals(bytes(raw(slot)), encoded), "entries not written in their order");
            check(problems, NativeIdentityRecords.decodeSlot(encoded).users.get(0).lifecycle.suspensions
                    .equals(ordered), "entries not decoded in their order");
            // Each neighbouring pair swapped is refused, as a value and as bytes.
            for (int i = 0; i + 1 < ordered.size(); i++) {
                List<Suspension> swapped = new ArrayList<>(ordered);
                Collections.swap(swapped, i, i + 1);
                check(problems, invalid(() -> lifecycle(LifecycleState.ELIGIBLE, swapped, null)),
                        "value accepted entries " + i + " and " + (i + 1) + " swapped");
                RawSlot raw = raw(slot);
                Collections.swap(first(raw).entries, i, i + 1);
                check(problems, refused(bytes(raw)), "decoder accepted entries " + i + " and " + (i + 1)
                        + " swapped");
            }
        });
        run("decoder refuses / negative actor users and serials", problems -> {
            broken(problems, "negative entry user", suspended, raw -> first(raw).entries.get(0).user = -1);
            broken(problems, "negative entry serial", suspended, raw -> first(raw).entries.get(0).serial = -1);
            broken(problems, "negative retirement user", retiring, raw -> first(raw).retirement.user = -1);
            broken(problems, "negative retirement serial", retiring, raw -> first(raw).retirement.serial = Long.MIN_VALUE);
        });
        run("decoder refuses / a retirement in ELIGIBLE or missing from RETIRING and RETIRED", problems -> {
            broken(problems, "ELIGIBLE with a retirement", suspended, raw -> first(raw).retirement = raw(retiring)
                    .users.get(0).retirement);
            broken(problems, "RETIRING without a retirement", retiring, raw -> first(raw).retirement = null);
            broken(problems, "RETIRED without a retirement", retired, raw -> first(raw).retirement = null);
            broken(problems, "RETIRING relabeled ELIGIBLE", retiring, raw -> first(raw).state = 1);
        });
        run("decoder refuses / retirement classes outside retirements", problems -> {
            for (int actor : new int[] {0, 3, 6, 0xff}) {
                broken(problems, "retirement class " + actor, retiring, raw -> first(raw).retirement.actor = actor);
            }
        });
        run("decoder refuses / a legacy marker with an actor, grant or time", problems -> {
            broken(problems, "legacy actor user", legacyHeld, raw -> first(raw).retirement.user = 1);
            broken(problems, "legacy actor serial", legacyHeld, raw -> first(raw).retirement.serial = 1);
            broken(problems, "legacy grant", legacyHeld, raw -> first(raw).retirement.grant = "01".repeat(16));
            broken(problems, "legacy time", legacyHeld, raw -> first(raw).retirement.time = 1);
            broken(problems, "a zero grant on an ADMIN_GRANT retirement", retired, raw -> first(raw).retirement.grant = ZERO);
            broken(problems, "a grant on an ACCOUNT_USER retirement", retiring,
                    raw -> first(raw).retirement.grant = "02".repeat(16));
        });
        run("decoder refuses / inventories other than every kind once or a legacy marker's none", problems -> {
            for (int inventory : new int[] {2, 0xff}) {
                broken(problems, "inventory " + inventory, retiring, raw -> first(raw).retirement.inventory = inventory);
            }
            broken(problems, "inventory 0 with 16 obligations", retiring, raw -> first(raw).retirement.inventory = 0);
            broken(problems, "inventory 1 without obligations", legacyHeld, raw -> first(raw).retirement.inventory = 1);
            broken(problems, "15 obligations", retiring, raw -> {
                first(raw).retirement.duties.remove(15);
                first(raw).retirement.count = 15;
            });
            broken(problems, "a count of 15 over 16 obligations", retiring, raw -> first(raw).retirement.count = 15);
            broken(problems, "17 obligations", retiring, raw -> {
                RawDuty extra = new RawDuty();
                extra.kind = 16;
                extra.state = 1;
                extra.reference = ZERO;
                first(raw).retirement.duties.add(extra);
                first(raw).retirement.count = 17;
            });
            broken(problems, "an unknown inventory by the account's user", retiring, raw -> {
                first(raw).retirement.inventory = 0;
                first(raw).retirement.count = 0;
                first(raw).retirement.duties.clear();
            });
        });
        run("decoder refuses / an unknown inventory outside RETIRING", problems -> {
            broken(problems, "RETIRED with an unknown inventory", legacyHeld, raw -> first(raw).state = 3);
            Slot plainLegacy = one(10123, "a.b", 2, Set.of(LOW), 1, 0, 7, lifecycle(LifecycleState.RETIRING,
                    List.of(entry(ActorClass.ACCOUNT_USER, 0, 0, 7, ZERO, 1, 0, null)), legacy()));
            broken(problems, "RETIRED legacy marker", plainLegacy, raw -> first(raw).state = 3);
        });
        run("decoder refuses / obligations out of kind order or of unknown kinds and states", problems -> {
            broken(problems, "two kinds swapped", retiring, raw -> {
                List<RawDuty> duties = first(raw).retirement.duties;
                duties.add(0, duties.remove(1));
            });
            broken(problems, "a kind twice", retiring, raw -> first(raw).retirement.duties.get(1).kind = 1);
            for (int kind : new int[] {0, 17, 0xff}) {
                broken(problems, "kind " + kind, retiring, raw -> first(raw).retirement.duties.get(15).kind = kind);
            }
            for (int state : new int[] {0, 5, 0xff}) {
                broken(problems, "obligation state " + state, retiring,
                        raw -> first(raw).retirement.duties.get(4).state = state);
            }
        });
        run("decoder refuses / DISPOSING on a retirement kind or outside RETIRED", problems -> {
            for (int kind = 1; kind <= 9; kind++) {
                final int at = kind - 1;
                broken(problems, "DISPOSING kind " + kind, retired, raw -> first(raw).retirement.duties.get(at).state = 2);
            }
            for (int kind = 10; kind <= 16; kind++) {
                final int at = kind - 1;
                broken(problems, "DISPOSING kind " + kind + " in RETIRING", retiring,
                        raw -> first(raw).retirement.duties.get(at).state = 2);
            }
        });
        run("decoder refuses / RETIRED with a retirement kind not DISCHARGED", problems -> {
            for (int kind = 1; kind <= 9; kind++) {
                final int at = kind - 1;
                for (int state : new int[] {1, 4}) {
                    broken(problems, "kind " + kind + " state " + state, retired,
                            raw -> first(raw).retirement.duties.get(at).state = state);
                }
            }
            // A disposition kind may stay outstanding, and a retirement kind discharged in RETIRING.
            RawSlot raw = raw(retired);
            first(raw).retirement.duties.get(10).state = 1;
            check(problems, !refused(bytes(raw)), "an outstanding disposition kind refused");
        });
        run("decoder refuses / ticket fields out of bounds", problems -> {
            broken(problems, "ticket principal 0", ticket, raw -> raw.lastId = 0);
            broken(problems, "negative ticket principal", ticket, raw -> raw.lastId = Long.MIN_VALUE);
            broken(problems, "negative ticket user", ticket, raw -> raw.ticketUser = -1);
            broken(problems, "negative ticket serial", ticket, raw -> raw.ticketSerial = -1);
            broken(problems, "zero ticket ID", ticket, raw -> raw.ticketId = ZERO);
        });
        run("decoder refuses / a tombstone without its ticket, a ticket beside users and trailing bytes", problems -> {
            broken(problems, "a tombstone without its ticket", ticket, raw -> raw.ticket = false);
            broken(problems, "a ticket beside a user", suspended, raw -> {
                raw.ticket = true;
                raw.lastId = 3;
                raw.ticketId = "55".repeat(16);
            });
            broken(problems, "a trailing byte", suspended, raw -> raw.tail = new byte[] {0});
            broken(problems, "a trailing byte after a ticket", ticket, raw -> raw.tail = new byte[] {0});
            broken(problems, "a truncated ticket", ticket, raw -> raw.ticketId = "55".repeat(15));
            byte[] encoded = NativeIdentityRecords.encodeSlot(ticket);
            check(problems, refused(withChecksum(Arrays.copyOf(encoded, encoded.length - CHECKSUM - 1))),
                    "unframed truncation accepted");
        });
    }

    private static void valueCases() throws Exception {
        Map<String, Slot> goldens = goldens();
        run("values / the constructors enforce the same rules", problems -> {
            check(problems, invalid(() -> entry(ActorClass.USER_REMOVAL, 0, 0, 0, ZERO, 1, 0, null)), "removal entry");
            check(problems, invalid(() -> entry(ActorClass.LEGACY_MARKER, 0, 0, 0, ZERO, 1, 0, null)), "legacy entry");
            check(problems, invalid(() -> entry(ActorClass.ACCOUNT_USER, 4, 0, 0, ZERO, 1, 0, null)), "scope bit 2");
            check(problems, invalid(() -> entry(ActorClass.ACCOUNT_USER, 2, 0, 0, ZERO, 1, 0, null)), "bit 1 user");
            check(problems, !invalid(() -> entry(ActorClass.RECOVERY_HOLD, 3, 0, 0, ZERO, 1, 0, null)), "bits on hold");
            check(problems, !invalid(() -> entry(ActorClass.ACCOUNT_USER, 1, 0, 0, ZERO, 1, 0, null)), "bit 0 decodes");
            check(problems, invalid(() -> entry(ActorClass.ADMIN_GRANT, 0, 0, 0, ZERO, 1, 0, null)), "zero grant");
            check(problems, invalid(() -> entry(ActorClass.ACCOUNT_USER, 0, 0, 0, "1".repeat(32), 1, 0, null)), "grant");
            check(problems, invalid(() -> entry(ActorClass.ACCOUNT_USER, 0, -1, 0, ZERO, 1, 0, null)), "actor user");
            check(problems, invalid(() -> entry(ActorClass.ACCOUNT_USER, 0, 0, -1, ZERO, 1, 0, null)), "actor serial");
            check(problems, invalid(() -> entry(ActorClass.ACCOUNT_USER, 0, 0, 0, ZERO, -1, 0, null)), "reason -1");
            check(problems, invalid(() -> entry(ActorClass.ACCOUNT_USER, 0, 0, 0, ZERO, 0x10000, 0, null)), "reason");
            check(problems, invalid(() -> entry(ActorClass.ACCOUNT_USER, 0, 0, 0, ZERO, 1, 0, "AB".repeat(32))), "note");
            check(problems, invalid(() -> entry(ActorClass.ACCOUNT_USER, 0, 0, 0, "0".repeat(31), 1, 0, null)), "hex");
            check(problems, missing(() -> entry(null, 0, 0, 0, ZERO, 1, 0, null)), "null class");
            check(problems, missing(() -> entry(ActorClass.ACCOUNT_USER, 0, 0, 0, null, 1, 0, null)), "null grant");
            check(problems, invalid(() -> new Obligation(ObligationKind.WORK, ObligationState.DISPOSING, ZERO, 0, 0)),
                    "DISPOSING retirement kind");
            check(problems, invalid(() -> new Obligation(ObligationKind.HOME, ObligationState.OUTSTANDING, ZERO, 256, 0)),
                    "obligation code");
            check(problems, missing(() -> new Obligation(null, ObligationState.OUTSTANDING, ZERO, 0, 0)), "null kind");
            List<Obligation> all = inventory(NativeLifecycleCodecTest::outstanding);
            check(problems, invalid(() -> new Retirement(ActorClass.RECOVERY_HOLD, 0, 0, ZERO, 0, all)), "hold retires");
            check(problems, invalid(() -> new Retirement(ActorClass.ACCOUNT_USER, 0, 0, ZERO, 0, List.of())),
                    "unknown inventory by the user");
            check(problems, invalid(() -> new Retirement(ActorClass.LEGACY_MARKER, 0, 1, ZERO, 0, List.of())), "legacy");
            check(problems, invalid(() -> new Retirement(ActorClass.ACCOUNT_USER, 0, 0, ZERO, 0, all.subList(0, 15))),
                    "15 kinds");
            List<Obligation> swapped = new ArrayList<>(all);
            swapped.add(0, swapped.remove(1));
            check(problems, invalid(() -> new Retirement(ActorClass.ACCOUNT_USER, 0, 0, ZERO, 0, swapped)), "order");
            Retirement known = new Retirement(ActorClass.ACCOUNT_USER, 0, 0, ZERO, 0, all);
            check(problems, invalid(() -> lifecycle(LifecycleState.ELIGIBLE, List.of(), known)), "ELIGIBLE retirement");
            check(problems, invalid(() -> lifecycle(LifecycleState.RETIRED, List.of(), null)), "RETIRED without");
            check(problems, invalid(() -> lifecycle(LifecycleState.RETIRED, List.of(), known)), "RETIRED outstanding");
            check(problems, invalid(() -> lifecycle(LifecycleState.RETIRED, List.of(), legacy())), "RETIRED unknown");
            Suspension user = entry(ActorClass.ACCOUNT_USER, 0, 0, 0, ZERO, 1, 0, null);
            Suspension hold = entry(ActorClass.RECOVERY_HOLD, 0, 0, 0, ZERO, 7, 0, null);
            check(problems, invalid(() -> lifecycle(LifecycleState.ELIGIBLE, List.of(hold, user), null)), "order");
            check(problems, invalid(() -> lifecycle(LifecycleState.ELIGIBLE, List.of(user, user), null)), "twice");
            check(problems, missing(() -> lifecycle(null, List.of(), null)), "null state");
            check(problems, missing(() -> lifecycle(LifecycleState.ELIGIBLE, Arrays.asList(user, null), null)),
                    "null entry");
            check(problems, invalid(() -> new ReleaseTicket(0, 0, 0, "01".repeat(16))), "ticket principal");
            check(problems, invalid(() -> new ReleaseTicket(1, -1, 0, "01".repeat(16))), "ticket user");
            check(problems, invalid(() -> new ReleaseTicket(1, 0, -1, "01".repeat(16))), "ticket serial");
            check(problems, invalid(() -> new ReleaseTicket(1, 0, 0, ZERO)), "zero ticket");
            check(problems, missing(() -> new ReleaseTicket(1, 0, 0, null)), "null ticket");
            ReleaseTicket ticket = new ReleaseTicket(1, 0, 0, "01".repeat(16));
            check(problems, invalid(() -> new Slot(LINEAGE, 10123, "a.b", 1, Set.of(LOW),
                    List.of(new UserEntry(1, 0, 0, false)), ticket)), "ticket beside a user");
            Lifecycle none = null;
            check(problems, missing(() -> new UserEntry(1, 0, 0, none)), "null lifecycle");
            // Lists are copied and unmodifiable.
            Slot holds = goldens.get("HOLDS");
            List<Suspension> entries = holds.users.get(0).lifecycle.suspensions;
            boolean immutable;
            try {
                entries.clear();
                immutable = false;
            } catch (UnsupportedOperationException expected) {
                immutable = true;
            }
            check(problems, immutable, "suspension entries changeable");
            List<Suspension> source = new ArrayList<>(List.of(user));
            Lifecycle copied = lifecycle(LifecycleState.ELIGIBLE, source, null);
            source.add(hold);
            check(problems, copied.suspensions.size() == 1, "entries not copied");
        });
        run("ticket / bounds round trip", problems -> {
            long[][] cases = {{1, 0, 0}, {Long.MAX_VALUE, Integer.MAX_VALUE, Long.MAX_VALUE}, {1, 21475, 0}};
            for (long[] bound : cases) {
                for (String id : List.of("0".repeat(31) + "1", "ff".repeat(16), "80" + "0".repeat(30))) {
                    Slot slot = new Slot(LINEAGE, 19999, "a.b", 1, Set.of(LOW), List.of(),
                            new ReleaseTicket(bound[0], (int) bound[1], bound[2], id));
                    byte[] encoded = NativeIdentityRecords.encodeSlot(slot);
                    check(problems, slot.version == 2 && NativeIdentityRecords.decodeSlot(encoded).equals(slot)
                            && encoded.length == GOLDEN_TICKET_BYTES - "dev.andrix.released".length() + 3,
                            "ticket " + Arrays.toString(bound) + " " + id);
                }
            }
        });
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
                    bytes = concat(Arrays.copyOf(bytes, at), new byte[] {(byte) random.nextInt(256)},
                            Arrays.copyOfRange(bytes, at, bytes.length));
                    break;
                default:
                    bytes = concat(Arrays.copyOf(bytes, at), Arrays.copyOfRange(bytes, at + 1, bytes.length));
                    break;
            }
        }
        return bytes;
    }

    // Random changes of the body, resealed. Each result is refused or is exactly the one encoding
    // of the value it decodes to, so no value has two encodings. A fixed seed repeats the inputs.
    private static void mutationCases() throws Exception {
        Map<String, Slot> goldens = goldens();
        run("mutation / resealed version 2 mutations are refused or canonical", problems -> {
            List<byte[]> bodies = new ArrayList<>();
            for (String name : List.of("SUSPENDED", "HOLDS", "RETIRING", "RETIRED", "LEGACY_SUSPENDED", "TWO_USERS",
                    "TICKET")) {
                bodies.add(body(NativeIdentityRecords.encodeSlot(goldens.get(name))));
            }
            Random random = new Random(20261008L);
            int accepted = 0, refused = 0, version1 = 0;
            for (int round = 0; round < 35_000; round++) {
                byte[] candidate = frame(2, mutate(bodies.get(round % bodies.size()).clone(), random));
                try {
                    Slot decoded = NativeIdentityRecords.decodeSlot(candidate);
                    if (!Arrays.equals(NativeIdentityRecords.encodeSlot(decoded), candidate)) {
                        problems.add("second encoding in round " + round);
                    }
                    if (decoded.version != 2) ++version1;
                    ++accepted;
                } catch (IllegalArgumentException expected) {
                    ++refused;
                }
            }
            check(problems, accepted > 1_000 && refused > 1_000, accepted + " accepted, " + refused + " refused");
            check(problems, version1 == 0, version1 + " version 1 values accepted in version 2");
            System.out.println("Resealed lifecycle mutations: " + accepted + " canonical, " + refused + " refused");
        });
    }

    private static void prefixCases() throws Exception {
        Map<String, Slot> goldens = goldens();
        byte[] two = NativeIdentityRecords.encodeSlot(goldens.get("TWO_USERS"));
        byte[] v1 = NativeIdentityRecords.encodeSlot(new Slot(LINEAGE, 10123, "a.b", 1, Set.of(LOW),
                List.of(new UserEntry(9, 0, 7, true))));
        run("prefix / later versions give their package and principals", problems -> {
            for (int version : new int[] {3, 4, 0x7fff, 0xffff}) {
                SlotPrefix prefix = NativeIdentityRecords.decodeSlotPrefix(relabeled(two, version));
                check(problems, prefix.version == version && prefix.packageName.equals("dev.andrix.shared")
                        && prefix.principalIds.equals(List.of(15L, 16L)), "version " + version + " " + prefix);
                check(problems, refused(relabeled(two, version)), "a later version decoded in full");
            }
            // A one user version 1 body has the same leading fields: its prefix is valid too.
            SlotPrefix old = NativeIdentityRecords.decodeSlotPrefix(relabeled(v1, 3));
            check(problems, old.packageName.equals("a.b") && old.principalIds.equals(List.of(9L)), "relabeled body");
            SlotPrefix tombstone = NativeIdentityRecords.decodeSlotPrefix(relabeled(
                    NativeIdentityRecords.encodeSlot(goldens.get("TICKET")), 3));
            check(problems, tombstone.principalIds.isEmpty()
                    && tombstone.packageName.equals("dev.andrix.released"), "tombstone prefix");
            SlotPrefix largest = NativeIdentityRecords.decodeSlotPrefix(relabeled(
                    NativeIdentityRecords.encodeSlot(goldens.get("MAXIMUM")), 3));
            check(problems, largest.principalIds.size() == 64 && largest.packageName.equals(LONGEST), "largest");
        });
        run("prefix / nothing after the prefix is read", problems -> {
            int prefixEnd = 16 + 4 + 8 + 2 + "dev.andrix.shared".length() + 2 + 2 * 32 + 2 + 2 * 20;
            byte[] cut = Arrays.copyOf(body(two), prefixEnd);
            for (byte[] tail : List.of(new byte[0], new byte[] {(byte) 0xff}, new byte[60000],
                    "any later layout".getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
                SlotPrefix prefix = NativeIdentityRecords.decodeSlotPrefix(frame(3, concat(cut, tail)));
                check(problems, prefix.principalIds.equals(List.of(15L, 16L)), "tail of " + tail.length);
            }
            check(problems, failsPrefix(frame(3, Arrays.copyOf(cut, prefixEnd - 1))), "a cut prefix accepted");
        });
        run("prefix / version 1 and 2 frames give no prefix", problems -> {
            check(problems, failsPrefix(two), "version 2");
            check(problems, failsPrefix(v1), "version 1");
            check(problems, failsPrefix(relabeled(two, 1)) && failsPrefix(relabeled(v1, 2))
                    && failsPrefix(relabeled(two, 0)), "relabeled");
        });
        run("prefix / damaged frames give no prefix", problems -> {
            byte[] later = relabeled(two, 3);
            byte[] bad = later.clone();
            bad[bad.length - 1] ^= 1;
            byte[] header = later.clone();
            header[4] = 1;
            byte[] magic = later.clone();
            magic[0] ^= 1;
            check(problems, failsPrefix(bad) && failsPrefix(withChecksum(Arrays.copyOf(header, header.length - CHECKSUM)))
                    && failsPrefix(withChecksum(Arrays.copyOf(magic, magic.length - CHECKSUM)))
                    && failsPrefix(Arrays.copyOf(later, later.length - 1))
                    && failsPrefix(concat(later, new byte[1])) && failsPrefix(new byte[44])
                    && failsPrefix(frame(3, new byte[NativeIdentityRecords.MAX_BYTES - 43])), "damage");
            check(problems, missing(() -> NativeIdentityRecords.decodeSlotPrefix(null)), "null");
            byte[] input = later.clone();
            NativeIdentityRecords.decodeSlotPrefix(input);
            check(problems, Arrays.equals(input, later), "input changed");
        });
        run("prefix / each frozen bound and rule refuses", problems -> {
            Map<String, RawSlot> cases = new LinkedHashMap<>();
            RawSlot raw = raw(goldens.get("TWO_USERS"));
            raw.version = 3;
            check(problems, !failsPrefix(bytes(raw)), "valid control");
            cases.put("app ID 9999", prefix(raw, r -> r.appId = 9999));
            cases.put("app ID 20000", prefix(raw, r -> r.appId = 20000));
            cases.put("generation 0", prefix(raw, r -> r.generation = 0));
            cases.put("negative generation", prefix(raw, r -> r.generation = -1));
            cases.put("one segment package", prefix(raw, r -> r.pkg = "shared"));
            cases.put("package grammar", prefix(raw, r -> r.pkg = "dev.andrix.1shared"));
            cases.put("256 character package", prefix(raw, r -> r.pkg = LONGEST + "b"));
            cases.put("no signers", prefix(raw, r -> r.signers = List.of()));
            cases.put("33 signers", prefix(raw, r -> {
                List<String> signers = new ArrayList<>();
                for (int i = 0; i < 33; i++) signers.add(hex2(i).repeat(32));
                r.signers = signers;
            }));
            cases.put("descending signers", prefix(raw, r -> r.signers = List.of(HIGH, LOW)));
            cases.put("65 users", prefix(raw, r -> {
                r.users.clear();
                for (int i = 0; i < 65; i++) {
                    RawUser user = new RawUser();
                    user.id = i + 1;
                    user.user = i;
                    r.users.add(user);
                }
            }));
            cases.put("principal 0", prefix(raw, r -> r.users.get(0).id = 0));
            cases.put("negative user", prefix(raw, r -> r.users.get(0).user = -1));
            cases.put("negative serial", prefix(raw, r -> r.users.get(1).serial = -1));
            cases.put("users out of order", prefix(raw, r -> r.users.get(1).user = 0));
            cases.put("duplicate principal", prefix(raw, r -> r.users.get(1).id = 15));
            cases.put("UID above the int range", prefix(raw, r -> {
                r.appId = 19999;
                r.users.get(1).user = 21475;
            }));
            for (Map.Entry<String, RawSlot> entry : cases.entrySet()) {
                check(problems, failsPrefix(prefixBytes(entry.getValue())), "accepted " + entry.getKey());
            }
            // 64 users and 32 signers are the bounds themselves.
            check(problems, !failsPrefix(relabeled(NativeIdentityRecords.encodeSlot(goldens.get("MAXIMUM")), 4)),
                    "the bounds refused");
        });
        run("prefix / the evidence carries no lifecycle", problems -> {
            Class<?> type = SlotPrefix.class;
            check(problems, !Modifier.isPublic(type.getModifiers()) && Modifier.isFinal(type.getModifiers()),
                    "prefix value is public");
            Set<String> fields = new TreeSet<>();
            for (Field field : type.getDeclaredFields()) {
                fields.add(field.getName());
                check(problems, Modifier.isFinal(field.getModifiers()), "mutable field " + field.getName());
            }
            check(problems, fields.equals(Set.of("version", "packageName", "principalIds")), "fields " + fields);
            check(problems, type.getDeclaredConstructors().length == 1
                    && Modifier.isPrivate(type.getDeclaredConstructors()[0].getModifiers()), "constructible");
            Method reader = NativeIdentityRecords.class.getDeclaredMethod("decodeSlotPrefix", byte[].class);
            check(problems, !Modifier.isPublic(reader.getModifiers()) && reader.getReturnType() == SlotPrefix.class,
                    "reader is public or returns a value");
            SlotPrefix prefix = NativeIdentityRecords.decodeSlotPrefix(relabeled(two, 3));
            boolean immutable;
            try {
                prefix.principalIds.add(1L);
                immutable = false;
            } catch (UnsupportedOperationException expected) {
                immutable = true;
            }
            check(problems, immutable, "principal IDs changeable");
        });
    }

    private interface Change { void apply(RawSlot raw); }

    // A later version's prefix with one rule broken. Only the prefix is written: a later version's
    // body after it is unknown.
    private static RawSlot prefix(RawSlot base, Change change) {
        RawSlot raw = new RawSlot();
        raw.version = base.version;
        raw.lineage = base.lineage;
        raw.appId = base.appId;
        raw.generation = base.generation;
        raw.pkg = base.pkg;
        raw.signers = new ArrayList<>(base.signers);
        for (RawUser user : base.users) {
            RawUser copy = new RawUser();
            copy.id = user.id;
            copy.user = user.user;
            copy.serial = user.serial;
            raw.users.add(copy);
        }
        change.apply(raw);
        return raw;
    }

    private static byte[] prefixBytes(RawSlot raw) throws Exception {
        Raw out = new Raw().hex(raw.lineage).i32(raw.appId).i64(raw.generation).text(raw.pkg);
        out.u16(raw.signers.size());
        for (String signer : raw.signers) out.hex(signer);
        out.u16(raw.users.size());
        for (RawUser user : raw.users) out.i64(user.id).i32(user.user).i64(user.serial);
        out.bytes("later fields".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        return frame(raw.version, out.toBytes());
    }

    private static boolean failsPrefix(byte[] record) {
        try {
            NativeIdentityRecords.decodeSlotPrefix(record);
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }

    private static void registryCases() throws Exception {
        run("reasons / a registry of specific codes without a catch-all", problems -> {
            Set<ActorClass> suspending = Set.of(ActorClass.ACCOUNT_USER, ActorClass.ADMIN_GRANT,
                    ActorClass.RECOVERY_HOLD);
            Set<ActorClass> userOrGrant = Set.of(ActorClass.ACCOUNT_USER, ActorClass.ADMIN_GRANT);
            Map<SuspensionReason, Set<ActorClass>> expected = new LinkedHashMap<>();
            expected.put(SuspensionReason.USER_PAUSED, Set.of(ActorClass.ACCOUNT_USER));
            expected.put(SuspensionReason.CREDENTIAL_EXPOSED, userOrGrant);
            expected.put(SuspensionReason.SUSPECTED_COMPROMISE, userOrGrant);
            expected.put(SuspensionReason.RESOURCE_OVERUSE, userOrGrant);
            expected.put(SuspensionReason.DEVICE_HANDOVER, userOrGrant);
            expected.put(SuspensionReason.DATA_TRANSFER, userOrGrant);
            expected.put(SuspensionReason.RECOVERY_REVIEW, Set.of(ActorClass.RECOVERY_HOLD));
            check(problems, Arrays.asList(SuspensionReason.values()).equals(new ArrayList<>(expected.keySet())),
                    "registry " + Arrays.toString(SuspensionReason.values()));
            Set<Integer> codes = new TreeSet<>();
            Set<ActorClass> served = new HashSet<>();
            for (SuspensionReason reason : SuspensionReason.values()) {
                check(problems, codes.add(reason.code) && reason.code == reason.ordinal() + 1, "code of " + reason);
                check(problems, SuspensionReason.registered(reason.code) == reason, "lookup of " + reason);
                for (String vague : List.of("OTHER", "UNKNOWN", "GENERIC", "MISC", "UNSPECIFIED", "DEFAULT", "NONE")) {
                    check(problems, !reason.name().contains(vague), "catch-all " + reason);
                }
                check(problems, reason.actors.equals(expected.get(reason)), "actors of " + reason + " " + reason.actors);
                check(problems, suspending.containsAll(reason.actors), "a retirement class for " + reason);
                served.addAll(reason.actors);
                boolean immutable;
                try {
                    reason.actors.clear();
                    immutable = false;
                } catch (UnsupportedOperationException expectedRefusal) {
                    immutable = true;
                }
                check(problems, immutable, "actor classes of " + reason + " changeable");
            }
            check(problems, codes.equals(Set.of(1, 2, 3, 4, 5, 6, 7)), "codes " + codes);
            check(problems, served.equals(suspending), "a suspension class without a reason: " + served);
            for (int code : new int[] {0, 8, 999, 0xffff}) {
                check(problems, SuspensionReason.registered(code) == null, "unregistered " + code);
            }
            // Informational: an unregistered code, and a code its actor may not use, are valid values
            // kept as they are. Only the writers enforce the registry.
            check(problems, entry(ActorClass.ACCOUNT_USER, 0, 0, 0, ZERO, 999, 0, null).reason == 999, "kept");
            check(problems, entry(ActorClass.ADMIN_GRANT, 0, 0, 0, "01".repeat(16), 1, 0, null).reason == 1,
                    "a user only code refused in a value");
        });
        run("surface / lifecycle values are closed and print no references", problems -> {
            for (Class<?> type : List.of(Suspension.class, Obligation.class, Retirement.class, Lifecycle.class,
                    ReleaseTicket.class)) {
                check(problems, Modifier.isPublic(type.getModifiers()) && Modifier.isFinal(type.getModifiers())
                        && type.getConstructors().length == 1, "shape of " + type.getSimpleName());
                for (Field field : type.getDeclaredFields()) {
                    int modifiers = field.getModifiers();
                    check(problems, Modifier.isFinal(modifiers) && (Modifier.isPublic(modifiers)
                            || Modifier.isStatic(modifiers)), "field " + field);
                }
                for (Method method : type.getDeclaredMethods()) {
                    check(problems, !Modifier.isPublic(method.getModifiers())
                            || Set.of("equals", "hashCode", "toString").contains(method.getName()), "method " + method);
                }
            }
            Method measure = NativeIdentityRecords.class.getDeclaredMethod("encodedSlotLength", Slot.class);
            check(problems, !Modifier.isPublic(measure.getModifiers()), "public measure");
            Map<String, Slot> goldens = goldens();
            StringBuilder text = new StringBuilder();
            for (Slot slot : goldens.values()) text.append(slot);
            for (String secret : List.of("11".repeat(16), "33".repeat(16), "55".repeat(16), "ab".repeat(32),
                    "cd".repeat(32), "0a".repeat(16), LINEAGE, LOW, HIGH)) {
                check(problems, !text.toString().contains(secret), "printed " + secret.substring(0, 8));
            }
            check(problems, text.toString().contains("RETIRED") && text.toString().contains("ACCOUNT_USER")
                    && text.toString().contains("note"), "states and classes print");
        });
    }

    public static void main(String[] args) throws Exception {
        if (!NativeLifecycleCodecTest.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        if (args.length != 1) throw new IllegalArgumentException("a fresh golden directory is required");
        Path out = Path.of(args[0]);
        if (!Files.isDirectory(out, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("golden directory");
        try (var listing = Files.list(out)) {
            if (listing.findAny().isPresent()) throw new IllegalArgumentException("golden directory not fresh");
        }
        goldenCases(out);
        versionCases();
        sizeCases();
        decoderCases();
        valueCases();
        mutationCases();
        prefixCases();
        registryCases();
        System.out.println(passed + " passed, " + failures.size() + " failed");
        if (!failures.isEmpty()) throw new AssertionError("failed: " + failures);
        System.out.println("Lifecycle record codec and stable prefix checks passed; host JVM only, store I/O,"
                + " PMS integration and Android unqualified");
    }
}
