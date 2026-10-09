// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import com.android.server.pm.NativeIdentityRecords.ActorClass;
import com.android.server.pm.NativeIdentityRecords.CreationBinding;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.HeaderEntry;
import com.android.server.pm.NativeIdentityRecords.Lifecycle;
import com.android.server.pm.NativeIdentityRecords.LifecycleState;
import com.android.server.pm.NativeIdentityRecords.Obligation;
import com.android.server.pm.NativeIdentityRecords.ObligationKind;
import com.android.server.pm.NativeIdentityRecords.ObligationState;
import com.android.server.pm.NativeIdentityRecords.Retirement;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.SlotPhase;
import com.android.server.pm.NativeIdentityRecords.Suspension;
import com.android.server.pm.NativeIdentityRecords.SuspensionReason;
import com.android.server.pm.NativeIdentityRecords.UserEntry;
import com.android.server.pm.NativeIdentityStore.Format;
import com.android.server.pm.NativeIdentityStore.ReadResult;
import com.android.server.pm.NativeIdentityStore.Status;
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
 * Shared host fixtures of the lifecycle store, transaction and fault tests: lifecycle values,
 * direct store layouts, exact file footprints and the case runner. A layout is written through
 * the codec directly, as durable state that a writer, an earlier image or a later one may leave,
 * never through the writers under test. Fixtures are aged, so any later write, rename or unlink
 * shows in the footprint. Host files only, not Android persistence.
 */
final class NativeLifecycleTestSupport {
    static final String LINEAGE = "e".repeat(32);
    static final Set<String> SIGNERS = Set.of("f".repeat(64));
    static final Set<String> OTHER_SIGNERS = Set.of("a".repeat(64));
    static final String ZERO = NativeIdentityRecords.NO_REFERENCE;
    static final int A = 10200, B = 10201;
    static final String PKG_A = "dev.andrix.lifecyclea", PKG_B = "dev.andrix.lifecycleb";
    static final long ID_A = 1, ID_B = 2, SERIAL = 7, TIME = 1_700_000_000_000L;
    static final NativePrincipalPins.Record RECORD_A = new NativePrincipalPins.Record(ID_A, PKG_A, A, 0, SERIAL);
    static final Format V1 = Format.V1, V2 = Format.V2, V3 = Format.V3;
    static final List<Format> EARLIER = List.of(Format.V1, Format.V2);
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

    // ------------------------------------------------------------------ values

    static String grant(int value) {
        return String.format("%032x", value);
    }

    static Suspension entry(ActorClass actorClass, int scope, int actorUser, long actorSerial, String grant,
            SuspensionReason reason, long time) {
        return new Suspension(actorClass, scope, actorUser, actorSerial, grant, reason.code, time, null);
    }

    /** The account user's own entry. */
    static Suspension byUser(SuspensionReason reason) {
        return entry(ActorClass.ACCOUNT_USER, 0, 0, SERIAL, ZERO, reason, TIME);
    }

    /** A grant's entry, placed by Android user 0 with serial 7. */
    static Suspension byGrant(int grant, SuspensionReason reason) {
        return entry(ActorClass.ADMIN_GRANT, 0, 0, SERIAL, grant(grant), reason, TIME + grant);
    }

    /** A recovery hold, which only the recovery route writes. */
    static Suspension hold(int scope) {
        return entry(ActorClass.RECOVERY_HOLD, scope, 0, SERIAL, ZERO, SuspensionReason.RECOVERY_REVIEW, TIME);
    }

    static Obligation obligation(ObligationKind kind, ObligationState state, String reference, int code,
            long time) {
        return new Obligation(kind, state, reference, code, time);
    }

    /** This design's inventory as a retirement starts it: every kind outstanding and unbound. */
    static List<Obligation> outstanding() {
        List<Obligation> list = new ArrayList<>();
        for (ObligationKind kind : ObligationKind.values()) {
            list.add(obligation(kind, ObligationState.OUTSTANDING, ZERO, 0, 0));
        }
        return list;
    }

    static Retirement retirement(ActorClass actorClass, int actorUser, long actorSerial, String grant, long time) {
        return new Retirement(actorClass, actorUser, actorSerial, grant, time, outstanding());
    }

    static Retirement byUserRetirement() {
        return retirement(ActorClass.ACCOUNT_USER, 0, SERIAL, ZERO, TIME + 100);
    }

    static Retirement byGrantRetirement() {
        return retirement(ActorClass.ADMIN_GRANT, 0, SERIAL, grant(5), TIME + 200);
    }

    /** The legacy marker a version 1 retiring flag decodes to: its inventory is unknown. */
    static Retirement legacyMarker() {
        return new Retirement(ActorClass.LEGACY_MARKER, 0, 0, ZERO, 0, List.of());
    }

    /** A legacy marker's continuation: the same block with every kind outstanding. */
    static Retirement legacyContinued() {
        return retirement(ActorClass.LEGACY_MARKER, 0, 0, ZERO, 0);
    }

    /**
     * One receipt for each retirement kind, in kind order. Odd kinds bind a reference; even
     * kinds discharge with none, as a receipt for nothing to do may.
     */
    static List<Obligation> receipts() {
        List<Obligation> list = new ArrayList<>();
        for (ObligationKind kind : ObligationKind.values()) {
            if (kind.disposition()) continue;
            list.add(obligation(kind, ObligationState.DISCHARGED, kind.code % 2 == 1
                    ? String.format("%02x", 0x10 + kind.code).repeat(16) : ZERO, kind.code, TIME + kind.code));
        }
        return list;
    }

    /** The retirement block after confirmed retirement: each retirement kind as its receipt. */
    static Retirement discharged(Retirement block, List<Obligation> receipts) {
        List<Obligation> obligations = new ArrayList<>(block.obligations);
        for (Obligation receipt : receipts) obligations.set(receipt.kind.code - 1, receipt);
        return new Retirement(block.actorClass, block.actorUserId, block.actorSerial, block.grant, block.time,
                obligations);
    }

    /** A block with every kind discharged: nothing would remain for the release engine. */
    static Retirement allDischarged(Retirement block) {
        List<Obligation> obligations = new ArrayList<>();
        for (ObligationKind kind : ObligationKind.values()) {
            obligations.add(obligation(kind, ObligationState.DISCHARGED, ZERO, 0, 0));
        }
        return new Retirement(block.actorClass, block.actorUserId, block.actorSerial, block.grant, block.time,
                obligations);
    }

    /** The block with one obligation replaced. */
    static Retirement with(Retirement block, Obligation duty) {
        List<Obligation> obligations = new ArrayList<>(block.obligations);
        obligations.set(duty.kind.code - 1, duty);
        return new Retirement(block.actorClass, block.actorUserId, block.actorSerial, block.grant, block.time,
                obligations);
    }

    private static List<Suspension> sorted(Suspension... entries) {
        List<Suspension> list = new ArrayList<>(List.of(entries));
        list.sort(NativeIdentityRecords::order);
        return list;
    }

    static Lifecycle eligible(Suspension... entries) {
        return new Lifecycle(LifecycleState.ELIGIBLE, sorted(entries), null);
    }

    static Lifecycle retiring(Retirement block, Suspension... entries) {
        return new Lifecycle(LifecycleState.RETIRING, sorted(entries), block);
    }

    static Lifecycle retired(Retirement block, Suspension... entries) {
        return new Lifecycle(LifecycleState.RETIRED, sorted(entries), block);
    }

    /** A's slot at this generation with this lifecycle. */
    static Slot slotA(long generation, Lifecycle lifecycle) {
        return new Slot(LINEAGE, A, PKG_A, generation, SIGNERS, List.of(new UserEntry(ID_A, 0, SERIAL, lifecycle)));
    }

    static Slot slotB(long generation, Lifecycle lifecycle) {
        return new Slot(LINEAGE, B, PKG_B, generation, SIGNERS, List.of(new UserEntry(ID_B, 0, SERIAL, lifecycle)));
    }

    // ------------------------------------------------------------------ files

    static Header header(long lastId, HeaderEntry... entries) {
        return new Header(LINEAGE, lastId, List.of(entries));
    }

    static HeaderEntry live(int appId) {
        return new HeaderEntry(appId, SlotPhase.LIVE, 0, "");
    }

    /** A's version 2 creation entry with its complete binding. */
    static Header creatingA() {
        return Header.newV2(LINEAGE, ID_A, List.of(new HeaderEntry(A, SlotPhase.CREATING, ID_A, PKG_A,
                new CreationBinding(0, SERIAL, SIGNERS))));
    }

    static Path fresh() throws Exception {
        return Files.createDirectory(base.resolve("c" + ++cases)).resolve("store");
    }

    /** A store with this header in its main and reserve, as its writers leave them, and no slot. */
    static Path store(Header header) throws Exception {
        Path root = fresh();
        Files.createDirectories(root.resolve("slots"));
        byte[] bytes = NativeIdentityRecords.encodeHeader(header);
        Files.write(root.resolve("store.bin"), bytes);
        Files.write(root.resolve("store.bin.reservecopy"), bytes);
        return root;
    }

    /** A store whose header copies are damage, which suspension does not need. */
    static Path damagedHeader() throws Exception {
        Path root = fresh();
        Files.createDirectories(root.resolve("slots"));
        Files.write(root.resolve("store.bin"), new byte[] {1, 2, 3});
        Files.write(root.resolve("store.bin.reservecopy"), new byte[] {1, 2, 3});
        return root;
    }

    /** One slot's main and reserve copy of this value. */
    static void slot(Path root, Slot value) throws Exception {
        byte[] bytes = NativeIdentityRecords.encodeSlot(value);
        raw(root, value.appId, bytes, bytes);
    }

    static void raw(Path root, int appId, byte[] main, byte[] reserve) throws Exception {
        Path directory = Files.createDirectories(root.resolve("slots/" + appId));
        Files.write(directory.resolve("record.bin"), main);
        Files.write(directory.resolve("record.bin.reservecopy"), reserve);
    }

    /** A LIVE store of A with this slot value. */
    static Path layout(Slot value) throws Exception {
        Path root = store(header(value.users.isEmpty() ? 1 : value.users.get(0).id, live(value.appId)));
        slot(root, value);
        return root;
    }

    static NativeIdentityStore open(Path root, Format format) {
        return new NativeIdentityStore(root.toFile(), format);
    }

    static NativeIdentityPersistence persistence(Path root, Format format) {
        return new NativeIdentityPersistence(open(root, format));
    }

    static NativeIdentityStore.Loaded load(Path root, Format format) {
        return open(root, format).load();
    }

    /** A's selected value, or null unless its record is VALID. */
    static Slot stored(Path root, Format format) {
        ReadResult<Slot> read = load(root, format).slots.get(A);
        return read != null && read.status == Status.VALID ? read.value : null;
    }

    /** The bytes of A's main copy. */
    static byte[] mainBytes(Path root) throws Exception {
        return Files.readAllBytes(root.resolve("slots/" + A + "/record.bin"));
    }

    /** Whether A's main and reserve hold exactly this value's one encoding, of this version. */
    static boolean holds(Path root, Slot value, int version) throws Exception {
        byte[] bytes = NativeIdentityRecords.encodeSlot(value);
        Path directory = root.resolve("slots/" + A);
        return value.version == version && NativeIdentityRecords.intactSlotVersion(bytes) == version
                && Arrays.equals(bytes, Files.readAllBytes(directory.resolve("record.bin")))
                && Arrays.equals(bytes, Files.readAllBytes(directory.resolve("record.bin.reservecopy")))
                && !Files.exists(directory.resolve("record.bin-backup"), LinkOption.NOFOLLOW_LINKS);
    }

    static void age(Path root) throws Exception {
        List<Path> paths;
        try (var walk = Files.walk(root)) {
            paths = walk.toList();
        }
        for (Path path : paths) {
            BasicFileAttributes attrs = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (attrs.isRegularFile() || attrs.isDirectory()) Files.setLastModifiedTime(path, AGED);
        }
    }

    /** Content, file identity and modification time of every path below the store's parent. */
    static Map<String, String> footprint(Path root) throws Exception {
        Path top = root.getParent();
        Map<String, String> result = new TreeMap<>();
        List<Path> paths;
        try (var walk = Files.walk(top)) {
            paths = walk.toList();
        }
        for (Path path : paths) {
            BasicFileAttributes attrs = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            result.put(top.relativize(path).toString(), attrs.fileKey() + " " + attrs.lastModifiedTime() + " "
                    + (attrs.isRegularFile() ? Base64.getEncoder().encodeToString(Files.readAllBytes(path))
                    : "directory"));
        }
        return result;
    }

    /** Refused before any effect: false, and every byte, file identity and time unchanged. */
    static void unchanged(List<String> problems, Path root, String what, Write write) throws Exception {
        age(root);
        Map<String, String> before = footprint(root);
        boolean result = write.run();
        check(problems, !result, what + " acknowledged");
        check(problems, footprint(root).equals(before), what + " changed the store");
    }

    /** Thrown as IllegalArgumentException before any effect, with every footprint unchanged. */
    static void invalid(List<String> problems, Path root, String what, Write write) throws Exception {
        age(root);
        Map<String, String> before = footprint(root);
        try {
            write.run();
            problems.add(what + " was not refused as an invalid request");
        } catch (IllegalArgumentException expected) {
            // The request is no writer's.
        }
        check(problems, footprint(root).equals(before), what + " changed the store");
    }

    private NativeLifecycleTestSupport() {}
}
