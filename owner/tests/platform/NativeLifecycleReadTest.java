// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import android.system.Os;
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
import com.android.server.pm.NativeIdentityStore.History;
import com.android.server.pm.NativeIdentityStore.Loaded;
import com.android.server.pm.NativeIdentityStore.ReadResult;
import com.android.server.pm.NativeIdentityStore.Source;
import com.android.server.pm.NativeIdentityStore.Status;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Reads of version 2 slots and of later slot frames under every store format. Format.V1 and V2,
 * whose slot ceiling is 1, read an intact version 2 frame as an unsupported footprint whose
 * decoded copies are negative evidence only: package names, principal IDs and sibling
 * conflicts. Every format reads the stable prefix of a frame above version 2 as the same
 * evidence, and a broken prefix as none, while the frame stays a footprint. Format.V3, which no
 * production text constructs, reads version 2 slots as positive state, the discrimination
 * control. The identity predicate is the exact fragment in the host Settings facade, and the
 * seeding names are the candidate Settings text in its history harness. Host files and facades
 * only: not Android boot, PMS state or authority.
 */
public final class NativeLifecycleReadTest {
    private static final String LINEAGE = "c".repeat(32);
    private static final Set<String> SIGNERS = Set.of("d".repeat(64));
    private static final String ZERO = "0".repeat(32);
    private static final int A = 10123, B = 10124, R = 10125, C = 10126;
    private static final String PKG_A = "dev.andrix.lifea", PKG_B = "dev.andrix.lifeb",
            PKG_R = "dev.andrix.lifer", PKG_C = "dev.andrix.lifec", UNNAMED = "dev.andrix.unnamed";
    private static final long SERIAL = 7;
    private static final int MAGIC = 0x44495841, TYPE_SLOT = 2, CHECKSUM = 32;
    private static final Format[] FORMATS = {Format.V1, Format.V2, Format.V3};

    private static final Suspension BY_USER = new Suspension(ActorClass.ACCOUNT_USER, 0, 0, SERIAL, ZERO,
            SuspensionReason.SUSPECTED_COMPROMISE.code, 1_700_000_000_000L, null);
    private static final Slot ELIGIBLE_A = body(A, PKG_A, 1, 1, Lifecycle.version1(false));
    private static final Slot RETIRING_A = body(A, PKG_A, 1, 2, Lifecycle.version1(true));
    private static final Slot SUSPENDED_A = body(A, PKG_A, 1, 2,
            new Lifecycle(LifecycleState.ELIGIBLE, List.of(BY_USER), null));
    private static final Slot RETIRED_A = body(A, PKG_A, 1, 3, new Lifecycle(LifecycleState.RETIRED, List.of(),
            new Retirement(ActorClass.ACCOUNT_USER, 0, SERIAL, ZERO, 1_700_000_000_001L, retiredInventory())));

    private interface Body { void run(List<String> problems) throws Exception; }
    private interface Write { boolean run(NativeIdentityStore store) throws Exception; }

    private static final List<String> failures = new ArrayList<>();
    private static int passed, directories;
    private static Path parent;

    private static Slot body(int appId, String name, long id, long generation, Lifecycle lifecycle) {
        return new Slot(LINEAGE, appId, name, generation, SIGNERS, List.of(new UserEntry(id, 0, SERIAL, lifecycle)));
    }

    private static List<Obligation> retiredInventory() {
        List<Obligation> list = new ArrayList<>();
        for (ObligationKind kind : ObligationKind.values()) {
            list.add(new Obligation(kind, kind.disposition() ? ObligationState.OUTSTANDING : ObligationState.DISCHARGED,
                    ZERO, 0, 0));
        }
        return list;
    }

    private static HeaderEntry live(int appId) {
        return new HeaderEntry(appId, SlotPhase.LIVE, 0, "");
    }

    private static Header header(long lastId, HeaderEntry... entries) {
        return new Header(LINEAGE, lastId, List.of(entries));
    }

    // ------------------------------------------------------------------ files

    private static byte[] sealed(byte[] unsealed) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(unsealed);
        byte[] record = Arrays.copyOf(unsealed, unsealed.length + CHECKSUM);
        System.arraycopy(digest, 0, record, unsealed.length, CHECKSUM);
        return record;
    }

    // An intact slot frame of this version around these body bytes.
    private static byte[] frame(int version, byte[] body) throws Exception {
        byte[] unsealed = new byte[12 + body.length];
        for (int i = 0; i < 4; i++) unsealed[i] = (byte) (MAGIC >>> (8 * i));
        unsealed[4] = TYPE_SLOT;
        unsealed[6] = (byte) version;
        unsealed[7] = (byte) (version >>> 8);
        int length = unsealed.length + CHECKSUM;
        for (int i = 0; i < 4; i++) unsealed[8 + i] = (byte) (length >>> (8 * i));
        System.arraycopy(body, 0, unsealed, 12, body.length);
        return sealed(unsealed);
    }

    private static byte[] body(byte[] record) {
        return Arrays.copyOfRange(record, 12, record.length - CHECKSUM);
    }

    // A version 3 frame of this slot's version 2 body and a later extension: its stable prefix
    // is valid. The broken twin ends inside the package name.
    private static byte[] laterValid(Slot slot) throws Exception {
        byte[] encoded = body(NativeIdentityRecords.encodeSlot(slot));
        byte[] extended = Arrays.copyOf(encoded, encoded.length + 5);
        return frame(3, extended);
    }

    private static byte[] laterBroken(Slot slot) throws Exception {
        return frame(3, Arrays.copyOf(body(NativeIdentityRecords.encodeSlot(slot)), 36));
    }

    private static Path fresh() throws Exception {
        return Files.createDirectory(parent.resolve("c" + ++directories)).resolve("store");
    }

    // The header's main and reserve copies, as its writers leave them.
    private static Path store(Header header) throws Exception {
        Path root = fresh();
        Files.createDirectories(root.resolve("slots"));
        byte[] bytes = NativeIdentityRecords.encodeHeader(header);
        Files.write(root.resolve("store.bin"), bytes);
        Files.write(root.resolve("store.bin.reservecopy"), bytes);
        return root;
    }

    // One slot's main, reserve, backup and seed, each only when given.
    private static void slot(Path root, int appId, byte[] main, byte[] reserve, byte[] backup, byte[] seed)
            throws Exception {
        Path directory = Files.createDirectories(root.resolve("slots/" + appId));
        if (main != null) Files.write(directory.resolve("record.bin"), main);
        if (reserve != null) Files.write(directory.resolve("record.bin.reservecopy"), reserve);
        if (backup != null) Files.write(directory.resolve("record.bin-backup"), backup);
        if (seed != null) Files.write(directory.resolve("record.bin-seed"), seed);
    }

    private static void slot(Path root, Slot value) throws Exception {
        byte[] bytes = NativeIdentityRecords.encodeSlot(value);
        slot(root, value.appId, bytes, bytes, null, null);
    }

    // Content, file identity and modification time of every path.
    private static Map<String, String> footprint(Path root) throws Exception {
        Map<String, String> result = new TreeMap<>();
        try (var paths = Files.walk(root)) {
            for (Path path : paths.toList()) {
                var attrs = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                result.put(root.relativize(path).toString(), attrs.fileKey() + ":" + attrs.lastModifiedTime() + ":"
                        + (attrs.isRegularFile() ? Base64.getEncoder().encodeToString(Files.readAllBytes(path))
                        : "directory"));
            }
        }
        return result;
    }

    private static NativeIdentityStore open(Path root, Format format) {
        return new NativeIdentityStore(root.toFile(), format);
    }

    private static Loaded load(Path root, Format format) {
        return open(root, format).load();
    }

    // ------------------------------------------------------------------ running

    private static void check(List<String> problems, boolean ok, String problem) {
        if (!ok) problems.add(problem);
    }

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

    private static boolean ceilingTwo(Format format) {
        return format == Format.V3;
    }

    // The facade's exact identity fragment, after the facade's own restoration.
    private static boolean identity(Path root, Format format, String name) {
        Settings settings = new Settings(root, false, format);
        settings.restoreAfterPackageSettings();
        return settings.isNativePrincipalPackageLPr(name);
    }

    // The candidate's boot restoration and seeding, and its identity fragment, over this view.
    private static NativeHistoryHarness seeded(Path root, Format format) {
        NativeHistoryHarness harness = new NativeHistoryHarness();
        harness.apply(load(root, format));
        return harness;
    }

    private static void negativeOnly(List<String> problems, Loaded loaded, int appId, List<Slot> copies) {
        ReadResult<Slot> read = loaded.slots.get(appId);
        check(problems, read.status == Status.UNSUPPORTED, "status " + read.status);
        check(problems, read.decodedCopies.equals(copies), "decoded copies " + read.decodedCopies);
        check(problems, read.prefixes.isEmpty(), "prefixes from version 2");
        check(problems, read.value == null && !loaded.bindingUsable(appId) && loaded.history(appId) == null,
                "a positive value");
        check(problems, loaded.unsupportedFootprint && !loaded.creationReady(), "not a footprint");
        check(problems, loaded.occupiedAppIds.contains(appId), "hold lost");
        check(problems, NativeIdentityPersistence.restoration(loaded.histories()).records.stream()
                .noneMatch(record -> record.appId == appId), "restored");
    }

    // ------------------------------------------------------------------ cases

    private static void versionTwoSlots(Format format) {
        String f = format.name() + " / ";
        run(f + "a suspended version 2 slot", problems -> {
            Path root = store(header(1, live(A)));
            slot(root, SUSPENDED_A);
            Loaded loaded = load(root, format);
            if (!ceilingTwo(format)) {
                negativeOnly(problems, loaded, A, List.of(SUSPENDED_A, SUSPENDED_A));
                return;
            }
            ReadResult<Slot> read = loaded.slots.get(A);
            check(problems, read.status == Status.VALID && read.value.equals(SUSPENDED_A), "status " + read.status);
            check(problems, loaded.bindingUsable(A) && loaded.creationReady() && !loaded.unsupportedFootprint,
                    "not positive state");
            History history = loaded.history(A);
            check(problems, history != null && history.source == Source.BODY
                    && history.state == LifecycleState.ELIGIBLE && history.suspensions.equals(List.of(BY_USER))
                    && !history.retiring && !history.eligible(), "history " + history);
            check(problems, NativeIdentityPersistence.scanOwner(history, PKG_A, A, false, PKG_A, false, SERIAL) == null,
                    "a suspended history owns the scan");
            NativeIdentityPersistence.Restoration restoration = NativeIdentityPersistence.restoration(loaded.histories());
            check(problems, restoration.records.size() == 1 && restoration.retiringIds.isEmpty(),
                    "suspension restored as a phase");
            // The same body without its entry owns the scan: the refusal is the suspension's.
            Path control = store(header(1, live(A)));
            slot(control, ELIGIBLE_A);
            History eligible = load(control, format).history(A);
            check(problems, eligible != null && eligible.eligible()
                    && NativeIdentityPersistence.scanOwner(eligible, PKG_A, A, false, PKG_A, false, SERIAL) == eligible,
                    "eligible control");
        });
        run(f + "a retired version 2 slot", problems -> {
            Path root = store(header(1, live(A)));
            slot(root, RETIRED_A);
            Loaded loaded = load(root, format);
            if (!ceilingTwo(format)) {
                negativeOnly(problems, loaded, A, List.of(RETIRED_A, RETIRED_A));
                return;
            }
            History history = loaded.history(A);
            check(problems, history != null && history.state == LifecycleState.RETIRED && history.retiring
                    && history.suspensions.isEmpty() && !history.eligible(), "history " + history);
            NativeIdentityPersistence.Restoration restoration = NativeIdentityPersistence.restoration(loaded.histories());
            check(problems, restoration.records.size() == 1 && restoration.retiringIds.equals(Set.of(1L)),
                    "RETIRED does not restore a RETIRING pin: " + restoration.retiringIds);
            check(problems, NativeIdentityPersistence.scanOwner(history, PKG_A, A, false, PKG_A, false, SERIAL) == null,
                    "a retired history owns the scan");
        });
        for (String kind : List.of("package", "principal", "unrelated")) {
            run(f + "a version 2 slot beside a sibling " + (kind.equals("unrelated") ? "naming neither"
                    : "naming its " + kind), problems -> {
                Slot sibling = body(B, kind.equals("package") ? PKG_A : PKG_B, kind.equals("principal") ? 1 : 2, 1,
                        Lifecycle.version1(false));
                Path root = store(header(2, live(A), live(B)));
                slot(root, SUSPENDED_A);
                slot(root, sibling);
                Loaded loaded = load(root, format);
                boolean related = !kind.equals("unrelated");
                Status a = loaded.slots.get(A).status, b = loaded.slots.get(B).status;
                if (ceilingTwo(format)) {
                    // Both positive: an ordinary duplicate makes both conflicts.
                    check(problems, related ? a == Status.CONFLICT && b == Status.CONFLICT
                            : a == Status.VALID && b == Status.VALID, "statuses " + a + " " + b);
                } else {
                    check(problems, a == Status.UNSUPPORTED, "version 2 slot " + a);
                    check(problems, b == (related ? Status.CONFLICT : Status.VALID), "sibling " + b);
                }
                check(problems, loaded.bindingUsable(B) == !related, "sibling eligibility");
                check(problems, loaded.occupiedAppIds.equals(Set.of(A, B)), "holds " + loaded.occupiedAppIds);
            });
        }
        run(f + "a reservation elsewhere beside a version 2 slot", problems -> {
            Header reserving = Header.newV2(LINEAGE, 2, List.of(live(A), new HeaderEntry(R, SlotPhase.CREATING, 2,
                    PKG_R, new CreationBinding(0, SERIAL, SIGNERS))));
            Path root = store(reserving);
            slot(root, SUSPENDED_A);
            Loaded loaded = load(root, format);
            check(problems, loaded.occupiedAppIds.equals(Set.of(A, R)), "holds " + loaded.occupiedAppIds);
            History reservation = loaded.history(R);
            if (ceilingTwo(format)) {
                check(problems, reservation != null && reservation.source == Source.RESERVATION
                        && reservation.id == 2 && reservation.eligible(), "reservation " + reservation);
                return;
            }
            check(problems, reservation == null && loaded.histories().isEmpty(), "histories " + loaded.histories());
            check(problems, !loaded.creationReady(), "creation ready");
            if (format == Format.V2) {
                // The same header beside a version 1 body keeps the reservation.
                Path control = store(reserving);
                slot(control, ELIGIBLE_A);
                History kept = load(control, format).history(R);
                check(problems, kept != null && kept.source == Source.RESERVATION, "control " + kept);
            }
        });
        run(f + "the identity predicate and seeding name a package that only a version 2 slot holds", problems -> {
            Path root = store(header(1, live(A)));
            slot(root, SUSPENDED_A);
            check(problems, identity(root, format, PKG_A), "facade identity");
            check(problems, !identity(root, format, UNNAMED), "facade control");
            NativeHistoryHarness harness = seeded(root, format);
            check(problems, harness.isNativePrincipalPackageLPr(PKG_A), "candidate identity");
            check(problems, harness.mNativeRecoveryView.protectsName(PKG_A), "seeding");
            check(problems, !harness.mNativeRecoveryView.protectsName(UNNAMED), "seeding control");
        });
    }

    private static void laterFrames(Format format) {
        String f = format.name() + " / ";
        run(f + "a later frame with a valid prefix is negative evidence only", problems -> {
            Path root = store(header(2, live(A), live(B)));
            byte[] later = laterValid(SUSPENDED_A);
            slot(root, A, later, later, null, null);
            slot(root, body(B, PKG_A, 2, 1, Lifecycle.version1(false)));
            Loaded loaded = load(root, format);
            ReadResult<Slot> read = loaded.slots.get(A);
            check(problems, read.status == Status.UNSUPPORTED && read.decodedCopies.isEmpty() && read.value == null,
                    "status " + read.status);
            check(problems, read.prefixes.size() == 2 && read.prefixes.get(0).version == 3
                    && read.prefixes.get(0).packageName.equals(PKG_A)
                    && read.prefixes.get(0).principalIds.equals(List.of(1L)), "prefixes " + read.prefixes);
            check(problems, loaded.history(A) == null && !loaded.bindingUsable(A), "a positive value");
            check(problems, loaded.slots.get(B).status == Status.CONFLICT && !loaded.bindingUsable(B),
                    "sibling " + loaded.slots.get(B).status);
            check(problems, loaded.unsupportedFootprint && !loaded.creationReady(), "not a footprint");
            check(problems, loaded.occupiedAppIds.equals(Set.of(A, B)), "holds " + loaded.occupiedAppIds);
            // A sibling naming its principal conflicts too.
            Path principal = store(header(2, live(A), live(B)));
            slot(principal, A, later, later, null, null);
            slot(principal, body(B, PKG_B, 1, 1, Lifecycle.version1(false)));
            check(problems, load(principal, format).slots.get(B).status == Status.CONFLICT, "principal sibling");
        });
        run(f + "the identity predicate and seeding read a later frame's valid prefix", problems -> {
            Path root = store(header(1, live(A)));
            byte[] later = laterValid(SUSPENDED_A);
            slot(root, A, later, later, null, null);
            check(problems, identity(root, format, PKG_A), "facade identity");
            NativeHistoryHarness harness = seeded(root, format);
            check(problems, harness.isNativePrincipalPackageLPr(PKG_A), "candidate identity");
            check(problems, harness.mNativeRecoveryView.protectsName(PKG_A), "seeding");
            // A broken prefix names nothing, and its app ID stays held.
            Path broken = store(header(1, live(A)));
            byte[] cut = laterBroken(SUSPENDED_A);
            slot(broken, A, cut, cut, null, null);
            check(problems, !identity(broken, format, PKG_A), "facade identity from a broken prefix");
            NativeHistoryHarness none = seeded(broken, format);
            check(problems, !none.isNativePrincipalPackageLPr(PKG_A) && !none.mNativeRecoveryView.protectsName(PKG_A),
                    "names from a broken prefix");
            check(problems, none.mNativeRecoveryView.holdsAppId(A), "broken prefix hold lost");
        });
        run(f + "a later frame with a broken prefix gives no evidence", problems -> {
            Path root = store(header(2, live(A), live(B)));
            byte[] cut = laterBroken(SUSPENDED_A);
            slot(root, A, cut, cut, null, null);
            slot(root, body(B, PKG_A, 2, 1, Lifecycle.version1(false)));
            Loaded loaded = load(root, format);
            ReadResult<Slot> read = loaded.slots.get(A);
            check(problems, read.status == Status.UNSUPPORTED && read.prefixes.isEmpty() && read.decodedCopies.isEmpty(),
                    "status " + read.status + " " + read.prefixes);
            check(problems, loaded.slots.get(B).status == Status.VALID && loaded.bindingUsable(B), "sibling withdrawn");
            check(problems, loaded.unsupportedFootprint && !loaded.creationReady(), "the footprint was dropped");
            Map<String, String> before = footprint(root);
            check(problems, !open(root, format).writeHeader(header(2, live(A), live(B)), header(2, live(A), live(B))),
                    "a writer wrote through a broken prefix");
            check(problems, footprint(root).equals(before), "store footprint changed");
        });
    }

    // Each writer of an otherwise valid layout: header retry, confirmation and marker of A, and
    // confirmation of an unrelated sibling.
    private static final Map<String, Write> WRITERS = Map.of(
            "header retry", store -> store.writeHeader(header(2, live(A), live(B)), header(2, live(A), live(B))),
            "confirm A", store -> store.confirmExistingSlot(ELIGIBLE_A),
            "mark A retiring", store -> store.updateExistingSlot(ELIGIBLE_A, RETIRING_A),
            "confirm sibling", store -> store.confirmExistingSlot(body(B, PKG_B, 2, 1, Lifecycle.version1(false))));

    // The older valid copies of A and an unrelated sibling, and this frame in one position.
    private static Path older(String position, byte[] frame) throws Exception {
        Path root = store(header(2, live(A), live(B)));
        byte[] valid = NativeIdentityRecords.encodeSlot(ELIGIBLE_A);
        switch (position) {
            case "main": slot(root, A, frame, valid, valid, null); break;
            case "reserve": slot(root, A, valid, frame, valid, null); break;
            case "backup": slot(root, A, valid, valid, frame, null); break;
            case "seed": slot(root, A, valid, valid, null, frame); break;
            default: slot(root, A, valid, valid, null, null); break;
        }
        slot(root, body(B, PKG_B, 2, 1, Lifecycle.version1(false)));
        return root;
    }

    private static void positions(Format format) {
        String f = format.name() + " / ";
        run(f + "healthy controls, every writer succeeds", problems -> {
            for (Map.Entry<String, Write> writer : new TreeMap<>(WRITERS).entrySet()) {
                Path root = older("none", null);
                check(problems, load(root, format).bindingUsable(A), "control not usable");
                check(problems, writer.getValue().run(open(root, format)), writer.getKey() + " refused");
            }
        });
        for (String kind : List.of("valid", "broken")) {
            for (String position : List.of("main", "reserve", "backup", "seed")) {
                run(f + "a later frame with a " + kind + " prefix in the " + position + (position.equals("seed")
                        ? ", the seed gives nothing and every writer refuses"
                        : ", nothing restored from the older copies and every writer refuses"), problems -> {
                    byte[] frame = kind.equals("valid") ? laterValid(SUSPENDED_A) : laterBroken(SUSPENDED_A);
                    boolean copy = !position.equals("seed");
                    Loaded loaded = load(older(position, frame), format);
                    ReadResult<Slot> read = loaded.slots.get(A);
                    check(problems, loaded.unsupportedFootprint && !loaded.creationReady(), "not a footprint");
                    if (copy) {
                        // The frame alone classifies the record: no older copy is selected around it.
                        check(problems, read.status == Status.UNSUPPORTED && read.value == null
                                && !loaded.bindingUsable(A) && loaded.history(A) == null, "restored " + read.status);
                        check(problems, read.decodedCopies.equals(List.of(ELIGIBLE_A, ELIGIBLE_A)), "older copies");
                        check(problems, read.prefixes.size() == (kind.equals("valid") ? 1 : 0), "prefix evidence");
                        check(problems, NativeIdentityPersistence.restoration(loaded.histories()).records.stream()
                                .noneMatch(record -> record.appId == A), "pin restored");
                    } else {
                        // A seed is staging, never a copy, history or evidence. It only blocks
                        // mutation and creation: the older copies stay the record, with their history.
                        check(problems, read.status == Status.VALID && read.prefixes.isEmpty()
                                && ELIGIBLE_A.equals(read.value), "seed read " + read.status);
                        History history = loaded.history(A);
                        check(problems, loaded.bindingUsable(A) && history != null && history.source == Source.BODY
                                && history.id == 1 && history.eligible(),
                                "the older copies' history is gone beside a newer seed: " + history);
                        check(problems, NativeIdentityPersistence.restoration(loaded.histories()).records.stream()
                                .anyMatch(record -> record.appId == A), "the older copies' pin is gone");
                    }
                    check(problems, loaded.slots.get(B).status == Status.VALID, "sibling " + loaded.slots.get(B).status);
                    for (Map.Entry<String, Write> writer : new TreeMap<>(WRITERS).entrySet()) {
                        Path root = older(position, frame);
                        Map<String, String> before = footprint(root);
                        check(problems, !writer.getValue().run(open(root, format)), writer.getKey() + " wrote");
                        check(problems, footprint(root).equals(before), writer.getKey() + " changed the store");
                    }
                });
            }
        }
    }

    private static void slotWrites(Format format) {
        String f = format.name() + " / ";
        run(f + "version 2 slot writes " + (ceilingTwo(format) ? "succeed" : "refuse before any effect"), problems -> {
            Slot eligibleC = body(C, PKG_C, 2, 1, Lifecycle.version1(false));
            Slot suspendedC = body(C, PKG_C, 2, 1, new Lifecycle(LifecycleState.ELIGIBLE, List.of(BY_USER), null));
            Header creating = header(2, live(A), new HeaderEntry(C, SlotPhase.CREATING, 2, PKG_C));
            if (ceilingTwo(format)) {
                Path root = store(header(1, live(A)));
                slot(root, SUSPENDED_A);
                NativeIdentityStore store = open(root, format);
                byte[] before = Files.readAllBytes(root.resolve("slots/" + A + "/record.bin"));
                check(problems, store.confirmExistingSlot(SUSPENDED_A), "version 2 confirmation refused");
                check(problems, Arrays.equals(before, Files.readAllBytes(root.resolve("slots/" + A + "/record.bin"))),
                        "confirmation changed bytes");
                Slot next = body(A, PKG_A, 1, 3, SUSPENDED_A.users.get(0).lifecycle);
                check(problems, store.updateExistingSlot(SUSPENDED_A, next), "version 2 update refused");
                check(problems, store.load().slots.get(A).value.equals(next), "update not durable");
                return;
            }
            // Publication refuses before the header confirmation, which would be its first effect.
            Path publish = store(creating);
            slot(publish, ELIGIBLE_A);
            Files.createDirectories(publish.resolve("slots/" + C));
            Map<String, String> before = footprint(publish);
            check(problems, !open(publish, format).publishCreatingSlot(creating, suspendedC), "version 2 published");
            check(problems, footprint(publish).equals(before), "publication changed the store");
            Path control = store(creating);
            slot(control, ELIGIBLE_A);
            Files.createDirectories(control.resolve("slots/" + C));
            check(problems, open(control, format).publishCreatingSlot(creating, eligibleC), "control publication");
            // An update to a version 2 value refuses before its first effect.
            Path update = store(header(1, live(A)));
            slot(update, ELIGIBLE_A);
            before = footprint(update);
            check(problems, !open(update, format).updateExistingSlot(ELIGIBLE_A, SUSPENDED_A), "version 2 written");
            check(problems, !open(update, format).confirmExistingSlot(SUSPENDED_A), "version 2 confirmed");
            check(problems, footprint(update).equals(before), "update changed the store");
            check(problems, open(update, format).updateExistingSlot(ELIGIBLE_A, RETIRING_A), "control update");
        });
    }

    public static void main(String[] args) throws Exception {
        if (!NativeLifecycleReadTest.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        parent = Files.createDirectories(Path.of(args[0]).resolve("lifecycle-read"));
        for (Format format : FORMATS) {
            versionTwoSlots(format);
            laterFrames(format);
            positions(format);
            slotWrites(format);
        }
        if (!Os.allClosed()) failures.add("open descriptors");
        System.out.println(passed + " passed, " + failures.size() + " failed");
        if (!failures.isEmpty()) throw new AssertionError("failed: " + failures);
        System.out.println("Lifecycle record reads under every store format passed; Android unqualified");
    }
}
