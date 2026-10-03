// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeBindingTestSupport.*;
import static com.android.server.pm.NativeHeaderTestSupport.*;

import android.content.pm.SigningDetails;
import android.system.Os;
import com.android.server.LocalServices;
import com.android.server.pm.NativeIdentityPersistence.CreationPlan;
import com.android.server.pm.NativeIdentityRecords.CreationBinding;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.HeaderEntry;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.SlotPhase;
import com.android.server.pm.NativeIdentityRecords.UserEntry;
import com.android.server.pm.NativeIdentityStore.Status;
import com.android.server.pm.NativePrincipalPins.Record;
import com.android.server.pm.NativePrincipalPins.Snapshot;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Complete original creation bindings and exact encoded byte admission, over the actual
 * records, store, persistence, manager and host PMS facade. Each case isolates one store. A
 * truly new entry needs the owned original signer row of its issuance; under the version 2
 * host format it carries that user, serial and signer set, and only it raises a version 1
 * header. Held entries and unselected additions stay exactly as durable state lists them,
 * with a missing binding kept missing. Bindings are checked only negatively. Publication is
 * refused where needed by real unprivileged permissions on the slot namespace, so a durable
 * reservation stays visible. Host facades only: not Android crash, power loss, storage,
 * SELinux or UID authority qualification, and not activation of the version 2 format.
 */
public final class NativeCreationBindingTest {
    private static final Set<String> OTHER = Set.of("1".repeat(64));
    private static final Set<String> PAIR = Set.of("2".repeat(64), "3".repeat(64));
    private static final Set<String> TWO = Set.of("6".repeat(64), "7".repeat(64));

    private static Set<String> wideSigners(int count, int seed) {
        Set<String> digests = new TreeSet<>();
        for (int i = 0; i < count; i++) digests.add(String.format("%064x", seed * 1000L + i));
        return digests;
    }
    // A valid package name of exactly this length, distinct for each index.
    private static String uniqueName(int length, int index) {
        String prefix = "dev.p" + index + "x";
        if (length < prefix.length() || length > 255) throw new IllegalArgumentException("length");
        return prefix + "q".repeat(length - prefix.length());
    }
    private static HeaderEntry entryOf(Header header, int appId) {
        for (HeaderEntry entry : header.entries) if (entry.appId == appId) return entry;
        return null;
    }
    private static byte[] concat(byte[] first, byte[] second) {
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }
    private static boolean emptyDirectory(Path directory) throws Exception {
        try (var entries = Files.list(directory)) {
            return entries.findAny().isEmpty();
        }
    }
    // Commits with the slot namespace read only: the reservation is written, and publication is
    // refused by real permissions before any slot directory exists.
    private static boolean commitWithoutPublication(Path root, NativePrincipalManager manager,
            NativePrincipalManager.Handle handle) throws Exception {
        return restricted(root.resolve("slots"), READ_ONLY, () -> manager.commit(handle));
    }

    // Plans are validated, immutable data. Rows belong to records of their own snapshot.
    private static void plans() {
        Snapshot two = new Snapshot(2, List.of(record(1, PKG_B, B), record(2, PKG_C, C)));
        run("plan / rows only for records of a valid snapshot", problems -> {
            check(problems, throwsType(() -> plan(two, Map.of(3L, SIGNERS)),
                    IllegalArgumentException.class), "row for a foreign ID accepted");
            check(problems, throwsType(() -> plan(new Snapshot(1, List.of(record(2, PKG_B, B))),
                    Map.of()), IllegalArgumentException.class), "malformed snapshot accepted");
            check(problems, throwsType(() -> plan(null, Map.of()), NullPointerException.class),
                    "null snapshot accepted");
            check(problems, throwsType(() -> plan(two, null), NullPointerException.class),
                    "null rows accepted");
            Map<Long, Set<String>> nullRow = new HashMap<>();
            nullRow.put(1L, null);
            check(problems, throwsType(() -> plan(two, nullRow), NullPointerException.class),
                    "null row accepted");
            CreationPlan valid = plan(two, Map.of(1L, SIGNERS));
            check(problems, SIGNERS.equals(valid.row(1)) && valid.row(2) == null
                    && valid.snapshot == two, "rows not kept as given");
        });
        run("plan / signer sets are valid, bounded and copied", problems -> {
            Set<String> tooMany = wideSigners(NativeIdentityRecords.MAX_SIGNERS + 1, 1);
            List<Set<String>> invalid = List.of(Set.of(), tooMany, Set.of("A".repeat(64)),
                    Set.of("a".repeat(63)), Set.of("g".repeat(64)));
            for (Set<String> signers : invalid) {
                check(problems, throwsType(() -> plan(two, Map.of(1L, signers)),
                        IllegalArgumentException.class), "invalid signer set of " + signers.size());
            }
            Set<String> withNull = new HashSet<>();
            withNull.add(null);
            check(problems, throwsType(() -> plan(two, Map.of(1L, withNull)),
                    NullPointerException.class), "null digest accepted");
            Set<String> mutable = new HashSet<>(PAIR);
            Map<Long, Set<String>> rows = new HashMap<>();
            rows.put(1L, mutable);
            CreationPlan copied = plan(two, rows);
            mutable.add("4".repeat(64));
            rows.put(2L, SIGNERS);
            check(problems, PAIR.equals(copied.row(1)) && copied.row(2) == null,
                    "plan follows its caller's collections");
            check(problems, throwsType(() -> copied.row(1).add("5".repeat(64)),
                    UnsupportedOperationException.class), "row is mutable");
            Set<String> max = wideSigners(NativeIdentityRecords.MAX_SIGNERS, 2);
            check(problems, plan(two, Map.of(1L, max)).row(1).size() == NativeIdentityRecords.MAX_SIGNERS,
                    "MAX_SIGNERS refused");
        });
    }

    // Truly new entries need owned provenance even under version 1, whose bytes stay golden.
    private static void provenance() {
        run("V1 / a new entry without an owned row refuses before effects", problems -> {
            Path root = layout(null, bytes(OLD), bytes(OLD));
            NativeIdentityPersistence persistence = persistence(root);
            Snapshot snapshot = new Snapshot(1, List.of(record(1, PKG_B, B)));
            CreationPlan unowned = plan(snapshot, Map.of());
            check(problems, persistence.projectReservation(persistence.load(), unowned) == null,
                    "admitted without provenance");
            unchanged(problems, root, "reservation without provenance",
                    () -> persistence.reservePending(unowned));
            check(problems, persistence.reservePending(plan(snapshot, Map.of(1L, SIGNERS))),
                    "owned reservation refused");
            check(problems, sameBytes(root.resolve("store.bin"), GOLDEN_PENDING_B_V1)
                    && sameBytes(root.resolve("store.bin.reservecopy"), GOLDEN_PENDING_B_V1),
                    "version 1 bytes differ from the golden encoding");
        });
        run("V1 / held entries and additions need no row", problems -> {
            Path root = legacy(header(1, creating(A, 1, PKG_A)),
                    header(2, creating(A, 1, PKG_A), creating(B, 2, PKG_B)));
            NativeIdentityPersistence persistence = persistence(root);
            Snapshot snapshot = new Snapshot(3, List.of(record(1, PKG_A, A), record(2, PKG_B, B),
                    record(3, PKG_C, C)));
            check(problems, persistence.projectReservation(persistence.load(),
                    plan(snapshot, Map.of(3L, SIGNERS))) != null, "held or added entry stranded");
            check(problems, persistence.projectReservation(persistence.load(),
                    plan(snapshot, Map.of(1L, SIGNERS, 2L, SIGNERS))) == null,
                    "new C admitted without a row");
            check(problems, persistence.reservePending(plan(snapshot, Map.of(3L, SIGNERS)))
                    && header(3, creating(A, 1, PKG_A), creating(B, 2, PKG_B), creating(C, 3, PKG_C))
                    .equals(stored(root)), "reservation " + stored(root));
        });
        run("manager / another manager's unreserved pin refuses before issuance", problems -> {
            for (NativeIdentityStore.Format format : List.of(V1, V2)) {
                PackageManagerService pm = livePmOf(format);
                Path root = pm.mSettings.root;
                NativePrincipalManager owner = new NativePrincipalManager(pm);
                NativePrincipalManager other = new NativePrincipalManager(pm);
                NativePrincipalManager.Handle b = owner.prepare(owner.select(PKG_B, 0));
                NativePrincipalManager.Selection c = other.select(PKG_C, 0);
                age(root);
                Map<String, String> before = footprint(root);
                int remembers = pm.mSettings.rememberCalls;
                check(problems, throwsType(() -> other.prepare(c), IllegalStateException.class),
                        format + " issued beside another manager's unreserved pin");
                check(problems, pm.mSettings.pins.snapshotForWrite().lastId == 1
                        && pm.mSettings.pins.find(PKG_C, 0) == null
                        && !pm.mSettings.pins.isAppIdPinned(C)
                        && pm.mSettings.rememberCalls == remembers, format + " issuance effects");
                check(problems, footprint(root).equals(before), format + " store changed");
                check(problems, owner.commit(b), format + " owner commit refused");
                NativePrincipalManager.Handle issued = other.prepare(other.select(PKG_C, 0));
                Header expected = format == V1 ? header(2, live(B), live(C)) : v2(2, live(B), live(C));
                check(problems, other.commit(issued) && expected.equals(storedOf(root, format)),
                        format + " header " + storedOf(root, format));
            }
        });
        run("manager / a late preparation failure keeps the original issuance", problems -> {
            for (NativeIdentityStore.Format format : List.of(V1, V2)) {
                PackageManagerService pm = livePmOf(format);
                Path root = pm.mSettings.root;
                NativePrincipalManager manager = new NativePrincipalManager(pm);
                NativePrincipalManager.Selection selection = manager.select(PKG_B, 0);
                pm.mSettings.failRemember = true;
                check(problems, throwsType(() -> manager.prepare(selection),
                        IllegalStateException.class), format + " injected failure not reached");
                NativePrincipalManager.Handle b = manager.find(PKG_B, 0);
                check(problems, b != null && manager.identity(b).id == 1
                        && manager.prepare(selection) == b, format + " original issuance lost");
                PackageSetting setting = pm.mSettings.packages.get(PKG_B);
                SigningDetails original = setting.signing;
                setting.signing = signing(9, 1);
                check(problems, throwsType(() -> manager.commit(b), IllegalStateException.class),
                        format + " replaced signer committed");
                setting.signing = original;
                Header expected = format == V1 ? header(1, live(B)) : v2(1, live(B));
                check(problems, manager.commit(b) && expected.equals(storedOf(root, format))
                        && pm.mSettings.pins.snapshotForWrite().lastId == 1, format + " commit");
                Slot body = loadedOf(root, format).slots.get(B).value;
                check(problems, body != null && SIGNERS.equals(body.signerSha256),
                        format + " body signers");
            }
        });
    }

    // Version 1 flows keep their exact bytes; version 2 writes the documented layout.
    private static void golden() {
        run("V1 / an owned flow writes the golden version 1 bytes", problems -> {
            PackageManagerService pm = livePm();
            Path root = pm.mSettings.root;
            check(problems, sameBytes(root.resolve("store.bin"), GOLDEN_EMPTY_V1), "initialization");
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
            check(problems, !commitWithoutPublication(root, manager, b)
                    && sameBytes(root.resolve("store.bin"), GOLDEN_PENDING_B_V1)
                    && sameBytes(root.resolve("store.bin.reservecopy"), GOLDEN_PENDING_B_V1),
                    "reservation bytes");
            check(problems, manager.commit(b) && sameBytes(root.resolve("store.bin"), GOLDEN_LIVE_B_V1)
                    && sameBytes(root.resolve("store.bin.reservecopy"), GOLDEN_LIVE_B_V1),
                    "publication bytes");
            check(problems, manager.beginRetirement(b) && manager.finishRetirementAfterQuiescence(b)
                    && header(1).equals(stored(root)), "retirement " + stored(root));
        });
        run("V2 / an owned flow writes the golden version 2 bytes", problems -> {
            PackageManagerService pm = livePmOf(V2);
            Path root = pm.mSettings.root;
            check(problems, sameBytes(root.resolve("store.bin"), GOLDEN_EMPTY_V1),
                    "initialization is not an empty version 1 header");
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
            check(problems, !commitWithoutPublication(root, manager, b)
                    && sameBytes(root.resolve("store.bin"), GOLDEN_PENDING_B_V2)
                    && sameBytes(root.resolve("store.bin.reservecopy"), GOLDEN_PENDING_B_V2),
                    "reservation bytes");
            check(problems, v2(1, boundCreating(B, 1, PKG_B)).equals(storedOf(root, V2)),
                    "reservation " + storedOf(root, V2));
            check(problems, manager.commit(b) && v2(1, live(B)).equals(storedOf(root, V2))
                    && pm.mSettings.pins.snapshotForWrite().lastId == 1,
                    "publication " + storedOf(root, V2));
        });
        run("V2 / legacy B beside new C writes the golden bytes", problems -> {
            PackageManagerService pm = livePmOf(V2);
            Path root = pm.mSettings.root;
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            manager.prepare(manager.select(PKG_B, 0));
            legacyReservation(pm, OLD, PENDING_B);
            NativePrincipalManager.Handle c = manager.prepare(manager.select(PKG_C, 0));
            check(problems, !commitWithoutPublication(root, manager, c)
                    && sameBytes(root.resolve("store.bin"), GOLDEN_LEGACY_B_BOUND_C_V2)
                    && sameBytes(root.resolve("store.bin.reservecopy"), GOLDEN_LEGACY_B_BOUND_C_V2)
                    && !Files.exists(root.resolve("store.bin-backup"), LinkOption.NOFOLLOW_LINKS),
                    "upgrade bytes");
        });
    }

    // The projection's byte measure is the encoder's own, for both versions.
    private static void encodedLengths() {
        run("encoded length / equals every actual encoding", problems -> {
            Set<String> wide = wideSigners(NativeIdentityRecords.MAX_SIGNERS, 3);
            List<Header> headers = new ArrayList<>(List.of(OLD, PENDING_B,
                    header(3, live(A), releasing(R), creating(C, 3, PKG_C)), v2(0),
                    v2(1, boundCreating(B, 1, PKG_B)), v2(2, creating(B, 1, PKG_B),
                    boundCreating(C, 2, uniqueName(255, 1), wide))));
            List<HeaderEntry> full1 = new ArrayList<>(), full2 = new ArrayList<>();
            for (int i = 0; i < NativeIdentityRecords.MAX_SLOTS; i++) {
                full1.add(new HeaderEntry(10100 + i, SlotPhase.CREATING, i + 1, uniqueName(255, i)));
                full2.add(i % 3 == 0
                        ? new HeaderEntry(10100 + i, SlotPhase.CREATING, i + 1, uniqueName(255, i))
                        : i % 3 == 1 ? new HeaderEntry(10100 + i, SlotPhase.LIVE, 0, "")
                        : new HeaderEntry(10100 + i, SlotPhase.CREATING, i + 1, uniqueName(100, i),
                                binding(wideSigners(8, i))));
            }
            headers.add(new Header(LINEAGE, NativeIdentityRecords.MAX_SLOTS, full1));
            headers.add(Header.newV2(LINEAGE, NativeIdentityRecords.MAX_SLOTS, full2));
            for (Header value : headers) {
                int measured = NativeIdentityRecords.encodedHeaderLength(value.version,
                        value.lineage, value.lastId, value.entries);
                check(problems, measured == NativeIdentityRecords.encodeHeader(value).length,
                        "measured " + measured + " for version " + value.version + " with "
                        + value.entries.size() + " entries");
            }
        });
        run("encoded length / refuses what it cannot measure", problems -> {
            List<HeaderEntry> tooMany = new ArrayList<>();
            for (int i = 0; i <= NativeIdentityRecords.MAX_SLOTS; i++) {
                tooMany.add(new HeaderEntry(10100 + i, SlotPhase.LIVE, 0, ""));
            }
            check(problems, throwsType(() -> NativeIdentityRecords.encodedHeaderLength(0, LINEAGE, 0,
                    List.of()), IllegalArgumentException.class), "version 0 measured");
            check(problems, throwsType(() -> NativeIdentityRecords.encodedHeaderLength(3, LINEAGE, 0,
                    List.of()), IllegalArgumentException.class), "version 3 measured");
            check(problems, throwsType(() -> NativeIdentityRecords.encodedHeaderLength(1, "abc", 0,
                    List.of()), IllegalArgumentException.class), "malformed lineage measured");
            check(problems, throwsType(() -> NativeIdentityRecords.encodedHeaderLength(2, LINEAGE,
                    NativeIdentityRecords.MAX_SLOTS + 1, tooMany), IllegalArgumentException.class),
                    "MAX_SLOTS + 1 entries measured");
            check(problems, throwsType(() -> NativeIdentityRecords.encodedHeaderLength(1, LINEAGE, 1,
                    List.of(boundCreating(B, 1, PKG_B))), IllegalStateException.class),
                    "version 1 measured a binding");
            check(problems, throwsType(() -> NativeIdentityRecords.encodedHeaderLength(1, LINEAGE, 0,
                    null), NullPointerException.class), "null entries measured");
        });
    }

    // A reopened version 2 registry over header only creations, one unpublished RETIRING pin
    // P, then N sized so the projection is exactly MAX_BYTES, or one byte more. Legacy entries
    // without a binding and LIVE entries are mixed in. Admission and the writer share one
    // projection, so both admit or both refuse, and a refusal comes before N's ID is issued.
    private static void byteAdmission() {
        for (int over : List.of(0, 1)) {
            run(over == 0 ? "admission / exactly MAX_BYTES is admitted and written"
                    : "admission / one byte over MAX_BYTES refuses before issuance", problems -> {
                Set<String> wide = wideSigners(NativeIdentityRecords.MAX_SIGNERS, 4);
                List<HeaderEntry> held = new ArrayList<>();
                for (int i = 0; i < 48; i++) {
                    held.add(new HeaderEntry(10100 + i, SlotPhase.CREATING, i + 1,
                            uniqueName(255, i), binding(wide)));
                }
                held.add(new HeaderEntry(10200, SlotPhase.CREATING, 49, uniqueName(255, 48)));
                held.add(new HeaderEntry(10201, SlotPhase.CREATING, 50, uniqueName(255, 49)));
                held.add(new HeaderEntry(10202, SlotPhase.LIVE, 0, ""));
                Header disk = Header.newV2(LINEAGE, 50, held);
                Path root = layout(null, bytes(disk), bytes(disk));
                int appP = 11000, appN = 11001;
                String pkgP = uniqueName(100, 90);
                SigningDetails pSigning = signing(90, NativeIdentityRecords.MAX_SIGNERS);
                Set<String> pSigners = digests(pSigning);
                List<HeaderEntry> withP = new ArrayList<>(held);
                withP.add(new HeaderEntry(appP, SlotPhase.CREATING, 51, pkgP, binding(pSigners)));
                int base = NativeIdentityRecords.encodedHeaderLength(2, LINEAGE, 52, withP);
                // A bound version 2 entry takes 30 bytes, its package and 32 per signer.
                int needed = NativeIdentityRecords.MAX_BYTES + over - base;
                int count = NativeIdentityRecords.MAX_SIGNERS;
                int length = needed - 30 - 32 * count;
                while (length < 10 && count > 1) length = needed - 30 - 32 * --count;
                check(problems, length >= 10 && length <= 255, "fixture cannot size N for " + needed);
                if (!problems.isEmpty()) return;
                String pkgN = uniqueName(length, 91);
                SigningDetails nSigning = signing(91, count);
                PackageManagerService pm = reopenOf(root, V2, Map.of(pkgP, appP, pkgN, appN));
                pm.mSettings.packages.get(pkgP).signing = pSigning;
                pm.mSettings.packages.get(pkgN).signing = nSigning;
                check(problems, pm.mSettings.pins.hasKnownCounter()
                        && pm.mSettings.pins.snapshotForWrite().lastId == 50, "fixture counter");
                NativePrincipalManager manager = new NativePrincipalManager(pm);
                NativePrincipalManager.Handle p = manager.prepare(manager.select(pkgP, 0));
                pm.mSettings.pins.beginRetire(pm.mSettings.pins.find(pkgP, 0));
                Snapshot proposed = new Snapshot(52, List.of(manager.identity(p),
                        new Record(52, pkgN, appN, 0, SERIAL)), Set.of(51L));
                CreationPlan planned = plan(proposed, Map.of(51L, pSigners, 52L, digests(nSigning)));
                Header projected = pm.mSettings.persistence.projectReservation(
                        pm.mSettings.mNativeIdentityLoaded, planned);
                age(root);
                Map<String, String> before = footprint(root);
                if (over == 0) {
                    check(problems, projected != null && NativeIdentityRecords.encodeHeader(projected)
                            .length == NativeIdentityRecords.MAX_BYTES, "projection is not MAX_BYTES");
                    NativePrincipalManager.Handle n = manager.prepare(manager.select(pkgN, 0));
                    check(problems, manager.identity(n).id == 52, "N was not issued ID 52");
                    check(problems, pm.mSettings.persistence.reservePending(planned)
                            && Files.size(root.resolve("store.bin")) == NativeIdentityRecords.MAX_BYTES
                            && projected != null && projected.equals(storedOf(root, V2)),
                            "the writer did not write the admitted projection");
                    check(problems, manager.commit(n)
                            && pm.mSettings.pins.snapshotForWrite().lastId == 52, "N commit refused");
                } else {
                    check(problems, projected == null, "oversized projection admitted");
                    int remembers = pm.mSettings.rememberCalls;
                    check(problems, throwsType(() -> manager.prepare(manager.select(pkgN, 0)),
                            IllegalStateException.class), "oversized proposal not refused by admission");
                    check(problems, pm.mSettings.pins.snapshotForWrite().lastId == 51
                            && pm.mSettings.pins.find(pkgN, 0) == null
                            && !pm.mSettings.pins.isAppIdPinned(appN)
                            && pm.mSettings.rememberCalls == remembers, "issued before refusal");
                    check(problems, !pm.mSettings.persistence.reservePending(planned)
                            && footprint(root).equals(before), "the writer projected differently");
                }
            });
        }
    }

    // Under version 2 a truly new entry is bound; restatements keep their entries and version.
    private static void projection() {
        run("V2 / a restatement alone keeps version 1", problems -> {
            PackageManagerService pm = livePmOf(V2);
            Path root = pm.mSettings.root;
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
            legacyReservation(pm, OLD, PENDING_B);
            check(problems, !commitWithoutPublication(root, manager, b)
                    && PENDING_B.equals(storedOf(root, V2)), "restatement " + storedOf(root, V2));
            check(problems, manager.commit(b) && header(1, live(B)).equals(storedOf(root, V2)),
                    "publication " + storedOf(root, V2));
        });
        for (boolean cFirst : List.of(true, false)) {
            run("V2 / legacy B with new C upgrades, " + (cFirst ? "C" : "B") + " committed first",
                    problems -> {
                PackageManagerService pm = livePmOf(V2);
                Path root = pm.mSettings.root;
                NativePrincipalManager manager = new NativePrincipalManager(pm);
                NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
                legacyReservation(pm, OLD, PENDING_B);
                NativePrincipalManager.Handle c = manager.prepare(manager.select(PKG_C, 0));
                check(problems, manager.identity(c).id == 2, "C was not issued the next ID");
                NativePrincipalManager.Handle first = cFirst ? c : b, second = cFirst ? b : c;
                Header upgraded = v2(2, creating(B, 1, PKG_B), boundCreating(C, 2, PKG_C));
                check(problems, !commitWithoutPublication(root, manager, first)
                        && upgraded.equals(storedOf(root, V2)), "upgrade " + storedOf(root, V2));
                check(problems, manager.commit(first), "first original retry refused");
                Header middle = storedOf(root, V2);
                HeaderEntry legacyB = middle == null ? null : entryOf(middle, B);
                check(problems, middle != null && middle.version == 2 && legacyB != null
                        && (cFirst ? legacyB.phase == SlotPhase.CREATING && legacyB.creationBinding == null
                        : legacyB.phase == SlotPhase.LIVE), "B after the first commit " + middle);
                check(problems, manager.commit(second), "second commit refused");
                check(problems, v2(2, live(B), live(C)).equals(storedOf(root, V2))
                        && pm.mSettings.pins.snapshotForWrite().lastId == 2,
                        "result " + storedOf(root, V2));
            });
        }
        run("V2 / a restatement stays version 1, then new C upgrades", problems -> {
            PackageManagerService pm = livePmOf(V2);
            Path root = pm.mSettings.root;
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
            legacyReservation(pm, OLD, PENDING_B);
            check(problems, manager.commit(b) && header(1, live(B)).equals(storedOf(root, V2)),
                    "restatement " + storedOf(root, V2));
            NativePrincipalManager.Handle c = manager.prepare(manager.select(PKG_C, 0));
            check(problems, !commitWithoutPublication(root, manager, c)
                    && v2(2, live(B), boundCreating(C, 2, PKG_C)).equals(storedOf(root, V2)),
                    "upgrade " + storedOf(root, V2));
            check(problems, manager.commit(c) && v2(2, live(B), live(C)).equals(storedOf(root, V2)),
                    "result " + storedOf(root, V2));
        });
        run("V2 / pending and unpublished RETIRING pins reserve together", problems -> {
            PackageManagerService pm = livePmOf(V2);
            Path root = pm.mSettings.root;
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle a = manager.prepare(manager.select(PKG_A, 0));
            NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
            NativePrincipalManager.Handle c = manager.prepare(manager.select(PKG_C, 0));
            pm.mSettings.pins.beginRetire(pm.mSettings.pins.find(PKG_C, 0));
            Header all = v2(3, boundCreating(A, 1, PKG_A), boundCreating(B, 2, PKG_B),
                    boundCreating(C, 3, PKG_C));
            check(problems, !commitWithoutPublication(root, manager, a)
                    && all.equals(storedOf(root, V2)), "reservation " + storedOf(root, V2));
            check(problems, manager.commit(a) && manager.commit(b), "pending commits refused");
            check(problems, manager.beginRetirement(c) && manager.finishRetirementAfterQuiescence(c),
                    "the RETIRING creation did not retire");
            check(problems, v2(3, live(A), live(B)).equals(storedOf(root, V2))
                    && pm.mSettings.pins.snapshotForWrite().lastId == 3, "result " + storedOf(root, V2));
        });
        run("V2 / a held binding refuses another owned signer row", problems -> {
            Header held = v2(1, boundCreating(B, 1, PKG_B));
            Path root = layout(null, bytes(held), bytes(held));
            NativeIdentityPersistence persistence = persistenceOf(root, V2);
            Snapshot own = new Snapshot(1, List.of(record(1, PKG_B, B)));
            NativeIdentityStore.Loaded loaded = persistence.load();
            check(problems, persistence.projectReservation(loaded, plan(own, Map.of(1L, OTHER))) == null,
                    "another signer set admitted");
            check(problems, held.equals(persistence.projectReservation(loaded, plan(own, Map.of()))),
                    "a missing row stranded the held entry");
            check(problems, held.equals(persistence.projectReservation(loaded,
                    plan(own, Map.of(1L, SIGNERS)))), "the matching row refused");
            Snapshot serial = new Snapshot(1, List.of(new Record(1, PKG_B, B, 0, SERIAL + 1)));
            check(problems, persistence.projectReservation(loaded, plan(serial, Map.of())) == null,
                    "another serial admitted");
            unchanged(problems, root, "another signer set",
                    () -> persistence.reservePending(plan(own, Map.of(1L, OTHER))));
        });
        run("V2 / a bound addition is restated exactly or refused", problems -> {
            Header next = v2(2, live(A), boundCreating(D, 2, PKG_D));
            Path root = legacy(v2(1, live(A)), next);
            NativeIdentityPersistence persistence = persistenceOf(root, V2);
            Snapshot own = new Snapshot(2, List.of(record(2, PKG_D, D)));
            NativeIdentityStore.Loaded loaded = persistence.load();
            check(problems, next.equals(persistence.projectReservation(loaded,
                    plan(own, Map.of(2L, SIGNERS)))), "the matching restatement refused");
            check(problems, next.equals(persistence.projectReservation(loaded, plan(own, Map.of()))),
                    "a restatement without a row refused");
            check(problems, persistence.projectReservation(loaded, plan(own, Map.of(2L, OTHER))) == null,
                    "another signer set admitted");
            check(problems, persistence.projectReservation(loaded, plan(new Snapshot(2,
                    List.of(new Record(2, PKG_D, D, 0, SERIAL + 1))), Map.of())) == null,
                    "another serial admitted");
            check(problems, persistence.reservePending(plan(own, Map.of(2L, SIGNERS)))
                    && next.equals(storedOf(root, V2)), "restatement " + storedOf(root, V2));
        });
    }

    // The store's own writer enforces the version rules, whatever a caller proposes.
    private static void lowLevel() {
        run("low level / the version 1 format never writes version 2", problems -> {
            Path root = layout(null, bytes(OLD), bytes(OLD));
            NativeIdentityStore store = storeOf(root, V1);
            unchanged(problems, root, "bound upgrade",
                    () -> store.writeHeader(OLD, v2(1, boundCreating(B, 1, PKG_B))));
            check(problems, store.writeHeader(OLD, PENDING_B) && PENDING_B.equals(stored(root)),
                    "version 1 reservation refused");
        });
        run("low level / a new entry under version 2 needs a complete binding", problems -> {
            Path root = layout(null, bytes(OLD), bytes(OLD));
            NativeIdentityStore store = storeOf(root, V2);
            unchanged(problems, root, "unbound version 1 addition", () -> store.writeHeader(OLD, PENDING_B));
            unchanged(problems, root, "unbound version 2 addition",
                    () -> store.writeHeader(OLD, v2(1, creating(B, 1, PKG_B))));
            Header upgraded = v2(1, boundCreating(B, 1, PKG_B));
            check(problems, store.writeHeader(OLD, upgraded) && upgraded.equals(storedOf(root, V2)),
                    "bound upgrade refused");
            unchanged(problems, root, "unbound addition to version 2", () -> store.writeHeader(upgraded,
                    v2(2, boundCreating(B, 1, PKG_B), creating(C, 2, PKG_C))));
            Header both = v2(2, boundCreating(B, 1, PKG_B), boundCreating(C, 2, PKG_C));
            check(problems, store.writeHeader(upgraded, both) && both.equals(storedOf(root, V2)),
                    "bound addition refused");
        });
        run("low level / a restatement alone never upgrades", problems -> {
            Path root = legacy(OLD, PENDING_B);
            NativeIdentityStore store = storeOf(root, V2);
            unchanged(problems, root, "restatement upgrade",
                    () -> store.writeHeader(OLD, v2(1, creating(B, 1, PKG_B))));
            check(problems, store.writeHeader(OLD, PENDING_B) && PENDING_B.equals(storedOf(root, V2)),
                    "version 1 restatement refused");
            Path filled = legacy(OLD, PENDING_B);
            unchanged(problems, filled, "filled legacy binding", () -> storeOf(filled, V2).writeHeader(OLD,
                    v2(2, boundCreating(B, 1, PKG_B), boundCreating(C, 2, PKG_C))));
            Path upgraded = legacy(OLD, PENDING_B);
            Header target = v2(2, creating(B, 1, PKG_B), boundCreating(C, 2, PKG_C));
            check(problems, storeOf(upgraded, V2).writeHeader(OLD, target)
                    && target.equals(storedOf(upgraded, V2)), "restatement with a new bound entry refused");
        });
        run("low level / relabels and downgrades refuse", problems -> {
            Path root = layout(null, bytes(PENDING_B), bytes(PENDING_B));
            NativeIdentityStore store = storeOf(root, V2);
            unchanged(problems, root, "relabel", () -> store.writeHeader(PENDING_B, v2(1, creating(B, 1, PKG_B))));
            Header boundB = v2(1, boundCreating(B, 1, PKG_B));
            Path other = layout(null, bytes(boundB), bytes(boundB));
            NativeIdentityStore upgraded = storeOf(other, V2);
            unchanged(problems, other, "downgrade", () -> upgraded.writeHeader(boundB, PENDING_B));
            unchanged(problems, other, "downgrade with a phase change",
                    () -> upgraded.writeHeader(boundB, header(1, live(B))));
        });
        run("low level / a binding is never changed, dropped or filled", problems -> {
            Header boundB = v2(1, boundCreating(B, 1, PKG_B));
            Path root = layout(null, bytes(boundB), bytes(boundB));
            NativeIdentityStore store = storeOf(root, V2);
            unchanged(problems, root, "changed signers",
                    () -> store.writeHeader(boundB, v2(1, boundCreating(B, 1, PKG_B, OTHER))));
            unchanged(problems, root, "dropped binding",
                    () -> store.writeHeader(boundB, v2(1, creating(B, 1, PKG_B))));
            Header incomplete = v2(1, creating(B, 1, PKG_B));
            Path other = layout(null, bytes(incomplete), bytes(incomplete));
            unchanged(problems, other, "filled binding",
                    () -> storeOf(other, V2).writeHeader(incomplete, boundB));
        });
        run("low level / an unselected addition is restated exactly", problems -> {
            for (NativeIdentityStore.Format format : List.of(V1, V2)) {
                Path root = legacy(OLD, PENDING_B);
                NativeIdentityStore store = storeOf(root, format);
                unchanged(problems, root, format + " another creation ID",
                        () -> store.writeHeader(OLD, header(2, creating(B, 2, PKG_B))));
                unchanged(problems, root, format + " another package",
                        () -> store.writeHeader(OLD, header(1, creating(B, 1, PKG_X))));
                check(problems, store.writeHeader(OLD, PENDING_B) && PENDING_B.equals(storedOf(root, format)),
                        format + " exact restatement refused");
            }
        });
        run("low level / an upgrade needs a pure reservation", problems -> {
            Header prior = header(1, creating(A, 1, PKG_A));
            Path root = layout(null, bytes(prior), bytes(prior));
            slot(root, A, bound(A, PKG_A, 1, false, 1));
            NativeIdentityStore store = storeOf(root, V2);
            unchanged(problems, root, "mixed upgrade",
                    () -> store.writeHeader(prior, v2(2, live(A), boundCreating(C, 2, PKG_C))));
            check(problems, store.writeHeader(prior, header(1, live(A))), "completion refused");
            check(problems, store.writeHeader(header(1, live(A)), v2(2, live(A),
                    boundCreating(C, 2, PKG_C))), "later upgrade refused");
        });
    }

    // Copies relate across versions only as a version 1 predecessor of a protected version 2
    // reservation. Anything else is incompatible: writes refuse and no counter is restored.
    private static void crossVersion() {
        run("cross version / a V2 target beside V1 predecessors restores only its counter", problems -> {
            Header target = v2(3, creating(A, 1, PKG_A), creating(B, 2, PKG_B),
                    boundCreating(C, 3, PKG_C));
            Path root = layout(bytes(target), bytes(header(1, creating(A, 1, PKG_A))),
                    bytes(header(2, creating(A, 1, PKG_A), creating(B, 2, PKG_B))));
            NativeIdentityStore.Loaded loaded = loadedOf(root, V2);
            check(problems, loaded.header.status == Status.VALID && target.equals(loaded.header.value)
                    && !loaded.unselectedFootprint && loaded.counterRestorable()
                    && loaded.occupiedAppIds.equals(Set.of(A, B, C)), "selection " + loaded.header.status);
            bootCounterOf(problems, root, V2, 3);
            check(problems, storeOf(root, V2).writeHeader(target, target)
                    && target.equals(storedOf(root, V2))
                    && !Files.exists(root.resolve("store.bin-backup"), LinkOption.NOFOLLOW_LINKS),
                    "exact retry refused");
        });
        run("cross version / a V1 selection beside a V2 copy is incompatible", problems -> {
            Header copy = v2(1, boundCreating(B, 1, PKG_B));
            Path root = layout(bytes(OLD), bytes(copy), bytes(copy));
            NativeIdentityStore store = storeOf(root, V2);
            NativeIdentityStore.Loaded loaded = store.load();
            check(problems, OLD.equals(loaded.header.value) && loaded.unselectedFootprint
                    && loaded.occupiedAppIds.contains(B), "view " + loaded.header.status);
            unchanged(problems, root, "selected header", () -> store.writeHeader(OLD, OLD));
            unchanged(problems, root, "owned restatement", () -> persistenceOf(root, V2).reservePending(
                    plan(new Snapshot(1, List.of(record(1, PKG_B, B))), Map.of(1L, SIGNERS))));
            bootCounterOf(problems, root, V2, -1);
        });
        Map<String, Header[]> shapes = new TreeMap<>();
        // Selected, copy, and an owner's restatement of every copy entry.
        shapes.put("a V1 copy at the selected counter", new Header[] {v2(1, live(A)),
                header(1, live(A)), null});
        shapes.put("a V1 copy above the selected counter", new Header[] {v2(1, live(A)),
                header(2, live(A), creating(D, 2, PKG_D)), v2(2, live(A), creating(D, 2, PKG_D))});
        shapes.put("a V1 copy without the newer reservation", new Header[] {v2(2, live(A), live(B)),
                header(1, live(A)), null});
        shapes.put("a V1 copy below a counter only advance", new Header[] {v2(2, live(A)),
                header(1, live(A)), null});
        for (Map.Entry<String, Header[]> shape : shapes.entrySet()) {
            run("cross version / " + shape.getKey() + " is incompatible", problems -> {
                Header selected = shape.getValue()[0];
                Header restatement = shape.getValue()[2];
                Path root = legacy(selected, shape.getValue()[1]);
                NativeIdentityStore store = storeOf(root, V2);
                check(problems, selected.equals(storedOf(root, V2)) && loadedOf(root, V2).unselectedFootprint,
                        "not the constructed selection");
                unchanged(problems, root, "selected header", () -> store.writeHeader(selected, selected));
                if (restatement != null) {
                    unchanged(problems, root, "restatement", () -> store.writeHeader(selected, restatement));
                }
                bootCounterOf(problems, root, V2, -1);
            });
        }
        run("cross version / an interrupted V1 publication then a protected V2 reservation",
                problems -> {
            PackageManagerService pm = livePmOf(V2);
            Path root = pm.mSettings.root;
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle a = manager.prepare(manager.select(PKG_A, 0));
            // A's reservation and body are durable; its completion to LIVE stopped after main.
            copies(root, bytes(header(1, creating(A, 1, PKG_A))), bytes(header(1, live(A))), null);
            slot(root, A, bound(A, PKG_A, 1, false, 1));
            observe(pm);
            NativePrincipalManager.Handle c = manager.prepare(manager.select(PKG_C, 0));
            check(problems, manager.commit(c)
                    && v2(2, creating(A, 1, PKG_A), live(C)).equals(storedOf(root, V2)),
                    "protected upgrade " + storedOf(root, V2));
            check(problems, manager.commit(a) && v2(2, live(A), live(C)).equals(storedOf(root, V2)),
                    "result " + storedOf(root, V2));
        });
    }

    // A complete binding is checked only negatively: every gate refuses a mismatched body or
    // record, keeps its holds and restores nothing from it. A matching body stays usable.
    private static void mismatches() {
        Header held = v2(1, boundCreating(R, 1, PKG_R, TWO));
        Record recordR = record(1, PKG_R, R);
        Map<String, Slot> bodies = new TreeMap<>();
        bodies.put("serial", new Slot(LINEAGE, R, PKG_R, 1, TWO,
                List.of(new UserEntry(1, 0, SERIAL + 1, false))));
        bodies.put("signer subset", new Slot(LINEAGE, R, PKG_R, 1, Set.of("6".repeat(64)),
                List.of(new UserEntry(1, 0, SERIAL, false))));
        bodies.put("signer superset", new Slot(LINEAGE, R, PKG_R, 1,
                Set.of("6".repeat(64), "7".repeat(64), "8".repeat(64)),
                List.of(new UserEntry(1, 0, SERIAL, false))));
        bodies.put("disjoint signers", new Slot(LINEAGE, R, PKG_R, 1, Set.of("9".repeat(64)),
                List.of(new UserEntry(1, 0, SERIAL, false))));
        bodies.put("zero users", new Slot(LINEAGE, R, PKG_R, 1, TWO, List.of()));
        bodies.put("two users", new Slot(LINEAGE, R, PKG_R, 1, TWO,
                List.of(new UserEntry(1, 0, SERIAL, false), new UserEntry(2, 10, SERIAL, false))));
        for (Map.Entry<String, Slot> body : bodies.entrySet()) {
            run("binding mismatch / " + body.getKey(), problems -> {
                Path root = layout(null, bytes(held), bytes(held));
                slot(root, R, body.getValue());
                NativeIdentityStore store = storeOf(root, V2);
                NativeIdentityStore.Loaded loaded = store.load();
                NativeIdentityStore.ReadResult<Slot> read = loaded.slots.get(R);
                // The counter admission correction: two users decode principal ID 2 above counter
                // 1 in an unsupported record, which blocks creation. Every other body stays at or
                // below the counter and keeps creation ready. Only this readiness changed.
                boolean ready = !body.getKey().equals("two users");
                check(problems, read != null && read.status != Status.VALID && !loaded.bindingUsable(R)
                        && loaded.occupiedAppIds.contains(R) && loaded.creationReady() == ready,
                        "load " + (read == null ? null : read.status) + " ready " + loaded.creationReady());
                unchanged(problems, root, "completion", () -> store.writeHeader(held, v2(1, live(R))));
                unchanged(problems, root, "publication",
                        () -> persistenceOf(root, V2).publish(recordR, TWO));
                Map<String, String> slotsBefore = footprint(root.resolve("slots"));
                check(problems, !store.resumeCreatingDirectory(held, R)
                        && footprint(root.resolve("slots")).equals(slotsBefore)
                        && sameBytes(root.resolve("store.bin"), bytes(held)), "resume accepted");
                PackageManagerService pm = reopenOf(root, V2, Map.of(PKG_R, R));
                check(problems, pm.mSettings.pins.find(PKG_R, 0) == null
                        && pm.mSettings.isNativePrincipalAppIdLPr(R), "restored from a mismatch");
                Path empty = layout(null, bytes(held), bytes(held));
                Path directory = Files.createDirectory(empty.resolve("slots/" + R));
                check(problems, !storeOf(empty, V2).publishCreatingSlot(held, body.getValue())
                        && emptyDirectory(directory), "mismatched body published");
            });
        }
        run("binding mismatch / another user", problems -> {
            Header other = v2(1, new HeaderEntry(R, SlotPhase.CREATING, 1, PKG_R,
                    new CreationBinding(10, SERIAL, TWO)));
            Path root = layout(null, bytes(other), bytes(other));
            slot(root, R, new Slot(LINEAGE, R, PKG_R, 1, TWO, List.of(new UserEntry(1, 0, SERIAL, false))));
            NativeIdentityStore.Loaded loaded = loadedOf(root, V2);
            check(problems, loaded.slots.get(R).status == Status.CONFLICT && !loaded.bindingUsable(R),
                    "load " + loaded.slots.get(R).status);
            unchanged(problems, root, "completion",
                    () -> storeOf(root, V2).writeHeader(other, v2(1, live(R))));
        });
        run("binding mismatch / publication of another serial or signer set", problems -> {
            Path root = layout(null, bytes(held), bytes(held));
            NativeIdentityPersistence persistence = persistenceOf(root, V2);
            unchanged(problems, root, "another serial",
                    () -> persistence.publish(new Record(1, PKG_R, R, 0, SERIAL + 1), TWO));
            unchanged(problems, root, "a signer subset",
                    () -> persistence.publish(recordR, Set.of("6".repeat(64))));
            unchanged(problems, root, "a signer superset", () -> persistence.publish(recordR,
                    Set.of("6".repeat(64), "7".repeat(64), "8".repeat(64))));
            check(problems, persistence.publish(recordR, TWO) && v2(1, live(R)).equals(storedOf(root, V2)),
                    "exact publication refused " + storedOf(root, V2));
        });
        for (boolean retiring : List.of(false, true)) {
            run("binding match / " + (retiring ? "a retiring" : "an active") + " body is usable",
                    problems -> {
                Path root = layout(null, bytes(held), bytes(held));
                slot(root, R, new Slot(LINEAGE, R, PKG_R, retiring ? 2 : 1, TWO,
                        List.of(new UserEntry(1, 0, SERIAL, retiring))));
                NativeIdentityStore.Loaded loaded = loadedOf(root, V2);
                check(problems, loaded.slots.get(R).status == Status.VALID && loaded.bindingUsable(R),
                        "matching body refused " + loaded.slots.get(R).status);
                PackageManagerService pm = reopenOf(root, V2, Map.of(PKG_R, R));
                NativePrincipalPins.Pin pin = pm.mSettings.pins.find(PKG_R, 0);
                check(problems, pin != null && pin.phase() == (retiring ? NativePrincipalPins.Phase.RETIRING
                        : NativePrincipalPins.Phase.PENDING), "restored phase");
                check(problems, storeOf(root, V2).writeHeader(held, v2(1, live(R)))
                        && v2(1, live(R)).equals(storedOf(root, V2)), "completion refused");
            });
        }
        run("binding / a published body stays usable beside a later reservation", problems -> {
            Header pending = v2(1, boundCreating(C, 1, PKG_C));
            Path root = layout(null, bytes(pending), bytes(pending));
            // C's body is published and its completion to LIVE was lost.
            slot(root, C, bound(C, PKG_C, 1, false, 1));
            NativeIdentityPersistence persistence = persistenceOf(root, V2);
            Snapshot later = new Snapshot(2, List.of(record(1, PKG_C, C), record(2, PKG_D, D)));
            check(problems, persistence.reservePending(plan(later, Map.of(1L, SIGNERS, 2L, SIGNERS))),
                    "later reservation refused");
            NativeIdentityStore.Loaded loaded = persistence.load();
            check(problems, v2(2, boundCreating(C, 1, PKG_C), boundCreating(D, 2, PKG_D))
                    .equals(loaded.header.value) && loaded.slots.get(C).status == Status.VALID
                    && loaded.bindingUsable(C), "C conflicted beside D");
            check(problems, persistence.publish(record(1, PKG_C, C), SIGNERS)
                    && v2(2, live(C), boundCreating(D, 2, PKG_D)).equals(storedOf(root, V2)),
                    "C completion refused");
            PackageManagerService pm = livePmOf(V2);
            Path liveRoot = pm.mSettings.root;
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
            check(problems, manager.commit(b), "B commit refused");
            NativePrincipalManager.Handle a = manager.prepare(manager.select(PKG_A, 0));
            check(problems, !commitWithoutPublication(liveRoot, manager, a), "A published read only");
            NativeIdentityStore.Loaded beside = loadedOf(liveRoot, V2);
            check(problems, v2(2, live(B), boundCreating(A, 2, PKG_A)).equals(beside.header.value)
                    && beside.slots.get(B).status == Status.VALID && beside.bindingUsable(B),
                    "B conflicted beside A's reservation");
        });
    }

    // A failed complete creation binding keeps all of its record's decoded copies as negative
    // package and principal evidence for siblings, also beside an ordinary conflict. Each
    // layout has R's CREATING creation 1 and N's LIVE entry under counter 2. It is read bound,
    // with R's version 2 binding of user 0, serial 7 and a signer set, and as its bindings
    // cleared twin under the version 1 format of the rollback reader, then reopened in a host
    // PMS facade.
    // The bound layout never makes more usable, holds the same IDs and is never readier.
    // Without an ordinary conflict for R, N fares the same in both. An ordinary conflict alone
    // stays no evidence. Expected statuses are R's, then N's. Host facades only.
    private static void siblingEvidence() {
        Set<String> s0 = Set.of("a0".repeat(32)), s1 = Set.of("b1".repeat(32));
        String pkgN = "dev.andrix.n", both = "CONFLICT CONFLICT";
        Slot bodyR = userBody(B, PKG_R, 1, SERIAL, s1);
        Slot packageN = userBody(C, PKG_R, 2, SERIAL, s1);
        Slot principalN = userBody(C, pkgN, 1, SERIAL, s1);
        Slot bothN = userBody(C, PKG_R, 1, SERIAL, s1);
        Slot unrelatedN = userBody(C, pkgN, 2, SERIAL, s1);
        evidence("package only collision", B, C, PKG_R, s0, null, bodyR, packageN, both, both);
        evidence("principal only collision", B, C, PKG_R, s0, null, bodyR, principalN, both, both);
        evidence("package and principal collision", B, C, PKG_R, s0, null, bodyR, bothN, both, both);
        evidence("an unrelated sibling stays usable", B, C, PKG_R, s0, null, bodyR, unrelatedN,
                "VALID VALID", "CONFLICT VALID");
        evidence("a serial mismatch keeps package evidence", B, C, PKG_R, s1, null,
                userBody(B, PKG_R, 1, SERIAL + 1, s1), packageN, both, both);
        evidence("a tombstone keeps package evidence", B, C, PKG_R, s1, null,
                new Slot(LINEAGE, B, PKG_R, 1, s1, List.of()), packageN, both, both);
        // R at the higher app ID and N at the lower one.
        evidence("swapped app IDs keep package evidence", C, B, PKG_R, s0, null,
                userBody(C, PKG_R, 1, SERIAL, s1), userBody(B, PKG_R, 2, SERIAL, s1), both, both);
        // The preferred backup binds R to its body's signers, main and reserve to others. The
        // header copies are incompatible, so the counter is withheld. Beside a collision R
        // would conflict anyway; the unrelated sibling shows that every copy is checked.
        evidence("unselected copies failing the binding beside a collision", B, C, PKG_R, s0, s1,
                bodyR, packageN, both, both);
        evidence("unselected copies failing the binding beside an unrelated sibling", B, C, PKG_R,
                s0, s1, bodyR, unrelatedN, "VALID VALID", "CONFLICT VALID");
        evidence("a matching binding keeps ordinary duplicates", B, C, PKG_R, s1, null, bodyR, bothN,
                both, both);
        // R's header names another package than its body. Version 1 keeps N usable as before.
        // Under version 2 the same R also fails its binding, which withdraws N.
        evidence("an ordinary conflict alone keeps N, a failed binding withdraws it", B, C,
                "dev.andrix.q", s0, null, bodyR, packageN, "CONFLICT VALID", both);
        run("binding conflict evidence / version 1 reads bound collisions as c9264e4 does",
                problems -> {
            for (Slot sibling : List.of(packageN, principalN, bothN)) {
                Header held = v2(2, boundCreating(B, 1, PKG_R, s0), live(C));
                Header twin = header(2, creating(B, 1, PKG_R), live(C));
                Path bound = layout(null, bytes(held), bytes(held));
                Path cleared = layout(null, bytes(twin), bytes(twin));
                for (Path root : List.of(bound, cleared)) {
                    slot(root, B, bodyR);
                    slot(root, C, sibling);
                }
                View twinView = view(problems, cleared, V1, B, C, both, bodyR, sibling, 2);
                // The reviewed c9264e4 reader has no binding check: R stays VALID there and
                // meets N in the duplicate checks, so both conflict.
                NativeIdentityStore.Loaded older = loadedOf(bound, V1);
                check(problems, older.header.status == Status.UNSUPPORTED && older.unsupportedFootprint
                        && older.slots.get(B).status == Status.CONFLICT
                        && older.slots.get(C).status == Status.CONFLICT
                        && !older.bindingUsable(B) && !older.bindingUsable(C)
                        && older.occupiedAppIds.equals(twinView.holds)
                        && !older.creationReady() && !older.counterRestorable(),
                        "version 1 view " + older.header.status + " " + older.slots.get(B).status
                        + " " + older.slots.get(C).status);
                NativeIdentityStore store = storeOf(bound, V1);
                unchanged(problems, bound, "version 1 header write", () -> store.writeHeader(held, held));
                unchanged(problems, bound, "version 1 slot confirmation",
                        () -> store.confirmExistingSlot(sibling));
                PackageManagerService reader = reopen(bound, Map.of());
                check(problems, !reader.mSettings.pins.hasKnownCounter()
                        && reader.mSettings.pins.reservedAppIds().isEmpty()
                        && !reader.mSettings.nativePrincipalCreationReadyLPr()
                        && reader.mSettings.isNativePrincipalAppIdLPr(B)
                        && reader.mSettings.isNativePrincipalAppIdLPr(C), "version 1 registry");
            }
        });
        staleSlotEvidence(s0, s1);
    }

    // A preferred slot backup chooses R's body, but every decoded sibling copy remains
    // negative evidence after the complete binding withdraws R. No stale copy is history.
    private static void staleSlotEvidence(Set<String> headerSigners, Set<String> bodySigners) {
        for (boolean matching : List.of(false, true)) {
            for (boolean packageCollision : List.of(true, false)) {
                String kind = packageCollision ? "package" : "principal";
                String name = matching ? "matching binding ignores unselected " + kind + " body"
                        : "unselected slot copy keeps " + kind + " evidence";
                run("binding conflict evidence / " + name, problems -> {
                    String other = "dev.andrix.other";
                    Slot selected = userBody(B, PKG_R, 1, SERIAL, bodySigners);
                    Slot unselected = userBody(B, packageCollision ? other : PKG_R,
                            packageCollision ? 1 : 2, SERIAL, bodySigners);
                    Slot sibling = userBody(C, packageCollision ? other : PKG_C, 2, SERIAL, bodySigners);
                    Header bound = v2(2, boundCreating(B, 1, PKG_R,
                            matching ? bodySigners : headerSigners), live(C));
                    Header twin = header(2, creating(B, 1, PKG_R), live(C));
                    Path held = layout(null, bytes(bound), bytes(bound));
                    Path cleared = layout(null, bytes(twin), bytes(twin));
                    for (Path root : List.of(held, cleared)) {
                        slot(root, B, selected);
                        Path directory = root.resolve("slots/" + B);
                        Files.write(directory.resolve("record.bin-backup"),
                                NativeIdentityRecords.encodeSlot(selected));
                        // Main alone carries stale package evidence, reserve alone carries
                        // stale principal evidence. First-only and last-only defects differ.
                        Files.write(directory.resolve(packageCollision ? "record.bin" : "record.bin.reservecopy"),
                                NativeIdentityRecords.encodeSlot(unselected));
                        slot(root, C, sibling);
                    }
                    View before = view(problems, cleared, V1, B, C, "VALID VALID", selected, sibling, 2);
                    View after = view(problems, held, V2, B, C,
                            matching ? "VALID VALID" : "CONFLICT CONFLICT", selected, sibling, 2);
                    check(problems, before.usable.containsAll(after.usable)
                            && before.holds.equals(after.holds)
                            && (before.creation || !after.creation) && (before.counter || !after.counter),
                            "unselected slot bytes became positive history or lost a hold");
                    for (NativeIdentityStore.Format format : List.of(V1, V2)) {
                        Path root = format == V1 ? cleared : held;
                        NativePrincipalPins.Pin pin = reopenOf(root, format, Map.of()).mSettings.pins.findId(1);
                        check(problems, pin == null ? format == V2 && !matching
                                : pin.record().equals(record(1, PKG_R, B)),
                                "restoration used an unselected slot package or principal");
                    }
                });
            }
        }
    }

    private static Slot userBody(int appId, String name, long id, long serial,
            Set<String> signers) {
        return new Slot(LINEAGE, appId, name, 1, signers, List.of(new UserEntry(id, 0, serial, false)));
    }

    // One read of a sibling layout, then its reopened host PMS facade.
    private static final class View {
        final Set<Integer> usable = new TreeSet<>(), holds = new TreeSet<>();
        boolean creation, counter;
        String sibling;

        @Override
        public String toString() {
            return "usable " + usable + ", holds " + holds + ", creation " + creation + ", counter "
                    + counter;
        }
    }

    // Checks one read against the expected statuses of R and N. A VALID body with a user is
    // usable and restored as a pin, and every other record keeps only its hold. counter is the
    // counter the reopened registry restores, or negative for none.
    private static View view(List<String> problems, Path root, NativeIdentityStore.Format format,
            int appR, int appN, String statuses, Slot bodyR, Slot bodyN, long counter) {
        View view = new View();
        NativeIdentityStore.Loaded loaded = loadedOf(root, format);
        String seen = loaded.slots.get(appR).status + " " + loaded.slots.get(appN).status;
        check(problems, seen.equals(statuses), format + " R and N " + seen);
        String[] expected = statuses.split(" ");
        Set<Integer> usable = new TreeSet<>();
        if (expected[0].equals("VALID") && !bodyR.users.isEmpty()) usable.add(appR);
        if (expected[1].equals("VALID") && !bodyN.users.isEmpty()) usable.add(appN);
        for (int appId : List.of(appR, appN)) {
            if (loaded.bindingUsable(appId)) view.usable.add(appId);
        }
        view.holds.addAll(loaded.occupiedAppIds);
        check(problems, view.usable.equals(usable) && view.holds.equals(Set.of(appR, appN))
                && loaded.creationReady() && !loaded.unsupportedFootprint
                && !loaded.unavailableFootprint && loaded.counterRestorable() == (counter >= 0),
                format + " read " + view);
        PackageManagerService pm = reopenOf(root, format, Map.of());
        Set<Integer> pins = pm.mSettings.pins.reservedAppIds();
        check(problems, pins.equals(usable) && pm.mSettings.isNativePrincipalAppIdLPr(appR)
                && pm.mSettings.isNativePrincipalAppIdLPr(appN), format + " reopened pins " + pins);
        bootCounterOf(problems, root, format, counter);
        view.creation = loaded.creationReady() && pm.mSettings.nativePrincipalCreationReadyLPr();
        view.counter = loaded.counterRestorable() && pm.mSettings.pins.hasKnownCounter();
        view.sibling = loaded.slots.get(appN).status + " " + loaded.bindingUsable(appN) + " "
                + pins.contains(appN);
        return view;
    }

    // A bound layout and its bindings cleared twin. selected, when not null, binds R instead in
    // a preferred backup copy of the bound header, beside main and reserve copies of bound.
    private static void evidence(String name, int appR, int appN, String packageR,
            Set<String> bound, Set<String> selected, Slot bodyR, Slot bodyN, String twinStatuses,
            String boundStatuses) {
        run("binding conflict evidence / " + name, problems -> {
            Header twin = header(2, creating(appR, 1, packageR), live(appN));
            Header held = v2(2, boundCreating(appR, 1, packageR, bound), live(appN));
            byte[] backup = selected == null ? null
                    : bytes(v2(2, boundCreating(appR, 1, packageR, selected), live(appN)));
            Path cleared = layout(backup == null ? null : bytes(twin), bytes(twin), bytes(twin));
            Path within = layout(backup, bytes(held), bytes(held));
            for (Path root : List.of(cleared, within)) {
                slot(root, appR, bodyR);
                slot(root, appN, bodyN);
            }
            View twinView = view(problems, cleared, V1, appR, appN, twinStatuses, bodyR, bodyN, 2);
            View boundView = view(problems, within, V2, appR, appN, boundStatuses, bodyR, bodyN,
                    backup == null ? 2 : -1);
            check(problems, twinView.usable.containsAll(boundView.usable)
                    && twinView.holds.equals(boundView.holds)
                    && (twinView.creation || !boundView.creation)
                    && (twinView.counter || !boundView.counter),
                    "bound " + boundView + " beyond its twin " + twinView);
            // Without an ordinary conflict for R, the binding changes nothing for N.
            if (packageR.equals(bodyR.packageName)) {
                check(problems, twinView.sibling.equals(boundView.sibling),
                        "N " + boundView.sibling + " beside its twin " + twinView.sibling);
            }
        });
    }

    // A restored binding has no issuance in this manager. Its durable entry stays as it is,
    // and nothing copies current package signers into it.
    private static void restored() {
        Header held = v2(1, boundCreating(R, 1, PKG_R));
        run("restored R / unrelated N reserves beside it without a row", problems -> {
            Path root = layout(null, bytes(held), bytes(held));
            slot(root, R, bound(R, PKG_R, 1, false, 1));
            PackageManagerService pm = reopenOf(root, V2, Map.of(PKG_R, R, PKG_B, B));
            NativePrincipalPins.Pin pin = pm.mSettings.pins.find(PKG_R, 0);
            check(problems, pin != null && pin.issuance() == null && pm.mSettings.pins.hasKnownCounter(),
                    "R not restored beside a known counter");
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle n = manager.prepare(manager.select(PKG_B, 0));
            check(problems, manager.identity(n).id == 2 && manager.commit(n), "N refused beside R");
            check(problems, v2(2, boundCreating(R, 1, PKG_R), live(B)).equals(storedOf(root, V2)),
                    "R changed " + storedOf(root, V2));
            NativePrincipalManager.Handle r = manager.prepare(manager.select(PKG_R, 0));
            check(problems, pm.mSettings.pins.find(PKG_R, 0).issuance() == null,
                    "an explicit rebind added issuance");
            check(problems, manager.commit(r) && v2(2, live(R), live(B)).equals(storedOf(root, V2)),
                    "R's own rebind refused " + storedOf(root, V2));
        });
        run("restored R / a changed APK signer refuses only R's own rebind", problems -> {
            Path root = layout(null, bytes(held), bytes(held));
            slot(root, R, bound(R, PKG_R, 1, false, 1));
            PackageManagerService pm = reopenOf(root, V2, Map.of(PKG_R, R, PKG_B, B));
            pm.mSettings.packages.get(PKG_R).signing = signing(5, 2);
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle n = manager.prepare(manager.select(PKG_B, 0));
            check(problems, manager.commit(n), "N refused beside R's changed APK");
            age(root);
            Map<String, String> before = footprint(root);
            check(problems, throwsType(() -> manager.prepare(manager.select(PKG_R, 0)),
                    IllegalStateException.class), "R rebound to its current signer");
            check(problems, footprint(root).equals(before)
                    && v2(2, boundCreating(R, 1, PKG_R), live(B)).equals(storedOf(root, V2)),
                    "R's binding changed " + storedOf(root, V2));
        });
        run("restored R / a mismatched body is a conflict that keeps its header", problems -> {
            Path root = layout(null, bytes(held), bytes(held));
            slot(root, R, new Slot(LINEAGE, R, PKG_R, 1, SIGNERS,
                    List.of(new UserEntry(1, 0, SERIAL + 1, false))));
            PackageManagerService pm = reopenOf(root, V2, Map.of(PKG_R, R, PKG_B, B));
            NativeIdentityStore.Loaded loaded = pm.mSettings.persistence.load();
            check(problems, pm.mSettings.pins.find(PKG_R, 0) == null
                    && loaded.slots.get(R).status == Status.CONFLICT
                    && pm.mSettings.isNativePrincipalAppIdLPr(R), "R restored from a mismatched body");
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle n = manager.prepare(manager.select(PKG_B, 0));
            check(problems, manager.commit(n)
                    && v2(2, boundCreating(R, 1, PKG_R), live(B)).equals(storedOf(root, V2)),
                    "N refused or R's header changed " + storedOf(root, V2));
        });
    }

    // Plan rows come from the original issuance, never the current PackageSetting. The real
    // designation gates are unchanged. A host facade is not proof of actual disposal.
    private static void signerMutation() {
        run("signer mutation / Q reserves P with its original signers", problems -> {
            PackageManagerService pm = livePmOf(V2);
            Path root = pm.mSettings.root;
            SigningDetails qSigning = signing(3, 3);
            Set<String> qSigners = digests(qSigning);
            pm.mSettings.packages.get(PKG_B).signing = qSigning;
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle p = manager.prepare(manager.select(PKG_A, 0));
            NativePrincipalManager.Handle q = manager.prepare(manager.select(PKG_B, 0));
            pm.mSettings.packages.get(PKG_A).signing = signing(4, 1);
            age(root);
            Map<String, String> before = footprint(root);
            check(problems, throwsType(() -> manager.commit(p), IllegalStateException.class)
                    && footprint(root).equals(before), "P committed with a replaced signer");
            check(problems, manager.commit(q), "Q stranded by P's replaced signer");
            check(problems, v2(2, boundCreating(A, 1, PKG_A), live(B)).equals(storedOf(root, V2)),
                    "P not reserved with its original signers " + storedOf(root, V2));
            Slot qBody = loadedOf(root, V2).slots.get(B).value;
            check(problems, qBody != null && qSigners.equals(qBody.signerSha256), "Q body signers");
            check(problems, manager.beginRetirement(p), "P's retirement refused");
            NativeIdentityStore.Loaded marked = loadedOf(root, V2);
            Slot pBody = marked.slots.get(A).value;
            check(problems, pBody != null && SIGNERS.equals(pBody.signerSha256)
                    && pBody.users.get(0).retiring && v2(2, live(A), live(B)).equals(marked.header.value),
                    "P not marked with its historical binding " + marked.header.value);
            check(problems, manager.finishRetirementAfterQuiescence(p)
                    && v2(2, live(B)).equals(storedOf(root, V2)), "P's retirement " + storedOf(root, V2));
        });
        run("signer mutation / a durable P reservation does not strand Q", problems -> {
            PackageManagerService pm = livePmOf(V2);
            Path root = pm.mSettings.root;
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle p = manager.prepare(manager.select(PKG_A, 0));
            check(problems, !commitWithoutPublication(root, manager, p)
                    && v2(1, boundCreating(A, 1, PKG_A)).equals(storedOf(root, V2)),
                    "P reservation " + storedOf(root, V2));
            pm.mSettings.packages.get(PKG_A).signing = signing(4, 1);
            pm.mSettings.packages.get(PKG_B).signing = signing(3, 3);
            NativePrincipalManager.Handle q = manager.prepare(manager.select(PKG_B, 0));
            check(problems, manager.commit(q), "Q stranded by P's replaced signer");
            check(problems, v2(2, boundCreating(A, 1, PKG_A), live(B)).equals(storedOf(root, V2)),
                    "result " + storedOf(root, V2));
            check(problems, throwsType(() -> manager.commit(p), IllegalStateException.class),
                    "P committed with a replaced signer");
            check(problems, manager.beginRetirement(p) && manager.finishRetirementAfterQuiescence(p)
                    && v2(2, live(B)).equals(storedOf(root, V2)), "P's retirement " + storedOf(root, V2));
        });
    }

    // The host version 2 format keeps every footprint and presence rule, one version up.
    private static void gates() {
        for (int version : List.of(3, 65535)) {
            for (String position : List.of("store.bin", "store.bin.reservecopy", "store.bin-backup",
                    "store.bin-seed")) {
                run("V2 gate / header version " + version + " in " + position, problems -> {
                    Header healthy = v2(1, live(A));
                    Path root = layout(null, bytes(healthy), bytes(healthy));
                    slot(root, A, bound(A, PKG_A, 1, false, 1));
                    Files.write(root.resolve(position), frame(1, version,
                            concat(body(bytes(v2(9, live(A), live(E)))), new byte[] {0x33, 0x33})));
                    NativeIdentityStore store = storeOf(root, V2);
                    NativeIdentityStore.Loaded loaded = store.load();
                    boolean copy = !position.endsWith("-seed");
                    check(problems, loaded.unsupportedFootprint && !loaded.creationReady()
                            && loaded.occupiedAppIds.contains(A) && !loaded.occupiedAppIds.contains(E),
                            "view " + loaded.header.status + " " + loaded.occupiedAppIds);
                    check(problems, copy ? loaded.header.status == Status.UNSUPPORTED
                            && !loaded.bindingUsable(A) : loaded.header.status == Status.VALID
                            && loaded.bindingUsable(A), "binding eligibility " + loaded.header.status);
                    unchanged(problems, root, "header rewrite", () -> store.writeHeader(healthy, healthy));
                    unchanged(problems, root, "slot confirmation",
                            () -> store.confirmExistingSlot(bound(A, PKG_A, 1, false, 1)));
                    unchanged(problems, root, "initialization", () -> store.initializeNew(LINEAGE));
                    bootCounterOf(problems, root, V2, -1);
                });
            }
        }
        run("V2 gate / malformed and damaged version 2 frames are damage", problems -> {
            Header healthy = v2(1, boundCreating(B, 1, PKG_B));
            byte[] good = bytes(healthy);
            // The binding tag of B's entry: frame, lineage, counter, count, then the entry.
            int tag = 12 + 16 + 8 + 2 + 4 + 1 + 8 + 2 + PKG_B.length();
            byte[] unknownTag = good.clone();
            unknownTag[tag] = 2;
            byte[] malformed = resealed(unknownTag);
            byte[] damaged = good.clone();
            damaged[damaged.length - 1] ^= 1;
            for (byte[] bad : List.of(malformed, damaged)) {
                Path root = layout(null, good, bad);
                NativeIdentityStore store = storeOf(root, V2);
                NativeIdentityStore.Loaded loaded = store.load();
                check(problems, loaded.header.status == Status.VALID && healthy.equals(loaded.header.value)
                        && !loaded.unsupportedFootprint && loaded.creationReady(),
                        "damage read as a footprint " + loaded.header.status);
                check(problems, store.writeHeader(healthy, healthy)
                        && sameBytes(root.resolve("store.bin.reservecopy"), good), "owned rewrite refused");
            }
            Path root = layout(null, bytes(OLD), malformed);
            NativeIdentityStore.Loaded older = loadedOf(root, V1);
            check(problems, older.header.status == Status.UNSUPPORTED && older.unsupportedFootprint,
                    "the version 1 format read an intact version 2 frame as damage");
        });
        for (NativeIdentityStore.Format format : List.of(V1, V2)) {
            run("V2 gate / version 2 slot frames are footprints under " + format, problems -> {
                Header liveA = header(1, live(A));
                Path root = layout(null, bytes(liveA), bytes(liveA));
                slot(root, A, bound(A, PKG_A, 1, false, 1));
                Files.write(root.resolve("slots/" + A + "/record.bin"),
                        relabeled(NativeIdentityRecords.encodeSlot(bound(A, PKG_A, 1, false, 1)), 2));
                NativeIdentityStore store = storeOf(root, format);
                NativeIdentityStore.Loaded loaded = store.load();
                check(problems, loaded.slots.get(A).status == Status.UNSUPPORTED && loaded.unsupportedFootprint
                        && !loaded.bindingUsable(A) && loaded.occupiedAppIds.contains(A),
                        "view " + loaded.slots.get(A).status);
                unchanged(problems, root, "slot confirmation",
                        () -> store.confirmExistingSlot(bound(A, PKG_A, 1, false, 1)));
                unchanged(problems, root, "header rewrite", () -> store.writeHeader(liveA, liveA));
            });
        }
        run("V2 gate / initialization writes an empty version 1 header", problems -> {
            Path root = fresh();
            NativeIdentityStore store = storeOf(root, V2);
            check(problems, store.initializeNew(LINEAGE) && sameBytes(root.resolve("store.bin"), GOLDEN_EMPTY_V1)
                    && sameBytes(root.resolve("store.bin.reservecopy"), GOLDEN_EMPTY_V1),
                    "initialization bytes");
            check(problems, store.initializeNew(LINEAGE), "exact retry refused");
            Path upgraded = layout(null, bytes(v2(0)), bytes(v2(0)));
            check(problems, !storeOf(upgraded, V2).initializeNew(LINEAGE),
                    "a version 2 header read as a fresh store");
        });
    }

    // Phase changes, markers, omission and a later reservation keep version 2.
    private static void versionPreserved() {
        run("V2 / publication, marker, release and a later reservation keep version 2", problems -> {
            PackageManagerService pm = livePmOf(V2);
            Path root = pm.mSettings.root;
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
            check(problems, manager.commit(b) && v2(1, live(B)).equals(storedOf(root, V2)), "publication");
            check(problems, manager.beginRetirement(b) && v2(1, live(B)).equals(storedOf(root, V2)), "marker");
            check(problems, manager.finishRetirementAfterQuiescence(b) && v2(1).equals(storedOf(root, V2)),
                    "release " + storedOf(root, V2));
            NativePrincipalManager.Handle c = manager.prepare(manager.select(PKG_C, 0));
            check(problems, !commitWithoutPublication(root, manager, c)
                    && v2(2, boundCreating(C, 2, PKG_C)).equals(storedOf(root, V2)),
                    "later reservation " + storedOf(root, V2));
            check(problems, manager.commit(c) && v2(2, live(C)).equals(storedOf(root, V2)),
                    "later publication " + storedOf(root, V2));
        });
    }

    // The version 1 format, the rollback reader model, reads every version 2 layout the host format
    // writes as unsupported and read only. It keeps each known hold and restores no counter or
    // binding.
    private static void v1Readers() {
        run("V1 reader / version 2 layouts stay read only with every hold", problems -> {
            List<Path> layouts = new ArrayList<>();
            PackageManagerService fresh = livePmOf(V2);
            NativePrincipalManager first = new NativePrincipalManager(fresh);
            check(problems, !commitWithoutPublication(fresh.mSettings.root, first,
                    first.prepare(first.select(PKG_B, 0))), "bound reservation published");
            layouts.add(fresh.mSettings.root);
            PackageManagerService published = livePmOf(V2);
            NativePrincipalManager second = new NativePrincipalManager(published);
            check(problems, second.commit(second.prepare(second.select(PKG_B, 0))), "publication refused");
            layouts.add(published.mSettings.root);
            PackageManagerService legacy = livePmOf(V2);
            NativePrincipalManager third = new NativePrincipalManager(legacy);
            third.prepare(third.select(PKG_B, 0));
            legacyReservation(legacy, OLD, PENDING_B);
            NativePrincipalManager.Handle c = third.prepare(third.select(PKG_C, 0));
            check(problems, third.commit(c), "upgrade beside legacy B refused");
            layouts.add(legacy.mSettings.root);
            layouts.add(layout(bytes(v2(1, boundCreating(B, 1, PKG_B))), bytes(OLD), bytes(OLD)));
            for (Path root : layouts) {
                NativeIdentityStore.Loaded current = loadedOf(root, V2);
                NativeIdentityStore.Loaded older = loadedOf(root, V1);
                check(problems, current.header.status == Status.VALID
                        && current.header.value.version == 2, root + " is not a version 2 layout");
                check(problems, older.header.status == Status.UNSUPPORTED && older.unsupportedFootprint
                        && !older.creationReady() && !older.counterRestorable()
                        && older.occupiedAppIds.equals(current.occupiedAppIds), root + " version 1 view");
                for (int appId : current.occupiedAppIds) {
                    check(problems, !older.bindingUsable(appId), root + " binding of " + appId);
                }
                NativeIdentityStore store = storeOf(root, V1);
                Header selected = current.header.value;
                unchanged(problems, root, "version 1 header write", () -> store.writeHeader(selected, selected));
                unchanged(problems, root, "version 1 initialization", () -> store.initializeNew(LINEAGE));
                for (NativeIdentityStore.ReadResult<Slot> read : current.slots.values()) {
                    if (read.status != Status.VALID) continue;
                    unchanged(problems, root, "version 1 slot confirmation",
                            () -> store.confirmExistingSlot(read.value));
                }
                PackageManagerService reader = reopen(root, Map.of());
                check(problems, !reader.mSettings.pins.hasKnownCounter()
                        && reader.mSettings.pins.reservedAppIds().isEmpty()
                        && !reader.mSettings.nativePrincipalCreationReadyLPr(), root + " version 1 registry");
                for (int appId : current.occupiedAppIds) {
                    check(problems, reader.mSettings.isNativePrincipalAppIdLPr(appId), root + " lost " + appId);
                }
            }
        });
    }

    public static void main(String[] args) throws Exception {
        if (!NativeCreationBindingTest.class.desiredAssertionStatus()) {
            throw new AssertionError("run with java -ea");
        }
        if (!LINEAGE.equals(Settings.LINEAGE)) throw new AssertionError("facade lineage");
        start(Path.of(args[0]).resolve("creation-binding"));
        requireDac(Path.of(args[0]).resolve("creation-binding-dac"));
        LocalServices.addService(UserManagerInternal.class, new UserManagerInternal());
        plans();
        provenance();
        golden();
        encodedLengths();
        byteAdmission();
        projection();
        lowLevel();
        crossVersion();
        mismatches();
        siblingEvidence();
        restored();
        signerMutation();
        gates();
        versionPreserved();
        v1Readers();
        finish(Os.allClosed());
        System.out.println("Complete creation bindings and exact byte admission; Android crash"
                + " recovery and version 2 activation unqualified");
    }
}
