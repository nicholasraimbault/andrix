// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeBindingTestSupport.*;
import static com.android.server.pm.NativeHeaderTestSupport.*;

import android.content.pm.Signature;
import android.content.pm.SigningDetails;
import com.android.server.LocalServices;
import com.android.server.pm.NativeIdentityRecords.CreationBinding;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.HeaderEntry;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.SlotPhase;
import com.android.server.pm.NativeIdentityRecords.UserEntry;
import java.io.File;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Prints one revision's history outcomes over a fixed matrix of store layouts, through that
 * revision's exact Settings text in NativeHistoryHarness. The same source runs against the
 * pinned 0018a1d sources and against B2, and builds the same bytes on both. Every layout is
 * also read as its bindings cleared twin, and every layout is read under both store formats.
 * Lines give the restore inputs and outcome, the body only inputs, recovery seeding for each
 * mapping of each app ID under each boot observation of device encrypted data owners, and scan
 * decisions over candidate, mapping, user and deferral. The
 * runner compares them: body only inputs equal the 0018 restore inputs on the same bytes; a
 * layout without a surviving reservation equals 0018 on the same bytes; and under version 2 a
 * reservation layout equals 0018 on its published twin, the state its original writer would
 * have left after publishing the body. Host files and facades only, not Android boot.
 */
public final class NativeHistoryParity {
    private interface Build { void write(Path root) throws Exception; }

    private static final class Layout {
        final String name, relation;
        final Map<Integer, String> owners;
        final Build build;

        Layout(String name, String relation, Map<Integer, String> owners, Build build) {
            this.name = name;
            this.relation = relation;
            this.owners = new TreeMap<>(owners);
            this.build = build;
        }
    }

    private static final String SAME = "same";
    private static final int FREE = 10010, UNINDEXED = 10050;
    private static final String PKG_OTHER = "dev.andrix.other", PKG_SHARED = "dev.andrix.shared",
            PKG_FREE = "dev.andrix.free";
    private static final Set<String> OTHER = Set.of("1".repeat(64));
    private static final List<String> NAMES = List.of(PKG_A, PKG_B, PKG_C, PKG_D, PKG_R, PKG_X,
            PKG_OTHER, PKG_SHARED, PKG_FREE);
    private static final List<String> MAPPINGS = List.of("none", "same", "same-shared", "other",
            "shared-user");
    private static final List<String> USERS = List.of("absent", "null", "partial", "serial-7",
            "serial-8");
    // What boot observed of device encrypted data directories: nothing, the owner package's own
    // UID, a foreign UID, an unreadable owner, a directory named for another package, or an
    // incomplete enumeration.
    private static final List<String> DATA_OWNERS = List.of("none", "matching", "foreign",
            "unreadable", "unowned-name", "incomplete");
    private static final int FOREIGN_UID = 10099;
    // The facade signer of every fixture body and binding, and another one.
    private static final SigningDetails OWN_SIGNER = new SigningDetails(new Signature(new byte[] {1, 2, 3}));
    private static final SigningDetails OTHER_SIGNER = new SigningDetails(new Signature(new byte[] {9}));

    private static void pair(Path root, Header header) throws Exception {
        copies(root, null, bytes(header), bytes(header));
    }

    private static Path slotDirectory(Path root, int appId) throws Exception {
        return Files.createDirectory(root.resolve("slots/" + appId));
    }

    private static List<Layout> layouts() {
        List<Layout> all = new ArrayList<>();
        Slot bodyA = bound(A, PKG_A, 1, false, 1);
        Slot bodyR1 = bound(R, PKG_R, 1, false, 1);
        Slot bodyR2 = bound(R, PKG_R, 2, false, 1);
        Header reservedR = v2(1, boundCreating(R, 1, PKG_R));
        Header besideA = v2(2, live(A), boundCreating(R, 2, PKG_R));
        Header target = v2(3, creating(A, 1, PKG_A), creating(B, 2, PKG_B),
                boundCreating(C, 3, PKG_C));
        Header unknownBackup = v2(1, boundCreating(R, 1, PKG_R));
        Header unknownCopy = v2(2, boundCreating(R, 1, PKG_R), boundCreating(D, 2, PKG_D));
        Map<Integer, String> onlyA = Map.of(A, PKG_A), onlyR = Map.of(R, PKG_R);
        Map<Integer, String> aAndR = Map.of(A, PKG_A, R, PKG_R);
        Map<Integer, String> abc = Map.of(A, PKG_A, B, PKG_B, C, PKG_C);

        // Published bodies.
        all.add(new Layout("body-live", SAME, onlyA, root -> {
            pair(root, v2(1, live(A)));
            slot(root, A, bodyA);
        }));
        all.add(new Layout("body-retiring", SAME, onlyA, root -> {
            pair(root, v2(1, live(A)));
            slot(root, A, bound(A, PKG_A, 1, true, 2));
        }));
        all.add(new Layout("body-under-creation", SAME, onlyA, root -> {
            pair(root, v2(1, boundCreating(A, 1, PKG_A)));
            slot(root, A, bodyA);
        }));
        all.add(new Layout("damaged-header-body", SAME, onlyA, root -> {
            copies(root, null, GARBAGE, GARBAGE);
            slot(root, A, bodyA);
        }));
        all.add(new Layout("tombstones", SAME, Map.of(A, PKG_A, B, PKG_B), root -> {
            pair(root, v2(2, live(A), releasing(B)));
            slot(root, A, tombstone(A, PKG_A, 2));
            slot(root, B, tombstone(B, PKG_B, 3));
        }));

        // Complete header creations whose slots the view reads as missing, and the published
        // twins their original writers would have left.
        all.add(new Layout("reservation", "reservation-published", onlyR,
                root -> pair(root, reservedR)));
        all.add(new Layout("reservation-published", SAME, onlyR, root -> {
            pair(root, reservedR);
            slot(root, R, bodyR1);
        }));
        all.add(new Layout("reservation-empty-directory", "reservation-published", onlyR, root -> {
            pair(root, reservedR);
            slotDirectory(root, R);
        }));
        all.add(new Layout("reservation-torn-seed", "reservation-published", onlyR, root -> {
            pair(root, reservedR);
            Files.write(slotDirectory(root, R).resolve("record.bin-seed"),
                    Arrays.copyOf(NativeIdentityRecords.encodeSlot(bodyR1), 40));
        }));
        all.add(new Layout("reservation-beside-body", "reservation-beside-body-published", aAndR,
                root -> {
            pair(root, besideA);
            slot(root, A, bodyA);
        }));
        all.add(new Layout("reservation-beside-body-published", SAME, aAndR, root -> {
            pair(root, besideA);
            slot(root, A, bodyA);
            slot(root, R, bodyR2);
        }));
        // The protected target beside its predecessors, and the confirmed state its owner's
        // publication leaves.
        all.add(new Layout("protected-target", "protected-target-published", abc, root ->
                copies(root, bytes(target), bytes(header(1, creating(A, 1, PKG_A))),
                        bytes(header(2, creating(A, 1, PKG_A), creating(B, 2, PKG_B))))));
        all.add(new Layout("protected-target-published", SAME, abc, root -> {
            pair(root, target);
            slot(root, C, bound(C, PKG_C, 3, false, 1));
        }));
        all.add(new Layout("unknown-counter", "unknown-counter-published", Map.of(R, PKG_R, D, PKG_D),
                root -> copies(root, bytes(unknownBackup), bytes(unknownCopy), bytes(unknownCopy))));
        all.add(new Layout("unknown-counter-published", SAME, Map.of(R, PKG_R, D, PKG_D), root -> {
            copies(root, bytes(unknownBackup), bytes(unknownCopy), bytes(unknownCopy));
            slot(root, R, bodyR1);
        }));

        // Claims at another app ID withdraw only the reservation.
        all.add(new Layout("collision-body-package", SAME, Map.of(A, PKG_A, R, PKG_A), root -> {
            pair(root, v2(2, live(A), boundCreating(R, 2, PKG_A)));
            slot(root, A, bodyA);
        }));
        all.add(new Layout("collision-body-principal", SAME, aAndR, root -> {
            pair(root, v2(2, live(A), boundCreating(R, 1, PKG_R)));
            slot(root, A, bodyA);
        }));
        all.add(new Layout("collision-damaged-copy", SAME, aAndR, root -> {
            pair(root, besideA);
            Path directory = slotDirectory(root, A);
            Files.write(directory.resolve("record.bin"),
                    NativeIdentityRecords.encodeSlot(bound(A, PKG_R, 1, false, 1)));
            Files.write(directory.resolve("record.bin-backup"), GARBAGE);
        }));
        all.add(new Layout("collision-conflicting-copies", SAME, aAndR, root -> {
            pair(root, besideA);
            Path directory = slotDirectory(root, A);
            Files.write(directory.resolve("record.bin"), NativeIdentityRecords.encodeSlot(bodyA));
            Files.write(directory.resolve("record.bin.reservecopy"),
                    NativeIdentityRecords.encodeSlot(bound(A, PKG_R, 1, false, 1)));
        }));
        all.add(new Layout("collision-unsupported-copy", SAME, aAndR, root -> {
            pair(root, besideA);
            slot(root, A, new Slot(LINEAGE, A, PKG_R, 1, SIGNERS,
                    List.of(new UserEntry(1, 10, SERIAL, false))));
        }));
        all.add(new Layout("collision-tombstone", SAME, aAndR, root -> {
            pair(root, besideA);
            slot(root, A, tombstone(A, PKG_R, 2));
        }));
        all.add(new Layout("collision-legacy-creation", SAME, aAndR,
                root -> pair(root, v2(2, creating(A, 1, PKG_R), boundCreating(R, 2, PKG_R)))));
        all.add(new Layout("collision-unselected-addition", SAME, Map.of(R, PKG_R, D, PKG_R), root -> {
            Header addition = v2(2, boundCreating(R, 1, PKG_R), creating(D, 2, PKG_R));
            copies(root, bytes(unknownBackup), bytes(addition), bytes(addition));
        }));
        all.add(new Layout("collision-two-reservations", SAME, Map.of(R, PKG_R, D, PKG_R),
                root -> pair(root, v2(2, boundCreating(R, 1, PKG_R), boundCreating(D, 2, PKG_R)))));
        all.add(new Layout("collision-physical-location", SAME, Map.of(C, PKG_C, R, PKG_R), root -> {
            pair(root, v2(2, live(C), boundCreating(R, 2, PKG_R)));
            byte[] misplaced = NativeIdentityRecords.encodeSlot(bound(R, PKG_R, 1, false, 1));
            Path directory = slotDirectory(root, C);
            Files.write(directory.resolve("record.bin"), misplaced);
            Files.write(directory.resolve("record.bin.reservecopy"), misplaced);
        }));

        // No fallback around a body that exists but is not eligible.
        all.add(new Layout("damaged-body", SAME, onlyR, root -> {
            pair(root, reservedR);
            Path directory = slotDirectory(root, R);
            Files.write(directory.resolve("record.bin"), GARBAGE);
            Files.write(directory.resolve("record.bin.reservecopy"), GARBAGE);
        }));
        all.add(new Layout("conflicting-body", SAME, onlyR, root -> {
            pair(root, reservedR);
            slot(root, R, new Slot(LINEAGE, R, PKG_R, 1, OTHER,
                    List.of(new UserEntry(1, 0, SERIAL, false))));
        }));
        all.add(new Layout("tombstone-under-creation", SAME, onlyR, root -> {
            pair(root, reservedR);
            slot(root, R, tombstone(R, PKG_R, 1));
        }));
        all.add(new Layout("future-body", SAME, onlyR, root -> {
            pair(root, reservedR);
            Files.write(slotDirectory(root, R).resolve("record.bin"),
                    relabeled(NativeIdentityRecords.encodeSlot(bodyR1), 2));
        }));
        all.add(new Layout("link-entry", SAME, onlyR, root -> {
            pair(root, reservedR);
            Files.createSymbolicLink(root.resolve("slots/" + R), Path.of("absent-target"));
        }));
        all.add(new Layout("file-entry", SAME, onlyR, root -> {
            pair(root, reservedR);
            Files.write(root.resolve("slots/" + R), GARBAGE);
        }));
        all.add(new Layout("directory-record", SAME, onlyR, root -> {
            pair(root, reservedR);
            Files.createDirectories(root.resolve("slots/" + R + "/record.bin"));
        }));

        // Header and store gates.
        all.add(new Layout("live-copy", SAME, onlyR, root ->
                copies(root, bytes(reservedR), bytes(v2(1, live(R))), bytes(v2(1, live(R))))));
        all.add(new Layout("another-user", SAME, onlyR, root -> pair(root, v2(1,
                new HeaderEntry(R, SlotPhase.CREATING, 1, PKG_R,
                        new CreationBinding(10, SERIAL, SIGNERS))))));
        all.add(new Layout("legacy-null", SAME, onlyR, root -> pair(root, v2(1, creating(R, 1, PKG_R)))));
        all.add(new Layout("legacy-version-1", SAME, onlyR,
                root -> pair(root, header(1, creating(R, 1, PKG_R)))));
        all.add(new Layout("unindexed-directory", SAME, onlyR, root -> {
            pair(root, reservedR);
            slotDirectory(root, UNINDEXED);
        }));
        all.add(new Layout("unsupported-header-seed", SAME, onlyR, root -> {
            pair(root, reservedR);
            Files.write(root.resolve("store.bin-seed"), frame(1, 3, body(bytes(reservedR))));
        }));
        all.add(new Layout("unsupported-slot-seed", SAME, aAndR, root -> {
            pair(root, besideA);
            slot(root, A, bodyA);
            Files.write(root.resolve("slots/" + A + "/record.bin-seed"),
                    relabeled(NativeIdentityRecords.encodeSlot(bodyA), 2));
        }));
        // A nonzero user makes a body unsupported, as in 0018a1d: never BODY history, whatever
        // its user 0 entry says. Its decoded copies still claim their package and principals.
        Slot twoUsers = new Slot(LINEAGE, A, PKG_A, 1, SIGNERS,
                List.of(new UserEntry(1, 0, SERIAL, false), new UserEntry(2, 1, 9, false)));
        Slot nonzeroOnly = new Slot(LINEAGE, A, PKG_A, 1, SIGNERS,
                List.of(new UserEntry(2, 1, 9, false)));
        Header besideUsers = v2(3, live(A), boundCreating(R, 3, PKG_R));
        all.add(new Layout("body-user-0-and-1", SAME, onlyA, root -> {
            pair(root, v2(2, live(A)));
            slot(root, A, twoUsers);
        }));
        all.add(new Layout("body-nonzero-user-only", SAME, onlyA, root -> {
            pair(root, v2(2, live(A)));
            slot(root, A, nonzeroOnly);
        }));
        all.add(new Layout("reservation-beside-multi-user-body", "reservation-beside-multi-user-body-published",
                aAndR, root -> {
            pair(root, besideUsers);
            slot(root, A, twoUsers);
        }));
        all.add(new Layout("reservation-beside-multi-user-body-published", SAME, aAndR, root -> {
            pair(root, besideUsers);
            slot(root, A, twoUsers);
            slot(root, R, bound(R, PKG_R, 3, false, 1));
        }));
        all.add(new Layout("collision-multi-user-body", SAME, aAndR, root -> {
            pair(root, v2(3, live(A), boundCreating(R, 2, PKG_R)));
            slot(root, A, twoUsers);
        }));
        all.add(new Layout("releasing-entry", SAME, onlyR, root -> pair(root, v2(1, releasing(R)))));
        all.add(new Layout("live-entry", SAME, onlyR, root -> pair(root, v2(1, live(R)))));
        all.add(new Layout("unselected-reservation", SAME, onlyR,
                root -> copies(root, bytes(v2(0)), bytes(reservedR), bytes(reservedR))));
        return all;
    }

    // Every decodable header copy rewritten as version 1 without creation bindings.
    private static void clearBindings(Path root) throws Exception {
        for (String name : List.of("store.bin", "store.bin.reservecopy", "store.bin-backup")) {
            Path path = root.resolve(name);
            if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) continue;
            Header header;
            try {
                header = NativeIdentityRecords.decodeHeader(Files.readAllBytes(path));
            } catch (IllegalArgumentException undecodable) {
                continue;
            }
            List<HeaderEntry> entries = new ArrayList<>();
            for (HeaderEntry entry : header.entries) {
                entries.add(entry.phase == SlotPhase.CREATING ? new HeaderEntry(entry.appId,
                        SlotPhase.CREATING, entry.creationId, entry.creationPackage) : entry);
            }
            Files.write(path, bytes(new Header(header.lineage, header.lastId, entries)));
        }
    }

    private static com.android.server.pm.pkg.PackageStateInternal state(String name) {
        return new com.android.server.pm.pkg.PackageStateInternal() {
            @Override public String getPackageName() { return name; }
            @Override public File getPath() { return new File("/data/app/~~host/" + name + "-1"); }
        };
    }

    private static NativeHistoryHarness.SettingBase mapping(String kind, int appId, String owner) {
        if (kind.equals("same")) return new NativeHistoryHarness.PackageSetting(owner, appId, false);
        if (kind.equals("same-shared")) return new NativeHistoryHarness.PackageSetting(owner, appId, true);
        if (kind.equals("other")) return new NativeHistoryHarness.PackageSetting(PKG_OTHER, appId, false);
        if (kind.equals("shared-user")) {
            NativeHistoryHarness.SharedUserSetting shared = new NativeHistoryHarness.SharedUserSetting();
            shared.add(state(PKG_SHARED));
            return shared;
        }
        return null;
    }

    private static void user(String kind) {
        if (kind.equals("absent")) {
            LocalServices.addService(UserManagerInternal.class, null);
            return;
        }
        UserManagerInternal users = new UserManagerInternal();
        if (kind.equals("null")) {
            users.info = null;
        } else {
            users.info.partial = kind.equals("partial");
            users.info.serialNumber = kind.equals("serial-8") ? 8 : 7;
        }
        LocalServices.addService(UserManagerInternal.class, users);
    }

    // A booted harness with this one mapping and data owner observation, or null when the boot
    // threw.
    private static NativeHistoryHarness boot(NativeIdentityStore.Loaded loaded, int appId,
            String kind, String owner, String dataOwner) {
        NativeHistoryHarness harness = new NativeHistoryHarness();
        NativeHistoryHarness.SettingBase setting = mapping(kind, appId, owner);
        if (setting != null) harness.map(appId, setting);
        if (dataOwner.equals("matching")) harness.mNativeDeOwnersAtBoot = Map.of(owner, appId);
        if (dataOwner.equals("foreign")) harness.mNativeDeOwnersAtBoot = Map.of(owner, FOREIGN_UID);
        if (dataOwner.equals("unreadable")) harness.mNativeDeOwnersAtBoot = Map.of(owner, -1);
        if (dataOwner.equals("unowned-name")) harness.mNativeDeOwnersAtBoot = Map.of(PKG_OTHER, appId);
        if (dataOwner.equals("incomplete")) harness.mNativeDeEnumerationComplete = false;
        try {
            harness.apply(loaded);
        } catch (RuntimeException threw) {
            return null;
        }
        return harness;
    }

    private static String records(NativeHistoryHarness.Inputs inputs) {
        StringBuilder text = new StringBuilder("records=");
        for (NativePrincipalPins.Record record : inputs.records) {
            text.append(record.id).append('/').append(record.packageName).append('/')
                    .append(record.appId).append('/').append(record.userId).append('/')
                    .append(record.userSerial).append(',');
        }
        return text.append(" retiring=").append(new TreeSet<>(inputs.retiring)).toString();
    }

    private static String restore(NativeIdentityStore.Loaded loaded) {
        NativeHistoryHarness.Inputs inputs;
        try {
            inputs = NativeHistoryHarness.restoreInputs(loaded);
        } catch (RuntimeException threw) {
            return "inputs-threw=" + threw.getClass().getSimpleName();
        }
        NativeHistoryHarness harness = new NativeHistoryHarness();
        String outcome;
        try {
            harness.apply(loaded);
            NativePrincipalPins pins = harness.nativePrincipalPinsLPr();
            StringBuilder phases = new StringBuilder();
            for (NativePrincipalPins.Record record : inputs.records) {
                NativePrincipalPins.Pin pin = pins.findId(record.id);
                phases.append(record.id).append(':').append(pin == null ? "none" : pin.phase()).append(',');
            }
            outcome = "counter=" + (pins.hasKnownCounter()
                    ? String.valueOf(pins.snapshotForWrite().lastId) : "none")
                    + " pinned=" + pins.reservedAppIds() + " phases=" + phases;
        } catch (RuntimeException threw) {
            outcome = "threw=" + threw.getClass().getSimpleName();
        }
        return records(inputs) + " " + outcome;
    }

    private static String bodyLine(NativeIdentityStore.Loaded loaded) {
        try {
            return records(NativeHistoryHarness.bodyInputs(loaded));
        } catch (RuntimeException threw) {
            return "threw=" + threw.getClass().getSimpleName();
        }
    }

    private static String seed(NativeHistoryHarness harness) {
        if (harness == null) return "boot-threw";
        NativePrincipalRecovery view = harness.mNativeRecoveryView;
        StringBuilder text = new StringBuilder("deferred=");
        for (String name : NAMES) if (view.defersName(name)) text.append(name).append(',');
        text.append(" protected=");
        for (String name : NAMES) if (view.protectsName(name)) text.append(name).append(',');
        text.append(" kept=");
        for (String name : NAMES) {
            if (view.keepsCodePath(new File("/data/app/~~host/" + name + "-1"))) {
                text.append(name).append(',');
            }
        }
        text.append(" unidentified=").append(view.hasUnidentifiedCode()).append(" held=");
        for (int appId = 10000; appId <= UNINDEXED; appId++) {
            if (view.protectsKeystore(appId)) text.append(appId).append(',');
        }
        // The allocator holds the refreshed Settings text published, and its pins.
        text.append(" allocator=").append(new TreeSet<>(harness.mAppIds.nativePrincipalAppIds()))
                .append(" pinned=").append(harness.nativePrincipalPinsLPr().reservedAppIds());
        return text.toString();
    }

    private static void emit(PrintWriter out, NativeIdentityStore.Format format, String name,
            String kind, String key, String payload) {
        out.println(format + "\t" + name + "\t" + kind + "\t" + key + "\t" + payload);
    }

    private static void inspect(PrintWriter out, Layout layout, String name, Path root) {
        for (NativeIdentityStore.Format format : List.of(V1, V2)) {
            NativeIdentityStore.Loaded loaded = new NativeIdentityStore(root.toFile(), format).load();
            emit(out, format, name, "restore", "-", restore(loaded));
            emit(out, format, name, "body", "-", bodyLine(loaded));
            List<Integer> appIds = new ArrayList<>(layout.owners.keySet());
            appIds.add(FREE);
            for (int appId : appIds) {
                String owner = layout.owners.getOrDefault(appId, PKG_FREE);
                for (String kind : MAPPINGS) {
                    for (String dataOwner : DATA_OWNERS) {
                        emit(out, format, name, "seed", appId + "/" + kind + "/" + dataOwner,
                                seed(boot(loaded, appId, kind, owner, dataOwner)));
                    }
                    for (String candidate : List.of(owner, PKG_OTHER)) {
                        for (boolean shared : List.of(false, true)) {
                            for (String userKind : USERS) {
                                for (boolean deferred : List.of(false, true)) {
                                    user(userKind);
                                    NativeHistoryHarness harness = boot(loaded, appId, kind, owner, "none");
                                    String key = appId + "/" + kind + "/" + candidate + "/" + shared
                                            + "/" + userKind + "/" + deferred;
                                    if (harness == null) {
                                        emit(out, format, name, "scan", key, "boot-threw");
                                        continue;
                                    }
                                    if (deferred) {
                                        harness.mNativeRecoveryView =
                                                harness.mNativeRecoveryView.defer(candidate, null);
                                    }
                                    NativeHistoryHarness.PackageSetting scanned =
                                            new NativeHistoryHarness.PackageSetting(candidate, appId, shared);
                                    emit(out, format, name, "scan", key,
                                            harness.nativeScanSubjectAllowedLPr(scanned) + " "
                                            + harness.nativeScanBindingAllowedLPr(scanned, OWN_SIGNER) + " "
                                            + harness.nativeScanBindingAllowedLPr(scanned, OTHER_SIGNER));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    public static void main(String[] args) throws Exception {
        if (!NativeHistoryParity.class.desiredAssertionStatus()) {
            throw new AssertionError("run with java -ea");
        }
        start(Path.of(args[0]));
        int count = 0;
        try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(Path.of(args[1])))) {
            for (Layout layout : layouts()) {
                Path root = layout(null, null, null);
                layout.build.write(root);
                Path cleared = layout(null, null, null);
                layout.build.write(cleared);
                clearBindings(cleared);
                out.println("relation\t" + layout.name + "\t" + layout.relation);
                out.println("relation\t" + layout.name + "~cleared\t" + SAME);
                inspect(out, layout, layout.name, root);
                inspect(out, layout, layout.name + "~cleared", cleared);
                count += 2;
            }
        }
        System.out.println(count + " layouts read through this revision's exact Settings history"
                + " text; Android boot unqualified");
    }
}
