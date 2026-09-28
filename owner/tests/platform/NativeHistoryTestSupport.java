// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeBindingTestSupport.*;
import static com.android.server.pm.NativeHeaderTestSupport.*;

import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.UserEntry;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Host fixtures of the B2 history tests, compiled only with the B2 sources. A booted facade
 * reopens a store as the host Settings facade does, then takes its recovery view from the exact
 * boot text of the adapted Settings, run by NativeHistoryHarness over the same mappings and the
 * same view. The boot requires that facade and harness restored the same core pins and holds.
 * The checks every history case shares live here too. Host files and facades only, not Android
 * boot, SELinux or crash qualification.
 */
final class NativeHistoryTestSupport {
    static final Header RESERVED_R = v2(1, boundCreating(R, 1, PKG_R));
    static final Slot BODY_R = bound(R, PKG_R, 1, false, 1);
    static final Slot BODY_A = bound(A, PKG_A, 1, false, 1);
    static final Set<String> OTHER_SIGNERS = Set.of("1".repeat(64));

    // The one core record of R's original creation.
    static NativePrincipalPins.Record recordR() {
        return record(1, PKG_R, R);
    }

    static Path reserved() throws Exception {
        return layout(null, bytes(RESERVED_R), bytes(RESERVED_R));
    }

    static Path slotDirectory(Path root, int appId) throws Exception {
        return Files.createDirectory(root.resolve("slots/" + appId));
    }

    /**
     * A reopened facade of this format over root with these packages mapped at these app IDs,
     * whose recovery view is the exact recovery seeding over the same mappings and view.
     */
    static PackageManagerService boot(Path root, NativeIdentityStore.Format format,
            Map<String, Integer> packages) {
        PackageManagerService pm = reopenOf(root, format, packages);
        NativeHistoryHarness seeded = new NativeHistoryHarness();
        for (Map.Entry<String, Integer> entry : new TreeMap<>(packages).entrySet()) {
            seeded.map(entry.getValue(), new NativeHistoryHarness.PackageSetting(entry.getKey(),
                    entry.getValue(), false));
        }
        seeded.apply(pm.mSettings.mNativeIdentityLoaded);
        String difference = pinDifference(pm.mSettings.pins, seeded.nativePrincipalPinsLPr(),
                pm.mSettings.mNativeIdentityLoaded);
        Set<Integer> facadeHolds = new TreeSet<>(pm.mSettings.storeHolds);
        facadeHolds.addAll(pm.mSettings.pins.reservedAppIds());
        if (difference == null && !facadeHolds.equals(seeded.mAppIds.nativePrincipalAppIds())) {
            difference = "allocator holds " + facadeHolds + " and "
                    + seeded.mAppIds.nativePrincipalAppIds();
        }
        if (difference != null) {
            throw new AssertionError("facade and adapted Settings text restored differently: "
                    + difference);
        }
        pm.mSettings.mNativeRecoveryView = seeded.mNativeRecoveryView;
        return pm;
    }

    /**
     * Why two registries restored from the same view differ, or null: their held app IDs, counter
     * knowledge, whole snapshot when the counter is known, and the record and phase of every pin
     * the view's restoration names.
     */
    static String pinDifference(NativePrincipalPins first, NativePrincipalPins second,
            NativeIdentityStore.Loaded loaded) {
        if (!first.reservedAppIds().equals(second.reservedAppIds())) {
            return "holds " + first.reservedAppIds() + " and " + second.reservedAppIds();
        }
        if (first.hasKnownCounter() != second.hasKnownCounter()) return "counter knowledge";
        if (first.hasKnownCounter() && !first.snapshotForWrite().equals(second.snapshotForWrite())) {
            return "snapshots " + first.snapshotForWrite() + " and " + second.snapshotForWrite();
        }
        for (NativePrincipalPins.Record record
                : NativeIdentityPersistence.restoration(loaded.histories()).records) {
            NativePrincipalPins.Pin one = first.findId(record.id), other = second.findId(record.id);
            if (one == null ? other != null : other == null || !one.record().equals(other.record())
                    || one.phase() != other.phase()) {
                return "pin " + record + ": " + one + " and " + other;
            }
        }
        return null;
    }

    /** The exact boot text over this view with one mapping, or none. */
    static NativeHistoryHarness seeded(NativeIdentityStore.Loaded loaded, int appId,
            NativeHistoryHarness.SettingBase mapping) {
        return seeded(loaded, appId, mapping, Map.of(), true);
    }

    /**
     * The exact boot text over this view with one mapping, or none, after boot observed these
     * device encrypted data directory owners, or an incomplete enumeration of them.
     */
    static NativeHistoryHarness seeded(NativeIdentityStore.Loaded loaded, int appId,
            NativeHistoryHarness.SettingBase mapping, Map<String, Integer> dataOwners,
            boolean enumerated) {
        NativeHistoryHarness harness = new NativeHistoryHarness();
        if (mapping != null) harness.map(appId, mapping);
        harness.mNativeDeOwnersAtBoot = Map.copyOf(dataOwners);
        harness.mNativeDeEnumerationComplete = enumerated;
        harness.apply(loaded);
        return harness;
    }

    /** What a call throws, as its simple class name and message, or "returned". */
    static String thrown(Call<?> call) {
        try {
            call.run();
            return "returned";
        } catch (Exception | AssertionError error) {
            return error.getClass().getSimpleName() + ": " + error.getMessage();
        }
    }

    /** Whether BODY histories are exactly the bindingUsable slots, with each one's user. */
    static boolean bodiesExact(NativeIdentityStore.Loaded loaded) {
        for (Map.Entry<Integer, NativeIdentityStore.ReadResult<Slot>> entry : loaded.slots.entrySet()) {
            int appId = entry.getKey();
            NativeIdentityStore.History history = loaded.history(appId);
            boolean body = history != null && history.source == NativeIdentityStore.Source.BODY;
            if (body != loaded.bindingUsable(appId)) return false;
            if (!body) continue;
            Slot slot = entry.getValue().value;
            if (slot.users.size() != 1) return false;
            UserEntry user = slot.users.get(0);
            if (history.appId != appId || history.id != user.id
                    || history.userId != user.userId || history.userSerial != user.userSerial
                    || history.retiring != user.retiring
                    || !history.packageName.equals(slot.packageName)
                    || !history.signerSha256.equals(slot.signerSha256)
                    || !history.lineage.equals(slot.lineage)) return false;
        }
        for (NativeIdentityStore.History history : loaded.histories().values()) {
            if (history.source == NativeIdentityStore.Source.BODY
                    && !loaded.bindingUsable(history.appId)) return false;
        }
        return true;
    }

    /** Checks that this history is exactly the named reservation. */
    static void reservation(List<String> problems, NativeIdentityStore.History history, int appId,
            long id, String name, Set<String> signers, String what) {
        check(problems, history != null && history.source == NativeIdentityStore.Source.RESERVATION
                && history.appId == appId && history.id == id && history.packageName.equals(name)
                && history.userId == 0 && history.userSerial == SERIAL
                && history.signerSha256.equals(signers) && !history.retiring
                && history.lineage.equals(LINEAGE), what + ": " + history);
    }

    /** Checks the view's history of R is R's original reservation. */
    static void reservedR(List<String> problems, NativeIdentityStore.Loaded loaded, String what) {
        reservation(problems, loaded.history(R), R, 1, PKG_R, SIGNERS, what);
        check(problems, loaded.occupiedAppIds.contains(R) && bodiesExact(loaded),
                what + ": holds " + loaded.occupiedAppIds);
    }

    /**
     * Checks that app ID has no history and keeps its hold, that BODY histories stay exactly
     * the eligible bodies, and that a reopened facade restores without throwing and pins nothing
     * there while keeping the hold.
     */
    static void noHistory(List<String> problems, Path root, NativeIdentityStore.Format format,
            int appId, String what) {
        NativeIdentityStore.Loaded loaded = loadedOf(root, format);
        check(problems, loaded.history(appId) == null, what + ": history " + loaded.history(appId));
        check(problems, loaded.occupiedAppIds.contains(appId) && bodiesExact(loaded),
                what + ": holds " + loaded.occupiedAppIds);
        NativeIdentityPersistence.Restoration restoration =
                NativeIdentityPersistence.restoration(loaded.histories());
        check(problems, restoration.withdrawnReservations.isEmpty(), what + ": backstop was needed");
        PackageManagerService pm;
        try {
            pm = reopenOf(root, format, Map.of());
        } catch (RuntimeException threw) {
            problems.add(what + ": reopen threw " + threw);
            return;
        }
        check(problems, !pm.mSettings.pins.isAppIdPinned(appId)
                && pm.mSettings.isNativePrincipalAppIdLPr(appId), what + ": reopened pin or lost hold");
    }

    /** The phase of the pin of this package in a registry reopened over root. */
    static NativePrincipalPins.Phase reopenedPhase(Path root, NativeIdentityStore.Format format,
            String name) {
        NativePrincipalPins.Pin pin = reopenOf(root, format, Map.of()).mSettings.pins.find(name, 0);
        return pin == null ? null : pin.phase();
    }

    private NativeHistoryTestSupport() {}
}
