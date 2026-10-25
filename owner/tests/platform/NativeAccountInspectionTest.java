// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import com.android.server.LocalServices;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.TreeMap;

/** Future separately admitted JVM gate. No account provisioning or execution service. */
public final class NativeAccountInspectionTest {
    private static Map<String, String> footprint(Path root) throws Exception {
        Map<String, String> result = new TreeMap<>();
        try (var walk = Files.walk(root)) {
            for (Path path : walk.toList()) {
                result.put(root.relativize(path).toString(), Files.getLastModifiedTime(path) + " "
                        + (Files.isRegularFile(path) ? java.util.Base64.getEncoder().encodeToString(
                        Files.readAllBytes(path)) : "directory"));
            }
        }
        return result;
    }

    public static void main(String[] args) throws Exception {
        if (!NativeAccountInspectionTest.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        UserManagerInternal users = new UserManagerInternal();
        LocalServices.addService(UserManagerInternal.class, users);
        PackageManagerService pm = new PackageManagerService(null, true, NativeIdentityStore.Format.V3);
        NativePrincipalManager manager = new NativePrincipalManager(pm);
        Map<String, String> before = footprint(pm.mSettings.root);
        var empty = manager.inspectUser(0, 7);
        assert empty.status == NativePrincipalManager.Inspection.Status.AVAILABLE
                && empty.store == NativePrincipalManager.Inspection.Store.READY
                && empty.complete && empty.rows.isEmpty();
        assert before.equals(footprint(pm.mSettings.root));
        try { empty.rows.add(null); throw new AssertionError("Mutable inspection rows"); }
        catch (UnsupportedOperationException expected) { }

        pm.mSettings.add("dev.andrix.account", 10123);
        NativePrincipalManager.Handle issued = manager.prepare(manager.select("dev.andrix.account", 0));
        // A pin with no eligible body or complete reservation is not an invented account row.
        assert manager.inspectUser(0, 7).status == NativePrincipalManager.Inspection.Status.UNAVAILABLE;
        assert manager.commit(issued);
        before = footprint(pm.mSettings.root);
        var bound = manager.inspectUser(0, 7);
        assert bound.status == NativePrincipalManager.Inspection.Status.AVAILABLE
                && bound.rows.size() == 1;
        var row = bound.rows.get(0);
        assert row.principalId == manager.identity(issued).id
                && row.appId == 10123 && row.packageName.equals("dev.andrix.account")
                && row.lineage.equals(Settings.LINEAGE)
                && row.source.equals("BODY") && row.phase.equals("ACTIVE")
                && row.lifecycle.equals("ELIGIBLE") && row.suspension.equals("NONE");
        assert before.equals(footprint(pm.mSettings.root));
        NativeIdentityStore.Loaded cached = pm.mSettings.mNativeIdentityLoaded;
        NativeIdentityRecords.Slot original = cached.slots.get(10123).value;
        // A real version 1 BODY marker records RETIRING; a version 2 BODY can record
        // ELIGIBLE with a suspension. Neither loses its lifecycle in the projection.
        var retiringBody = NativeIdentityRecords.decodeSlot(NativeIdentityRecords.encodeSlot(
                new NativeIdentityRecords.Slot(original.lineage, original.appId,
                        original.packageName, original.generation + 1, original.signerSha256,
                        java.util.List.of(new NativeIdentityRecords.UserEntry(
                                original.users.get(0).id, 0, 7, true)))));
        var bodySlots = new java.util.HashMap<>(cached.slots);
        bodySlots.put(10123, new NativeIdentityStore.ReadResult<>(
                NativeIdentityStore.Status.VALID, retiringBody, java.util.List.of(retiringBody)));
        var retiring = NativePrincipalManager.project(0, 7,
                new NativeIdentityStore.Loaded(cached.header, bodySlots,
                        cached.occupiedAppIds, false, true), pm.mSettings.pins,
                pm.mSettings.mNativeStoreAppIds, pm.mSettings.mNativeRememberedBindings);
        assert retiring.status == NativePrincipalManager.Inspection.Status.AVAILABLE;
        var retiringRow = retiring.rows.get(0);
        assert retiringRow.source.equals("BODY") && retiringRow.lifecycle.equals("RETIRING")
                && retiringRow.suspension.equals("NONE");
        var suspension = new NativeIdentityRecords.Suspension(
                NativeIdentityRecords.ActorClass.ACCOUNT_USER, 0, 0, 7,
                NativeIdentityRecords.NO_REFERENCE, 1, 1, null);
        var suspendedBody = NativeIdentityRecords.decodeSlot(NativeIdentityRecords.encodeSlot(
                new NativeIdentityRecords.Slot(original.lineage, original.appId,
                        original.packageName, original.generation + 1, original.signerSha256,
                        java.util.List.of(new NativeIdentityRecords.UserEntry(
                                original.users.get(0).id, 0, 7,
                                new NativeIdentityRecords.Lifecycle(
                                        NativeIdentityRecords.LifecycleState.ELIGIBLE,
                                        java.util.List.of(suspension), null))))));
        bodySlots.put(10123, new NativeIdentityStore.ReadResult<>(
                NativeIdentityStore.Status.VALID, suspendedBody, java.util.List.of(suspendedBody)));
        var suspended = NativePrincipalManager.project(0, 7,
                new NativeIdentityStore.Loaded(cached.header, bodySlots,
                        cached.occupiedAppIds, false, true), pm.mSettings.pins,
                pm.mSettings.mNativeStoreAppIds, pm.mSettings.mNativeRememberedBindings);
        assert suspended.status == NativePrincipalManager.Inspection.Status.AVAILABLE;
        var suspendedRow = suspended.rows.get(0);
        assert suspendedRow.source.equals("BODY") && suspendedRow.lifecycle.equals("ELIGIBLE")
                && suspendedRow.suspension.equals("PRESENT");
        assert before.equals(footprint(pm.mSettings.root));
        String otherLineage = "abcdef0123456789abcdef0123456789";
        var foreignBody = new NativeIdentityRecords.Slot(otherLineage, original.appId,
                original.packageName, original.generation, original.signerSha256, original.users);
        var foreignSlots = new java.util.HashMap<>(cached.slots);
        foreignSlots.put(10123, new NativeIdentityStore.ReadResult<>(
                NativeIdentityStore.Status.VALID, foreignBody, java.util.List.of(foreignBody)));
        NativeIdentityRecords.Header headerB = NativeIdentityRecords.Header.newV2(
                otherLineage, cached.header.value.lastId, cached.header.value.entries);
        var foreignHeader = new NativeIdentityStore.ReadResult<>(
                NativeIdentityStore.Status.VALID, headerB, java.util.List.of(headerB));
        var foreign = new NativeIdentityStore.Loaded(foreignHeader, foreignSlots,
                cached.occupiedAppIds, false, true);
        var changedLineage = NativePrincipalManager.project(0, 7, foreign, pm.mSettings.pins,
                pm.mSettings.mNativeStoreAppIds, pm.mSettings.mNativeRememberedBindings);
        assert changedLineage.status == NativePrincipalManager.Inspection.Status.UNAVAILABLE
                && changedLineage.store == NativePrincipalManager.Inspection.Store.CONFLICT
                && changedLineage.rows.isEmpty(); // Issuance's original lineage, not numeric pin ID.
        var foreignSigner = new NativeIdentityRecords.Slot(original.lineage, original.appId,
                original.packageName, original.generation,
                java.util.Set.of("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
                original.users);
        foreignSlots.put(10123, new NativeIdentityStore.ReadResult<>(
                NativeIdentityStore.Status.VALID, foreignSigner, java.util.List.of(foreignSigner)));
        var changedSigner = NativePrincipalManager.project(0, 7,
                new NativeIdentityStore.Loaded(cached.header, foreignSlots,
                        cached.occupiedAppIds, false, true), pm.mSettings.pins,
                pm.mSettings.mNativeStoreAppIds, pm.mSettings.mNativeRememberedBindings);
        assert changedSigner.status == NativePrincipalManager.Inspection.Status.UNAVAILABLE
                && changedSigner.rows.isEmpty();
        PackageManagerService reopened = new PackageManagerService(pm.mSettings.root, false,
                NativeIdentityStore.Format.V3);
        reopened.mSettings.add("dev.andrix.account", 10123);
        reopened.mSettings.restoreAfterPackageSettings();
        NativePrincipalManager restoredManager = new NativePrincipalManager(reopened);
        var restored = restoredManager.inspectUser(0, 7);
        assert restored.status == NativePrincipalManager.Inspection.Status.AVAILABLE
                && restored.rows.size() == 1 && restored.rows.get(0).phase.equals("PENDING");
        var restoredChangedLineage = NativePrincipalManager.project(0, 7, foreign,
                reopened.mSettings.pins, reopened.mSettings.mNativeStoreAppIds,
                reopened.mSettings.mNativeRememberedBindings);
        assert restoredChangedLineage.status == NativePrincipalManager.Inspection.Status.UNAVAILABLE
                && restoredChangedLineage.rows.isEmpty(); // First remembered ORIGINAL history.
        // Unlike a body, the selected version 2 header alone has a complete original
        // creation binding but NO recorded lifecycle or suspension. Persist the actual
        // header and read the genuinely absent slot, then restore its PENDING pin.
        PackageManagerService reservationPm = new PackageManagerService(null, true,
                NativeIdentityStore.Format.V3);
        NativeIdentityStore store = reservationPm.mSettings.store;
        NativeIdentityRecords.Header emptyHeader = store.load().header.value;
        NativeIdentityRecords.Header creating = NativeIdentityRecords.Header.newV2(
                Settings.LINEAGE, 1, java.util.List.of(new NativeIdentityRecords.HeaderEntry(
                        10124, NativeIdentityRecords.SlotPhase.CREATING, 1,
                        "dev.andrix.reserved", new NativeIdentityRecords.CreationBinding(
                                0, 7, java.util.Set.of("a".repeat(64))))));
        assert store.writeHeader(emptyHeader, creating);
        NativeIdentityStore.Loaded reservationView = store.load();
        assert reservationView.header.status == NativeIdentityStore.Status.VALID
                && reservationView.creationReady()
                && reservationView.slots.get(10124).status == NativeIdentityStore.Status.MISSING
                && !Files.exists(reservationPm.mSettings.root.resolve("slots/10124"))
                && reservationView.history(10124) != null
                && reservationView.history(10124).source == NativeIdentityStore.Source.RESERVATION;
        PackageManagerService reservationRestored = new PackageManagerService(
                reservationPm.mSettings.root, false, NativeIdentityStore.Format.V3);
        reservationRestored.mSettings.add("dev.andrix.reserved", 10124);
        reservationRestored.mSettings.restoreAfterPackageSettings();
        Map<String, String> reservationBefore = footprint(reservationRestored.mSettings.root);
        var reservation = new NativePrincipalManager(reservationRestored).inspectUser(0, 7);
        assert reservation.status == NativePrincipalManager.Inspection.Status.AVAILABLE
                && reservation.complete && reservation.rows.size() == 1;
        var reservationRow = reservation.rows.get(0);
        assert reservationRow.principalId == 1 && reservationRow.appId == 10124
                && reservationRow.packageName.equals("dev.andrix.reserved")
                && reservationRow.lineage.equals(Settings.LINEAGE)
                && reservationRow.source.equals("RESERVATION") && reservationRow.phase.equals("PENDING")
                && reservationRow.lifecycle.equals("NOT_OBSERVED")
                && reservationRow.suspension.equals("NOT_OBSERVED");
        assert reservationBefore.equals(footprint(reservationRestored.mSettings.root));
        var incomplete = NativePrincipalManager.project(0, 7,
                new NativeIdentityStore.Loaded(cached.header, cached.slots,
                        cached.occupiedAppIds, false, false), pm.mSettings.pins,
                pm.mSettings.mNativeStoreAppIds, pm.mSettings.mNativeRememberedBindings);
        assert incomplete.status == NativePrincipalManager.Inspection.Status.UNAVAILABLE
                && incomplete.rows.isEmpty();
        var newer = NativePrincipalManager.project(0, 7,
                new NativeIdentityStore.Loaded(cached.header, cached.slots,
                        cached.occupiedAppIds, false, true, true), pm.mSettings.pins,
                pm.mSettings.mNativeStoreAppIds, pm.mSettings.mNativeRememberedBindings);
        assert newer.store == NativePrincipalManager.Inspection.Store.UNSUPPORTED
                && newer.rows.isEmpty();
        var conflicts = new java.util.HashMap<>(cached.slots);
        conflicts.put(10123, new NativeIdentityStore.ReadResult<>(
                NativeIdentityStore.Status.CONFLICT, null, java.util.List.of()));
        var conflicting = NativePrincipalManager.project(0, 7,
                new NativeIdentityStore.Loaded(cached.header, conflicts,
                        cached.occupiedAppIds, false, true), pm.mSettings.pins,
                pm.mSettings.mNativeStoreAppIds, pm.mSettings.mNativeRememberedBindings);
        assert conflicting.store == NativePrincipalManager.Inspection.Store.CONFLICT
                && conflicting.rows.isEmpty();
        users.info.serialNumber = 8;
        try { manager.inspectUser(0, 7); throw new AssertionError("Stale serial accepted"); }
        catch (IllegalStateException expected) { }
        users.info.serialNumber = 7;

        // An intact prior hold still exists, but the cached view is now unavailable: not empty.
        PackageManagerService missing = new PackageManagerService(null, false,
                NativeIdentityStore.Format.V3);
        var absent = NativePrincipalManager.project(0, 7, missing.mSettings.mNativeIdentityLoaded,
                pm.mSettings.pins, pm.mSettings.mNativeStoreAppIds,
                pm.mSettings.mNativeRememberedBindings);
        assert absent.status == NativePrincipalManager.Inspection.Status.UNAVAILABLE
                && absent.rows.isEmpty();
        var other = NativePrincipalManager.project(10, 9, pm.mSettings.mNativeIdentityLoaded,
                pm.mSettings.pins, pm.mSettings.mNativeStoreAppIds,
                pm.mSettings.mNativeRememberedBindings);
        assert other.status == NativePrincipalManager.Inspection.Status.UNSUPPORTED
                && other.rows.isEmpty() && other.userId == 10;
        assert before.equals(footprint(pm.mSettings.root));
        System.out.println("native cached inspection host gate, no Android qualification");
    }
}
