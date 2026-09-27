// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import android.system.Os;
import com.android.server.LocalServices;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Exact preparation admission and retained ownership, not Android authority qualification. */
public final class NativePreparationAdmissionTest {
    private static final String A = "dev.andrix.admission", B = "dev.andrix.admissionpeer";
    private static void refused(Runnable operation) {
        try { operation.run(); }
        catch (IllegalArgumentException | IllegalStateException expected) { return; }
        throw new AssertionError("operation unexpectedly accepted");
    }
    private static PackageManagerService fixture(int count, boolean mixed) throws Exception {
        PackageManagerService initial = new PackageManagerService();
        List<NativeIdentityRecords.HeaderEntry> entries = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            var phase = !mixed ? NativeIdentityRecords.SlotPhase.LIVE
                    : NativeIdentityRecords.SlotPhase.values()[i % 3];
            boolean creating = phase == NativeIdentityRecords.SlotPhase.CREATING;
            entries.add(new NativeIdentityRecords.HeaderEntry(10000 + i, phase,
                    creating ? i + 1 : 0, creating ? "dev.andrix.held" + i : ""));
        }
        var header = new NativeIdentityRecords.Header(Settings.LINEAGE, count, entries);
        byte[] bytes = NativeIdentityRecords.encodeHeader(header);
        Files.write(initial.mSettings.root.resolve("store.bin"), bytes);
        Files.write(initial.mSettings.root.resolve("store.bin.reservecopy"), bytes);
        PackageManagerService pm = new PackageManagerService(initial.mSettings.root, false);
        pm.mSettings.add(A, 11000); pm.mSettings.add(B, 11001);
        pm.mSettings.add("dev.andrix.admissionthird", 11002);
        pm.mSettings.restoreAfterPackageSettings();
        assert pm.mSettings.storeHolds.size() == count;
        assert pm.mSettings.pins.snapshotForWrite().records.isEmpty();
        assert pm.mSettings.pins.snapshotForWrite().lastId == count;
        return pm;
    }
    private static void corePlans() {
        NativePrincipalPins pins = new NativePrincipalPins(3);
        refused(() -> pins.retry(A, 11000, 0, 7));
        assert pins.snapshotForWrite().lastId == 0 && pins.reservedAppIds().isEmpty();
        var first = pins.previewPrepare(A, 11000, 0, 7);
        assert first.record.id == 1 && first.snapshot.lastId == 1;
        assert pins.snapshotForWrite().lastId == 0 && pins.reservedAppIds().isEmpty();
        Object owner = new Object();
        var issued = pins.prepare(first, owner);
        assert issued.issuance() == owner && issued.record().equals(first.record);
        assert pins.snapshotForWrite().equals(first.snapshot);
        assert pins.retry(A, 11000, 0, 7) == issued;
        refused(() -> pins.previewPrepare(A, 11000, 0, 7));
        refused(() -> pins.prepare(first, owner));
        var staleSecond = pins.previewPrepare(B, 11001, 0, 7);
        pins.beginRetire(issued);
        refused(() -> pins.prepare(staleSecond, owner));
        assert pins.snapshotForWrite().lastId == 1 && pins.find(B, 0) == null;
        var second = pins.previewPrepare(B, 11001, 0, 7);
        assert second.snapshot.retiringIds.equals(Set.of(1L));
        var current = second;
        var foreign = new NativePrincipalPins(3);
        foreign.restore(pins.snapshotForWrite());
        refused(() -> foreign.prepare(current, owner));
        assert pins.prepare(current, owner).record().id == 2;
        var beforeRestore = new NativePrincipalPins(3);
        var stale = beforeRestore.previewPrepare(A, 11000, 0, 7);
        beforeRestore.restore(new NativePrincipalPins.Snapshot(0, List.of()));
        refused(() -> beforeRestore.prepare(stale, owner));
        var unknown = new NativePrincipalPins(3);
        unknown.restoreBindingsWithoutCounter(List.of(), Set.of());
        refused(() -> unknown.previewPrepare(A, 11000, 0, 7));
        assert unknown.reservedAppIds().isEmpty();
    }
    private static void capacity() throws Exception {
        for (boolean mixed : List.of(false, true)) {
            PackageManagerService pm = fixture(64, mixed);
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            var selected = manager.select(A, 0);
            var before = pm.mSettings.pins.snapshotForWrite();
            byte[] header = Files.readAllBytes(pm.mSettings.root.resolve("store.bin"));
            int remembers = pm.mSettings.rememberCalls, refreshes = pm.mSettings.refreshCalls;
            Os.forbiddenMonitor = pm.mLock;
            refused(() -> manager.prepare(selected));
            assert pm.mSettings.pins.snapshotForWrite().equals(before);
            assert manager.find(A, 0) == null && !pm.mSettings.pins.isAppIdPinned(11000);
            assert !pm.mSettings.isNativePrincipalAppIdLPr(11000);
            assert pm.mSettings.rememberCalls == remembers && pm.mSettings.refreshCalls == refreshes;
            Os.forbiddenMonitor = null;
            assert Arrays.equals(header, Files.readAllBytes(pm.mSettings.root.resolve("store.bin")));
        }
        for (int count : List.of(62, 63)) {
            PackageManagerService pm = fixture(count, false);
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            var selectedA = manager.select(A, 0);
            var a = manager.prepare(selectedA);
            assert manager.identity(a).id == count + 1 && manager.prepare(selectedA) == a;
            NativePrincipalManager.Handle b = count == 62 ? manager.prepare(manager.select(B, 0)) : null;
            String next = count == 62 ? "dev.andrix.admissionthird" : B;
            refused(() -> manager.prepare(manager.select(next, 0)));
            assert pm.mSettings.pins.snapshotForWrite().lastId == 64;
            assert manager.commit(a);
            if (b != null) assert manager.commit(b);
            assert pm.mSettings.mNativeIdentityLoaded.header.value.entries.size() == 64;
            // A retiring binding still consumes admission capacity.
            assert manager.beginRetirement(a);
            refused(() -> manager.prepare(manager.select(next, 0)));
            assert pm.mSettings.pins.snapshotForWrite().lastId == 64;
        }
        PackageManagerService pm = fixture(62, false);
        NativePrincipalManager manager = new NativePrincipalManager(pm);
        var a = manager.prepare(manager.select(A, 0));
        pm.mSettings.pins.beginRetire(pm.mSettings.pins.findId(manager.identity(a).id));
        var b = manager.prepare(manager.select(B, 0));
        refused(() -> manager.prepare(manager.select("dev.andrix.admissionthird", 0)));
        assert manager.beginRetirement(a) && manager.commit(b);
        assert pm.mSettings.mNativeIdentityLoaded.header.value.lastId == 64;
    }
    private static void projectionMatchesWriter() throws Exception {
        for (int held : List.of(0, 1, 62, 63, 64)) {
            for (int pending : List.of(0, 1, 2, 3)) {
                PackageManagerService pm = fixture(held, true);
                List<NativePrincipalPins.Record> records = new ArrayList<>();
                for (int i = 0; i < pending; i++) records.add(new NativePrincipalPins.Record(held + i + 1,
                        "dev.andrix.projected" + i, 11000 + i, 0, 7));
                var snapshot = new NativePrincipalPins.Snapshot(held + pending, records,
                        pending == 0 ? Set.of() : Set.of((long) held + 1));
                var projected = NativeIdentityPersistence.projectReservation(pm.mSettings.mNativeIdentityLoaded, snapshot);
                boolean fit;
                Os.forbiddenMonitor = pm.mLock;
                synchronized (pm.mLock) { fit = pm.mSettings.nativeIdentityReservationFitsLPr(snapshot); }
                assert fit == (held + pending <= NativeIdentityRecords.MAX_SLOTS);
                assert fit == (projected != null);
                Os.forbiddenMonitor = null;
                assert pm.mSettings.persistence.reservePending(snapshot) == fit;
                if (fit) assert pm.mSettings.persistence.load().header.value.equals(projected);
            }
        }
    }
    private static void projectionRefusalsAndLag() throws Exception {
        PackageManagerService pm = fixture(0, false);
        NativePrincipalManager manager = new NativePrincipalManager(pm);
        var a = manager.prepare(manager.select(A, 0));
        var first = pm.mSettings.pins.snapshotForWrite();
        var cache = pm.mSettings.mNativeIdentityLoaded;
        assert pm.mSettings.persistence.reservePending(first);
        var durable = pm.mSettings.persistence.load();
        assert !cache.header.value.equals(durable.header.value);
        // A skipped observe after the first header write must not count a pin twice.
        var b = manager.prepare(manager.select(B, 0));
        var both = pm.mSettings.pins.snapshotForWrite();
        var lagged = NativeIdentityPersistence.projectReservation(cache, both);
        var current = NativeIdentityPersistence.projectReservation(durable, both);
        assert lagged.equals(current) && current.entries.size() == 2;
        assert pm.mSettings.persistence.reservePending(both);
        assert pm.mSettings.persistence.load().header.value.equals(lagged);
        assert manager.commit(a) && manager.commit(b);

        PackageManagerService fresh = fixture(0, false);
        var own = new NativePrincipalPins.Snapshot(1,
                List.of(new NativePrincipalPins.Record(1, A, 11000, 0, 7)));
        assert fresh.mSettings.persistence.reservePending(own);
        var loaded = fresh.mSettings.persistence.load();
        assert NativeIdentityPersistence.projectReservation(loaded, own).equals(loaded.header.value);
        var wrong = new NativePrincipalPins.Snapshot(2,
                List.of(new NativePrincipalPins.Record(2, A, 11000, 0, 7)));
        var passed = new NativePrincipalPins.Snapshot(1,
                List.of(new NativePrincipalPins.Record(1, B, 11001, 0, 7)));
        var secondary = new NativePrincipalPins.Snapshot(2,
                List.of(new NativePrincipalPins.Record(2, B, 11001, 10, 8)));
        for (var snapshot : List.of(wrong, passed, secondary)) {
            assert NativeIdentityPersistence.projectReservation(loaded, snapshot) == null;
            byte[] before = Files.readAllBytes(fresh.mSettings.root.resolve("store.bin"));
            assert !fresh.mSettings.persistence.reservePending(snapshot);
            assert Arrays.equals(before, Files.readAllBytes(fresh.mSettings.root.resolve("store.bin")));
        }
    }

    private static void retainedOwnership() throws Exception {
        PackageManagerService pm = fixture(0, false);
        NativePrincipalManager manager = new NativePrincipalManager(pm);
        var selection = manager.select(A, 0);
        pm.mSettings.failLineage = true;
        refused(() -> manager.prepare(selection));
        assert pm.mSettings.pins.snapshotForWrite().lastId == 0;
        assert pm.mSettings.pins.reservedAppIds().isEmpty() && pm.mSettings.rememberCalls == 0;
        pm.mSettings.failLineage = false;
        pm.mSettings.failRemember = true;
        refused(() -> manager.prepare(selection));
        var first = manager.find(A, 0);
        assert manager.identity(first).id == 1 && manager.phase(first) == NativePrincipalPins.Phase.PENDING;
        assert manager.prepare(selection) == first;
        assert pm.mSettings.isNativePrincipalAppIdLPr(11000);
        pm.mSettings.failRefresh = true;
        refused(() -> manager.prepare(selection));
        assert manager.prepare(selection) == first && pm.mSettings.pins.snapshotForWrite().lastId == 1;
        // Lose only the auxiliary lookup and response references. The canonical
        // handle and original issuance facts still belong to the actual pin.
        var handles = NativePrincipalManager.class.getDeclaredField("handles"); handles.setAccessible(true);
        ((Map<?, ?>) handles.get(manager)).clear();
        var prepared = NativePrincipalManager.Selection.class.getDeclaredField("prepared"); prepared.setAccessible(true);
        prepared.set(selection, null);
        assert manager.find(A, 0) == first && manager.prepare(selection) == first;
        assert manager.commit(first) && pm.mSettings.mNativeIdentityLoaded.header.value.lastId == 1;
    }
    public static void main(String[] args) throws Exception {
        if (!NativePreparationAdmissionTest.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        LocalServices.addService(UserManagerInternal.class, new UserManagerInternal());
        corePlans(); capacity(); projectionMatchesWriter(); projectionRefusalsAndLag(); retainedOwnership();
        assert Os.allClosed();
        System.out.println("Exact native preparation capacity, projection and retained ownership passed; Android unqualified");
    }
}
