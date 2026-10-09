// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import com.android.server.LocalServices;
import java.util.Set;

/** Controlled failures compiled into temporary source copies, not hardware OOM qualification. */
public final class NativePreparationFaultTest {
    // Legacy version 1 writer runs: Format.V1 explicitly, never the facade's production default.
    private static final NativeIdentityStore.Format LEGACY = NativeIdentityStore.Format.V1;
    private static final String A = "dev.andrix.copyfirst", B = "dev.andrix.copysecond", C = "dev.andrix.copythird";
    private static void allocationFailure(Runnable operation) {
        try { operation.run(); }
        catch (OutOfMemoryError expected) { assert expected.getMessage().startsWith("injected"); return; }
        throw new AssertionError("injected allocation failure was not reached");
    }
    private static void copyFailures() {
        for (int point = 1; point <= 12; point++) {
            NativePreparationFaults.reset(0);
            NativePrincipalPins pins = new NativePrincipalPins(4);
            var a = NativePinTestSupport.prepare(pins, A, 11000, 0, 7);
            var b = NativePinTestSupport.prepare(pins, B, 11001, 0, 7);
            var before = pins.snapshotForWrite();
            var proposal = pins.previewPrepare(C, 11002, 0, 7);
            Object issuance = new Object();
            NativePreparationFaults.reset(point);
            allocationFailure(() -> pins.prepare(proposal, issuance));
            NativePreparationFaults.reset(0);
            assert pins.snapshotForWrite().equals(before);
            assert pins.find(A, 0) == a && pins.find(B, 0) == b;
            assert pins.find(C, 0) == null && !pins.isPackagePinned(C) && !pins.isAppIdPinned(11002);
            assert pins.reservedAppIds().equals(Set.of(11000, 11001));
            // The exact proposal remains current. A failed allocation issued no ID.
            var c = pins.prepare(proposal, issuance);
            assert c.record().id == 3 && c.issuance() == issuance;
        }
        for (int point = 1; point <= 12; point++) {
            NativePreparationFaults.reset(0);
            NativePrincipalPins pins = new NativePrincipalPins(4);
            var a = NativePinTestSupport.prepare(pins, A, 11000, 0, 7);
            var b = NativePinTestSupport.prepare(pins, B, 11001, 0, 7);
            pins.beginRetire(a);
            var before = pins.snapshotForWrite();
            NativePreparationFaults.reset(point);
            allocationFailure(() -> pins.finishRetire(a));
            NativePreparationFaults.reset(0);
            assert pins.snapshotForWrite().equals(before);
            assert pins.find(A, 0) == a && pins.find(B, 0) == b;
            assert a.phase() == NativePrincipalPins.Phase.RETIRING;
            assert pins.reservedAppIds().equals(Set.of(11000, 11001));
            pins.finishRetire(a);
            assert a.phase() == NativePrincipalPins.Phase.RETIRED && pins.find(A, 0) == null;
        }
        // The release's end of a pin shares that one index copy, and keeps the same state on failure.
        for (int point = 1; point <= 12; point++) {
            NativePreparationFaults.reset(0);
            NativePrincipalPins pins = new NativePrincipalPins(4);
            var a = NativePinTestSupport.prepare(pins, A, 11000, 0, 7);
            var b = NativePinTestSupport.prepare(pins, B, 11001, 0, 7);
            pins.beginRetire(a);
            var before = pins.snapshotForWrite();
            NativePreparationFaults.reset(point);
            allocationFailure(() -> pins.finishRelease(a));
            NativePreparationFaults.reset(0);
            assert pins.snapshotForWrite().equals(before);
            assert pins.find(A, 0) == a && pins.find(B, 0) == b;
            assert a.phase() == NativePrincipalPins.Phase.RETIRING;
            assert pins.reservedAppIds().equals(Set.of(11000, 11001));
            pins.finishRelease(a);
            assert a.phase() == NativePrincipalPins.Phase.RETIRED && pins.find(A, 0) == null;
        }
    }
    private static void issuedBeforeHandle() {
        NativePreparationFaults.reset(0);
        PackageManagerService pm = new PackageManagerService(null, true, LEGACY);
        PackageSetting setting = pm.mSettings.add(A, 11000);
        NativePrincipalManager manager = new NativePrincipalManager(pm);
        var selected = manager.select(A, 0);
        NativePreparationFaults.failAfterIssuance = true;
        allocationFailure(() -> manager.prepare(selected));
        assert pm.mSettings.pins.snapshotForWrite().lastId == 1;
        assert pm.mSettings.pins.isAppIdPinned(11000);
        assert pm.mSettings.rememberCalls == 0;
        var recovered = manager.prepare(manager.select(A, 0));
        assert manager.find(A, 0) == recovered;
        assert manager.identity(recovered).id == 1;
        assert manager.phase(recovered) == NativePrincipalPins.Phase.PENDING;
        long version = setting.version;
        setting.version++;
        try { manager.prepare(manager.select(A, 0)); throw new AssertionError("original designation replaced"); }
        catch (IllegalStateException expected) { }
        setting.version = version;
        assert manager.prepare(selected) == recovered;
        assert manager.commit(recovered);
        assert pm.mSettings.pins.snapshotForWrite().lastId == 1;
    }
    public static void main(String[] args) {
        if (!NativePreparationFaultTest.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        LocalServices.addService(UserManagerInternal.class, new UserManagerInternal());
        copyFailures(); issuedBeforeHandle();
        System.out.println("Controlled index and post-issuance failures retain exact state/ownership; Android OOM unqualified");
    }
}
