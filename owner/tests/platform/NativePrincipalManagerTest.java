// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import com.android.server.LocalServices;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Actual adapter logic with PMS/user/write facades, not Android authority proof. */
public final class NativePrincipalManagerTest {
    private static void refused(Runnable operation) {
        try { operation.run(); } catch (IllegalArgumentException | IllegalStateException expected) { return; }
        throw new AssertionError("operation unexpectedly accepted");
    }
    @SuppressWarnings("try")
    private static void installLockExcludesAcquire() throws Exception {
        PackageManagerService pm = new PackageManagerService();
        pm.mSettings.add("dev.andrix.locked", 10130);
        NativePrincipalManager manager = new NativePrincipalManager(pm);
        CountDownLatch started = new CountDownLatch(1);
        AtomicReference<NativePrincipalManager.Handle> result = new AtomicReference<>();
        Thread thread = new Thread(() -> {
            started.countDown();
            result.set(manager.prepare("dev.andrix.locked", 0, 10130, 7));
        });
        thread.setDaemon(true);
        try (PackageManagerTracedLock ignored = pm.mInstallLock.acquireLock()) {
            thread.start();
            assert started.await(5, TimeUnit.SECONDS);
            Thread.sleep(50);
            assert result.get() == null && pm.mSettings.pins.find("dev.andrix.locked", 0) == null;
        }
        thread.join(5000);
        assert !thread.isAlive() && result.get() != null;
    }

    public static void main(String[] args) throws Exception {
        if (!NativePrincipalManagerTest.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        UserManagerInternal users = new UserManagerInternal();
        LocalServices.addService(UserManagerInternal.class, users);
        installLockExcludesAcquire();
        PackageManagerService pm = new PackageManagerService();
        PackageSetting a = pm.mSettings.add("dev.andrix.first", 10123);
        pm.mSettings.add("dev.andrix.second", 10124);
        NativePrincipalManager manager = new NativePrincipalManager(pm);
        refused(() -> manager.prepare(a.getPackageName(), 10, 10123, 7));
        refused(() -> manager.prepare("absent.package", 0, 10123, 7));
        pm.mFrozenPackages.put(a.getPackageName(), 1);
        refused(() -> manager.prepare(a.getPackageName(), 0, 10123, 7));
        pm.mFrozenPackages.clear();
        pm.installing.add(a.getPackageName());
        refused(() -> manager.prepare(a.getPackageName(), 0, 10123, 7));
        pm.installing.clear();
        pm.mSettings.mutating.add(a.getPackageName());
        refused(() -> manager.prepare(a.getPackageName(), 0, 10123, 7));
        pm.mSettings.mutating.clear();
        pm.mSettings.recoveryBlocked = true;
        refused(() -> manager.prepare(a.getPackageName(), 0, 10123, 7));
        pm.mSettings.recoveryBlocked = false;
        a.system = true;
        refused(() -> manager.prepare(a.getPackageName(), 0, 10123, 7));
        a.system = false;
        a.shared = true;
        refused(() -> manager.prepare(a.getPackageName(), 0, 10123, 7));
        a.shared = false;
        a.volume = "external";
        refused(() -> manager.prepare(a.getPackageName(), 0, 10123, 7));
        a.volume = null;
        a.pkg.sdk = true;
        refused(() -> manager.prepare(a.getPackageName(), 0, 10123, 7));
        a.pkg.sdk = false;
        a.state.archive = new Object();
        refused(() -> manager.prepare(a.getPackageName(), 0, 10123, 7));
        a.state.archive = null;

        refused(() -> manager.prepare(a.getPackageName(), 0, 10124, 7));
        refused(() -> manager.prepare(a.getPackageName(), 0, 10123, 8));
        NativePrincipalManager.Handle first = manager.prepare(a.getPackageName(), 0, 10123, 7);
        assert first == manager.prepare(a.getPackageName(), 0, 10123, 7);
        assert first == manager.find(a.getPackageName(), 0);
        assert manager.phase(first) == NativePrincipalPins.Phase.PENDING;
        assert manager.identity(first).appId == 10123 && manager.identity(first).userSerial == 7;
        assert pm.mSettings.pins.reservedAppIds().equals(Set.of(10123));
        refused(() -> manager.currentIdentity(first));
        pm.mSettings.writeOk = false;
        pm.mSettings.storeOnFailure = true; // Publication may occur despite a lost acknowledgement.
        assert !manager.commit(first);
        assert manager.phase(first) == NativePrincipalPins.Phase.PENDING;
        refused(() -> manager.currentIdentity(first));
        assert first == manager.prepare(a.getPackageName(), 0, 10123, 7);
        pm.mSettings.writeOk = true;
        assert manager.commit(first);
        assert manager.currentIdentity(first).id == manager.identity(first).id;
        users.info.serialNumber = 8;
        refused(() -> manager.currentIdentity(first));
        users.info.serialNumber = 7;
        NativePrincipalManager.Handle second = manager.prepare("dev.andrix.second", 0, 10124, 7);
        assert manager.commit(second);

        // The durable marker is a separate step before quiescence. An unknown
        // marker outcome cannot authorize the final omission.
        pm.mSettings.writeOk = false;
        assert !manager.beginRetirement(first);
        assert manager.phase(first) == NativePrincipalPins.Phase.RETIRING;
        refused(() -> manager.commit(first));
        refused(() -> manager.finishRetirementAfterQuiescence(first));
        pm.mSettings.writeOk = true;
        assert manager.beginRetirement(first);
        assert manager.beginRetirement(second);
        long secondId = manager.identity(second).id;
        assert pm.mSettings.persisted.retiringIds.size() == 2;
        // Simulated external quiescence of FIRST only. SECOND still owns its pin.
        pm.mSettings.writeOk = false;
        assert !manager.finishRetirementAfterQuiescence(first);
        assert pm.mSettings.pins.reservedAppIds().equals(Set.of(10123, 10124));
        assert pm.mSettings.persisted.records.size() == 1;
        assert pm.mSettings.persisted.retiringIds.equals(Set.of(secondId));
        pm.mSettings.writeOk = true;
        assert manager.finishRetirementAfterQuiescence(first);
        assert manager.finishRetirementAfterQuiescence(first); // Exact local result reconciliation.
        assert pm.mSettings.pins.reservedAppIds().equals(Set.of(10124));
        refused(() -> manager.commit(first));
        assert manager.phase(second) == NativePrincipalPins.Phase.RETIRING;
        assert manager.finishRetirementAfterQuiescence(second);
        assert pm.mSettings.pins.reservedAppIds().isEmpty();

        NativePrincipalManager.Handle fresh = manager.prepare(a.getPackageName(), 0, 10123, 7);
        assert manager.identity(fresh).id > secondId;
        assert manager.commit(fresh);
        PackageManagerService restoredPm = new PackageManagerService();
        restoredPm.mSettings.add(a.getPackageName(), 10123);
        restoredPm.mSettings.pins.restore(pm.mSettings.persisted);
        restoredPm.mSettings.refreshNativePrincipalAppIdsLPw();
        NativePrincipalManager restored = new NativePrincipalManager(restoredPm);
        NativePrincipalManager.Handle recovery = restored.find(a.getPackageName(), 0);
        assert restored.phase(recovery) == NativePrincipalPins.Phase.PENDING;
        refused(() -> restored.commit(fresh)); // A handle from another service incarnation.
        assert restored.commit(recovery);
        assert restored.beginRetirement(recovery);
        PackageManagerService afterMarker = new PackageManagerService();
        afterMarker.mSettings.add(a.getPackageName(), 10123);
        afterMarker.mSettings.pins.restore(restoredPm.mSettings.persisted);
        afterMarker.mSettings.refreshNativePrincipalAppIdsLPw();
        NativePrincipalManager markerManager = new NativePrincipalManager(afterMarker);
        NativePrincipalManager.Handle marker = markerManager.find(a.getPackageName(), 0);
        assert markerManager.phase(marker) == NativePrincipalPins.Phase.RETIRING;
        refused(() -> markerManager.commit(marker));
        refused(() -> markerManager.finishRetirementAfterQuiescence(marker));
        assert markerManager.beginRetirement(marker); // Reconfirm exact persisted marker first.
        assert markerManager.finishRetirementAfterQuiescence(marker);
        System.out.println("Native PMS adapter handles/unknown writes/retirement/restart passed; Android unqualified");
    }
}
