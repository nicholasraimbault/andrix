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
            result.set(manager.prepare(manager.select("dev.andrix.locked", 0)));
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
        refused(() -> manager.select(a.getPackageName(), 10));
        refused(() -> manager.select("absent.package", 0));
        pm.mFrozenPackages.put(a.getPackageName(), 1);
        refused(() -> manager.prepare(manager.select(a.getPackageName(), 0)));
        pm.mFrozenPackages.clear();
        pm.installing.add(a.getPackageName());
        refused(() -> manager.prepare(manager.select(a.getPackageName(), 0)));
        pm.installing.clear();
        pm.mSettings.mutating.add(a.getPackageName());
        refused(() -> manager.prepare(manager.select(a.getPackageName(), 0)));
        pm.mSettings.mutating.clear();
        pm.mSettings.recoveryBlocked = true;
        refused(() -> manager.prepare(manager.select(a.getPackageName(), 0)));
        pm.mSettings.recoveryBlocked = false;
        a.system = true;
        refused(() -> manager.prepare(manager.select(a.getPackageName(), 0)));
        a.system = false;
        a.shared = true;
        refused(() -> manager.prepare(manager.select(a.getPackageName(), 0)));
        a.shared = false;
        a.volume = "external";
        refused(() -> manager.prepare(manager.select(a.getPackageName(), 0)));
        a.volume = null;
        a.pkg.sdk = true;
        refused(() -> manager.prepare(manager.select(a.getPackageName(), 0)));
        a.pkg.sdk = false;
        a.state.archive = new Object();
        refused(() -> manager.prepare(manager.select(a.getPackageName(), 0)));
        a.state.archive = null;

        NativePrincipalManager.Selection selected = manager.select(a.getPackageName(), 0);
        assert pm.mSettings.pins.reservedAppIds().isEmpty(); // Selecting is not reservation or consent.
        assert selected.appId == 10123 && selected.userSerial == 7;
        assert selected.currentSignerSha256.equals(Set.of(
                "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81"));
        try { selected.currentSignerSha256.clear(); throw new AssertionError("mutable signers"); }
        catch (UnsupportedOperationException expected) { }
        a.version++;
        refused(() -> manager.prepare(selected));
        a.version--;
        android.content.pm.SigningDetails originalSigning = a.signing;
        a.signing = new android.content.pm.SigningDetails(new android.content.pm.Signature(new byte[]{9}));
        refused(() -> manager.prepare(selected));
        a.signing = originalSigning;
        users.info.serialNumber++;
        refused(() -> manager.prepare(selected));
        users.info.serialNumber--;
        PackageSetting replacement = new PackageSetting(a.getPackageName()); replacement.appId = a.appId;
        pm.mSettings.packages.put(a.getPackageName(), replacement);
        pm.mSettings.ids.replaceSetting(a.appId, replacement);
        refused(() -> manager.prepare(selected)); // Same numbers/signers/version are not this installation.
        pm.mSettings.packages.put(a.getPackageName(), a);
        pm.mSettings.ids.replaceSetting(a.appId, a);
        refused(() -> new NativePrincipalManager(pm).prepare(selected));
        refused(() -> manager.prepare(null));
        NativePrincipalManager.Handle first = manager.prepare(selected);
        assert first == manager.prepare(selected);
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
        assert first == manager.prepare(manager.select(a.getPackageName(), 0));
        pm.mSettings.writeOk = true;
        assert manager.commit(first);
        assert manager.currentIdentity(first).id == manager.identity(first).id;
        a.signing = new android.content.pm.SigningDetails(new android.content.pm.Signature(new byte[]{9}));
        refused(() -> manager.currentIdentity(first));
        refused(() -> manager.commit(first));
        refused(() -> manager.prepare(selected));
        a.signing = originalSigning;
        users.info.serialNumber = 8;
        refused(() -> manager.currentIdentity(first));
        users.info.serialNumber = 7;
        NativePrincipalManager.Handle second = manager.prepare(manager.select("dev.andrix.second", 0));
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
        refused(() -> manager.prepare(selected)); // The old selection cannot recreate the account.
        assert pm.mSettings.pins.reservedAppIds().equals(Set.of(10124));
        refused(() -> manager.commit(first));
        assert manager.phase(second) == NativePrincipalPins.Phase.RETIRING;
        assert manager.finishRetirementAfterQuiescence(second);
        assert pm.mSettings.pins.reservedAppIds().isEmpty();

        NativePrincipalManager.Handle fresh = manager.prepare(manager.select(a.getPackageName(), 0));
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
        refused(() -> restored.commit(recovery)); // Restored metadata is not recovered designation.
        assert recovery == restored.prepare(restored.select(a.getPackageName(), 0));
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
