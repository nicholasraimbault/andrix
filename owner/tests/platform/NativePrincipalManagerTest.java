// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import com.android.server.LocalServices;
import android.system.Os;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Actual adapter logic with PMS/user/write facades, not Android authority proof. */
public final class NativePrincipalManagerTest {
    // Legacy version 1 writer runs: Format.V1 explicitly, never the facade's production default.
    private static final NativeIdentityStore.Format LEGACY = NativeIdentityStore.Format.V1;
    private static void refused(Runnable operation) {
        try { operation.run(); } catch (IllegalArgumentException | IllegalStateException expected) { return; }
        throw new AssertionError("operation unexpectedly accepted");
    }
    // The retirement block of this account's user, every kind outstanding.
    private static NativeIdentityRecords.Retirement block(NativePrincipalPins.Record record) {
        java.util.List<NativeIdentityRecords.Obligation> outstanding = new java.util.ArrayList<>();
        for (NativeIdentityRecords.ObligationKind kind : NativeIdentityRecords.ObligationKind.values()) {
            outstanding.add(new NativeIdentityRecords.Obligation(kind,
                    NativeIdentityRecords.ObligationState.OUTSTANDING, NativeIdentityRecords.NO_REFERENCE, 0, 0));
        }
        return new NativeIdentityRecords.Retirement(NativeIdentityRecords.ActorClass.ACCOUNT_USER, record.userId,
                record.userSerial, NativeIdentityRecords.NO_REFERENCE, 1_700_000_000_100L, outstanding);
    }
    // Content and modification time of every path below the store.
    private static java.util.Map<String, String> footprint(Path root) throws Exception {
        java.util.Map<String, String> result = new java.util.TreeMap<>();
        try (var walk = Files.walk(root)) {
            for (Path path : walk.toList()) {
                result.put(root.relativize(path).toString(), Files.getLastModifiedTime(path) + " "
                        + (Files.isRegularFile(path) ? java.util.Base64.getEncoder().encodeToString(
                        Files.readAllBytes(path)) : "directory"));
            }
        }
        return result;
    }
    // Under the version 1 format the lifecycle record's retirement refuses with the format refusal
    // before any effect: every store byte and time and the pin's phase stay. So does the same
    // account's under Format.V2 (twinRefused).
    private static boolean retirementRefused(Path root, NativePrincipalManager manager,
            NativePrincipalManager.Handle handle) throws Exception {
        try (var walk = Files.walk(root)) {
            for (Path path : walk.toList()) {
                Files.setLastModifiedTime(path, java.nio.file.attribute.FileTime.fromMillis(86_400_000L));
            }
        }
        java.util.Map<String, String> before = footprint(root);
        NativePrincipalPins.Phase phase = manager.phase(handle);
        try {
            manager.beginRetirement(handle, block(manager.identity(handle)));
            return false;
        } catch (IllegalStateException refusal) {
            if (!"Native lifecycle records need the lifecycle format".equals(refusal.getMessage())
                    || !footprint(root).equals(before) || manager.phase(handle) != phase) {
                return false;
            }
        }
        return twinRefused(root, manager.identity(handle));
    }
    private static final java.util.function.Function<NativePrincipalPins.Record, NativeIdentityRecords.Retirement>
            TWIN_BLOCK = NativePrincipalManagerTest::block;
    private static int twins;

    // The same account under Format.V2, which reads this version 1 state as it is, reopened over a
    // copy of the same files: its retirement refuses with the format refusal before any effect, with
    // every byte and time of the copy and the twin pin's phase unchanged. A published body always
    // restores its pin there; an account without one restores none, and has no retirement to refuse.
    private static boolean twinRefused(Path root, NativePrincipalPins.Record identity) throws Exception {
        Path copy = root.resolveSibling(root.getFileName() + "-twin-" + ++twins);
        java.util.List<Path> paths;
        try (var walk = Files.walk(root)) {
            paths = walk.toList();
        }
        for (Path path : paths) {
            Path target = copy.resolve(root.relativize(path).toString());
            if (Files.isDirectory(path)) Files.createDirectories(target);
            else Files.copy(path, target);
        }
        PackageManagerService production = new PackageManagerService(copy, false, NativeIdentityStore.Format.V2);
        production.mSettings.restoreAfterPackageSettings();
        NativePrincipalManager manager = new NativePrincipalManager(production);
        NativePrincipalManager.Handle handle = manager.find(identity.packageName, identity.userId);
        if (handle == null) {
            NativeIdentityStore.ReadResult<NativeIdentityRecords.Slot> body = new NativeIdentityStore(copy.toFile(),
                    NativeIdentityStore.Format.V2).load().slots.get(identity.appId);
            System.out.println("twin V2: no pin without a published body of " + identity.packageName);
            return body == null || body.status != NativeIdentityStore.Status.VALID;
        }
        try (var walk = Files.walk(copy)) {
            for (Path path : walk.toList()) {
                Files.setLastModifiedTime(path, java.nio.file.attribute.FileTime.fromMillis(86_400_000L));
            }
        }
        java.util.Map<String, String> before = footprint(copy);
        NativePrincipalPins.Phase phase = manager.phase(handle);
        try {
            manager.beginRetirement(handle, TWIN_BLOCK.apply(identity));
            return false;
        } catch (IllegalStateException refusal) {
            System.out.println("twin V2: refused for " + identity.packageName);
            return "Native lifecycle records need the lifecycle format".equals(refusal.getMessage())
                    && footprint(copy).equals(before) && manager.phase(handle) == phase;
        }
    }

    @SuppressWarnings("try")
    private static void installLockExcludesAcquire() throws Exception {
        PackageManagerService pm = new PackageManagerService(null, true, LEGACY);
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
        PackageManagerService pm = new PackageManagerService(null, true, LEGACY);
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
        pm.mSettings.deferred.add(a.getPackageName());
        refused(() -> manager.prepare(manager.select(a.getPackageName(), 0)));
        pm.mSettings.deferred.clear();
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
        Os.forbiddenMonitor = pm.mLock;
        Os.failSync = true;
        assert !manager.commit(first);
        Os.failSync = false;
        assert manager.phase(first) == NativePrincipalPins.Phase.PENDING;
        refused(() -> manager.currentIdentity(first));
        assert first == manager.prepare(manager.select(a.getPackageName(), 0));
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

        // Retirement under the version 1 format refuses before any effect, for committed handles,
        // for a handle restored from the store, for a restored retiring body, beside a damaged header
        // and for a prepared but never published identity: the lifecycle record's retirement, the one
        // that survives, needs the lifecycle format, and the version 1 marker and release are gone.
        // Nothing is marked or released, and every hold stays. The positive halves run under Format.V3.
        Path persistedRoot = pm.mSettings.root;
        Os.forbiddenMonitor = pm.mLock;
        assert retirementRefused(persistedRoot, manager, first) && retirementRefused(persistedRoot, manager, second);
        assert manager.phase(first) == NativePrincipalPins.Phase.ACTIVE
                && manager.phase(second) == NativePrincipalPins.Phase.ACTIVE;
        assert pm.mSettings.pins.reservedAppIds().equals(Set.of(10123, 10124));
        assert pm.mSettings.storeHolds.containsAll(Set.of(10123, 10124));
        Os.forbiddenMonitor = null;
        PackageManagerService restoredPm = new PackageManagerService(persistedRoot, false, LEGACY);
        restoredPm.mSettings.add(a.getPackageName(), 10123); // Ordinary Settings read comes first.
        restoredPm.mSettings.restoreAfterPackageSettings();
        assert restoredPm.mSettings.storeHolds.containsAll(Set.of(10123, 10124));
        Os.forbiddenMonitor = restoredPm.mLock;
        NativePrincipalManager restored = new NativePrincipalManager(restoredPm);
        NativePrincipalManager.Handle recovery = restored.find(a.getPackageName(), 0);
        assert restored.phase(recovery) == NativePrincipalPins.Phase.PENDING;
        refused(() -> restored.commit(recovery)); // A stored binding is not current designation.
        PackageSetting restoredSubject = restoredPm.mSettings.getPackageLPr(a.getPackageName());
        restoredSubject.signing = new android.content.pm.SigningDetails(
                new android.content.pm.Signature(new byte[]{9}));
        refused(() -> restored.prepare(restored.select(a.getPackageName(), 0)));
        restoredSubject.signing = originalSigning;
        assert recovery == restored.prepare(restored.select(a.getPackageName(), 0));
        assert restored.commit(recovery);
        assert retirementRefused(persistedRoot, restored, recovery);
        Os.forbiddenMonitor = null;

        // A retiring body an older writer left restores a RETIRING pin, which no commit makes active
        // again, and whose retirement refuses too.
        NativeIdentityRecords.Slot body = new NativeIdentityStore(persistedRoot.toFile(), LEGACY).load()
                .slots.get(10123).value;
        NativeIdentityRecords.UserEntry user = body.users.get(0);
        byte[] marked = NativeIdentityRecords.encodeSlot(new NativeIdentityRecords.Slot(body.lineage, body.appId,
                body.packageName, body.generation + 1, body.signerSha256,
                java.util.List.of(new NativeIdentityRecords.UserEntry(user.id, user.userId, user.userSerial, true))));
        Files.write(persistedRoot.resolve("slots/10123/record.bin"), marked);
        Files.write(persistedRoot.resolve("slots/10123/record.bin.reservecopy"), marked);
        PackageManagerService afterMarker = new PackageManagerService(persistedRoot, false, LEGACY);
        afterMarker.mSettings.add(a.getPackageName(), 10123);
        afterMarker.mSettings.restoreAfterPackageSettings();
        Os.forbiddenMonitor = afterMarker.mLock;
        NativePrincipalManager markerManager = new NativePrincipalManager(afterMarker);
        NativePrincipalManager.Handle marker = markerManager.find(a.getPackageName(), 0);
        assert markerManager.phase(marker) == NativePrincipalPins.Phase.RETIRING;
        refused(() -> markerManager.commit(marker));
        assert retirementRefused(persistedRoot, markerManager, marker);
        assert afterMarker.mSettings.storeHolds.contains(10123);
        Os.forbiddenMonitor = null;

        // Counter/header damage does not destroy prior signer/user binding, retirement refuses beside
        // it, and a repair never patches the counter into live handles.
        PackageManagerService damaged = new PackageManagerService(null, true, LEGACY);
        damaged.mSettings.add(a.getPackageName(), 10123);
        NativePrincipalManager original = new NativePrincipalManager(damaged);
        NativePrincipalManager.Handle source = original.prepare(original.select(a.getPackageName(), 0));
        assert original.commit(source);
        Path header = damaged.mSettings.root.resolve("store.bin");
        Path reserve = damaged.mSettings.root.resolve("store.bin.reservecopy");
        byte[] savedHeader = Files.readAllBytes(header);
        Files.delete(header); Files.write(header, new byte[]{1});
        Files.delete(reserve); Files.write(reserve, new byte[]{2});
        PackageManagerService missingCounter = new PackageManagerService(damaged.mSettings.root, false, LEGACY);
        missingCounter.mSettings.add(a.getPackageName(), 10123);
        missingCounter.mSettings.add("dev.andrix.third", 10125);
        missingCounter.mSettings.restoreAfterPackageSettings();
        Os.forbiddenMonitor = missingCounter.mLock;
        assert !missingCounter.mSettings.pins.hasKnownCounter();
        NativePrincipalManager partial = new NativePrincipalManager(missingCounter);
        NativePrincipalManager.Handle intact = partial.find(a.getPackageName(), 0);
        assert intact == partial.prepare(partial.select(a.getPackageName(), 0));
        assert partial.commit(intact);
        refused(() -> partial.prepare(partial.select("dev.andrix.third", 0)));
        assert retirementRefused(damaged.mSettings.root, partial, intact);
        assert missingCounter.mSettings.storeHolds.contains(10123);
        Files.delete(header); Files.write(header, savedHeader);
        Files.delete(reserve); Files.write(reserve, savedHeader);
        assert !missingCounter.mSettings.pins.hasKnownCounter(); // Never patched into live handles.
        refused(() -> partial.prepare(partial.select("dev.andrix.third", 0)));
        Os.forbiddenMonitor = null;

        // A prepared but never published identity owns its pin, and its retirement refuses without
        // reserving or publishing anything: the pin keeps its place in this instance, and no store write
        // leaves a hold for the next.
        PackageManagerService early = new PackageManagerService(null, true, LEGACY);
        early.mSettings.add("dev.andrix.early", 10126);
        NativePrincipalManager earlyManager = new NativePrincipalManager(early);
        NativePrincipalManager.Handle neverActive = earlyManager.prepare(
                earlyManager.select("dev.andrix.early", 0));
        Os.forbiddenMonitor = early.mLock;
        assert retirementRefused(early.mSettings.root, earlyManager, neverActive);
        assert earlyManager.phase(neverActive) == NativePrincipalPins.Phase.PENDING;
        assert early.mSettings.pins.reservedAppIds().equals(Set.of(10126)) && early.mSettings.storeHolds.isEmpty();
        Os.forbiddenMonitor = null;
        PackageManagerService earlyNext = new PackageManagerService(early.mSettings.root, false, LEGACY);
        earlyNext.mSettings.add("dev.andrix.early", 10126);
        earlyNext.mSettings.restoreAfterPackageSettings();
        assert earlyNext.mSettings.storeHolds.isEmpty();

        // Codec support for a future header is not manager admission. Its
        // header-only UID hold survives even when no directory can reveal it.
        PackageManagerService versioned = new PackageManagerService(null, true, LEGACY);
        String knownName = "dev.andrix.versioned";
        versioned.mSettings.add(knownName, 10001);
        NativePrincipalManager oldVersion = new NativePrincipalManager(versioned);
        NativePrincipalManager.Handle known = oldVersion.prepare(oldVersion.select(knownName, 0));
        assert oldVersion.commit(known);
        NativeIdentityRecords.Header future = NativeIdentityRecords.Header.newV2(Settings.LINEAGE, 2,
                java.util.List.of(new NativeIdentityRecords.HeaderEntry(10000,
                        NativeIdentityRecords.SlotPhase.CREATING, 2, "dev.andrix.future",
                        new NativeIdentityRecords.CreationBinding(0, users.info.serialNumber, Set.of("b".repeat(64)))),
                        new NativeIdentityRecords.HeaderEntry(10001, NativeIdentityRecords.SlotPhase.LIVE, 0, "")));
        byte[] futureBytes = NativeIdentityRecords.encodeHeader(future);
        Files.write(versioned.mSettings.root.resolve("store.bin"), futureBytes);
        Files.write(versioned.mSettings.root.resolve("store.bin.reservecopy"), futureBytes);
        PackageManagerService unsupported = new PackageManagerService(versioned.mSettings.root, false, LEGACY);
        unsupported.mSettings.add(knownName, 10001);
        unsupported.mSettings.restoreAfterPackageSettings();
        NativePrincipalManager refusedVersion = new NativePrincipalManager(unsupported);
        assert unsupported.mSettings.storeHolds.equals(Set.of(10000, 10001));
        assert !unsupported.mSettings.pins.hasKnownCounter();
        assert refusedVersion.find(knownName, 0) == null;
        refused(() -> refusedVersion.prepare(refusedVersion.select(knownName, 0)));
        assert unsupported.mSettings.ids.acquireAndRegisterNewAppId(new PackageSetting("dev.andrix.ordinary")) == 10002;
        assert java.util.Arrays.equals(futureBytes, Files.readAllBytes(unsupported.mSettings.root.resolve("store.bin")));
        assert !Files.exists(unsupported.mSettings.root.resolve("slots/10000"));
        assert Os.allClosed();
        System.out.println("Native PMS adapter handles/unknown writes/retirement/restart passed; Android unqualified");
    }
}
