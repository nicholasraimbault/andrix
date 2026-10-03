// SPDX-License-Identifier: Apache-2.0
// Host PMS facade around the actual slot store. Not Android state, permissions or authority.
package com.android.server.pm;

import android.os.UserHandle;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

// Restoration, stored histories, the identity predicate and the scan rule are the exact
// fragments of the adapted framework Settings. Boot recovery seeding is not run here; the
// separate history harness runs its exact fragment.
final class Settings {
    static final String LINEAGE = "0123456789abcdef0123456789abcdef";
    NativePrincipalPins pins = new NativePrincipalPins(64);
    final AppIdSettingMap ids = new AppIdSettingMap();
    // The adapted framework's names, for its exact fragments.
    final AppIdSettingMap mAppIds = ids;
    NativePrincipalRecovery mNativeRecoveryView = NativePrincipalRecovery.empty();
    final HashMap<String, PackageSetting> packages = new HashMap<>();
    final HashSet<String> mutating = new HashSet<>();
    final HashSet<String> deferred = new HashSet<>();
    final Set<Integer> storeHolds = new TreeSet<>();
    final HashMap<Long, NativeIdentityStore.History> mNativeRememberedBindings = new HashMap<>();
    final Path root;
    final NativeIdentityStore store;
    final NativeIdentityPersistence persistence;
    NativeIdentityStore.Loaded mNativeIdentityLoaded;
    boolean recoveryBlocked;
    boolean applied;
    boolean failLineage, failRemember, failRefresh;
    int rememberCalls, refreshCalls;

    Settings() { this(null, true); }
    // The production format of the boot read. A rollback or legacy test passes V1 explicitly.
    Settings(Path existing, boolean initialize) { this(existing, initialize, NativeIdentityStore.Format.V2); }
    Settings(Path existing, boolean initialize, NativeIdentityStore.Format format) {
        try {
            root = existing != null ? existing : Files.createTempDirectory("native-manager-").resolve("store");
            store = new NativeIdentityStore(root.toFile(), format);
            if (initialize && !store.initializeNew(LINEAGE)) throw new AssertionError("fixture initialization");
            persistence = new NativeIdentityPersistence(store);
            mNativeIdentityLoaded = persistence.load();
            applied = initialize;
        } catch (java.io.IOException error) { throw new AssertionError(error); }
    }

    void restoreAfterPackageSettings() {
        if (applied) throw new AssertionError("already restored");
        NativeIdentityStore.Loaded loaded = persistence.load();
        mNativeIdentityLoaded = loaded;
        // The exact restore-history fragment of the adapted framework Settings.
        // Every eligible body, and every complete header creation whose slot this view reads
        // as missing, through the one shared restoration. Holding them needs no mapping.
        NativeIdentityPersistence.Restoration restoration =
                NativeIdentityPersistence.restoration(loaded.histories());
        java.util.List<NativePrincipalPins.Record> records = restoration.records;
        java.util.Set<Long> retiring = restoration.retiringIds;
        // The exact restore-capacity fragment of the adapted framework Settings.
        NativePrincipalPins restored = new NativePrincipalPins(64);
        if (records.size() > 64) {
            // Parsing holds is not permission to exceed this adapter's binding
            // capacity or abort ordinary PMS boot. Retain every store footprint.
            restored.restoreBindingsWithoutCounter(java.util.List.of(), java.util.Set.of());
        } else if (loaded.counterRestorable()) {
            restored.restore(new NativePrincipalPins.Snapshot(loaded.header.value.lastId,
                    records, retiring));
        } else {
            // No usable counter, or an unselected header copy adds to it or does not
            // follow it. Keep every hold and eligible binding; guess no counter.
            restored.restoreBindingsWithoutCounter(records, retiring);
        }
        pins = restored;
        applied = true;
        observeNativeIdentityStoreLPw(loaded);
    }

    NativePrincipalPins nativePrincipalPinsLPr() { return pins; }
    boolean nativePrincipalCreationReadyLPr() {
        return applied && !recoveryBlocked && mNativeIdentityLoaded.creationReady() && pins.hasKnownCounter();
    }
    boolean nativeIdentityReservationFitsLPr(NativeIdentityPersistence.CreationPlan plan) {
        return mNativeIdentityLoaded != null
                && nativeIdentityPersistenceLPr().projectReservation(mNativeIdentityLoaded, plan) != null;
    }
    boolean nativePrincipalMutationInProgressLPr(String name) { return mutating.contains(name); }
    boolean nativePrincipalDesignationDeferredLPr(String name) {
        return deferred.contains(name) || mNativeRecoveryView.defersName(name);
    }
    PackageSetting getPackageLPr(String name) { return packages.get(name); }
    SettingBase getSettingLPr(int id) { return ids.getSetting(id); }
    boolean isNativePrincipalAppIdLPr(int appId) {
        return storeHolds.contains(appId) || pins.isAppIdPinned(appId);
    }
    NativeIdentityPersistence nativeIdentityPersistenceLPr() { return persistence; }
    String nativeIdentityLineageLPr() {
        if (failLineage) throw new IllegalStateException("injected lineage observation failure");
        if (!nativePrincipalCreationReadyLPr()) throw new IllegalStateException("counter unavailable");
        return mNativeIdentityLoaded.header.value.lineage;
    }
    void rememberNativeSubjectLPw(PackageSetting setting) {
        rememberCalls++;
        if (failRemember) { failRemember = false; throw new IllegalStateException("injected remember failure"); }
        /* No filesystem or authority here. */
    }
    void refreshNativePrincipalAppIdsLPw() {
        refreshCalls++;
        if (failRefresh) { failRefresh = false; throw new IllegalStateException("injected refresh failure"); }
        TreeSet<Integer> union = new TreeSet<>(storeHolds);
        union.addAll(pins.reservedAppIds());
        ids.setNativePrincipalAppIds(union);
        // As the adapted framework's refresh does: the recovery view holds the same app IDs.
        mNativeRecoveryView = mNativeRecoveryView.withHolds(union);
    }
    void observeNativeIdentityStoreLPw(NativeIdentityStore.Loaded value) {
        mNativeIdentityLoaded = value;
        storeHolds.addAll(value.occupiedAppIds);
        rememberNativeHistoriesLPw(value);
        refreshNativePrincipalAppIdsLPw();
    }

    // The exact stored-history fragment of the adapted framework Settings.
    // Prior binding metadata for this live PMS instance, only for an existing exact core pin:
    // its body or header reservation history, first seen and never replaced. It is not a
    // substitute for current eligibility or an authority grant.
    private void rememberNativeHistoriesLPw(NativeIdentityStore.Loaded loaded) {
        for (NativeIdentityStore.History history : loaded.histories().values()) {
            NativePrincipalPins.Pin pin = nativePrincipalPinsLPr().findId(history.id);
            if (pin != null && NativeIdentityPersistence.identifies(history, pin.record())) {
                mNativeRememberedBindings.putIfAbsent(history.id, history);
            }
        }
    }

    /** The original history remembered for exactly this record, every field included, or null. */
    NativeIdentityStore.History nativePrincipalStoredHistoryLPr(NativePrincipalPins.Record record) {
        NativeIdentityStore.History history = mNativeRememberedBindings.get(record.id);
        return history != null && NativeIdentityPersistence.identifies(history, record) ? history : null;
    }

    // Published bodies only, as in the adapted framework: never a header reservation.
    NativeIdentityRecords.Slot nativePrincipalBindingLPr(NativePrincipalPins.Record record) {
        if (!mNativeIdentityLoaded.bindingUsable(record.appId)) return null;
        NativeIdentityRecords.Slot slot = mNativeIdentityLoaded.slots.get(record.appId).value;
        return matches(slot, record) ? slot : null;
    }
    private static boolean matches(NativeIdentityRecords.Slot slot, NativePrincipalPins.Record record) {
        if (slot.appId != record.appId || !slot.packageName.equals(record.packageName)) return false;
        for (NativeIdentityRecords.UserEntry user : slot.users) {
            if (user.id == record.id && user.userId == record.userId
                    && user.userSerial == record.userSerial) return true;
        }
        return false;
    }

    // The exact identity fragment of the adapted framework Settings.
    boolean isNativePrincipalPackageLPr(String packageName) {
        if (packageName == null) return false;
        if (nativePrincipalPinsLPr().isPackagePinned(packageName)) return true;
        PackageSetting setting = getPackageLPr(packageName);
        if (setting != null && isNativePrincipalAppIdLPr(setting.getAppId())) return true;
        if (mNativeIdentityLoaded != null) {
            for (NativeIdentityStore.ReadResult<NativeIdentityRecords.Slot> copies
                    : mNativeIdentityLoaded.slots.values()) {
                for (NativeIdentityRecords.Slot slot : copies.decodedCopies) {
                    if (slot.packageName.equals(packageName)) return true;
                }
            }
            for (NativeIdentityRecords.Header header : mNativeIdentityLoaded.header.decodedCopies) {
                for (NativeIdentityRecords.HeaderEntry entry : header.entries) {
                    if (entry.creationPackage.equals(packageName)) return true;
                }
            }
        }
        return false;
    }

    // The exact scan fragment of the adapted framework Settings.
    boolean nativeScanSubjectAllowedLPr(PackageSetting candidate) {
        if (!isNativePrincipalPackageLPr(candidate.getPackageName())
                && !isNativePrincipalAppIdLPr(candidate.getAppId())) return true;
        return nativeScanOwnerLPr(candidate) != null;
    }

    /** Only after normal APK verification/reconcile, before attaching any code. */
    boolean nativeScanBindingAllowedLPr(PackageSetting candidate, android.content.pm.SigningDetails signer) {
        if (!isNativePrincipalPackageLPr(candidate.getPackageName())
                && !isNativePrincipalAppIdLPr(candidate.getAppId())) return true;
        NativeIdentityStore.History history = nativeScanOwnerLPr(candidate);
        if (history == null) return false;
        // The APK's signers against the recorded historical set, never the current APK's own.
        try { return history.signerSha256.equals(NativePrincipalManager.signerDigests(signer)); }
        catch (IllegalStateException unavailable) { return false; }
    }

    // The one shared scan rule over the cached history of the candidate's app ID, a body or a
    // header reservation. Empty-slot restoration is a separately owned recovery operation. Do
    // not guess a fresh UID or mutate installed truth in the scan stream.
    private NativeIdentityStore.History nativeScanOwnerLPr(PackageSetting candidate) {
        String name = candidate.getPackageName();
        int appId = candidate.getAppId();
        if (mNativeRecoveryView.defersName(name) || mNativeIdentityLoaded == null) return null;
        SettingBase mapping = mAppIds.getSetting(appId);
        PackageSetting owner = mapping instanceof PackageSetting mapped ? mapped : null;
        com.android.server.pm.UserManagerInternal users =
                com.android.server.LocalServices.getService(com.android.server.pm.UserManagerInternal.class);
        android.content.pm.UserInfo user = users == null ? null : users.getUserInfo(UserHandle.USER_SYSTEM);
        return NativeIdentityPersistence.scanOwner(mNativeIdentityLoaded.history(appId), name, appId,
                candidate.hasSharedUser(), owner == null ? null : owner.getPackageName(),
                owner != null && owner.hasSharedUser(),
                user == null || user.partial ? -1 : user.serialNumber);
    }

    void finishNativeIdentityReleaseLPw(NativePrincipalPins.Record record, NativeIdentityStore.Loaded observed) {
        if (!observed.enumerationComplete || observed.header.status != NativeIdentityStore.Status.VALID
                || observed.occupiedAppIds.contains(record.appId)) throw new AssertionError("early UID release");
        storeHolds.remove(record.appId);
        mNativeRememberedBindings.remove(record.id);
        observeNativeIdentityStoreLPw(observed);
    }
    PackageSetting add(String name, int uid) {
        PackageSetting setting = new PackageSetting(name);
        setting.appId = uid;
        packages.put(name, setting);
        if (!ids.registerExistingAppId(uid, setting, name)) throw new AssertionError();
        return setting;
    }
}
