// SPDX-License-Identifier: Apache-2.0
// Host PMS facade around the actual slot store. Not Android state, permissions or authority.
package com.android.server.pm;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

final class Settings {
    static final String LINEAGE = "0123456789abcdef0123456789abcdef";
    NativePrincipalPins pins = new NativePrincipalPins(64);
    final AppIdSettingMap ids = new AppIdSettingMap();
    final HashMap<String, PackageSetting> packages = new HashMap<>();
    final HashSet<String> mutating = new HashSet<>();
    final HashSet<String> deferred = new HashSet<>();
    final Set<Integer> storeHolds = new TreeSet<>();
    final HashMap<Long, NativeIdentityRecords.Slot> remembered = new HashMap<>();
    final Path root;
    final NativeIdentityStore store;
    final NativeIdentityPersistence persistence;
    NativeIdentityStore.Loaded mNativeIdentityLoaded;
    boolean recoveryBlocked;
    boolean applied;
    boolean failLineage, failRemember, failRefresh;
    int rememberCalls, refreshCalls;

    Settings() { this(null, true); }
    // The production format. A host test may construct the version 2 format explicitly.
    Settings(Path existing, boolean initialize) { this(existing, initialize, NativeIdentityStore.Format.V1); }
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
        ArrayList<NativePrincipalPins.Record> records = new ArrayList<>();
        Set<Long> retiring = new TreeSet<>();
        for (int appId : loaded.slots.keySet()) {
            if (!loaded.bindingUsable(appId)) continue;
            NativeIdentityRecords.Slot slot = loaded.slots.get(appId).value;
            for (NativeIdentityRecords.UserEntry user : slot.users) {
                records.add(new NativePrincipalPins.Record(user.id, slot.packageName, appId,
                        user.userId, user.userSerial));
                if (user.retiring) retiring.add(user.id);
            }
        }
        records.sort(java.util.Comparator.comparingLong(value -> value.id));
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
    boolean nativePrincipalDesignationDeferredLPr(String name) { return deferred.contains(name); }
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
    }
    void observeNativeIdentityStoreLPw(NativeIdentityStore.Loaded value) {
        mNativeIdentityLoaded = value;
        storeHolds.addAll(value.occupiedAppIds);
        for (int id : value.slots.keySet()) {
            if (!value.bindingUsable(id)) continue;
            NativeIdentityRecords.Slot slot = value.slots.get(id).value;
            for (NativeIdentityRecords.UserEntry user : slot.users) remembered.putIfAbsent(user.id, slot);
        }
        refreshNativePrincipalAppIdsLPw();
    }
    NativeIdentityRecords.Slot nativePrincipalBindingLPr(NativePrincipalPins.Record record) {
        if (!mNativeIdentityLoaded.bindingUsable(record.appId)) return null;
        NativeIdentityRecords.Slot slot = mNativeIdentityLoaded.slots.get(record.appId).value;
        return matches(slot, record) ? slot : null;
    }
    NativeIdentityRecords.Slot nativePrincipalStoredBindingLPr(NativePrincipalPins.Record record) {
        NativeIdentityRecords.Slot slot = remembered.get(record.id);
        return slot != null && matches(slot, record) ? slot : null;
    }
    private static boolean matches(NativeIdentityRecords.Slot slot, NativePrincipalPins.Record record) {
        if (slot.appId != record.appId || !slot.packageName.equals(record.packageName)) return false;
        for (NativeIdentityRecords.UserEntry user : slot.users) {
            if (user.id == record.id && user.userId == record.userId
                    && user.userSerial == record.userSerial) return true;
        }
        return false;
    }
    void finishNativeIdentityReleaseLPw(NativePrincipalPins.Record record, NativeIdentityStore.Loaded observed) {
        if (!observed.enumerationComplete || observed.header.status != NativeIdentityStore.Status.VALID
                || observed.occupiedAppIds.contains(record.appId)) throw new AssertionError("early UID release");
        storeHolds.remove(record.appId);
        remembered.remove(record.id);
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
