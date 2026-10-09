// SPDX-License-Identifier: Apache-2.0
// Host PMS facade around the actual slot store. Not Android state, permissions or authority.
package com.android.server.pm;

import android.os.UserHandle;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

// Restoration, stored histories, the identity predicate, the scan rule, path safety, boot
// recovery seeding, the boot facts, the retired boot queries, the deferral, the observation and
// the release finish are the exact fragments of the adapted framework Settings. Its restore runs
// them in the adapted boot order.
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
    // The adapted framework's names of the held app IDs, the boot data owners and the lock.
    final Set<Integer> mNativeStoreAppIds = storeHolds;
    java.util.Map<String, Integer> mNativeDeOwnersAtBoot = java.util.Map.of();
    boolean mNativeDeEnumerationComplete = true;
    final Object mLock = new Object();
    NativeIdentityPersistence.BootFacts mNativeBootFacts;
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
            // A new store's boot read: no fact, through the exact boot facts fragment.
            if (initialize) recordNativeBootFactsLPw(mNativeIdentityLoaded);
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
        // The adapted boot order: restore, observe, seed, then the boot facts.
        observeNativeIdentityStoreLPw(loaded);
        seedNativeRecoveryLPw();
        recordNativeBootFactsLPw(loaded);
    }

    // The exact boot facts fragment of the adapted framework Settings.
    // The boot facts, from the same boot read that restoration and seeding took before any scan
    // or write. Never the cached view, which every store read replaces, nor the remembered
    // histories. Each named package is deferred for the rest of this instance, so nothing under
    // its UID starts. They are recorded once.
    private void recordNativeBootFactsLPw(NativeIdentityStore.Loaded loaded) {
        if (mNativeBootFacts != null) throw new IllegalStateException("Native boot facts recorded twice");
        NativeIdentityPersistence.BootFacts facts = NativeIdentityPersistence.bootFacts(loaded);
        java.util.Set<String> names = new java.util.TreeSet<>();
        for (NativePrincipalPins.Record record : facts.retired.values()) names.add(record.packageName);
        for (NativeIdentityRecords.Slot tombstone : facts.ticketedTombstones.values()) {
            names.add(tombstone.packageName);
        }
        for (int appId : facts.releasingWithoutDirectory) {
            SettingBase mapping = mAppIds.getSetting(appId);
            if (mapping instanceof PackageSetting) names.add(((PackageSetting) mapping).getPackageName());
        }
        for (String name : names) {
            PackageSetting pkg = getPackageLPr(name);
            mNativeRecoveryView = deferNativeName(mNativeRecoveryView, name, pkg == null ? null : pkg.getPath());
        }
        mNativeBootFacts = facts;
    }

    // The exact retired boot queries fragment of the adapted framework Settings.
    // This instance's boot facts: the evidence of a retired boot and of continuing a release.
    NativeIdentityPersistence.BootFacts nativeBootFactsLPr() {
        if (mNativeBootFacts == null) throw new IllegalStateException("Native boot facts are not recorded");
        return mNativeBootFacts;
    }

    /** Whether this instance began with exactly this account RETIRED: a retired boot for it. */
    boolean nativeRetiredBootLPr(NativePrincipalPins.Record record) {
        return nativeBootFactsLPr().retiredBoot(record);
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
    // The exact observation fragment of the adapted framework Settings.
    void observeNativeIdentityStoreLPw(NativeIdentityStore.Loaded loaded) {
        mNativeIdentityLoaded = loaded;
        // A failed/reduced read is not authority to forget a previous hold.
        mNativeStoreAppIds.addAll(loaded.occupiedAppIds);
        rememberNativeHistoriesLPw(loaded);
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
                // A later slot version's stable prefix names its package as negative evidence.
                for (NativeIdentityRecords.SlotPrefix prefix : copies.prefixes) {
                    if (prefix.packageName.equals(packageName)) return true;
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

    // The exact release finish fragment of the adapted framework Settings.
    // The release finish, only after the checked store acknowledgement of a durable omission. It
    // forgets the remembered history, but the app ID stays in the held set until a new Settings
    // instance: the allocator skips it, the key fence holds, preparation refuses and package
    // mutation stays blocked, and callbacks queued in memory by its numeric IDs end with this one.
    void finishNativeIdentityReleaseLPw(NativePrincipalPins.Record record, NativeIdentityStore.Loaded loaded) {
        if (!loaded.enumerationComplete || loaded.header.status != NativeIdentityStore.Status.VALID
                || loaded.occupiedAppIds.contains(record.appId)) {
            throw new IllegalStateException("Native store release is not confirmed");
        }
        mNativeRememberedBindings.remove(record.id);
        observeNativeIdentityStoreLPw(loaded);
    }

    // The exact deferral fragment of the adapted framework Settings.
    void deferNativePackage(String packageName, File codePath) {
        synchronized (mLock) {
            if (codePath != null && !codePath.isAbsolute()) {
                mNativeRecoveryView = mNativeRecoveryView.defer(packageName, null).withUnidentifiedCode();
            } else mNativeRecoveryView = mNativeRecoveryView.defer(packageName, codePath);
        }
    }

    // The exact path safety fragment of the adapted framework Settings.
    private static NativePrincipalRecovery withNativeCodePath(NativePrincipalRecovery view, File codePath) {
        return codePath != null && codePath.isAbsolute() ? view.retainCode(codePath)
                : view.withUnidentifiedCode();
    }

    private static NativePrincipalRecovery deferNativeName(NativePrincipalRecovery view, String name, File codePath) {
        return codePath == null || codePath.isAbsolute() ? view.defer(name, codePath)
                : view.defer(name, null).withUnidentifiedCode();
    }

    // The exact recovery seeding fragment of the adapted framework Settings.
    private void seedNativeRecoveryLPw() {
        java.util.Set<String> names = new java.util.TreeSet<>();
        for (NativeIdentityStore.ReadResult<NativeIdentityRecords.Slot> copies
                : mNativeIdentityLoaded.slots.values()) {
            for (NativeIdentityRecords.Slot slot : copies.decodedCopies) names.add(slot.packageName);
            for (NativeIdentityRecords.SlotPrefix prefix : copies.prefixes) names.add(prefix.packageName);
        }
        for (NativeIdentityRecords.Header header : mNativeIdentityLoaded.header.decodedCopies) {
            for (NativeIdentityRecords.HeaderEntry entry : header.entries) {
                if (!entry.creationPackage.isEmpty()) names.add(entry.creationPackage);
            }
        }
        for (int appId : mNativeStoreAppIds) {
            SettingBase mapping = mAppIds.getSetting(appId);
            if (mapping instanceof PackageSetting) {
                PackageSetting pkg = (PackageSetting) mapping;
                names.add(pkg.getPackageName());
                mNativeRecoveryView = withNativeCodePath(mNativeRecoveryView, pkg.getPath());
                // The same history view as restoration: this mapped package's own body, or its
                // complete header reservation, stays recoverable only in the policy's Eligible
                // state, as the scan requires. Anything else is deferred: a retiring or retired
                // account, a suspended one, and every other mapping.
                NativeIdentityStore.History history = mNativeIdentityLoaded.history(appId);
                if (history == null || pkg.hasSharedUser()
                        || !history.packageName.equals(pkg.getPackageName())
                        || history.retiring
                        || !history.suspensions.isEmpty()) {
                    mNativeRecoveryView = deferNativeName(mNativeRecoveryView, pkg.getPackageName(), pkg.getPath());
                }
            } else {
                mNativeRecoveryView = mNativeRecoveryView.withUnidentifiedCode();
                if (mapping instanceof SharedUserSetting) {
                    for (com.android.server.pm.pkg.PackageStateInternal pkg
                            : ((SharedUserSetting) mapping).getPackageStates()) {
                        names.add(pkg.getPackageName());
                        mNativeRecoveryView = deferNativeName(mNativeRecoveryView, pkg.getPackageName(), pkg.getPath());
                    }
                }
            }
        }
        names.addAll(mNativeDeOwnersAtBoot.keySet());
        mNativeRecoveryView = mNativeRecoveryView.protectNames(names);
        if (!mNativeDeEnumerationComplete) mNativeRecoveryView = mNativeRecoveryView.withUnidentifiedCode();
        for (java.util.Map.Entry<String, Integer> footprint : mNativeDeOwnersAtBoot.entrySet()) {
            PackageSetting pkg = getPackageLPr(footprint.getKey());
            if (pkg == null || footprint.getValue() < 0
                    || UserHandle.getUid(UserHandle.USER_SYSTEM, pkg.getAppId()) != footprint.getValue()) {
                mNativeRecoveryView = deferNativeName(mNativeRecoveryView, footprint.getKey(),
                        pkg == null ? null : pkg.getPath());
            }
        }
        for (String name : names) {
            PackageSetting pkg = getPackageLPr(name);
            if (pkg != null) mNativeRecoveryView = withNativeCodePath(mNativeRecoveryView, pkg.getPath());
        }
        for (NativeIdentityStore.History history : mNativeIdentityLoaded.histories().values()) {
            PackageSetting pkg = getPackageLPr(history.packageName);
            if (pkg == null || pkg.getAppId() != history.appId || pkg.hasSharedUser()) {
                mNativeRecoveryView = deferNativeName(mNativeRecoveryView, history.packageName,
                        pkg == null ? null : pkg.getPath()).withUnidentifiedCode();
            }
        }
    }

    PackageSetting add(String name, int uid) {
        PackageSetting setting = new PackageSetting(name);
        setting.appId = uid;
        packages.put(name, setting);
        if (!ids.registerExistingAppId(uid, setting, name)) throw new AssertionError();
        return setting;
    }
}
