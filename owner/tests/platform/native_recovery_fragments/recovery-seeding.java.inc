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
