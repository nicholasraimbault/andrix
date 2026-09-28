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
