    void observeNativeIdentityStoreLPw(NativeIdentityStore.Loaded loaded) {
        mNativeIdentityLoaded = loaded;
        // A failed/reduced read is not authority to forget a previous hold.
        mNativeStoreAppIds.addAll(loaded.occupiedAppIds);
        rememberNativeHistoriesLPw(loaded);
        refreshNativePrincipalAppIdsLPw();
    }
