    /** Only metadata from this live Settings instance, never a store operation or authority. */
    NativePrincipalManager.Inspection nativeAccountInspectionLPr(int userId, long serial) {
        return NativePrincipalManager.project(userId, serial, mNativeIdentityLoaded,
                nativePrincipalPinsLPr(), mNativeStoreAppIds, mNativeRememberedBindings);
    }
