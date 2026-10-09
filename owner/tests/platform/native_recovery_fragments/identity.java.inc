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
