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
