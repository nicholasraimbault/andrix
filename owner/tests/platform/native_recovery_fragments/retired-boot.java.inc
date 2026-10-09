    // This instance's boot facts: the evidence of a retired boot and of continuing a release.
    NativeIdentityPersistence.BootFacts nativeBootFactsLPr() {
        if (mNativeBootFacts == null) throw new IllegalStateException("Native boot facts are not recorded");
        return mNativeBootFacts;
    }

    /** Whether this instance began with exactly this account RETIRED: a retired boot for it. */
    boolean nativeRetiredBootLPr(NativePrincipalPins.Record record) {
        return nativeBootFactsLPr().retiredBoot(record);
    }
