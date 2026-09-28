    boolean nativeIdentityReservationFitsLPr(NativeIdentityPersistence.CreationPlan plan) {
        return mNativeIdentityLoaded != null
                && nativeIdentityPersistenceLPr().projectReservation(mNativeIdentityLoaded, plan) != null;
    }
