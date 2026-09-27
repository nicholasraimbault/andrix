    boolean nativeIdentityReservationFitsLPr(NativePrincipalPins.Snapshot candidate) {
        return mNativeIdentityLoaded != null
                && NativeIdentityPersistence.projectReservation(mNativeIdentityLoaded, candidate) != null;
    }
