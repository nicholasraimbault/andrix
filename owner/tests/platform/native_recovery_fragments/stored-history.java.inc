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
