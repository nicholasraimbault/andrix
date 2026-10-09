    // The release finish, only after the checked store acknowledgement of a durable omission. It
    // forgets the remembered history, but the app ID stays in the held set until a new Settings
    // instance: the allocator skips it, the key fence holds, preparation refuses and package
    // mutation stays blocked, and callbacks queued in memory by its numeric IDs end with this one.
    void finishNativeIdentityReleaseLPw(NativePrincipalPins.Record record, NativeIdentityStore.Loaded loaded) {
        if (!loaded.enumerationComplete || loaded.header.status != NativeIdentityStore.Status.VALID
                || loaded.occupiedAppIds.contains(record.appId)) {
            throw new IllegalStateException("Native store release is not confirmed");
        }
        mNativeRememberedBindings.remove(record.id);
        observeNativeIdentityStoreLPw(loaded);
    }
