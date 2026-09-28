        // Host adapter for B2: the shared restoration over this view's BODY histories alone.
        java.util.Map<Integer, NativeIdentityStore.History> bodies = new java.util.TreeMap<>();
        for (java.util.Map.Entry<Integer, NativeIdentityStore.History> entry
                : loaded.histories().entrySet()) {
            if (entry.getValue().source == NativeIdentityStore.Source.BODY) {
                bodies.put(entry.getKey(), entry.getValue());
            }
        }
        NativeIdentityPersistence.Restoration restoration =
                NativeIdentityPersistence.restoration(bodies);
        return new Inputs(restoration.records, restoration.retiringIds);
