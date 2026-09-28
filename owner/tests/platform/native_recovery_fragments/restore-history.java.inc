        // Every eligible body, and every complete header creation whose slot this view reads
        // as missing, through the one shared restoration. Holding them needs no mapping.
        NativeIdentityPersistence.Restoration restoration =
                NativeIdentityPersistence.restoration(loaded.histories());
        java.util.List<NativePrincipalPins.Record> records = restoration.records;
        java.util.Set<Long> retiring = restoration.retiringIds;
