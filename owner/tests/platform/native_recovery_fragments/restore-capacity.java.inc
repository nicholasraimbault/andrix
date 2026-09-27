        NativePrincipalPins restored = new NativePrincipalPins(64);
        if (records.size() > 64) {
            // Parsing holds is not permission to exceed this adapter's binding
            // capacity or abort ordinary PMS boot. Retain every store footprint.
            restored.restoreBindingsWithoutCounter(java.util.List.of(), java.util.Set.of());
        } else if (loaded.counterRestorable()) {
            restored.restore(new NativePrincipalPins.Snapshot(loaded.header.value.lastId,
                    records, retiring));
        } else {
            // No usable counter, or an unselected header copy adds to it or does not
            // follow it. Keep every hold and eligible binding; guess no counter.
            restored.restoreBindingsWithoutCounter(records, retiring);
        }
