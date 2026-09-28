package com.android.server.pm;

import static com.android.server.pm.NativeHeaderTestSupport.*;
import static com.android.server.pm.NativeBindingTestSupport.*;
import com.android.server.LocalServices;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.UserEntry;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public final class UnsupportedCounterProbe {
    public static void main(String[] args) throws Exception {
        if (!UnsupportedCounterProbe.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        start(Path.of(args[0]));
        LocalServices.addService(UserManagerInternal.class, new UserManagerInternal());
        Path root = layout(null, bytes(header(1, live(B))), bytes(header(1, live(B))));
        slot(root, B, new Slot(LINEAGE, B, PKG_B, 1, SIGNERS, List.of(new UserEntry(2, 1, SERIAL, false))));
        NativeIdentityStore.Loaded loaded = loadedOf(root, V1);
        NativeHistoryHarness harness = new NativeHistoryHarness();
        harness.map(B, new NativeHistoryHarness.PackageSetting(PKG_B, B, false));
        harness.map(C, new NativeHistoryHarness.PackageSetting(PKG_C, C, false));
        harness.mNativeDeOwnersAtBoot = Map.of(PKG_B, B, PKG_C, C);
        harness.apply(loaded);
        System.out.println("before N=" + loaded.slots.get(B).status + " ready=" + loaded.creationReady()
                + " counter_restorable=" + loaded.counterRestorable() + " unsupported_format=" + loaded.unsupportedFootprint
                + " Q_deferred=" + harness.mNativeRecoveryView.defersName(PKG_C));
        assert !harness.mNativeRecoveryView.defersName(PKG_C);
        PackageManagerService pm = reopenOf(root, V1, Map.of(PKG_B, B, PKG_C, C));
        NativePrincipalManager manager = new NativePrincipalManager(pm);
        NativePrincipalManager.Handle created = manager.prepare(manager.select(PKG_C, 0));
        long id = manager.identity(created).id;
        System.out.println("prepared Q principal ID=" + id + " beside decoded unsupported N principal ID=2");
        boolean committed = manager.commit(created);
        NativeIdentityStore.Loaded after = pm.mSettings.store.load();
        System.out.println("commit=" + committed + " Q_phase=" + manager.phase(created)
                + " N=" + after.slots.get(B).status + " Q=" + after.slots.get(C).status
                + " holds=" + after.occupiedAppIds + " selected_counter=" + after.header.value.lastId);
        if (id == 2) throw new AssertionError("issued a principal ID already present in decoded same-lineage unsupported state");
    }
}
