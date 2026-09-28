package com.android.server.pm;

import static com.android.server.pm.NativeHeaderTestSupport.*;
import static com.android.server.pm.NativeBindingTestSupport.*;
import com.android.server.LocalServices;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativePrincipalPins.Phase;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/** Existing B1 behavior only, with controlled host disk mutations and a synthetic retirement boundary. */
public final class BodyOriginRetirementProbe {
    private static void one(NativeIdentityStore.Format format, String mode) throws Exception {
        boolean live = mode.equals("live-missing");
        Header held = format == V1 ? header(1, live ? live(B) : creating(B, 1, PKG_B))
                : v2(1, live ? live(B) : boundCreating(B, 1, PKG_B));
        Header ahead = format == V1 ? header(2, creating(B, 1, PKG_B), creating(C, 2, PKG_C))
                : v2(2, boundCreating(B, 1, PKG_B), boundCreating(C, 2, PKG_C));
        Path root = mode.equals("counter-unknown") ? layout(bytes(held), bytes(ahead), bytes(ahead))
                : layout(null, bytes(held), bytes(held));
        slot(root, B, bound(B, PKG_B, 1, false, 1));
        PackageManagerService pm = reopenOf(root, format, Map.of(PKG_B, B));
        NativePrincipalManager manager = new NativePrincipalManager(pm);
        NativePrincipalManager.Handle handle = manager.find(PKG_B, 0);
        assert handle != null && manager.phase(handle) == Phase.PENDING;
        assert pm.mSettings.pins.findId(1).issuance() == null;
        Map<String, String> before = headerFootprint(root);
        Path directory = root.resolve("slots/" + B);
        if (!mode.equals("present")) {
            for (String name : List.of("record.bin", "record.bin.reservecopy")) {
                if (mode.equals("damaged")) Files.write(directory.resolve(name), new byte[]{1, 2, 3});
                else Files.delete(directory.resolve(name));
            }
            if (!mode.equals("damaged")) Files.delete(directory);
        }
        boolean marked = manager.beginRetirement(handle);
        NativeIdentityStore.Loaded after = pm.mSettings.store.load();
        boolean expected = mode.equals("missing") || mode.equals("present");
        System.out.println(format + " " + mode + " marked=" + marked + " phase=" + manager.phase(handle)
                + " counter_known=" + pm.mSettings.pins.hasKnownCounter()
                + " header=" + after.header.value + " slot=" + after.slots.get(B).status);
        assert marked == expected && manager.phase(handle) == Phase.RETIRING;
        Header expectedHeader = mode.equals("missing")
                ? (format == V1 ? header(1, live(B)) : v2(1, live(B))) : held;
        assert after.header.value.equals(expectedHeader);
        if (expected) {
            Slot body = after.slots.get(B).value;
            assert body != null && body.generation == 2 && body.signerSha256.equals(SIGNERS)
                    && body.users.size() == 1 && body.users.get(0).id == 1 && body.users.get(0).retiring;
            assert manager.finishRetirementAfterQuiescence(handle);
            assert pm.mSettings.store.load().occupiedAppIds.isEmpty();
            assert pm.mSettings.store.load().header.value.lastId == 1;
        } else {
            assert before.keySet().equals(headerFootprint(root).keySet());
            if (mode.equals("counter-unknown")) {
                assert before.equals(headerFootprint(root));
                assert !pm.mSettings.pins.hasKnownCounter();
            }
            if (!mode.equals("damaged")) assert !Files.exists(directory);
            else assert java.util.Arrays.equals(Files.readAllBytes(directory.resolve("record.bin")), new byte[]{1,2,3});
            boolean refused = false;
            try { manager.finishRetirementAfterQuiescence(handle); }
            catch (IllegalStateException error) { refused = error.getMessage().equals("Retirement marker is not durably confirmed"); }
            assert refused;
        }
    }
    public static void main(String[] args) throws Exception {
        if (!BodyOriginRetirementProbe.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        start(Path.of(args[0]));
        LocalServices.addService(UserManagerInternal.class, new UserManagerInternal());
        for (NativeIdentityStore.Format format : List.of(V1, V2)) {
            for (String mode : List.of("missing", "present", "damaged", "live-missing", "counter-unknown")) one(format, mode);
        }
        System.out.println("B1 BODY-origin retirement baseline passed; no Android disposal or cancellation claim");
    }
}
