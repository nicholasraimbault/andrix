// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import java.io.File;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Actual immutable negative view; not PMS admission, filesystem or device qualification. */
public final class NativePrincipalRecoveryTest {
    private static void invalid(Runnable action) {
        try { action.run(); } catch (IllegalArgumentException expected) { return; }
        throw new AssertionError("Invalid recovery view accepted");
    }
    public static void main(String[] args) {
        if (!NativePrincipalRecoveryTest.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        NativePrincipalRecovery empty = NativePrincipalRecovery.empty();
        assert !empty.hasHolds() && !empty.protectsName(null) && !empty.defersName(null);
        Set<Integer> mutable = new HashSet<>(Set.of(10123));
        NativePrincipalRecovery held = empty.withHolds(mutable);
        mutable.clear();
        assert held.holdsAppId(10123) && !empty.holdsAppId(10123);
        assert held.protectsObservedUid(10123) && held.protectsObservedUid(1010123);
        assert !held.protectsObservedUid(-1) && !held.protectsObservedUid(10124);
        assert held.protectsKeystore(10123) && !held.protectsKeystore(1000);

        Set<String> names = new HashSet<>(Set.of("dev.andrix.account"));
        NativePrincipalRecovery named = held.protectNames(names);
        names.clear();
        assert named.protectsName("dev.andrix.account") && !held.protectsName("dev.andrix.account");
        assert !named.defersName("dev.andrix.account"); // Preservation is not an admission verdict.
        NativePrincipalRecovery deferred = named.defer("dev.andrix.account",
                new File("/data/app/opaque/account/base.apk"));
        assert deferred.defersName("dev.andrix.account") && !named.defersName("dev.andrix.account");
        assert deferred.keepsCodePath(new File("/data/app/opaque"));
        assert deferred.keepsCodePath(new File("/data/app/opaque/account"));
        assert deferred.keepsCodePath(new File("/data/app/opaque/account/base.apk"));
        assert !deferred.keepsCodePath(new File("/data/app/opaque/account2"));
        assert !deferred.keepsCodePath(new File("/data/app/opaque2"));
        assert !deferred.keepsCodePath(new File("/data/app/other"));
        NativePrincipalRecovery directory = deferred.retainCode(new File("/data/app/other"));
        assert directory.keepsCodePath(new File("/data/app/other/lib/x.so"));
        assert !deferred.keepsCodePath(new File("/data/app/other/lib/x.so"));

        NativePrincipalRecovery unknown = deferred.withUnidentifiedCode();
        File root = new File("/data/app");
        assert unknown.preservesUnidentifiedCode(new File("/data/app/unparsed"), root);
        assert !unknown.preservesUnidentifiedCode(root, root);
        assert !unknown.preservesUnidentifiedCode(new File("/data/app-staging/session"), root);
        assert !unknown.preservesUnidentifiedCode(new File("/data/app/../other/file"), root);
        assert !deferred.preservesUnidentifiedCode(new File("/data/app/unparsed"), root);
        // Removing the actual hold is a caller-owned confirmed operation. It
        // does not silently clear deferred names or the retained code inventory.
        NativePrincipalRecovery released = unknown.withHolds(Set.of());
        assert !released.protectsKeystore(10123) && !released.hasUnidentifiedCode();
        assert released.defersName("dev.andrix.account");
        assert released.keepsCodePath(new File("/data/app/opaque"));
        assert unknown.holdsAppId(10123);

        for (int id : new int[]{-1, 0, 9999, 20000, Integer.MAX_VALUE}) {
            invalid(() -> held.withHolds(Set.of(id)));
        }
        invalid(() -> held.protectNames(List.of("")));
        invalid(() -> held.defer("", new File("/data/app/item")));
        invalid(() -> held.retainCode(new File("relative")));
        invalid(() -> held.keepsCodePath(new File("relative")));
        assert held.holdsAppId(10123);
        System.out.println("Native recovery negative view checks passed; Android/PMS unqualified");
    }
}
