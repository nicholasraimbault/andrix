// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import java.util.HashSet;
import java.util.Set;

/** Compiles the exact adapted AppIdSettingMap with host collection facades. */
public final class NativePrincipalAllocatorTest {
    private static PackageSetting pkg(String name) { return new PackageSetting(name); }
    private static void refuse(Runnable call) {
        try { call.run(); } catch (IllegalStateException expected) { return; }
        throw new AssertionError("unexpected reserved mapping replacement");
    }
    public static void main(String[] args) {
        if (!NativePrincipalAllocatorTest.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        AppIdSettingMap ordinary = new AppIdSettingMap();
        assert ordinary.acquireAndRegisterNewAppId(pkg("first")) == 10000;
        assert ordinary.acquireAndRegisterNewAppId(pkg("second")) == 10001;
        ordinary.removeSetting(10000);
        assert ordinary.acquireAndRegisterNewAppId(pkg("third")) == 10002; // Existing high watermark.

        AppIdSettingMap restored = new AppIdSettingMap();
        Set<Integer> source = new HashSet<>(Set.of(10000, 10001, 10003));
        restored.setNativePrincipalAppIds(source);
        source.clear(); // Setter must take an immutable copy.
        assert restored.acquireAndRegisterNewAppId(pkg("new")) == 10002;
        assert restored.acquireAndRegisterNewAppId(pkg("next")) == 10004;
        for (int id : new int[]{10000, 10001, 10003}) {
            assert restored.getSetting(id) == null; // Reserved is not installed.
            assert !restored.registerExistingAppId(id, pkg("foreign"), "foreign");
            refuse(() -> restored.replaceSetting(id, pkg("foreign")));
        }
        restored.setNativePrincipalAppIds(Set.of());
        assert restored.acquireAndRegisterNewAppId(pkg("released")) == 10000;

        AppIdSettingMap held = new AppIdSettingMap();
        PackageSetting original = pkg("same");
        assert held.registerExistingAppId(10123, original, "same");
        held.setNativePrincipalAppIds(Set.of(10123));
        PackageSetting update = pkg("same");
        held.replaceSetting(10123, update);
        assert held.getSetting(10123) == update;
        refuse(() -> held.replaceSetting(10123, pkg("other")));
        refuse(() -> held.replaceSetting(10123, new SettingBase()));
        held.removeSetting(10123);
        assert held.getSetting(10123) == null;
        assert !held.registerExistingAppId(10123, pkg("different"), "different");
        refuse(() -> held.replaceSetting(10123, pkg("same")));

        Set<Integer> every = new HashSet<>();
        for (int id = 10000; id <= 19999; id++) every.add(id);
        AppIdSettingMap exhausted = new AppIdSettingMap();
        exhausted.setNativePrincipalAppIds(every);
        assert exhausted.acquireAndRegisterNewAppId(pkg("none")) == -1;
        assert exhausted.getSetting(19999) == null;
        every.remove(19999);
        exhausted.setNativePrincipalAppIds(every);
        assert exhausted.acquireAndRegisterNewAppId(pkg("last")) == 19999;
        assert exhausted.acquireAndRegisterNewAppId(pkg("full")) == -1;
        System.out.println("Adapted PMS allocator reservations passed; host facades, Android unqualified");
    }
}
