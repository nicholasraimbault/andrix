// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeBindingTestSupport.*;
import static com.android.server.pm.NativeHeaderTestSupport.*;
import static com.android.server.pm.NativeHistoryTestSupport.*;

import android.system.Os;
import com.android.server.LocalServices;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The rollback model's package deferral: the version 1 reader of the pinned 78456b3 image, or of
 * the current sources under Format.V1, boots the host facade over every emitted version 2 layout
 * with each store named package mapped at its held app ID, and takes its recovery view from the
 * exact recovery seeding text of the adapted Settings, run by NativeHistoryHarness. Under a
 * version 2 header copy no history exists, so the seeding defers every mapped package and the
 * facade refuses its scan, while every hold remains without a pin. The counter stays withheld,
 * and no byte changes.
 *
 * The caller predicts how many layouts hold a version 2 header copy, so no layout leaves that
 * branch unnoticed, and names control layouts. Booted again under the production Format.V2, a
 * control's mapped packages keep their pins, are not deferred and are admitted, so the version 1
 * deferral is an effect of the format and not of the fixture. Host files only, not Android boot.
 */
public final class NativeRollbackSeedingCheck {
    private static void inspect(Path layout) {
        run("rollback seeding / " + layout.getFileName(), problems -> {
            Path root = layout.resolve("store");
            boolean copy = NativeRollbackReaderCheck.versionTwoCopy(layout);
            Set<Integer> holds = NativeRollbackReaderCheck.holds(layout);
            Map<String, Integer> packages = NativeRollbackReaderCheck.mapped(loadedOf(root, V1), holds);
            age(root);
            Map<String, String> before = footprint(root);
            PackageManagerService pm = boot(root, V1, packages);
            check(problems, !pm.mSettings.pins.hasKnownCounter()
                    && !pm.mSettings.nativePrincipalCreationReadyLPr(), "counter restored");
            for (int appId : holds) {
                check(problems, pm.mSettings.isNativePrincipalAppIdLPr(appId), "hold " + appId + " lost");
            }
            if (copy) {
                check(problems, pm.mSettings.pins.reservedAppIds().isEmpty(),
                        "pins " + pm.mSettings.pins.reservedAppIds());
                check(problems, holds.isEmpty() || !packages.isEmpty(), "no store named package to map");
                for (Map.Entry<String, Integer> entry : packages.entrySet()) {
                    PackageSetting setting = pm.mSettings.getPackageLPr(entry.getKey());
                    // A setup check, not a rollback effect: the boot maps every package itself.
                    check(problems, setting != null && setting.getAppId() == entry.getValue(),
                            "setup: " + entry.getKey() + " is not mapped at " + entry.getValue());
                    check(problems, pm.mSettings.mNativeRecoveryView.defersName(entry.getKey()),
                            entry.getKey() + " not deferred by the recovery seeding");
                    if (setting != null) {
                        check(problems, !pm.mSettings.nativeScanSubjectAllowedLPr(setting),
                                entry.getKey() + " scan admitted");
                    }
                }
            }
            check(problems, footprint(root).equals(before), "layout changed");
        });
    }

    /**
     * The discrimination control: booted under the production Format.V2, the same layout restores
     * each mapped package's pin, the recovery seeding defers none of them and the facade admits
     * them, and no byte changes.
     */
    private static void control(Path layout) {
        run("rollback seeding control / " + layout.getFileName(), problems -> {
            Path root = layout.resolve("store");
            check(problems, NativeRollbackReaderCheck.versionTwoCopy(layout),
                    "a control must hold a version 2 header copy");
            Map<String, Integer> packages = NativeRollbackReaderCheck.mapped(loadedOf(root, V1),
                    NativeRollbackReaderCheck.holds(layout));
            check(problems, !packages.isEmpty(), "no store named package to map");
            age(root);
            Map<String, String> before = footprint(root);
            PackageManagerService pm = boot(root, V2, packages);
            for (Map.Entry<String, Integer> entry : packages.entrySet()) {
                PackageSetting setting = pm.mSettings.getPackageLPr(entry.getKey());
                check(problems, pm.mSettings.pins.reservedAppIds().contains(entry.getValue()),
                        entry.getKey() + " has no version 2 pin");
                check(problems, !pm.mSettings.mNativeRecoveryView.defersName(entry.getKey()),
                        entry.getKey() + " deferred under version 2");
                check(problems, setting != null && pm.mSettings.nativeScanSubjectAllowedLPr(setting),
                        entry.getKey() + " is not admitted under version 2");
            }
            check(problems, footprint(root).equals(before), "layout changed");
        });
    }

    public static void main(String[] args) throws Exception {
        if (!NativeRollbackSeedingCheck.class.desiredAssertionStatus()) {
            throw new AssertionError("run with java -ea");
        }
        if (args.length != 4) {
            throw new AssertionError("layouts, state, predicted version 2 copy layouts and controls required");
        }
        start(Path.of(args[1]).resolve("rollback-seeding"));
        int predicted = Integer.parseInt(args[2]);
        LocalServices.addService(UserManagerInternal.class, new UserManagerInternal());
        List<Path> layouts = new ArrayList<>();
        try (var entries = Files.list(Path.of(args[0]))) {
            entries.sorted().forEach(layouts::add);
        }
        if (layouts.isEmpty()) throw new AssertionError("no layouts");
        int copies = 0;
        for (Path layout : layouts) {
            if (NativeRollbackReaderCheck.versionTwoCopy(layout)) ++copies;
            inspect(layout);
        }
        for (String control : args[3].split(",")) control(Path.of(args[0]).resolve(control));
        int counted = copies;
        run("rollback seeding / version 2 copy layouts", problems -> check(problems, counted == predicted,
                counted + " layouts hold a version 2 header copy, not the predicted " + predicted));
        finish(Os.allClosed());
        System.out.println(layouts.size() + " version 2 layouts deferred every mapped package under the"
                + " version 1 rollback reader's recovery seeding, and the version 2 controls admitted"
                + " them; Android boot unqualified");
    }
}
