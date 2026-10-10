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
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * The rollback models of the lifecycle record: an older image reads every layout that the lifecycle
 * writers leave. Written against the API of 24bfb6a and 78456b3 only, and compiled with each one's
 * pinned product and its own harness texts: 24bfb6a under Format.V2 and 78456b3 under Format.V1.
 * Each layout is booted through the facade with its store named packages mapped at their held app
 * IDs, and with the recovery view from the exact recovery seeding text of that image's Settings.
 *
 * <p>The caller states each layout's expected class, from an independent reading of its bytes:
 * <ul>
 *   <li>footprint, reservation and lost: a version 2 slot is an unsupported footprint. Every hold
 *       stays without a pin or history, the counter is withheld, and every mapped package is named
 *       native, deferred by the seeding and refused by the scan. A bound reservation elsewhere is
 *       withdrawn the same way. A package whose mapping is lost is not known as native.</li>
 *   <li>sibling and sibling-principal: the version 2 slot's app ID stays held without a pin or
 *       history, while the valid sibling is restored under its own record and its package admitted at
 *       its own app ID. A sibling naming the version 2 account's principal therefore has that principal
 *       restored: a damage case below the rollback floor, since no writer issues a principal twice.</li>
 *   <li>conflict, the control: beside a readable version 1 account the same siblings are refused.</li>
 *   <li>withdrawn: 78456b3 under a version 2 header. The header is an unsupported footprint and
 *       every binding is withdrawn, with every hold kept.</li>
 *   <li>The positive controls, layouts with no version 2 slot frame: admitted, an eligible version
 *       1 body with its pin and admission; retiring, a version 1 legacy marker with its pin, refused
 *       by the scan; tombstone, a version 1 tombstone whose package is deferred; nothing, a layout
 *       that names no package.</li>
 * </ul>
 * The caller predicts how many layouts each class holds, so no layout leaves its branch unnoticed.
 * No byte changes. Host files only, not Android boot.
 */
public final class NativeLifecycleRollbackCheck {
    private static NativeIdentityStore.Format format;

    static Set<Integer> layoutHolds(Path layout) throws Exception {
        Set<Integer> holds = new TreeSet<>();
        for (String line : Files.readAllLines(layout.resolve("holds"))) {
            if (!line.isEmpty()) holds.add(Integer.parseInt(line));
        }
        return holds;
    }

    /** The packages Package Manager maps, by name, at their app IDs. Lost mappings are not here. */
    static Map<String, Integer> layoutMapped(Path layout) throws Exception {
        Map<String, Integer> mapped = new TreeMap<>();
        for (String line : Files.readAllLines(layout.resolve("packages"))) {
            String[] words = line.split(" ");
            if (!words[1].equals("lost")) mapped.put(words[0], Integer.parseInt(words[1]));
        }
        return mapped;
    }

    static List<String> layoutLost(Path layout) throws Exception {
        List<String> lost = new ArrayList<>();
        for (String line : Files.readAllLines(layout.resolve("packages"))) {
            String[] words = line.split(" ");
            if (words[1].equals("lost")) lost.add(words[0]);
        }
        return lost;
    }

    private static boolean refused(PackageManagerService pm, PackageSetting setting) {
        return !pm.mSettings.nativeScanSubjectAllowedLPr(setting)
                && !pm.mSettings.nativeScanBindingAllowedLPr(setting, setting.getSigningDetails());
    }

    private static void inspect(Path layout, String expected, Set<Integer> versionTwo, int siblingAppId,
            long siblingPrincipal) {
        run("lifecycle rollback / " + layout.getFileName(), problems -> {
            Path root = layout.resolve("store");
            Set<Integer> holds = layoutHolds(layout);
            Map<String, Integer> mapped = layoutMapped(layout);
            age(root);
            Map<String, String> before = footprint(root);
            NativeIdentityStore.Loaded loaded = new NativeIdentityStore(root.toFile(), format).load();
            PackageManagerService pm = boot(root, format, mapped);
            Set<Integer> pins = new TreeSet<>(pm.mSettings.pins.reservedAppIds());
            Set<Integer> histories = new TreeSet<>(loaded.histories().keySet());
            for (int hold : holds) {
                check(problems, pm.mSettings.isNativePrincipalAppIdLPr(hold), "hold " + hold + " lost");
            }
            for (String name : layoutLost(layout)) {
                check(problems, !pm.mSettings.isNativePrincipalPackageLPr(name), name + " known as native");
            }
            boolean withheld = !pm.mSettings.pins.hasKnownCounter() && !pm.mSettings.nativePrincipalCreationReadyLPr();
            switch (expected) {
                case "footprint", "reservation", "lost", "withdrawn" -> {
                    check(problems, loaded.unsupportedFootprint && !loaded.creationReady(), "no unsupported footprint");
                    check(problems, (loaded.header.status == NativeIdentityStore.Status.UNSUPPORTED)
                            == expected.equals("withdrawn"), "header " + loaded.header.status);
                    check(problems, withheld, "counter restored");
                    check(problems, pins.isEmpty(), "pins " + pins);
                    check(problems, histories.isEmpty(), "history " + histories);
                    check(problems, !expected.equals("lost") || mapped.isEmpty(), "a lost layout maps " + mapped);
                    for (Map.Entry<String, Integer> entry : mapped.entrySet()) {
                        PackageSetting setting = pm.mSettings.getPackageLPr(entry.getKey());
                        check(problems, setting != null && setting.getAppId() == entry.getValue(),
                                "setup: " + entry.getKey() + " is not mapped at " + entry.getValue());
                        check(problems, pm.mSettings.isNativePrincipalPackageLPr(entry.getKey()),
                                entry.getKey() + " not named native");
                        check(problems, pm.mSettings.mNativeRecoveryView.defersName(entry.getKey()),
                                entry.getKey() + " not deferred by the recovery seeding");
                        check(problems, setting != null && refused(pm, setting), entry.getKey() + " scan admitted");
                    }
                }
                case "sibling", "sibling-principal" -> {
                    // The old image cannot read the version 2 slot, so it reads the sibling as valid, as
                    // beside a damaged slot: admitted at its own app ID under its own record, which for a
                    // sibling naming the version 2 account's principal restores that principal.
                    check(problems, loaded.unsupportedFootprint && withheld, "no unsupported footprint");
                    for (int appId : versionTwo) {
                        check(problems, !pins.contains(appId) && !histories.contains(appId),
                                "the version 2 slot at " + appId + " has a pin or history");
                    }
                    NativeIdentityStore.History history = loaded.histories().get(siblingAppId);
                    check(problems, pins.contains(siblingAppId) && history != null && history.id == siblingPrincipal,
                            "the sibling at " + siblingAppId + " is not restored with principal " + siblingPrincipal);
                    for (Map.Entry<String, Integer> entry : mapped.entrySet()) {
                        PackageSetting setting = pm.mSettings.getPackageLPr(entry.getKey());
                        if (entry.getValue() == siblingAppId) {
                            check(problems, setting != null && !pm.mSettings.mNativeRecoveryView.defersName(entry.getKey())
                                    && pm.mSettings.nativeScanSubjectAllowedLPr(setting),
                                    entry.getKey() + " is not admitted at the sibling");
                        } else {
                            check(problems, versionTwo.contains(entry.getValue())
                                    && pm.mSettings.mNativeRecoveryView.defersName(entry.getKey())
                                    && setting != null && refused(pm, setting),
                                    entry.getKey() + " of the version 2 slot is not deferred and refused");
                        }
                    }
                }
                case "conflict" -> {
                    // The control: beside a readable version 1 account the same sibling is refused.
                    check(problems, !loaded.unsupportedFootprint, "an unsupported footprint");
                    check(problems, pins.isEmpty() && histories.isEmpty(), "pins " + pins + " history " + histories);
                    for (Map.Entry<String, Integer> entry : mapped.entrySet()) {
                        PackageSetting setting = pm.mSettings.getPackageLPr(entry.getKey());
                        check(problems, pm.mSettings.mNativeRecoveryView.defersName(entry.getKey())
                                && setting != null && refused(pm, setting), entry.getKey() + " is not deferred and refused");
                    }
                }
                case "admitted", "retiring", "tombstone", "nothing" -> {
                    check(problems, !loaded.unsupportedFootprint && !withheld, "a footprint or withheld counter");
                    boolean pinned = expected.equals("admitted") || expected.equals("retiring");
                    check(problems, !expected.equals("nothing") || mapped.isEmpty(), "a nothing layout maps " + mapped);
                    if (!pinned) {
                        check(problems, pins.isEmpty() && histories.isEmpty(), "pins " + pins + " history " + histories);
                    }
                    for (Map.Entry<String, Integer> entry : mapped.entrySet()) {
                        PackageSetting setting = pm.mSettings.getPackageLPr(entry.getKey());
                        check(problems, setting != null, "setup: " + entry.getKey() + " is not mapped");
                        if (setting == null) continue;
                        if (pinned) {
                            check(problems, pins.contains(entry.getValue()) && histories.contains(entry.getValue()),
                                    entry.getKey() + " has no pin or history");
                        }
                        if (expected.equals("admitted")) {
                            check(problems, !pm.mSettings.mNativeRecoveryView.defersName(entry.getKey())
                                    && pm.mSettings.nativeScanSubjectAllowedLPr(setting), entry.getKey() + " not admitted");
                        } else {
                            check(problems, refused(pm, setting), entry.getKey() + " scan admitted");
                        }
                        if (expected.equals("tombstone")) {
                            check(problems, pm.mSettings.mNativeRecoveryView.defersName(entry.getKey()),
                                    entry.getKey() + " not deferred by the recovery seeding");
                        }
                    }
                }
                default -> problems.add("unknown expected class " + expected);
            }
            check(problems, footprint(root).equals(before), "layout changed");
        });
    }

    /**
     * Arguments: the layouts, a state directory, the format of the boot read (V1 or V2), the
     * expectations file, one line per layout naming its class, the comma separated app IDs of its
     * version 2 slots or "-", and a sibling's app ID and principal as appId:principal or "-", and the
     * predicted count of each class as class=count pairs.
     */
    public static void main(String[] args) throws Exception {
        if (!NativeLifecycleRollbackCheck.class.desiredAssertionStatus()) {
            throw new AssertionError("run with java -ea");
        }
        if (args.length != 5) {
            throw new AssertionError("layouts, state, format, expectations and predicted counts required");
        }
        format = NativeIdentityStore.Format.valueOf(args[2]);
        start(Path.of(args[1]).resolve("lifecycle-rollback"));
        LocalServices.addService(UserManagerInternal.class, new UserManagerInternal());
        Map<String, String> classes = new TreeMap<>();
        Map<String, Set<Integer>> versionTwo = new TreeMap<>();
        Map<String, long[]> siblings = new TreeMap<>();
        for (String line : Files.readAllLines(Path.of(args[3]))) {
            String[] words = line.split(" ");
            if (words.length != 4 || classes.put(words[0], words[1]) != null) {
                throw new AssertionError("expectation line " + line);
            }
            Set<Integer> ids = new TreeSet<>();
            if (!words[2].equals("-")) for (String id : words[2].split(",")) ids.add(Integer.parseInt(id));
            versionTwo.put(words[0], ids);
            siblings.put(words[0], words[3].equals("-") ? new long[] {-1, -1}
                    : new long[] {Long.parseLong(words[3].split(":")[0]), Long.parseLong(words[3].split(":")[1])});
        }
        List<Path> layouts = new ArrayList<>();
        try (var entries = Files.list(Path.of(args[0]))) {
            entries.sorted().forEach(layouts::add);
        }
        Set<String> names = new TreeSet<>();
        for (Path layout : layouts) names.add(layout.getFileName().toString());
        if (layouts.isEmpty() || !names.equals(classes.keySet())) {
            throw new AssertionError("the expectations do not name exactly the layouts");
        }
        Map<String, Integer> counted = new TreeMap<>();
        for (Path layout : layouts) {
            String name = layout.getFileName().toString();
            counted.merge(classes.get(name), 1, Integer::sum);
            inspect(layout, classes.get(name), versionTwo.get(name), (int) siblings.get(name)[0], siblings.get(name)[1]);
        }
        Map<String, Integer> predicted = new TreeMap<>();
        for (String pair : args[4].split(",")) {
            String[] words = pair.split("=");
            predicted.put(words[0], Integer.parseInt(words[1]));
        }
        run("lifecycle rollback / layouts by class", problems -> check(problems, counted.equals(predicted),
                counted + " layouts by class, not the predicted " + predicted));
        finish(Os.allClosed());
        System.out.println(layouts.size() + " lifecycle layouts read by the rollback model under Format." + format
                + "; Android boot unqualified");
    }
}
