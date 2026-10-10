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
 * B1's own readers over every layout that the lifecycle writers leave, with the current sources and
 * the candidate's exact Settings texts. Each layout is booted through the facade with its store
 * named packages mapped at their held app IDs.
 *
 * <p>Under the production Format.V2 a version 2 slot is negative evidence only. Every hold stays,
 * the counter is withheld, and no version 2 slot gives a pin, a history or a VALID read. Every
 * package the store names is protected: the identity predicate names it, which is the first check of
 * a fresh app ID registration, so a package whose mapping is lost cannot register afresh. A mapped
 * package of a version 2 slot is deferred and refused by the scan. A valid sibling naming the same
 * package or principal as a version 2 slot reads as a CONFLICT. A bound reservation beside a version 2
 * slot is withdrawn: no pin, no history, its package deferred and refused. Layouts without a version 2
 * slot are read as the old images read them, under either format: the positive controls and the
 * conflict of two readable siblings.
 *
 * <p>Under Format.V3, the lifecycle format that B1 builds but does not ship, the same bytes are
 * positive state: no unsupported footprint, no version 2 slot read as UNSUPPORTED unless it holds a
 * user other than user 0, which this stage reads as UNSUPPORTED under every format, and a history for
 * each one user account read VALID. That is the discrimination control: the refusals above are effects of the
 * format, not of the fixture. The caller predicts how many layouts each class holds and how many
 * version 2 slots Format.V3 reads VALID. No byte changes. Host files only, not Android boot.
 */
public final class NativeLifecycleReaderCheck {
    private static NativeIdentityStore.Format format;
    // The format whose expectations are asserted: the read format, or the other one in a control.
    private static NativeIdentityStore.Format asserted;
    private static int validUnderV3;
    // Version 2 slots that hold a user other than user 0, which the store reads as UNSUPPORTED under
    // every format: this stage supports user 0 only.
    private static int outsideUserZero;

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
        for (Map.Entry<String, String> entry : layoutPackages(layout).entrySet()) {
            if (!entry.getValue().equals("lost")) mapped.put(entry.getKey(), Integer.parseInt(entry.getValue()));
        }
        return mapped;
    }

    static Map<String, String> layoutPackages(Path layout) throws Exception {
        Map<String, String> packages = new TreeMap<>();
        for (String line : Files.readAllLines(layout.resolve("packages"))) {
            String[] words = line.split(" ");
            packages.put(words[0], words[1]);
        }
        return packages;
    }

    private static final Set<String> VERSION_TWO = Set.of("footprint", "reservation", "sibling", "sibling-principal",
            "lost");

    private static boolean refused(PackageManagerService pm, PackageSetting setting) {
        return !pm.mSettings.nativeScanSubjectAllowedLPr(setting)
                && !pm.mSettings.nativeScanBindingAllowedLPr(setting, setting.getSigningDetails());
    }

    /**
     * The controls without a version 2 slot, which B1 must read as the old images do, under either
     * format: an eligible body or a bound reservation admitted with its pin, a legacy marker pinned and
     * refused by the scan, a tombstone without a ticket deferred, a layout naming nothing, and two readable
     * siblings naming one package or principal both refused.
     */
    private static void positive(List<String> problems, PackageManagerService pm, NativeIdentityStore.Loaded loaded,
            String expected, Map<String, Integer> mapped) {
        Set<Integer> pins = new TreeSet<>(pm.mSettings.pins.reservedAppIds());
        Set<Integer> histories = new TreeSet<>(loaded.histories().keySet());
        check(problems, !loaded.unsupportedFootprint, "an unsupported footprint");
        boolean pinned = expected.equals("admitted") || expected.equals("retiring");
        check(problems, !expected.equals("nothing") || mapped.isEmpty(), "a nothing layout maps " + mapped);
        if (!pinned) check(problems, pins.isEmpty() && histories.isEmpty(), "pins " + pins + " history " + histories);
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
            if (expected.equals("tombstone") || expected.equals("conflict")) {
                check(problems, pm.mSettings.mNativeRecoveryView.defersName(entry.getKey()),
                        entry.getKey() + " not deferred by the recovery seeding");
            }
        }
    }

    private static void inspect(Path layout, String expected, Set<Integer> versionTwo) {
        String prefix = asserted == NativeIdentityStore.Format.V2 ? "lifecycle reader / " : "lifecycle reader V3 / ";
        run(prefix + layout.getFileName(), problems -> {
            Path root = layout.resolve("store");
            Set<Integer> holds = layoutHolds(layout);
            Map<String, String> packages = layoutPackages(layout);
            Map<String, Integer> mapped = layoutMapped(layout);
            age(root);
            Map<String, String> before = footprint(root);
            NativeIdentityStore.Loaded loaded = new NativeIdentityStore(root.toFile(), format).load();
            PackageManagerService pm = boot(root, format, mapped);
            Set<Integer> pins = new TreeSet<>(pm.mSettings.pins.reservedAppIds());
            for (int hold : holds) {
                check(problems, pm.mSettings.isNativePrincipalAppIdLPr(hold), "hold " + hold + " lost");
            }
            check(problems, VERSION_TWO.contains(expected) != versionTwo.isEmpty(), "version 2 slots " + versionTwo);
            if (!VERSION_TWO.contains(expected)) positive(problems, pm, loaded, expected, mapped);
            if (asserted == NativeIdentityStore.Format.V2 && VERSION_TWO.contains(expected)) {
                check(problems, loaded.unsupportedFootprint && !pm.mSettings.pins.hasKnownCounter(),
                        "no unsupported footprint, or the counter restored");
                for (int appId : versionTwo) {
                    NativeIdentityStore.ReadResult<NativeIdentityRecords.Slot> read = loaded.slots.get(appId);
                    check(problems, read != null && read.status != NativeIdentityStore.Status.VALID
                            && !pins.contains(appId) && loaded.history(appId) == null,
                            "the version 2 slot at " + appId + " gave positive state");
                }
                // Names protected: the identity predicate is the first check of a fresh registration.
                for (String name : packages.keySet()) {
                    check(problems, pm.mSettings.isNativePrincipalPackageLPr(name), name + " is not protected");
                }
                for (Map.Entry<String, Integer> entry : mapped.entrySet()) {
                    if (!versionTwo.contains(entry.getValue())) continue;
                    PackageSetting setting = pm.mSettings.getPackageLPr(entry.getKey());
                    check(problems, pm.mSettings.mNativeRecoveryView.defersName(entry.getKey())
                            && setting != null && !pm.mSettings.nativeScanSubjectAllowedLPr(setting),
                            entry.getKey() + " is not deferred and refused");
                }
                if (expected.equals("lost")) {
                    check(problems, mapped.isEmpty() && packages.containsValue("lost"), "not a lost mapping");
                }
                if (expected.equals("reservation")) {
                    // The bound reservation elsewhere is withdrawn under B1's image too: no pin, no
                    // history, and its package deferred and refused like the version 2 slot's.
                    Set<Integer> histories = new TreeSet<>(loaded.histories().keySet());
                    check(problems, pins.isEmpty() && histories.isEmpty(),
                            "the reservation kept pins " + pins + " history " + histories);
                    for (Map.Entry<String, Integer> entry : mapped.entrySet()) {
                        PackageSetting setting = pm.mSettings.getPackageLPr(entry.getKey());
                        check(problems, pm.mSettings.mNativeRecoveryView.defersName(entry.getKey())
                                && setting != null && refused(pm, setting),
                                entry.getKey() + " is not withdrawn: deferred and refused");
                    }
                }
                if (expected.startsWith("sibling")) {
                    for (int appId : mapped.values()) {
                        if (versionTwo.contains(appId)) continue;
                        NativeIdentityStore.ReadResult<NativeIdentityRecords.Slot> read = loaded.slots.get(appId);
                        check(problems, read != null && read.status == NativeIdentityStore.Status.CONFLICT,
                                "the sibling at " + appId + " read " + (read == null ? null : read.status));
                    }
                }
            }
            if (asserted == NativeIdentityStore.Format.V3) {
                check(problems, !loaded.unsupportedFootprint, "an unsupported footprint under V3");
                for (int appId : versionTwo) {
                    NativeIdentityStore.ReadResult<NativeIdentityRecords.Slot> read = loaded.slots.get(appId);
                    check(problems, read != null, "no read of the version 2 slot at " + appId);
                    if (read == null) continue;
                    if (read.status == NativeIdentityStore.Status.UNSUPPORTED) {
                        boolean other = false;
                        for (NativeIdentityRecords.Slot copy : read.decodedCopies) {
                            for (NativeIdentityRecords.UserEntry user : copy.users) other |= user.userId != 0;
                        }
                        if (other) ++outsideUserZero;
                        check(problems, other, "the version 2 slot at " + appId + " is unsupported under V3");
                    }
                    if (read.status == NativeIdentityStore.Status.VALID) {
                        ++validUnderV3;
                        // A history belongs to an account of one user. A tombstone has none.
                        check(problems, read.value.users.size() != 1 || loaded.history(appId) != null,
                                "no history at " + appId + " under V3");
                    }
                }
            }
            check(problems, footprint(root).equals(before), "layout changed");
        });
    }

    /**
     * Arguments: the layouts, a state directory, the format (V2 or V3), the expectations file, one line
     * per layout naming its class and the comma separated app IDs of its version 2 slots or "-", and the
     * predicted counts as class=count pairs, with valid=count under V3. An optional sixth argument names
     * the other format, whose expectations a control asserts over this read: they must fail.
     */
    public static void main(String[] args) throws Exception {
        if (!NativeLifecycleReaderCheck.class.desiredAssertionStatus()) {
            throw new AssertionError("run with java -ea");
        }
        if (args.length != 5 && args.length != 6) {
            throw new AssertionError("layouts, state, format, expectations and predicted counts required");
        }
        format = NativeIdentityStore.Format.valueOf(args[2]);
        asserted = args.length == 6 ? NativeIdentityStore.Format.valueOf(args[5]) : format;
        if (format == NativeIdentityStore.Format.V1 || asserted == NativeIdentityStore.Format.V1) {
            throw new AssertionError("Format.V2 or V3 required");
        }
        start(Path.of(args[1]).resolve("lifecycle-reader"));
        LocalServices.addService(UserManagerInternal.class, new UserManagerInternal());
        Map<String, String> classes = new TreeMap<>();
        Map<String, Set<Integer>> versionTwo = new TreeMap<>();
        for (String line : Files.readAllLines(Path.of(args[3]))) {
            String[] words = line.split(" ");
            if (words.length != 4 || classes.put(words[0], words[1]) != null) {
                throw new AssertionError("expectation line " + line);
            }
            Set<Integer> ids = new TreeSet<>();
            if (!words[2].equals("-")) for (String id : words[2].split(",")) ids.add(Integer.parseInt(id));
            versionTwo.put(words[0], ids);
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
            inspect(layout, classes.get(name), versionTwo.get(name));
        }
        if (asserted == NativeIdentityStore.Format.V3) {
            counted.put("valid", validUnderV3);
            counted.put("outside-user-0", outsideUserZero);
        }
        Map<String, Integer> predicted = new TreeMap<>();
        for (String pair : args[4].split(",")) {
            String[] words = pair.split("=");
            predicted.put(words[0], Integer.parseInt(words[1]));
        }
        String prefix = asserted == NativeIdentityStore.Format.V2 ? "lifecycle reader / " : "lifecycle reader V3 / ";
        run(prefix + "layouts by class", problems -> check(problems, counted.equals(predicted),
                counted + " layouts by class, not the predicted " + predicted));
        finish(Os.allClosed());
        System.out.println(layouts.size() + " lifecycle layouts read by B1's reader under Format." + format
                + "; Android boot unqualified");
    }
}
