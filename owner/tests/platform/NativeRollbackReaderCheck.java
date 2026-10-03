// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeHeaderTestSupport.*;

import android.system.Os;
import com.android.server.LocalServices;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.HeaderEntry;
import com.android.server.pm.NativeIdentityRecords.Slot;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * The rollback model in the host Settings facade: the version 1 reader of the pinned 78456b3
 * image, or of the current sources under Format.V1, over every emitted version 2 layout. Each
 * package the store names for a held app ID is mapped there, as its installed setting would be.
 * A version 2 header copy is an unsupported footprint: the header reads UNSUPPORTED, the counter
 * is withheld, creation is not ready and no body or reservation history exists. Every hold
 * remains without a pin. The identity predicate still names each mapped package, and the facade
 * refuses its scan, so it is not admitted. A layout with only a version 2 staging seed keeps its
 * holds and withholds the counter. The reopened registry changes no byte.
 *
 * The caller predicts how many layouts hold a version 2 header copy, so no layout leaves that
 * branch unnoticed. It also names control layouts, which are read again under the production
 * Format.V2: there the same bytes give the history, pins and admission that the version 1 reader
 * withholds, so those refusals are effects of the format and not of the fixture. The harness
 * selects the reader's sources and the Format.V1 adapter. Host files only, not Android boot.
 */
public final class NativeRollbackReaderCheck {
    /** The package each held app ID's decoded copies name, mapped once, in app ID order. */
    static Map<String, Integer> mapped(NativeIdentityStore.Loaded loaded, Set<Integer> holds) {
        Map<String, Integer> result = new TreeMap<>();
        for (int appId : new TreeSet<>(holds)) {
            Set<String> names = new TreeSet<>();
            for (Header header : loaded.header.decodedCopies) {
                for (HeaderEntry entry : header.entries) {
                    if (entry.appId == appId && !entry.creationPackage.isEmpty()) {
                        names.add(entry.creationPackage);
                    }
                }
            }
            NativeIdentityStore.ReadResult<Slot> read = loaded.slots.get(appId);
            if (read != null) {
                for (Slot copy : read.decodedCopies) names.add(copy.packageName);
            }
            for (String name : names) {
                if (!result.containsKey(name)) {
                    result.put(name, appId);
                    break;
                }
            }
        }
        return result;
    }

    static Set<Integer> holds(Path layout) throws Exception {
        Set<Integer> holds = new TreeSet<>();
        for (String line : Files.readAllLines(layout.resolve("holds"))) {
            if (!line.isEmpty()) holds.add(Integer.parseInt(line));
        }
        return holds;
    }

    /** Whether the layout holds a version 2 header copy, not only a version 2 staging seed. */
    static boolean versionTwoCopy(Path layout) throws Exception {
        return Files.readString(layout.resolve("kind")).equals("copy\n");
    }

    private static void inspect(Path layout) {
        run("rollback reader / " + layout.getFileName(), problems -> {
            Path root = layout.resolve("store");
            boolean copy = versionTwoCopy(layout);
            Set<Integer> holds = holds(layout);
            NativeIdentityStore.Loaded loaded = NativeHeaderApi.store(root).load();
            Map<String, Integer> packages = mapped(loaded, holds);
            age(root);
            Map<String, String> before = footprint(root);
            PackageManagerService pm = NativeHeaderApi.pm(root, false);
            for (Map.Entry<String, Integer> entry : packages.entrySet()) {
                pm.mSettings.add(entry.getKey(), entry.getValue());
            }
            pm.mSettings.restoreAfterPackageSettings();
            check(problems, loaded.unsupportedFootprint && !loaded.creationReady(),
                    "view " + loaded.header.status);
            check(problems, !pm.mSettings.pins.hasKnownCounter()
                    && !pm.mSettings.nativePrincipalCreationReadyLPr(), "counter restored");
            for (int appId : holds) {
                check(problems, pm.mSettings.isNativePrincipalAppIdLPr(appId), "hold " + appId + " lost");
            }
            // Setup checks, not rollback effects: the facade keeps every mapped setting and UID by
            // construction. They guard the fixture that the effects below are asserted over.
            for (Map.Entry<String, Integer> entry : packages.entrySet()) {
                PackageSetting setting = pm.mSettings.getPackageLPr(entry.getKey());
                check(problems, setting != null && setting.getAppId() == entry.getValue(),
                        "setup: " + entry.getKey() + " is not mapped at " + entry.getValue());
            }
            if (copy) {
                check(problems, loaded.header.status == NativeIdentityStore.Status.UNSUPPORTED,
                        "a version 2 copy read as " + loaded.header.status);
                check(problems, loaded.histories().isEmpty()
                        && pm.mSettings.mNativeIdentityLoaded.histories().isEmpty(),
                        "history " + loaded.histories().keySet());
                check(problems, pm.mSettings.pins.reservedAppIds().isEmpty(),
                        "pins " + pm.mSettings.pins.reservedAppIds());
                check(problems, holds.isEmpty() || !packages.isEmpty(), "no store named package to map");
                for (Map.Entry<String, Integer> entry : packages.entrySet()) {
                    PackageSetting setting = pm.mSettings.getPackageLPr(entry.getKey());
                    if (setting == null) continue;
                    check(problems, pm.mSettings.isNativePrincipalPackageLPr(entry.getKey()),
                            entry.getKey() + " no longer named native");
                    check(problems, !pm.mSettings.nativeScanSubjectAllowedLPr(setting)
                            && !pm.mSettings.nativeScanBindingAllowedLPr(setting, setting.getSigningDetails()),
                            entry.getKey() + " scan admitted");
                }
            }
            check(problems, footprint(root).equals(before), "layout changed");
        });
    }

    /**
     * The discrimination control: the same layout under the production Format.V2 gives each mapped
     * package its history, its pin and admission by the facade's scan, and changes no byte.
     */
    private static void control(Path layout) {
        run("rollback reader control / " + layout.getFileName(), problems -> {
            Path root = layout.resolve("store");
            check(problems, versionTwoCopy(layout), "a control must hold a version 2 header copy");
            Map<String, Integer> packages = mapped(NativeHeaderApi.store(root).load(), holds(layout));
            check(problems, !packages.isEmpty(), "no store named package to map");
            age(root);
            Map<String, String> before = footprint(root);
            NativeIdentityStore.Loaded loaded =
                    new NativeIdentityStore(root.toFile(), NativeIdentityStore.Format.V2).load();
            PackageManagerService pm = new PackageManagerService(root, false, NativeIdentityStore.Format.V2);
            for (Map.Entry<String, Integer> entry : packages.entrySet()) {
                pm.mSettings.add(entry.getKey(), entry.getValue());
            }
            pm.mSettings.restoreAfterPackageSettings();
            for (Map.Entry<String, Integer> entry : packages.entrySet()) {
                PackageSetting setting = pm.mSettings.getPackageLPr(entry.getKey());
                check(problems, loaded.history(entry.getValue()) != null,
                        entry.getKey() + " has no version 2 history");
                check(problems, pm.mSettings.pins.reservedAppIds().contains(entry.getValue()),
                        entry.getKey() + " has no version 2 pin");
                check(problems, setting != null && pm.mSettings.nativeScanSubjectAllowedLPr(setting)
                        && pm.mSettings.nativeScanBindingAllowedLPr(setting, setting.getSigningDetails()),
                        entry.getKey() + " is not admitted under version 2");
            }
            check(problems, footprint(root).equals(before), "layout changed");
        });
    }

    public static void main(String[] args) throws Exception {
        if (!NativeRollbackReaderCheck.class.desiredAssertionStatus()) {
            throw new AssertionError("run with java -ea");
        }
        if (args.length != 4) {
            throw new AssertionError("layouts, state, predicted version 2 copy layouts and controls required");
        }
        start(Path.of(args[1]).resolve("rollback-readers"));
        int predicted = Integer.parseInt(args[2]);
        LocalServices.addService(UserManagerInternal.class, new UserManagerInternal());
        List<Path> layouts = new ArrayList<>();
        try (var entries = Files.list(Path.of(args[0]))) {
            entries.sorted().forEach(layouts::add);
        }
        if (layouts.isEmpty()) throw new AssertionError("no layouts");
        int copies = 0;
        for (Path layout : layouts) {
            if (versionTwoCopy(layout)) ++copies;
            inspect(layout);
        }
        for (String control : args[3].split(",")) control(Path.of(args[0]).resolve(control));
        int counted = copies;
        run("rollback reader / version 2 copy layouts", problems -> check(problems, counted == predicted,
                counted + " layouts hold a version 2 header copy, not the predicted " + predicted));
        finish(Os.allClosed());
        System.out.println(layouts.size() + " version 2 layouts kept holds without pins, history or"
                + " admission under the version 1 rollback reader, and the version 2 controls gave"
                + " them; Android boot unqualified");
    }
}
