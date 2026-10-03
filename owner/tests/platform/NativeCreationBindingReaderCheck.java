// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeHeaderTestSupport.*;

import android.system.Os;
import com.android.server.LocalServices;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.Slot;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Reads the emitted version 2 layouts with a version 1 reader: the rollback reader model, the
 * creation plan sources under Format.V1 or the pinned 78456b3 image, or the archived c9264e4
 * sources. Only store, facade and codec surface common to all of them is used, through the host
 * NativeHeaderApi adapter the harness selects. Every layout must stay read only with every known
 * hold, also across the reopened registry. A version 2 header copy also withholds the counter
 * and every binding; a version 2 staging seed alone withholds the counter and creation. A
 * constructed layout may also list the status each reader must give its slots. The bound
 * collision layouts require the CONFLICT outcome of the reviewed c9264e4 reader for both.
 * The layouts are fresh copies, never the emitted originals. Host files only, not Android boot.
 */
public final class NativeCreationBindingReaderCheck {
    private static void inspect(Path layout) {
        run("version 1 reader / " + layout.getFileName(), problems -> {
            Path root = layout.resolve("store");
            boolean copy = Files.readString(layout.resolve("kind")).equals("copy\n");
            Set<Integer> holds = new TreeSet<>();
            for (String line : Files.readAllLines(layout.resolve("holds"))) {
                if (!line.isEmpty()) holds.add(Integer.parseInt(line));
            }
            NativeIdentityStore store = store(root);
            NativeIdentityStore.Loaded loaded = store.load();
            Path statuses = layout.resolve("statuses");
            if (Files.isRegularFile(statuses)) {
                for (String line : Files.readAllLines(statuses)) {
                    if (line.isEmpty()) continue;
                    String[] expected = line.split(" ");
                    NativeIdentityStore.ReadResult<Slot> read =
                            loaded.slots.get(Integer.parseInt(expected[0]));
                    check(problems, read != null && read.status.name().equals(expected[1]),
                            "slot " + expected[0] + " read as " + (read == null ? null : read.status));
                }
            }
            check(problems, loaded.unsupportedFootprint && !loaded.creationReady()
                    && loaded.occupiedAppIds.containsAll(holds), "view " + loaded.header.status + " "
                    + loaded.occupiedAppIds);
            if (copy) {
                check(problems, loaded.header.status == NativeIdentityStore.Status.UNSUPPORTED,
                        "a version 2 copy read as " + loaded.header.status);
                for (int appId : loaded.occupiedAppIds) {
                    check(problems, !loaded.bindingUsable(appId), "binding of " + appId);
                }
            }
            age(root);
            Map<String, String> before = footprint(root);
            for (Header header : loaded.header.decodedCopies) {
                check(problems, !store.writeHeader(header, header), "header write accepted");
            }
            check(problems, !store.initializeNew(LINEAGE), "initialization accepted");
            for (NativeIdentityStore.ReadResult<Slot> read : loaded.slots.values()) {
                for (Slot slot : read.decodedCopies) {
                    check(problems, !store.confirmExistingSlot(slot), "slot confirmation accepted");
                }
            }
            check(problems, footprint(root).equals(before), "layout changed");
            PackageManagerService pm = reopen(root, Map.of());
            check(problems, !pm.mSettings.pins.hasKnownCounter()
                    && !pm.mSettings.nativePrincipalCreationReadyLPr(), "counter restored");
            if (copy) {
                check(problems, pm.mSettings.pins.reservedAppIds().isEmpty(), "binding restored");
            }
            for (int appId : holds) {
                check(problems, pm.mSettings.isNativePrincipalAppIdLPr(appId), "hold " + appId + " lost");
            }
            check(problems, footprint(root).equals(before), "layout changed by the reopened registry");
        });
    }

    public static void main(String[] args) throws Exception {
        if (!NativeCreationBindingReaderCheck.class.desiredAssertionStatus()) {
            throw new AssertionError("run with java -ea");
        }
        start(Path.of(args[1]).resolve("creation-binding-readers"));
        LocalServices.addService(UserManagerInternal.class, new UserManagerInternal());
        List<Path> layouts = new ArrayList<>();
        try (var entries = Files.list(Path.of(args[0]))) {
            entries.sorted().forEach(layouts::add);
        }
        if (layouts.isEmpty()) throw new AssertionError("no layouts");
        for (Path layout : layouts) inspect(layout);
        finish(Os.allClosed());
        System.out.println(layouts.size() + " version 2 layouts read only with every hold by a"
                + " version 1 reader; Android boot unqualified");
    }
}
