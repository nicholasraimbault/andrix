// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeBindingTestSupport.*;
import static com.android.server.pm.NativeHeaderTestSupport.*;

import com.android.server.LocalServices;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.UserEntry;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * Emits every version 2 layout the host format's actual writer leaves: each interrupted step
 * of a fresh upgrade, of legacy B beside bound C, of pending and RETIRING pins reserved
 * together, of a restatement followed by an upgrade and of a version 2 publication, plus the
 * final reserved, published, legacy and released states. Each layout records its known holds
 * and whether a header copy or only the unpublished staging seed is version 2. Three more are
 * constructed, not written: R's version 2 binding fails its body while N collides with it by
 * package, principal or both. They also record the CONFLICT status every version 1 reader, like
 * the reviewed c9264e4 one, must give both slots. A separately compiled reader checks them with
 * other sources. The harness inserts the existing fault seam
 * into copies of the store and strict writer sources. Host files only, not Android storage.
 */
public final class NativeCreationBindingLayouts {
    private static final List<String> STEPS = List.of("seed-synced", "backup-renamed",
            "backup-published", "write-started", "main-synced", "reserve-synced", "backup-unlink",
            "backup-unlinked");
    private static Path out;
    private static int emitted;

    private static boolean version2(Path path) throws Exception {
        return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                && NativeIdentityRecords.intactHeaderVersion(Files.readAllBytes(path)) == 2;
    }

    // Copies the store tree and records what every reader must keep.
    private static void emit(String name, Path root, Set<Integer> holds) throws Exception {
        boolean copy = false;
        for (String file : List.of("store.bin", "store.bin.reservecopy", "store.bin-backup")) {
            copy |= version2(root.resolve(file));
        }
        boolean seed = version2(root.resolve("store.bin-seed"));
        if (!copy && !seed) throw new AssertionError(name + " is not a version 2 layout");
        Path target = Files.createDirectories(out.resolve(name));
        List<Path> paths;
        try (var walk = Files.walk(root)) {
            paths = walk.toList();
        }
        for (Path path : paths) {
            Path destination = target.resolve("store").resolve(root.relativize(path).toString());
            if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                Files.createDirectories(destination);
            } else {
                Files.copy(path, destination);
            }
        }
        Files.writeString(target.resolve("kind"), copy ? "copy\n" : "seed\n");
        Files.writeString(target.resolve("holds"), new TreeSet<>(holds).stream()
                .map(String::valueOf).collect(Collectors.joining("\n", "", "\n")));
        ++emitted;
    }

    private static boolean interrupted(NativePrincipalManager manager,
            NativePrincipalManager.Handle handle, String step) {
        NativeHeaderWriteFaults.arm(step, "store.bin");
        try {
            return !manager.commit(handle) && NativeHeaderWriteFaults.reached();
        } finally {
            NativeHeaderWriteFaults.disarm();
        }
    }

    public static void main(String[] args) throws Exception {
        out = Path.of(args[0]);
        if (Files.exists(out, LinkOption.NOFOLLOW_LINKS)) throw new AssertionError("fresh output required");
        Files.createDirectories(out);
        start(Path.of(args[1]).resolve("creation-binding-layouts"));
        LocalServices.addService(UserManagerInternal.class, new UserManagerInternal());
        for (String step : STEPS) {
            boolean target = STEPS.indexOf(step) > 0;
            PackageManagerService fresh = livePmOf(V2);
            NativePrincipalManager first = new NativePrincipalManager(fresh);
            if (!interrupted(first, first.prepare(first.select(PKG_B, 0)), step)) {
                throw new AssertionError("fresh upgrade not interrupted at " + step);
            }
            emit("fresh-upgrade-" + step, fresh.mSettings.root, target ? Set.of(B) : Set.of());

            PackageManagerService legacy = livePmOf(V2);
            NativePrincipalManager second = new NativePrincipalManager(legacy);
            second.prepare(second.select(PKG_B, 0));
            legacyReservation(legacy, OLD, PENDING_B);
            if (!interrupted(second, second.prepare(second.select(PKG_C, 0)), step)) {
                throw new AssertionError("legacy upgrade not interrupted at " + step);
            }
            emit("legacy-b-bound-c-" + step, legacy.mSettings.root, target ? Set.of(B, C) : Set.of(B));

            PackageManagerService several = livePmOf(V2);
            NativePrincipalManager third = new NativePrincipalManager(several);
            NativePrincipalManager.Handle a = third.prepare(third.select(PKG_A, 0));
            third.prepare(third.select(PKG_B, 0));
            third.prepare(third.select(PKG_C, 0));
            several.mSettings.pins.beginRetire(several.mSettings.pins.find(PKG_C, 0));
            if (!interrupted(third, a, step)) throw new AssertionError("reservation not interrupted at " + step);
            emit("pending-retiring-" + step, several.mSettings.root, target ? Set.of(A, B, C) : Set.of());

            PackageManagerService restated = livePmOf(V2);
            NativePrincipalManager fourth = new NativePrincipalManager(restated);
            NativePrincipalManager.Handle b = fourth.prepare(fourth.select(PKG_B, 0));
            legacyReservation(restated, OLD, PENDING_B);
            if (!fourth.commit(b)) throw new AssertionError("restatement refused");
            if (!interrupted(fourth, fourth.prepare(fourth.select(PKG_C, 0)), step)) {
                throw new AssertionError("upgrade after restatement not interrupted at " + step);
            }
            emit("restated-then-upgraded-" + step, restated.mSettings.root,
                    target ? Set.of(B, C) : Set.of(B));

            Header creatingA = v2(1, boundCreating(A, 1, PKG_A));
            Path published = layout(null, bytes(creatingA), bytes(creatingA));
            slot(published, A, bound(A, PKG_A, 1, false, 1));
            NativeHeaderWriteFaults.arm(step, "store.bin");
            try {
                if (storeOf(published, V2).writeHeader(creatingA, v2(1, live(A)))
                        || !NativeHeaderWriteFaults.reached()) {
                    throw new AssertionError("publication not interrupted at " + step);
                }
            } finally {
                NativeHeaderWriteFaults.disarm();
            }
            emit("v2-publication-" + step, published, Set.of(A));
        }
        Path reserved = layout(null, bytes(OLD), bytes(OLD));
        if (!storeOf(reserved, V2).writeHeader(OLD, v2(1, boundCreating(B, 1, PKG_B)))) {
            throw new AssertionError("bound reservation refused");
        }
        emit("final-reserved", reserved, Set.of(B));
        PackageManagerService live = livePmOf(V2);
        NativePrincipalManager fifth = new NativePrincipalManager(live);
        NativePrincipalManager.Handle held = fifth.prepare(fifth.select(PKG_B, 0));
        if (!fifth.commit(held)) throw new AssertionError("publication refused");
        emit("final-published", live.mSettings.root, Set.of(B));
        PackageManagerService legacy = livePmOf(V2);
        NativePrincipalManager sixth = new NativePrincipalManager(legacy);
        sixth.prepare(sixth.select(PKG_B, 0));
        legacyReservation(legacy, OLD, PENDING_B);
        if (!sixth.commit(sixth.prepare(sixth.select(PKG_C, 0)))) throw new AssertionError("upgrade refused");
        emit("final-legacy-null", legacy.mSettings.root, Set.of(B, C));
        if (!fifth.beginRetirement(held) || !fifth.finishRetirementAfterQuiescence(held)) {
            throw new AssertionError("retirement refused");
        }
        emit("final-released", live.mSettings.root, Set.of());
        Set<String> other = Set.of("a0".repeat(32)), signers = Set.of("b1".repeat(32));
        Header bound = v2(2, boundCreating(B, 1, PKG_R, other), live(C));
        Map<String, Slot> siblings = new TreeMap<>();
        siblings.put("package", new Slot(LINEAGE, C, PKG_R, 1, signers,
                List.of(new UserEntry(2, 0, SERIAL, false))));
        siblings.put("principal", new Slot(LINEAGE, C, "dev.andrix.n", 1, signers,
                List.of(new UserEntry(1, 0, SERIAL, false))));
        siblings.put("both", new Slot(LINEAGE, C, PKG_R, 1, signers,
                List.of(new UserEntry(1, 0, SERIAL, false))));
        for (Map.Entry<String, Slot> sibling : siblings.entrySet()) {
            Path collision = layout(null, bytes(bound), bytes(bound));
            slot(collision, B, new Slot(LINEAGE, B, PKG_R, 1, signers,
                    List.of(new UserEntry(1, 0, SERIAL, false))));
            slot(collision, C, sibling.getValue());
            String name = "bound-collision-" + sibling.getKey();
            emit(name, collision, Set.of(B, C));
            Files.writeString(out.resolve(name).resolve("statuses"),
                    B + " CONFLICT\n" + C + " CONFLICT\n");
        }
        System.out.println(emitted + " version 2 layouts emitted; Android storage unqualified");
    }
}
