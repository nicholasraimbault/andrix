// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeBindingTestSupport.*;
import static com.android.server.pm.NativeHeaderTestSupport.*;
import static com.android.server.pm.NativeHistoryTestSupport.*;

import com.android.server.LocalServices;
import com.android.server.pm.NativeIdentityRecords.Header;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * Emits the version 2 layouts a restored reservation and its explicit rebind leave under the
 * host format's actual writer: the reservation itself, beside a body, beside an unselected
 * addition and as a protected target, the completed rebind, and each interrupted step of its
 * exact header confirmation, first body write, completion to LIVE and rebound retirement
 * publication and marker. Each records its known holds and whether a header copy or only the
 * staging seed is version 2. A separately compiled version 1 reader checks them with other
 * sources: every layout must stay read only with every hold, no counter and no history. The
 * harness inserts the existing fault seam into copies of the store and strict writer sources.
 * Host files only, not Android storage.
 */
public final class NativeCreationHistoryLayouts {
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

    private interface Interrupt { boolean run(NativePrincipalManager manager, NativePrincipalManager.Handle handle); }

    // A rebound reservation of R, one call interrupted at step for file, then emitted.
    private static void interrupted(String name, String step, String file, boolean commitFirst,
            boolean publishFirst, Interrupt call) throws Exception {
        Path root = reserved();
        PackageManagerService pm = boot(root, V2, Map.of(PKG_R, R));
        NativePrincipalManager manager = new NativePrincipalManager(pm);
        NativePrincipalManager.Handle handle = manager.prepare(manager.select(PKG_R, 0));
        if (commitFirst && !manager.commit(handle)) throw new AssertionError("rebind refused");
        if (publishFirst) {
            NativeIdentityStore store = storeOf(root, V2);
            if (!store.resumeCreatingDirectory(RESERVED_R, R) || !store.publishCreatingSlot(RESERVED_R, BODY_R)) {
                throw new AssertionError("fixture body refused");
            }
        }
        NativeHeaderWriteFaults.arm(step, file);
        try {
            if (call.run(manager, handle) || !NativeHeaderWriteFaults.reached()) {
                throw new AssertionError(name + " not interrupted at " + step);
            }
        } finally {
            NativeHeaderWriteFaults.disarm();
        }
        emit(name + "-" + step, root, Set.of(R));
    }

    public static void main(String[] args) throws Exception {
        out = Path.of(args[0]);
        if (Files.exists(out, LinkOption.NOFOLLOW_LINKS)) throw new AssertionError("fresh output required");
        Files.createDirectories(out);
        start(Path.of(args[1]).resolve("creation-history-layouts"));
        LocalServices.addService(UserManagerInternal.class, new UserManagerInternal());
        emit("history-reserved", reserved(), Set.of(R));
        Header besideA = v2(2, live(A), boundCreating(R, 2, PKG_R));
        Path beside = layout(null, bytes(besideA), bytes(besideA));
        slot(beside, A, BODY_A);
        emit("history-beside-body", beside, Set.of(A, R));
        Header addition = v2(2, boundCreating(R, 1, PKG_R), boundCreating(D, 2, PKG_D));
        emit("history-unknown-counter", layout(bytes(RESERVED_R), bytes(addition), bytes(addition)),
                Set.of(R, D));
        Header target = v2(3, creating(A, 1, PKG_A), creating(B, 2, PKG_B), boundCreating(C, 3, PKG_C));
        emit("history-protected-target", layout(bytes(target), bytes(header(1, creating(A, 1, PKG_A))),
                bytes(header(2, creating(A, 1, PKG_A), creating(B, 2, PKG_B)))), Set.of(A, B, C));
        Path rebound = reserved();
        PackageManagerService pm = boot(rebound, V2, Map.of(PKG_R, R));
        NativePrincipalManager manager = new NativePrincipalManager(pm);
        if (!manager.commit(manager.prepare(manager.select(PKG_R, 0)))) throw new AssertionError("rebind refused");
        emit("history-rebound", rebound, Set.of(R));
        for (String step : STEPS) {
            interrupted("history-exact-confirmation", step, "store.bin", false, false,
                    (owner, handle) -> owner.commit(handle));
            interrupted("history-first-body", step, "record.bin", false, false,
                    (owner, handle) -> owner.commit(handle));
            interrupted("history-live-completion", step, "store.bin", false, true,
                    (owner, handle) -> owner.commit(handle));
            interrupted("history-retirement-publication", step, "record.bin", false, false,
                    (owner, handle) -> owner.beginRetirement(handle));
            interrupted("history-retirement-marker", step, "record.bin", true, false,
                    (owner, handle) -> owner.beginRetirement(handle));
        }
        System.out.println(emitted + " version 2 history layouts emitted; Android storage unqualified");
    }
}
