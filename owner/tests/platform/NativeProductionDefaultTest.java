// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeBindingTestSupport.*;
import static com.android.server.pm.NativeHeaderTestSupport.*;

import android.system.Os;
import com.android.server.LocalServices;
import com.android.server.pm.NativeIdentityRecords.ActorClass;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.Lifecycle;
import com.android.server.pm.NativeIdentityRecords.LifecycleState;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.Suspension;
import com.android.server.pm.NativeIdentityRecords.SuspensionReason;
import com.android.server.pm.NativeIdentityRecords.UserEntry;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * The host facade's default format against Format.V3, the production format that the normal
 * image's boot read constructs. Every substantive host suite passes its format explicitly, so only
 * this check notices when the default stops being the production format. Each representative
 * store, missing, initialized, supported, damaged, of a later version or holding a reservation, is
 * copied once per reader. A facade boots over each copy, through the default constructors and
 * through explicit Format.V3, Format.V2 and Format.V1, and the check compares what each one reads,
 * restores, holds, defers and scans, the store's bytes and the diagnostic dump, and that no boot
 * wrote. The default must equal Format.V3 everywhere. The controls show that the cases tell the
 * formats apart: Format.V2 reads otherwise exactly where version 2 slots are supported state, and
 * Format.V1 also where version 2 headers are; both dump another schema everywhere. Host facades
 * only: not Android boot, crash, storage or activation qualification.
 */
public final class NativeProductionDefaultTest {
    // The production format, which the normal image's boot read constructs.
    private static final NativeIdentityStore.Format V3 = NativeIdentityStore.Format.V3;
    // The facade's default: no format argument, in place of a format.
    private static final NativeIdentityStore.Format DEFAULT = null;
    private static final long TIME = 1_700_000_000_000L;

    private interface Build { void write(Path root) throws Exception; }

    // One representative store: how to build it and the packages a boot maps.
    private static final class Case {
        final Build build;
        final Map<String, Integer> packages;

        Case(Map<String, Integer> packages, Build build) {
            this.build = build;
            this.packages = new TreeMap<>(packages);
        }
    }

    // What one facade reads of a case: its facts and its diagnostic dump.
    private static final class Read {
        final String facts, dump;

        Read(String facts, String dump) {
            this.facts = facts;
            this.dump = dump;
        }
    }

    // The cases where an earlier format's facts must differ from Format.V3's. Its dump differs in
    // every case, since the slot ceiling selects the dump's schema.
    private static final Set<String> V2_DIFFERS = Set.of("a suspended version 2 slot",
            "a retiring version 2 slot", "a version 2 slot beside a bound reservation");
    private static final Set<String> V1_DIFFERS = Set.of("a suspended version 2 slot",
            "a retiring version 2 slot", "a version 2 slot beside a bound reservation", "a bound reservation",
            "a reservation and publication through the manager");

    private static Slot lifecycleBody(int appId, String name, long id, Lifecycle lifecycle) {
        return new Slot(LINEAGE, appId, name, 2, SIGNERS, List.of(new UserEntry(id, 0, SERIAL, lifecycle)));
    }

    // A version 2 slot whose one account its own user suspended.
    private static Slot suspended(int appId, String name, long id) {
        Suspension paused = new Suspension(ActorClass.ACCOUNT_USER, 0, 0, SERIAL, NativeIdentityRecords.NO_REFERENCE,
                SuspensionReason.USER_PAUSED.code, TIME, null);
        return lifecycleBody(appId, name, id, new Lifecycle(LifecycleState.ELIGIBLE, List.of(paused), null));
    }

    private static void pair(Path root, Header header) throws Exception {
        copies(root, null, bytes(header), bytes(header));
    }

    // The representative stores, in print order. A null build leaves the store missing.
    private static Map<String, Case> cases() {
        Map<String, Case> all = new LinkedHashMap<>();
        all.put("a missing store", new Case(Map.of(PKG_A, A), null));
        all.put("a store the facade initializes", new Case(Map.of(PKG_A, A), null));
        all.put("an eligible version 1 body", new Case(Map.of(PKG_A, A), root -> {
            pair(root, header(1, live(A)));
            slot(root, A, bound(A, PKG_A, 1, false, 1));
        }));
        all.put("a suspended version 2 slot", new Case(Map.of(PKG_A, A), root -> {
            pair(root, header(1, live(A)));
            slot(root, A, suspended(A, PKG_A, 1));
        }));
        all.put("a retiring version 2 slot", new Case(Map.of(PKG_A, A), root -> {
            pair(root, header(1, live(A)));
            slot(root, A, lifecycleBody(A, PKG_A, 1, new Lifecycle(LifecycleState.RETIRING, List.of(),
                    retirementBlock())));
        }));
        all.put("a damaged header beside a body", new Case(Map.of(PKG_A, A), root -> {
            copies(root, null, GARBAGE, GARBAGE);
            slot(root, A, bound(A, PKG_A, 1, false, 1));
        }));
        all.put("a damaged slot", new Case(Map.of(PKG_A, A), root -> {
            pair(root, header(1, live(A)));
            Path directory = Files.createDirectory(root.resolve("slots/" + A));
            Files.write(directory.resolve("record.bin"), GARBAGE);
            Files.write(directory.resolve("record.bin.reservecopy"), GARBAGE);
        }));
        all.put("a header of version 3", new Case(Map.of(PKG_A, A), root -> {
            copies(root, null, frame(1, 3, body(bytes(header(2, live(A), live(E))))), bytes(header(1, live(A))));
            slot(root, A, bound(A, PKG_A, 1, false, 1));
        }));
        all.put("a slot of version 3 with its stable prefix", new Case(Map.of(PKG_A, A), root -> {
            pair(root, header(1, live(A)));
            Path directory = Files.createDirectory(root.resolve("slots/" + A));
            byte[] later = relabeled(NativeIdentityRecords.encodeSlot(suspended(A, PKG_A, 1)), 3);
            Files.write(directory.resolve("record.bin"), later);
            Files.write(directory.resolve("record.bin.reservecopy"), later);
        }));
        all.put("a bound reservation", new Case(Map.of(PKG_R, R), root ->
                pair(root, v2(1, boundCreating(R, 1, PKG_R)))));
        all.put("a version 2 slot beside a bound reservation", new Case(Map.of(PKG_A, A, PKG_R, R), root -> {
            pair(root, v2(2, live(A), boundCreating(R, 2, PKG_R)));
            slot(root, A, suspended(A, PKG_A, 1));
        }));
        all.put("a reservation and publication through the manager", new Case(Map.of(PKG_B, B), null));
        return all;
    }

    // A facade of this format, or of the default, over root.
    private static PackageManagerService facade(Path root, boolean initialize, NativeIdentityStore.Format format) {
        return format == DEFAULT ? new PackageManagerService(root, initialize)
                : new PackageManagerService(root, initialize, format);
    }

    // A booted facade of this format, or of the default, over root: the packages, then the store.
    private static PackageManagerService boot(Path root, NativeIdentityStore.Format format,
            Map<String, Integer> packages) {
        PackageManagerService pm = facade(root, false, format);
        for (Map.Entry<String, Integer> entry : packages.entrySet()) pm.mSettings.add(entry.getKey(), entry.getValue());
        pm.mSettings.restoreAfterPackageSettings();
        return pm;
    }

    // Every file below root by path and SHA-256, and every directory: the store's bytes, wherever
    // the copy lies.
    private static String contents(Path root) throws Exception {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return "none";
        Map<String, String> files = new TreeMap<>();
        List<Path> paths;
        try (var walk = Files.walk(root)) {
            paths = walk.toList();
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        for (Path path : paths) {
            files.put(root.relativize(path).toString(), Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                    ? HexFormat.of().formatHex(digest.digest(Files.readAllBytes(path))) : "directory");
        }
        return files.toString();
    }

    // What one booted facade reads, restores, holds, defers and scans over its store, and the
    // store's bytes: everything but the diagnostic dump.
    private static String facts(PackageManagerService pm, Path root, Map<String, Integer> packages)
            throws Exception {
        Settings settings = pm.mSettings;
        NativeIdentityStore.Loaded loaded = settings.mNativeIdentityLoaded;
        StringBuilder text = new StringBuilder("header=").append(loaded.header.status)
                .append(loaded.header.unavailable ? "/unavailable" : "").append('/').append(loaded.header.value)
                .append('/').append(loaded.header.decodedCopies.size());
        for (Map.Entry<Integer, NativeIdentityStore.ReadResult<Slot>> entry : new TreeMap<>(loaded.slots).entrySet()) {
            NativeIdentityStore.ReadResult<Slot> read = entry.getValue();
            text.append(" slot ").append(entry.getKey()).append('=').append(read.status)
                    .append(read.unavailable ? "/unavailable" : "").append('/').append(read.value)
                    .append('/').append(read.decodedCopies.size())
                    .append(loaded.bindingUsable(entry.getKey()) ? "/usable" : "");
        }
        text.append(" holds=").append(new TreeSet<>(loaded.occupiedAppIds))
                .append(" flags=").append(loaded.enumerationComplete).append('/').append(loaded.unsupportedFootprint)
                .append('/').append(loaded.unavailableFootprint).append('/').append(loaded.unselectedFootprint)
                .append(" ready=").append(loaded.creationReady())
                .append(" restorable=").append(loaded.counterRestorable())
                .append(" histories=").append(new TreeMap<>(loaded.histories()).values());
        NativePrincipalPins pins = settings.pins;
        text.append(" pins=").append(pins.reservedAppIds()).append(" counter=")
                .append(pins.hasKnownCounter() ? String.valueOf(pins.snapshotForWrite().lastId) : "none")
                .append(" creation=").append(settings.nativePrincipalCreationReadyLPr());
        for (Map.Entry<String, Integer> entry : packages.entrySet()) {
            String name = entry.getKey();
            NativePrincipalPins.Pin pin = pins.find(name, 0);
            text.append(' ').append(name).append('=').append(pin == null ? "none" : pin.phase() + "/" + pin.record())
                    .append(settings.nativePrincipalDesignationDeferredLPr(name) ? "/deferred" : "")
                    .append(settings.isNativePrincipalPackageLPr(name) ? "/native" : "")
                    .append(settings.nativeScanSubjectAllowedLPr(settings.packages.get(name)) ? "/scanned" : "");
        }
        for (int appId : List.of(B, C, A, R, D, E)) {
            if (settings.isNativePrincipalAppIdLPr(appId)) text.append(" held ").append(appId);
        }
        NativeIdentityPersistence.BootFacts boot = settings.nativeBootFactsLPr();
        text.append(" retired=").append(boot.retired.keySet()).append(" ticketed=")
                .append(boot.ticketedTombstones.keySet()).append(" releasing=").append(boot.releasingWithoutDirectory)
                .append(" bytes=").append(contents(root));
        return text.toString();
    }

    // One reader's boot over its own copy of a case, which must write nothing.
    private static Read read(List<String> problems, String name, Case shape, NativeIdentityStore.Format format)
            throws Exception {
        String reader = format == DEFAULT ? "the default" : format.toString();
        try {
            if (name.equals("a store the facade initializes")) {
                PackageManagerService pm = facade(fresh(), true, format);
                for (Map.Entry<String, Integer> entry : shape.packages.entrySet()) {
                    pm.mSettings.add(entry.getKey(), entry.getValue());
                }
                return new Read(facts(pm, pm.mSettings.root, shape.packages), pm.mSettings.nativeIdentityDumpLPr());
            }
            if (name.equals("a reservation and publication through the manager")) {
                PackageManagerService live = facade(fresh(), true, format);
                for (Map.Entry<String, Integer> entry : shape.packages.entrySet()) {
                    live.mSettings.add(entry.getKey(), entry.getValue());
                }
                NativePrincipalManager manager = new NativePrincipalManager(live);
                check(problems, manager.commit(manager.prepare(manager.select(PKG_B, 0))),
                        reader + " publication refused");
                Path root = live.mSettings.root;
                age(root);
                Map<String, String> before = footprint(root);
                PackageManagerService pm = boot(root, format, shape.packages);
                check(problems, footprint(root).equals(before), reader + " boot wrote");
                return new Read(facts(pm, root, shape.packages), pm.mSettings.nativeIdentityDumpLPr());
            }
            Path root = fresh();
            if (shape.build != null) {
                Files.createDirectories(root.resolve("slots"));
                shape.build.write(root);
                age(root);
            }
            Map<String, String> before = shape.build == null ? null : footprint(root);
            PackageManagerService pm = boot(root, format, shape.packages);
            check(problems, shape.build == null ? !Files.exists(root, LinkOption.NOFOLLOW_LINKS)
                    : footprint(root).equals(before), reader + " boot wrote");
            return new Read(facts(pm, root, shape.packages), pm.mSettings.nativeIdentityDumpLPr());
        } catch (Exception | AssertionError error) {
            return new Read("threw " + error, "threw " + error);
        }
    }

    public static void main(String[] args) throws Exception {
        if (!NativeProductionDefaultTest.class.desiredAssertionStatus()) {
            throw new AssertionError("run with java -ea");
        }
        if (!LINEAGE.equals(Settings.LINEAGE)) throw new AssertionError("facade lineage");
        start(Path.of(args[0]).resolve("production-default"));
        LocalServices.addService(UserManagerInternal.class, new UserManagerInternal());
        Map<String, Case> cases = cases();
        Map<String, Map<String, Read>> reads = new LinkedHashMap<>();
        for (Map.Entry<String, Case> entry : cases.entrySet()) {
            String name = entry.getKey();
            run("default / " + name, problems -> {
                Map<String, Read> byReader = new LinkedHashMap<>();
                for (NativeIdentityStore.Format format : new NativeIdentityStore.Format[] {DEFAULT, V3, V2, V1}) {
                    byReader.put(format == DEFAULT ? "default" : format.toString(),
                            read(problems, name, entry.getValue(), format));
                }
                reads.put(name, byReader);
                Read fallback = byReader.get("default"), production = byReader.get("V3");
                check(problems, !production.facts.startsWith("threw "), "V3 " + production.facts);
                check(problems, fallback.facts.equals(production.facts), "the default read " + fallback.facts
                        + " where Format.V3 read " + production.facts);
                check(problems, fallback.dump.equals(production.dump), "the default dumped " + fallback.dump
                        + " where Format.V3 dumped " + production.dump);
            });
        }
        run("default / the facade without arguments constructs Format.V3", problems -> {
            PackageManagerService bare = new PackageManagerService();
            Path initialized = fresh(), opened = layout(null, bytes(OLD), bytes(OLD));
            for (PackageManagerService pm : List.of(bare, new PackageManagerService(initialized, true),
                    new PackageManagerService(opened, false))) {
                check(problems, pm.mSettings.store.format() == V3 && pm.mSettings.persistence.lifecycleFormat()
                        && pm.mSettings.nativeIdentitySlotCeilingLPr() == V3.slotCeiling,
                        "a default facade constructs " + pm.mSettings.store.format());
            }
            check(problems, bare.mSettings.nativeIdentityDumpLPr().equals(
                    new PackageManagerService(fresh(), true, V3).mSettings.nativeIdentityDumpLPr()),
                    "the facade without arguments dumps otherwise than Format.V3");
        });
        for (NativeIdentityStore.Format format : List.of(V2, V1)) {
            Set<String> expected = format == V2 ? V2_DIFFERS : V1_DIFFERS;
            String what = format == V2 ? "where version 2 slots are supported state" : "where version 2 records are";
            run("control / Format." + format + " reads differently exactly " + what, problems -> {
                Set<String> facts = new TreeSet<>(), dumps = new TreeSet<>();
                for (Map.Entry<String, Map<String, Read>> entry : reads.entrySet()) {
                    Read earlier = entry.getValue().get(format.toString()), production = entry.getValue().get("V3");
                    check(problems, !earlier.facts.startsWith("threw "), format + " " + earlier.facts);
                    if (!earlier.facts.equals(production.facts)) facts.add(entry.getKey());
                    if (!earlier.dump.equals(production.dump)) dumps.add(entry.getKey());
                }
                check(problems, reads.keySet().equals(cases.keySet()), "cases not read " + reads.keySet());
                check(problems, facts.equals(new TreeSet<>(expected)), format + " reads differently on " + facts);
                check(problems, dumps.equals(new TreeSet<>(cases.keySet())), format + " dumps differently on "
                        + dumps);
            });
        }
        finish(Os.allClosed());
        System.out.println("The host facade's default format is Format.V3 over every representative store;"
                + " Android boot and activation unqualified");
    }
}
