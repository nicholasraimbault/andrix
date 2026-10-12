// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeLifecycleTestSupport.*;

import android.system.Os;
import com.android.server.LocalServices;
import com.android.server.pm.NativeIdentityRecords.Lifecycle;
import com.android.server.pm.NativeIdentityRecords.SuspensionReason;
import com.android.server.pm.NativeIdentityStore.Format;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import dev.andrix.proof.nativelab.LabHistoryStore;

/**
 * The privileged native identity diagnostic, from the one shared fragment: in the host Settings
 * facade, which carries the fragment verbatim, and in the candidate's own Settings text in its
 * history harness. Schema 2 under the existing formats names every deferred package as standard
 * padded Base64 in Java String order, after its exact count. Schema 3, which only the lifecycle
 * format's slot ceiling selects and no production text constructs, adds one slot row per hold with
 * positive state from a selected VALID body only. A malformed or oversized report is only the
 * unavailable envelope, and a Settings without live pins only the not live one. Expected text comes
 * from an independent encoder and Java String order, never from the fragment. Host facades only: not
 * an Android dump, a lease or any authority.
 */
public final class NativeIdentityDumpTest {
    private static final String SCHEMA2 = "andrix-native-identities-v2\n";
    private static final String SCHEMA3 = "andrix-native-identities-v3\n";
    // Each named report this run produced, written for the runner's independent observer.
    private static Path dumps;
    private static final List<String> KEYS = List.of("live_settings", "authority", "counter_known", "cached_header",
            "cached_enumeration_complete", "creation_ready", "allocator_search_start", "unidentified_code",
            "deferred_count");

    // One line, so that a failure message never breaks the runner's line protocol.
    private static String flat(Object value) {
        return String.valueOf(value).replace("\n", "\\n").replace("\t", "\\t");
    }

    private static String emitted(String name, String text) throws Exception {
        Files.writeString(dumps.resolve(name + ".txt"), text, StandardCharsets.US_ASCII);
        return text;
    }

    private static String encoded(String name) {
        return Base64.getEncoder().encodeToString(name.getBytes(StandardCharsets.UTF_8));
    }

    // A facade over this store with the account's package mapped, restored as at boot.
    private static Settings facade(Path root, Format format, boolean mapped) {
        return facade(root, format, settings -> {
            if (mapped) settings.add(PKG_A, A);
        });
    }

    // A facade over this store with these mappings, restored as at boot.
    private static Settings facade(Path root, Format format, java.util.function.Consumer<Settings> mappings) {
        PackageManagerService pm = new PackageManagerService(root, false, format);
        mappings.accept(pm.mSettings);
        pm.mSettings.restoreAfterPackageSettings();
        return pm.mSettings;
    }

    // The scalar lines after the header, in their order.
    private static List<String> scalars(String text) {
        List<String> found = new ArrayList<>();
        for (String line : text.split("\n", -1)) {
            if (line.contains("=") && !line.startsWith("hold=") && !line.startsWith("slot=")
                    && !line.startsWith("deferred=")) {
                found.add(line);
            }
        }
        return found;
    }

    private static List<String> expectedScalars(boolean counter, String header, boolean complete, boolean creation,
            boolean unidentified, int deferred) {
        return List.of("live_settings=true", "authority=not-reported", "counter_known=" + counter,
                "cached_header=" + header, "cached_enumeration_complete=" + complete, "creation_ready=" + creation,
                "allocator_search_start=10000", "unidentified_code=" + unidentified, "deferred_count=" + deferred);
    }

    // A version 2 body: an eligible account with a pause, which version 1 cannot hold.
    private static NativeIdentityRecords.Slot pausedBody(int appId, String packageName, long principal) {
        return new NativeIdentityRecords.Slot(LINEAGE, appId, packageName, 1, SIGNERS, List.of(
                new NativeIdentityRecords.UserEntry(principal, 0, SERIAL, eligible(byUser(SuspensionReason.USER_PAUSED)))));
    }

    // The candidate's own Settings text over the same store and mapping.
    private static NativeHistoryHarness candidate(Path root, Format format, boolean mapped) {
        NativeHistoryHarness harness = new NativeHistoryHarness();
        harness.slotCeiling = format == Format.V3 ? 2 : 1;
        if (mapped) harness.map(A, new NativeHistoryHarness.PackageSetting(PKG_A, A, false));
        harness.apply(load(root, format));
        return harness;
    }

    private static List<String> lines(String text, String prefix) {
        List<String> found = new ArrayList<>();
        for (String line : text.split("\n", -1)) if (line.startsWith(prefix)) found.add(line);
        return found;
    }

    // Every line but the two the facades legitimately report differently: creation readiness and
    // the allocator's search start.
    private static List<String> shared(String text) {
        List<String> kept = new ArrayList<>();
        for (String line : text.split("\n", -1)) {
            if (!line.startsWith("creation_ready=") && !line.startsWith("allocator_search_start=")) kept.add(line);
        }
        return kept;
    }

    private static List<String> keys(String text) {
        List<String> found = new ArrayList<>();
        for (String line : text.split("\n", -1)) {
            int at = line.indexOf('=');
            if (at > 0 && !line.startsWith("hold=") && !line.startsWith("slot=") && !line.startsWith("deferred=")) {
                found.add(line.substring(0, at));
            }
        }
        return found;
    }

    private static String hold(Settings s, int appId, String status, String kind, String name) {
        return "hold=" + appId + "\t" + status + "\t" + s.pins.isAppIdPinned(appId) + "\t" + kind + "\t" + encoded(name);
    }

    private static void schemaTwo() {
        run("v2 / an eligible mapped body has no deferred name and the hold row as before", problems -> {
            Settings s = facade(layout(slotA(1, eligible())), Format.V2, true);
            String text = emitted("v2-eligible", s.nativeIdentityDumpLPr());
            check(problems, text.startsWith(SCHEMA2), "schema " + flat(text));
            check(problems, keys(text).equals(KEYS), "scalar order " + flat(keys(text)));
            check(problems, lines(text, "deferred_count=").equals(List.of("deferred_count=0")), "count " + flat(text));
            check(problems, lines(text, "deferred=").isEmpty() && lines(text, "slot").isEmpty(), "rows " + flat(text));
            check(problems, lines(text, "hold=").equals(List.of(hold(s, A, "VALID", "package", PKG_A))), "hold " + flat(text));
            check(problems, text.endsWith("\n"), "a last line without its end");
        });
        run("v2 / a retiring mapped body is deferred and named once", problems -> {
            Settings s = facade(layout(slotA(1, Lifecycle.version1(true))), Format.V2, true);
            String text = emitted("v2-retiring", s.nativeIdentityDumpLPr());
            check(problems, lines(text, "deferred_count=").equals(List.of("deferred_count=1")), "count " + flat(text));
            check(problems, lines(text, "deferred=").equals(List.of("deferred=" + encoded(PKG_A))), "name " + flat(text));
            check(problems, !text.contains(PKG_A), "a raw name");
        });
        run("v2 / every deferred name in Java String order, padded Base64, never raw", problems -> {
            Settings s = facade(layout(slotA(1, eligible())), Format.V2, true);
            List<String> names = List.of("dev.b", "dev.a", "caf\u00e9", "line\nbreak", "smile\uD83D\uDE00", "Z");
            for (String name : names) s.mNativeRecoveryView = s.mNativeRecoveryView.defer(name, null);
            List<String> expected = new ArrayList<>();
            for (String name : new TreeSet<>(names)) expected.add("deferred=" + encoded(name));
            String text = emitted("v2-names", s.nativeIdentityDumpLPr());
            check(problems, lines(text, "deferred=").equals(expected), "names " + flat(lines(text, "deferred=")));
            check(problems, lines(text, "deferred_count=").equals(List.of("deferred_count=6")), "count");
            check(problems, text.contains("deferred=Wg==\n"), "padding");
            check(problems, !text.contains("line\nbreak") && !text.contains("caf\u00e9"), "a raw name");
            int deferredAt = text.indexOf("\ndeferred="), holdAt = text.indexOf("\nhold=");
            check(problems, holdAt > 0 && deferredAt > holdAt, "the names follow the holds");
        });
        run("v2 / a malformed deferred name gives only the unavailable envelope", problems -> {
            for (String bad : List.of("lone\uD800", "\uDC00lead", "x".repeat(256))) {
                Settings s = facade(layout(slotA(1, eligible())), Format.V2, true);
                s.mNativeRecoveryView = s.mNativeRecoveryView.defer("dev.ok", null).defer(bad, null);
                check(problems, emitted("v2-unavailable-" + bad.length(), s.nativeIdentityDumpLPr())
                        .equals(SCHEMA2 + "observer_available=false\n"),
                        "accepted a malformed name of length " + bad.length());
            }
            Settings s = facade(layout(slotA(1, eligible())), Format.V2, true);
            s.mNativeRecoveryView = s.mNativeRecoveryView.defer("x".repeat(255), null);
            check(problems, s.nativeIdentityDumpLPr().contains("deferred=" + encoded("x".repeat(255)) + "\n"),
                    "refused a name at its bound");
        });
        run("v2 / more than 100000 names or 8 MiB of output give only the unavailable envelope", problems -> {
            List<String> many = new ArrayList<>();
            for (int i = 0; i < 100000; i++) many.add(String.format("n%06d", i));
            Settings s = facade(layout(slotA(1, eligible())), Format.V2, true);
            s.mNativeRecoveryView = new NativePrincipalRecovery(Set.of(), Set.of(), many, List.of(), false);
            check(problems, s.nativeIdentityDumpLPr().contains("deferred_count=100000\n"), "refused 100000 names");
            many.add("n100000");
            s.mNativeRecoveryView = new NativePrincipalRecovery(Set.of(), Set.of(), many, List.of(), false);
            check(problems, s.nativeIdentityDumpLPr().equals(SCHEMA2 + "observer_available=false\n"), "100001 names");
            List<String> long_ = new ArrayList<>();
            for (int i = 0; i < 30000; i++) long_.add(String.format("%05d", i) + "x".repeat(250));
            s.mNativeRecoveryView = new NativePrincipalRecovery(Set.of(), Set.of(), long_, List.of(), false);
            check(problems, s.nativeIdentityDumpLPr().equals(SCHEMA2 + "observer_available=false\n"), "above 8 MiB");
        });
        run("v2 / a Settings without live pins gives only the not live envelope", problems -> {
            for (Format format : List.of(Format.V2, Format.V3)) {
                Settings s = facade(layout(slotA(1, eligible())), format, true);
                s.pins = null;
                check(problems, emitted("v2-unavailable-not-live-" + format, s.nativeIdentityDumpLPr())
                        .equals(SCHEMA2 + "live_settings=false\n"), "format " + format);
            }
        });
    }

    private static void states() {
        run("v2 / a missing store is not complete, cannot create and holds nothing", problems -> {
            String text = facade(fresh(), Format.V2, true).nativeIdentityDumpLPr();
            check(problems, scalars(text).equals(expectedScalars(false, "MISSING", false, false, false, 0)),
                    "scalars " + flat(text));
            check(problems, lines(text, "hold=").isEmpty() && lines(text, "deferred=").isEmpty(), "rows " + flat(text));
        });
        run("v2 / an empty valid store holds nothing and can create", problems -> {
            String text = facade(store(header(0)), Format.V2, false).nativeIdentityDumpLPr();
            check(problems, scalars(text).equals(expectedScalars(true, "VALID", true, true, false, 0)),
                    "scalars " + flat(text));
            check(problems, lines(text, "hold=").isEmpty(), "holds " + flat(text));
        });
        run("v2 / each mapping kind and slot status names its hold", problems -> {
            int c = B + 1, d = B + 2;
            Path root = store(header(ID_B, live(A), live(B), live(c), live(d)));
            slot(root, accountA());
            raw(root, c, new byte[] {1, 2, 3}, new byte[] {1, 2, 3});
            slot(root, pausedBody(d, "dev.andrix.lifecycleother", ID_B));
            SharedUserSetting shared = new SharedUserSetting();
            shared.name = "dev.andrix.shareduser";
            Settings s = facade(root, Format.V2, settings -> {
                settings.add(PKG_A, A);
                settings.ids.registerExistingAppId(B, shared, shared.name);
                settings.ids.registerExistingAppId(c, new SettingBase() { }, "other");
            });
            String text = s.nativeIdentityDumpLPr();
            check(problems, scalars(text).equals(expectedScalars(false, "VALID", true, false, true, 0)),
                    "scalars " + flat(text));
            check(problems, lines(text, "hold=").equals(List.of(
                    "hold=" + A + "\tVALID\ttrue\tpackage\t" + encoded(PKG_A),
                    "hold=" + B + "\tMISSING\tfalse\tshared\t" + encoded("dev.andrix.shareduser"),
                    "hold=" + c + "\tDAMAGED\tfalse\tother\t",
                    "hold=" + d + "\tUNSUPPORTED\tfalse\tempty\t")), "holds " + flat(lines(text, "hold=")));
        });
        run("v2 / a supported body beside its own unsupported sibling conflicts and is deferred", problems -> {
            Path root = store(header(ID_B, live(A), live(B)));
            slot(root, accountA());
            slot(root, pausedBody(B, PKG_A, ID_B));
            String text = facade(root, Format.V2, true).nativeIdentityDumpLPr();
            check(problems, scalars(text).equals(expectedScalars(false, "VALID", true, false, true, 1)),
                    "scalars " + flat(text));
            check(problems, lines(text, "hold=").equals(List.of(
                    "hold=" + A + "\tCONFLICT\tfalse\tpackage\t" + encoded(PKG_A),
                    "hold=" + B + "\tUNSUPPORTED\tfalse\tempty\t")), "holds " + flat(lines(text, "hold=")));
            check(problems, lines(text, "deferred=").equals(List.of("deferred=" + encoded(PKG_A))), "names " + flat(text));
        });
        run("v2 / an unrelated unsupported body leaves the supported account pinned and undeferred", problems -> {
            Path root = store(header(ID_B, live(A), live(B)));
            slot(root, accountA());
            slot(root, pausedBody(B, "dev.andrix.lifecycleother", ID_B));
            String text = facade(root, Format.V2, true).nativeIdentityDumpLPr();
            check(problems, scalars(text).equals(expectedScalars(false, "VALID", true, false, true, 0)),
                    "scalars " + flat(text));
            check(problems, lines(text, "hold=").equals(List.of(
                    "hold=" + A + "\tVALID\ttrue\tpackage\t" + encoded(PKG_A),
                    "hold=" + B + "\tUNSUPPORTED\tfalse\tempty\t")), "holds " + flat(lines(text, "hold=")));
        });
        run("v2 / the dump follows the restoration's replacement of the live pins", problems -> {
            PackageManagerService pm = new PackageManagerService(layout(accountA()), false, Format.V2);
            pm.mSettings.add(PKG_A, A);
            NativePrincipalPins initial = pm.mSettings.pins;
            String before = pm.mSettings.nativeIdentityDumpLPr();
            pm.mSettings.restoreAfterPackageSettings();
            String after = pm.mSettings.nativeIdentityDumpLPr();
            // The restoration installs new pins, which pin A where the initial ones never did.
            check(problems, pm.mSettings.pins != initial && !initial.isAppIdPinned(A), "the pins were not replaced");
            check(problems, before.contains("creation_ready=false\n") && lines(before, "hold=").isEmpty(),
                    "before " + flat(before));
            check(problems, after.contains("creation_ready=true\n") && lines(after, "hold=").equals(List.of(
                    "hold=" + A + "\tVALID\ttrue\tpackage\t" + encoded(PKG_A))), "after " + flat(after));
        });
        run("v2 / a protected name that is not deferred is never printed", problems -> {
            Settings s = facade(layout(accountA()), Format.V2, true);
            s.mNativeRecoveryView = s.mNativeRecoveryView.protectNames(List.of("dev.andrix.protectedonly"));
            String text = s.nativeIdentityDumpLPr();
            check(problems, text.contains("deferred_count=0\n") && lines(text, "deferred=").isEmpty()
                    && !text.contains(encoded("dev.andrix.protectedonly")), "printed " + flat(text));
        });
    }

    // The guest rows G9 and G10, which the image step keeps as exact host controls: the guest
    // generator's own bytes through the actual codec, the subject mapped at its app ID as installed,
    // and the facade's dump and scan rule under the production format.
    private static final String GUEST_LINEAGE = "00112233445566778899aabbccddeeff";
    private static final int SUBJECT_ID = 10148, OTHER_ID = 10149;
    private static final long GUEST_SERIAL = 7;

    private static Path guestStore(Map<String, byte[]> files) throws Exception {
        Path root = fresh();
        Files.createDirectories(root.resolve("slots"));
        for (Map.Entry<String, byte[]> file : files.entrySet()) {
            Path path = root.resolve(file.getKey());
            Files.createDirectories(path.getParent());
            Files.write(path, file.getValue());
        }
        return root;
    }

    private static void guestControls() {
        Set<String> signers = Set.of(LabHistoryStore.FIXTURE_SIGNER);
        String subject = LabHistoryStore.SUBJECT;
        run("g9 / the subject's bound reservation alone is restored, pinned and admitted", problems -> {
            byte[] header = LabHistoryStore.creatingHeader(GUEST_LINEAGE, SUBJECT_ID, GUEST_SERIAL, signers);
            Path root = guestStore(Map.of("store.bin", header, "store.bin.reservecopy", header));
            Settings s = facade(root, Format.V2, settings -> settings.add(subject, SUBJECT_ID));
            String text = s.nativeIdentityDumpLPr();
            check(problems, scalars(text).equals(expectedScalars(true, "VALID", true, true, false, 0)),
                    "scalars " + flat(text));
            check(problems, lines(text, "hold=").equals(List.of(
                    "hold=" + SUBJECT_ID + "\tMISSING\ttrue\tpackage\t" + encoded(subject))), "holds " + flat(text));
            check(problems, s.nativeScanSubjectAllowedLPr(s.packages.get(subject)), "the subject was not admitted");
        });
        run("g10 / another package's unsupported body leaves the subject restored, pinned and admitted", problems -> {
            Path root = guestStore(LabHistoryStore.lifecycleLayout("v2-beside-unrelated-body", GUEST_LINEAGE,
                    SUBJECT_ID, OTHER_ID, GUEST_SERIAL, signers));
            Settings s = facade(root, Format.V2, settings -> settings.add(subject, SUBJECT_ID));
            String text = s.nativeIdentityDumpLPr();
            check(problems, scalars(text).equals(expectedScalars(false, "VALID", true, false, true, 0)),
                    "scalars " + flat(text));
            check(problems, lines(text, "hold=").equals(List.of(
                    "hold=" + SUBJECT_ID + "\tVALID\ttrue\tpackage\t" + encoded(subject),
                    "hold=" + OTHER_ID + "\tUNSUPPORTED\tfalse\tempty\t")), "holds " + flat(text));
            check(problems, s.nativeScanSubjectAllowedLPr(s.packages.get(subject)), "the subject was not admitted");
            // The discriminator: the same layout with the subject's own sibling conflicts and defers it.
            Path sibling = guestStore(LabHistoryStore.lifecycleLayout("v2-beside-sibling", GUEST_LINEAGE,
                    SUBJECT_ID, OTHER_ID, GUEST_SERIAL, signers));
            Settings t = facade(sibling, Format.V2, settings -> settings.add(subject, SUBJECT_ID));
            String refused = t.nativeIdentityDumpLPr();
            check(problems, lines(refused, "hold=").get(0).startsWith("hold=" + SUBJECT_ID + "\tCONFLICT\tfalse")
                    && lines(refused, "deferred=").equals(List.of("deferred=" + encoded(subject)))
                    && !t.nativeScanSubjectAllowedLPr(t.packages.get(subject)), "sibling " + flat(refused));
        });
    }

    private static void schemaThree() {
        run("v3 / the lifecycle format reports each held slot's version, lifecycle and suspensions", problems -> {
            Path root = store(header(ID_B, live(A), live(B)));
            slot(root, slotA(2, eligible(byUser(SuspensionReason.USER_PAUSED))));
            slot(root, slotB(2, retired(retiredBlock())));
            Settings s = facade(root, Format.V3, true);
            String text = emitted("v3-slots", s.nativeIdentityDumpLPr());
            check(problems, text.startsWith(SCHEMA3), "schema " + flat(text));
            List<String> expectedKeys = new ArrayList<>(KEYS);
            expectedKeys.add("slot_count");
            check(problems, keys(text).equals(expectedKeys), "scalar order " + flat(keys(text)));
            check(problems, lines(text, "slot_count=").equals(List.of("slot_count=2")), "count " + flat(text));
            check(problems, lines(text, "slot=").equals(List.of("slot=" + A + "\t2\tELIGIBLE\ttrue",
                    "slot=" + B + "\t2\tRETIRED\tfalse")), "rows " + flat(lines(text, "slot=")));
            int holdAt = text.indexOf("\nhold="), slotAt = text.indexOf("\nslot="), nameAt = text.indexOf("\ndeferred=");
            check(problems, holdAt > 0 && slotAt > holdAt && (nameAt < 0 || nameAt > slotAt), "row order " + flat(text));
        });
        run("v3 / an empty body is a tombstone, and a version 1 body reports version 1", problems -> {
            Path root = store(header(ID_B, live(A), live(B)));
            slot(root, tombstoneA());
            slot(root, slotB(1, eligible()));
            String text = emitted("v3-tombstone", facade(root, Format.V3, false).nativeIdentityDumpLPr());
            check(problems, lines(text, "slot=").equals(List.of("slot=" + A + "\t2\tTOMBSTONE\tfalse",
                    "slot=" + B + "\t1\tELIGIBLE\tfalse")), "rows " + flat(lines(text, "slot=")));
        });
        run("v3 / damaged and missing records report nothing", problems -> {
            Path root = store(header(ID_B, live(A), live(B)));
            raw(root, A, new byte[] {1, 2, 3}, new byte[] {1, 2, 3});
            String text = emitted("v3-not-reported", facade(root, Format.V3, false).nativeIdentityDumpLPr());
            check(problems, lines(text, "slot=").equals(List.of(
                    "slot=" + A + "\tnot-reported\tnot-reported\tnot-reported",
                    "slot=" + B + "\tnot-reported\tnot-reported\tnot-reported")), "rows " + flat(lines(text, "slot=")));
        });
        run("v2 / the existing formats never report schema 3 rows, whatever the bodies hold", problems -> {
            for (Format format : List.of(Format.V1, Format.V2)) {
                Path root = store(header(ID_B, live(A), live(B)));
                slot(root, slotA(2, eligible(byUser(SuspensionReason.USER_PAUSED))));
                String text = facade(root, format, true).nativeIdentityDumpLPr();
                check(problems, text.startsWith(SCHEMA2) && lines(text, "slot").isEmpty(), "format " + format);
            }
        });
    }

    private static void parity() {
        run("parity / the candidate's own Settings text gives the facade's report", problems -> {
            List<Path> roots = List.of(layout(slotA(1, Lifecycle.version1(true))), layout(slotA(1, eligible())));
            for (Path root : roots) {
                for (Format format : List.of(Format.V1, Format.V2)) {
                    String facade = facade(root, format, true).nativeIdentityDumpLPr();
                    String candidate = candidate(root, format, true).nativeIdentityDumpLPr();
                    check(problems, shared(facade).equals(shared(candidate)), flat(format + " " + facade + " " + candidate));
                }
            }
            Path root = store(header(ID_B, live(A), live(B)));
            slot(root, slotA(2, eligible(byUser(SuspensionReason.USER_PAUSED))));
            slot(root, slotB(2, retired(retiredBlock())));
            String facade = facade(root, Format.V3, true).nativeIdentityDumpLPr();
            String candidate = candidate(root, Format.V3, true).nativeIdentityDumpLPr();
            check(problems, shared(facade).equals(shared(candidate)), flat("V3 " + facade + " " + candidate));
            check(problems, facade.startsWith(SCHEMA3) && lines(facade, "deferred=").size() == 2, "V3 names " + flat(facade));
        });
    }

    public static void main(String[] args) throws Exception {
        if (!NativeIdentityDumpTest.class.desiredAssertionStatus()) throw new AssertionError("run with java -ea");
        start(Path.of(args[0]).resolve("dump"));
        LocalServices.addService(UserManagerInternal.class, new UserManagerInternal());
        dumps = Files.createDirectories(Path.of(args[0]).resolve("dumps"));
        schemaTwo();
        states();
        guestControls();
        schemaThree();
        parity();
        finish(Os.allClosed());
        System.out.println("The diagnostic followed its schemas in both host renderers; Android unqualified");
    }
}
