// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

import dev.andrix.server.deployment.ArtifactRecords;
import dev.andrix.server.deployment.ArtifactRecords.Member;
import dev.andrix.server.deployment.ArtifactRecords.Operation;
import dev.andrix.server.deployment.ArtifactRecords.Output;
import dev.andrix.server.deployment.ArtifactRecords.Role;
import dev.andrix.server.deployment.ArtifactRecords.Scheme;
import dev.andrix.server.deployment.ArtifactRecords.Transaction;
import dev.andrix.server.deployment.ArtifactRecords.TransactionState;
import dev.andrix.server.deployment.DeploymentRecords;
import dev.andrix.server.deployment.DeploymentRecords.ChoiceKind;
import dev.andrix.server.deployment.DeploymentRecords.Classification;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.Realization;
import dev.andrix.server.deployment.DeploymentRecords.Route;
import dev.andrix.server.deployment.DeploymentRecords.Selection;
import dev.andrix.server.deployment.DeploymentRecords.UpdateResponsibility;
import dev.andrix.server.deployment.DeploymentStore;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * Host checks of the lab driver's guards that the end to end suite cannot isolate: which boot's
 * facts a plan binds and each refusal of the baseline, the selection a plan is made from, the host
 * configuration's parsing, pins and binding to the bridge configuration, and the signing approval's
 * conditions. Records are written
 * through the deployment package's public API. No guest, signer, key operation or Android is used;
 * the pinned files are arbitrary bytes. Argument: a scratch directory.
 */
public final class DriverTest {
    private static final String INSTALLATION = "00112233445566778899aabbccddeeff";
    private static final String COMPONENT = "com.android.systemui";
    private static final String FINGERPRINT = "andrix/cf/cf:17/BP4A.260813.001/2026081300:userdebug/test-keys";
    private static final String CONTEXT = "u:r:platform_app:s0:c512,c768";
    private static final String FACTORY = "f0".repeat(32), OTHER = "ed".repeat(32);
    private static final String BOOT_1 = "b1".repeat(16), BOOT_2 = "b2".repeat(16);
    private static final String PLAN = "0d".repeat(16), OTHER_PLAN = "0a".repeat(16);
    private static final String CERTIFICATE = "c8".repeat(32), KEY = "3d".repeat(32);
    private static final int UID = 10112;
    private static int failures;
    private static long ids = 0x500;
    private static Path scratch;

    private interface Case {
        void run() throws Exception;
    }

    private DriverTest() {}

    /** Runs named cases and prints PASS or FAIL lines, the lab runner's form. */
    private static final class Cases {
        void run(String name, Case c) {
            try {
                c.run();
                System.out.println("PASS " + name);
            } catch (Throwable t) {
                failures++;
                System.out.println("FAIL " + name + ": " + t);
            }
        }
    }

    private static final Cases cases = new Cases();

    private static void check(boolean ok, String what) {
        if (!ok) throw new AssertionError(what);
    }

    /** The case is refused, for the reason named by the fragment. */
    private static void refuses(String fragment, Case c) throws Exception {
        try {
            c.run();
        } catch (IllegalStateException | IllegalArgumentException | IOException e) {
            check(e.getMessage() != null && e.getMessage().contains(fragment), "refused for another reason: " + e.getMessage());
            return;
        }
        throw new AssertionError("not refused: " + fragment);
    }

    private static String id(long n) {
        return String.format("%032x", n);
    }

    private static Observation.Builder fact(String boot, Classification c, long wall) {
        return new Observation.Builder().installation(INSTALLATION).observationId(id(ids++)).boot(boot).route(Route.SHELL)
                .raw("99".repeat(32)).classification(c).at(-1, 1000, wall);
    }

    private static Observation completed(String boot, long wall, String fingerprint) {
        return fact(boot, Classification.BOOT_COMPLETED, wall).text(fingerprint).build();
    }

    private static Observation checkpoint(String boot, long wall, Classification c) {
        return fact(boot, c, wall).build();
    }

    private static Observation factory(String boot, long wall, String apk) {
        return fact(boot, Classification.FACTORY_PRESENT, wall).component(COMPONENT).digest(apk).version(37).build();
    }

    private static Observation active(String boot, long wall, Classification c, String apk) {
        return fact(boot, c, wall).component(COMPONENT).digest(apk).version(37).number(UID).text(CONTEXT).build();
    }

    /** One boot's complete baseline facts: completed with its fingerprint, committed, factory and active. */
    private static List<Observation> boot(String boot, long wall, String apk) {
        return List.of(completed(boot, wall, FINGERPRINT), checkpoint(boot, wall, Classification.CHECKPOINT_COMMITTED),
                factory(boot, wall, apk), active(boot, wall, Classification.FACTORY_COPY, apk));
    }

    private static DeploymentStore store(String name, List<Observation> facts) throws IOException {
        DeploymentStore store = new DeploymentStore(scratch.resolve(name), INSTALLATION);
        store.initialize();
        for (Observation o : facts) check(store.addObservation(o), "an observation was not written");
        return store;
    }

    private static List<Observation> concat(List<Observation> a, List<Observation> b) {
        List<Observation> all = new ArrayList<>(a);
        all.addAll(b);
        return all;
    }

    private static Selection selection(long revision, ChoiceKind choice, Realization realization, String checked) {
        return new Selection(INSTALLATION, COMPONENT, revision, choice, choice == ChoiceKind.PLAN ? PLAN : DeploymentRecords.NO_ID,
                UpdateResponsibility.REBUILD_WINDOW, 14L * 24 * 3600 * 1000, realization, checked, DeploymentRecords.NO_ID,
                DeploymentRecords.NO_ID, 1000);
    }

    /** A host configuration over arbitrary pinned files, its digest, and the directory it lives in. */
    private static final class Host {
        final Path dir;
        final Path config;
        final String digest;

        Host(String name, String plans, String sdk) throws IOException {
            dir = Files.createDirectory(scratch.resolve(name));
            String[] files = {"key", "certificate", "variant", "restoration"};
            StringBuilder text = new StringBuilder(LabHost.HEADER + "\n");
            text.append("signer ").append(dir.resolve("signer")).append('\n');
            text.append("artifacts ").append(dir.resolve("artifacts")).append('\n');
            text.append("work ").append(dir.resolve("work")).append('\n');
            for (int i = 0; i < 2; i++) {
                Path f = dir.resolve(files[i]);
                Files.write(f, (files[i] + " bytes").getBytes(StandardCharsets.US_ASCII));
                text.append(files[i]).append(' ').append(f).append(' ').append(LabProtocol.sha256Hex(Files.readAllBytes(f))).append('\n');
            }
            text.append("role ").append(CERTIFICATE).append(' ').append(KEY).append('\n');
            text.append("sdk ").append(sdk).append('\n');
            for (int i = 2; i < 4; i++) {
                Path f = dir.resolve(files[i]);
                Files.write(f, (files[i] + " bytes").getBytes(StandardCharsets.US_ASCII));
                text.append(files[i]).append(' ').append(f).append(' ').append(LabProtocol.sha256Hex(Files.readAllBytes(f))).append('\n');
            }
            text.append("plans ").append(plans).append('\n');
            config = dir.resolve("host.config");
            Files.write(config, text.toString().getBytes(StandardCharsets.US_ASCII));
            digest = LabProtocol.sha256Hex(Files.readAllBytes(config));
        }

        LabHost open() throws IOException {
            return new LabHost(config, digest);
        }
    }

    private static Transaction transaction(String plan, String certificate, String key, int sdkMin, int sdkMax) {
        List<Operation> ops = new ArrayList<>();
        List<Output> outs = new ArrayList<>();
        long n = 0x700;
        for (Role role : Role.values()) {
            for (Scheme scheme : Scheme.values()) ops.add(new Operation(id(n++), role, scheme));
            String input = (role == Role.VARIANT ? "a1" : "a2").repeat(32);
            String entries = (role == Role.VARIANT ? "b1" : "b2").repeat(32);
            long version = role == Role.VARIANT ? 38 : 39;
            outs.add(new Output(role, Member.APK, ArtifactRecords.APK_FACTS, input, entries, version, DeploymentRecords.NO_DIGEST, 0));
            outs.add(new Output(role, Member.IDSIG, ArtifactRecords.IDSIG_FACTS, input, entries, version, DeploymentRecords.NO_DIGEST, 0));
        }
        return new Transaction(INSTALLATION, id(0x600), COMPONENT, plan, id(0x601), certificate, key, sdkMin, sdkMax,
                TransactionState.OPEN, 0, ops, outs);
    }

    public static void main(String[] args) throws Exception {
        scratch = Files.createTempDirectory(Paths.get(args[0]), "driver");

        cases.run("baseline / binds T0's facts, whatever their wall times within the boot", () -> {
            // Tied and decreasing wall times inside T0 change nothing: no fact is chosen by time.
            DeploymentStore store = store("t0-walls", List.of(completed(BOOT_1, 5000, FINGERPRINT),
                    checkpoint(BOOT_1, 1000, Classification.CHECKPOINT_COMMITTED), factory(BOOT_1, 1000, FACTORY),
                    active(BOOT_1, 9000, Classification.FACTORY_COPY, FACTORY), completed(BOOT_1, 1000, FINGERPRINT)));
            LabDriverMain.Baseline b = LabDriverMain.baseline(store, COMPONENT, BOOT_1, BOOT_1);
            check(b.boot.equals(BOOT_1) && b.fingerprint.equals(FINGERPRINT) && b.apk.equals(FACTORY) && b.version == 37
                    && b.uid == UID && b.context.equals(CONTEXT), "T0's own facts");
        });
        cases.run("baseline / facts of another boot are refused, whatever the wall times", () -> {
            // The other boot's facts are earlier, tied or later on the wall clock, and the baseline is
            // refused each time rather than ordered by it.
            long[] walls = {1000, 5000, 9000};
            for (long wall : walls) {
                DeploymentStore store = store("other-boot-" + wall, concat(boot(BOOT_1, wall, OTHER), boot(BOOT_2, 5000, FACTORY)));
                refuses("facts of another boot", () -> LabDriverMain.baseline(store, COMPONENT, BOOT_2, BOOT_2));
            }
        });
        cases.run("baseline / a later incomplete check's facts are refused", () -> {
            // T0 checked completely; a later check in another boot recorded its completed boot and
            // stopped before the selection changed.
            DeploymentStore store = store("incomplete", concat(boot(BOOT_1, 1000, FACTORY), List.of(completed(BOOT_2, 2000, FINGERPRINT))));
            refuses("facts of another boot", () -> LabDriverMain.baseline(store, COMPONENT, BOOT_1, BOOT_1));
        });
        cases.run("baseline / a selection checked in another boot than T0 is refused", () -> {
            DeploymentStore store = store("checked-other", boot(BOOT_2, 1000, FACTORY));
            refuses("not the boot the driver's check established", () -> LabDriverMain.baseline(store, COMPONENT, BOOT_1, BOOT_2));
        });
        cases.run("baseline / no checked boot is refused", () -> {
            DeploymentStore store = store("unchecked", boot(BOOT_1, 1000, FACTORY));
            refuses("names no checked boot", () -> LabDriverMain.baseline(store, COMPONENT, DeploymentRecords.NO_ID, BOOT_1));
        });
        cases.run("baseline / T0 without a committed checkpoint is refused", () -> {
            DeploymentStore store = store("no-checkpoint", List.of(completed(BOOT_1, 1000, FINGERPRINT), factory(BOOT_1, 1000, FACTORY),
                    active(BOOT_1, 1000, Classification.FACTORY_COPY, FACTORY)));
            refuses("no committed checkpoint", () -> LabDriverMain.baseline(store, COMPONENT, BOOT_1, BOOT_1));
        });
        cases.run("baseline / a pending checkpoint in T0 is refused", () -> {
            DeploymentStore store = store("pending", concat(boot(BOOT_1, 1000, FACTORY),
                    List.of(checkpoint(BOOT_1, 1001, Classification.CHECKPOINT_PENDING))));
            refuses("pending checkpoint", () -> LabDriverMain.baseline(store, COMPONENT, BOOT_1, BOOT_1));
        });
        cases.run("baseline / two fingerprints in T0 are refused", () -> {
            DeploymentStore store = store("fingerprints", concat(boot(BOOT_1, 1000, FACTORY),
                    List.of(completed(BOOT_1, 1001, FINGERPRINT.replace("2026081300", "2026100600")))));
            refuses("fingerprint is not one value", () -> LabDriverMain.baseline(store, COMPONENT, BOOT_1, BOOT_1));
        });
        cases.run("baseline / T0 with no completed boot fact is refused", () -> {
            DeploymentStore store = store("no-completed", List.of(checkpoint(BOOT_1, 1000, Classification.CHECKPOINT_COMMITTED),
                    factory(BOOT_1, 1000, FACTORY), active(BOOT_1, 1000, Classification.FACTORY_COPY, FACTORY)));
            refuses("fingerprint is not one value", () -> LabDriverMain.baseline(store, COMPONENT, BOOT_1, BOOT_1));
        });
        cases.run("baseline / two factory copies in T0 are refused", () -> {
            DeploymentStore store = store("factories", concat(boot(BOOT_1, 1000, FACTORY), List.of(factory(BOOT_1, 1001, OTHER))));
            refuses("factory copy is not one observed value", () -> LabDriverMain.baseline(store, COMPONENT, BOOT_1, BOOT_1));
        });
        cases.run("baseline / an active copy other than the factory copy is refused", () -> {
            DeploymentStore store = store("active-other", List.of(completed(BOOT_1, 1000, FINGERPRINT),
                    checkpoint(BOOT_1, 1000, Classification.CHECKPOINT_COMMITTED), factory(BOOT_1, 1000, FACTORY),
                    active(BOOT_1, 1000, Classification.FACTORY_COPY, OTHER)));
            refuses("active copy is not the factory copy", () -> LabDriverMain.baseline(store, COMPONENT, BOOT_1, BOOT_1));
        });
        cases.run("baseline / a data copy with the factory bytes is refused", () -> {
            DeploymentStore store = store("data-copy", concat(boot(BOOT_1, 1000, FACTORY),
                    List.of(active(BOOT_1, 1001, Classification.DATA_COPY, FACTORY))));
            refuses("a data copy is active", () -> LabDriverMain.baseline(store, COMPONENT, BOOT_1, BOOT_1));
        });
        cases.run("baseline / T0 without a factory or an active fact is refused", () -> {
            DeploymentStore noFactory = store("no-factory", List.of(completed(BOOT_1, 1000, FINGERPRINT),
                    checkpoint(BOOT_1, 1000, Classification.CHECKPOINT_COMMITTED), active(BOOT_1, 1000, Classification.FACTORY_COPY, FACTORY)));
            refuses("factory copy is not one observed value", () -> LabDriverMain.baseline(noFactory, COMPONENT, BOOT_1, BOOT_1));
            DeploymentStore noActive = store("no-active", List.of(completed(BOOT_1, 1000, FINGERPRINT),
                    checkpoint(BOOT_1, 1000, Classification.CHECKPOINT_COMMITTED), factory(BOOT_1, 1000, FACTORY)));
            refuses("active copy is not one observed value", () -> LabDriverMain.baseline(noActive, COMPONENT, BOOT_1, BOOT_1));
        });
        cases.run("baseline / two active identities in T0 are refused", () -> {
            Observation other = fact(BOOT_1, Classification.FACTORY_COPY, 1001).component(COMPONENT).digest(FACTORY).version(37)
                    .number(UID + 1).text(CONTEXT).build();
            DeploymentStore store = store("two-actives", concat(boot(BOOT_1, 1000, FACTORY), List.of(other)));
            refuses("active copy is not one observed value", () -> LabDriverMain.baseline(store, COMPONENT, BOOT_1, BOOT_1));
        });
        cases.run("selection / a plan only from the factory choice found current at revision 0", () -> {
            check(LabDriverMain.factoryCurrent(selection(0, ChoiceKind.FACTORY, Realization.CURRENT, BOOT_1)), "factory, current, revision 0");
            check(!LabDriverMain.factoryCurrent(selection(0, ChoiceKind.FACTORY, Realization.UNCHECKED, DeploymentRecords.NO_ID)),
                    "unchecked");
            check(!LabDriverMain.factoryCurrent(selection(0, ChoiceKind.FACTORY, Realization.DIVERGED, BOOT_1)), "diverged");
            check(!LabDriverMain.factoryCurrent(selection(1, ChoiceKind.FACTORY, Realization.CURRENT, BOOT_1)), "revision 1");
            check(!LabDriverMain.factoryCurrent(selection(1, ChoiceKind.PLAN, Realization.CURRENT, BOOT_1)), "a plan's choice");
        });

        cases.run("host config / one exact form, every line checked", () -> {
            Host h = new Host("form", PLAN, "37 65535");
            byte[] good = Files.readAllBytes(h.config);
            check(LabHost.parse(good).digest.equals(h.digest) && LabHost.parse(good).plans.contains(PLAN), "the good form");
            String text = new String(good, StandardCharsets.US_ASCII);
            String[] bad = {text.replace(LabHost.HEADER, "andrix-lab-host 2"), text.substring(0, text.length() - 1),
                text.replace("signer /", "signer "), text.replace("plans " + PLAN, "plans " + PLAN + "," + PLAN),
                text.replace("sdk 37 65535", "sdk 38 37"), text.replace("sdk 37 65535", "sdk 37 65536"), text + "extra 1\n"};
            for (String b : bad) {
                refuses("", () -> LabHost.parse(b.getBytes(StandardCharsets.US_ASCII)));
            }
        });
        cases.run("host pins / a pinned file changed after its configuration is refused", () -> {
            Host h = new Host("pins", PLAN, "37 65535");
            Files.write(h.dir.resolve("key"), "another key".getBytes(StandardCharsets.US_ASCII));
            refuses("differs from its admitted digest", h::open);
        });
        cases.run("host pins / each pinned file changed after its configuration is refused", () -> {
            for (String file : new String[] {"key", "certificate", "variant", "restoration"}) {
                Host h = new Host("pins-" + file, PLAN, "37 65535");
                h.open();
                Files.write(h.dir.resolve(file), ("another " + file).getBytes(StandardCharsets.US_ASCII));
                refuses("differs from its admitted digest", h::open);
            }
        });
        cases.run("admission / only the bridge configuration the admission binds is read", () -> {
            Path dir = Files.createDirectory(scratch.resolve("admitted"));
            Path store = Paths.get("/lab/store");
            Path bound = dir.resolve("bridge.config"), other = dir.resolve("bridge-other.config");
            Files.write(bound, LabConfig.encode(INSTALLATION, COMPONENT, "c0".repeat(16), "7a".repeat(32), "aa".repeat(32), store, "5e".repeat(32)));
            Files.write(other, LabConfig.encode(INSTALLATION, COMPONENT, "c0".repeat(16), "7a".repeat(32), "aa".repeat(32), store, "6f".repeat(32)));
            String digest = LabProtocol.sha256Hex(Files.readAllBytes(bound));
            check(LabDriverMain.admitted(bound.toString(), digest).host.equals("5e".repeat(32)), "the admitted configuration");
            refuses("not the one the admission binds", () -> LabDriverMain.admitted(other.toString(), digest));
            refuses("digest is not given", () -> LabDriverMain.admitted(bound.toString(), null));
        });
        cases.run("host pins / a configuration other than its given digest is refused", () -> {
            Host h = new Host("given", PLAN, "37 65535");
            refuses("differs from its admitted digest", () -> new LabHost(h.config, "00".repeat(32)));
        });
        cases.run("host binding / only the host configuration the bridge configuration binds", () -> {
            Host h = new Host("binding", PLAN, "37 65535");
            LabHost host = h.open();
            Path store = Paths.get("/lab/store");
            LabConfig v1 = LabConfig.parse(LabConfig.encode(INSTALLATION, COMPONENT, "c0".repeat(16), "7a".repeat(32), "aa".repeat(32), store));
            LabConfig other = LabConfig.parse(LabConfig.encode(INSTALLATION, COMPONENT, "c0".repeat(16), "7a".repeat(32), "aa".repeat(32), store,
                    "ee".repeat(32)));
            LabConfig bound = LabConfig.parse(LabConfig.encode(INSTALLATION, COMPONENT, "c0".repeat(16), "7a".repeat(32), "aa".repeat(32), store,
                    h.digest));
            refuses("not the one the bridge configuration binds", () -> host.requireBoundBy(v1));
            refuses("not the one the bridge configuration binds", () -> host.requireBoundBy(other));
            host.requireBoundBy(bound);
            check(bound.host.equals(h.digest) && v1.host == null, "the parsed host digest");
        });

        cases.run("approval / an admitted transaction, within its declared operations only", () -> {
            LabHost host = new Host("approve", PLAN, "37 65535").open();
            Transaction t = transaction(PLAN, CERTIFICATE, KEY, 37, 65535);
            for (int op = 1; op <= 6; op++) check(host.allows(t, op, INSTALLATION, COMPONENT), "operation " + op);
            check(!host.allows(t, 0, INSTALLATION, COMPONENT) && !host.allows(t, 7, INSTALLATION, COMPONENT), "outside the operations");
        });
        cases.run("approval / a plan the configuration does not admit is refused", () -> {
            LabHost host = new Host("other-plan", PLAN, "37 65535").open();
            check(!host.allows(transaction(OTHER_PLAN, CERTIFICATE, KEY, 37, 65535), 1, INSTALLATION, COMPONENT), "another plan");
        });
        cases.run("approval / another role identity is refused", () -> {
            LabHost host = new Host("role", PLAN, "37 65535").open();
            check(!host.allows(transaction(PLAN, "ee".repeat(32), KEY, 37, 65535), 1, INSTALLATION, COMPONENT)
                    && !host.allows(transaction(PLAN, CERTIFICATE, "ee".repeat(32), 37, 65535), 1, INSTALLATION, COMPONENT),
                    "another certificate or key");
        });
        cases.run("approval / another SDK range is refused", () -> {
            LabHost host = new Host("range", PLAN, "37 65535").open();
            check(!host.allows(transaction(PLAN, CERTIFICATE, KEY, 37, 37), 1, INSTALLATION, COMPONENT)
                    && !host.allows(transaction(PLAN, CERTIFICATE, KEY, 36, 65535), 1, INSTALLATION, COMPONENT), "another range");
        });
        cases.run("contradict / the cohort's factory copy differs from T0's in its last digit only", () -> {
            for (String digest : List.of(FACTORY, "a0".repeat(32), "1".repeat(64))) {
                String other = LabDriverMain.otherDigest(digest);
                check(!other.equals(digest) && other.length() == digest.length()
                        && other.substring(0, 63).equals(digest.substring(0, 63)), "one digit changed: " + digest);
            }
        });
        cases.run("approval / another installation or component is refused", () -> {
            LabHost host = new Host("scope", PLAN, "37 65535").open();
            Transaction t = transaction(PLAN, CERTIFICATE, KEY, 37, 65535);
            check(!host.allows(t, 1, "99".repeat(16), COMPONENT) && !host.allows(t, 1, INSTALLATION, "com.example"), "another scope");
        });

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }
}
