// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import static dev.andrix.server.deployment.Cases.check;
import static dev.andrix.server.deployment.Fixtures.id;

import dev.andrix.server.deployment.ArtifactRecords.Publication;
import dev.andrix.server.deployment.ArtifactRecords.Role;
import dev.andrix.server.deployment.ArtifactRecords.Transaction;
import dev.andrix.server.deployment.ArtifactRecords.TransactionState;
import dev.andrix.server.deployment.ArtifactStore.Presence;
import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.Classification;
import dev.andrix.server.deployment.DeploymentRecords.Crossing;
import dev.andrix.server.deployment.DeploymentRecords.Effect;
import dev.andrix.server.deployment.DeploymentRecords.Entry;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.State;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Host checks of the host signer and the bundle builder with a fake apksig: one transaction of
 * six key operations under the captive callback, its durable record, lost replies resolved by the
 * transaction ID, the proof that a request can no longer complete, verification against the
 * platform role, and publication of both bundles together through the artifact store. The real
 * apksig runs in the sealed comparison. Host JVM only.
 */
public final class SigningTest {
    private static final Cases cases = new Cases();
    static final String ROLE = "platform";
    static final String TX = id(0x7e57);

    private SigningTest() {}

    /** A process stop in the middle of a transaction, which no handler sees. */
    static final class Stop extends Error {
        private static final long serialVersionUID = 1L;
    }

    static byte[] zip(String... entries) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(bytes)) {
            for (int i = 0; i < entries.length; i += 2) {
                z.putNextEntry(new ZipEntry(entries[i]));
                z.write(entries[i + 1].getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                z.closeEntry();
            }
        }
        return bytes.toByteArray();
    }

    static final byte[] VARIANT_INPUT;
    static final byte[] RESTORATION_INPUT;

    static {
        try {
            VARIANT_INPUT = zip("AndroidManifest.xml", "variant 40", "classes.dex", "variant code");
            RESTORATION_INPUT = zip("AndroidManifest.xml", "restoration 41", "classes.dex", "known good code");
        } catch (IOException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    /** One host: a signer, a store and a builder over a fresh directory. */
    static final class Host {
        final Path root;
        final FakeEngine engine;
        final HostSigner signer;
        final ArtifactStore store;
        final BundleBuilder builder;
        final List<Integer> asked = new ArrayList<>();
        int refuse;
        long ids;

        Host(Path root, String engineCertificate, String keyName, String role, ArtifactStore.Steps steps)
                throws IOException {
            this.root = root;
            engine = new FakeEngine(engineCertificate);
            signer = new HostSigner(root.resolve("signer"), Fixtures.INSTALLATION, engine, FakeEngine.key(keyName),
                    (t, operation) -> {
                        asked.add(operation);
                        if (operation == 1 && read(t.transaction) == null) throw new AssertionError("no record yet");
                        return operation != refuse;
                    });
            signer.initialize();
            store = new ArtifactStore(root.resolve("store"), Fixtures.INSTALLATION, steps, true);
            store.initialize();
            Map<String, byte[]> inputs = Map.of(ApkEntries.digest(VARIANT_INPUT), VARIANT_INPUT,
                    ApkEntries.digest(RESTORATION_INPUT), RESTORATION_INPUT);
            builder = new BundleBuilder(Fixtures.INSTALLATION, signer, store, engine,
                    new BundleBuilder.RoleIdentity(FakeEngine.certificateDigest(role), FakeEngine.keyDigest(role)), 37,
                    0xffff, inputs::get, () -> id(0x3c0000 + (++ids)), () -> Fixtures.TIME);
        }

        Transaction read(String transaction) { return signer.read(transaction); }
    }

    private static int roots;

    static Host host(Path base) throws IOException { return host(base, ROLE, ROLE, ROLE, step -> { }); }

    static Host host(Path base, String engineCertificate, String keyName, String role, ArtifactStore.Steps steps)
            throws IOException {
        Path root = base.resolve("host-" + (++roots));
        Files.createDirectories(root);
        return new Host(root, engineCertificate, keyName, role, steps);
    }

    static Plan plan() {
        return Fixtures.plan(1).bundle(ApkEntries.digest(VARIANT_INPUT), Fixtures.BUNDLE_VERSION)
                .restoration(ApkEntries.digest(RESTORATION_INPUT), Fixtures.RESTORATION_VERSION)
                .signer(FakeEngine.certificateDigest(ROLE)).build();
    }

    static Authorization grant(Plan plan, long n, int inputs) {
        return Fixtures.lab(n, plan, Effect.SIGN, inputs, Fixtures.TIME);
    }

    static Entry signEntry(Authorization grant, String transaction) {
        return new Entry(Crossing.SIGN, DeploymentRecords.NO_ID, -1, 0, grant.authorizationId, transaction, Fixtures.TIME);
    }

    static Entry publishEntry(long n) {
        return new Entry(Crossing.PUBLISH, DeploymentRecords.NO_ID, -1, 0, DeploymentRecords.NO_ID, id(0x9b00 + n),
                Fixtures.TIME);
    }

    static Ticket ticket(Plan plan, State state, Entry... ledger) {
        Ticket.Builder b = Fixtures.ticket(1, plan).state(state);
        for (Entry e : ledger) b.append(e);
        return b.build();
    }

    static long stagingDirs(Path store) throws IOException {
        try (Stream<Path> s = Files.list(store)) {
            return s.filter(p -> p.getFileName().toString().startsWith(".staging-")).count();
        }
    }

    static long retainedFiles(Host h) throws IOException {
        try (Stream<Path> s = Files.walk(h.root.resolve("signer").resolve("outputs"))) {
            return s.filter(Files::isRegularFile).count();
        }
    }

    public static void main(String[] args) throws Exception {
        Cases.requireAssertions(SigningTest.class);
        Path base = Path.of(args[0]);
        Plan plan = plan();
        Authorization both = grant(plan, 1, 3);
        Entry sign = signEntry(both, TX);
        cases.run("signer / the record is written OPEN before the first key operation and names six operations and four outputs",
                problems -> {
            Host h = host(base);
            Observation fact = h.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
            Transaction t = h.read(TX);
            check(problems, fact != null && fact.classification == Classification.SIGN_COMPLETED
                    && fact.subject.equals(TX), "reply " + fact);
            check(problems, t != null && t.state == TransactionState.COMPLETED && t.operations.size() == 6
                    && t.outputs.size() == 4 && t.roles().equals(List.of(Role.VARIANT, Role.RESTORATION))
                    && t.plan.equals(plan.planId) && t.authorization.equals(both.authorizationId),
                    "record " + (t == null ? null : t.state));
            check(problems, h.asked.equals(List.of(1, 2, 3, 4, 5, 6)) && h.signer.operations() == 6,
                    "operations " + h.asked);
            check(problems, t != null && t.outputs.get(0).facts == ArtifactRecords.APK_FACTS
                    && t.outputs.get(1).facts == ArtifactRecords.IDSIG_FACTS
                    && t.outputs.get(0).inputEntries.equals(plan.bundleInput)
                    && t.outputs.get(2).inputEntries.equals(plan.restorationInput), "expected outputs");
            check(problems, t != null && ArtifactRecords.decodeTransaction(ArtifactRecords.encodeTransaction(t)).equals(t),
                    "round trip");
        });
        cases.run("signer / refusing each signing callback in turn publishes nothing", problems -> {
            for (int k = 1; k <= 6; k++) {
                Host h = host(base);
                h.refuse = k;
                Observation fact = h.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
                Transaction t = h.read(TX);
                check(problems, fact != null && fact.classification == Classification.SIGN_REFUSED,
                        k + " reply " + (fact == null ? null : fact.classification));
                check(problems, t != null && t.state == TransactionState.REFUSED && t.refused == k
                        && h.signer.operations() == k - 1, k + " record " + (t == null ? null : t.state));
                check(problems, retainedFiles(h) == 0 && h.signer.retained(TX, Role.VARIANT) == null,
                        k + " a partial output kept");
                Ticket signed = ticket(plan, State.SIGNED, sign, publishEntry(k));
                Observation read = h.builder.publish(signed, plan, signed.last(Crossing.PUBLISH));
                check(problems, read != null && read.classification == Classification.BUNDLE_ABSENT
                        && h.store.planPublication(plan.planId) == Presence.ABSENT
                        && stagingDirs(h.root.resolve("store")) == 0, k + " published " + read);
            }
        });
        cases.run("signer / a lost signing reply resolves by the transaction ID, never by signing again", problems -> {
            Host h = host(base);
            h.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both); // The reply is lost.
            List<Observation> read = h.builder.query(ticket(plan, State.SIGNING, sign), plan);
            check(problems, read.size() == 1 && read.get(0).classification == Classification.SIGN_COMPLETED
                    && read.get(0).subject.equals(TX), "read " + read);
            Observation again = h.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
            check(problems, again != null && again.classification == Classification.SIGN_COMPLETED
                    && h.signer.operations() == 6, "signed again: " + h.signer.operations());
            // Lost after the signer committed but before anything was verified or staged.
            Host g = host(base);
            Map<Role, byte[]> inputs = Map.of(Role.VARIANT, VARIANT_INPUT, Role.RESTORATION, RESTORATION_INPUT);
            Transaction open = g.builder.open(plan, both, TX);
            check(problems, open != null && g.signer.sign(open, inputs) != null && stagingDirs(g.root.resolve("store")) == 0,
                    "signed without staging");
            List<Observation> late = g.builder.query(ticket(plan, State.SIGNING, sign), plan);
            check(problems, late.size() == 1 && late.get(0).classification == Classification.SIGN_COMPLETED
                    && stagingDirs(g.root.resolve("store")) == 2 && g.signer.operations() == 6,
                    "resolved from the retained outputs " + late);
        });
        cases.run("signer / a request that can no longer complete records SIGN_FAILED", problems -> {
            Host h = host(base);
            // The SIGN entry was synced, and the call never reached the signer.
            List<Observation> read = h.builder.query(ticket(plan, State.SIGNING, sign), plan);
            check(problems, read.size() == 1 && read.get(0).classification == Classification.SIGN_CANNOT_COMPLETE
                    && h.read(TX).state == TransactionState.CANNOT_COMPLETE, "read " + read);
            Observation late = h.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
            check(problems, late != null && late.classification == Classification.SIGN_CANNOT_COMPLETE
                    && h.signer.operations() == 0, "a late call signed: " + h.signer.operations());
            Bed bed = new Bed(plan).grants().at(State.SIGNING, Crossing.SIGN);
            bed.ticket = bed.ticket.toBuilder().ledger(List.of(sign)).flags(DeploymentRecords.FLAG_UNRESOLVED).build();
            bed.obs.add(read.get(0));
            check(problems, bed.step().ticket.state == State.SIGN_FAILED, "not SIGN_FAILED");
            // A signer stopped in the middle of a transaction leaves it OPEN with a partial output.
            Host g = host(base);
            HostSigner crashing = new HostSigner(g.root.resolve("signer"), Fixtures.INSTALLATION, g.engine,
                    FakeEngine.key(ROLE), (t, operation) -> {
                        if (operation == 4) throw new Stop();
                        return true;
                    });
            Transaction open = g.builder.open(plan, both, TX);
            boolean stopped = false;
            try {
                crashing.sign(open, Map.of(Role.VARIANT, VARIANT_INPUT, Role.RESTORATION, RESTORATION_INPUT));
            } catch (Stop expected) {
                stopped = true;
            }
            Transaction left = g.read(TX);
            check(problems, stopped && left != null && left.state == TransactionState.OPEN && retainedFiles(g) == 2,
                    "left " + (left == null ? null : left.state));
            List<Observation> proof = g.builder.query(ticket(plan, State.SIGNING, sign), plan);
            check(problems, proof.size() == 1 && proof.get(0).classification == Classification.SIGN_CANNOT_COMPLETE
                    && retainedFiles(g) == 0, "proof " + proof);
        });
        cases.run("builder / every scheme verifies and every signer has the platform role", problems -> {
            Host other = host(base, "other", "other", ROLE, step -> { });
            Observation wrongRole = other.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
            check(problems, wrongRole != null && wrongRole.classification == Classification.SIGN_CANNOT_COMPLETE
                    && stagingDirs(other.root.resolve("store")) == 0, "another role " + wrongRole);
            Host wrongKey = host(base, ROLE, "other", ROLE, step -> { });
            Observation unsigned = wrongKey.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
            check(problems, unsigned != null && unsigned.classification == Classification.SIGN_CANNOT_COMPLETE
                    && stagingDirs(wrongKey.root.resolve("store")) == 0, "a key that is not the certificate's");
            Host v4 = host(base);
            v4.engine.breakV4 = true;
            Observation noV4 = v4.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
            check(problems, noV4 != null && noV4.classification == Classification.SIGN_CANNOT_COMPLETE
                    && stagingDirs(v4.root.resolve("store")) == 0, "a broken v4 sidecar");
            Host good = host(base);
            Observation ok = good.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
            check(problems, ok != null && ok.classification == Classification.SIGN_COMPLETED
                    && stagingDirs(good.root.resolve("store")) == 2, "the platform role refused");
        });
        cases.run("builder / both bundles publish together through the store, or neither", problems -> {
            Host h = host(base);
            h.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
            Ticket none = ticket(plan, State.SIGNED, publishEntry(1));
            Observation unnamed = h.builder.publish(none, plan, none.last(Crossing.PUBLISH));
            check(problems, unnamed.classification == Classification.BUNDLE_ABSENT, "published without its SIGN request");
            Ticket signed = ticket(plan, State.SIGNED, sign, publishEntry(2));
            Observation fact = h.builder.publish(signed, plan, signed.last(Crossing.PUBLISH));
            Publication p = h.store.publication(plan.planId);
            check(problems, fact.classification == Classification.BUNDLE_PUBLISHED && p != null
                    && p.bundles.size() == 2 && p.transactions.equals(List.of(TX, TX))
                    && fact.bundleApk.equals(DeploymentRecords.sha256Hex(h.signer.retained(TX, Role.VARIANT).apk))
                    && fact.restorationApk.equals(DeploymentRecords.sha256Hex(
                            h.signer.retained(TX, Role.RESTORATION).apk)), "publication " + fact);
            for (String step : ArtifactStore.STEPS) {
                Host s = host(base, ROLE, ROLE, ROLE, at -> {
                    if (at.equals(step)) throw new IOException("stopped at " + step);
                });
                s.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
                Observation stopped = s.builder.publish(signed, plan, signed.last(Crossing.PUBLISH));
                Presence presence = s.store.planPublication(plan.planId);
                boolean whole = presence == Presence.PUBLISHED && stopped.classification == Classification.BUNDLE_PUBLISHED;
                boolean nothing = presence == Presence.ABSENT && stopped.classification == Classification.BUNDLE_ABSENT;
                check(problems, whole || nothing, step + " " + presence);
            }
        });
        cases.run("builder / a lost acknowledgement resolves by reading the exact bytes", problems -> {
            Host h = host(base);
            h.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
            Ticket signed = ticket(plan, State.SIGNED, sign, publishEntry(1));
            h.builder.publish(signed, plan, signed.last(Crossing.PUBLISH)); // The acknowledgement is lost.
            byte[] record = Files.readAllBytes(h.root.resolve("store/publications/" + plan.planId + ".rec"));
            List<Observation> read = h.builder.query(signed, plan);
            Observation bundle = read.get(read.size() - 1);
            check(problems, bundle.classification == Classification.BUNDLE_PUBLISHED
                    && bundle.subject.equals(signed.last(Crossing.PUBLISH).reference), "read " + bundle);
            check(problems, java.util.Arrays.equals(record,
                    Files.readAllBytes(h.root.resolve("store/publications/" + plan.planId + ".rec")))
                    && h.signer.operations() == 6, "written or signed again");
        });
        cases.run("builder / a second publication completes from the held bundles without signing again", problems -> {
            Path root = base.resolve("host-" + (++roots));
            Files.createDirectories(root);
            Host first = new Host(root, ROLE, ROLE, ROLE, at -> {
                if (at.equals("bundles-synced")) throw new IOException("stopped");
            });
            first.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
            Ticket once = ticket(plan, State.SIGNED, sign, publishEntry(1));
            Observation absent = first.builder.publish(once, plan, once.last(Crossing.PUBLISH));
            check(problems, absent.classification == Classification.BUNDLE_ABSENT, "first " + absent);
            Host second = new Host(root, ROLE, ROLE, ROLE, at -> { });
            Ticket twice = ticket(plan, State.SIGNED, sign, publishEntry(1), publishEntry(2));
            Observation published = second.builder.publish(twice, plan, twice.last(Crossing.PUBLISH));
            check(problems, published.classification == Classification.BUNDLE_PUBLISHED
                    && first.signer.operations() + second.signer.operations() == 6, "second " + published);
        });
        cases.run("builder / a pair from two signing transactions publishes together", problems -> {
            Host h = host(base);
            Plan two = plan.toBuilder().signing(2).build();
            Authorization variant = grant(two, 2, DeploymentRecords.INPUT_VARIANT);
            Authorization restoration = grant(two, 3, DeploymentRecords.INPUT_RESTORATION);
            Entry first = signEntry(variant, id(0x7e58));
            Entry second = signEntry(restoration, id(0x7e59));
            Observation a = h.builder.sign(ticket(two, State.SIGNING, first), two, first, variant);
            Observation b = h.builder.sign(ticket(two, State.SIGNING, first, second), two, second, restoration);
            check(problems, a.classification == Classification.SIGN_COMPLETED
                    && b.classification == Classification.SIGN_COMPLETED && h.read(id(0x7e58)).operations.size() == 3
                    && h.read(id(0x7e59)).operations.size() == 3 && h.signer.operations() == 6, "two transactions");
            Ticket signed = ticket(two, State.SIGNED, first, second, publishEntry(1));
            Observation fact = h.builder.publish(signed, two, signed.last(Crossing.PUBLISH));
            Publication p = h.store.publication(two.planId);
            check(problems, fact.classification == Classification.BUNDLE_PUBLISHED && p != null
                    && p.transactions.equals(List.of(id(0x7e58), id(0x7e59))), "pair " + fact);
        });
        cases.run("builder / a restoration plan publishes the already published restoration", problems -> {
            Host h = host(base);
            Plan restoring = Fixtures.plan(5).repairs(plan.planId).bundle(plan.restorationInput, plan.restorationVersion)
                    .restoration(DeploymentRecords.NO_DIGEST, 0).signing(0).signer(plan.signer)
                    .base(Fixtures.BUNDLE_APK, Fixtures.BUNDLE_VERSION, Fixtures.UID, Fixtures.CONTEXT)
                    .selectionRevision(1).build();
            Ticket early = Fixtures.ticket(2, restoring).state(State.SIGNED).append(publishEntry(1)).build();
            Observation before = h.builder.publish(early, restoring, early.last(Crossing.PUBLISH));
            check(problems, before.classification == Classification.BUNDLE_ABSENT, "published before its pair");
            h.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
            Ticket signed = ticket(plan, State.SIGNED, sign, publishEntry(2));
            h.builder.publish(signed, plan, signed.last(Crossing.PUBLISH));
            Ticket later = Fixtures.ticket(2, restoring).state(State.SIGNED).append(publishEntry(3)).build();
            Observation fact = h.builder.publish(later, restoring, later.last(Crossing.PUBLISH));
            Publication p = h.store.publication(restoring.planId);
            check(problems, fact.classification == Classification.BUNDLE_PUBLISHED && p != null
                    && p.bundles.size() == 1 && p.transactions.equals(List.of(TX)) && fact.plan.equals(restoring.planId)
                    && fact.bundleApk.equals(DeploymentRecords.sha256Hex(h.signer.retained(TX, Role.RESTORATION).apk))
                    && fact.restorationApk.equals(DeploymentRecords.NO_DIGEST) && h.signer.operations() == 6,
                    "restoration " + fact);
        });
        cases.finish("Host signer and bundle builder checks passed");
    }
}
