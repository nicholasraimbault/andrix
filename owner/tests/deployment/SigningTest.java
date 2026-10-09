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
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
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
 * platform role, and publication of both bundles together through the artifact store. Also the
 * input entry digest, {@link ApkEntries}. The real apksig runs in the sealed comparison. Host JVM
 * only.
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
            VARIANT_INPUT = zip("AndroidManifest.xml", manifest(Fixtures.BUNDLE_VERSION), "classes.dex", "variant code");
            RESTORATION_INPUT = zip("AndroidManifest.xml", manifest(Fixtures.RESTORATION_VERSION), "classes.dex",
                    "known good code");
        } catch (IOException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    // SystemUI's own facts at a versionCode, as the fake parser reads them.
    static String manifest(long versionCode) {
        return FakeEngine.manifest(Fixtures.COMPONENT, versionCode, BundleBuilder.SYSTEMUI_SHARED_USER, true, 37);
    }

    /** One host: a signer, a store and a builder over a fresh directory. */
    static final class Host {
        final Path root;
        final FakeEngine engine;
        final HostSigner signer;
        final ArtifactStore store;
        final BundleBuilder builder;
        final List<Integer> asked = new ArrayList<>();
        /** The operator's inputs by entry digest; a case may replace them. */
        final Map<String, byte[]> inputs = new java.util.HashMap<>();
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
            inputs.put(ApkEntries.digest(VARIANT_INPUT), VARIANT_INPUT);
            inputs.put(ApkEntries.digest(RESTORATION_INPUT), RESTORATION_INPUT);
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

    /**
     * A deployment store and a coordinator with a host's builder as its host and the facade's shell
     * route as its device, the factory chosen, and the pair's plan with its SIGN grant and ticket.
     */
    static final class Run {
        final DeploymentStore store;
        final Coordinator c;
        final Plan pair = plan();
        final Ticket first = Fixtures.ticket(1, pair).build();

        Run(Host h, List<String> problems) throws IOException {
            store = DeploymentStore.unsynced(h.root.resolve("deployment"), Fixtures.INSTALLATION);
            store.initialize();
            AndroidFacade android = new AndroidFacade(7, World.FACTORY);
            android.store = store;
            long[] n = {0};
            c = new Coordinator(store, android.shell(), h.builder, Fixtures.TRUST,
                    () -> String.format("%016x%016x", 0x2a5000000000000L, ++n[0]));
            String none = DeploymentRecords.NO_ID;
            check(problems, store.putSelection(null, new DeploymentRecords.Selection(Fixtures.INSTALLATION,
                    Fixtures.COMPONENT, 0, DeploymentRecords.ChoiceKind.FACTORY, none,
                    DeploymentRecords.UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW,
                    DeploymentRecords.Realization.UNCHECKED, none, none, none, Fixtures.TIME)), "selection");
            check(problems, store.addPlan(pair) && store.addAuthorization(grant(pair, 1, 3)), "plan and SIGN grant");
            check(problems, store.createTicket(first), "ticket");
        }
    }

    // The coordinator with this builder as its host and the facade's shell route as its device,
    // from an approved plan to PUBLISHED, then a repair plan that publishes the restoration.
    static void whole(Path base, List<String> problems) throws Exception {
        Host h = host(base);
        Run run = new Run(h, problems);
        DeploymentStore store = run.store;
        Coordinator c = run.c;
        Plan pair = run.pair;
        Ticket first = run.first;
        // Without a STAGE grant the ticket stays PUBLISHED once its publication reads back.
        Ticket end = settle(c, store, first.ticketId, 40, null);
        check(problems, end.state == State.PUBLISHED && end.flags == 0
                && h.store.planPublication(pair.planId) == Presence.PUBLISHED && h.signer.operations() == 6,
                "the pair's run ended " + end.state + " flags " + end.flags);
        // After SIGNED the builder still reads the publication back, naming the last attempt.
        List<Observation> after = h.builder.query(end, pair, store.authorizationsOf(pair.planId));
        check(problems, after.size() == 1 && after.get(0).classification == Classification.BUNDLE_PUBLISHED
                && after.get(0).subject.equals(end.last(Crossing.PUBLISH).reference), "read after SIGNED " + after);
        // One open ticket for each component: the owner cancels the pair's ticket, whose publication stays.
        check(problems, c.cancel(first.ticketId) && settle(c, store, first.ticketId, 10, null).state == State.CANCELLED
                && h.store.planPublication(pair.planId) == Presence.PUBLISHED, "the pair's ticket not cancelled");
        // The repair plan signs nothing and publishes the restoration that the pair's publication bound.
        Plan restoring = Fixtures.plan(5).repairs(pair.planId).bundle(pair.restorationInput, pair.restorationVersion)
                .restoration(DeploymentRecords.NO_DIGEST, 0).signing(0).signer(pair.signer).build();
        check(problems, store.addPlan(restoring)
                && store.addAuthorization(Fixtures.lab(9, restoring, Effect.STAGE, 0, Fixtures.TIME)), "repair plan");
        Ticket second = Fixtures.ticket(2, restoring).build();
        check(problems, store.createTicket(second), "repair ticket");
        Ticket repaired = settle(c, store, second.ticketId, 40, State.PUBLISHED);
        Publication p = h.store.publication(restoring.planId);
        check(problems, repaired.state == State.PUBLISHED && p != null && p.bundles.size() == 1
                && p.bundles.get(0).equals(h.store.publication(pair.planId).bundles.get(1))
                && h.signer.operations() == 6, "the repair plan's run ended " + repaired.state);
    }

    // The pair's run to PUBLISHED, then damage to its publication: a bundle that reads other bytes,
    // or a record that is gone. The builder's next read names the ticket's last attempt, which read
    // the publication complete, and the ticket holds with the alert. A cancellation still ends it.
    static void later(Path base, List<String> problems) throws Exception {
        for (String damage : List.of("other bytes", "no record")) {
            Host h = host(base);
            Run run = new Run(h, problems);
            Ticket end = settle(run.c, run.store, run.first.ticketId, 40, null);
            check(problems, end.state == State.PUBLISHED && end.flags == 0, damage + ": the run ended " + end.state);
            Path store = h.root.resolve("store");
            if (damage.equals("other bytes")) {
                Path apk = store.resolve("bundles").resolve(h.store.publication(run.pair.planId).bundles.get(0))
                        .resolve("base.apk");
                Files.write(apk, new byte[] {1}, java.nio.file.StandardOpenOption.APPEND);
            } else {
                try (Stream<Path> records = Files.list(store.resolve("publications"))) {
                    for (Path record : records.toList()) Files.delete(record);
                }
            }
            Presence seen = damage.equals("other bytes") ? Presence.MISMATCH : Presence.ABSENT;
            Classification read = damage.equals("other bytes") ? Classification.BUNDLE_MISMATCH
                    : Classification.BUNDLE_ABSENT;
            Ticket held = settle(run.c, run.store, run.first.ticketId, 10, null);
            boolean recorded = run.store.observations().values.stream().anyMatch(o -> o.classification == read
                    && o.subject.equals(end.last(Crossing.PUBLISH).reference));
            check(problems, h.store.planPublication(run.pair.planId) == seen && recorded, damage + ": no later read");
            check(problems, held.state == State.PUBLISHED && held.flag(DeploymentRecords.FLAG_REQUEST_LIMIT),
                    damage + ": the ticket did not hold, flags " + held.flags);
            check(problems, run.c.cancel(run.first.ticketId)
                    && settle(run.c, run.store, run.first.ticketId, 10, null).state == State.CANCELLED,
                    damage + ": the hold has no exit");
        }
    }

    // Rounds until a round changes nothing and issues nothing, or the ticket reaches the state.
    static Ticket settle(Coordinator c, DeploymentStore store, String id, int rounds, State stop) {
        for (int i = 0; i < rounds; i++) {
            Ticket before = store.ticket(id).value;
            Reconciler.Step step = c.round(id);
            if (step.ticket.state == stop || (step.issue == null && step.ticket.equals(before))) return step.ticket;
        }
        return store.ticket(id).value;
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
            List<Observation> read = h.builder.query(ticket(plan, State.SIGNING, sign), plan, List.of(both));
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
            List<Observation> late = g.builder.query(ticket(plan, State.SIGNING, sign), plan, List.of(both));
            check(problems, late.size() == 1 && late.get(0).classification == Classification.SIGN_COMPLETED
                    && stagingDirs(g.root.resolve("store")) == 2 && g.signer.operations() == 6,
                    "resolved from the retained outputs " + late);
        });
        cases.run("signer / a request that can no longer complete records SIGN_FAILED", problems -> {
            Host h = host(base);
            // The SIGN entry was synced, and the call never reached the signer.
            List<Observation> read = h.builder.query(ticket(plan, State.SIGNING, sign), plan, List.of(both));
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
            List<Observation> proof = g.builder.query(ticket(plan, State.SIGNING, sign), plan, List.of(both));
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
            List<Observation> read = h.builder.query(signed, plan, List.of(both));
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
        cases.run("signer / an engine that swallows a refusal still ends REFUSED with nothing kept", problems -> {
            for (int k = 1; k <= 6; k++) {
                Host h = host(base);
                h.engine.swallow = true;
                h.refuse = k;
                Observation fact = h.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
                Transaction t = h.read(TX);
                check(problems, fact != null && fact.classification == Classification.SIGN_REFUSED,
                        k + " reply " + (fact == null ? null : fact.classification));
                check(problems, t != null && t.state == TransactionState.REFUSED && t.refused == k
                        && h.signer.operations() == k - 1, k + " record " + (t == null ? null : t.state));
                // No key use and no question after the refusal, and no output kept.
                check(problems, h.asked.size() == k && retainedFiles(h) == 0, k + " asked " + h.asked);
            }
            Host allowed = host(base);
            allowed.engine.swallow = true;
            Observation fact = allowed.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
            check(problems, fact != null && fact.classification == Classification.SIGN_COMPLETED
                    && allowed.signer.operations() == 6, "every operation allowed " + fact);
        });
        cases.run("builder / a staging error gives no fact, and a later read stages the same outputs", problems -> {
            Host h = host(base);
            Transaction open = h.builder.open(plan, both, TX);
            HostSigner.Reply reply = h.signer.sign(open, Map.of(Role.VARIANT, VARIANT_INPUT, Role.RESTORATION,
                    RESTORATION_INPUT));
            Transaction done = h.read(TX);
            check(problems, reply != null && done != null && done.state == TransactionState.COMPLETED, "signed");
            // A file where the restoration's private copy goes: staging fails with an I/O error.
            Path blocked = h.root.resolve("store").resolve(".staging-"
                    + ArtifactRecords.bundleId(h.builder.manifest(done, Role.RESTORATION)));
            Files.write(blocked, new byte[] {1});
            List<Observation> read = h.builder.query(ticket(plan, State.SIGNING, sign), plan, List.of(both));
            check(problems, read.isEmpty() && h.read(TX).state == TransactionState.COMPLETED,
                    "a staging error gave " + read);
            Observation call = h.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
            check(problems, call == null && h.signer.operations() == 6, "a staging error answered " + call);
            Files.delete(blocked);
            List<Observation> later = h.builder.query(ticket(plan, State.SIGNING, sign), plan, List.of(both));
            check(problems, later.size() == 1 && later.get(0).classification == Classification.SIGN_COMPLETED
                    && stagingDirs(h.root.resolve("store")) == 2 && h.signer.operations() == 6, "later " + later);
        });
        cases.run("builder / an I/O error of the verifier gives no fact, and a later read verifies the same outputs",
                problems -> {
            Host h = host(base);
            Transaction open = h.builder.open(plan, both, TX);
            HostSigner.Reply reply = h.signer.sign(open, Map.of(Role.VARIANT, VARIANT_INPUT, Role.RESTORATION,
                    RESTORATION_INPUT));
            check(problems, reply != null && h.read(TX) != null && h.read(TX).state == TransactionState.COMPLETED,
                    "signed");
            // The verifier cannot write its scratch files: that proves nothing about the outputs.
            h.engine.ioErrors = 1;
            List<Observation> read = h.builder.query(ticket(plan, State.SIGNING, sign), plan, List.of(both));
            check(problems, read.isEmpty() && h.read(TX).state == TransactionState.COMPLETED
                    && stagingDirs(h.root.resolve("store")) == 0, "an I/O error of the verifier gave " + read);
            h.engine.ioErrors = 1;
            Observation call = h.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
            check(problems, call == null && h.signer.operations() == 6, "an I/O error of the verifier answered " + call);
            List<Observation> later = h.builder.query(ticket(plan, State.SIGNING, sign), plan, List.of(both));
            check(problems, later.size() == 1 && later.get(0).classification == Classification.SIGN_COMPLETED
                    && stagingDirs(h.root.resolve("store")) == 2 && h.signer.operations() == 6, "later " + later);
        });
        cases.run("builder / a request without a record is recorded with the role and input of its own grant",
                problems -> {
            Host h = host(base);
            Plan two = plan.toBuilder().signing(2).build();
            Authorization variant = grant(two, 2, DeploymentRecords.INPUT_VARIANT);
            Authorization restoration = grant(two, 3, DeploymentRecords.INPUT_RESTORATION);
            Entry first = signEntry(variant, id(0x7e58));
            Entry second = signEntry(restoration, id(0x7e59));
            Entry unknown = signEntry(grant(two, 4, DeploymentRecords.INPUT_VARIANT), id(0x7e5a));
            // The SIGN entries were synced, and no call reached the signer.
            List<Observation> read = h.builder.query(ticket(two, State.SIGNING, first, second), two,
                    List.of(variant, restoration));
            Transaction a = h.read(id(0x7e58));
            Transaction b = h.read(id(0x7e59));
            check(problems, read.size() == 2 && read.get(0).classification == Classification.SIGN_CANNOT_COMPLETE
                    && read.get(1).classification == Classification.SIGN_CANNOT_COMPLETE, "read " + read);
            check(problems, a != null && a.state == TransactionState.CANNOT_COMPLETE
                    && a.roles().equals(List.of(Role.VARIANT)) && a.authorization.equals(variant.authorizationId)
                    && a.outputs.get(0).inputEntries.equals(two.bundleInput)
                    && a.outputs.get(0).versionCode == two.bundleVersion, "the variant's request");
            check(problems, b != null && b.state == TransactionState.CANNOT_COMPLETE
                    && b.roles().equals(List.of(Role.RESTORATION))
                    && b.authorization.equals(restoration.authorizationId)
                    && b.operations.stream().allMatch(o -> o.role == Role.RESTORATION)
                    && b.outputs.stream().allMatch(o -> o.inputEntries.equals(two.restorationInput)
                            && o.versionCode == two.restorationVersion), "the restoration's request");
            Observation late = h.builder.sign(ticket(two, State.SIGNING, first, second), two, second, restoration);
            check(problems, late != null && late.classification == Classification.SIGN_CANNOT_COMPLETE
                    && h.signer.operations() == 0, "a late call signed: " + h.signer.operations());
            // An entry whose grant is not among the plan's is never recorded.
            List<Observation> none = h.builder.query(ticket(two, State.SIGNING, unknown), two,
                    List.of(variant, restoration));
            check(problems, none.isEmpty() && h.read(id(0x7e5a)) == null, "a request without its grant " + none);
        });
        cases.run("entries / only ASCII letters fold in the names of v1 signature files", problems -> {
            byte[] plain = zip("AndroidManifest.xml", "m", "classes.dex", "c");
            byte[] lower = zip("AndroidManifest.xml", "m", "classes.dex", "c", "META-INF/cert.sf", "s",
                    "META-INF/cert.rsa", "r", "META-INF/manifest.mf", "x");
            check(problems, ApkEntries.digest(plain).equals(ApkEntries.digest(lower)), "ASCII case not folded");
            // Letters outside ASCII that a locale folds to S or I: such a file stays an entry.
            for (String name : List.of("META-INF/a.\u017ff", "META-INF/MAN\u0131FEST.MF", "META-INF/a.\u017fF")) {
                byte[] other = zip("AndroidManifest.xml", "m", "classes.dex", "c", name, "x");
                check(problems, !ApkEntries.digest(plain).equals(ApkEntries.digest(other)), "left out " + name);
            }
        });
        cases.run("entries / a name past the end of the archive is refused as invalid", problems -> {
            byte[] good = zip("AndroidManifest.xml", "m", "classes.dex", "c");
            ByteBuffer eocd = ByteBuffer.wrap(good).order(ByteOrder.LITTLE_ENDIAN);
            int central = eocd.getInt(good.length - 22 + 16);
            // The name, extra field and comment lengths of the first entry, each in turn.
            for (int field : new int[] {28, 30, 32}) {
                byte[] broken = good.clone();
                ByteBuffer.wrap(broken).order(ByteOrder.LITTLE_ENDIAN).putShort(central + field, (short) 0xffff);
                String thrown = "nothing";
                try {
                    ApkEntries.digest(broken);
                } catch (IllegalArgumentException invalid) {
                    thrown = "invalid";
                } catch (RuntimeException other) {
                    thrown = other.getClass().getSimpleName();
                }
                check(problems, thrown.equals("invalid"), "field " + field + ": " + thrown);
            }
            // The builder reads such an input as not the plan's: never signed, and no exception.
            byte[] broken = good.clone();
            ByteBuffer.wrap(broken).order(ByteOrder.LITTLE_ENDIAN).putShort(central + 28, (short) 0xffff);
            Host h = host(base);
            BundleBuilder builder = new BundleBuilder(Fixtures.INSTALLATION, h.signer, h.store, h.engine,
                    new BundleBuilder.RoleIdentity(FakeEngine.certificateDigest(ROLE), FakeEngine.keyDigest(ROLE)), 37,
                    0xffff, entries -> broken, () -> id(0x3d0000 + (++h.ids)), () -> Fixtures.TIME);
            Observation fact = builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
            check(problems, fact != null && fact.classification == Classification.SIGN_CANNOT_COMPLETE
                    && h.signer.operations() == 0, "a broken input " + fact);
        });
        cases.run("signer / an engine that returns its input, or discards its key operations' results, keeps nothing",
                problems -> {
            // Inputs already signed by the same key: their signatures prove nothing about the outputs.
            byte[] signedA = new FakeEngine(ROLE).sign(VARIANT_INPUT, FakeEngine.key(ROLE)).apk;
            byte[] signedR = new FakeEngine(ROLE).sign(RESTORATION_INPUT, FakeEngine.key(ROLE)).apk;
            for (String mode : List.of("returns its input", "discards its results")) {
                Host h = host(base);
                h.inputs.put(plan.bundleInput, signedA);
                h.inputs.put(plan.restorationInput, signedR);
                h.engine.returnInput = mode.equals("returns its input");
                h.engine.forge = mode.equals("discards its results");
                Observation fact = h.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
                Transaction t = h.read(TX);
                check(problems, fact != null && fact.classification == Classification.SIGN_CANNOT_COMPLETE
                        && t != null && t.state == TransactionState.CANNOT_COMPLETE && retainedFiles(h) == 0
                        && stagingDirs(h.root.resolve("store")) == 0, mode + ": " + (t == null ? null : t.state));
            }
            // The same inputs with an engine that signs: the outputs are made again, by the six operations.
            Host good = host(base);
            good.inputs.put(plan.bundleInput, signedA);
            good.inputs.put(plan.restorationInput, signedR);
            Observation fact = good.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
            check(problems, fact != null && fact.classification == Classification.SIGN_COMPLETED
                    && java.util.Arrays.equals(good.signer.retained(TX, Role.VARIANT).apk, signedA)
                    && good.signer.operations() == 6, "signed again from signed inputs " + fact);
            check(problems, ApkEntries.signingBlock(ApkEntries.withoutSigningBlock(signedA)).length == 0
                    && ApkEntries.digest(ApkEntries.withoutSigningBlock(signedA)).equals(plan.bundleInput)
                    && java.util.Arrays.equals(ApkEntries.withoutSigningBlock(VARIANT_INPUT), VARIANT_INPUT),
                    "the signing block stripped");
        });
        cases.run("builder / an input that carries v1 signature files is never signed", problems -> {
            Host h = host(base);
            byte[] withV1 = zip("AndroidManifest.xml", manifest(Fixtures.BUNDLE_VERSION), "classes.dex", "variant code",
                    "META-INF/CERT.SF", "s", "META-INF/CERT.RSA", "r", "META-INF/MANIFEST.MF", "m");
            h.inputs.put(plan.bundleInput, withV1);
            check(problems, ApkEntries.digest(withV1).equals(plan.bundleInput), "the same entries");
            Observation fact = h.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
            check(problems, fact != null && fact.classification == Classification.SIGN_CANNOT_COMPLETE
                    && h.signer.operations() == 0 && h.read(TX).state == TransactionState.CANNOT_COMPLETE,
                    "a v1 input signed " + h.signer.operations());
        });
        cases.run("signer / a fourth key operation for one APK is refused and nothing is kept", problems -> {
            for (boolean swallow : new boolean[] {false, true}) {
                Host h = host(base);
                h.engine.extraOperations = 1;
                h.engine.swallow = swallow;
                Observation fact = h.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
                Transaction t = h.read(TX);
                check(problems, fact != null && fact.classification == Classification.SIGN_CANNOT_COMPLETE
                        && t != null && t.state == TransactionState.CANNOT_COMPLETE && h.signer.operations() == 3
                        && retainedFiles(h) == 0, (swallow ? "swallowed: " : "") + (t == null ? null : t.state) + " "
                        + h.signer.operations());
            }
        });
        cases.run("builder / a signer of any scheme without the platform role is refused", problems -> {
            for (int scheme = 0; scheme < 3; scheme++) {
                Host h = host(base);
                h.engine.schemeCertificates[scheme] = "other";
                Observation fact = h.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
                check(problems, fact != null && fact.classification == Classification.SIGN_CANNOT_COMPLETE
                        && h.read(TX).state == TransactionState.COMPLETED && stagingDirs(h.root.resolve("store")) == 0,
                        "scheme " + scheme + " " + (fact == null ? null : fact.classification));
            }
        });
        cases.run("builder / outputs whose entries are not the input's are refused", problems -> {
            Host h = host(base);
            h.engine.substitute = zip("AndroidManifest.xml", manifest(Fixtures.BUNDLE_VERSION), "classes.dex", "other");
            Observation fact = h.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
            check(problems, fact != null && fact.classification == Classification.SIGN_CANNOT_COMPLETE
                    && stagingDirs(h.root.resolve("store")) == 0, "other entries " + fact);
        });
        cases.run("builder / input bytes that are not the plan's are never signed", problems -> {
            Host h = host(base);
            h.inputs.put(plan.bundleInput, RESTORATION_INPUT);
            Observation fact = h.builder.sign(ticket(plan, State.SIGNING, sign), plan, sign, both);
            check(problems, fact != null && fact.classification == Classification.SIGN_CANNOT_COMPLETE
                    && h.signer.operations() == 0 && h.read(TX).state == TransactionState.CANNOT_COMPLETE,
                    "other bytes signed " + h.signer.operations());
        });
        cases.run("builder / an input whose own facts are not the plan's is never signed", problems -> {
            List<String> bad = List.of(
                    FakeEngine.manifest("com.android.other", Fixtures.BUNDLE_VERSION, BundleBuilder.SYSTEMUI_SHARED_USER,
                            true, 37),
                    FakeEngine.manifest(Fixtures.COMPONENT, Fixtures.BUNDLE_VERSION, "android.uid.system", true, 37),
                    FakeEngine.manifest(Fixtures.COMPONENT, Fixtures.BUNDLE_VERSION, BundleBuilder.SYSTEMUI_SHARED_USER,
                            false, 37),
                    manifest(Fixtures.BUNDLE_VERSION + 1),
                    FakeEngine.manifest(Fixtures.COMPONENT, Fixtures.BUNDLE_VERSION, BundleBuilder.SYSTEMUI_SHARED_USER,
                            true, 36),
                    "no facts");
            for (String words : bad) {
                Host h = host(base);
                byte[] input = zip("AndroidManifest.xml", words, "classes.dex", "variant code");
                Plan other = plan.toBuilder().bundle(ApkEntries.digest(input), plan.bundleVersion).build();
                h.inputs.put(other.bundleInput, input);
                Observation fact = h.builder.sign(ticket(other, State.SIGNING, sign), other, sign, grant(other, 1, 3));
                check(problems, fact != null && fact.classification == Classification.SIGN_CANNOT_COMPLETE
                        && h.signer.operations() == 0, words + " signed " + h.signer.operations());
            }
            Host h = host(base);
            check(problems, h.builder.facts(plan, Role.VARIANT, h.engine.facts(VARIANT_INPUT)) == null
                    && h.builder.facts(plan, Role.RESTORATION, h.engine.facts(RESTORATION_INPUT)) == null,
                    "the plan's own facts refused");
        });
        cases.run("builder / an unreadable retained output gives no fact, and one that is gone reads CANNOT_COMPLETE",
                problems -> {
            Map<Role, byte[]> inputs = Map.of(Role.VARIANT, VARIANT_INPUT, Role.RESTORATION, RESTORATION_INPUT);
            Host h = host(base);
            check(problems, h.signer.sign(h.builder.open(plan, both, TX), inputs) != null, "signed");
            Path output = h.root.resolve("signer/outputs").resolve(TX).resolve("variant").resolve("base.apk");
            java.nio.file.Files.setPosixFilePermissions(output, java.nio.file.attribute.PosixFilePermissions
                    .fromString("---------"));
            List<Observation> read = h.builder.query(ticket(plan, State.SIGNING, sign), plan, List.of(both));
            java.nio.file.Files.setPosixFilePermissions(output, java.nio.file.attribute.PosixFilePermissions
                    .fromString("rw-------"));
            check(problems, read.isEmpty(), "an unreadable output gave " + read);
            List<Observation> later = h.builder.query(ticket(plan, State.SIGNING, sign), plan, List.of(both));
            check(problems, later.size() == 1 && later.get(0).classification == Classification.SIGN_COMPLETED,
                    "later " + later);
            Host g = host(base);
            check(problems, g.signer.sign(g.builder.open(plan, both, TX), inputs) != null, "signed");
            Files.delete(g.root.resolve("signer/outputs").resolve(TX).resolve("variant").resolve("base.apk"));
            List<Observation> gone = g.builder.query(ticket(plan, State.SIGNING, sign), plan, List.of(both));
            check(problems, gone.size() == 1 && gone.get(0).classification == Classification.SIGN_CANNOT_COMPLETE,
                    "a missing output read " + gone);
        });
        cases.run("builder / one whole run publishes a variant and its restoration, then a repair plan the restoration",
                problems -> whole(base, problems));
        cases.run("builder / a later read of the publication, damaged or gone, holds the ticket with the alert",
                problems -> later(base, problems));
        cases.finish("Host signer and bundle builder checks passed");
    }
}
