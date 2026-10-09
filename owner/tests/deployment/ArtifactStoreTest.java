// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import static dev.andrix.server.deployment.Cases.check;
import static dev.andrix.server.deployment.Fixtures.INSTALLATION;
import static dev.andrix.server.deployment.Fixtures.TIME;

import dev.andrix.server.deployment.ArtifactRecords.Manifest;
import dev.andrix.server.deployment.ArtifactRecords.Member;
import dev.andrix.server.deployment.ArtifactRecords.Operation;
import dev.andrix.server.deployment.ArtifactRecords.Output;
import dev.andrix.server.deployment.ArtifactRecords.Publication;
import dev.andrix.server.deployment.ArtifactRecords.Role;
import dev.andrix.server.deployment.ArtifactRecords.Scheme;
import dev.andrix.server.deployment.ArtifactRecords.Transaction;
import dev.andrix.server.deployment.ArtifactRecords.TransactionState;
import dev.andrix.server.deployment.ArtifactRecords.V4Check;
import dev.andrix.server.deployment.ArtifactStore.Presence;
import dev.andrix.server.deployment.ArtifactStore.Staged;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

/**
 * The artifact store and its records: goldens of the manifest and the publication, strict codes,
 * the stable prefix, mutation of every byte, and publication that is visible only when complete,
 * verified first, pairs a variant with its restoration, survives a stop at every step, and
 * resolves a lost acknowledgement by reading the exact bytes. Every store here syncs. Host JVM
 * only.
 */
public final class ArtifactStoreTest {
    // Pinned by the runner against its independent encoder.
    private static final int GOLDEN_MANIFEST_VARIANT_BYTES = 321;
    private static final String GOLDEN_MANIFEST_VARIANT_SHA256 = "54ee87992b779d59aedbeb6ced96cdab977167a4f8613af84403e8b462000a74";
    private static final int GOLDEN_MANIFEST_RESTORATION_BYTES = 321;
    private static final String GOLDEN_MANIFEST_RESTORATION_SHA256 = "5a13a6b299d322c2faf35ceb4d787f3344c6e1dff20b467fdd438a27e8cfd1d0";
    private static final int GOLDEN_PUBLICATION_PAIR_BYTES = 205;
    private static final String GOLDEN_PUBLICATION_PAIR_SHA256 = "1436d9786033a39b5d486a771be40c6d2d9c85bd736ee1526898de3f2087282f";
    private static final int GOLDEN_PUBLICATION_ONE_BYTES = 156;
    private static final String GOLDEN_PUBLICATION_ONE_SHA256 = "cb1811d26a22c4849d4d45ad360a9e66ad1f5ed0259a5bace9bd76c081e31524";
    private static final int GOLDEN_TRANSACTION_OPEN_BYTES = 770;
    private static final String GOLDEN_TRANSACTION_OPEN_SHA256 = "b6418e2fc715b7d8f2753845ac5ac7ec87f026d4f95227c1a32885cc80b173c4";
    private static final int GOLDEN_TRANSACTION_COMPLETED_BYTES = 770;
    private static final String GOLDEN_TRANSACTION_COMPLETED_SHA256 = "6d33ee095a3a930ff7d123448e6409d6522b7844da0f34fe381139cd0353c485";

    private static final Cases cases = new Cases();
    private static final String REQUEST = Fixtures.id(0x5e);
    private static final String CERT = Fixtures.digest(0xc1);
    private static final String KEY = Fixtures.digest(0xc2);

    private ArtifactStoreTest() {}

    public static void main(String[] args) throws Exception {
        Cases.requireAssertions(ArtifactStoreTest.class);
        Path out = Path.of(args[0]);
        Files.createDirectories(out.resolve("goldens"));
        recordCases(out.resolve("goldens"));
        storeCases(out.resolve("stores"));
        cases.finish("artifact store and records");
    }

    // ------------------------------------------------------------------ fixtures

    static byte[] apk(int n) { return ("signed apk " + n + " ").repeat(50 + n).getBytes(StandardCharsets.US_ASCII); }

    static byte[] idsig(int n) { return ("v4 sidecar " + n).getBytes(StandardCharsets.US_ASCII); }

    static Manifest manifest(Role role, int n, String transaction) {
        byte[] apk = apk(n);
        byte[] idsig = idsig(n);
        return new Manifest(INSTALLATION, Fixtures.COMPONENT, role, transaction, Fixtures.digest(0x30 + n),
                Fixtures.digest(0x40 + n), role == Role.VARIANT ? Fixtures.BUNDLE_VERSION : Fixtures.RESTORATION_VERSION,
                DeploymentRecords.sha256Hex(apk), apk.length, DeploymentRecords.sha256Hex(idsig), idsig.length, CERT,
                KEY, ArtifactRecords.SCHEMES, 37, 37, V4Check.VERIFIED);
    }

    static Manifest variant() { return manifest(Role.VARIANT, 1, REQUEST); }

    static Manifest restoration() { return manifest(Role.RESTORATION, 2, REQUEST); }

    static String variantId() { return ArtifactRecords.bundleId(variant()); }

    static String restorationId() { return ArtifactRecords.bundleId(restoration()); }

    // The plan names the signing inputs by their entry digests and the signer certificate, never
    // the bundles signed from them or their APK digests.
    static Plan plan(boolean withRestoration) {
        Plan.Builder b = Fixtures.plan(1).bundle(variant().inputEntries, Fixtures.BUNDLE_VERSION).signer(CERT);
        if (withRestoration) {
            b.restoration(restoration().inputEntries, Fixtures.RESTORATION_VERSION);
        } else {
            b.restoration(DeploymentRecords.NO_DIGEST, 0);
        }
        return b.build();
    }

    // Decision 3's restoration plan: it installs the variant plan's restoration bundle and signs nothing.
    static Plan restorationPlan(Plan variant) {
        return Fixtures.plan(5).repairs(variant.planId).bundle(variant.restorationInput, variant.restorationVersion)
                .restoration(DeploymentRecords.NO_DIGEST, 0).signing(0).signer(CERT)
                .base(Fixtures.digest(0xa1), Fixtures.BUNDLE_VERSION, Fixtures.UID, Fixtures.CONTEXT)
                .selectionRevision(1).build();
    }

    static Publication publication(Plan plan) {
        List<String> ids = new ArrayList<>(List.of(variantId()));
        List<String> transactions = new ArrayList<>(List.of(REQUEST));
        if (plan.hasRestoration()) {
            ids.add(restorationId());
            transactions.add(REQUEST);
        }
        return new Publication(INSTALLATION, plan.planId, plan.component, ids, transactions, TIME + 9);
    }

    // The host signer's record of the pair's transaction, before its first key operation.
    static Transaction transactionOpen() {
        List<Operation> operations = new ArrayList<>();
        int n = 0;
        for (Role r : List.of(Role.VARIANT, Role.RESTORATION)) {
            for (Scheme scheme : Scheme.values()) operations.add(new Operation(Fixtures.id(0x6f1 + n++), r, scheme));
        }
        List<Output> outputs = new ArrayList<>();
        for (Role r : List.of(Role.VARIANT, Role.RESTORATION)) {
            int k = r == Role.VARIANT ? 1 : 2;
            long version = r == Role.VARIANT ? Fixtures.BUNDLE_VERSION : Fixtures.RESTORATION_VERSION;
            outputs.add(new Output(r, Member.APK, ArtifactRecords.APK_FACTS, Fixtures.digest(0x30 + k),
                    Fixtures.digest(0x40 + k), version, DeploymentRecords.NO_DIGEST, 0));
            outputs.add(new Output(r, Member.IDSIG, ArtifactRecords.IDSIG_FACTS, Fixtures.digest(0x30 + k),
                    Fixtures.digest(0x40 + k), version, DeploymentRecords.NO_DIGEST, 0));
        }
        return new Transaction(INSTALLATION, REQUEST, Fixtures.COMPONENT, Fixtures.id(0x101), Fixtures.id(0x201), CERT,
                KEY, 37, 0xffff, TransactionState.OPEN, 0, operations, outputs);
    }

    // The same transaction once its four outputs are retained: the members of both bundles.
    static Transaction transactionCompleted() {
        Transaction open = transactionOpen();
        List<Output> produced = new ArrayList<>();
        for (Output o : open.outputs) {
            int k = o.role == Role.VARIANT ? 1 : 2;
            byte[] bytes = o.member == Member.APK ? apk(k) : idsig(k);
            produced.add(o.produced(DeploymentRecords.sha256Hex(bytes), bytes.length));
        }
        return open.with(TransactionState.COMPLETED, 0, produced);
    }

    // ------------------------------------------------------------------ records

    private static void golden(Path dir, List<String> problems, String name, byte[] bytes, int length, String sha)
            throws IOException {
        Files.write(dir.resolve(name + ".bin"), bytes);
        check(problems, bytes.length == length && DeploymentRecords.sha256Hex(bytes).equals(sha),
                name + " is " + bytes.length + " bytes " + DeploymentRecords.sha256Hex(bytes));
    }

    private static void recordCases(Path dir) {
        cases.run("records / goldens of both manifests and both publications", problems -> {
            golden(dir, problems, "MANIFEST_VARIANT", ArtifactRecords.encodeManifest(variant()),
                    GOLDEN_MANIFEST_VARIANT_BYTES, GOLDEN_MANIFEST_VARIANT_SHA256);
            golden(dir, problems, "MANIFEST_RESTORATION", ArtifactRecords.encodeManifest(restoration()),
                    GOLDEN_MANIFEST_RESTORATION_BYTES, GOLDEN_MANIFEST_RESTORATION_SHA256);
            golden(dir, problems, "PUBLICATION_PAIR", ArtifactRecords.encodePublication(publication(plan(true))),
                    GOLDEN_PUBLICATION_PAIR_BYTES, GOLDEN_PUBLICATION_PAIR_SHA256);
            golden(dir, problems, "PUBLICATION_ONE", ArtifactRecords.encodePublication(publication(plan(false))),
                    GOLDEN_PUBLICATION_ONE_BYTES, GOLDEN_PUBLICATION_ONE_SHA256);
            for (Manifest m : List.of(variant(), restoration())) {
                check(problems, ArtifactRecords.decodeManifest(ArtifactRecords.encodeManifest(m)).equals(m), "manifest");
            }
            Publication p = publication(plan(true));
            check(problems, ArtifactRecords.decodePublication(ArtifactRecords.encodePublication(p)).equals(p), "pair");
        });
        // The signing transaction: state at 166, refused at 167 and the operation count at 168.
        cases.run("records / the signing transaction record keeps its goldens, strict codes, relations and prefix",
                problems -> {
            byte[] open = ArtifactRecords.encodeTransaction(transactionOpen());
            byte[] done = ArtifactRecords.encodeTransaction(transactionCompleted());
            golden(dir, problems, "TRANSACTION_OPEN", open, GOLDEN_TRANSACTION_OPEN_BYTES, GOLDEN_TRANSACTION_OPEN_SHA256);
            golden(dir, problems, "TRANSACTION_COMPLETED", done, GOLDEN_TRANSACTION_COMPLETED_BYTES,
                    GOLDEN_TRANSACTION_COMPLETED_SHA256);
            check(problems, ArtifactRecords.decodeTransaction(open).equals(transactionOpen())
                    && ArtifactRecords.decodeTransaction(done).equals(transactionCompleted()), "round trip");
            for (int[] change : new int[][] {{166, 0}, {166, 5}, {166, 2}, {167, 1}, {168, 4}, {168, 9}, {169 + 16 + 1, 4},
                {169 + 16, 3}}) {
                byte[] bad = resealed(open, change[0], change[1]);
                check(problems, refusedTransaction(bad), "byte " + change[0] + " = " + change[1] + " accepted");
            }
            Transaction t = transactionOpen();
            List<Operation> twice = new ArrayList<>(t.operations);
            twice.set(1, twice.get(0));
            check(problems, refusedValue(() -> new Transaction(INSTALLATION, REQUEST, Fixtures.COMPONENT, t.plan,
                    t.authorization, CERT, KEY, 37, 0xffff, TransactionState.OPEN, 0, twice, t.outputs)),
                    "an operation twice");
            check(problems, refusedValue(() -> t.with(TransactionState.COMPLETED, 0, t.outputs)),
                    "COMPLETED without outputs");
            check(problems, refusedValue(() -> transactionCompleted().with(TransactionState.OPEN, 0,
                    transactionCompleted().outputs)), "OPEN with outputs");
            check(problems, refusedValue(() -> t.with(TransactionState.REFUSED, 0, t.outputs)), "REFUSED without its operation");
            check(problems, refusedValue(() -> t.with(TransactionState.REFUSED, 7, t.outputs)), "a refused operation beyond six");
            check(problems, refusedValue(() -> new Output(Role.VARIANT, Member.APK, ArtifactRecords.IDSIG_FACTS,
                    Fixtures.digest(1), Fixtures.digest(2), 40, DeploymentRecords.NO_DIGEST, 0)), "another member's facts");
            List<Output> swapped = new ArrayList<>(t.outputs);
            swapped.set(0, t.outputs.get(1));
            swapped.set(1, t.outputs.get(0));
            check(problems, refusedValue(() -> new Transaction(INSTALLATION, REQUEST, Fixtures.COMPONENT, t.plan,
                    t.authorization, CERT, KEY, 37, 0xffff, TransactionState.OPEN, 0, t.operations, swapped)),
                    "outputs out of order");
            check(problems, refusedValue(() -> new Transaction(INSTALLATION, REQUEST, Fixtures.COMPONENT, t.plan,
                    t.authorization, CERT, KEY, 37, 0xffff, TransactionState.OPEN, 0, t.operations.subList(0, 5),
                    t.outputs)), "five operations");
            byte[] later = resealed(open, 6, 2);
            ArtifactRecords.Prefix prefix = ArtifactRecords.decodePrefix(later);
            check(problems, refusedTransaction(later) && prefix.type == ArtifactRecords.TRANSACTION
                    && prefix.id.equals(REQUEST) && prefix.component.equals(Fixtures.COMPONENT), "prefix");
        });
        cases.run("records / strict codes, relations and trailing bytes are refused", problems -> {
            byte[] m = ArtifactRecords.encodeManifest(variant());
            int role = 12 + 16 + 2 + Fixtures.COMPONENT.length();
            int schemes = role + 1 + 16 + 32 + 32 + 8 + 32 + 8 + 32 + 8 + 32 + 32;
            for (int[] change : new int[][] {{role, 0}, {role, 3}, {schemes, 3}, {schemes, 15}, {schemes + 5, 2},
                    {schemes + 5, 0}}) {
                check(problems, refusedManifest(resealed(m, change[0], change[1])), "manifest byte " + change[0]);
            }
            check(problems, refusedManifest(reseal(Arrays.copyOf(m, m.length + 1))), "manifest trailing byte");
            byte[] p = ArtifactRecords.encodePublication(publication(plan(true)));
            int count = 12 + 16 + 16 + 2 + Fixtures.COMPONENT.length();
            for (int[] change : new int[][] {{count, 0}, {count, 3}, {count + 33, 2}, {count + 82, 1}}) {
                check(problems, refusedPublication(resealed(p, change[0], change[1])), "publication byte " + change[0]);
            }
            check(problems, refusedPublication(resealed(m, 4, 7)), "a manifest read as a publication");
            check(problems, refusedManifest(resealed(m, 6, 2)), "version 2 read as version 1");
            boolean twice = false;
            try {
                new Publication(INSTALLATION, Fixtures.id(1), Fixtures.COMPONENT,
                        List.of(Fixtures.digest(1), Fixtures.digest(1)), List.of(REQUEST, REQUEST), 0);
            } catch (IllegalArgumentException expected) {
                twice = true;
            }
            check(problems, twice, "a bundle named twice");
            byte[] zero = p.clone();
            Arrays.fill(zero, count + 34, count + 50, (byte) 0);
            check(problems, refusedPublication(reseal(zero)), "a zero signing transaction");
            boolean unpaired = false;
            try {
                new Publication(INSTALLATION, Fixtures.id(1), Fixtures.COMPONENT, List.of(Fixtures.digest(1)),
                        List.of(REQUEST, REQUEST), 0);
            } catch (IllegalArgumentException expected) {
                unpaired = true;
            }
            check(problems, unpaired, "a transaction without its bundle");
        });
        cases.run("records / informational times decide nothing and the prefix reads a later version", problems -> {
            for (long t : new long[] {Long.MIN_VALUE, -1, 0, Long.MAX_VALUE}) {
                Publication p = publication(plan(true));
                Publication other = new Publication(p.installation, p.plan, p.component, p.bundles, p.transactions, t);
                check(problems, ArtifactRecords.decodePublication(ArtifactRecords.encodePublication(other))
                        .publishedAt == t, "time " + t);
            }
            byte[] later = resealed(ArtifactRecords.encodeManifest(variant()), 6, 2);
            ArtifactRecords.Prefix prefix = ArtifactRecords.decodePrefix(later);
            check(problems, prefix.type == ArtifactRecords.MANIFEST && prefix.version == 2
                    && prefix.installation.equals(INSTALLATION) && prefix.component.equals(Fixtures.COMPONENT)
                    && prefix.id.equals(REQUEST), "manifest prefix");
            byte[] laterPublication = resealed(ArtifactRecords.encodePublication(publication(plan(true))), 6, 2);
            ArtifactRecords.Prefix p = ArtifactRecords.decodePrefix(laterPublication);
            check(problems, p.type == ArtifactRecords.PUBLICATION && p.id.equals(plan(true).planId)
                    && p.component.equals(Fixtures.COMPONENT), "publication prefix");
            boolean refused = false;
            try {
                ArtifactRecords.decodePrefix(ArtifactRecords.encodeManifest(variant()));
            } catch (IllegalArgumentException expected) {
                refused = true;
            }
            check(problems, refused, "a version 1 record read by prefix");
        });
        cases.run("records / every single byte change is refused or canonical", problems -> {
            List<byte[]> records = List.of(ArtifactRecords.encodeManifest(variant()),
                    ArtifactRecords.encodePublication(publication(plan(true))),
                    ArtifactRecords.encodePublication(publication(plan(false))));
            for (byte[] record : records) {
                for (int i = 0; i < record.length - 32; i++) {
                    for (int delta : new int[] {1, 0x80, 0xff}) {
                        byte[] changed = resealed(record, i, (record[i] + delta) & 0xff);
                        boolean manifest = record[4] == ArtifactRecords.MANIFEST;
                        try {
                            byte[] again = manifest
                                    ? ArtifactRecords.encodeManifest(ArtifactRecords.decodeManifest(changed))
                                    : ArtifactRecords.encodePublication(ArtifactRecords.decodePublication(changed));
                            check(problems, Arrays.equals(again, changed), "byte " + i + " not canonical");
                        } catch (IllegalArgumentException refusedChange) {
                            // Refused.
                        }
                    }
                }
                byte[] torn = record.clone();
                torn[torn.length - 1] ^= 1;
                check(problems, ArtifactRecords.intactFrame(torn) == null, "a checksum change accepted");
            }
        });
        cases.run("records / the same bytes keep one bundle ID, and the output may equal its input", problems -> {
            check(problems, variantId().equals(ArtifactRecords.bundleId(manifest(Role.VARIANT, 1, REQUEST))),
                    "a manifest built again has another ID");
            check(problems, !variantId().equals(ArtifactRecords.bundleId(manifest(Role.VARIANT, 1, Fixtures.id(0x5f)))),
                    "the signing transaction outside the ID");
            Manifest m = variant();
            Manifest reproduced = new Manifest(m.installation, m.component, m.role, m.transaction, m.apk,
                    m.inputEntries, m.versionCode, m.apk, m.apkBytes, m.idsig, m.idsigBytes, m.certificate, m.key,
                    m.schemes, m.sdkMin, m.sdkMax, m.v4);
            check(problems, ArtifactRecords.decodeManifest(ArtifactRecords.encodeManifest(reproduced))
                    .equals(reproduced), "signing that reproduced its input exactly refused");
        });
    }

    private static byte[] resealed(byte[] record, int at, int value) {
        byte[] copy = record.clone();
        copy[at] = (byte) value;
        return reseal(copy);
    }

    // A frame with its length and checksum set again over the changed bytes.
    static byte[] reseal(byte[] record) {
        byte[] copy = record.clone();
        int length = copy.length;
        for (int i = 0; i < 4; i++) copy[8 + i] = (byte) (length >>> (8 * i));
        byte[] sum = DeploymentRecords.sha256(copy, length - 32);
        System.arraycopy(sum, 0, copy, length - 32, 32);
        return copy;
    }

    private static boolean refusedManifest(byte[] record) {
        try {
            ArtifactRecords.decodeManifest(record);
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }

    private static boolean refusedTransaction(byte[] record) {
        try {
            ArtifactRecords.decodeTransaction(record);
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }

    private static boolean refusedValue(Runnable build) {
        try {
            build.run();
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }

    private static boolean refusedPlan(Runnable build) {
        try {
            build.run();
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }

    private static boolean refusedPublication(byte[] record) {
        try {
            ArtifactRecords.decodePublication(record);
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }

    // ------------------------------------------------------------------ the store

    private static int stores;

    private static Path fresh(Path base) throws IOException {
        Path root = base.resolve("store-" + (++stores));
        Files.createDirectories(base);
        return root;
    }

    private static ArtifactStore store(Path root, ArtifactStore.Steps steps) throws IOException {
        ArtifactStore s = new ArtifactStore(root, INSTALLATION, steps, true);
        s.initialize();
        return s;
    }

    private static List<Staged> stageBoth(ArtifactStore s) {
        List<Staged> list = new ArrayList<>();
        list.add(s.stage(variant(), apk(1), idsig(1)));
        list.add(s.stage(restoration(), apk(2), idsig(2)));
        return list;
    }

    private static final ArtifactStore.Verifier PASS = b -> null;

    private static List<Presence> both(ArtifactStore s, Plan plan) {
        return List.of(s.presence(variantId()), s.presence(restorationId()));
    }

    private static final List<Presence> PUBLISHED = List.of(Presence.PUBLISHED, Presence.PUBLISHED);
    private static final List<Presence> ABSENT = List.of(Presence.ABSENT, Presence.ABSENT);

    private static final class Stop extends IOException {
        private static final long serialVersionUID = 1L;
    }

    private static long bundleDirs(Path root) throws IOException {
        try (Stream<Path> s = Files.list(root.resolve("bundles"))) {
            return s.count();
        }
    }

    private static void storeCases(Path base) {
        cases.run("store / the pair is staged, published together and read back exactly", problems -> {
            Path root = fresh(base);
            ArtifactStore s = store(root, step -> { });
            Plan plan = plan(true);
            List<Staged> staged = stageBoth(s);
            check(problems, staged.get(0) != null && staged.get(1) != null, "staged");
            check(problems, staged.get(0).id.equals(variantId()) && staged.get(1).id.equals(restorationId()),
                    "bundle IDs are the manifest digests");
            check(problems, both(s, plan).equals(ABSENT), "staging is invisible " + both(s, plan));
            check(problems, s.publish(plan, publication(plan), staged, PASS), "published");
            check(problems, both(s, plan).equals(PUBLISHED), "both published " + both(s, plan));
            check(problems, Arrays.equals(s.members(variantId()).get(0), apk(1))
                    && Arrays.equals(s.members(restorationId()).get(1), idsig(2)), "exact members");
            check(problems, s.publication(plan.planId).equals(publication(plan)), "publication read back");
            Plan alone = plan(false);
            ArtifactStore single = store(fresh(base), step -> { });
            List<Staged> one = List.of(single.stage(variant(), apk(1), idsig(1)));
            check(problems, single.publish(alone, publication(alone), one, PASS)
                    && single.presence(variantId()) == Presence.PUBLISHED, "a plan without a restoration");
        });
        cases.run("store / a stop at every step leaves both bundles visible or neither", problems -> {
            Plan plan = plan(true);
            int points = 0;
            for (int k = 0; ; k++) {
                Path root = fresh(base);
                int[] seen = {0};
                final int stopAt = k;
                ArtifactStore s = store(root, step -> {
                    if (seen[0]++ == stopAt) throw new Stop();
                });
                List<Staged> staged = stageBoth(s);
                boolean done = s.publish(plan, publication(plan), staged, PASS);
                if (done) {
                    points = k;
                    check(problems, both(s, plan).equals(PUBLISHED), "completed " + both(s, plan));
                    break;
                }
                List<Presence> after = both(s, plan);
                check(problems, after.equals(ABSENT) || after.equals(PUBLISHED), "after a stop at " + k + " " + after);
                // A new store on the same root resumes: read first, publish only what nothing shows.
                ArtifactStore resumed = store(root, step -> { });
                if (after.equals(ABSENT)) {
                    List<Staged> again = stageBoth(resumed);
                    check(problems, resumed.publish(plan, publication(plan), again, PASS), "resumed at " + k);
                } else {
                    check(problems, resumed.publish(plan, publication(plan), staged, PASS), "read back at " + k);
                }
                check(problems, both(resumed, plan).equals(PUBLISHED), "resumed " + k + " " + both(resumed, plan));
            }
            check(problems, points == ArtifactStore.STEPS.size() + 1, "points " + points);
        });
        cases.run("store / refusing either bundle's verification publishes nothing", problems -> {
            Plan plan = plan(true);
            for (int refuse = 0; refuse < 2; refuse++) {
                Path root = fresh(base);
                ArtifactStore s = store(root, step -> { });
                List<Staged> staged = stageBoth(s);
                final String refused = staged.get(refuse).id;
                check(problems, !s.publish(plan, publication(plan), staged, b -> b.id.equals(refused) ? "wrong" : null),
                        "published with bundle " + refuse + " refused");
                check(problems, both(s, plan).equals(ABSENT) && bundleDirs(root) == 0 && s.publication(plan.planId) == null,
                        "visible after refusing " + refuse);
            }
        });
        cases.run("store / every bundle is verified before anything is renamed", problems -> {
            Plan plan = plan(true);
            Path root = fresh(base);
            ArtifactStore s = store(root, step -> { });
            List<Staged> staged = stageBoth(s);
            List<String> verified = new ArrayList<>();
            boolean ok = s.publish(plan, publication(plan), staged, b -> {
                try {
                    if (bundleDirs(root) != 0 || !both(s, plan).equals(ABSENT)) return "something visible";
                } catch (IOException e) {
                    return "unreadable";
                }
                verified.add(b.id);
                return null;
            });
            check(problems, ok && verified.equals(List.of(variantId(), restorationId())), "verified " + verified);
        });
        cases.run("store / a bundle is never published alone", problems -> {
            Plan plan = plan(true);
            Path root = fresh(base);
            ArtifactStore s = store(root, step -> { });
            List<Staged> staged = stageBoth(s);
            Publication alone = new Publication(INSTALLATION, plan.planId, plan.component, List.of(variantId()),
                    List.of(REQUEST), TIME);
            check(problems, !s.publish(plan, alone, staged.subList(0, 1), PASS), "the variant alone");
            Publication swapped = new Publication(INSTALLATION, plan.planId, plan.component,
                    List.of(restorationId(), variantId()), List.of(REQUEST, REQUEST), TIME);
            check(problems, !s.publish(plan, swapped, List.of(staged.get(1), staged.get(0)), PASS), "roles swapped");
            check(problems, !s.publish(plan, publication(plan), staged.subList(0, 1), PASS), "one staged bundle");
            Staged otherRequest = s.stage(manifest(Role.RESTORATION, 2, Fixtures.id(0x5f)), apk(2), idsig(2));
            check(problems, !s.publish(plan, publication(plan), List.of(staged.get(0), otherRequest), PASS),
                    "a restoration the publication does not name");
            check(problems, both(s, plan).equals(ABSENT) && bundleDirs(root) == 0, "visible " + both(s, plan));
        });
        cases.run("store / a lost acknowledgement resolves by reading the exact bytes", problems -> {
            Plan plan = plan(true);
            Path root = fresh(base);
            boolean[] lose = {true};
            ArtifactStore s = store(root, step -> {
                if (lose[0] && step.equals("parent-synced")) throw new Stop();
            });
            List<Staged> staged = stageBoth(s);
            check(problems, !s.publish(plan, publication(plan), staged, PASS), "the acknowledgement was lost");
            check(problems, both(s, plan).equals(PUBLISHED), "read back " + both(s, plan));
            check(problems, Arrays.equals(s.members(variantId()).get(0), apk(1))
                    && Arrays.equals(s.members(restorationId()).get(0), apk(2)), "the exact bytes");
            lose[0] = false;
            List<String> points = new ArrayList<>();
            ArtifactStore again = store(root, points::add);
            check(problems, again.publish(plan, publication(plan), staged, b -> "never asked"), "resolved by reading");
            check(problems, points.isEmpty(), "written again " + points);
            Publication other = new Publication(INSTALLATION, plan.planId, plan.component,
                    List.of(variantId(), restorationId()), List.of(REQUEST, REQUEST), TIME + 1);
            check(problems, !again.publish(plan, other, staged, PASS) && again.publication(plan.planId)
                    .equals(publication(plan)), "a published record never changes");
        });
        cases.run("store / changed, missing or extra members read as MISMATCH", problems -> {
            Plan plan = plan(true);
            for (int damage = 0; damage < 4; damage++) {
                Path root = fresh(base);
                ArtifactStore s = store(root, step -> { });
                check(problems, s.publish(plan, publication(plan), stageBoth(s), PASS), "published");
                Path dir = root.resolve("bundles").resolve(restorationId());
                if (damage == 0) {
                    byte[] bytes = Files.readAllBytes(dir.resolve("base.apk"));
                    bytes[7] ^= 1;
                    Files.write(dir.resolve("base.apk"), bytes);
                } else if (damage == 1) {
                    Files.delete(dir.resolve("base.apk.idsig"));
                } else if (damage == 2) {
                    Files.write(dir.resolve("extra"), new byte[] {1});
                } else {
                    Files.write(dir.resolve("manifest.rec"), ArtifactRecords.encodeManifest(variant()));
                }
                check(problems, s.presence(variantId()) == Presence.PUBLISHED
                        && s.presence(restorationId()) == Presence.MISMATCH
                        && s.planPublication(plan.planId) == Presence.MISMATCH, "damage " + damage + " " + both(s, plan));
            }
        });
        cases.run("store / unpublished bundles, staging leftovers and unreadable publications", problems -> {
            Plan plan = plan(true);
            Path root = fresh(base);
            ArtifactStore s = store(root, step -> { });
            List<Staged> staged = stageBoth(s);
            Files.move(root.resolve(".staging-" + variantId()), root.resolve("bundles").resolve(variantId()));
            check(problems, s.presence(variantId()) == Presence.ABSENT, "a bundle no publication names is invisible");
            Files.write(root.resolve("publications").resolve(".x.rec.staging"), new byte[] {1});
            check(problems, s.presence(variantId()) == Presence.ABSENT, "a staging leftover is a record");
            Path damaged = root.resolve("publications").resolve(Fixtures.id(0x777) + ".rec");
            Files.write(damaged, new byte[] {1, 2, 3});
            check(problems, s.presence(variantId()) == Presence.UNAVAILABLE
                    && s.presence(restorationId()) == Presence.UNAVAILABLE, "a damaged publication might name it");
            Files.delete(damaged);
            Files.write(root.resolve("publications").resolve(Fixtures.id(0x778) + ".rec"),
                    resealed(ArtifactRecords.encodePublication(publication(plan)), 6, 2));
            check(problems, s.presence(variantId()) == Presence.UNAVAILABLE, "a newer publication might name it");
            Files.delete(root.resolve("publications").resolve(Fixtures.id(0x778) + ".rec"));
            // The resumed publication keeps the bundle already there, which has the exact bytes.
            List<Staged> again = List.of(staged.get(0), staged.get(1));
            check(problems, s.stage(variant(), apk(1), idsig(1)) != null
                    && s.publish(plan, publication(plan), again, PASS) && both(s, plan).equals(PUBLISHED),
                    "published over the identical bundle");
        });
        cases.run("store / a different bundle under the same ID is never replaced", problems -> {
            Plan plan = plan(true);
            Path root = fresh(base);
            ArtifactStore s = store(root, step -> { });
            List<Staged> staged = stageBoth(s);
            Path squatter = root.resolve("bundles").resolve(restorationId());
            Files.createDirectory(squatter);
            Files.write(squatter.resolve("base.apk"), apk(9));
            check(problems, !s.publish(plan, publication(plan), staged, PASS), "published over other bytes");
            check(problems, s.publication(plan.planId) == null && both(s, plan).equals(ABSENT)
                    && Arrays.equals(Files.readAllBytes(squatter.resolve("base.apk")), apk(9)), "replaced");
            check(problems, s.stage(variant(), apk(2), idsig(1)) == null, "members that differ from the manifest staged");
        });
        cases.run("store / the plan names its inputs and the publication binds the bundles signed from them",
                problems -> {
            Plan plan = plan(true);
            ArtifactStore s = store(fresh(base), step -> { });
            List<Staged> staged = stageBoth(s);
            Plan otherInput = plan.toBuilder().restoration(Fixtures.digest(0x49), Fixtures.RESTORATION_VERSION).build();
            check(problems, !s.publish(otherInput, publication(otherInput), staged, PASS), "a bundle of another input");
            Plan otherVersion = plan.toBuilder().restoration(restoration().inputEntries, 42).build();
            check(problems, !s.publish(otherVersion, publication(otherVersion), staged, PASS), "another versionCode");
            Plan signsNothing = plan.toBuilder().signing(0).build();
            check(problems, !s.publish(signsNothing, publication(signsNothing), staged, PASS), "a plan that signs nothing");
            check(problems, both(s, plan).equals(ABSENT) && s.planPublication(plan.planId) == Presence.ABSENT,
                    "visible " + both(s, plan));
            check(problems, s.publish(plan, publication(plan), staged, PASS)
                    && s.planPublication(plan.planId) == Presence.PUBLISHED, "the plan's own inputs refused");
        });
        cases.run("store / a second publication completes from the bundles the store already holds", problems -> {
            Plan plan = plan(true);
            Path root = fresh(base);
            boolean[] stop = {true};
            ArtifactStore s = store(root, step -> {
                if (stop[0] && step.equals("bundles-synced")) throw new Stop();
            });
            check(problems, !s.publish(plan, publication(plan), stageBoth(s), PASS), "stopped after the renames");
            check(problems, both(s, plan).equals(ABSENT) && s.planPublication(plan.planId) == Presence.ABSENT
                    && bundleDirs(root) == 2, "an effect " + both(s, plan));
            stop[0] = false;
            // No bytes are supplied again and nothing is signed again: the store reads its own bundles.
            List<Staged> held = Arrays.asList(s.held(variantId()), s.held(restorationId()));
            check(problems, held.get(0) != null && held.get(1) != null, "held bundles unreadable");
            List<String> verified = new ArrayList<>();
            check(problems, s.publish(plan, publication(plan), held, b -> {
                verified.add(b.id);
                return null;
            }) && both(s, plan).equals(PUBLISHED) && s.planPublication(plan.planId) == Presence.PUBLISHED,
                    "the second publication " + both(s, plan));
            check(problems, verified.equals(List.of(variantId(), restorationId())), "verified again " + verified);
            check(problems, s.held(Fixtures.digest(0x99)) == null, "a bundle the store does not hold");
            // A stop before any rename leaves the private copies, which the store also holds.
            Path second = fresh(base);
            ArtifactStore t = store(second, step -> {
                if (step.equals("verified")) throw new Stop();
            });
            check(problems, !t.publish(plan, publication(plan), stageBoth(t), PASS), "stopped before the renames");
            ArtifactStore resumed = store(second, step -> { });
            List<Staged> copies = Arrays.asList(resumed.held(variantId()), resumed.held(restorationId()));
            check(problems, copies.get(0) != null && copies.get(1) != null
                    && resumed.publish(plan, publication(plan), copies, PASS) && both(resumed, plan).equals(PUBLISHED),
                    "completed from the private copies");
            // A held copy whose bytes changed is no bundle.
            Path third = fresh(base);
            ArtifactStore u = store(third, step -> {
                if (step.equals("bundles-synced")) throw new Stop();
            });
            check(problems, !u.publish(plan, publication(plan), stageBoth(u), PASS), "stopped");
            Path apkFile = third.resolve("bundles").resolve(restorationId()).resolve("base.apk");
            byte[] bytes = Files.readAllBytes(apkFile);
            bytes[3] ^= 1;
            Files.write(apkFile, bytes);
            check(problems, u.held(restorationId()) == null, "a changed bundle read as held");
        });
        cases.run("store / a pair from two signing transactions fits the publication", problems -> {
            ArtifactStore s = store(fresh(base), step -> { });
            Manifest r = manifest(Role.RESTORATION, 2, Fixtures.id(0x5f));
            String rid = ArtifactRecords.bundleId(r);
            Plan plan = plan(true).toBuilder().signing(2).build();
            List<Staged> staged = List.of(s.stage(variant(), apk(1), idsig(1)), s.stage(r, apk(2), idsig(2)));
            Publication wrong = new Publication(INSTALLATION, plan.planId, plan.component, List.of(variantId(), rid),
                    List.of(REQUEST, REQUEST), TIME);
            check(problems, !s.publish(plan, wrong, staged, PASS), "a transaction the bundle was not signed in");
            Publication two = new Publication(INSTALLATION, plan.planId, plan.component, List.of(variantId(), rid),
                    List.of(REQUEST, Fixtures.id(0x5f)), TIME);
            check(problems, s.publish(plan, two, staged, PASS) && s.presence(variantId()) == Presence.PUBLISHED
                    && s.presence(rid) == Presence.PUBLISHED && s.publication(plan.planId).equals(two),
                    "the pair of two transactions");
        });
        cases.run("store / a restoration plan publishes the restoration that its pair's publication made visible",
                problems -> {
            Plan variant = plan(true);
            Plan restoring = restorationPlan(variant);
            Publication own = new Publication(INSTALLATION, restoring.planId, restoring.component,
                    List.of(restorationId()), List.of(REQUEST), TIME + 10);
            Path root = fresh(base);
            ArtifactStore s = store(root, step -> { });
            List<Staged> staged = stageBoth(s);
            // Before the pair is published, the restoration is no published bundle: never alone.
            check(problems, !s.publish(restoring, own, List.of(s.held(restorationId())), PASS)
                    && s.planPublication(restoring.planId) == Presence.ABSENT
                    && s.presence(restorationId()) == Presence.ABSENT, "a restoration published before its pair");
            check(problems, s.publish(variant, publication(variant), staged, PASS)
                    && s.apks(variant.planId).equals(List.of(variant().apk, restoration().apk)), "the pair");
            Staged held = s.held(restorationId());
            check(problems, held != null && held.manifest.role == Role.RESTORATION, "held restoration");
            // Matched by input, versionCode, signer and the bundle's own transaction.
            Plan otherInput = restoring.toBuilder().bundle(Fixtures.digest(0x49), Fixtures.RESTORATION_VERSION).build();
            check(problems, !s.publish(otherInput, own, List.of(held), PASS), "another input");
            Plan otherVersion = restoring.toBuilder().bundle(restoration().inputEntries, 42).build();
            check(problems, !s.publish(otherVersion, own, List.of(held), PASS), "another versionCode");
            Plan otherSigner = restoring.toBuilder().signer(Fixtures.digest(0xc9)).build();
            check(problems, !s.publish(otherSigner, own, List.of(held), PASS), "another signer");
            Publication otherTransaction = new Publication(INSTALLATION, restoring.planId, restoring.component,
                    List.of(restorationId()), List.of(Fixtures.id(0x5f)), TIME + 10);
            check(problems, !s.publish(restoring, otherTransaction, List.of(held), PASS), "another transaction");
            Plan signing = restoring.toBuilder().signing(1).build();
            check(problems, !s.publish(signing, own, List.of(held), PASS),
                    "a signing plan publishing a bundle signed in another role");
            // Verified again before the record is written.
            List<String> verified = new ArrayList<>();
            check(problems, !s.publish(restoring, own, List.of(held), b -> {
                verified.add(b.id);
                return "refused";
            }) && s.planPublication(restoring.planId) == Presence.ABSENT, "published although its check failed");
            check(problems, s.publish(restoring, own, List.of(held), b -> {
                verified.add(b.id);
                return null;
            }) && s.planPublication(restoring.planId) == Presence.PUBLISHED
                    && s.planPublication(variant.planId) == Presence.PUBLISHED, "the restoration plan's publication");
            check(problems, verified.equals(List.of(restorationId(), restorationId())), "verified again " + verified);
            // The manifest keeps its signing role, and the publication gives the role in this plan.
            Manifest m = ArtifactRecords.decodeManifest(Files.readAllBytes(root.resolve("bundles")
                    .resolve(restorationId()).resolve("manifest.rec")));
            check(problems, m.role == Role.RESTORATION && s.publication(restoring.planId).equals(own)
                    && s.apks(restoring.planId).equals(List.of(restoration().apk)), "roles " + m.role);
            check(problems, s.publish(restoring, own, List.of(held), PASS), "a lost acknowledgement read back");
        });
        cases.run("store / a plan that signs nothing publishes only the restoration its repaired pair published",
                problems -> {
            Plan variant = plan(true);
            Plan restoring = restorationPlan(variant);
            Path root = fresh(base);
            ArtifactStore s = store(root, step -> { });
            check(problems, s.publish(variant, publication(variant), stageBoth(s), PASS), "the pair");
            // Another pair's variant, in place of the restoration: refused by its signing role.
            Plan takesVariant = restoring.toBuilder().bundle(variant().inputEntries, Fixtures.BUNDLE_VERSION)
                    .base(Fixtures.FACTORY_APK, Fixtures.FACTORY_VERSION, Fixtures.UID, Fixtures.CONTEXT).build();
            Publication variantOwn = new Publication(INSTALLATION, takesVariant.planId, takesVariant.component,
                    List.of(variantId()), List.of(REQUEST), TIME);
            check(problems, !s.publish(takesVariant, variantOwn, List.of(s.held(variantId())), PASS)
                    && s.planPublication(takesVariant.planId) == Presence.ABSENT, "another pair's variant");
            // A record from another writer that binds a variant in its RESTORATION role: still a variant.
            String forged = Fixtures.id(0x1f0);
            Files.write(root.resolve("publications").resolve(forged + ".rec"), ArtifactRecords.encodePublication(
                    new Publication(INSTALLATION, forged, Fixtures.COMPONENT, List.of(restorationId(), variantId()),
                            List.of(REQUEST, REQUEST), TIME)));
            Plan forgedRestoration = takesVariant.toBuilder().repairs(forged).build();
            Publication forgedOwn = new Publication(INSTALLATION, forgedRestoration.planId,
                    forgedRestoration.component, List.of(variantId()), List.of(REQUEST), TIME);
            check(problems, s.planPublication(forged) == Presence.PUBLISHED
                    && !s.publish(forgedRestoration, forgedOwn, List.of(s.held(variantId())), PASS),
                    "a variant bound in a RESTORATION role");
            // A variant published alone, by a plan without a restoration: still a variant.
            Path alone = fresh(base);
            ArtifactStore t = store(alone, step -> { });
            Plan single = plan(false);
            check(problems, t.publish(single, publication(single), List.of(t.stage(variant(), apk(1), idsig(1))), PASS),
                    "a variant alone");
            Plan restoresSingle = takesVariant.toBuilder().repairs(single.planId).build();
            Publication singleOwn = new Publication(INSTALLATION, restoresSingle.planId, restoresSingle.component,
                    List.of(variantId()), List.of(REQUEST), TIME);
            check(problems, !t.publish(restoresSingle, singleOwn, List.of(t.held(variantId())), PASS),
                    "a variant published alone");
            // The restoration of a plan other than the one it repairs.
            Plan elsewhere = restoring.toBuilder().repairs(Fixtures.id(0x199)).build();
            Publication elsewhereOwn = new Publication(INSTALLATION, elsewhere.planId, elsewhere.component,
                    List.of(restorationId()), List.of(REQUEST), TIME);
            check(problems, !s.publish(elsewhere, elsewhereOwn, List.of(s.held(restorationId())), PASS),
                    "a restoration of another plan");
            // More than one bundle: a second restoration of another pair in its RESTORATION role.
            Manifest other = new Manifest(INSTALLATION, Fixtures.COMPONENT, Role.RESTORATION, REQUEST,
                    Fixtures.digest(0x33), Fixtures.digest(0x43), 42, DeploymentRecords.sha256Hex(apk(3)),
                    apk(3).length, DeploymentRecords.sha256Hex(idsig(3)), idsig(3).length, CERT, KEY,
                    ArtifactRecords.SCHEMES, 37, 37, V4Check.VERIFIED);
            Manifest otherVariant = new Manifest(INSTALLATION, Fixtures.COMPONENT, Role.VARIANT, REQUEST,
                    Fixtures.digest(0x34), Fixtures.digest(0x44), 40, DeploymentRecords.sha256Hex(apk(4)),
                    apk(4).length, DeploymentRecords.sha256Hex(idsig(4)), idsig(4).length, CERT, KEY,
                    ArtifactRecords.SCHEMES, 37, 37, V4Check.VERIFIED);
            Plan second = Fixtures.plan(2).bundle(otherVariant.inputEntries, 40).restoration(other.inputEntries, 42)
                    .signer(CERT).build();
            String otherId = ArtifactRecords.bundleId(other);
            Publication secondPair = new Publication(INSTALLATION, second.planId, second.component,
                    List.of(ArtifactRecords.bundleId(otherVariant), otherId), List.of(REQUEST, REQUEST), TIME);
            check(problems, s.publish(second, secondPair, List.of(s.stage(otherVariant, apk(4), idsig(4)),
                    s.stage(other, apk(3), idsig(3))), PASS), "the second pair");
            Plan two = restoring.toBuilder().restoration(other.inputEntries, 42).build();
            Publication twoOwn = new Publication(INSTALLATION, two.planId, two.component,
                    List.of(restorationId(), otherId), List.of(REQUEST, REQUEST), TIME);
            check(problems, !s.publish(two, twoOwn, List.of(s.held(restorationId()), s.held(otherId)), PASS),
                    "two bundles for a plan that signs nothing");
            check(problems, refusedPlan(() -> restoring.toBuilder().repairs(DeploymentRecords.NO_ID).build())
                    || !s.publish(restoring.toBuilder().repairs(DeploymentRecords.NO_ID).build(),
                    publication(restoring), List.of(s.held(restorationId())), PASS), "no plan it repairs");
            // Decision 3's case.
            Publication own = new Publication(INSTALLATION, restoring.planId, restoring.component,
                    List.of(restorationId()), List.of(REQUEST), TIME);
            check(problems, s.publish(restoring, own, List.of(s.held(restorationId())), PASS)
                    && s.planPublication(restoring.planId) == Presence.PUBLISHED, "decision 3's restoration refused");
        });
        cases.run("store / every bundle carries the plan's signer certificate", problems -> {
            Plan plan = plan(true);
            ArtifactStore s = store(fresh(base), step -> { });
            List<Staged> staged = stageBoth(s);
            Plan otherSigner = plan.toBuilder().signer(Fixtures.SIGNER).build();
            check(problems, !s.publish(otherSigner, publication(otherSigner), staged, PASS)
                    && both(s, plan).equals(ABSENT) && s.planPublication(plan.planId) == Presence.ABSENT,
                    "bundles of another certificate published");
            Manifest other = new Manifest(INSTALLATION, Fixtures.COMPONENT, Role.RESTORATION, REQUEST,
                    Fixtures.digest(0x32), Fixtures.digest(0x42), Fixtures.RESTORATION_VERSION,
                    DeploymentRecords.sha256Hex(apk(2)), apk(2).length, DeploymentRecords.sha256Hex(idsig(2)),
                    idsig(2).length, Fixtures.digest(0xc9), KEY, ArtifactRecords.SCHEMES, 37, 37, V4Check.VERIFIED);
            String otherId = ArtifactRecords.bundleId(other);
            List<Staged> mixed = List.of(staged.get(0), s.stage(other, apk(2), idsig(2)));
            Publication pair = new Publication(INSTALLATION, plan.planId, plan.component, List.of(variantId(), otherId),
                    List.of(REQUEST, REQUEST), TIME);
            check(problems, !s.publish(plan, pair, mixed, PASS) && s.presence(variantId()) == Presence.ABSENT
                    && s.presence(otherId) == Presence.ABSENT, "a restoration of another certificate published");
            check(problems, s.publish(plan, publication(plan), staged, PASS) && both(s, plan).equals(PUBLISHED),
                    "the plan's own signer refused");
        });
    }
}
