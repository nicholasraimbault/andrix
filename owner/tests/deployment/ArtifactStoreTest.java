// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import static dev.andrix.server.deployment.Cases.check;
import static dev.andrix.server.deployment.Fixtures.INSTALLATION;
import static dev.andrix.server.deployment.Fixtures.TIME;

import dev.andrix.server.deployment.ArtifactRecords.Manifest;
import dev.andrix.server.deployment.ArtifactRecords.Publication;
import dev.andrix.server.deployment.ArtifactRecords.Role;
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
    private static final int GOLDEN_MANIFEST_VARIANT_BYTES = 329;
    private static final String GOLDEN_MANIFEST_VARIANT_SHA256 = "78aca427279c846a3c2963a724971313ad63e0683a9e09acb33111f683d5808e";
    private static final int GOLDEN_MANIFEST_RESTORATION_BYTES = 329;
    private static final String GOLDEN_MANIFEST_RESTORATION_SHA256 = "86a448487e6567ac5a5836a8c29f2a5f01edd3cfb78aa3b0465322a14192b55b";
    private static final int GOLDEN_PUBLICATION_PAIR_BYTES = 189;
    private static final String GOLDEN_PUBLICATION_PAIR_SHA256 = "63625b68147359c0ea9e3d7053f34fb80b57bd0781852cc643abecff4bb70499";
    private static final int GOLDEN_PUBLICATION_ONE_BYTES = 156;
    private static final String GOLDEN_PUBLICATION_ONE_SHA256 = "35915c5304625e9233e39b2f23544890c363f80787853a35c7786a728fd24fa9";

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

    static Manifest manifest(Role role, int n, String request) {
        byte[] apk = apk(n);
        byte[] idsig = idsig(n);
        return new Manifest(INSTALLATION, Fixtures.COMPONENT, role, request, Fixtures.digest(0x30 + n),
                Fixtures.digest(0x40 + n), role == Role.VARIANT ? Fixtures.BUNDLE_VERSION : Fixtures.RESTORATION_VERSION,
                DeploymentRecords.sha256Hex(apk), apk.length, DeploymentRecords.sha256Hex(idsig), idsig.length, CERT,
                KEY, ArtifactRecords.SCHEMES, 37, 37, V4Check.VERIFIED, TIME + n);
    }

    static Manifest variant() { return manifest(Role.VARIANT, 1, REQUEST); }

    static Manifest restoration() { return manifest(Role.RESTORATION, 2, REQUEST); }

    static Plan plan(boolean withRestoration) {
        Plan.Builder b = Fixtures.plan(1).bundle(ArtifactRecords.bundleId(variant()), variant().apk,
                Fixtures.BUNDLE_VERSION);
        if (withRestoration) {
            b.restoration(ArtifactRecords.bundleId(restoration()), restoration().apk, Fixtures.RESTORATION_VERSION);
        } else {
            b.restoration(DeploymentRecords.NO_DIGEST, DeploymentRecords.NO_DIGEST, 0);
        }
        return b.build();
    }

    static Publication publication(Plan plan) {
        List<String> ids = new ArrayList<>(List.of(plan.bundle));
        if (plan.hasRestoration()) ids.add(plan.restoration);
        return new Publication(INSTALLATION, plan.planId, plan.component, REQUEST, ids, TIME + 9);
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
            int count = 12 + 16 + 16 + 2 + Fixtures.COMPONENT.length() + 16;
            for (int[] change : new int[][] {{count, 0}, {count, 3}, {count + 33, 2}, {count + 66, 1}}) {
                check(problems, refusedPublication(resealed(p, change[0], change[1])), "publication byte " + change[0]);
            }
            check(problems, refusedPublication(resealed(m, 4, 7)), "a manifest read as a publication");
            check(problems, refusedManifest(resealed(m, 6, 2)), "version 2 read as version 1");
            boolean twice = false;
            try {
                new Publication(INSTALLATION, Fixtures.id(1), Fixtures.COMPONENT, REQUEST,
                        List.of(Fixtures.digest(1), Fixtures.digest(1)), 0);
            } catch (IllegalArgumentException expected) {
                twice = true;
            }
            check(problems, twice, "a bundle named twice");
        });
        cases.run("records / informational times decide nothing and the prefix reads a later version", problems -> {
            for (long t : new long[] {Long.MIN_VALUE, -1, 0, Long.MAX_VALUE}) {
                Manifest m = variant();
                Manifest other = new Manifest(m.installation, m.component, m.role, m.request, m.input, m.inputEntries,
                        m.versionCode, m.apk, m.apkBytes, m.idsig, m.idsigBytes, m.certificate, m.key, m.schemes,
                        m.sdkMin, m.sdkMax, m.v4, t);
                check(problems, ArtifactRecords.decodeManifest(ArtifactRecords.encodeManifest(other)).createdAt == t,
                        "time " + t);
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
        return List.of(s.presence(plan.bundle), s.presence(plan.restoration));
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
            check(problems, staged.get(0).id.equals(plan.bundle) && staged.get(1).id.equals(plan.restoration),
                    "bundle IDs are the manifest digests");
            check(problems, both(s, plan).equals(ABSENT), "staging is invisible " + both(s, plan));
            check(problems, s.publish(plan, publication(plan), staged, PASS), "published");
            check(problems, both(s, plan).equals(PUBLISHED), "both published " + both(s, plan));
            check(problems, Arrays.equals(s.members(plan.bundle).get(0), apk(1))
                    && Arrays.equals(s.members(plan.restoration).get(1), idsig(2)), "exact members");
            check(problems, s.publication(plan.planId).equals(publication(plan)), "publication read back");
            Plan alone = plan(false);
            ArtifactStore single = store(fresh(base), step -> { });
            List<Staged> one = List.of(single.stage(variant(), apk(1), idsig(1)));
            check(problems, single.publish(alone, publication(alone), one, PASS)
                    && single.presence(alone.bundle) == Presence.PUBLISHED, "a plan without a restoration");
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
            check(problems, ok && verified.equals(List.of(plan.bundle, plan.restoration)), "verified " + verified);
        });
        cases.run("store / a bundle is never published alone", problems -> {
            Plan plan = plan(true);
            Path root = fresh(base);
            ArtifactStore s = store(root, step -> { });
            List<Staged> staged = stageBoth(s);
            Publication alone = new Publication(INSTALLATION, plan.planId, plan.component, REQUEST,
                    List.of(plan.bundle), TIME);
            check(problems, !s.publish(plan, alone, staged.subList(0, 1), PASS), "the variant alone");
            Publication swapped = new Publication(INSTALLATION, plan.planId, plan.component, REQUEST,
                    List.of(plan.restoration, plan.bundle), TIME);
            check(problems, !s.publish(plan, swapped, List.of(staged.get(1), staged.get(0)), PASS), "roles swapped");
            check(problems, !s.publish(plan, publication(plan), staged.subList(0, 1), PASS), "one staged bundle");
            Staged otherRequest = s.stage(manifest(Role.RESTORATION, 2, Fixtures.id(0x5f)), apk(2), idsig(2));
            check(problems, !s.publish(plan, publication(plan), List.of(staged.get(0), otherRequest), PASS),
                    "a restoration of another signing transaction");
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
            check(problems, Arrays.equals(s.members(plan.bundle).get(0), apk(1))
                    && Arrays.equals(s.members(plan.restoration).get(0), apk(2)), "the exact bytes");
            lose[0] = false;
            List<String> points = new ArrayList<>();
            ArtifactStore again = store(root, points::add);
            check(problems, again.publish(plan, publication(plan), staged, b -> "never asked"), "resolved by reading");
            check(problems, points.isEmpty(), "written again " + points);
            Publication other = new Publication(INSTALLATION, plan.planId, plan.component, REQUEST,
                    List.of(plan.bundle, plan.restoration), TIME + 1);
            check(problems, !again.publish(plan, other, staged, PASS) && again.publication(plan.planId)
                    .equals(publication(plan)), "a published record never changes");
        });
        cases.run("store / changed, missing or extra members read as MISMATCH", problems -> {
            Plan plan = plan(true);
            for (int damage = 0; damage < 4; damage++) {
                Path root = fresh(base);
                ArtifactStore s = store(root, step -> { });
                check(problems, s.publish(plan, publication(plan), stageBoth(s), PASS), "published");
                Path dir = root.resolve("bundles").resolve(plan.restoration);
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
                check(problems, s.presence(plan.bundle) == Presence.PUBLISHED
                        && s.presence(plan.restoration) == Presence.MISMATCH, "damage " + damage + " " + both(s, plan));
            }
        });
        cases.run("store / unpublished bundles, staging leftovers and unreadable publications", problems -> {
            Plan plan = plan(true);
            Path root = fresh(base);
            ArtifactStore s = store(root, step -> { });
            List<Staged> staged = stageBoth(s);
            Files.move(root.resolve(".staging-" + plan.bundle), root.resolve("bundles").resolve(plan.bundle));
            check(problems, s.presence(plan.bundle) == Presence.ABSENT, "a bundle no publication names is invisible");
            Files.write(root.resolve("publications").resolve(".x.rec.staging"), new byte[] {1});
            check(problems, s.presence(plan.bundle) == Presence.ABSENT, "a staging leftover is a record");
            Path damaged = root.resolve("publications").resolve(Fixtures.id(0x777) + ".rec");
            Files.write(damaged, new byte[] {1, 2, 3});
            check(problems, s.presence(plan.bundle) == Presence.UNAVAILABLE
                    && s.presence(plan.restoration) == Presence.UNAVAILABLE, "a damaged publication might name it");
            Files.delete(damaged);
            Files.write(root.resolve("publications").resolve(Fixtures.id(0x778) + ".rec"),
                    resealed(ArtifactRecords.encodePublication(publication(plan)), 6, 2));
            check(problems, s.presence(plan.bundle) == Presence.UNAVAILABLE, "a newer publication might name it");
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
            Path squatter = root.resolve("bundles").resolve(plan.restoration);
            Files.createDirectory(squatter);
            Files.write(squatter.resolve("base.apk"), apk(9));
            check(problems, !s.publish(plan, publication(plan), staged, PASS), "published over other bytes");
            check(problems, s.publication(plan.planId) == null && both(s, plan).equals(ABSENT)
                    && Arrays.equals(Files.readAllBytes(squatter.resolve("base.apk")), apk(9)), "replaced");
            check(problems, s.stage(variant(), apk(2), idsig(1)) == null, "members that differ from the manifest staged");
        });
    }
}
