// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import static dev.andrix.server.deployment.Cases.check;

import dev.andrix.server.deployment.ArtifactRecords.Publication;
import dev.andrix.server.deployment.ArtifactRecords.Role;
import dev.andrix.server.deployment.ArtifactRecords.Transaction;
import dev.andrix.server.deployment.ArtifactRecords.TransactionState;
import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.Classification;
import dev.andrix.server.deployment.DeploymentRecords.Crossing;
import dev.andrix.server.deployment.DeploymentRecords.Effect;
import dev.andrix.server.deployment.DeploymentRecords.Entry;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.State;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * The host signer and bundle builder on the frozen SystemUI outputs, with the pinned apksig and
 * the public development platform key. With the tool's options, v1 included, the pinned engine
 * reproduces every sealed output byte for byte, and counts the key operations that took. Decision
 * 8's transaction then signs the built variant and its built restoration with six key operations,
 * without v1, verifies both bundles against the platform role, checks that they hold the sealed
 * outputs' entries and publishes them together. Arguments:
 * the sealed directory holding {@code artifacts/}, the directory with {@code platform.pk8} and
 * {@code platform.x509.pem}, the role's certificate and key digests from the trusted role
 * manifest, and a fresh work directory. Host JVM only; nothing here is built or installed.
 */
public final class SealedOutputsTest {
    private static final Cases cases = new Cases();
    private static final String TRANSACTION = Fixtures.id(0x5e1);

    private SealedOutputsTest() {}

    public static void main(String[] args) throws Exception {
        Cases.requireAssertions(SealedOutputsTest.class);
        Path sealed = Path.of(args[0]).resolve("artifacts");
        Path keys = Path.of(args[1]);
        BundleBuilder.RoleIdentity role = new BundleBuilder.RoleIdentity(args[2], args[3]);
        Path work = Path.of(args[4]);
        // The tool's own outputs without v1: --v1-signing-enabled false --v4-signing-enabled true
        // --min-sdk-version 37, as the runner produced them with the pinned jar.
        Path reference = Path.of(args[5]);
        Files.createDirectories(work.resolve("engine"));
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Files.readAllBytes(keys.resolve("platform.x509.pem"))));
        PrivateKey key = KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(keys.resolve("platform.pk8"))));
        byte[] builtA = Files.readAllBytes(sealed.resolve("built-A.apk"));
        byte[] builtR = Files.readAllBytes(sealed.resolve("built-R.apk"));
        Map<String, byte[]> inputs = Map.of(ApkEntries.digest(builtA), builtA, ApkEntries.digest(builtR), builtR);
        Plan plan = Fixtures.plan(1).bundle(ApkEntries.digest(builtA), 38).restoration(ApkEntries.digest(builtR), 39)
                .signer(role.certificate).build();
        ApksigEngine engine = new ApksigEngine(certificate, work.resolve("engine"), false);
        HostSigner.Keys keyOperation = (data, algorithm) -> {
            Signature s = Signature.getInstance(algorithm);
            s.initSign(key);
            s.update(data);
            return s.sign();
        };
        cases.run("sealed / the pinned apksig with the tool's options reproduces every sealed output byte for byte",
                problems -> {
            ApksigEngine tool = new ApksigEngine(certificate, work.resolve("engine"), true);
            for (String variant : List.of("A", "R")) {
                int[] operations = {0};
                HostSigner.Signed out = tool.sign(Files.readAllBytes(sealed.resolve("built-" + variant + ".apk")),
                        (data, algorithm) -> {
                            operations[0]++;
                            return keyOperation.sign(data, algorithm);
                        });
                Path dir = sealed.resolve(variant);
                check(problems, Arrays.equals(out.apk, Files.readAllBytes(dir.resolve("SystemUI.apk"))),
                        variant + " base.apk differs from the sealed output");
                check(problems, Arrays.equals(out.idsig, Files.readAllBytes(dir.resolve("SystemUI.apk.idsig"))),
                        variant + " base.apk.idsig differs from the sealed output");
                // v1, v2, v3 and v4: the tool's default signs v1 too, which decision 8 leaves out.
                check(problems, operations[0] == 4, variant + " took " + operations[0] + " key operations");
                System.out.println("INFO " + variant + " with the tool's options: " + operations[0] + " key operations");
            }
        });
        HostSigner signer = new HostSigner(work.resolve("signer"), Fixtures.INSTALLATION, engine, keyOperation,
                (t, operation) -> true);
        signer.initialize();
        ArtifactStore store = new ArtifactStore(work.resolve("store"), Fixtures.INSTALLATION);
        store.initialize();
        long[] n = {0};
        BundleBuilder builder = new BundleBuilder(Fixtures.INSTALLATION, signer, store, engine, role,
                ApksigEngine.MIN_SDK, 0xffff, inputs::get, () -> Fixtures.id(0x7a000 + (++n[0])), () -> Fixtures.TIME);
        Authorization grant = Fixtures.lab(1, plan, Effect.SIGN, 3, Fixtures.TIME);
        Entry sign = new Entry(Crossing.SIGN, DeploymentRecords.NO_ID, -1, 0, grant.authorizationId, TRANSACTION,
                Fixtures.TIME);
        Ticket signing = Fixtures.ticket(1, plan).state(State.SIGNING).append(sign).build();
        Observation[] signed = new Observation[1];
        cases.run("sealed / six key operations sign the variant and its restoration in one transaction", problems -> {
            signed[0] = builder.sign(signing, plan, sign, grant);
            Transaction t = signer.read(TRANSACTION);
            check(problems, signed[0] != null && signed[0].classification == Classification.SIGN_COMPLETED,
                    "reply " + (signed[0] == null ? null : signed[0].classification));
            check(problems, signer.operations() == 6 && t != null && t.state == TransactionState.COMPLETED
                    && t.operations.size() == 6 && t.outputs.size() == 4, "operations " + signer.operations());
        });
        cases.run("sealed / the transaction's outputs equal the tool's reference without v1 byte for byte",
                problems -> {
            for (Role r : List.of(Role.VARIANT, Role.RESTORATION)) {
                String name = r == Role.VARIANT ? "A" : "R";
                HostSigner.Signed out = signer.retained(TRANSACTION, r);
                check(problems, out != null && Arrays.equals(out.apk, Files.readAllBytes(reference.resolve(name + ".apk"))),
                        r + " base.apk differs from the reference");
                check(problems, out != null
                        && Arrays.equals(out.idsig, Files.readAllBytes(reference.resolve(name + ".apk.idsig"))),
                        r + " base.apk.idsig differs from the reference");
            }
        });
        cases.run("sealed / an engine that also signs v1 is refused by the operation count", problems -> {
            HostSigner withV1 = new HostSigner(work.resolve("signer-v1"), Fixtures.INSTALLATION,
                    new ApksigEngine(certificate, work.resolve("engine"), true), keyOperation, (t, operation) -> true);
            withV1.initialize();
            ArtifactStore other = new ArtifactStore(work.resolve("store-v1"), Fixtures.INSTALLATION);
            other.initialize();
            BundleBuilder v1Builder = new BundleBuilder(Fixtures.INSTALLATION, withV1, other, engine, role,
                    ApksigEngine.MIN_SDK, 0xffff, inputs::get, () -> Fixtures.id(0x7c000 + (++n[0])), () -> Fixtures.TIME);
            Observation reply = v1Builder.sign(signing, plan, sign, grant);
            check(problems, reply != null && reply.classification == Classification.SIGN_CANNOT_COMPLETE
                    && withV1.operations() == 3 && withV1.retained(TRANSACTION, Role.VARIANT) == null,
                    "a v1 signature passed: " + (reply == null ? null : reply.classification) + " "
                    + withV1.operations());
        });
        cases.run("sealed / the six operation outputs hold the sealed outputs' entries without v1", problems -> {
            for (Role r : List.of(Role.VARIANT, Role.RESTORATION)) {
                Path dir = sealed.resolve(r == Role.VARIANT ? "A" : "R");
                HostSigner.Signed out = signer.retained(TRANSACTION, r);
                byte[] sealedApk = Files.readAllBytes(dir.resolve("SystemUI.apk"));
                check(problems, out != null && ApkEntries.digest(out.apk).equals(ApkEntries.digest(sealedApk))
                        && ApkEntries.digest(sealedApk).equals(r == Role.VARIANT ? plan.bundleInput
                        : plan.restorationInput), r + " entries differ from the sealed output's");
                check(problems, out != null && !Arrays.equals(out.apk, sealedApk), r + " equals the v1 signed output");
            }
        });
        cases.run("sealed / both bundles verify against the platform role over every scheme", problems -> {
            Transaction t = signer.read(TRANSACTION);
            for (Role r : List.of(Role.VARIANT, Role.RESTORATION)) {
                HostSigner.Signed out = signer.retained(TRANSACTION, r);
                String failed = out == null ? "no output" : builder.verify(out.apk, out.idsig, builder.manifest(t, r));
                check(problems, failed == null, r + ": " + failed);
                HostSigner.Verification v = engine.verify(out.apk, out.idsig, ApksigEngine.MIN_SDK, 0xffff);
                check(problems, v.v2BelowSdk28 && v.v3 && v.v4 && v.signers.size() == 3, r + " schemes " + v.signers.size());
            }
            BundleBuilder.RoleIdentity other = new BundleBuilder.RoleIdentity(Fixtures.digest(0xc9), role.key);
            BundleBuilder wrong = new BundleBuilder(Fixtures.INSTALLATION, signer, store, engine, other,
                    ApksigEngine.MIN_SDK, 0xffff, inputs::get, () -> Fixtures.id(0x7b000 + (++n[0])), () -> Fixtures.TIME);
            HostSigner.Signed out = signer.retained(TRANSACTION, Role.VARIANT);
            check(problems, wrong.verify(out.apk, out.idsig, builder.manifest(t, Role.VARIANT)) != null,
                    "another role accepted");
        });
        cases.run("sealed / both bundles publish together through the store", problems -> {
            Ticket signedTicket = signing.toBuilder().state(State.SIGNED)
                    .append(new Entry(Crossing.PUBLISH, DeploymentRecords.NO_ID, -1, 0, DeploymentRecords.NO_ID,
                            Fixtures.id(0x9b5), Fixtures.TIME)).build();
            Observation fact = builder.publish(signedTicket, plan, signedTicket.last(Crossing.PUBLISH));
            Publication p = store.publication(plan.planId);
            check(problems, fact != null && fact.classification == Classification.BUNDLE_PUBLISHED
                    && p != null && p.bundles.size() == 2 && p.transactions.equals(List.of(TRANSACTION, TRANSACTION)),
                    "publication " + (fact == null ? null : fact.classification));
            check(problems, fact != null && fact.bundleApk.equals(DeploymentRecords.sha256Hex(
                    signer.retained(TRANSACTION, Role.VARIANT).apk)) && fact.restorationApk.equals(
                    DeploymentRecords.sha256Hex(signer.retained(TRANSACTION, Role.RESTORATION).apk)),
                    "the fact's APKs");
        });
        cases.finish("Sealed SystemUI outputs reproduced and published");
    }
}
