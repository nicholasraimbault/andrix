// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

import dev.andrix.server.deployment.ApkEntries;
import dev.andrix.server.deployment.ApksigEngine;
import dev.andrix.server.deployment.ArtifactRecords.Transaction;
import dev.andrix.server.deployment.ArtifactStore;
import dev.andrix.server.deployment.BundleBuilder;
import dev.andrix.server.deployment.Coordinator;
import dev.andrix.server.deployment.DeploymentRecords;
import dev.andrix.server.deployment.DeploymentStore;
import dev.andrix.server.deployment.HostSigner;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The lab driver's host signer and publisher: the deployment package's {@link HostSigner} over
 * apksig without v1, its {@link ArtifactStore} and its {@link BundleBuilder}, which the bridge puts
 * behind its fault wrapper. It signs with the development platform key that public Android source
 * trees carry, for a disposable lab guest only, never with a personal or release key.
 *
 * <p>Its configuration is one file that the lab driver writes at admission. A generation names the
 * file and its SHA-256 in the system properties {@code andrix.lab.host} and
 * {@code andrix.lab.hostSha256}. This class reads the file once and checks that digest, then reads
 * each file it names once and checks that file's SHA-256 before any use, so the bytes it checked are
 * the bytes it uses. Exactly these lines, in order, each ending with a newline:
 *
 * <pre>
 * andrix-lab-host 1
 * signer &lt;absolute directory of the host signer's records&gt;
 * artifacts &lt;absolute directory of the artifact store&gt;
 * work &lt;absolute directory for apksig's sidecar copies&gt;
 * key &lt;absolute path of the PKCS#8 platform key&gt; &lt;its SHA-256&gt;
 * certificate &lt;absolute path of the PEM platform certificate&gt; &lt;its SHA-256&gt;
 * role &lt;certificate digest&gt; &lt;public key digest&gt;
 * sdk &lt;minimum&gt; &lt;maximum&gt;
 * variant &lt;absolute path of the variant's signing input&gt; &lt;its SHA-256&gt;
 * restoration &lt;absolute path of the restoration's signing input&gt; &lt;its SHA-256&gt;
 * plans &lt;plan ID&gt;[,&lt;plan ID&gt;...]
 * </pre>
 *
 * Version 2, the next campaign profile's, has the header {@code andrix-lab-host 2}, version 1's
 * lines and one more, {@code repair <repair plan ID> <repaired plan ID>}: the one plan that may
 * repair one admitted plan without signing. The repaired plan is in {@code plans}; the repair plan
 * is not, so no key operation is ever approved for it.
 *
 * <p>The bridge's version 2 and 3 configurations name this file's SHA-256, and the broker's
 * admission binds that configuration's digest, so a generation, a plan and a publication read
 * refuse any other host configuration even when it comes with its own matching digest.
 *
 * <p>The role is the platform role as the trusted role manifest binds it, and must be the certificate's
 * own identity. The approval callback allows a key operation only for a transaction of the store's
 * installation and the configured component, of one of these plans, for this role and SDK range, and
 * only within the operations the transaction declares. The coordinator still decides when to sign;
 * this callback only refuses what the admission did not name. Host only.
 */
public final class LabHost implements LabBridge.HostFactory {
    public static final String HEADER = "andrix-lab-host 1";
    public static final String HEADER_2 = "andrix-lab-host 2";
    public static final String PROPERTY = "andrix.lab.host";
    public static final String DIGEST_PROPERTY = "andrix.lab.hostSha256";
    private static final List<String> KEYS = Arrays.asList("signer", "artifacts", "work", "key", "certificate", "role",
            "sdk", "variant", "restoration", "plans");
    private static final List<String> KEYS_2 = Arrays.asList("signer", "artifacts", "work", "key", "certificate",
            "role", "sdk", "variant", "restoration", "plans", "repair");
    private static final int MAX_INPUT = 256 << 20;

    /** One parsed configuration. Paths are absolute and normal; digests are lower case hexadecimal. */
    public static final class Config {
        public final Path signer;
        public final Path artifacts;
        public final Path work;
        public final Path key;
        public final String keySha256;
        public final Path certificate;
        public final String certificateSha256;
        public final BundleBuilder.RoleIdentity role;
        public final int sdkMin;
        public final int sdkMax;
        public final Path variant;
        public final String variantSha256;
        public final Path restoration;
        public final String restorationSha256;
        public final Set<String> plans;
        /** In version 2, the repair plan and the admitted plan it repairs; null in version 1. */
        public final String repair, repaired;
        /** SHA-256 of the exact file bytes. */
        public final String digest;

        private Config(String[] v, String digest) {
            signer = absolute(v[0], "signer");
            artifacts = absolute(v[1], "artifacts");
            work = absolute(v[2], "work");
            String[] key = pair(v[3], "key");
            this.key = absolute(key[0], "key");
            keySha256 = hex(key[1], 32, "key digest");
            String[] certificate = pair(v[4], "certificate");
            this.certificate = absolute(certificate[0], "certificate");
            certificateSha256 = hex(certificate[1], 32, "certificate digest");
            String[] role = pair(v[5], "role");
            this.role = new BundleBuilder.RoleIdentity(hex(role[0], 32, "role certificate"), hex(role[1], 32, "role key"));
            String[] sdk = pair(v[6], "sdk");
            sdkMin = number(sdk[0], "sdk minimum");
            sdkMax = number(sdk[1], "sdk maximum");
            if (sdkMin < 1 || sdkMax < sdkMin || sdkMax > 0xffff) throw new IllegalArgumentException("SDK range");
            String[] variant = pair(v[7], "variant");
            this.variant = absolute(variant[0], "variant");
            variantSha256 = hex(variant[1], 32, "variant digest");
            String[] restoration = pair(v[8], "restoration");
            this.restoration = absolute(restoration[0], "restoration");
            restorationSha256 = hex(restoration[1], 32, "restoration digest");
            Set<String> ids = new LinkedHashSet<>();
            for (String id : v[9].split(",", -1)) {
                if (!ids.add(hex(id, 16, "plan"))) throw new IllegalArgumentException("a plan named twice");
            }
            plans = Collections.unmodifiableSet(ids);
            if (v.length > KEYS.size()) {
                String[] link = pair(v[10], "repair");
                repair = hex(link[0], 16, "repair plan");
                repaired = hex(link[1], 16, "repaired plan");
                // The repaired plan signs under this configuration; the repair plan never does.
                if (repair.equals(repaired) || !plans.contains(repaired) || plans.contains(repair)) {
                    throw new IllegalArgumentException("the repair plan is not a plan outside plans repairing one in it");
                }
            } else {
                repair = null;
                repaired = null;
            }
            this.digest = digest;
        }

        private static String[] pair(String value, String what) {
            String[] parts = value.split(" ", -1);
            if (parts.length != 2) throw new IllegalArgumentException(what + " is two values");
            return parts;
        }

        private static Path absolute(String value, String what) {
            Path p = Paths.get(value);
            if (!p.isAbsolute() || !p.normalize().equals(p) || value.contains(" ")) {
                throw new IllegalArgumentException(what + " is an absolute normal path without spaces");
            }
            return p;
        }

        private static String hex(String value, int bytes, String what) {
            LabProtocol.checkHex(value, bytes, what, false);
            return value;
        }

        private static int number(String value, String what) {
            if (!value.matches("[1-9][0-9]{0,4}")) throw new IllegalArgumentException(what + " is a number");
            return Integer.parseInt(value);
        }
    }

    /** The configuration exact bytes hold. */
    public static Config parse(byte[] data) {
        for (byte b : data) {
            if (b != '\n' && (b < 0x20 || b > 0x7e)) throw new IllegalArgumentException("not printable ASCII");
        }
        String text = new String(data, StandardCharsets.US_ASCII);
        if (!text.endsWith("\n")) throw new IllegalArgumentException("the last line has no newline");
        String[] lines = text.substring(0, text.length() - 1).split("\n", -1);
        List<String> keys = lines.length > 0 && lines[0].equals(HEADER_2) ? KEYS_2 : KEYS;
        if (lines.length != keys.size() + 1 || !(lines[0].equals(HEADER) || lines[0].equals(HEADER_2))) {
            throw new IllegalArgumentException("not a version 1 or 2 lab host configuration");
        }
        String[] values = new String[keys.size()];
        for (int i = 0; i < keys.size(); i++) {
            String prefix = keys.get(i) + " ";
            String line = lines[i + 1];
            if (!line.startsWith(prefix) || line.length() == prefix.length()) {
                throw new IllegalArgumentException("line " + (i + 2) + " is not " + keys.get(i));
            }
            values[i] = line.substring(prefix.length());
        }
        return new Config(values, LabProtocol.sha256Hex(data));
    }

    /** One file's bytes, read once without following a link, refused unless they have this digest. */
    static byte[] pinned(Path path, String sha256, String what) throws IOException {
        if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException(what + " is not a regular file");
        }
        if (Files.size(path) > MAX_INPUT) throw new IOException(what + " is too large");
        byte[] data = Files.readAllBytes(path);
        if (!LabProtocol.sha256Hex(data).equals(sha256)) throw new IOException(what + " differs from its admitted digest");
        return data;
    }

    private final Config config;
    private final byte[] key;
    private final byte[] certificate;
    private final byte[] variant;
    private final byte[] restoration;

    /** A host factory over one configuration and its pinned files, all read and checked here. */
    public LabHost(Path path, String sha256) throws IOException {
        this.config = parse(pinned(path, sha256, "the host configuration"));
        this.key = pinned(config.key, config.keySha256, "the platform key");
        this.certificate = pinned(config.certificate, config.certificateSha256, "the platform certificate");
        this.variant = pinned(config.variant, config.variantSha256, "the variant input");
        this.restoration = pinned(config.restoration, config.restorationSha256, "the restoration input");
    }

    /** The factory the system properties name, or null when they name none. */
    public static LabHost fromProperties() throws IOException {
        String path = System.getProperty(PROPERTY);
        String sha256 = System.getProperty(DIGEST_PROPERTY);
        if (path == null && sha256 == null) return null;
        if (path == null || sha256 == null) throw new IOException("the host configuration and its digest go together");
        return new LabHost(Paths.get(path), sha256);
    }

    public Config config() { return config; }

    /** The pinned variant input, as checked. */
    public byte[] variant() { return variant.clone(); }

    /** The pinned restoration input, as checked. */
    public byte[] restoration() { return restoration.clone(); }

    private X509Certificate parsedCertificate() throws IOException {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(certificate));
        } catch (GeneralSecurityException e) {
            throw new IOException("the platform certificate cannot be read", e);
        }
    }

    /** An APK's own manifest facts, from apksig's binary manifest parser, or null when unreadable. */
    public HostSigner.Facts facts(byte[] apk) throws IOException {
        return new ApksigEngine(parsedCertificate(), config.work, false).facts(apk);
    }

    /**
     * Refuses, before anything is signed, inputs whose own declared SDK range is not the configured
     * one: the bundle builder signs only over an input's declared range (its minimum, and 65535 when
     * it declares no maximum), and would otherwise end the transaction unable to complete.
     */
    void checkInputs() throws IOException {
        for (byte[] input : new byte[][] {variant, restoration}) {
            HostSigner.Facts f = facts(input);
            if (f == null) throw new IOException("an input has no readable binary manifest");
            int max = f.maxSdk == 0 ? 0xffff : f.maxSdk;
            if (f.minSdk != config.sdkMin || max != config.sdkMax) {
                throw new IOException("the configured SDK range " + config.sdkMin + "-" + config.sdkMax
                        + " is not an input's declared range " + f.minSdk + "-" + max);
            }
        }
    }

    /** Refuses a bridge configuration that does not bind exactly this host configuration. */
    public void requireBoundBy(LabConfig lab) throws IOException {
        if (lab.host == null || !lab.host.equals(config.digest)) {
            throw new IOException("the host configuration is not the one the bridge configuration binds");
        }
    }

    /** Refuses a repair other than exactly the one this version 2 configuration admits. */
    public void requireRepair(String repair, String repaired) throws IOException {
        if (config.repair == null || !config.repair.equals(repair) || !config.repaired.equals(repaired)) {
            throw new IOException("the host configuration does not admit this repair of this plan");
        }
    }

    @Override
    public Coordinator.Host host(DeploymentStore store, LabConfig lab) throws IOException {
        requireBoundBy(lab);
        X509Certificate cert = parsedCertificate();
        PrivateKey privateKey;
        try {
            privateKey = KeyFactory.getInstance(cert.getPublicKey().getAlgorithm())
                    .generatePrivate(new PKCS8EncodedKeySpec(key));
            // The configured role must be this certificate's own identity, as apksig reports a signer.
            if (!DeploymentRecords.sha256Hex(cert.getEncoded()).equals(config.role.certificate)
                    || !DeploymentRecords.sha256Hex(cert.getPublicKey().getEncoded()).equals(config.role.key)) {
                throw new IOException("the role is not the platform certificate's identity");
            }
        } catch (GeneralSecurityException e) {
            throw new IOException("the platform key or certificate cannot be read", e);
        }
        checkInputs();
        String variantEntries = ApkEntries.digest(variant);
        String restorationEntries = ApkEntries.digest(restoration);
        if (variantEntries.equals(restorationEntries)) throw new IOException("the two signing inputs have one entry digest");
        Map<String, byte[]> inputs = Map.of(variantEntries, variant, restorationEntries, restoration);
        HostSigner.Keys keys = (data, algorithm) -> {
            Signature s = Signature.getInstance(algorithm);
            s.initSign(privateKey);
            s.update(data);
            return s.sign();
        };
        String installation = store.installation();
        HostSigner.Approval approval = (Transaction t, int operation) -> allows(t, operation, installation, lab.component);
        if (!Files.isDirectory(config.work, LinkOption.NOFOLLOW_LINKS)) {
            Files.createDirectory(config.work, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        }
        ApksigEngine engine = new ApksigEngine(cert, config.work, false);
        HostSigner signer = new HostSigner(config.signer, installation, engine, keys, approval);
        signer.initialize();
        ArtifactStore artifacts = new ArtifactStore(config.artifacts, installation);
        artifacts.initialize();
        SecureRandom random = new SecureRandom();
        return new BundleBuilder(installation, signer, artifacts, engine, config.role, config.sdkMin, config.sdkMax,
                entries -> {
                    byte[] input = inputs.get(entries);
                    return input == null ? null : input.clone();
                }, () -> freshId(random), System::currentTimeMillis);
    }

    /**
     * The approval of one key operation: a transaction of this installation and component, of an
     * admitted plan, for the configured role and SDK range, within its declared operations.
     */
    boolean allows(Transaction t, int operation, String installation, String component) {
        return t.installation.equals(installation) && t.component.equals(component) && config.plans.contains(t.plan)
                && t.certificate.equals(config.role.certificate) && t.key.equals(config.role.key)
                && t.sdkMin == config.sdkMin && t.sdkMax == config.sdkMax && operation >= 1
                && operation <= t.operations.size();
    }

    private static String freshId(SecureRandom random) {
        while (true) {
            byte[] bytes = new byte[16];
            random.nextBytes(bytes);
            String id = LabProtocol.hex(bytes);
            if (!id.equals(LabProtocol.ZERO_ID)) return id;
        }
    }
}
