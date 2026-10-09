// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import dev.andrix.server.deployment.ArtifactRecords.Manifest;
import dev.andrix.server.deployment.ArtifactRecords.Publication;
import dev.andrix.server.deployment.ArtifactRecords.Role;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Target;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * The host artifact store: bundles stored by content digest, and publications that make the
 * bundles of one plan visible together or not at all.
 *
 * <p>Layout under the root:
 * <ul>
 *   <li>{@code bundles/<id>/} with exactly {@code manifest.rec}, {@code base.apk} and
 *       {@code base.apk.idsig}. The ID is the SHA-256 of the manifest's bytes.</li>
 *   <li>{@code publications/<plan>.rec}, the publication record of one plan.</li>
 *   <li>{@code .staging-<id>/}, the private staging copy of one bundle, never read as a bundle.</li>
 * </ul>
 *
 * <p>A bundle is visible only when a publication names it and its directory reads back with the
 * exact bytes its manifest names. A bundle directory that no publication names is invisible, so a
 * stop between the renames and the publication's own rename publishes nothing. Publication
 * stages each bundle privately, verifies every bundle, syncs every file through its writing
 * descriptor and each directory, renames each bundle into {@code bundles/<id>}, syncs
 * {@code bundles/}, then writes the publication by the deployment store's protocol: stage, sync,
 * read back, rename, sync the parent, read back. A published bundle never changes. A lost
 * acknowledgement is resolved by reading the exact bytes, never by publishing again: a second
 * publication of a plan that has a publication only reads.
 *
 * <p>The plan names the signing inputs of its bundles, and the publication binds the bundles
 * signed from them to the plan. A plan that signs nothing is decision 3's restoration plan: it
 * publishes the one bundle that the publication of the plan it repairs bound in its RESTORATION
 * role, so no bundle is ever published alone and no bundle signed as a variant fills a
 * RESTORATION role. A publication that stopped before its record was written had no
 * effect, which {@link #planPublication} shows by reading the record absent. One more publication
 * then completes from the exact bundles the store already holds, whether still staged or already
 * renamed, never from a second signing: {@link #held} reads such a bundle back.
 *
 * <p>The store holds no lock. Its one coordinator serializes every call. Host only: the device
 * keeps restoration bundles in system DE storage, which step D7 owns.
 */
public final class ArtifactStore {
    /** Named points of publication, for host fault injection. Production passes none. */
    public interface Steps {
        void at(String step) throws IOException;
    }

    /** Checks one staged bundle before anything is published. Returns null when it passes. */
    public interface Verifier {
        String verify(Staged bundle);
    }

    /** Publication's points, in order. Bundle renames repeat for each bundle. */
    public static final List<String> STEPS = List.of("verified", "bundle-renamed", "bundles-synced", "staged",
            "synced", "renamed", "parent-synced");

    /** What one bundle ID shows a reader. */
    public enum Presence { PUBLISHED, ABSENT, MISMATCH, UNAVAILABLE }

    /** One bundle staged privately. Its bytes are what the manifest names. */
    public static final class Staged {
        public final String id;
        public final Manifest manifest;
        final byte[] manifestBytes;
        final byte[] apk;
        final byte[] idsig;

        Staged(Manifest manifest, byte[] manifestBytes, byte[] apk, byte[] idsig) {
            this.id = DeploymentRecords.sha256Hex(manifestBytes);
            this.manifest = manifest;
            this.manifestBytes = manifestBytes;
            this.apk = apk;
            this.idsig = idsig;
        }

        public byte[] apk() { return apk.clone(); }

        public byte[] idsig() { return idsig.clone(); }
    }

    static final String MANIFEST_FILE = "manifest.rec";
    static final String APK_FILE = "base.apk";
    static final String IDSIG_FILE = "base.apk.idsig";
    private static final List<String> MEMBERS = List.of(APK_FILE, IDSIG_FILE, MANIFEST_FILE);
    private static final String SUFFIX = ".rec";
    private static final String STAGING = ".staging";
    /** No member is larger. A SystemUI APK is about 30 MB. */
    static final long MAX_MEMBER = 256L << 20;

    private final Path root;
    private final String installation;
    private final Steps steps;
    private final boolean sync;

    public ArtifactStore(Path root, String installation) {
        this(root, installation, step -> { }, true);
    }

    ArtifactStore(Path root, String installation, Steps steps, boolean sync) {
        this.root = Objects.requireNonNull(root, "root");
        DeploymentRecords.checkId(installation, "installation", false);
        this.installation = installation;
        this.steps = Objects.requireNonNull(steps, "steps");
        this.sync = sync;
    }

    /** Creates the root, bundles and publications, owner only, and syncs each parent. */
    public void initialize() throws IOException {
        directory(root);
        directory(bundles());
        directory(publications());
    }

    private Path bundles() { return root.resolve("bundles"); }

    private Path publications() { return root.resolve("publications"); }

    private Path bundle(String id) { return bundles().resolve(id); }

    private Path publicationFile(String plan) { return publications().resolve(plan + SUFFIX); }

    private void directory(Path path) throws IOException {
        Node node = node(path);
        if (node == Node.DIRECTORY) return;
        if (node != Node.ABSENT) throw new IOException("store path is not a directory");
        Files.createDirectory(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        if (sync) syncDirectory(path.getParent());
    }

    // ------------------------------------------------------------------ staging

    /**
     * Stages one bundle privately: each member written and synced through its own descriptor,
     * then the staging directory synced. Returns null when the members do not match the manifest
     * or staging fails. Staging publishes nothing.
     */
    public Staged stage(Manifest manifest, byte[] apk, byte[] idsig) {
        if (!installation.equals(manifest.installation)) return null;
        if (apk.length != manifest.apkBytes || idsig.length != manifest.idsigBytes
                || !DeploymentRecords.sha256Hex(apk).equals(manifest.apk)
                || !DeploymentRecords.sha256Hex(idsig).equals(manifest.idsig)) {
            return null;
        }
        Staged staged = new Staged(manifest, ArtifactRecords.encodeManifest(manifest), apk.clone(), idsig.clone());
        Path dir = root.resolve(STAGING + "-" + staged.id);
        try {
            if (node(root) != Node.DIRECTORY) return null;
            clear(dir); // An earlier stager's copy is never a bundle.
            Files.createDirectory(dir, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            writeNew(dir.resolve(APK_FILE), staged.apk);
            writeNew(dir.resolve(IDSIG_FILE), staged.idsig);
            writeNew(dir.resolve(MANIFEST_FILE), staged.manifestBytes);
            if (sync) syncDirectory(dir);
            if (sync) syncDirectory(root);
            return exact(dir, staged) ? staged : null;
        } catch (IOException | RuntimeException error) {
            return null;
        }
    }

    private void clear(Path dir) throws IOException {
        Node node = node(dir);
        if (node == Node.ABSENT) return;
        if (node != Node.DIRECTORY) throw new IOException("staging path is not a directory");
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(dir)) {
            for (Path entry : entries) {
                if (node(entry) != Node.FILE) throw new IOException("staging holds a non file");
                Files.delete(entry);
            }
        }
        Files.delete(dir);
    }

    private void writeNew(Path path, byte[] bytes) throws IOException {
        try (FileChannel out = FileChannel.open(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) out.write(buffer);
            if (sync) out.force(true);
        }
    }

    // ------------------------------------------------------------------ publication

    /**
     * Publishes the plan's bundles together: the variant, and its restoration when the plan has
     * one. Each bundle must be signed from the plan's input for its role in this plan, at the plan's
     * versionCode, by the plan's signer, in the transaction the publication names for it, which is
     * the bundle's own. A plan that signs names the bundles it signed, each in its signing role. A
     * plan that signs nothing is only decision 3's restoration plan: it names the plan it repairs,
     * and publishes one bundle in its VARIANT role, which was signed as RESTORATION and which the
     * publication of the plan it repairs binds in its RESTORATION role. Every bundle is verified
     * again before anything is renamed or written. True
     * only when the publication reads back with every bundle PUBLISHED. When the plan already has a
     * publication, nothing is written: the result is whether it reads back as exactly this one.
     */
    public boolean publish(Plan plan, Publication publication, List<Staged> staged, Verifier verifier) {
        if (!installation.equals(publication.installation) || !publication.plan.equals(plan.planId)
                || !publication.component.equals(plan.component) || plan.target == Target.FACTORY) {
            return false;
        }
        // Decision 3: a plan that signs nothing names the plan it repairs and publishes one bundle.
        if (plan.signing == 0 && (plan.repairs.equals(DeploymentRecords.NO_ID) || plan.hasRestoration())) {
            return false;
        }
        // Decision 8: the variant and its restoration are published together or not at all.
        List<String> inputs = new ArrayList<>();
        inputs.add(plan.bundleInput);
        if (plan.hasRestoration()) inputs.add(plan.restorationInput);
        if (publication.bundles.size() != inputs.size()) return false; // Never one bundle alone.
        if (staged.size() != publication.bundles.size()) return false;
        for (int i = 0; i < staged.size(); i++) {
            Staged b = staged.get(i);
            Manifest m = b.manifest;
            long version = i == 0 ? plan.bundleVersion : plan.restorationVersion;
            // Each bundle fills the role it was signed in, except the restoration plan's one bundle,
            // signed as RESTORATION. No bundle signed as a variant fills a RESTORATION role.
            boolean role = m.role == (plan.signing == 0 ? Role.RESTORATION : Publication.roleAt(i));
            if (!b.id.equals(publication.bundles.get(i)) || !role || !m.certificate.equals(plan.signer)
                    || !m.component.equals(plan.component) || !m.inputEntries.equals(inputs.get(i))
                    || m.versionCode != version || !m.transaction.equals(publication.transactions.get(i))) {
                return false;
            }
        }
        byte[] bytes = ArtifactRecords.encodePublication(publication);
        Path index = publicationFile(plan.planId);
        Read current = readRaw(index);
        if (current.found != Node.ABSENT) {
            // Resolved by reading, never by publishing again.
            return current.found == Node.FILE && Arrays.equals(current.bytes, bytes) && visible(publication);
        }
        if (plan.signing == 0) {
            // The publication of the plan it repairs reads back PUBLISHED and binds this same bundle
            // in its RESTORATION role: the pair was published together first.
            Publication repaired = publication(plan.repairs);
            if (planPublication(plan.repairs) != Presence.PUBLISHED || repaired == null
                    || repaired.bundles.size() != 2 || !repaired.bundles.get(1).equals(staged.get(0).id)) {
                return false;
            }
        }
        try {
            for (Staged b : staged) {
                // The private copy, or the exact bundle already under bundles/<id>: renamed by an earlier
                // attempt that no record names, or published by another plan's record.
                if (!exact(root.resolve(STAGING + "-" + b.id), b) && !exact(bundle(b.id), b)) return false;
                String reason = verifier.verify(b);
                if (reason != null) return false;
            }
            steps.at("verified");
            for (Staged b : staged) place(b);
            if (sync) syncDirectory(bundles());
            steps.at("bundles-synced");
            if (!write(index, bytes)) return false; // Visible from here.
            return visible(publication);
        } catch (IOException | RuntimeException error) {
            // Retain every copy: the outcome is resolved by reading the exact bytes.
            return false;
        }
    }

    // Renames one staged bundle into bundles/<id>. A bundle already there with the exact bytes is
    // the same content, because its name is its manifest's digest, and its staging copy goes.
    private void place(Staged b) throws IOException {
        Path staging = root.resolve(STAGING + "-" + b.id);
        Path target = bundle(b.id);
        Node there = node(target);
        if (there == Node.DIRECTORY && exact(target, b)) {
            clear(staging);
        } else if (there == Node.ABSENT) {
            Files.move(staging, target, StandardCopyOption.ATOMIC_MOVE);
        } else {
            throw new IOException("a different bundle under its ID");
        }
        steps.at("bundle-renamed");
    }

    // The deployment store's write protocol, for a record that must be absent.
    private boolean write(Path target, byte[] bytes) throws IOException {
        Path parent = target.getParent();
        Path staging = parent.resolve("." + target.getFileName() + STAGING);
        if (node(parent) != Node.DIRECTORY || node(target) != Node.ABSENT) return false;
        Node leftover = node(staging);
        if (leftover == Node.FILE) {
            Files.delete(staging);
        } else if (leftover != Node.ABSENT) {
            return false;
        }
        try (FileChannel out = FileChannel.open(staging, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) out.write(buffer);
            steps.at("staged");
            if (sync) out.force(true);
        }
        steps.at("synced");
        Read staged = readRaw(staging);
        if (staged.found != Node.FILE || !Arrays.equals(staged.bytes, bytes)) return false;
        Files.move(staging, target, StandardCopyOption.ATOMIC_MOVE);
        steps.at("renamed");
        if (sync) syncDirectory(parent);
        steps.at("parent-synced");
        Read written = readRaw(target);
        return written.found == Node.FILE && Arrays.equals(written.bytes, bytes);
    }

    private boolean visible(Publication p) {
        for (String id : p.bundles) if (presence(id) != Presence.PUBLISHED) return false;
        return true;
    }

    /**
     * A bundle the store already holds, read back as staged: its private copy, or its directory
     * under {@code bundles/}, holding exactly the manifest with this ID and the members it names.
     * Null when it holds neither. This is how a second publication completes without the bytes
     * being supplied again, and never by signing again.
     */
    public Staged held(String id) {
        DeploymentRecords.checkDigest(id, "bundle", false);
        for (Path dir : List.of(root.resolve(STAGING + "-" + id), bundle(id))) {
            if (node(dir) != Node.DIRECTORY) continue;
            Read manifest = readRaw(dir.resolve(MANIFEST_FILE));
            Read apk = readRaw(dir.resolve(APK_FILE));
            Read idsig = readRaw(dir.resolve(IDSIG_FILE));
            if (manifest.found != Node.FILE || apk.found != Node.FILE || idsig.found != Node.FILE) continue;
            if (!DeploymentRecords.sha256Hex(manifest.bytes).equals(id)) continue;
            try {
                Manifest m = ArtifactRecords.decodeManifest(manifest.bytes);
                Staged b = new Staged(m, manifest.bytes, apk.bytes, idsig.bytes);
                if (installation.equals(m.installation) && apk.bytes.length == m.apkBytes
                        && idsig.bytes.length == m.idsigBytes && DeploymentRecords.sha256Hex(apk.bytes).equals(m.apk)
                        && DeploymentRecords.sha256Hex(idsig.bytes).equals(m.idsig) && exact(dir, b)) {
                    return b;
                }
            } catch (IllegalArgumentException damaged) {
                // Not this copy.
            }
        }
        return null;
    }

    /**
     * What a reader sees of one plan's publication: PUBLISHED when its record reads back and every
     * bundle it names is PUBLISHED, ABSENT when no record exists, MISMATCH when the record names
     * another plan or a bundle reads back other bytes, and UNAVAILABLE when the record or a bundle
     * cannot be read, or is damaged or newer. Read after a PUBLISH call has ended, ABSENT shows that
     * the call had no effect, because the record's rename is the single commit point.
     */
    public Presence planPublication(String plan) {
        DeploymentRecords.checkId(plan, "plan", false);
        Read raw = readRaw(publicationFile(plan));
        if (raw.found == Node.ABSENT) return Presence.ABSENT;
        if (raw.found != Node.FILE) return Presence.UNAVAILABLE;
        Publication p;
        try {
            p = ArtifactRecords.decodePublication(raw.bytes);
        } catch (IllegalArgumentException damagedOrNewer) {
            return Presence.UNAVAILABLE;
        }
        if (!p.plan.equals(plan) || !p.installation.equals(installation)) return Presence.MISMATCH;
        Presence result = Presence.PUBLISHED;
        for (String id : p.bundles) {
            Presence each = presence(id);
            if (each == Presence.UNAVAILABLE) return Presence.UNAVAILABLE;
            if (each != Presence.PUBLISHED) result = Presence.MISMATCH;
        }
        return result;
    }

    // ------------------------------------------------------------------ reads

    /**
     * What a reader sees of one bundle ID. PUBLISHED: a publication names it and its directory
     * holds exactly the manifest and members whose digests and sizes the manifest names.
     * ABSENT: no publication names it, whatever its directory holds. MISMATCH: a publication names
     * it and the bytes differ, are missing or hold more. UNAVAILABLE: a publication or the bundle
     * could not be read, or a damaged or newer publication might name it.
     */
    public Presence presence(String id) {
        DeploymentRecords.checkDigest(id, "bundle", false);
        Boolean named = named(id);
        if (named == null) return Presence.UNAVAILABLE;
        if (!named) return Presence.ABSENT;
        Path dir = bundle(id);
        Node node = node(dir);
        if (node == Node.UNKNOWN) return Presence.UNAVAILABLE;
        if (node != Node.DIRECTORY) return Presence.MISMATCH;
        try {
            Set<String> names = new TreeSet<>();
            try (DirectoryStream<Path> entries = Files.newDirectoryStream(dir)) {
                for (Path entry : entries) names.add(entry.getFileName().toString());
            }
            if (!names.equals(new TreeSet<>(MEMBERS))) return Presence.MISMATCH;
            Read manifest = readRaw(dir.resolve(MANIFEST_FILE));
            if (manifest.found == Node.UNKNOWN) return Presence.UNAVAILABLE;
            if (manifest.found != Node.FILE || !DeploymentRecords.sha256Hex(manifest.bytes).equals(id)) {
                return Presence.MISMATCH;
            }
            Manifest m = ArtifactRecords.decodeManifest(manifest.bytes);
            Read apk = readRaw(dir.resolve(APK_FILE));
            Read idsig = readRaw(dir.resolve(IDSIG_FILE));
            if (apk.found == Node.UNKNOWN || idsig.found == Node.UNKNOWN) return Presence.UNAVAILABLE;
            boolean exact = apk.found == Node.FILE && idsig.found == Node.FILE && apk.bytes.length == m.apkBytes
                    && idsig.bytes.length == m.idsigBytes && DeploymentRecords.sha256Hex(apk.bytes).equals(m.apk)
                    && DeploymentRecords.sha256Hex(idsig.bytes).equals(m.idsig);
            return exact ? Presence.PUBLISHED : Presence.MISMATCH;
        } catch (IllegalArgumentException damaged) {
            return Presence.MISMATCH;
        } catch (IOException | RuntimeException unavailable) {
            return Presence.UNAVAILABLE;
        }
    }

    /**
     * The base.apk digests of the bundles that a plan's PUBLISHED publication binds to its roles:
     * the VARIANT role first, then the RESTORATION role when it names one. A BUNDLE_PUBLISHED fact
     * carries them, because a plan cannot know its signed output. Null unless the publication reads
     * PUBLISHED.
     */
    public List<String> apks(String plan) {
        if (planPublication(plan) != Presence.PUBLISHED) return null;
        Publication p = publication(plan);
        if (p == null) return null;
        List<String> result = new ArrayList<>();
        for (String id : p.bundles) {
            Read manifest = readRaw(bundle(id).resolve(MANIFEST_FILE));
            if (manifest.found != Node.FILE || !DeploymentRecords.sha256Hex(manifest.bytes).equals(id)) return null;
            try {
                result.add(ArtifactRecords.decodeManifest(manifest.bytes).apk);
            } catch (IllegalArgumentException damaged) {
                return null;
            }
        }
        return result;
    }

    /** The members of a PUBLISHED bundle, base.apk then base.apk.idsig, or null. */
    public List<byte[]> members(String id) {
        if (presence(id) != Presence.PUBLISHED) return null;
        Read apk = readRaw(bundle(id).resolve(APK_FILE));
        Read idsig = readRaw(bundle(id).resolve(IDSIG_FILE));
        if (apk.found != Node.FILE || idsig.found != Node.FILE) return null;
        return List.of(apk.bytes, idsig.bytes);
    }

    /** The publication of one plan, or null when it is absent or cannot be read as version 1. */
    public Publication publication(String plan) {
        Read raw = readRaw(publicationFile(plan));
        if (raw.found != Node.FILE) return null;
        try {
            Publication p = ArtifactRecords.decodePublication(raw.bytes);
            return p.plan.equals(plan) && p.installation.equals(installation) ? p : null;
        } catch (IllegalArgumentException damaged) {
            return null;
        }
    }

    // Whether any publication names the bundle: null when one cannot be read, is damaged or is
    // newer, because it might.
    private Boolean named(String id) {
        if (node(publications()) != Node.DIRECTORY) return null;
        List<String> names = new ArrayList<>();
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(publications())) {
            for (Path entry : entries) names.add(entry.getFileName().toString());
        } catch (IOException | RuntimeException unavailable) {
            return null;
        }
        boolean named = false;
        for (String name : names) {
            if (name.startsWith(".") && name.endsWith(STAGING)) continue; // Never a record.
            if (!name.endsWith(SUFFIX)) return null;
            Read raw = readRaw(publications().resolve(name));
            if (raw.found != Node.FILE) return null;
            try {
                Publication p = ArtifactRecords.decodePublication(raw.bytes);
                if (!(p.plan + SUFFIX).equals(name) || !p.installation.equals(installation)) return null;
                named |= p.bundles.contains(id);
            } catch (IllegalArgumentException damagedOrNewer) {
                return null;
            }
        }
        return named;
    }

    // Whether a directory holds exactly the staged bundle's three files.
    private static boolean exact(Path dir, Staged b) {
        if (node(dir) != Node.DIRECTORY) return false;
        Set<String> names = new TreeSet<>();
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(dir)) {
            for (Path entry : entries) names.add(entry.getFileName().toString());
        } catch (IOException | RuntimeException unavailable) {
            return false;
        }
        if (!names.equals(new TreeSet<>(MEMBERS))) return false;
        Read manifest = readRaw(dir.resolve(MANIFEST_FILE));
        Read apk = readRaw(dir.resolve(APK_FILE));
        Read idsig = readRaw(dir.resolve(IDSIG_FILE));
        return manifest.found == Node.FILE && apk.found == Node.FILE && idsig.found == Node.FILE
                && Arrays.equals(manifest.bytes, b.manifestBytes) && Arrays.equals(apk.bytes, b.apk)
                && Arrays.equals(idsig.bytes, b.idsig);
    }

    private static void syncDirectory(Path directory) throws IOException {
        if (node(directory) != Node.DIRECTORY) throw new IOException("parent is not a directory");
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        }
    }

    private enum Node { ABSENT, FILE, DIRECTORY, OTHER, UNKNOWN }

    private static Node node(Path path) {
        try {
            BasicFileAttributes attributes = Files.readAttributes(path, BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS);
            if (attributes.isRegularFile()) return Node.FILE;
            return attributes.isDirectory() ? Node.DIRECTORY : Node.OTHER;
        } catch (NoSuchFileException absent) {
            return Node.ABSENT;
        } catch (IOException | RuntimeException unknown) {
            return Node.UNKNOWN;
        }
    }

    private static final class Read {
        final Node found;
        final byte[] bytes;

        Read(Node found, byte[] bytes) {
            this.found = found;
            this.bytes = bytes;
        }
    }

    // The bytes of one regular file within the member bound. A link or special node is OTHER.
    private static Read readRaw(Path path) {
        Node node = node(path);
        if (node != Node.FILE) return new Read(node, null);
        try (InputStream in = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
            byte[] bytes = in.readNBytes((int) Math.min(Integer.MAX_VALUE - 8, MAX_MEMBER + 1));
            if (bytes.length > MAX_MEMBER) return new Read(Node.OTHER, null);
            return new Read(Node.FILE, bytes);
        } catch (IOException | RuntimeException unavailable) {
            return new Read(Node.UNKNOWN, null);
        }
    }
}
