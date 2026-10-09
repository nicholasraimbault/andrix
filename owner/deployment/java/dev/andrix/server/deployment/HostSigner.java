// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import dev.andrix.server.deployment.ArtifactRecords.Member;
import dev.andrix.server.deployment.ArtifactRecords.Output;
import dev.andrix.server.deployment.ArtifactRecords.Role;
import dev.andrix.server.deployment.ArtifactRecords.Transaction;
import dev.andrix.server.deployment.ArtifactRecords.TransactionState;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The host signer with the development key: one signing transaction of three key operations for
 * each APK, six for a variant and its restoration (decision 8), under one approval.
 *
 * <p>Its durable record of each transaction, type 8, is written OPEN before the first key
 * operation. It names the transaction, which is the ticket's SIGN request ID, the six operation
 * IDs and the four expected outputs by role and member, with the facts each must meet. Each key
 * operation first asks the captive callback, and a refusal ends the transaction REFUSED with no
 * output kept, even when the engine swallows the callback's exception: the signer latches the
 * refusal, and refuses every later key operation of the transaction without asking. The engine
 * signs each input without its APK Signing Block, and each key operation's result must appear in
 * the output's signing block or its sidecar, so the signatures the outputs carry are this
 * transaction's own. The outputs are retained privately and synced, then the record is replaced
 * once by COMPLETED with their digests and sizes, which is the commit point. A transaction ID that
 * has a record is never signed again: a lost reply is resolved by reading the record by that ID. A
 * read that finds a transaction still OPEN, or no record at all, proves that the request can no
 * longer complete, because calls are serialized and this signer never resumes a transaction: the
 * read records CANNOT_COMPLETE, and the ticket records SIGN_FAILED.
 *
 * <p>Layout under the root: {@code transactions/<id>.rec} and the retained outputs
 * {@code outputs/<id>/<role>/base.apk} and {@code base.apk.idsig}. Host only. The protected device
 * signer is step D8.
 */
public final class HostSigner {
    /** Signs one APK with apksig or a host fake, calling the keys once for each key operation. */
    public interface Engine {
        /** Returns base.apk and base.apk.idsig signed from the input. */
        Signed sign(byte[] input, Keys keys) throws Exception;

        /**
         * Verifies one signed APK and its v4 sidecar: v2 with a pass below SDK 28, v3 and v4 over
         * the declared range, and every signer's certificate and key digests.
         */
        Verification verify(byte[] apk, byte[] idsig, int sdkMin, int sdkMax);

        /** The facts of an APK's own binary manifest, or null when it has none that parses. */
        Facts facts(byte[] apk);
    }

    /** What an APK's binary manifest declares. A maxSdk of 0 means none is declared. */
    public static final class Facts {
        public final String packageName;
        public final long versionCode;
        /** Empty when none is declared. */
        public final String sharedUserId;
        public final boolean persistent;
        public final int minSdk;
        public final int targetSdk;
        public final int maxSdk;

        public Facts(String packageName, long versionCode, String sharedUserId, boolean persistent, int minSdk,
                int targetSdk, int maxSdk) {
            this.packageName = Objects.requireNonNull(packageName, "packageName");
            this.versionCode = versionCode;
            this.sharedUserId = Objects.requireNonNull(sharedUserId, "sharedUserId");
            this.persistent = persistent;
            this.minSdk = minSdk;
            this.targetSdk = targetSdk;
            this.maxSdk = maxSdk;
        }
    }

    /** One key operation with the signing key. */
    public interface Keys {
        byte[] sign(byte[] data, String algorithm) throws GeneralSecurityException;
    }

    /** The captive callback: each key operation of a transaction asks it first, by its index from 1. */
    public interface Approval {
        boolean allow(Transaction transaction, int operation);
    }

    /** One signed APK and its sidecar. */
    public static final class Signed {
        public final byte[] apk;
        public final byte[] idsig;

        public Signed(byte[] apk, byte[] idsig) {
            this.apk = Objects.requireNonNull(apk, "apk").clone();
            this.idsig = Objects.requireNonNull(idsig, "idsig").clone();
        }
    }

    /** What the verifier found. Each scheme is checked explicitly. */
    public static final class Verification {
        public final boolean v2BelowSdk28;
        public final boolean v3;
        public final boolean v4;
        /** Each signer of every scheme as {certificate SHA-256, public key SHA-256}. */
        public final List<String[]> signers;

        public Verification(boolean v2BelowSdk28, boolean v3, boolean v4, List<String[]> signers) {
            this.v2BelowSdk28 = v2BelowSdk28;
            this.v3 = v3;
            this.v4 = v4;
            this.signers = List.copyOf(signers);
        }
    }

    /** The answer to a signing call or a read by transaction ID. */
    public static final class Reply {
        public final Transaction record;

        Reply(Transaction record) { this.record = record; }

        public TransactionState state() { return record.state; }
    }

    private static final class Refused extends Exception {
        private static final long serialVersionUID = 1L;
        final int operation;

        Refused(int operation) { this.operation = operation; }
    }

    private final Path root;
    private final String installation;
    private final Engine engine;
    private final Keys key;
    private final Approval approval;
    private int operations;

    public HostSigner(Path root, String installation, Engine engine, Keys key, Approval approval) {
        this.root = Objects.requireNonNull(root, "root");
        DeploymentRecords.checkId(installation, "installation", false);
        this.installation = installation;
        this.engine = Objects.requireNonNull(engine, "engine");
        this.key = Objects.requireNonNull(key, "key");
        this.approval = Objects.requireNonNull(approval, "approval");
    }

    /** Creates the root and its directories, owner only. */
    public void initialize() throws IOException {
        for (Path p : List.of(root, root.resolve("transactions"), root.resolve("outputs"))) {
            if (node(p) == Node.DIRECTORY) continue;
            Files.createDirectory(p, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            sync(p.getParent());
        }
    }

    /** Key operations this signer performed, for qualification: a second signing would show here. */
    public int operations() { return operations; }

    private Path record(String id) { return root.resolve("transactions").resolve(id + ".rec"); }

    private Path outputs(String id, Role role) {
        return root.resolve("outputs").resolve(id).resolve(role.name().toLowerCase(java.util.Locale.ROOT));
    }

    /**
     * Signs the inputs of an OPEN transaction, one APK for each of its roles. A transaction ID that
     * already has a record is never signed again: the reply is that record. Returns null only when
     * the record cannot be written, before any key operation.
     */
    public Reply sign(Transaction open, Map<Role, byte[]> inputs) {
        if (open.state != TransactionState.OPEN || !open.installation.equals(installation)) {
            throw new IllegalArgumentException("not an OPEN transaction of this installation");
        }
        Transaction existing = read(open.transaction);
        if (existing != null || node(record(open.transaction)) != Node.ABSENT) {
            return existing == null ? null : new Reply(existing); // Resolved by its ID, never signed again.
        }
        byte[] openBytes = ArtifactRecords.encodeTransaction(open);
        try {
            if (!writeNew(record(open.transaction), openBytes)) return null;
        } catch (IOException e) {
            return null;
        }
        List<Output> produced = new ArrayList<>();
        int[] index = {0};
        // The first refused operation. A refusal is latched here, so an engine that swallows the
        // callback's exception still ends the transaction REFUSED, and no key is used after it.
        int[] refused = {0};
        try {
            for (Role role : open.roles()) {
                byte[] input = inputs.get(role);
                if (input == null) throw new IllegalArgumentException("no input for " + role);
                // Signatures the input already carries prove nothing: the engine never sees them.
                byte[] unsigned = ApkEntries.withoutSigningBlock(input);
                int first = index[0];
                List<byte[]> results = new ArrayList<>();
                Signed signed = engine.sign(unsigned, (data, algorithm) -> {
                    int next = ++index[0];
                    if (refused[0] != 0) throw new GeneralSecurityException(new Refused(refused[0]));
                    if (next > first + 3 || next > open.operations.size()) {
                        throw new GeneralSecurityException("more than three key operations for one APK");
                    }
                    if (!approval.allow(open, next)) {
                        refused[0] = next;
                        throw new GeneralSecurityException(new Refused(next));
                    }
                    operations++;
                    byte[] result = key.sign(data, algorithm);
                    results.add(result.clone());
                    return result;
                });
                if (refused[0] != 0) throw new Refused(refused[0]);
                if (index[0] != first + 3) throw new IllegalStateException("an APK signed without its three operations");
                byte[] block = ApkEntries.signingBlock(signed.apk);
                for (byte[] result : results) {
                    if (!contains(block, result) && !contains(signed.idsig, result)) {
                        throw new IllegalStateException("a key operation's result is not in the output");
                    }
                }
                retain(open.transaction, role, signed);
                for (Output o : open.outputs) {
                    if (o.role != role) continue;
                    byte[] bytes = o.member == Member.APK ? signed.apk : signed.idsig;
                    produced.add(o.produced(DeploymentRecords.sha256Hex(bytes), bytes.length));
                }
            }
            return finish(open, openBytes, open.with(TransactionState.COMPLETED, 0, produced));
        } catch (Exception failure) {
            discard(open.transaction);
            Transaction end = refused[0] != 0 ? open.with(TransactionState.REFUSED, refused[0], open.outputs)
                    : open.with(TransactionState.CANNOT_COMPLETE, 0, open.outputs);
            return finish(open, openBytes, end);
        }
    }

    private Reply finish(Transaction open, byte[] openBytes, Transaction end) {
        try {
            if (replace(record(open.transaction), openBytes, ArtifactRecords.encodeTransaction(end))) {
                return new Reply(end);
            }
        } catch (IOException e) {
            // The record stays OPEN, and a read proves that it can no longer complete.
        }
        return null;
    }

    /**
     * The record of one transaction by its ID, as the coordinator reads it after a lost reply. An
     * OPEN record, or none at all, can no longer complete: this read records CANNOT_COMPLETE for it,
     * from the template when there is no record, so a late call with that ID never signs. Returns
     * null when nothing can be read or written.
     */
    public Reply query(String transaction, Transaction template) {
        Transaction t = read(transaction);
        try {
            if (t == null) {
                if (node(record(transaction)) != Node.ABSENT || template == null
                        || !template.transaction.equals(transaction)) {
                    return null;
                }
                Transaction dead = template.with(TransactionState.CANNOT_COMPLETE, 0, template.outputs);
                return writeNew(record(transaction), ArtifactRecords.encodeTransaction(dead)) ? new Reply(dead) : null;
            }
            if (t.state == TransactionState.OPEN) {
                discard(transaction);
                Transaction dead = t.with(TransactionState.CANNOT_COMPLETE, 0, t.outputs);
                return replace(record(transaction), ArtifactRecords.encodeTransaction(t),
                        ArtifactRecords.encodeTransaction(dead)) ? new Reply(dead) : null;
            }
        } catch (IOException e) {
            return null;
        }
        return new Reply(t);
    }

    /** The record of one transaction, or null when it is absent or unreadable. */
    public Transaction read(String transaction) {
        Read r = readRaw(record(transaction));
        if (r.found != Node.FILE) return null;
        try {
            Transaction t = ArtifactRecords.decodeTransaction(r.bytes);
            return t.transaction.equals(transaction) && t.installation.equals(installation) ? t : null;
        } catch (IllegalArgumentException damaged) {
            return null;
        }
    }

    /**
     * The retained outputs of a COMPLETED transaction for one role, checked against the digests
     * and sizes its record names. Null when they are gone or damaged, or the record is not
     * COMPLETED. Nothing is signed again to recover them. Throws UncheckedIOException when a read
     * fails, which proves nothing: a later read may find them.
     */
    public Signed retained(String transaction, Role role) {
        if (readRaw(record(transaction)).found == Node.UNKNOWN) throw unreadable();
        Transaction t = read(transaction);
        if (t == null || t.state != TransactionState.COMPLETED || !t.roles().contains(role)) return null;
        Read apk = readRaw(outputs(transaction, role).resolve(ArtifactStore.APK_FILE));
        Read idsig = readRaw(outputs(transaction, role).resolve(ArtifactStore.IDSIG_FILE));
        if (apk.found == Node.UNKNOWN || idsig.found == Node.UNKNOWN) throw unreadable();
        if (apk.found != Node.FILE || idsig.found != Node.FILE) return null;
        for (Output o : t.outputs) {
            if (o.role != role) continue;
            byte[] bytes = o.member == Member.APK ? apk.bytes : idsig.bytes;
            if (bytes.length != o.bytes || !DeploymentRecords.sha256Hex(bytes).equals(o.digest)) return null;
        }
        return new Signed(apk.bytes, idsig.bytes);
    }

    private static UncheckedIOException unreadable() {
        return new UncheckedIOException(new IOException("a retained output cannot be read"));
    }

    // Whether the bytes hold the needle anywhere.
    private static boolean contains(byte[] bytes, byte[] needle) {
        if (needle.length == 0) return false;
        outer:
        for (int i = 0; i + needle.length <= bytes.length; i++) {
            for (int j = 0; j < needle.length; j++) if (bytes[i + j] != needle[j]) continue outer;
            return true;
        }
        return false;
    }

    private void retain(String transaction, Role role, Signed signed) throws IOException {
        Path dir = outputs(transaction, role);
        Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        writeFile(dir.resolve(ArtifactStore.APK_FILE), signed.apk);
        writeFile(dir.resolve(ArtifactStore.IDSIG_FILE), signed.idsig);
        sync(dir);
        sync(dir.getParent());
        sync(dir.getParent().getParent());
    }

    // No partial output: a transaction that does not complete keeps none of its outputs.
    private void discard(String transaction) {
        Path dir = root.resolve("outputs").resolve(transaction);
        try {
            if (node(dir) != Node.DIRECTORY) return;
            try (var roles = Files.list(dir)) {
                for (Path r : (Iterable<Path>) roles::iterator) {
                    try (var files = Files.list(r)) {
                        for (Path f : (Iterable<Path>) files::iterator) Files.delete(f);
                    }
                    Files.delete(r);
                }
            }
            Files.delete(dir);
            sync(dir.getParent());
        } catch (IOException | RuntimeException ignored) {
            // A leftover is never read: only a COMPLETED record names outputs.
        }
    }

    // ------------------------------------------------------------------ durable files

    private void writeFile(Path path, byte[] bytes) throws IOException {
        try (FileChannel out = FileChannel.open(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) out.write(buffer);
            out.force(true);
        }
    }

    // Writes a record that must be absent: stage, sync, read back, rename, sync the parent, read back.
    private boolean writeNew(Path target, byte[] bytes) throws IOException {
        if (node(target) != Node.ABSENT) return false;
        return put(target, bytes);
    }

    // Replaces a record only from its exact expected bytes.
    private boolean replace(Path target, byte[] expected, byte[] bytes) throws IOException {
        Read current = readRaw(target);
        if (current.found != Node.FILE || !Arrays.equals(current.bytes, expected)) return false;
        return put(target, bytes);
    }

    private boolean put(Path target, byte[] bytes) throws IOException {
        Path staging = target.getParent().resolve("." + target.getFileName() + ".staging");
        if (node(staging) == Node.FILE) Files.delete(staging);
        writeFile(staging, bytes);
        Read staged = readRaw(staging);
        if (staged.found != Node.FILE || !Arrays.equals(staged.bytes, bytes)) return false;
        Files.move(staging, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        sync(target.getParent());
        Read written = readRaw(target);
        return written.found == Node.FILE && Arrays.equals(written.bytes, bytes);
    }

    private static void sync(Path directory) throws IOException {
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        }
    }

    private enum Node { ABSENT, FILE, DIRECTORY, OTHER, UNKNOWN }

    private static Node node(Path path) {
        try {
            BasicFileAttributes a = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (a.isRegularFile()) return Node.FILE;
            return a.isDirectory() ? Node.DIRECTORY : Node.OTHER;
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

    private static Read readRaw(Path path) {
        Node node = node(path);
        if (node != Node.FILE) return new Read(node, null);
        try (InputStream in = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
            byte[] bytes = in.readNBytes((int) Math.min(Integer.MAX_VALUE - 8, ArtifactStore.MAX_MEMBER + 1));
            if (bytes.length > ArtifactStore.MAX_MEMBER) return new Read(Node.OTHER, null);
            return new Read(Node.FILE, bytes);
        } catch (IOException | RuntimeException unavailable) {
            return new Read(Node.UNKNOWN, null);
        }
    }
}
