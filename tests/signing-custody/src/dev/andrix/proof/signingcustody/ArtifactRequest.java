// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.signingcustody;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Finite LAB artifact bookkeeping, separate from the inner Signature request.
 * Owns an immutable input snapshot, but does not parse or authenticate an APK,
 * its package/version metadata, a caller or an owner. The trusted broker supplies
 * observed identity and parser metadata. Attaching a child grants no approval.
 * Do not expose these transition methods as an untrusted authorization API.
 *
 * Worker ownership is reserved at construction, before external publication or
 * queueing. Cancellation records intent, not worker exit. Backend calls, blocking,
 * authentication, signing and output verification belong outside this monitor.
 * The caller must propagate cancellation to the stored child outside this monitor
 * and retire ownership only when the real worker or queue cleanup has retired.
 * Only construction hashes bytes, before publication and without a monitor.
 *
 * The SDK, scheme and size/text limits are fixed proof scope, not product policy.
 */
public final class ArtifactRequest {
    public static final String PURPOSE = "sign-disposable-apk-v2";
    public static final int MIN_SDK_VERSION = 37;
    public static final String SIGNING_SCHEME = "v2";
    public static final int MAX_REQUEST_ID_CHARS = SigningRequest.MAX_REQUEST_ID_CHARS;
    public static final int MAX_PACKAGE_NAME_CHARS = 255;
    public static final int MAX_APK_BYTES = 1024 * 1024;
    public static final int MAX_OUTPUT_BYTES = 2 * 1024 * 1024;

    public enum State { PREPARING, AWAITING_SIGNATURE, FINALIZING, COMPLETE, CANCELLED, FAILED }

    private final String requestId;
    private final int requesterUid;
    private final int requesterUserId;
    private final String packageName;
    private final long versionCode;
    private final String certificateSha256;
    private final String artifactSha256;
    private final byte[] apk;
    private State state = State.PREPARING;
    private boolean cancellationRequested;
    private boolean workerOwned = true;
    private boolean workerStarted;
    private SigningRequest signatureRequest;
    private byte[] output;

    /**
     * Copies the bounded, nonempty input and hashes that owned copy. Both digest
     * inputs must be canonical lowercase SHA256; the expected artifact digest must
     * match the copy. Package and version remain trusted parser metadata, not facts
     * established by this class. No package syntax or APK format is checked here.
     *
     * @throws IllegalArgumentException if any input is absent, invalid or mismatched
     */
    public ArtifactRequest(String id, int requesterUid, int androidUser, String packageName,
            long versionCode, String certificateSha256, String expectedArtifactSha256, byte[] apk) {
        requireText(id, MAX_REQUEST_ID_CHARS, "request ID");
        requireText(packageName, MAX_PACKAGE_NAME_CHARS, "package name");
        requireDigest(certificateSha256, "certificate SHA256");
        requireDigest(expectedArtifactSha256, "expected artifact SHA256");
        if (requesterUid < 0 || androidUser < 0) {
            throw new IllegalArgumentException("invalid observed requester identity");
        }
        if (versionCode <= 0) throw new IllegalArgumentException("invalid version code");
        requireBytes(apk, MAX_APK_BYTES, "APK");
        byte[] snapshot = apk.clone();
        String actualSha256 = sha256(snapshot);
        if (!actualSha256.equals(expectedArtifactSha256)) {
            throw new IllegalArgumentException("artifact SHA256 does not match owned APK");
        }
        this.requestId = id;
        this.requesterUid = requesterUid;
        this.requesterUserId = androidUser;
        this.packageName = packageName;
        this.versionCode = versionCode;
        this.certificateSha256 = certificateSha256;
        this.artifactSha256 = actualSha256;
        this.apk = snapshot;
    }

    public String id() { return requestId; }
    public int requesterUid() { return requesterUid; }
    public int androidUser() { return requesterUserId; }
    public String packageName() { return packageName; }
    public long versionCode() { return versionCode; }
    public String certificateSha256() { return certificateSha256; }
    public String artifactSha256() { return artifactSha256; }
    public byte[] apk() { return apk.clone(); }
    public synchronized State state() { return state; }
    public synchronized boolean cancellationRequested() { return cancellationRequested; }
    public synchronized boolean workerOwned() { return workerOwned; }
    public synchronized boolean workerStarted() { return workerStarted; }

    /** Exact stored object, not a replacement request or an authentication result. */
    public synchronized SigningRequest signatureRequest() { return signatureRequest; }

    /** Returns a copy only after the trusted worker has published verified output. */
    public synchronized byte[] output() {
        return state == State.COMPLETE ? output.clone() : null;
    }

    /**
     * Claims the reserved worker once, even after queued cancellation so it can clean
     * up. The worker must check cancellation before doing work. This is not approval.
     */
    public synchronized boolean claimWorker() {
        if (state != State.PREPARING || !workerOwned || workerStarted) return false;
        workerStarted = true;
        return true;
    }

    /**
     * Binds the exact child once. Returns false for null, mismatched metadata or an
     * ineligible stage. Immutable child metadata is read before taking this monitor
     * because SigningRequest getters take the child's monitor. No nested locks or
     * child state transitions are needed, and no authentication is inferred.
     */
    public boolean attachSignature(SigningRequest child) {
        if (child == null) return false;
        String childId = child.id();
        int childUid = child.requesterUid();
        int childUser = child.androidUser();
        String childCertificate = child.certificateSha256();
        String childPurpose = child.purpose();
        synchronized (this) {
            if (state != State.PREPARING || !workerOwned || !workerStarted
                    || cancellationRequested || !requestId.equals(childId)
                    || requesterUid != childUid || requesterUserId != childUser
                    || !certificateSha256.equals(childCertificate) || !PURPOSE.equals(childPurpose)) {
                return false;
            }
            signatureRequest = child;
            state = State.AWAITING_SIGNATURE;
            return true;
        }
    }

    /**
     * Records only the first nonterminal cancellation. Does not change stage, release
     * worker ownership or cancel the child. Propagate to signatureRequest() outside
     * this monitor. Published output and other terminal results cannot be undone.
     */
    public synchronized boolean cancel() {
        if (cancellationRequested || terminal()) return false;
        cancellationRequested = true;
        return true;
    }

    /** Trusted worker only, after actual signing. Does not verify a signature. */
    public synchronized boolean beginFinalizing() {
        if (state != State.AWAITING_SIGNATURE || !workerOwned || !workerStarted
                || cancellationRequested) return false;
        state = State.FINALIZING;
        return true;
    }

    /**
     * Trusted worker only, after actual output verification. Consumes a FINALIZING
     * result, including cancellation that discards it, without retiring the worker.
     * This method validates only byte bounds, not APK contents or signatures. Stale
     * callbacks return false before inspecting arguments. Malformed current output
     * throws without changing state; the worker must fail if it cannot finish.
     */
    public synchronized boolean completeVerifiedOutput(byte[] output) {
        if (state != State.FINALIZING) return false;
        requireBytes(output, MAX_OUTPUT_BYTES, "output APK");
        if (cancellationRequested) {
            state = State.CANCELLED;
        } else {
            this.output = output.clone();
            state = State.COMPLETE;
        }
        return true;
    }

    /** Consumes any nonterminal stage, but does not claim that its worker has exited. */
    public synchronized boolean fail() {
        if (terminal()) return false;
        state = cancellationRequested ? State.CANCELLED : State.FAILED;
        return true;
    }

    /**
     * Releases the reserved ticket exactly once, only after a terminal result. The
     * caller must observe actual worker or queue cleanup retirement, not a timeout.
     */
    public synchronized boolean retireWorker() {
        if (!terminal() || !workerOwned) return false;
        workerOwned = false;
        return true;
    }

    private boolean terminal() {
        return state == State.COMPLETE || state == State.CANCELLED || state == State.FAILED;
    }

    private static void requireText(String value, int maximum, String name) {
        if (value == null || value.length() > maximum || value.isBlank()) {
            throw new IllegalArgumentException("invalid " + name);
        }
    }

    private static void requireDigest(String value, String name) {
        if (value == null || value.length() != 64) {
            throw new IllegalArgumentException("invalid " + name);
        }
        for (int i = 0; i < value.length(); i++) {
            char digit = value.charAt(i);
            if (!(digit >= '0' && digit <= '9') && !(digit >= 'a' && digit <= 'f')) {
                throw new IllegalArgumentException("noncanonical " + name);
            }
        }
    }

    private static void requireBytes(byte[] value, int maximum, String name) {
        if (value == null || value.length == 0 || value.length > maximum) {
            throw new IllegalArgumentException("invalid " + name);
        }
    }

    private static String sha256(byte[] bytes) {
        final byte[] digest;
        try {
            digest = MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError("SHA-256 unavailable", impossible);
        }
        char[] hex = new char[digest.length * 2];
        String alphabet = "0123456789abcdef";
        for (int i = 0; i < digest.length; i++) {
            int value = digest[i] & 0xff;
            hex[i * 2] = alphabet.charAt(value >>> 4);
            hex[i * 2 + 1] = alphabet.charAt(value & 0xf);
        }
        return new String(hex);
    }
}
