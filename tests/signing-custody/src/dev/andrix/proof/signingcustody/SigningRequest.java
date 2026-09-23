// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.signingcustody;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Finite LAB request bookkeeping, not an authentication or authorization boundary.
 * The trusted broker supplies a unique request ID it generated, observes the requester
 * UID and Android user, selects the purpose and certificate, and binds real authentication
 * to this exact request before calling claimSigning(). This object authenticates none of
 * those inputs, callers or UI. Requester PID is not authorization and is not stored.
 * Do not expose these transition methods as an untrusted approval API.
 *
 * SIGNING retains ownership until the real operation calls complete() or fail(), even
 * after cancellation. Callers must perform authentication, signing and other backend
 * work outside this object's monitor. No such callbacks are made here. Only the
 * constructor computes a digest, before publication and without holding the monitor.
 * Limits below bound this lab vehicle, not a general signing service or product policy.
 */
public final class SigningRequest {
    public static final int MAX_REQUEST_ID_CHARS = 128;
    public static final int MAX_PURPOSE_CHARS = 1024;
    public static final int MAX_PAYLOAD_BYTES = 64 * 1024;
    public static final int MAX_SIGNATURE_BYTES = 16 * 1024;

    public enum State { PENDING, AUTHENTICATING, SIGNING, COMPLETE, CANCELLED, FAILED }

    private final String requestId;
    private final int requesterUid;
    private final int requesterUserId;
    private final String purpose;
    private final String certificateSha256;
    private final byte[] payload;
    private final String payloadSha256;
    private State state = State.PENDING;
    private boolean cancellationRequested;
    private byte[] signature;

    /**
     * Copies a nonempty payload and hashes that copy. Digests use 64 lowercase hex
     * characters. IDs and purposes must be nonblank and within their character limits;
     * observed UID and user must be nonnegative. No Android identity is inferred here.
     *
     * @throws IllegalArgumentException if any supplied field is absent or invalid
     */
    public SigningRequest(String requestId, int requesterUid, int requesterUserId,
            String purpose, String certificateSha256, byte[] payload) {
        requireText(requestId, MAX_REQUEST_ID_CHARS, "request ID");
        requireText(purpose, MAX_PURPOSE_CHARS, "purpose");
        requireDigest(certificateSha256);
        if (requesterUid < 0 || requesterUserId < 0) {
            throw new IllegalArgumentException("invalid observed requester identity");
        }
        requireBytes(payload, MAX_PAYLOAD_BYTES, "payload");
        this.requestId = requestId;
        this.requesterUid = requesterUid;
        this.requesterUserId = requesterUserId;
        this.purpose = purpose;
        this.certificateSha256 = certificateSha256;
        this.payload = payload.clone();
        this.payloadSha256 = sha256(this.payload);
    }

    public synchronized String id() { return requestId; }
    public synchronized int requesterUid() { return requesterUid; }
    public synchronized int androidUser() { return requesterUserId; }
    public synchronized String purpose() { return purpose; }
    public synchronized String certificateSha256() { return certificateSha256; }
    public synchronized String payloadSha256() { return payloadSha256; }
    public synchronized byte[] payload() { return payload.clone(); }
    public synchronized State state() { return state; }
    public synchronized boolean cancellationRequested() { return cancellationRequested; }

    /** Returns a copy of the public signature only after successful publication. */
    public synchronized byte[] signature() {
        return state == State.COMPLETE ? signature.clone() : null;
    }

    public synchronized boolean beginAuthentication() {
        if (state != State.PENDING) return false;
        state = State.AUTHENTICATING;
        return true;
    }

    /** Trusted broker only, after actual authentication of this request. Claims once. */
    public synchronized boolean claimSigning() {
        if (state != State.AUTHENTICATING) return false;
        state = State.SIGNING;
        return true;
    }

    /**
     * Returns true for the first effective cancellation. Cancellation during SIGNING
     * suppresses publication but cannot claim that the backend operation has finished.
     * Terminal results, including a published signature, cannot be undone.
     */
    public synchronized boolean cancel() {
        if (cancellationRequested || state == State.COMPLETE || state == State.CANCELLED
                || state == State.FAILED) return false;
        cancellationRequested = true;
        if (state != State.SIGNING) state = State.CANCELLED;
        return true;
    }

    /**
     * Consumes only a real SIGNING operation. Returns true when consumed, including
     * when cancellation discards the result. Stale callbacks return false before
     * inspecting their arguments. A malformed current result throws without changing
     * state; the broker must call fail() when its operation cannot supply a valid result.
     * This stores bounded public bytes, not proof of their cryptographic validity.
     */
    public synchronized boolean complete(byte[] signature) {
        if (state != State.SIGNING) return false;
        requireBytes(signature, MAX_SIGNATURE_BYTES, "signature");
        if (cancellationRequested) {
            state = State.CANCELLED;
        } else {
            this.signature = signature.clone();
            state = State.COMPLETE;
        }
        return true;
    }

    /** Fails any active stage. An operation cancelled in flight finishes CANCELLED. */
    public synchronized boolean fail() {
        if (state == State.COMPLETE || state == State.CANCELLED || state == State.FAILED) {
            return false;
        }
        state = cancellationRequested ? State.CANCELLED : State.FAILED;
        return true;
    }

    private static void requireText(String value, int maximum, String name) {
        if (value == null || value.length() > maximum || value.trim().isEmpty()) {
            throw new IllegalArgumentException("invalid " + name);
        }
    }

    private static void requireDigest(String value) {
        if (value == null || value.length() != 64) {
            throw new IllegalArgumentException("invalid certificate SHA256");
        }
        for (int i = 0; i < value.length(); i++) {
            char digit = value.charAt(i);
            if (!(digit >= '0' && digit <= '9') && !(digit >= 'a' && digit <= 'f')) {
                throw new IllegalArgumentException("noncanonical certificate SHA256");
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
