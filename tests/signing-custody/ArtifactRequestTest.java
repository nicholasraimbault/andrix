// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.signingcustody;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Host bookkeeping controls. Synthetic bytes establish no APK or signing validity. */
public final class ArtifactRequestTest {
    private static final String ID = "artifact.1";
    private static final int UID = 2000;
    private static final int USER = 10;
    private static final String PACKAGE = "dev.andrix.proof.disposable";
    private static final long VERSION = 7;
    private static final String CERT = "a".repeat(64);
    private static final byte[] APK = {1, 0, 2};
    private static final String HASH =
            "16305a6b2292e931665a34089864ee3fcc24171c81551f152cf4d1db0dd6122d";
    private static final int ROUNDS = 200;
    private static final int WAIT_SECONDS = 5;

    private static void need(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }

    private static void invalid(Runnable operation) {
        try {
            operation.run();
            throw new AssertionError("expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) { }
    }

    private static String hash(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static ArtifactRequest request() {
        return new ArtifactRequest(ID, UID, USER, PACKAGE, VERSION, CERT, HASH, APK);
    }

    private static SigningRequest child(String id, int uid, int user, String purpose, String cert) {
        // Signature payload is deliberately distinct from the outer APK snapshot.
        return new SigningRequest(id, uid, user, purpose, cert, new byte[]{6, 7});
    }

    private static SigningRequest child() {
        return child(ID, UID, USER, ArtifactRequest.PURPOSE, CERT);
    }

    private static ArtifactRequest atStage(int stage) {
        ArtifactRequest r = request();
        if (stage >= 1) need(r.claimWorker(), "claim worker");
        if (stage >= 2) need(r.attachSignature(child()), "attach child");
        if (stage >= 3) need(r.beginFinalizing(), "trusted worker begins finalizing");
        return r;
    }

    private static void lateCallbacks(ArtifactRequest r) {
        need(!r.claimWorker() && !r.attachSignature(child()) && !r.attachSignature(null),
                "terminal request cannot claim or attach");
        need(!r.beginFinalizing() && !r.completeVerifiedOutput(null)
                && !r.completeVerifiedOutput(new byte[0])
                && !r.completeVerifiedOutput(new byte[]{9}), "late completion is ignored");
        need(!r.fail() && !r.cancel(), "terminal result cannot be changed");
    }

    private static void retire(ArtifactRequest r) {
        ArtifactRequest.State state = r.state();
        boolean started = r.workerStarted();
        boolean cancelled = r.cancellationRequested();
        SigningRequest inner = r.signatureRequest();
        byte[] output = r.output();
        need(r.workerOwned() && r.retireWorker(), "terminal ownership retires once");
        need(!r.workerOwned() && !r.retireWorker(), "retired ticket cannot retire again");
        lateCallbacks(r);
        need(r.state() == state && r.workerStarted() == started
                && r.cancellationRequested() == cancelled && r.signatureRequest() == inner
                && Arrays.equals(r.output(), output), "retirement preserves the result and history");
    }

    private static void inputValidationAndCopies() {
        need(ArtifactRequest.PURPOSE.equals("sign-disposable-apk-v2")
                && ArtifactRequest.MIN_SDK_VERSION == 37
                && ArtifactRequest.SIGNING_SCHEME.equals("v2"), "fixed lab signing scope");
        need(ArtifactRequest.MAX_APK_BYTES == 1024 * 1024
                && ArtifactRequest.MAX_OUTPUT_BYTES == 2 * 1024 * 1024, "fixed lab byte bounds");
        byte[] input = APK.clone();
        ArtifactRequest r = new ArtifactRequest(ID, UID, USER, PACKAGE, VERSION, CERT, HASH, input);
        input[0] = 9;
        need(Arrays.equals(r.apk(), APK), "constructor owns its snapshot");
        byte[] read = r.apk();
        read[1] = 9;
        need(Arrays.equals(r.apk(), APK) && r.artifactSha256().equals(HASH), "defensive APK getter");
        need(r.id().equals(ID) && r.requesterUid() == UID && r.androidUser() == USER
                && r.packageName().equals(PACKAGE) && r.versionCode() == VERSION
                && r.certificateSha256().equals(CERT), "exact immutable metadata");
        need(r.state() == ArtifactRequest.State.PREPARING && !r.cancellationRequested()
                && r.workerOwned() && !r.workerStarted() && r.signatureRequest() == null
                && r.output() == null, "ticket reserved before publication or worker start");
        invalid(() -> new ArtifactRequest(ID, UID, USER, PACKAGE, VERSION, CERT, HASH, input));
        invalid(() -> new ArtifactRequest(ID, UID, USER, PACKAGE, VERSION, CERT,
                "b".repeat(64), APK));

        for (String bad : new String[]{null, "", " \t\r\n", "\u2003"}) {
            invalid(() -> new ArtifactRequest(bad, UID, USER, PACKAGE, VERSION, CERT, HASH, APK));
            invalid(() -> new ArtifactRequest(ID, UID, USER, bad, VERSION, CERT, HASH, APK));
        }
        invalid(() -> new ArtifactRequest("x".repeat(ArtifactRequest.MAX_REQUEST_ID_CHARS + 1),
                UID, USER, PACKAGE, VERSION, CERT, HASH, APK));
        invalid(() -> new ArtifactRequest(ID, UID, USER,
                "p".repeat(ArtifactRequest.MAX_PACKAGE_NAME_CHARS + 1), VERSION, CERT, HASH, APK));
        invalid(() -> new ArtifactRequest(ID, -1, USER, PACKAGE, VERSION, CERT, HASH, APK));
        invalid(() -> new ArtifactRequest(ID, UID, -1, PACKAGE, VERSION, CERT, HASH, APK));
        for (long bad : new long[]{0, -1, Long.MIN_VALUE}) {
            invalid(() -> new ArtifactRequest(ID, UID, USER, PACKAGE, bad, CERT, HASH, APK));
        }
        for (String bad : new String[]{null, "", "a".repeat(63), "a".repeat(65),
                "A".repeat(64), "g".repeat(64), " ".repeat(64), "a".repeat(63) + "\n"}) {
            invalid(() -> new ArtifactRequest(ID, UID, USER, PACKAGE, VERSION, bad, HASH, APK));
            invalid(() -> new ArtifactRequest(ID, UID, USER, PACKAGE, VERSION, CERT, bad, APK));
        }
        invalid(() -> new ArtifactRequest(ID, UID, USER, PACKAGE, VERSION, CERT, HASH, null));
        for (byte[] bad : new byte[][]{new byte[0], new byte[ArtifactRequest.MAX_APK_BYTES + 1]}) {
            String correctHash = hash(bad);
            invalid(() -> new ArtifactRequest(ID, UID, USER, PACKAGE, VERSION, CERT, correctHash, bad));
        }

        byte[] largest = new byte[ArtifactRequest.MAX_APK_BYTES];
        largest[largest.length - 1] = 42;
        ArtifactRequest maximum = new ArtifactRequest("i".repeat(ArtifactRequest.MAX_REQUEST_ID_CHARS),
                Integer.MAX_VALUE, Integer.MAX_VALUE, "p".repeat(ArtifactRequest.MAX_PACKAGE_NAME_CHARS),
                Long.MAX_VALUE, "0".repeat(64), hash(largest), largest);
        need(Arrays.equals(maximum.apk(), largest) && maximum.artifactSha256().equals(hash(largest))
                && maximum.id().length() == ArtifactRequest.MAX_REQUEST_ID_CHARS
                && maximum.packageName().length() == ArtifactRequest.MAX_PACKAGE_NAME_CHARS
                && maximum.requesterUid() == Integer.MAX_VALUE && maximum.androidUser() == Integer.MAX_VALUE
                && maximum.versionCode() == Long.MAX_VALUE, "inclusive input and metadata maxima");
        byte[] smallest = {0};
        ArtifactRequest minimum = new ArtifactRequest("i", 0, 0, "p", 1, CERT, hash(smallest), smallest);
        need(minimum.apk().length == 1 && minimum.requesterUid() == 0 && minimum.androidUser() == 0
                && minimum.versionCode() == 1, "inclusive input and metadata minima");
    }

    private static void childBinding() {
        ArtifactRequest r = request();
        SigningRequest exact = child();
        need(!r.attachSignature(exact) && !r.attachSignature(null), "cannot attach before worker claim");
        need(r.claimWorker(), "claim before binding");
        for (SigningRequest wrong : new SigningRequest[]{null,
                child("other", UID, USER, ArtifactRequest.PURPOSE, CERT),
                child(ID, UID + 1, USER, ArtifactRequest.PURPOSE, CERT),
                child(ID, UID, USER + 1, ArtifactRequest.PURPOSE, CERT),
                child(ID, UID, USER, ArtifactRequest.PURPOSE, "b".repeat(64)),
                child(ID, UID, USER, "sign-probe", CERT)}) {
            need(!r.attachSignature(wrong), "reject mismatched child metadata");
            need(r.signatureRequest() == null && r.state() == ArtifactRequest.State.PREPARING
                    && r.workerOwned() && r.workerStarted(), "rejected child leaves stage and ticket intact");
        }
        need(r.attachSignature(exact) && r.signatureRequest() == exact, "store exact child object");
        need(!r.attachSignature(exact) && !r.attachSignature(child())
                && r.signatureRequest() == exact, "child cannot be attached twice or replaced");
        need(exact.state() == SigningRequest.State.PENDING, "attachment grants no authentication");
        need(r.cancel() && exact.state() == SigningRequest.State.PENDING, "outer cancellation does not call child");
        SigningRequest stored = r.signatureRequest();
        need(stored.cancel(), "caller propagates to stored child outside artifact monitor");
        need(r.state() == ArtifactRequest.State.AWAITING_SIGNATURE && r.workerOwned(),
                "inner cancellation is not outer worker exit");
        need(r.fail() && r.state() == ArtifactRequest.State.CANCELLED, "worker consumes cancellation");
        retire(r);
    }

    private static void stagesAndOutput() {
        ArtifactRequest r = request();
        need(!r.beginFinalizing() && !r.completeVerifiedOutput(null) && !r.retireWorker(),
                "unclaimed request cannot finalize, complete or retire");
        need(r.claimWorker() && !r.claimWorker(), "worker starts exactly once");
        need(!r.beginFinalizing() && !r.completeVerifiedOutput(null) && !r.retireWorker(),
                "preparation cannot finalize, complete or retire");
        SigningRequest exact = child();
        need(r.attachSignature(exact), "preparation attaches child");
        need(r.state() == ArtifactRequest.State.AWAITING_SIGNATURE && !r.claimWorker()
                && !r.completeVerifiedOutput(null) && !r.retireWorker(), "awaiting signature stage");
        need(r.beginFinalizing() && !r.beginFinalizing(), "trusted worker begins finalizing once");
        need(exact.state() == SigningRequest.State.PENDING, "model does not perform or authenticate signing");
        need(r.state() == ArtifactRequest.State.FINALIZING && !r.claimWorker()
                && !r.attachSignature(child()) && !r.retireWorker() && r.output() == null,
                "finalizing still owns worker and withholds output");
        for (byte[] bad : new byte[][]{null, new byte[0], new byte[ArtifactRequest.MAX_OUTPUT_BYTES + 1]}) {
            invalid(() -> r.completeVerifiedOutput(bad));
            need(r.state() == ArtifactRequest.State.FINALIZING && r.output() == null
                    && r.workerOwned(), "malformed current output does not consume completion");
        }
        byte[] output = {3, 4};
        need(r.completeVerifiedOutput(output), "valid current output consumed");
        output[0] = 9;
        need(Arrays.equals(r.output(), new byte[]{3, 4}), "completion owns output copy");
        byte[] read = r.output();
        read[1] = 9;
        need(Arrays.equals(r.output(), new byte[]{3, 4}), "defensive output getter");
        need(r.state() == ArtifactRequest.State.COMPLETE && r.workerOwned() && r.workerStarted()
                && !r.cancellationRequested() && r.signatureRequest() == exact, "publication retains worker");
        lateCallbacks(r);
        need(!r.cancellationRequested() && Arrays.equals(r.output(), new byte[]{3, 4}),
                "published output cannot be undone by cancel");
        retire(r);

        ArtifactRequest maximum = atStage(3);
        byte[] largest = new byte[ArtifactRequest.MAX_OUTPUT_BYTES];
        largest[largest.length - 1] = 42;
        need(maximum.completeVerifiedOutput(largest) && maximum.output().length == largest.length
                && maximum.output()[largest.length - 1] == 42, "inclusive output maximum");
        retire(maximum);
        ArtifactRequest minimum = atStage(3);
        need(minimum.completeVerifiedOutput(new byte[]{0}) && minimum.output().length == 1,
                "inclusive output minimum");
        retire(minimum);
    }

    private static void cancellationAndFailure() {
        for (int stage = 0; stage <= 3; stage++) {
            ArtifactRequest failed = atStage(stage);
            need(failed.fail() && failed.state() == ArtifactRequest.State.FAILED
                    && failed.workerOwned() && failed.workerStarted() == (stage > 0)
                    && failed.output() == null && !failed.cancellationRequested(), "failure consumes active stage");
            lateCallbacks(failed);
            retire(failed);

            ArtifactRequest cancelled = atStage(stage);
            ArtifactRequest.State before = cancelled.state();
            need(cancelled.cancel() && !cancelled.cancel() && cancelled.cancellationRequested(),
                    "first cancellation only");
            need(cancelled.state() == before && cancelled.workerOwned()
                    && cancelled.workerStarted() == (stage > 0) && cancelled.output() == null
                    && !cancelled.retireWorker(), "cancellation is not completion or worker exit");
            if (stage == 0) {
                need(cancelled.claimWorker() && !cancelled.claimWorker(),
                        "real queued worker can claim cancelled ticket once for cleanup");
            }
            need(!cancelled.attachSignature(child()) && !cancelled.beginFinalizing(),
                    "cancelled worker cannot attach or begin finalizing");
            need(cancelled.fail() && cancelled.state() == ArtifactRequest.State.CANCELLED
                    && cancelled.workerOwned(), "failure after cancellation consumes as cancelled");
            lateCallbacks(cancelled);
            retire(cancelled);
        }

        ArtifactRequest removedFromQueue = request();
        need(removedFromQueue.cancel() && removedFromQueue.fail() && !removedFromQueue.workerStarted()
                && removedFromQueue.workerOwned(), "queue cleanup can consume without starting worker");
        retire(removedFromQueue);

        ArtifactRequest cancelledOutput = atStage(3);
        need(cancelledOutput.cancel(), "cancel before output completion");
        invalid(() -> cancelledOutput.completeVerifiedOutput(null));
        need(cancelledOutput.state() == ArtifactRequest.State.FINALIZING && cancelledOutput.workerOwned(),
                "invalid cancelled result is still unconsumed");
        need(cancelledOutput.completeVerifiedOutput(new byte[]{8})
                && cancelledOutput.state() == ArtifactRequest.State.CANCELLED
                && cancelledOutput.output() == null && cancelledOutput.workerOwned(),
                "completion consumes cancellation without publishing or retiring");
        lateCallbacks(cancelledOutput);
        retire(cancelledOutput);
    }

    private static void await(CountDownLatch latch) {
        try {
            need(latch.await(WAIT_SECONDS, TimeUnit.SECONDS), "bounded latch wait");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError(e);
        }
    }

    private static Thread task(String name, Runnable operation, AtomicReference<Throwable> failure) {
        Thread thread = new Thread(() -> {
            try {
                operation.run();
            } catch (Throwable thrown) {
                failure.compareAndSet(null, thrown);
            }
        }, name);
        thread.setDaemon(true); // A regression must not leave the test JVM stuck on a deadlock.
        thread.start();
        return thread;
    }

    private static void join(Thread thread) throws InterruptedException {
        thread.join(TimeUnit.SECONDS.toMillis(WAIT_SECONDS));
        need(!thread.isAlive(), "bounded thread join: " + thread.getName());
    }

    private static void checkFailure(AtomicReference<Throwable> failure) {
        if (failure.get() != null) throw new AssertionError("concurrent operation failed", failure.get());
    }

    private static void race(Runnable first, Runnable second) throws InterruptedException {
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread left = task("artifact-first", () -> { ready.countDown(); await(start); first.run(); }, failure);
        Thread right = task("artifact-second", () -> { ready.countDown(); await(start); second.run(); }, failure);
        await(ready);
        start.countDown();
        join(left);
        join(right);
        checkFailure(failure);
    }

    private static void childLockOrdering() throws InterruptedException {
        ArtifactRequest r = atStage(1);
        SigningRequest inner = child();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread attaching;
        synchronized (inner) {
            attaching = task("artifact-child-metadata", () -> need(!r.attachSignature(inner),
                    "cancellation wins while metadata read waits"), failure);
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(WAIT_SECONDS);
            while (attaching.isAlive() && attaching.getState() != Thread.State.BLOCKED
                    && System.nanoTime() < deadline) {
                Thread.sleep(1);
            }
            need(attaching.getState() == Thread.State.BLOCKED, "attachment waits for child metadata monitor");
            Thread cancelling = task("artifact-cancel-with-child-locked", () -> need(r.cancel(),
                    "metadata read does not hold artifact monitor"), failure);
            join(cancelling);
            checkFailure(failure);
        }
        join(attaching);
        checkFailure(failure);
        need(r.signatureRequest() == null && r.state() == ArtifactRequest.State.PREPARING
                && r.workerOwned() && inner.state() == SigningRequest.State.PENDING, "lock ordering preserves state");
        need(r.fail(), "consume cancelled preparation");
        retire(r);
    }

    private static void attachCancelRaces() throws InterruptedException {
        for (int round = 0; round < ROUNDS; round++) {
            ArtifactRequest r = atStage(1);
            SigningRequest inner = child();
            AtomicBoolean attached = new AtomicBoolean();
            AtomicBoolean cancelled = new AtomicBoolean();
            race(() -> attached.set(r.attachSignature(inner)), () -> cancelled.set(r.cancel()));
            need(cancelled.get() && r.cancellationRequested() && r.workerOwned() && r.workerStarted()
                    && r.output() == null && !r.retireWorker(), "attach/cancel retains worker ownership");
            need(r.state() == (attached.get() ? ArtifactRequest.State.AWAITING_SIGNATURE
                    : ArtifactRequest.State.PREPARING), "attach/cancel stage reflects winning transition");
            need(r.signatureRequest() == (attached.get() ? inner : null)
                    && inner.state() == SigningRequest.State.PENDING, "exact child, no automatic child cancellation");
            need(!r.claimWorker() && !r.attachSignature(inner) && !r.beginFinalizing()
                    && !r.completeVerifiedOutput(null), "cancelled request cannot advance");
            SigningRequest stored = r.signatureRequest();
            if (stored != null) need(stored.cancel(), "caller propagates cancellation after race");
            need(r.fail() && r.state() == ArtifactRequest.State.CANCELLED && r.workerOwned(),
                    "worker consumes raced cancellation");
            retire(r);
        }
    }

    private static void completeCancelRaces() throws InterruptedException {
        for (int round = 0; round < ROUNDS; round++) {
            ArtifactRequest r = atStage(3);
            AtomicBoolean consumed = new AtomicBoolean();
            AtomicBoolean cancelled = new AtomicBoolean();
            byte[] output = {8, 9};
            race(() -> consumed.set(r.completeVerifiedOutput(output)), () -> cancelled.set(r.cancel()));
            need(consumed.get() && r.workerOwned() && r.workerStarted(), "raced completion consumed, not retired");
            need(r.cancellationRequested() == cancelled.get(), "only effective cancellation is recorded");
            if (cancelled.get()) {
                need(r.state() == ArtifactRequest.State.CANCELLED && r.output() == null,
                        "cancel before completion withholds output");
            } else {
                need(r.state() == ArtifactRequest.State.COMPLETE && Arrays.equals(r.output(), output),
                        "completion before cancel preserves output");
            }
            lateCallbacks(r);
            retire(r);
        }
    }

    public static void main(String[] args) throws Exception {
        inputValidationAndCopies();
        childBinding();
        stagesAndOutput();
        cancellationAndFailure();
        childLockOrdering();
        attachCancelRaces();
        completeCancelRaces();
        System.out.println("ARTIFACT_REQUEST_MODEL_PASS races=400 attach_cancel_rounds=200"
                + " complete_cancel_rounds=200 no_Android_or_protected_signing_claim");
    }
}
