// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.signingcustody;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.AbstractExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;

/** Real host apksig integration with a SOFTWARE fixture backend, not Android authentication. */
public final class ArtifactEngineTest {
    private enum Mode { SIGN, DECLINE, CANCEL_SIGNING, CANCEL_AFTER_SIGNATURE }
    private static PrivateKey key;
    private static byte[] certificate;
    private static String certificateHash;
    private static int signatures;

    private static void need(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }

    private static ArtifactRequest request(String id, byte[] apk) throws Exception {
        ApkArtifactSigner.Metadata metadata = ApkArtifactSigner.inspect(apk);
        return new ArtifactRequest(id, 2000, 0, metadata.packageName, metadata.versionCode,
                certificateHash, ApkArtifactSigner.sha256(apk), apk);
    }

    private static ApkArtifactSigner.Backend backend(Mode mode) {
        return (artifact, signature) -> {
            need(artifact.signatureRequest() == signature && artifact.workerOwned()
                    && artifact.workerStarted() && artifact.state() == ArtifactRequest.State.AWAITING_SIGNATURE,
                    "exact captured child and live worker");
            need(signature.purpose().equals(ArtifactRequest.PURPOSE), "artifact purpose");
            if (mode == Mode.DECLINE) {
                artifact.cancel(); signature.cancel(); return;
            }
            // Deliberate host test stand-in only. These model calls authenticate nobody.
            need(signature.beginAuthentication() && signature.claimSigning(), "software fixture transitions");
            if (mode == Mode.CANCEL_SIGNING) {
                need(artifact.cancel() && signature.cancel(), "cancel before backend finishes");
                need(signature.state() == SigningRequest.State.SIGNING && artifact.workerOwned(),
                        "cancellation did not release accepted signing or artifact worker");
            }
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(key); signer.update(signature.payload()); byte[] bytes = signer.sign(); signatures++;
            need(signature.complete(bytes), "software signature completion consumed");
            if (mode == Mode.CANCEL_AFTER_SIGNATURE) {
                need(artifact.cancel() && !signature.cancel(), "cannot undo the generated signature");
            }
        };
    }

    private static void cancelled(ArtifactRequest request, Mode mode) throws Exception {
        boolean rejected = false;
        int before = signatures;
        try { ApkArtifactSigner.execute(request, certificate, backend(mode)); }
        catch (java.security.SignatureException expected) { rejected = true; }
        need(rejected && request.state() == ArtifactRequest.State.CANCELLED
                && !request.workerOwned() && request.output() == null, "cancelled result retired without APK");
        need(signatures - before == (mode == Mode.DECLINE ? 0 : 1),
                "APK cancellation must not be mistaken for no generated signature");
    }

    private static final class Executor extends AbstractExecutorService {
        enum Behavior { QUEUE, REJECT, ACCEPT_THEN_THROW }
        final ArrayDeque<Runnable> queue = new ArrayDeque<>();
        final Behavior behavior;
        Executor(Behavior behavior) { this.behavior = behavior; }
        @Override public void execute(Runnable work) {
            if (behavior == Behavior.REJECT) throw new RejectedExecutionException("known rejection");
            queue.add(work);
            if (behavior == Behavior.ACCEPT_THEN_THROW) throw new IllegalStateException("unknown submission");
        }
        @Override public void shutdown() { }
        @Override public List<Runnable> shutdownNow() { return List.of(); }
        @Override public boolean isShutdown() { return false; }
        @Override public boolean isTerminated() { return false; }
        @Override public boolean awaitTermination(long timeout, TimeUnit unit) { return false; }
    }

    private static void coordinator(byte[] apk) throws Exception {
        Executor queued = new Executor(Executor.Behavior.QUEUE);
        ArtifactCoordinator coordinator = new ArtifactCoordinator(queued);
        ArtifactRequest first = request("queue.1", apk);
        coordinator.submit(first, certificate, backend(Mode.SIGN));
        need(coordinator.ownsWork() && first.workerOwned() && !first.workerStarted(), "queued ticket reserved");
        for (ArtifactRequest duplicate : List.of(first, request("queue.1", apk))) {
            try {
                coordinator.submit(duplicate, certificate, backend(Mode.SIGN));
                throw new AssertionError("duplicate submission accepted");
            } catch (IllegalStateException expected) { }
            need(first.workerOwned() && first.state() == ArtifactRequest.State.PREPARING
                    && queued.queue.size() == 1, "duplicate did not fail or retire original ticket");
            if (duplicate != first) need(!duplicate.workerOwned(), "unregistered candidate retired");
        }
        need(first.cancel() && coordinator.ownsWork(), "queued cancellation retains ticket");
        queued.queue.remove().run();
        need(first.state() == ArtifactRequest.State.CANCELLED && !coordinator.ownsWork(), "real queued cleanup retired");

        ArtifactCoordinator rejection = new ArtifactCoordinator(new Executor(Executor.Behavior.REJECT));
        ArtifactRequest rejected = request("reject.1", apk);
        rejection.submit(rejected, certificate, backend(Mode.SIGN));
        need(rejected.state() == ArtifactRequest.State.FAILED && !rejected.workerOwned()
                && !rejected.workerStarted(), "contractual rejection did not create a worker");

        Executor uncertainExecutor = new Executor(Executor.Behavior.ACCEPT_THEN_THROW);
        ArtifactCoordinator uncertain = new ArtifactCoordinator(uncertainExecutor);
        ArtifactRequest unknown = request("unknown.1", apk);
        try {
            uncertain.submit(unknown, certificate, backend(Mode.SIGN));
            throw new AssertionError("expected unknown executor failure");
        } catch (IllegalStateException expected) { }
        need(uncertain.ownsWork() && unknown.workerOwned() && uncertainExecutor.queue.size() == 1,
                "arbitrary executor exception must not retire an accepted task");
        need(unknown.cancel(), "cancel unresolved submission");
        uncertainExecutor.queue.remove().run();
        need(unknown.state() == ArtifactRequest.State.CANCELLED && !unknown.workerOwned(),
                "retire only after the actual queued worker finishes");
    }

    private static void run(String[] args) throws Exception {
        need(args.length == 2, "owned fixture APK and output directory");
        Path input = Path.of(args[0]);
        need(Files.size(input) > 0 && Files.size(input) <= ApkArtifactSigner.MAX_APK, "fixture APK bound");
        byte[] apk = Files.readAllBytes(input);
        DataInputStream frame = new DataInputStream(System.in);
        need(Arrays.equals(frame.readNBytes(8), new byte[]{'A','N','D','R','K','0','0','1'})
                && frame.readInt() == 1, "private input frame");
        int keyLength = frame.readInt(), certificateLength = frame.readInt();
        need(keyLength > 0 && keyLength <= 65536 && certificateLength > 0 && certificateLength <= 65536,
                "private input bounds");
        byte[] encoded = frame.readNBytes(keyLength); certificate = frame.readNBytes(certificateLength);
        need(encoded.length == keyLength && certificate.length == certificateLength && frame.read() == -1,
                "complete private frame");
        key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
        Arrays.fill(encoded, (byte) 0); // Not comprehensive provider or heap erasure.
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certificate));
        need(Arrays.equals(cert.getEncoded(), certificate), "exact certificate bytes");
        certificateHash = ApkArtifactSigner.sha256(certificate);

        byte[] caller = apk.clone(); ArtifactRequest positive = request("sign.1", caller);
        Arrays.fill(caller, (byte) 0);
        need(ApkArtifactSigner.execute(positive, certificate, backend(Mode.SIGN)), "worker claimed");
        need(positive.state() == ArtifactRequest.State.COMPLETE && !positive.workerOwned()
                && signatures == 1 && positive.output() != null, "verified APK and worker retirement");
        byte[] signed = positive.output(); signed[0] ^= 1;
        need(signed[0] != positive.output()[0], "published output is a defensive copy");
        need(!ApkArtifactSigner.execute(positive, certificate, backend(Mode.SIGN)), "completed job not replayed");
        Files.write(Path.of(args[1]).resolve("signed-artifact.apk"), positive.output(), StandardOpenOption.CREATE_NEW);
        cancelled(request("decline.1", apk), Mode.DECLINE);
        cancelled(request("cancel-sign.1", apk), Mode.CANCEL_SIGNING);
        cancelled(request("cancel-complete.1", apk), Mode.CANCEL_AFTER_SIGNATURE);

        ApkArtifactSigner.Metadata metadata = ApkArtifactSigner.inspect(apk);
        ArtifactRequest wrong = new ArtifactRequest("wrong-package.1", 2000, 0, "different.package", 1,
                certificateHash, ApkArtifactSigner.sha256(apk), apk);
        int before = signatures;
        try {
            ApkArtifactSigner.execute(wrong, certificate, backend(Mode.SIGN));
            throw new AssertionError("wrong package metadata accepted");
        } catch (IllegalArgumentException expected) { }
        need(wrong.state() == ArtifactRequest.State.FAILED && !wrong.workerOwned()
                && wrong.output() == null && signatures == before, "bad metadata refused before backend");
        coordinator(apk);
        System.out.println("ARTIFACT_ENGINE_HOST_PASS package=" + metadata.packageName
                + " version=" + metadata.versionCode + " signed_sha256="
                + ApkArtifactSigner.sha256(positive.output()) + " cancellation_cases=3"
                + " coordinator_rejection_duplicate_unknown_controls=true");
        System.out.println("NO_ANDROID_AUTHENTICATION_OR_PROTECTED_ARTIFACT_SIGNING_CLAIM");
    }

    public static void main(String[] args) {
        try { run(args); }
        catch (Throwable error) {
            System.err.println("ARTIFACT_ENGINE_HOST_FAILURE " + error.getClass().getName());
            System.exit(1);
        }
    }
}
