// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.signingcustody;

import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.AbstractExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.json.JSONObject;

/** Metadata snapshots and lock ordering only, using explicit JSON and signer test shapes. */
public final class CoordinatorStatusTest {
    private static final String CERT = "a".repeat(64);
    private static final class Queued extends AbstractExecutorService {
        Runnable pending;
        @Override public void execute(Runnable task) {
            if (pending != null) throw new AssertionError("unexpected second task");
            pending = task;
        }
        @Override public void shutdown() { }
        @Override public List<Runnable> shutdownNow() { return List.of(); }
        @Override public boolean isShutdown() { return false; }
        @Override public boolean isTerminated() { return false; }
        @Override public boolean awaitTermination(long timeout, TimeUnit unit) { return false; }
    }
    private static void need(boolean value) { if (!value) throw new AssertionError(); }
    private static ArtifactRequest create() throws Exception {
        byte[] input = {1, 2};
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(input));
        return new ArtifactRequest("status.1", 2000, 0, "test.fixture", 1, CERT, hash, input);
    }
    private static SigningRequest attach(ArtifactRequest artifact) {
        need(artifact.claimWorker());
        SigningRequest child = new SigningRequest(artifact.id(), 2000, 0,
                ArtifactRequest.PURPOSE, CERT, new byte[]{4, 5});
        need(artifact.attachSignature(child));
        return child;
    }
    private static Thread task(Runnable run, AtomicReference<Throwable> failure) {
        Thread thread = new Thread(() -> {
            try { run.run(); } catch (Throwable error) { failure.compareAndSet(null, error); }
        });
        thread.setDaemon(true); thread.start(); return thread;
    }
    private static void joined(Thread thread, AtomicReference<Throwable> failure) throws Exception {
        thread.join(5000); need(!thread.isAlive());
        if (failure.get() != null) throw new AssertionError(failure.get());
    }
    public static void main(String[] args) throws Exception {
        Queued queue = new Queued(); ArtifactCoordinator coordinator = new ArtifactCoordinator(queue);
        ArtifactRequest artifact = create(); coordinator.submit(artifact, new byte[]{1}, (a, s) -> {});
        SigningRequest child = attach(artifact); AtomicReference<Throwable> failure = new AtomicReference<>();
        // Holding the child's monitor must not block a coordinator metadata read.
        // Otherwise a broker holding that child and waiting for this coordinator
        // can deadlock with a status observer holding the coordinator first.
        synchronized (child) {
            Thread observer = task(() -> {
                try { need(coordinator.status(artifact).get("signature_request").equals(artifact.id())); }
                catch (Exception error) { throw new AssertionError(error); }
            }, failure);
            joined(observer, failure);
        }
        need(artifact.fail() && artifact.retireWorker()); queue.pending = null;
        for (int round = 0; round < 200; round++) {
            Queued executor = new Queued(); ArtifactCoordinator ledger = new ArtifactCoordinator(executor);
            ArtifactRequest request = create(); ledger.submit(request, new byte[]{1}, (a, s) -> {});
            attach(request); need(request.beginFinalizing());
            CountDownLatch start = new CountDownLatch(1); AtomicReference<Throwable> errors = new AtomicReference<>();
            Thread completion = task(() -> {
                try { need(start.await(5, TimeUnit.SECONDS)); }
                catch (InterruptedException error) { throw new AssertionError(error); }
                need(request.completeVerifiedOutput(new byte[]{8, 9, 10})); need(request.retireWorker());
            }, errors);
            start.countDown();
            for (int observation = 0; observation < 5; observation++) {
                JSONObject row = ledger.status(request);
                if (row.get("state").equals("COMPLETE")) {
                    need(row.get("output_bytes").equals(3)); need(row.get("output_sha256") != JSONObject.NULL);
                } else {
                    need(row.get("state").equals("FINALIZING")); need(row.get("output_bytes").equals(0));
                    need(row.get("output_sha256") == JSONObject.NULL);
                }
            }
            joined(completion, errors); need(!ledger.ownsWork()); executor.pending = null;
        }
        System.out.println("ARTIFACT_METADATA_PASS atomic_snapshot_rounds=200 no_child_monitor_under_coordinator no_APK_or_JSON_runtime_claim");
    }
}
