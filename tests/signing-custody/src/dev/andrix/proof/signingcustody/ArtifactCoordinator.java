// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.signingcustody;

import org.json.JSONArray;
import org.json.JSONObject;
import java.util.LinkedHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

/** Lab artifact ledger. Never calls the backend while holding its monitor. */
final class ArtifactCoordinator {
    private final LinkedHashMap<String, ArtifactRequest> requests = new LinkedHashMap<>();
    private final LinkedHashMap<String, String> failures = new LinkedHashMap<>();
    // Separate from the key signing executor, whose result this worker awaits.
    private final ExecutorService worker;

    ArtifactCoordinator() { this(Executors.newSingleThreadExecutor()); }
    ArtifactCoordinator(ExecutorService worker) {
        if (worker == null) throw new IllegalArgumentException("artifact executor");
        this.worker = worker;
    }

    synchronized boolean ownsWork() {
        for (ArtifactRequest request : requests.values()) if (request.workerOwned()) return true;
        return false;
    }

    synchronized ArtifactRequest find(String id) { return requests.get(id); }

    void submit(ArtifactRequest request, byte[] certificate, ApkArtifactSigner.Backend backend) {
        final byte[] certificateCopy;
        try {
            if (certificate == null || backend == null) throw new IllegalArgumentException("artifact backend");
            certificateCopy = certificate.clone();
            synchronized (this) {
                if (ownsWork() || requests.size() >= 4 || requests.containsKey(request.id())) {
                    throw new IllegalStateException("artifact capacity or live worker");
                }
                requests.put(request.id(), request);
            }
        } catch (RuntimeException | Error unsubmitted) {
            // No executor call has occurred in this invocation. A duplicate
            // call must not retire an object already registered by another call.
            synchronized (this) {
                if (requests.get(request.id()) != request) {
                    request.fail(); request.retireWorker();
                }
            }
            throw unsubmitted;
        }
        try {
            worker.execute(() -> {
                try {
                    if (!ApkArtifactSigner.execute(request, certificateCopy, backend)) {
                        recordFailure(request, new IllegalStateException("worker claim refused"));
                    }
                } catch (Throwable failure) { recordFailure(request, failure); }
            });
        } catch (RejectedExecutionException rejected) {
            // A contractual rejection establishes no queued worker was accepted.
            request.fail();
            if (!request.retireWorker()) throw new IllegalStateException("unqueued artifact ticket");
            recordFailure(request, rejected);
        } catch (RuntimeException | Error uncertain) {
            // Do not equate an arbitrary executor failure with nonacceptance.
            // Keep the registered ticket owned for inspection or broker loss.
            recordFailure(request, uncertain);
            throw uncertain;
        }
    }

    private synchronized void recordFailure(ArtifactRequest request, Throwable failure) {
        StringBuilder classes = new StringBuilder();
        for (int count = 0; failure != null && count < 8; count++, failure = failure.getCause()) {
            if (count != 0) classes.append(" <- ");
            classes.append(failure.getClass().getName());
        }
        failures.put(request.id(), classes.toString());
    }

    synchronized JSONObject status(ArtifactRequest request) throws Exception {
        if (requests.get(request.id()) != request) throw new IllegalStateException("stale artifact");
        synchronized (request) {
            byte[] output = request.output();
            SigningRequest signature = request.signatureRequest();
            return new JSONObject().put("id", request.id()).put("requester_uid", request.requesterUid())
                    .put("user", request.androidUser()).put("purpose", ArtifactRequest.PURPOSE)
                    .put("package", request.packageName()).put("version_code", request.versionCode())
                    .put("input_sha256", request.artifactSha256()).put("input_bytes", request.apk().length)
                    .put("certificate_sha256", request.certificateSha256()).put("scheme", "v2")
                    .put("min_sdk", 37).put("target_sdk", 37)
                    .put("state", request.state().name()).put("cancel_requested", request.cancellationRequested())
                    .put("worker_owned", request.workerOwned()).put("worker_started", request.workerStarted())
                    // Attachment checked this immutable ID. Do not acquire the
                    // child's monitor while holding the artifact/coordinator locks.
                    .put("signature_request", signature == null ? JSONObject.NULL : request.id())
                    .put("output_bytes", output == null ? 0 : output.length)
                    .put("output_sha256", output == null ? JSONObject.NULL : ApkArtifactSigner.sha256(output))
                    .put("failure_classes", failures.containsKey(request.id())
                            ? failures.get(request.id()) : JSONObject.NULL);
        }
    }

    synchronized JSONArray status() throws Exception {
        JSONArray rows = new JSONArray();
        for (ArtifactRequest request : requests.values()) rows.put(status(request));
        return rows;
    }
}
