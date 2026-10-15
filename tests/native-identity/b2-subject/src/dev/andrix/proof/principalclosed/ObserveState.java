// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.principalclosed;

import android.Manifest;
import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.PersistableBundle;
import android.util.Base64;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.json.JSONObject;

/** Selected state is only read or used here. Never asks NotificationManager for preferences. */
final class ObserveState {
    static final String[] PAYLOAD_FIELDS = {
        "version", "operation", "nonce", "setup", "contract_sha256", "phase",
        "guest_binding_sha256", "package", "uid", "user_serial", "apk_signer_sha256",
        "pid", "elapsed_ms", "user_unlocked", "key0_existed_before", "key1_existed_before",
        "ce_existed_before", "de_existed_before", "intent_existed_before", "key0_sha256",
        "key1_sha256", "ce_sha256", "de_sha256", "intent_sha256", "post_notifications_granted",
        "job_id", "job_namespace", "job_service", "job_persisted", "job_periodic",
        "job_min_latency_ms", "job_max_delay_ms", "job_setup", "job_contract_sha256",
        "stage", "passed"
    };
    static byte[] payload(JSONObject result) throws Exception {
        StringBuilder text = new StringBuilder("andrix-b2-state-v1\n");
        for (String field : PAYLOAD_FIELDS) {
            text.append(field).append('=').append(result.get(field).toString()).append('\n');
        }
        return Contract.ascii(text.toString());
    }
    static JobInfo job(Context context, Contract request) throws Exception {
        JobScheduler scheduler = context.getSystemService(JobScheduler.class);
        Map<String, List<JobInfo>> all = scheduler.getPendingJobsInAllNamespaces();
        if (all.size() != 1 || !all.containsKey(null) || all.get(null).size() != 1) {
            throw new IllegalStateException("job identity or namespace count");
        }
        JobInfo job = scheduler.getPendingJob(Contract.JOB_ID);
        if (job == null || all.get(null).get(0).getId() != Contract.JOB_ID
                || job.getId() != Contract.JOB_ID
                || !new ComponentName(Contract.PACKAGE, Contract.SERVICE).equals(job.getService())
                || !job.isPersisted() || job.isPeriodic() || job.getMinLatencyMillis() <= 0
                || job.getMinLatencyMillis() > Contract.LATENCY + 60000
                || job.getMaxExecutionDelayMillis() != 0 || job.isExpedited() || job.isUserInitiated()
                || job.isPrefetch() || job.isImportantWhileForeground()
                || job.getRequiredNetwork() != null || job.getClipData() != null
                || job.getTriggerContentUris() != null || !job.getTransientExtras().isEmpty()
                || job.isRequireCharging() || job.isRequireDeviceIdle()
                || job.isRequireBatteryNotLow() || job.isRequireStorageNotLow()
                || job.getPriority() != JobInfo.PRIORITY_DEFAULT || job.getTraceTag() != null
                || !job.getDebugTags().isEmpty()
                || job.getBackoffPolicy() != JobInfo.BACKOFF_POLICY_EXPONENTIAL
                || job.getInitialBackoffMillis() != JobInfo.DEFAULT_INITIAL_BACKOFF_MILLIS) {
            throw new IllegalStateException("job contract");
        }
        PersistableBundle extras = job.getExtras();
        if (!extras.keySet().equals(Set.of("andrix.b2.setup", "andrix.b2.contract_sha256"))
                || !(extras.get("andrix.b2.setup") instanceof String)
                || !(extras.get("andrix.b2.contract_sha256") instanceof String)
                || !request.setup.equals(extras.getString("andrix.b2.setup"))
                || !request.contract.equals(extras.getString("andrix.b2.contract_sha256"))) {
            throw new IllegalStateException("job extras");
        }
        return job;
    }
    static void run(Context context, Contract request, StateFiles files, KeyStore keys,
            JSONObject result) throws Exception {
        files.existing();
        Set<String> aliases = new HashSet<>();
        Enumeration<String> names = keys.aliases();
        while (names.hasMoreElements()) {
            if (aliases.size() >= 16 || !aliases.add(names.nextElement())) {
                throw new IllegalStateException("alias enumeration");
            }
        }
        if (!aliases.equals(Set.of(Contract.ALIASES))) throw new IllegalStateException("key set");
        result.put("ce_sha256", Contract.hash(StateFiles.readExact(files.ce, request.canary(true))));
        result.put("de_sha256", Contract.hash(StateFiles.readExact(files.de, request.canary(false))));
        result.put("intent_sha256", Contract.hash(StateFiles.readExact(files.intent, request.intent())));
        boolean permission = context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                == PackageManager.PERMISSION_GRANTED;
        if (permission != request.operation.equals("observe")) {
            throw new IllegalStateException("secondary permission read");
        }
        result.put("post_notifications_granted", permission);
        JobInfo job = job(context, request);
        result.put("job_id", job.getId()).put("job_namespace", "null")
                .put("job_service", Contract.SERVICE).put("job_persisted", job.isPersisted())
                .put("job_periodic", job.isPeriodic()).put("job_min_latency_ms", job.getMinLatencyMillis())
                .put("job_max_delay_ms", job.getMaxExecutionDelayMillis())
                .put("job_setup", job.getExtras().getString("andrix.b2.setup"))
                .put("job_contract_sha256", job.getExtras().getString("andrix.b2.contract_sha256"));
        PublicKey[] publicKeys = new PublicKey[2];
        for (int i = 0; i < 2; i++) {
            publicKeys[i] = keys.getCertificate(Contract.ALIASES[i]).getPublicKey();
            if (!(publicKeys[i] instanceof ECPublicKey)
                    || ((ECPublicKey) publicKeys[i]).getParams().getCurve().getField().getFieldSize() != 256) {
                throw new IllegalStateException("key type");
            }
            String digest = Contract.hash(publicKeys[i].getEncoded());
            String expected = i == 0 ? request.key0 : request.key1;
            if (expected != null && !digest.equals(expected)) {
                throw new IllegalStateException("original key missing");
            }
            result.put("key" + i + "_sha256", digest).put("key" + i + "_spki_b64",
                    Base64.encodeToString(publicKeys[i].getEncoded(), Base64.NO_WRAP));
        }
        if (result.getString("key0_sha256").equals(result.getString("key1_sha256"))) {
            throw new IllegalStateException("keys not independent");
        }
        result.put("stage", "complete").put("passed", true);
        byte[] payload = payload(result);
        for (int i = 0; i < 2; i++) {
            Signature signing = Signature.getInstance("SHA256withECDSA");
            signing.initSign((PrivateKey) keys.getKey(Contract.ALIASES[i], null));
            signing.update(payload);
            byte[] signature = signing.sign();
            Signature check = Signature.getInstance("SHA256withECDSA");
            check.initVerify(publicKeys[i]); check.update(payload);
            if (!check.verify(signature)) throw new IllegalStateException("signature self check");
            result.put("key" + i + "_signature_b64", Base64.encodeToString(signature, Base64.NO_WRAP));
        }
        files.existing(); // A callback during this observation invalidates it.
    }
}
