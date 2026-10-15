// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.principalclosed;

import android.Manifest;
import android.app.AppOpsManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.PersistableBundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.spec.ECGenParameterSpec;

/** The only normal path allowed to create selected state. No cleanup or retry. */
final class InitializeState {
    static void run(Context context, Contract request, StateFiles files, KeyStore keys)
            throws Exception {
        // All local preconditions precede the first create. Host preflight additionally covers
        // deleted channels, notification preferences, saved permission flags and mode scopes.
        files.preflight();
        if (keys.aliases().hasMoreElements()) throw new IllegalStateException("old key namespace");
        // containsAlias and enumeration can hide provider errors. getKey propagates failures
        // for the selected private key aliases, so unavailability cannot authorize replacement.
        for (String alias : Contract.ALIASES) {
            if (keys.getKey(alias, null) != null || keys.containsAlias(alias)) {
                throw new IllegalStateException("old selected key or certificate");
            }
        }
        JobScheduler scheduler = context.getSystemService(JobScheduler.class);
        if (!scheduler.getPendingJobsInAllNamespaces().isEmpty()) {
            throw new IllegalStateException("old job namespace");
        }
        if (context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_DENIED) throw new IllegalStateException("old grant");
        if (context.getSystemService(AppOpsManager.class).unsafeCheckOpRawNoThrow(
                "android:vibrate", request.uid, Contract.PACKAGE)
                != AppOpsManager.MODE_ALLOWED) throw new IllegalStateException("old app operation");
        NotificationManager notifications = context.getSystemService(NotificationManager.class);
        for (NotificationChannel channel : notifications.getNotificationChannels()) {
            if (!channel.getId().equals("miscellaneous")) {
                throw new IllegalStateException("old channel");
            }
        }
        if (!StateFiles.exists(files.deFiles)) StateFiles.make(files.deFiles);
        StateFiles.make(files.deDir);
        StateFiles.newFile(files.intent, request.intent()); // Intent is durable before keys.
        if (!StateFiles.exists(files.ceFiles)) StateFiles.make(files.ceFiles);
        StateFiles.make(files.ceDir);
        for (String alias : Contract.ALIASES) {
            if (keys.getKey(alias, null) != null || keys.containsAlias(alias)) {
                throw new IllegalStateException("key exists or cannot be read safely");
            }
            KeyPairGenerator generator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            generator.initialize(new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(false).build());
            generator.generateKeyPair();
        }
        StateFiles.newFile(files.ce, request.canary(true));
        StateFiles.newFile(files.de, request.canary(false));
        NotificationChannel channel = new NotificationChannel(Contract.CHANNEL,
                "Andrix B2 state", NotificationManager.IMPORTANCE_LOW);
        // Explicit platform default audio attributes serialize and reload identically.
        channel.setSound(null, Notification.AUDIO_ATTRIBUTES_DEFAULT);
        channel.enableVibration(false); channel.enableLights(false); channel.setShowBadge(true);
        notifications.createNotificationChannel(channel);
        PersistableBundle extras = new PersistableBundle();
        extras.putString("andrix.b2.setup", request.setup);
        extras.putString("andrix.b2.contract_sha256", request.contract);
        JobInfo job = new JobInfo.Builder(Contract.JOB_ID,
                new ComponentName(Contract.PACKAGE, Contract.SERVICE))
                .setPersisted(true).setMinimumLatency(Contract.LATENCY).setExtras(extras).build();
        if (scheduler.schedule(job) != JobScheduler.RESULT_SUCCESS) {
            throw new IllegalStateException("schedule refused");
        }
        // Read back only. No schedule retry even if the result is missing or lost.
        ObserveState.job(context, request);
    }
}
