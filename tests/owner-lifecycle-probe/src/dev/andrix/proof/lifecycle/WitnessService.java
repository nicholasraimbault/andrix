// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.lifecycle;

import android.app.KeyguardManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Binder;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Looper;
import android.os.PowerManager;
import android.os.Process;
import android.os.SystemClock;
import android.os.UserManager;
import android.util.Log;

import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/** A finite ordinary foreground service, not part of the owner computing TCB. */
public final class WitnessService extends Service {
    static final String START = "dev.andrix.proof.lifecycle.START";
    static final String STOP = "dev.andrix.proof.lifecycle.STOP";
    private static final String CHANNEL = "lifecycle-probe";
    private static final int NOTIFICATION = 1;
    private static final long MAX_DURATION_MS = 15 * 60 * 1000;
    private static final long FRESH_MS = 2000;
    private static final AtomicLong EPOCHS = new AtomicLong(SystemClock.elapsedRealtimeNanos());
    private final AtomicReference<Bundle> sample = new AtomicReference<>(new Bundle());
    private final Handler main = new Handler(Looper.getMainLooper());
    private HandlerThread thread;
    private Handler worker;
    private UserManager users;
    private KeyguardManager keyguard;
    private PowerManager power;
    private volatile boolean active;
    private volatile long epoch;
    private long sequence;
    private final ILifecycleProbe.Stub binder = new ILifecycleProbe.Stub() {
        @Override public Bundle snapshot() {
            if (Binder.getCallingUid() != Process.myUid())
                throw new SecurityException("not the same APK identity");
            Bundle copy = new Bundle(sample.get());
            copy.putBoolean("active", active);
            copy.putBoolean("fresh", active && copy.getLong("epoch", -1) == epoch && LifecycleSample.fresh(
                    SystemClock.elapsedRealtime(), copy.getLong("observed_ms", -1), FRESH_MS));
            return copy;
        }
    };

    @Override public void onCreate() {
        super.onCreate();
        users = getSystemService(UserManager.class);
        keyguard = getSystemService(KeyguardManager.class);
        power = getSystemService(PowerManager.class);
        getSystemService(NotificationManager.class).createNotificationChannel(
                new NotificationChannel(CHANNEL, "Lifecycle probe", NotificationManager.IMPORTANCE_LOW));
        thread = new HandlerThread("lifecycle-probe");
        thread.start();
        worker = new Handler(thread.getLooper());
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null || !START.equals(intent.getAction())) {
            stopProbe();
            return START_NOT_STICKY;
        }
        if (Process.myUid() < 10000 || Process.myUid() >= 100000
                || !getSystemService(NotificationManager.class).areNotificationsEnabled()) {
            stopProbe();
            return START_NOT_STICKY;
        }
        if (active) return START_NOT_STICKY;
        long generation = EPOCHS.incrementAndGet();
        epoch = generation;
        long began = SystemClock.elapsedRealtime();
        Intent open = new Intent(this, ProbeActivity.class);
        Intent stop = new Intent(this, WitnessService.class).setAction(STOP);
        PendingIntent view = PendingIntent.getActivity(this, 1, open,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        PendingIntent end = PendingIntent.getService(this, 2, stop,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification notification = new Notification.Builder(this, CHANNEL)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentTitle("Lifecycle probe running")
                .setContentText("User-state observation only; no owner-job authority")
                .setContentIntent(view).setOngoing(true)
                .addAction(new Notification.Action.Builder(null, "Stop probe", end).build())
                .build();
        startForeground(NOTIFICATION, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        active = true;
        main.postDelayed(() -> { if (epoch == generation) stopProbe(); }, MAX_DURATION_MS);
        worker.post(() -> observe(generation, began));
        Log.i("AndrixLifeProbe", "START pid=" + Process.myPid() + " epoch=" + epoch);
        return START_NOT_STICKY;
    }

    private void observe(long generation, long started) {
        if (!active || epoch != generation) return;
        long began = SystemClock.elapsedRealtime();
        Bundle next = new Bundle();
        boolean before = false, unlocked = false, after = false, queried = false;
        try {
            before = users.isUserRunning(Process.myUserHandle());
            unlocked = users.isUserUnlocked();
            after = users.isUserRunning(Process.myUserHandle());
            next.putBoolean("device_locked", keyguard.isDeviceLocked());
            next.putBoolean("interactive", power.isInteractive());
            queried = true;
        } catch (RuntimeException ignored) {
            // No arbitrary exception message, terminal data or credential logging.
        }
        long finished = SystemClock.elapsedRealtime();
        if (!active || epoch != generation) return;
        boolean usable = LifecycleSample.usable(queried, before, unlocked, after)
                && LifecycleSample.fresh(finished, began, FRESH_MS);
        next.putInt("pid", Process.myPid());
        next.putInt("uid", Process.myUid());
        next.putLong("epoch", generation);
        next.putLong("sequence", ++sequence);
        next.putLong("observed_ms", finished);
        next.putLong("query_ms", finished - began);
        next.putBoolean("queried", queried);
        next.putBoolean("running_before", before);
        next.putBoolean("unlocked", unlocked);
        next.putBoolean("running_after", after);
        next.putBoolean("usable", usable);
        sample.set(next);
        if (sequence == 1 || sequence % 20 == 0 || !usable) {
            Log.i("AndrixLifeProbe", "SAMPLE pid=" + Process.myPid() + " epoch=" + generation
                    + " seq=" + sequence + " running=" + (before && after)
                    + " unlocked=" + unlocked + " locked=" + next.getBoolean("device_locked")
                    + " usable=" + usable);
        }
        if (!usable || finished - started >= MAX_DURATION_MS) {
            main.post(() -> { if (epoch == generation) stopProbe(); });
        } else worker.postDelayed(() -> observe(generation, started), 500);
    }

    private void stopProbe() {
        active = false;
        epoch = EPOCHS.incrementAndGet();
        main.removeCallbacksAndMessages(null);
        if (worker != null) worker.removeCallbacksAndMessages(null);
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    @Override public IBinder onBind(Intent intent) { return binder; }
    @Override public void onDestroy() {
        active = false;
        epoch = EPOCHS.incrementAndGet();
        main.removeCallbacksAndMessages(null);
        worker.removeCallbacksAndMessages(null);
        thread.quitSafely();
        Log.i("AndrixLifeProbe", "DESTROY pid=" + Process.myPid() + " epoch=" + epoch);
        super.onDestroy();
    }
}
