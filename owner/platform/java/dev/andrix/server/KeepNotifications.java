// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.drawable.Icon;
import android.net.Uri;
import android.os.Handler;
import android.os.SystemClock;
import android.service.notification.StatusBarNotification;
import android.util.Slog;

import dev.andrix.server.KeepWorkState.Record;

import java.util.function.Consumer;

/** System-context notification/PendingIntent adapter; not an APK or OS-state poller. */
final class KeepNotifications implements KeepWork.Backend {
    private static final String TAG = "AndrixOwnerLifecycle";
    private static final String CHANNEL = "andrix.kept_terminal";
    private static final String STOP = "dev.andrix.server.action.STOP_KEPT_TERMINAL";
    private static final int NOTICE_ID = 1;
    private final Context context;
    private final Consumer<Runnable> commands;
    private NotificationManager manager;
    private volatile boolean ready;

    KeepNotifications(Context context, Consumer<Runnable> commands) {
        this.context = context; this.commands = commands;
    }

    void initialize(KeepWork keep, Handler handler) {
        try {
            manager = context.getSystemService(NotificationManager.class);
            if (manager == null) return;
            NotificationChannel channel = new NotificationChannel(CHANNEL,
                    "Andrix kept terminal", NotificationManager.IMPORTANCE_LOW);
            // This is optional owner work, not a non-blockable system warning.
            // The system context has a fixed notification permission; opt THIS
            // channel into Android's normal owner controls. Re-creating it may
            // update blockability but must not override a user's blocked state.
            channel.setBlockable(true);
            manager.createNotificationChannel(channel);
            IntentFilter stopFilter = new IntentFilter(STOP);
            stopFilter.addDataScheme("andrix-keep");
            stopFilter.addDataAuthority("stop", null);
            context.registerReceiver(new BroadcastReceiver() {
                @Override public void onReceive(Context ignored, Intent intent) {
                    if (STOP.equals(intent.getAction()) && intent.getData() != null) {
                        // The complete URI includes instance/registration/random nonce.
                        // Stop is safe while locked: it only ends computation, never attaches.
                        keep.stop(intent.getData().toString());
                    }
                }
            }, stopFilter, null, handler, Context.RECEIVER_NOT_EXPORTED);
            IntentFilter blockFilter = new IntentFilter();
            blockFilter.addAction(NotificationManager.ACTION_APP_BLOCK_STATE_CHANGED);
            blockFilter.addAction(NotificationManager.ACTION_NOTIFICATION_CHANNEL_BLOCK_STATE_CHANGED);
            context.registerReceiver(new BroadcastReceiver() {
                @Override public void onReceive(Context ignored, Intent intent) {
                    String action = intent.getAction();
                    if (NotificationManager.ACTION_NOTIFICATION_CHANNEL_BLOCK_STATE_CHANGED.equals(action)
                            && !CHANNEL.equals(intent.getStringExtra(
                                    NotificationManager.EXTRA_NOTIFICATION_CHANNEL_ID))) return;
                    // Recheck current settings, rather than applying a delayed old
                    // block broadcast to a new registration after re-enabling.
                    if (!allowed()) keep.notificationRevoked();
                }
            }, blockFilter, null, handler, Context.RECEIVER_NOT_EXPORTED);
            ready = true;
        } catch (RuntimeException error) {
            error("Keep notifications unavailable; Keep stays denied", error);
        }
    }

    private boolean allowed() {
        try {
            if (!ready || manager == null || !manager.areNotificationsEnabled()) return false;
            NotificationChannel channel = manager.getNotificationChannel(CHANNEL);
            // This channel has no group. Never adopt an unexpectedly grouped channel
            // whose group may be blocked independently of the channel's importance.
            return channel != null && channel.getImportance() != NotificationManager.IMPORTANCE_NONE
                    && channel.getGroup() == null;
        } catch (RuntimeException error) {
            error("Cannot establish notification availability", error);
            return false;
        }
    }

    @Override public boolean post(Record<KeepWork.Lifetime> record) {
        if (!allowed()) return false;
        Uri uri = Uri.parse(record.token);
        PendingIntent stop = PendingIntent.getBroadcast(context, 0,
                new Intent(STOP).setPackage(context.getPackageName()).setData(uri),
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        PendingIntent console = PendingIntent.getActivity(context, 0,
                new Intent(Intent.ACTION_MAIN).setComponent(new ComponentName(
                        "dev.andrix.terminal", "dev.andrix.terminal.ConsoleActivity"))
                        .setData(uri).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP),
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification notification = new Notification.Builder(context, CHANNEL)
                .setSmallIcon(android.R.drawable.stat_notify_more)
                .setContentTitle("Kept terminal running")
                .setContentText("Terminal work continues after leaving the Console. Stop ends this work.")
                .setCategory(Notification.CATEGORY_SERVICE)
                .setVisibility(Notification.VISIBILITY_PUBLIC)
                .setOngoing(true).setOnlyAlertOnce(true).setShowWhen(false)
                .setContentIntent(console).setDeleteIntent(stop)
                .addAction(new Notification.Action.Builder(Icon.createWithResource(context,
                        android.R.drawable.ic_menu_close_clear_cancel), "Stop", stop)
                        .setAuthenticationRequired(false).build())
                .build();
        manager.notify(record.token, NOTICE_ID, notification);
        // notify() enqueues asynchronously. Bound OUR post acknowledgement to
        // 400ms; no lifecycle/storage lock is held and no OS authority is polled.
        // A stalled framework Binder call itself cannot be bounded here: native's
        // issued-query deadline also covers Keep plus its confirming snapshot.
        return KeepNoticeWait.await(new KeepNoticeWait.Probe() {
            @Override public boolean allowed() { return KeepNotifications.this.allowed(); }
            @Override public boolean active() {
                for (StatusBarNotification active : manager.getActiveNotifications()) {
                    if (active.getId() == NOTICE_ID && record.token.equals(active.getTag())
                            && CHANNEL.equals(active.getNotification().getChannelId())
                            && (active.getNotification().flags & Notification.FLAG_ONGOING_EVENT) != 0) {
                        return true;
                    }
                }
                return false;
            }
        }, new KeepNoticeWait.Clock() {
            @Override public long now() { return SystemClock.uptimeMillis(); }
            @Override public void sleep(long millis) { SystemClock.sleep(millis); }
        });
    }

    @Override public void cancel(Record<KeepWork.Lifetime> record) {
        // Per-registration tags prevent a late old cancel deleting a new notice.
        if (manager != null) manager.cancel(record.token, NOTICE_ID);
    }
    @Override public void execute(Runnable command) { commands.accept(command); }
    @Override public void error(String message, Exception error) { Slog.e(TAG, message, error); }
}
