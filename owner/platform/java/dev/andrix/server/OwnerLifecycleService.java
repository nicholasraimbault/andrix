// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server;

import android.content.Context;
import android.os.Binder;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.SystemProperties;
import android.util.Slog;

import com.android.server.LocalServices;
import com.android.server.StorageManagerInternal;
import com.android.server.SystemService;
import com.android.server.pm.UserManagerInternal;
import com.android.server.storage.CeStorageAccessTracker;

import dev.andrix.lifecycle.IPlatformLifecycle;
import dev.andrix.lifecycle.PlatformState;

import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Opt-in adapter to Android's actual user/storage lifecycle. It owns no keys,
 * packages, PTYs or owner files. Android init remains the process-group supervisor.
 */
public final class OwnerLifecycleService extends SystemService {
    private static final String TAG = "AndrixOwnerLifecycle";
    private static final String SERVICE = "andrix.owner.lifecycle";
    private static final int OWNER_UID = 7500;
    private final OwnerLifecycleState state = new OwnerLifecycleState();
    private final long instance;
    private final AtomicBoolean publishQueued = new AtomicBoolean();
    private Handler commands;
    // These fields belong only to the independent command handler.
    private long publishedGeneration;
    private boolean publishedReady;
    private boolean published;

    private final IPlatformLifecycle.Stub binder = new IPlatformLifecycle.Stub() {
        @Override public PlatformState snapshot() {
            // SELinux restricts discovery to andrixd; UID7500 owner workers cannot
            // call this endpoint (worker Binder filter and owner policy boundary).
            // No supplied PID, UID, user ID or Boolean is accepted as authority.
            if (Binder.getCallingUid() != OWNER_UID || Binder.getCallingPid() <= 1) {
                throw new SecurityException("not the native owner coordinator");
            }
            OwnerLifecycleState.State current = state.snapshot();
            PlatformState result = new PlatformState();
            result.instance = instance; result.generation = current.generation;
            result.available = current.available;
            return result;
        }
        @Override protected void dump(FileDescriptor fd, PrintWriter out, String[] args) {
            int uid = Binder.getCallingUid();
            if (uid != android.os.Process.SYSTEM_UID && uid != android.os.Process.SHELL_UID) {
                throw new SecurityException("lifecycle metadata dump denied");
            }
            OwnerLifecycleState.State current = state.snapshot();
            out.println("instance=" + instance + " generation=" + current.generation
                    + " available=" + current.available);
            out.println("Android lifecycle metadata; no synchronous key/cleanup completion claim");
        }
    };

    public OwnerLifecycleService(Context context) {
        super(context);
        long seed = new SecureRandom().nextLong() & Long.MAX_VALUE;
        instance = seed == 0 ? 1 : seed;
    }

    @Override public void onStart() {
        HandlerThread thread = new HandlerThread("AndrixLifecycleCommands");
        thread.start();
        commands = new Handler(thread.getLooper());
        publishBinderService(SERVICE, binder);
        schedulePublication(); // Starts blocked, including missing dependency paths.
        try {
            StorageManagerInternal storage = LocalServices.getService(StorageManagerInternal.class);
            UserManagerInternal users = LocalServices.getService(UserManagerInternal.class);
            if (storage == null || users == null) throw new IllegalStateException("services absent");
            CeStorageAccessTracker.Snapshot initial = storage.registerCeStorageAccessListener(
                    0, this::ceChanged);
            ceChanged(initial); // Sequence reconciliation handles callback-before-return.
            long before = state.userRevision();
            boolean ready = users.isUserRunning(0) && users.isUserUnlocked(0);
            state.bootstrapUser(before, ready); // User state only; CE has its separate observation.
            schedulePublication();
        } catch (RuntimeException error) {
            state.fail(); schedulePublication();
            Slog.e(TAG, "Cannot establish lifecycle observation", error);
        }
    }

    private void ceChanged(CeStorageAccessTracker.Snapshot observation) {
        if (observation.userId != 0) return;
        // No storage locks, Binder downcalls, property I/O or cleanup waits here.
        state.ce(observation.sequence, observation.revocation, observation.available);
        schedulePublication();
    }

    private void userChanged(TargetUser user, boolean ready) {
        if (user.getUserIdentifier() != 0) return;
        state.user(ready); schedulePublication();
    }
    @Override public void onUserStarting(TargetUser user) { userChanged(user, false); }
    @Override public void onUserUnlocking(TargetUser user) { userChanged(user, false); }
    @Override public void onUserUnlocked(TargetUser user) { userChanged(user, true); }
    @Override public void onUserStopping(TargetUser user) { userChanged(user, false); }
    @Override public void onUserStopped(TargetUser user) { userChanged(user, false); }

    private void schedulePublication() {
        if (commands == null || !publishQueued.compareAndSet(false, true)) return;
        if (!commands.post(this::publish)) {
            publishQueued.set(false); state.fail();
            Slog.e(TAG, "Lifecycle command handler unavailable");
        }
    }

    private void publish() {
        publishQueued.set(false); // At most this invocation plus one pending update.
        OwnerLifecycleState.State current = state.snapshot();
        try {
            // Existing init control requests, not a second process supervisor.
            if (!current.available) {
                SystemProperties.set("ctl.stop", "andrixd");
            } else if (published && (current.generation != publishedGeneration || !publishedReady)) {
                // A newer positive may have overtaken a negative notification.
                // Restart through init; never preserve old work across that epoch.
                SystemProperties.set("ctl.restart", "andrixd");
            } else if (!published) {
                SystemProperties.set("ctl.start", "andrixd");
            }
            Slog.i(TAG, "instance=" + instance + " generation=" + current.generation
                    + " available=" + current.available);
            published = true; publishedGeneration = current.generation;
            publishedReady = current.available;
        } catch (RuntimeException error) {
            state.fail();
            // Do not let publication failure leave a true Binder observation.
            // This is a stop request, not an acknowledgement that cleanup ended.
            try { SystemProperties.set("ctl.stop", "andrixd"); }
            catch (RuntimeException stopError) { Slog.e(TAG, "Init stop request failed", stopError); }
            Slog.e(TAG, "Lifecycle publication failed", error);
        }
    }
}
