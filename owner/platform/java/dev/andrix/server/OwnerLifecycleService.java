// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server;

import android.content.Context;
import android.os.Binder;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.SystemProperties;
import android.util.Slog;

import com.android.server.LocalServices;
import com.android.server.StorageManagerInternal;
import com.android.server.SystemService;
import com.android.server.pm.UserManagerInternal;
import com.android.server.storage.CeStorageAccessTracker;

import dev.andrix.lifecycle.IKeptWork;
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
    private final KeepNotifications notifications;
    private final KeepWork keep;
    private final AtomicBoolean publishQueued = new AtomicBoolean();
    private Handler commands;
    // These fields belong only to the independent command handler.
    private long publishedGeneration;
    private boolean publishedReady;
    private boolean published;

    private final OwnerLifecycleBinder binder = new OwnerLifecycleBinder(getContext()) {
        @Override protected PlatformState captureState() {
            KeepWork.Snapshot current = keep.snapshot();
            PlatformState result = new PlatformState();
            result.instance = instance; result.generation = current.platform.generation;
            result.available = current.platform.available;
            result.keptWorkId = current.workId; result.keepRegistration = current.registration;
            return result;
        }
        @Override public PlatformState snapshot() {
            enforceCoordinator();
            PlatformState result = captureState();
            // Normal products select a no-op source implementation. The separate
            // authorized lab variant may delay this actual captured reply outside
            // the lifecycle monitor; it cannot manufacture availability.
            beforeReply(result);
            return result;
        }
        @Override public long keepWork(IBinder lifetime, long workId,
                long platformInstance, long platformGeneration) throws RemoteException {
            enforceCoordinator();
            if (!KeepBuild.ENABLED || lifetime == null) return 0;
            // Authorized platform work uses system context AND system Binder identity,
            // not the remote UID7500 identity inherited by this Binder thread.
            long identity = Binder.clearCallingIdentity();
            try {
                // Descriptor/object checks are outside all lifecycle/storage locks.
                // Endpoint UID + MAC/worker filtering trust the native coordinator to
                // supply its own process-lifetime IKeptWork, not an arbitrary token.
                if (lifetime instanceof Binder
                        || !IKeptWork.DESCRIPTOR.equals(lifetime.getInterfaceDescriptor())) return 0;
                return keep.keep(new BinderLifetime(lifetime, IKeptWork.Stub.asInterface(lifetime)),
                        workId, platformInstance, platformGeneration);
            } finally { Binder.restoreCallingIdentity(identity); }
        }
        @Override protected void dump(FileDescriptor fd, PrintWriter out, String[] args) {
            int uid = Binder.getCallingUid();
            if (uid != android.os.Process.SYSTEM_UID && uid != android.os.Process.SHELL_UID) {
                throw new SecurityException("lifecycle metadata dump denied");
            }
            PlatformState current = captureState();
            out.println("instance=" + current.instance + " generation=" + current.generation
                    + " available=" + current.available + " keptWorkId=" + current.keptWorkId
                    + " keepRegistration=" + current.keepRegistration);
            out.println("Android lifecycle metadata; no synchronous key/cleanup completion claim");
        }
    };

    public OwnerLifecycleService(Context context) {
        super(context);
        long seed = new SecureRandom().nextLong() & Long.MAX_VALUE;
        instance = seed == 0 ? 1 : seed;
        notifications = new KeepNotifications(context, this::postCommand);
        keep = new KeepWork(KeepBuild.ENABLED, instance, state, notifications);
    }

    private static void enforceCoordinator() {
        // MAC service-manager find policy excludes owner workers/Console/apps but
        // also admits some system/debug domains. It is not endpoint authorization.
        // Only the ACTUAL Binder caller UID7500/PID>1 is accepted here. Worker Binder
        // filtering and MAC separate same-UID owner code from the coordinator;
        // neither a supplied UID/PID nor mere discovery establishes that identity.
        if (Binder.getCallingUid() != OWNER_UID || Binder.getCallingPid() <= 1) {
            throw new SecurityException("not the native owner coordinator");
        }
    }

    private static final class BinderLifetime implements KeepWork.Lifetime {
        private final IBinder binder;
        private final IKeptWork callback;
        private IBinder.DeathRecipient recipient;
        BinderLifetime(IBinder binder, IKeptWork callback) {
            this.binder = binder; this.callback = callback;
        }
        @Override public Object identity() { return binder; }
        @Override public void link(Runnable death) throws RemoteException {
            recipient = death::run; // Per-registration recipient, never PID keyed.
            try { binder.linkToDeath(recipient, 0); }
            catch (RemoteException error) { death.run(); throw error; }
        }
        @Override public void unlink() {
            if (recipient != null) binder.unlinkToDeath(recipient, 0);
        }
        @Override public boolean isAlive() { return binder.isBinderAlive(); }
        @Override public void stop(long workId, long registration) throws RemoteException {
            // Oneway to THIS process token. Native authenticates system_server and
            // exits; init reaps the group. A request is not cleanup acknowledgement.
            callback.stop(workId, registration);
        }
    }

    private void postCommand(Runnable command) {
        if (commands == null || !commands.post(command)) {
            throw new IllegalStateException("Lifecycle command handler unavailable");
        }
    }

    private void failState() {
        synchronized (state) { state.fail(); keep.platformChanged(); }
    }

    @Override public void onStart() {
        HandlerThread thread = new HandlerThread("AndrixLifecycleCommands");
        thread.start();
        commands = new Handler(thread.getLooper());
        if (KeepBuild.ENABLED) notifications.initialize(keep, commands);
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
            synchronized (state) {
                state.bootstrapUser(before, ready); // User state only; CE is separately observed.
                keep.platformChanged();
            }
            schedulePublication();
        } catch (RuntimeException error) {
            failState(); schedulePublication();
            Slog.e(TAG, "Cannot establish lifecycle observation", error);
        }
    }

    private void ceChanged(CeStorageAccessTracker.Snapshot observation) {
        if (observation.userId != 0) return;
        // No storage locks, Binder downcalls, property I/O or cleanup waits here.
        synchronized (state) {
            state.ce(observation.sequence, observation.revocation, observation.available);
            keep.platformChanged();
        }
        schedulePublication();
    }

    private void userChanged(TargetUser user, boolean ready) {
        if (user.getUserIdentifier() != 0) return;
        synchronized (state) { state.user(ready); keep.platformChanged(); }
        schedulePublication();
    }
    @Override public void onUserStarting(TargetUser user) { userChanged(user, false); }
    @Override public void onUserUnlocking(TargetUser user) { userChanged(user, false); }
    @Override public void onUserUnlocked(TargetUser user) { userChanged(user, true); }
    @Override public void onUserStopping(TargetUser user) { userChanged(user, false); }
    @Override public void onUserStopped(TargetUser user) { userChanged(user, false); }

    private void schedulePublication() {
        if (commands == null || !publishQueued.compareAndSet(false, true)) return;
        if (!commands.post(this::publish)) {
            publishQueued.set(false); failState();
            Slog.e(TAG, "Lifecycle command handler unavailable");
        }
    }

    private void publish() {
        publishQueued.set(false); // At most this invocation plus one pending update.
        OwnerLifecycleState.State current = keep.snapshot().platform;
        keep.cancelRevoked(); // Notification I/O outside storage/lifecycle monitors.
        try {
            // Existing GLOBAL Android lifecycle init controls, not notification Stop.
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
            failState(); keep.cancelRevoked();
            // Do not let publication failure leave a true Binder observation.
            // This is a stop request, not an acknowledgement that cleanup ended.
            try { SystemProperties.set("ctl.stop", "andrixd"); }
            catch (RuntimeException stopError) { Slog.e(TAG, "Init stop request failed", stopError); }
            Slog.e(TAG, "Lifecycle publication failed", error);
        }
    }
}
