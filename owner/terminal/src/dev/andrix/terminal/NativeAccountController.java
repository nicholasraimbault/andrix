// SPDX-License-Identifier: GPL-3.0-or-later
package dev.andrix.terminal;

import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.widget.TextView;

import dev.andrix.lifecycle.INativeAccountQuery;
import dev.andrix.lifecycle.NativeAccountRow;
import dev.andrix.lifecycle.NativeAccountSnapshot;

import java.lang.ref.WeakReference;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/** An independent, bounded read lane. It neither discovers work nor acquires a terminal lease. */
final class NativeAccountController {
    private static final String SERVICE = "andrix.owner.accounts";
    private static final long DISPLAY_TIMEOUT_MS = 5_000;
    private static final Object LANE_LOCK = new Object();
    // Process lifetime, not Activity lifetime. A blocked synchronous Binder call cannot be
    // cancelled by shutdownNow. At most ONE such call and ONE replaceable queued request exist.
    private static final ThreadPoolExecutor QUERY_LANE = new ThreadPoolExecutor(1, 1, 0,
            TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(1),
            work -> new Thread(work, "AndrixNativeAccountsRead"));
    private final Handler main = new Handler(Looper.getMainLooper());
    private final TextView view;
    private volatile long generation;
    private volatile boolean visible, closed;
    private Runnable timeout; // Main thread, removed on refresh, hide and close.

    private static final class Query implements Runnable {
        final WeakReference<NativeAccountController> owner;
        final long request;
        final int user;

        Query(NativeAccountController owner, long request, int user) {
            this.owner = new WeakReference<>(owner);
            this.request = request;
            this.user = user;
        }

        @Override public void run() {
            if (!isCurrent(owner, request, user)) return;
            NativeAccountSnapshot result = null;
            IBinder observed = null;
            try {
                observed = ServiceManager.checkService(SERVICE);
                if (observed != null) {
                    INativeAccountQuery service = INativeAccountQuery.Stub.asInterface(observed);
                    result = service.inspectCurrentUser();
                    if (!observed.isBinderAlive() || ServiceManager.checkService(SERVICE) != observed) {
                        result = null;
                    }
                }
            } catch (Exception unavailable) {
                // A synchronous Binder failure is not an empty account list.
                result = null;
            }
            // No controller, Activity or TextView was held while the Binder call was blocked.
            NativeAccountController target = owner.get();
            if (target != null) {
                final NativeAccountSnapshot captured = result;
                final IBinder binder = observed;
                target.main.post(() -> target.finish(this, captured, binder));
            }
        }
    }

    private static boolean isCurrent(WeakReference<NativeAccountController> owner,
            long request, int user) {
        NativeAccountController target = owner.get();
        return target != null && target.current(request, user);
    }

    private boolean current(long request, int user) {
        return visible && !closed && generation == request && user == UserHandle.myUserId();
    }

    NativeAccountController(TextView view) { this.view = view; }

    void open() {
        if (closed) return;
        visible = true;
        view.setText("Native Accounts. Press Refresh to inspect cached identity state. "
                + "Inspection is not login, CE access, designation or launch authority.");
    }

    private void cancelTimeout() {
        if (timeout != null) {
            main.removeCallbacks(timeout);
            timeout = null;
        }
    }

    private void cancelQueued() {
        synchronized (LANE_LOCK) {
            for (Runnable job : QUERY_LANE.getQueue()) {
                if (job instanceof Query && ((Query) job).owner.get() == this) {
                    QUERY_LANE.remove(job);
                }
            }
        }
    }

    void hide() {
        visible = false;
        generation++;
        cancelTimeout();
        cancelQueued();
        view.setText("Native Accounts. Press Refresh to inspect.");
    }

    void close() {
        closed = true;
        hide(); // A blocked call may remain, but its weak owner cannot publish or enqueue.
    }

    void refresh() {
        if (closed || !visible) return;
        cancelTimeout();
        final long request = ++generation;
        final int user = UserHandle.myUserId();
        Query query = new Query(this, request, user);
        view.setText("Native Accounts: refreshing cached identity state...");
        try {
            synchronized (LANE_LOCK) {
                QUERY_LANE.getQueue().clear(); // Replace one obsolete pending request only.
                QUERY_LANE.execute(query);
            }
            Runnable expiry = () -> {
                if (!current(request, user)) return;
                generation++; // An eventual late Binder reply is stale, not a new observation.
                synchronized (LANE_LOCK) { QUERY_LANE.remove(query); }
                timeout = null;
                view.setText("Native Accounts: query timed out. State unavailable. Refresh again.");
            };
            timeout = expiry;
            if (!main.postDelayed(expiry, DISPLAY_TIMEOUT_MS)) {
                generation++;
                cancelQueued();
                timeout = null;
                view.setText("Native Accounts: query unavailable. Refresh again.");
            }
        } catch (RejectedExecutionException busy) {
            if (current(request, user)) {
                view.setText("Native Accounts: query lane busy. State unavailable. Refresh again.");
            }
        }
    }

    private void finish(Query query, NativeAccountSnapshot captured, IBinder binder) {
        if (!current(query.request, query.user)) return;
        // The worker's check was before this callback was queued. An old Binder can still be
        // alive after registration changes. Accept only if the non waiting service lookup now
        // names that exact Binder. This is an observation at delivery, not future liveness.
        NativeAccountSnapshot accepted = null;
        if (captured != null && binder != null) {
            try {
                if (binder.isBinderAlive() && ServiceManager.checkService(SERVICE) == binder) {
                    accepted = captured;
                }
            } catch (RuntimeException unavailable) {
                // A lookup or Binder failure cannot make the old response current.
            }
        }
        cancelTimeout();
        view.setText(render(accepted, query.user));
    }

    static String render(NativeAccountSnapshot snapshot, int user) {
        final String disclaimer = "\nInspection is not login, CE access, designation or launch authority. "
                + "Current data availability and in-memory admission closure are not reported.";
        if (snapshot == null || snapshot.userId != user) {
            return "Native Accounts: state unavailable. Refresh again." + disclaimer;
        }
        String prefix = "Native Accounts, Android user " + snapshot.userId + " serial "
                + (snapshot.userSerial < 0 ? "unavailable" : snapshot.userSerial) + ". ";
        if (snapshot.status == NativeAccountSnapshot.UNSUPPORTED_USER) {
            return prefix + "Unsupported for this Android user. No primary user accounts shown."
                    + disclaimer;
        }
        if (snapshot.userSerial < 0) {
            return prefix + "State unavailable. Refresh again." + disclaimer;
        }
        if (snapshot.status != NativeAccountSnapshot.AVAILABLE || !snapshot.complete
                || snapshot.store != NativeAccountSnapshot.STORE_READY
                || snapshot.rows == null || snapshot.rows.length > 64) {
            return prefix + "Cached store " + storeLabel(snapshot.store)
                    + "; identity state unavailable, not an empty account list." + disclaimer;
        }
        if (snapshot.rows.length == 0) return prefix + "No recorded native accounts in a complete "
                + "cached store. This does not create the normal login." + disclaimer;
        StringBuilder text = new StringBuilder(prefix).append(snapshot.rows.length)
                .append(" recorded account(s), cached store complete:\n");
        for (NativeAccountRow row : snapshot.rows) {
            if (row == null || row.principalId <= 0 || row.appId < 10000 || row.appId > 19999
                    || row.packageName == null || row.packageName.length() > 255
                    || row.packageName.isEmpty() || !validLineage(row.lineage)) {
                return prefix + "Invalid account response; state unavailable." + disclaimer;
            }
            String source = switch (row.source) {
                case NativeAccountRow.BODY -> "body";
                case NativeAccountRow.RESERVATION -> "reservation";
                default -> null;
            };
            String pin = switch (row.phase) {
                case NativeAccountRow.PENDING -> "pending";
                case NativeAccountRow.ACTIVE -> "active pin";
                case NativeAccountRow.RETIRING_PIN -> "retiring pin";
                case NativeAccountRow.NOT_PINNED -> "not pinned";
                default -> null;
            };
            String lifecycle = switch (row.lifecycle) {
                case NativeAccountRow.LIFECYCLE_NOT_OBSERVED -> "lifecycle not observed";
                case NativeAccountRow.ELIGIBLE -> "eligible";
                case NativeAccountRow.RETIRING -> "retiring";
                case NativeAccountRow.RETIRED -> "recorded retired; retirement alone deletes no data and releases no UID";
                default -> null;
            };
            String suspension = switch (row.suspension) {
                case NativeAccountRow.SUSPENSION_NOT_OBSERVED -> "suspension not observed";
                case NativeAccountRow.SUSPENSION_NONE -> "no recorded suspension";
                case NativeAccountRow.SUSPENSION_PRESENT -> "recorded suspension";
                default -> null;
            };
            if (source == null || pin == null || lifecycle == null || suspension == null
                    || (row.source == NativeAccountRow.RESERVATION
                            && (row.lifecycle != NativeAccountRow.LIFECYCLE_NOT_OBSERVED
                                    || row.suspension != NativeAccountRow.SUSPENSION_NOT_OBSERVED))
                    || (row.source == NativeAccountRow.BODY
                            && (row.lifecycle == NativeAccountRow.LIFECYCLE_NOT_OBSERVED
                                    || row.suspension == NativeAccountRow.SUSPENSION_NOT_OBSERVED))) {
                return prefix + "Unknown account response; state unavailable." + disclaimer;
            }
            text.append(row.packageName).append(" (lineage ").append(row.lineage)
                    .append(", principal ").append(row.principalId)
                    .append(", app ID ").append(row.appId).append(") ")
                    .append(source).append(", ").append(pin).append(", ")
                    .append(lifecycle).append(", ").append(suspension).append('\n');
        }
        return text.append(disclaimer).toString();
    }

    private static boolean validLineage(String lineage) {
        if (lineage == null || lineage.length() != 32) return false;
        for (int i = 0; i < lineage.length(); ++i) {
            char c = lineage.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        }
        return true;
    }

    private static String storeLabel(int store) {
        return switch (store) {
            case NativeAccountSnapshot.STORE_MISSING -> "missing, provisioning unavailable";
            case NativeAccountSnapshot.STORE_DAMAGED -> "damaged";
            case NativeAccountSnapshot.STORE_CONFLICT -> "conflicting";
            case NativeAccountSnapshot.STORE_NEWER -> "newer than this reader";
            default -> "unavailable";
        };
    }
}
