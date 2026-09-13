// SPDX-License-Identifier: Apache-2.0
package com.android.server.storage;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * system_server-local observation metadata for existing CE operations. No key
 * management, upstream-cache modification, client waiting, or cleanup barrier.
 *
 * Registration plus returned snapshot is atomic relative to this tracker.
 * Callbacks run outside its lock and may be delivered out of order. Consumers
 * MUST reconcile sequence, including the returned initial snapshot. Positives
 * carry the latest revocation generation even if a negative callback was delayed.
 * Availability is platform metadata, not inode-key eviction/home-preparation proof.
 */
public final class CeStorageAccessTracker {
    public interface Listener { void onStateChanged(Snapshot state); }

    public static final class Snapshot {
        public final int userId;
        public final long sequence, revocation;
        public final boolean available;
        private Snapshot(int userId, long sequence, long revocation, boolean available) {
            this.userId = userId; this.sequence = sequence;
            this.revocation = revocation; this.available = available;
        }
    }

    private enum Kind { AVAILABLE, REVOKE, RESTORE, RESET }

    /** Instance-bound, single-use downcall token; never sent over Binder. */
    public static final class Operation {
        private final CeStorageAccessTracker owner;
        private final Object daemon;
        private final long backend, revision;
        private final int userId;
        private final Kind kind;
        private final boolean eligible, counted;
        private boolean completed;
        private Operation(CeStorageAccessTracker owner, int userId, Kind kind,
                boolean eligible, boolean counted) {
            this.owner = owner; this.userId = userId; this.kind = kind;
            this.eligible = eligible; this.counted = counted; daemon = owner.daemon;
            backend = owner.backend; revision = owner.revision;
        }
    }

    private static final class User {
        Snapshot state;
        final ArrayList<Listener> listeners = new ArrayList<>();
        User(Snapshot state) { this.state = state; }
    }
    private static final class Delivery {
        final Snapshot state;
        final ArrayList<Listener> listeners;
        Delivery(User user) { state = user.state; listeners = new ArrayList<>(user.listeners); }
    }

    private final Map<Integer, User> users = new HashMap<>();
    private final Consumer<RuntimeException> errors;
    private Object daemon;
    private long backend, revision, sequence;
    private int pendingRevocations;
    private boolean exhausted;

    public CeStorageAccessTracker(Consumer<RuntimeException> errors) { this(errors, 1); }
    // Package-local seed makes counter boundaries testable without runtime hooks.
    CeStorageAccessTracker(Consumer<RuntimeException> errors, long seed) {
        if (seed <= 0 || seed >= Long.MAX_VALUE) throw new IllegalArgumentException("seed");
        this.errors = Objects.requireNonNull(errors);
        backend = revision = sequence = seed;
    }

    private User user(int id) {
        if (id < 0) throw new IllegalArgumentException("negative user");
        return users.computeIfAbsent(id,
                key -> new User(new Snapshot(key, sequence, revision, false)));
    }

    public synchronized Snapshot register(int id, Listener listener) {
        Objects.requireNonNull(listener);
        User user = user(id);
        for (Listener existing : user.listeners) {
            if (existing == listener) throw new IllegalStateException("already registered");
        }
        user.listeners.add(listener);
        return user.state;
    }

    public synchronized void unregister(int id, Listener listener) {
        User user = users.get(id);
        if (user != null) user.listeners.removeIf(existing -> existing == listener);
    }

    // Reserve MAX_VALUE for terminal invalidation; never publish a positive with
    // that sequence. Exhaustion disables observations, not Android's key operation.
    private boolean advance() {
        if (exhausted) return false;
        if (sequence >= Long.MAX_VALUE - 1 || revision >= Long.MAX_VALUE - 1
                || backend >= Long.MAX_VALUE - 1) {
            exhaust();
            return false;
        }
        ++sequence;
        return true;
    }

    private void exhaust() {
        exhausted = true; sequence = revision = backend = Long.MAX_VALUE;
        daemon = null; pendingRevocations = 0;
    }

    private Delivery publish(int id, boolean available, boolean revoke) {
        User user = user(id);
        user.state = new Snapshot(id, sequence,
                revoke || exhausted ? revision : user.state.revocation,
                available && !exhausted);
        return new Delivery(user);
    }

    private ArrayList<Delivery> allUnavailable() {
        ArrayList<Delivery> deliveries = new ArrayList<>();
        for (int id : users.keySet()) deliveries.add(publish(id, false, true));
        return deliveries;
    }

    private ArrayList<Delivery> invalidateAll() {
        if (advance()) ++revision;
        return allUnavailable();
    }

    private void finishEvents(ArrayList<Delivery> events) {
        // Called under the tracker lock after every potentially exhausting step.
        if (exhausted) { events.clear(); events.addAll(allUnavailable()); }
    }

    private void deliver(Iterable<Delivery> deliveries) {
        for (Delivery delivery : deliveries) {
            for (Listener listener : delivery.listeners) {
                try { listener.onStateChanged(delivery.state); }
                catch (RuntimeException error) {
                    // Listener/logging failure must not interrupt key locking.
                    try { errors.accept(error); } catch (RuntimeException ignored) { }
                }
            }
        }
    }

    /** New vold binding, before restoration/downcalls. Snapshot starts unknown. */
    public void connected(Object identity) {
        Objects.requireNonNull(identity);
        final ArrayList<Delivery> events;
        synchronized (this) {
            if (daemon == identity) return;
            events = invalidateAll();
            if (!exhausted) { ++backend; daemon = identity; }
            pendingRevocations = 0;
            finishEvents(events);
        }
        deliver(events);
    }

    /** Old daemon death cannot invalidate a replacement binding. */
    public void died(Object identity) {
        final ArrayList<Delivery> events;
        synchronized (this) {
            if (daemon == null || daemon != identity) return;
            events = invalidateAll();
            if (!exhausted) ++backend;
            daemon = null; pendingRevocations = 0;
            finishEvents(events);
        }
        deliver(events);
    }

    private boolean matches(Object identity) {
        return !exhausted && daemon != null && daemon == identity;
    }

    /** Pre-request revocation for lock, key destruction or relevant CE destruction. */
    public Operation beginRevocation(int id, Object identity) {
        final ArrayList<Delivery> events = new ArrayList<>();
        final Operation token;
        synchronized (this) {
            user(id);
            if (advance()) ++revision;
            events.add(publish(id, false, true));
            boolean counted = matches(identity);
            if (counted && pendingRevocations == Integer.MAX_VALUE) {
                exhaust(); counted = false;
            }
            if (counted) ++pendingRevocations;
            token = new Operation(this, id, Kind.REVOKE, false, counted);
            finishEvents(events);
        }
        deliver(events);
        return token;
    }

    public synchronized Operation beginAvailable(int id, Object identity) {
        user(id);
        return new Operation(this, id, Kind.AVAILABLE,
                matches(identity) && pendingRevocations == 0, false);
    }

    public synchronized Operation beginRestore(Object identity) {
        return new Operation(this, -1, Kind.RESTORE,
                matches(identity) && pendingRevocations == 0, false);
    }

    /** Reset invalidates observation authority but does not clear Android's CE cache. */
    public Operation beginReset(Object identity) {
        final ArrayList<Delivery> events;
        final Operation token;
        synchronized (this) {
            events = invalidateAll();
            final boolean eligible = matches(identity) && pendingRevocations == 0;
            boolean counted = matches(identity);
            if (counted && pendingRevocations == Integer.MAX_VALUE) {
                exhaust(); counted = false;
            }
            if (counted) ++pendingRevocations;
            token = new Operation(this, -1, Kind.RESET, eligible, counted);
            finishEvents(events);
        }
        deliver(events);
        return token;
    }

    /** Finish single-user operations after upstream cache mutation, outside SMS mLock. */
    public void complete(Operation token, boolean success) {
        if (token != null && (token.kind == Kind.RESET || token.kind == Kind.RESTORE)) {
            throw new IllegalArgumentException("bulk operation");
        }
        completeInternal(token, success, null);
    }

    /**
     * A successful reset may revalidate the preserved platform cache, but only when
     * no later revocation/backend change overlapped it. A restoration query has the
     * same fence. Old completions cannot acquire the newest generation by arriving
     * late. Call with a copy of upstream IDs, outside StorageManagerService.mLock.
     */
    public void completeBulk(Operation token, boolean success, int[] unlockedUsers) {
        Objects.requireNonNull(unlockedUsers);
        if (token != null && token.kind != Kind.RESET && token.kind != Kind.RESTORE) {
            throw new IllegalArgumentException("single-user operation");
        }
        completeInternal(token, success, unlockedUsers.clone());
    }

    private void completeInternal(Operation token, boolean success, int[] unlockedUsers) {
        final ArrayList<Delivery> events = new ArrayList<>();
        synchronized (this) {
            if (token == null || token.owner != this || token.completed) return;
            token.completed = true;
            final boolean sameBackend = token.backend == backend && token.daemon == daemon;
            if (sameBackend && token.counted && pendingRevocations > 0) --pendingRevocations;
            if (token.kind == Kind.REVOKE) return; // Never undo pre-request revocation.
            if (!sameBackend || exhausted) return;
            if (!success) {
                if (token.kind == Kind.AVAILABLE) {
                    if (advance()) ++revision;
                    events.add(publish(token.userId, false, true));
                } else events.addAll(invalidateAll());
            } else if (token.eligible && token.revision == revision && pendingRevocations == 0) {
                if (token.kind == Kind.AVAILABLE) {
                    advance(); events.add(publish(token.userId, true, false));
                } else {
                    for (int id : unlockedUsers) {
                        advance(); events.add(publish(id, true, false));
                    }
                }
            }
            finishEvents(events);
        }
        deliver(events);
    }
}
