// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server;

import dev.andrix.server.KeepWorkState.Record;

import java.util.UUID;

/** Host-testable ordering around the Android adapters. No timers or key authority. */
final class KeepWork {
    interface Lifetime {
        Object identity(); // The actual coordinator service Binder, never its PID.
        void link(Runnable death) throws Exception;
        void unlink();
        boolean isAlive();
        void stop(long workId, long registration) throws Exception;
    }
    interface Backend {
        boolean post(Record<Lifetime> record);
        void cancel(Record<Lifetime> record);
        void execute(Runnable command);
        void error(String message, Exception error);
    }
    static final class Snapshot {
        final OwnerLifecycleState.State platform;
        final long workId, registration;
        Snapshot(OwnerLifecycleState.State platform, Record<Lifetime> active) {
            this.platform = platform;
            workId = active == null ? 0 : active.workId;
            registration = active == null ? 0 : active.registration;
        }
    }

    private final boolean enabled;
    private final OwnerLifecycleState lifecycle;
    private final KeepWorkState<Lifetime> state;
    private final Backend backend;

    KeepWork(boolean enabled, long instance, OwnerLifecycleState lifecycle, Backend backend) {
        this.enabled = enabled; this.lifecycle = lifecycle; this.backend = backend;
        state = new KeepWorkState<>(instance);
    }

    Snapshot snapshot() {
        synchronized (lifecycle) {
            OwnerLifecycleState.State platform = lifecycle.snapshot();
            return new Snapshot(platform, state.active(platform));
        }
    }

    // May be called with the lifecycle monitor held, including from storage/user
    // callbacks: memory only. Existing lifecycle publication does all OS cleanup.
    void platformChanged() {
        synchronized (lifecycle) { state.observe(lifecycle.snapshot()); }
    }

    long keep(Lifetime lifetime, long workId, long instance, long generation) {
        if (!enabled || lifetime == null) return 0;
        Object identity = lifetime.identity();
        String nonce = UUID.randomUUID().toString();
        final Record<Lifetime> record;
        synchronized (lifecycle) {
            record = state.begin(identity, lifetime, workId, instance, generation,
                    lifecycle.snapshot(), nonce);
        }
        if (record == null) return 0;
        boolean committed = false;
        try {
            lifetime.link(() -> died(record));
            synchronized (lifecycle) {
                if (!state.linked(record, lifecycle.snapshot())) return 0;
            }
            // Enqueue alone is insufficient: the adapter waits at most 400ms for
            // the matching active tag, with channel/app checks and no locks held.
            if (!backend.post(record) || !lifetime.isAlive()) return 0;
            synchronized (lifecycle) {
                committed = state.commit(record, lifecycle.snapshot());
                return committed ? record.registration : 0;
            }
        } catch (Exception error) {
            backend.error("Keep registration failed", error);
            return 0;
        } finally {
            boolean bound;
            synchronized (lifecycle) {
                if (!committed) state.abort(record);
                bound = state.isBound(record);
            }
            // A revoke/death cancel can run BEFORE an in-flight notify returns.
            // Cancel again after failed completion, using this registration's tag.
            if (!committed) cancel(record);
            if (!bound) {
                try { lifetime.unlink(); }
                catch (RuntimeException error) { backend.error("Keep unlink failed", error); }
            }
        }
    }

    void stop(String token) {
        final Record<Lifetime> record;
        synchronized (lifecycle) { record = state.stop(token); }
        if (record != null) execute(() -> stopRecord(record));
    }

    void notificationRevoked() {
        final Record<Lifetime> record;
        synchronized (lifecycle) { record = state.revokeNotification(); }
        if (record != null) execute(() -> stopRecord(record));
    }

    private void died(Record<Lifetime> record) {
        synchronized (lifecycle) { state.died(record); }
        execute(() -> cancel(record)); // No auto-work restart and no init request on death.
    }

    // Called on the existing publication handler, after it has sampled the global
    // lifecycle. Revocation needs no second/parallel process manager.
    void cancelRevoked() {
        final Record<Lifetime> record;
        synchronized (lifecycle) { record = state.retiring(); }
        if (record != null) cancel(record);
    }

    private void stopRecord(Record<Lifetime> record) {
        cancel(record);
        synchronized (lifecycle) { if (!state.beginStop(record)) return; }
        try {
            // The callback targets the old process-lifetime Binder, NOT an init
            // service name/PID. Death immediately after isAlive cannot retarget it
            // to a fresh coordinator (even a plain one outside the Keep slot).
            if (!record.lifetime.isAlive()) { died(record); return; }
            synchronized (lifecycle) { if (!state.canStop(record)) return; }
            record.lifetime.stop(record.workId, record.registration);
            // Oneway delivery is a stop request, never a cleanup acknowledgement.
        } catch (Exception error) {
            backend.error("Keep stop request failed (not a cleanup acknowledgement)", error);
        } finally {
            synchronized (lifecycle) { state.finishStop(record); }
        }
    }

    private void execute(Runnable command) {
        try { backend.execute(command); }
        catch (RuntimeException error) { backend.error("Keep command handler unavailable", error); }
    }

    private void cancel(Record<Lifetime> record) {
        try { backend.cancel(record); }
        catch (RuntimeException error) { backend.error("Keep notification cancel failed", error); }
    }
}
