// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server;

/**
 * One daemon/work consent slot, not a process supervisor. Callers guard this and
 * OwnerLifecycleState with the lifecycle monitor. All methods are memory-only;
 * Binder, notifications, handlers and init must be called after dropping it.
 */
final class KeepWorkState<T> {
    static final class Record<T> {
        final Object binderIdentity;
        final T lifetime;
        final long workId, instance, generation, registration;
        final String token;
        private boolean linked, active, retiring, dead, stopRequested, stopInFlight;

        Record(Object binderIdentity, T lifetime, long workId, long instance,
                long generation, long registration, String nonce) {
            this.binderIdentity = binderIdentity; this.lifetime = lifetime;
            this.workId = workId; this.instance = instance; this.generation = generation;
            this.registration = registration;
            token = "andrix-keep://stop/" + instance + "/" + registration + "/" + nonce;
        }
    }

    private final long instance;
    private long lastRegistration;
    private Record<T> record;

    KeepWorkState(long instance) {
        if (instance <= 0) throw new IllegalArgumentException("invalid platform instance");
        this.instance = instance;
    }

    Record<T> begin(Object binderIdentity, T lifetime, long workId, long requestedInstance,
            long generation, OwnerLifecycleState.State platform, String nonce) {
        observe(platform);
        // No idempotent duplicate or plain-work conversion. A failed, uncommitted
        // attempt may be retried, but an active/retiring live binding cannot be replaced.
        if (record != null || binderIdentity == null || lifetime == null || workId <= 0
                || requestedInstance != instance || generation <= 0
                || !platform.available || generation != platform.generation
                || lastRegistration == Long.MAX_VALUE || nonce == null || nonce.isEmpty()) {
            return null;
        }
        record = new Record<>(binderIdentity, lifetime, workId, instance, generation,
                ++lastRegistration, nonce);
        return record; // Installed BEFORE linkToDeath and notification posting.
    }

    void observe(OwnerLifecycleState.State platform) {
        if (record != null && (!platform.available || record.generation != platform.generation)) {
            retire(record); // Includes a new positive epoch overtaking a negative.
        }
    }

    boolean linked(Record<T> candidate, OwnerLifecycleState.State platform) {
        observe(platform);
        if (!isBound(candidate)) return false;
        candidate.linked = true;
        return !candidate.retiring;
    }

    boolean commit(Record<T> candidate, OwnerLifecycleState.State platform) {
        observe(platform);
        if (!isBound(candidate) || candidate.retiring || candidate.active || !candidate.linked) {
            return false;
        }
        candidate.active = true;
        return true;
    }

    void abort(Record<T> candidate) {
        // No grant was returned, hence no newly admitted kept work. A concurrent
        // Stop/revocation instead owns retirement and must retain its death link.
        if (record == candidate && !candidate.active && !candidate.retiring) record = null;
    }

    Record<T> active(OwnerLifecycleState.State platform) {
        observe(platform);
        return record != null && record.active && !record.retiring && !record.dead ? record : null;
    }

    Record<T> stop(String token) {
        if (record == null || !record.token.equals(token) || record.dead || record.stopRequested) {
            return null;
        }
        record.stopRequested = true;
        retire(record); // A Stop of a pending notification is effective immediately.
        return record;
    }

    Record<T> revokeNotification() {
        return record == null ? null : stop(record.token);
    }

    private void retire(Record<T> candidate) {
        candidate.active = false; candidate.retiring = true;
    }

    void died(Record<T> candidate) {
        candidate.dead = true; retire(candidate);
        // An already executing callback fences replacement admission until its
        // I/O returns. This tombstone is never an active grant or cleanup ack.
        if (record == candidate && !candidate.stopInFlight) record = null;
    }

    boolean isBound(Record<T> candidate) {
        return record == candidate && !candidate.dead;
    }

    Record<T> retiring() { return record != null && record.retiring ? record : null; }

    boolean beginStop(Record<T> candidate) {
        if (!isBound(candidate) || !candidate.retiring || !candidate.stopRequested
                || candidate.stopInFlight) return false;
        candidate.stopInFlight = true;
        return true;
    }

    boolean canStop(Record<T> candidate) {
        return isBound(candidate) && candidate.stopInFlight;
    }

    void finishStop(Record<T> candidate) {
        candidate.stopInFlight = false;
        if (record == candidate && candidate.dead) record = null;
    }
}
