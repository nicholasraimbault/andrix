// SPDX-License-Identifier: Apache-2.0
package dev.andrix.terminal.protocol;

import dev.andrix.session.WorkInfo;

/**
 * Bounded metadata observation and exact Stop completion targeting. No Binder or
 * other I/O occurs here. Work records do not grant terminal or retention authority.
 */
public final class WorkTracker<T> {
    public static final class Query {
        private final Object version;
        private Query(Object version) { this.version = version; }
    }
    private Object version = new Object();
    private Query pending;
    private WorkReference<T> current;

    public synchronized WorkReference<T> current() { return current; }

    /** A new intent invalidates old observations without permitting another hung RPC. */
    public synchronized Object invalidate() {
        version = new Object();
        return version;
    }
    public synchronized Query beginQuery() {
        if (pending != null) return null;
        pending = new Query(version);
        return pending;
    }
    public synchronized boolean queryCurrent(Query query) {
        return query != null && query == pending && query.version == version;
    }
    public synchronized boolean finishQuery(Query query, WorkReference<T> value, boolean eligible) {
        if (query == null || query != pending) return false;
        pending = null;
        if (!eligible || query.version != version || revivesStopped(value)) return false;
        current = value; // Null means the exact observation found no service, not an RPC error.
        return true;
    }
    public synchronized void failQuery(Query query) {
        if (query != null && query == pending) pending = null;
    }
    /** A successful attachment supplies work metadata without another RPC in its lease window. */
    public synchronized boolean attached(WorkReference<T> value) {
        if (value == null || value.state != WorkInfo.RUNNING || revivesStopped(value)) return false;
        invalidate();
        current = value;
        return true;
    }
    private boolean revivesStopped(WorkReference<T> value) {
        return current != null && current.state == WorkInfo.STOPPING && current.sameTarget(value)
                && value.state != WorkInfo.STOPPING;
    }
    public synchronized boolean currentTarget(Object token, WorkReference<T> target) {
        return token == version && current != null && current.sameTarget(target);
    }
    public synchronized boolean stopAccepted(Object token, WorkReference<T> target) {
        if (!currentTarget(token, target)) return false;
        invalidate();
        current = current.stopping();
        return true; // A local request receipt, not complete process cleanup.
    }
}
