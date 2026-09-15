// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server;

/** Lab-only, memory-only fault budget. This class supplies no Android authority. */
final class LifecycleFaultGate {
    static final long REPLY_DELAY_MILLIS = 2500;
    static final long ARM_WINDOW_MILLIS = 5000;

    static final class Target {
        final long instance, generation, work, registration;
        final boolean available;
        Target(long instance, long generation, boolean available, long work, long registration) {
            this.instance = instance; this.generation = generation; this.available = available;
            this.work = work; this.registration = registration;
        }
        boolean valid() {
            return available && instance > 0 && generation > 0 && work > 0 && registration > 0;
        }
        boolean matches(Target other) {
            return other != null && valid() && other.valid() && instance == other.instance
                    && generation == other.generation && work == other.work
                    && registration == other.registration;
        }
        @Override public String toString() {
            return "instance=" + instance + " generation=" + generation + " work=" + work
                    + " registration=" + registration;
        }
    }

    private boolean delayUsed, keyUsed;
    private Target armed, delaying, locking;
    private long armedAt;

    synchronized boolean armDelay(Target target, long now) {
        expire(now);
        if (target == null || !target.valid() || now < 0
                || now > Long.MAX_VALUE - ARM_WINDOW_MILLIS
                || delayUsed || locking != null || delaying != null || armed != null) return false;
        delayUsed = true; // Accepted use is consumed even if it later expires or changes target.
        armed = target; armedAt = now;
        return true;
    }

    synchronized Target takeDelay(Target current, long now) {
        expire(now);
        Target target = armed;
        armed = null; // A mismatching epoch/work must never leave a trap for a later target.
        if (target == null || !target.matches(current)) return null;
        delaying = target;
        return target;
    }

    synchronized void finishDelay(Target ticket) {
        if (ticket != null && delaying == ticket) delaying = null;
    }

    synchronized Target beginKeyLock(Target target, long now) {
        expire(now);
        if (now < 0 || target == null || !target.valid() || keyUsed
                || armed != null || delaying != null || locking != null) return null;
        keyUsed = true; locking = target;
        return target;
    }

    synchronized void finishKeyLock(Target ticket) {
        if (ticket != null && locking == ticket) locking = null;
    }

    private void expire(long now) {
        if (armed != null && (now < armedAt || now - armedAt >= ARM_WINDOW_MILLIS)) armed = null;
    }
}
