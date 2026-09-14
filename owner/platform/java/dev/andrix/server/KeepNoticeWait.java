// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server;

/** Bounded acknowledgement of OUR notification, not polling for OS/key authority. */
final class KeepNoticeWait {
    interface Probe {
        boolean allowed();
        boolean active();
    }
    interface Clock {
        long now();
        void sleep(long millis);
    }
    private static final long LIMIT_MS = 400, STEP_MS = 20;

    static boolean await(Probe probe, Clock clock) {
        long start = clock.now();
        if (start < 0 || start > Long.MAX_VALUE - LIMIT_MS) return false;
        long deadline = start + LIMIT_MS, observed = start;
        for (;;) {
            long now = clock.now();
            if (now < observed || now > deadline || !probe.allowed()) return false;
            observed = now; now = clock.now();
            if (now < observed || now > deadline) return false;
            observed = now;
            if (probe.active()) {
                now = clock.now();
                if (now < observed || now > deadline || !probe.allowed()) return false;
                observed = now; now = clock.now(); // The final check may itself have stalled.
                return now >= observed && now <= deadline;
            }
            now = clock.now();
            if (now < observed || now >= deadline) return false;
            observed = now;
            clock.sleep(Math.min(STEP_MS, deadline - now));
        }
    }
}
