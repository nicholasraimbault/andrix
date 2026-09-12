// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.lifecycle;

/** Pure observation predicate, not a cryptographic attestation or job grant. */
public final class LifecycleSample {
    private LifecycleSample() {}

    public static boolean usable(boolean querySucceeded, boolean runningBefore,
                                 boolean unlocked, boolean runningAfter) {
        // UserManager may report CE-unlocked while a user is stopping. Running
        // is a separate requirement; screen/keyguard lock is intentionally not here.
        return querySucceeded && runningBefore && unlocked && runningAfter;
    }

    public static boolean fresh(long now, long observed, long maximumAge) {
        return observed >= 0 && maximumAge > 0 && now >= observed
                && now - observed < maximumAge;
    }
}
