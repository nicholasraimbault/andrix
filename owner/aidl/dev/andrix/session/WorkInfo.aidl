// SPDX-License-Identifier: Apache-2.0
package dev.andrix.session;

// Metadata for one coordinator/work scope. This is not a terminal capability,
// a fresh Android authority grant or acknowledgement of complete group cleanup.
// workId is immutable for the coordinator's lifetime, including while idle.
parcelable WorkInfo {
    const int IDLE = 0;
    const int PREPARING = 1;
    const int RUNNING = 2;
    const int STOPPING = 3;

    // Existing compatibility policies. PREPARING reports the requested policy,
    // not an active retention grant. No new default or automatic restart policy.
    const int CONSOLE_BOUND = 0;
    const int EXPLICIT_KEEP = 1;

    // Presentation recovery is independent of workload retention permission.
    const int CONTINUOUS_TERMINAL = 0;
    const int RECREATE_TERMINAL = 1;

    long workId;
    int state;
    int lifetimePolicy;
    int terminalRecovery;
}
