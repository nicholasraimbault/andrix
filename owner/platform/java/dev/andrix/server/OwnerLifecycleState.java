// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server;

/** Small state composition: Android user lifecycle AND fenced CE access metadata. */
final class OwnerLifecycleState {
    static final class State {
        final long generation;
        final boolean available;
        State(long generation, boolean available) {
            this.generation = generation; this.available = available;
        }
    }
    private long generation = 1, userRevision, ceSequence = -1, ceRevocation = -1;
    private boolean userReady, ceReady, failed;

    private void revoke() {
        if (generation >= Long.MAX_VALUE - 1) { fail(); return; }
        ++generation;
    }
    synchronized long userRevision() { return userRevision; }
    synchronized void bootstrapUser(long expected, boolean ready) {
        if (expected == userRevision && !failed) userReady = ready;
    }
    synchronized void user(boolean ready) {
        if (failed) return;
        if (userRevision == Long.MAX_VALUE) { fail(); return; }
        ++userRevision;
        // Lifecycle callbacks, not screen focus/relock, drive this value.
        if (!ready) revoke();
        userReady = ready;
    }
    synchronized void ce(long sequence, long revocation, boolean available) {
        if (failed) return;
        if (sequence <= 0 || revocation <= 0) { fail(); return; }
        if (sequence <= ceSequence) return; // Includes a delayed initial snapshot.
        if ((ceRevocation > 0 && revocation < ceRevocation)
                || (available && (sequence == Long.MAX_VALUE || revocation == Long.MAX_VALUE))) {
            fail(); return;
        }
        if ((ceRevocation != -1 && revocation != ceRevocation) || (ceReady && !available)) {
            revoke(); // A positive carrying a new revocation still ends old work.
        }
        ceSequence = sequence; ceRevocation = revocation; ceReady = available;
    }
    synchronized void fail() {
        failed = true; generation = Long.MAX_VALUE; userReady = ceReady = false;
    }
    synchronized State snapshot() { return new State(generation, !failed && userReady && ceReady); }
}
