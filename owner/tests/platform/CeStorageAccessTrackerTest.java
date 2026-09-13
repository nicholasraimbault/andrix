// SPDX-License-Identifier: Apache-2.0
package com.android.server.storage;

import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public final class CeStorageAccessTrackerTest {
    private static final class Latest implements CeStorageAccessTracker.Listener {
        CeStorageAccessTracker.Snapshot state;
        @Override public synchronized void onStateChanged(CeStorageAccessTracker.Snapshot next) {
            if (state == null || next.sequence > state.sequence) state = next;
        }
    }
    private static CeStorageAccessTracker tracker() {
        return new CeStorageAccessTracker(error -> { throw new AssertionError(error); });
    }
    private static void ready(CeStorageAccessTracker tracker, int user, Object daemon) {
        tracker.complete(tracker.beginAvailable(user, daemon), true);
    }

    private static void registrationAndRevocation() {
        CeStorageAccessTracker tracker = tracker();
        Latest latest = new Latest();
        var initial = tracker.register(0, latest);
        assert !initial.available;
        Object daemon = new Object(); tracker.connected(daemon);
        ready(tracker, 0, daemon);
        assert latest.state.available;
        latest.onStateChanged(initial); // Returned snapshot processed after a newer event.
        assert latest.state.available;
        long oldRevocation = latest.state.revocation;
        var delayed = tracker.beginAvailable(0, daemon);
        var revoke = tracker.beginRevocation(0, daemon);
        assert !latest.state.available && latest.state.revocation > oldRevocation;
        var overlapping = tracker.beginAvailable(0, daemon);
        tracker.complete(revoke, false); // Failed lock does not restore old authority.
        tracker.complete(delayed, true);
        tracker.complete(overlapping, true);
        assert !latest.state.available;
        ready(tracker, 0, daemon);
        assert latest.state.available;
        long restoredSequence = latest.state.sequence;
        tracker.complete(delayed, true); // Consumed once, including stale completion.
        tracker.complete(revoke, true);
        assert latest.state.sequence == restoredSequence;
        var current = tracker.beginAvailable(0, daemon);
        tracker().complete(current, true); // Wrong tracker cannot consume this token.
        tracker.complete(current, true);
        assert latest.state.sequence > restoredSequence;
        tracker.complete(tracker.beginAvailable(0, daemon), false);
        assert !latest.state.available;
    }

    private static void backendReplacementAndRestoration() {
        CeStorageAccessTracker tracker = tracker(); Latest latest = new Latest();
        tracker.register(0, latest);
        Object old = new Object(); tracker.connected(old); ready(tracker, 0, old);
        var oldReply = tracker.beginAvailable(0, old);
        var oldRestore = tracker.beginRestore(old);
        Object replacement = new Object(); tracker.connected(replacement);
        assert !latest.state.available;
        long replacementSequence = latest.state.sequence;
        tracker.died(old); // Stale death cannot revoke/rewrite replacement state.
        tracker.complete(oldReply, true);
        tracker.completeBulk(oldRestore, true, new int[]{0});
        assert latest.state.sequence == replacementSequence && !latest.state.available;
        var emptyRestore = tracker.beginRestore(replacement);
        tracker.completeBulk(emptyRestore, true, new int[0]);
        var reset = tracker.beginReset(replacement);
        tracker.completeBulk(reset, true, new int[]{0}); // Old cache is not new-backend evidence.
        assert !latest.state.available;
        var restore = tracker.beginRestore(replacement);
        tracker.completeBulk(restore, true, new int[]{0});
        assert latest.state.available;
        tracker.died(replacement);
        assert !latest.state.available;
        ready(tracker, 0, replacement); // No live binding: never authorizes.
        assert !latest.state.available;
        tracker.connected(new Object());
    }

    private static void resetFences() {
        CeStorageAccessTracker tracker = tracker(); Latest latest = new Latest();
        tracker.register(0, latest); Object daemon = new Object(); tracker.connected(daemon);
        ready(tracker, 0, daemon);
        var oldReply = tracker.beginAvailable(0, daemon);
        var reset = tracker.beginReset(daemon);
        assert !latest.state.available;
        tracker.complete(oldReply, true);
        assert !latest.state.available;
        tracker.completeBulk(reset, true, new int[]{0}); // Reset preserves upstream CE cache.
        assert latest.state.available;

        reset = tracker.beginReset(daemon);
        var lock = tracker.beginRevocation(0, daemon);
        tracker.complete(lock, true);
        tracker.completeBulk(reset, true, new int[]{0}); // Cache may still say true: fenced out.
        assert !latest.state.available;
        ready(tracker, 0, daemon); assert latest.state.available;

        lock = tracker.beginRevocation(0, daemon);
        reset = tracker.beginReset(daemon); // Reset started during an existing key operation.
        tracker.complete(lock, true);
        tracker.completeBulk(reset, true, new int[]{0});
        assert !latest.state.available;
        ready(tracker, 0, daemon); assert latest.state.available;

        var restore = tracker.beginRestore(daemon);
        lock = tracker.beginRevocation(0, daemon);
        tracker.complete(lock, true);
        tracker.completeBulk(restore, true, new int[]{0});
        assert !latest.state.available;
        // Rejected restore can still have appended to the upstream cache. A
        // later non-overlapping reset must not launder it into new authority.
        reset = tracker.beginReset(daemon);
        tracker.completeBulk(reset, true, new int[]{0});
        assert !latest.state.available;
        reset = tracker.beginReset(daemon);
        tracker.completeBulk(reset, true, new int[]{0});
        assert !latest.state.available;
        ready(tracker, 0, daemon); // A fresh successful operation is new evidence.
        reset = tracker.beginReset(daemon);
        tracker.completeBulk(reset, false, new int[]{0});
        assert !latest.state.available;
        reset = tracker.beginReset(daemon);
        tracker.completeBulk(reset, true, new int[]{0});
        assert !latest.state.available; // Failure is not undone by cache membership either.
        ready(tracker, 0, daemon); assert latest.state.available; // No stuck revocation count.
        Latest unknown = new Latest(); tracker.register(1, unknown);
        reset = tracker.beginReset(daemon);
        tracker.completeBulk(reset, true, new int[]{0, 1});
        assert latest.state.available && !unknown.state.available;
    }

    private static void listenerSafetyAndOrdering() throws Exception {
        AtomicInteger errors = new AtomicInteger();
        CeStorageAccessTracker tracker = new CeStorageAccessTracker(error -> errors.incrementAndGet());
        Latest latest = new Latest();
        tracker.register(0, state -> { throw new IllegalStateException("observer failure"); });
        tracker.register(0, latest);
        AtomicBoolean checked = new AtomicBoolean();
        AtomicReference<Throwable> problem = new AtomicReference<>();
        tracker.register(0, state -> {
            if (!checked.compareAndSet(false, true)) return;
            Thread thread = new Thread(() -> {
                try { tracker.register(1, ignored -> { }); }
                catch (Throwable failure) { problem.set(failure); }
            });
            thread.start();
            try { thread.join(2000); }
            catch (InterruptedException error) { throw new AssertionError(error); }
            if (thread.isAlive()) problem.set(new AssertionError("callback held tracker lock"));
        });
        Object daemon = new Object(); tracker.connected(daemon);
        assert checked.get() && problem.get() == null;
        assert errors.get() == 1 && !latest.state.available;
        ready(tracker, 0, daemon);
        assert errors.get() == 2 && latest.state.available;
        var oldPositive = latest.state;
        var lock = tracker.beginRevocation(0, daemon);
        var negative = latest.state;
        tracker.complete(lock, true); ready(tracker, 0, daemon);
        var freshPositive = latest.state;
        assert freshPositive.revocation == negative.revocation;
        latest.onStateChanged(negative); latest.onStateChanged(oldPositive);
        assert latest.state == freshPositive;
        tracker.unregister(0, latest);
        tracker.beginRevocation(0, daemon);
        assert latest.state == freshPositive;
    }

    private static void exhaustion() {
        CeStorageAccessTracker tracker = new CeStorageAccessTracker(error -> { }, Long.MAX_VALUE - 3);
        Latest first = new Latest(), second = new Latest();
        tracker.register(0, first); tracker.register(1, second);
        Object daemon = new Object(); tracker.connected(daemon);
        ready(tracker, 0, daemon);
        assert first.state.available && first.state.sequence == Long.MAX_VALUE - 1;
        tracker.beginRevocation(1, daemon);
        assert !first.state.available && !second.state.available;
        assert first.state.sequence == Long.MAX_VALUE && second.state.sequence == Long.MAX_VALUE;
        ready(tracker, 0, daemon); tracker.connected(new Object());
        assert !first.state.available;
        assert !tracker.register(2, ignored -> { }).available;
    }

    public static void main(String[] args) throws Exception {
        registrationAndRevocation(); backendReplacementAndRestoration(); resetFences();
        listenerSafetyAndOrdering(); exhaustion();
        System.out.println("CE observation fencing/registration/reset tests passed; Android unqualified");
    }
}
