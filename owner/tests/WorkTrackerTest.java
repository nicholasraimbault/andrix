// SPDX-License-Identifier: Apache-2.0
import dev.andrix.session.WorkInfo;
import dev.andrix.terminal.protocol.WorkReference;
import dev.andrix.terminal.protocol.WorkTracker;
import dev.andrix.terminal.protocol.WorkTracker.Query;

public final class WorkTrackerTest {
    static WorkInfo info(long id, int state, int policy, int recovery) {
        WorkInfo i = new WorkInfo(); i.workId = id; i.state = state;
        i.lifetimePolicy = policy; i.terminalRecovery = recovery; return i;
    }
    static WorkReference<Object> reference(Object binder, long id, int state) {
        return new WorkReference<>(binder, binder, info(id, state, WorkInfo.EXPLICIT_KEEP, WorkInfo.RECREATE_TERMINAL));
    }
    static void invalid(Object service, Object binder, WorkInfo i) {
        try { new WorkReference<>(service, binder, i); throw new AssertionError("accepted invalid metadata"); }
        catch (IllegalArgumentException expected) { }
    }
    public static void main(String[] args) {
        Object a = new Object(), b = new Object();
        WorkInfo source = info(7, WorkInfo.RUNNING, WorkInfo.EXPLICIT_KEEP, WorkInfo.CONTINUOUS_TERMINAL);
        WorkReference<Object> detachedRoot = new WorkReference<>(a, a, source);
        assert detachedRoot.retained() && !detachedRoot.recreatesTerminal();
        source.workId = 99; source.state = WorkInfo.IDLE;
        assert detachedRoot.id == 7 && detachedRoot.state == WorkInfo.RUNNING; // Immutable copy.
        WorkReference<Object> boundClient = new WorkReference<>(b, b,
                info(8, WorkInfo.RUNNING, WorkInfo.CONSOLE_BOUND, WorkInfo.RECREATE_TERMINAL));
        assert !boundClient.retained() && boundClient.recreatesTerminal(); // Independent axes.
        invalid(null, a, source); invalid(a, null, source); invalid(a, a, null);
        for (long bad : new long[] {0, -1, Long.MIN_VALUE})
            invalid(a, a, info(bad, WorkInfo.RUNNING, WorkInfo.CONSOLE_BOUND, WorkInfo.CONTINUOUS_TERMINAL));
        for (int bad : new int[] {-1, 4, Integer.MAX_VALUE})
            invalid(a, a, info(7, bad, WorkInfo.CONSOLE_BOUND, WorkInfo.CONTINUOUS_TERMINAL));
        invalid(a, a, info(7, WorkInfo.RUNNING, 2, WorkInfo.CONTINUOUS_TERMINAL));
        invalid(a, a, info(7, WorkInfo.RUNNING, WorkInfo.CONSOLE_BOUND, 2));

        WorkTracker<Object> work = new WorkTracker<>();
        Query initial = work.beginQuery(); assert initial != null && work.beginQuery() == null;
        WorkReference<Object> idle = reference(a, 7, WorkInfo.IDLE);
        assert work.finishQuery(initial, idle, true) && work.current() == idle;
        assert !idle.hasWork() && !idle.canRequestStop();
        assert !work.attached(idle) && !work.attached(reference(a, 7, WorkInfo.PREPARING));
        WorkReference<Object> active = reference(a, 7, WorkInfo.RUNNING);
        assert work.attached(active);
        Query delayed = work.beginQuery();
        work.invalidate(); // A new user intent overtakes a query, without allowing another hung RPC.
        assert work.beginQuery() == null && !work.queryCurrent(delayed);
        assert !work.finishQuery(delayed, idle, true) && work.current() == active;
        Query later = work.beginQuery(); assert later != null;
        assert !work.finishQuery(delayed, idle, true) && work.queryCurrent(later);
        work.failQuery(delayed); assert work.queryCurrent(later);
        assert !work.finishQuery(later, idle, false) && work.current() == active; // Ineligible UI.

        Query unavailable = work.beginQuery(); work.failQuery(unavailable);
        assert work.current() == active; // An RPC error is not an empty-work observation.
        Query old = work.beginQuery();
        WorkReference<Object> replacement = reference(b, 9, WorkInfo.RUNNING);
        assert work.attached(replacement);
        assert !work.finishQuery(old, active, true) && work.current() == replacement;

        Object token = work.invalidate();
        assert !work.stopAccepted(token, active) && work.current() == replacement;
        assert !replacement.sameTarget(reference(a, 9, WorkInfo.RUNNING));
        assert !replacement.sameTarget(reference(b, 7, WorkInfo.RUNNING));
        Query beforeReceipt = work.beginQuery();
        assert work.stopAccepted(token, replacement);
        assert work.current().state == WorkInfo.STOPPING && !work.current().canRequestStop();
        assert work.current().hasWork(); // Stop is not a completed cleanup observation.
        assert !work.finishQuery(beforeReceipt, replacement, true);
        assert !work.attached(replacement); // A late attachment cannot revive a stopped work identity.
        Query regressing = work.beginQuery();
        assert !work.finishQuery(regressing, reference(b, 9, WorkInfo.IDLE), true);
        assert work.current().state == WorkInfo.STOPPING;

        WorkReference<Object> newer = reference(new Object(), 10, WorkInfo.RUNNING);
        assert work.attached(newer);
        assert !work.stopAccepted(token, replacement) && work.current() == newer;
        Query absent = work.beginQuery();
        assert work.finishQuery(absent, null, true) && work.current() == null;
        WorkReference<Object> preparing = reference(a, 11, WorkInfo.PREPARING);
        assert preparing.canRequestStop(); // Pending work is stoppable without any terminal capability.
        Query pending = work.beginQuery(); assert work.finishQuery(pending, preparing, true);
        token = work.invalidate(); assert work.stopAccepted(token, preparing);
        assert work.current().state == WorkInfo.STOPPING;
        System.out.println("Work identity, immutable metadata and stale query/Stop fences passed; Android unqualified");
    }
}
