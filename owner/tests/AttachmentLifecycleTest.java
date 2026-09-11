// SPDX-License-Identifier: Apache-2.0
import dev.andrix.terminal.protocol.AttachmentLifecycle;
import dev.andrix.terminal.protocol.AttachmentLifecycle.Request;
import java.util.concurrent.CountDownLatch;

public final class AttachmentLifecycleTest {
    public static void main(String[] args) throws Exception {
        AttachmentLifecycle<Object> slot = new AttachmentLifecycle<>();
        Request request = slot.begin(); Object lease = new Object();
        assert slot.retain(request, lease);
        // During arbitrarily delayed Main work the existing heartbeat sees this
        // lease. Only active ownership can expose input; time does not promote it.
        for (int turn = 0; turn < 10000; ++turn) {
            assert slot.lease() == lease && slot.active() == null;
            assert !slot.inputAllowed(lease) && slot.preparing();
        }
        assert slot.promote(request, lease, true);
        assert slot.lease() == lease && slot.active() == lease && slot.inputAllowed(lease);
        assert !slot.finish(request);
        slot.blockInput(lease);
        assert !slot.inputAllowed(lease) && slot.active() == lease; // End still possible
        assert slot.cancel() == lease && !slot.owns(lease);

        // Cancelled in-flight RPC cannot accumulate replacements or retain its late FD.
        Request cancelled = slot.begin();
        assert slot.cancel() == null && slot.begin() == null;
        assert !slot.retain(cancelled, lease);
        assert slot.finish(cancelled);
        Request newer = slot.begin(); Object next = new Object();
        assert !slot.finish(cancelled) && slot.current(newer);
        assert slot.retain(newer, next);
        assert !slot.finish(newer); // cannot forget a still-owned FD
        assert slot.retire(next); // renewal false/exception, or other retirement
        assert !slot.promote(newer, next, true) && !slot.inputAllowed(next);
        assert slot.finish(newer);

        Request duringPrepare = slot.begin();
        assert slot.retain(duringPrepare, lease);
        assert slot.cancel() == lease;
        assert !slot.promote(duringPrepare, lease, true);
        assert slot.finish(duringPrepare);

        Request gap = slot.begin();
        assert slot.retain(gap, lease) && slot.promote(gap, lease, false);
        assert slot.active() == lease && !slot.inputAllowed(lease);
        assert !slot.retire(next) && slot.owns(lease); // stale object cannot retire current
        assert slot.cancel() == lease;

        // Promotion versus retirement cannot restore input on a retired object.
        for (int i = 0; i < 200; ++i) {
            AttachmentLifecycle<Object> race = new AttachmentLifecycle<>();
            Request r = race.begin(); Object c = new Object();
            assert race.retain(r, c);
            CountDownLatch start = new CountDownLatch(1);
            Thread promote = new Thread(() -> { await(start); race.promote(r, c, true); });
            Thread retire = new Thread(() -> { await(start); race.retire(c); });
            promote.start(); retire.start(); start.countDown(); promote.join(); retire.join();
            assert !race.owns(c) && !race.inputAllowed(c) && race.active() == null;
            race.finish(r);
            assert race.begin() != null;
        }
        System.out.println("Pending/active ownership races passed; Android unqualified");
    }
    private static void await(CountDownLatch latch) {
        try { latch.await(); } catch (InterruptedException e) { throw new AssertionError(e); }
    }
}
