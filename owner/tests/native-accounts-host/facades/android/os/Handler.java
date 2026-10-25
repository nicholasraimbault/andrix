// SPDX-License-Identifier: Apache-2.0
// Host test input only. Not an Android build input.
package android.os;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
/** Main callbacks do not execute automatically. Test owns all scheduling events. */
public final class Handler {
    private static final LinkedBlockingQueue<Runnable> ready=new LinkedBlockingQueue<>();
    private static final Deque<Runnable> delayed=new ArrayDeque<>();
    public Handler(Looper main) { if (main != Looper.getMainLooper()) throw new AssertionError(); }
    public boolean post(Runnable task) { ready.add(task); return true; }
    public boolean postDelayed(Runnable task, long millis) {
        if (millis!=5000) throw new AssertionError("unexpected display delay");
        synchronized (delayed) { delayed.addLast(task); }
        return true;
    }
    public void removeCallbacks(Runnable task) {
        ready.remove(task);
        synchronized (delayed) { delayed.remove(task); }
    }
    public static Runnable awaitPostedForHostTest() throws InterruptedException {
        Runnable result=ready.poll(4, TimeUnit.SECONDS);
        if (result==null) throw new AssertionError("expected main callback not posted");
        return result;
    }
    public static int pendingPostsForHostTest() { return ready.size(); }
    public static int pendingTimersForHostTest() { synchronized (delayed) { return delayed.size(); } }
    public static void fireOneTimerForHostTest() {
        Runnable result; synchronized (delayed) { result=delayed.pollFirst(); }
        if (result==null) throw new AssertionError("expected timeout not scheduled");
        result.run();
    }
    public static void resetForHostTest() {
        ready.clear(); synchronized (delayed) { delayed.clear(); }
    }
}
