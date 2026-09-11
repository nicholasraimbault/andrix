// SPDX-License-Identifier: Apache-2.0
import dev.andrix.terminal.protocol.AttachTrace;
import dev.andrix.terminal.protocol.AttachTrace.Event;
import dev.andrix.terminal.protocol.AttachTrace.Report;
import java.util.concurrent.atomic.AtomicLong;

public final class AttachTraceTest {
    public static void main(String[] args) throws Exception {
        AtomicLong clock = new AtomicLong(100);
        AttachTrace trace = new AttachTrace(7, clock::get);
        clock.set(110); trace.mark(Event.ATTACH_BEGIN);
        clock.set(120); trace.mark(Event.ATTACH_BEGIN);
        clock.set(150); trace.mark(Event.ATTACH_REPLY);
        String first = trace.report(Report.FAILURE);
        assert first.contains("attempt=7 start_ms=100 report=FAILURE");
        assert first.contains("ATTACH_BEGIN=10") && !first.contains("ATTACH_BEGIN=20");
        assert first.contains("ATTACH_REPLY=50");
        assert trace.report(Report.FAILURE) == null;
        Thread[] threads = new Thread[8];
        for (int i = 0; i < threads.length; ++i) {
            threads[i] = new Thread(() -> {
                for (int j = 0; j < 1000; ++j)
                    for (Event event : Event.values()) trace.mark(event);
            });
            threads[i].start();
        }
        for (Thread thread : threads) thread.join();
        String closed = trace.report(Report.CLOSED);
        assert closed.length() < 4096;
        assert closed.contains("REQUEST=0");
        assert trace.report(Report.FAILURE) == null;
        assert trace.report(Report.CLOSED) == null;
        System.out.println("Fixed-size enum-only trace passed; no Android timing claim");
    }
}
