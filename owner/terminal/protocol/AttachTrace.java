// SPDX-License-Identifier: Apache-2.0
package dev.andrix.terminal.protocol;

import java.util.Arrays;
import java.util.function.LongSupplier;

/** Fixed-size timing diagnostics. No terminal data, paths, tokens or error text. */
public final class AttachTrace {
    public enum Event {
        REQUEST, CONTROL_BEGIN, REGISTER_BEGIN, REGISTER_END, ATTACH_BEGIN, ATTACH_REPLY,
        FDS_READY, PENDING_SET, FINISH_BEGIN, CURSOR_READY, TERMINAL_BEGIN, TERMINAL_END, CONNECTION_SET,
        PUBLISHED, READER_BEGIN, FRAME_READ, FRAME_APPLIED, READ_EOF, READ_EXCEPTION,
        RENEW_BEGIN, RENEW_CALL, RENEW_INELIGIBLE, RENEW_USER_LOCKED,
        RENEW_OK, RENEW_FALSE, RENEW_EXCEPTION, RESIZE_QUEUED, RESIZE_BEGIN,
        RESIZE_OK, RESIZE_INACTIVE, RESIZE_PTY_ERROR, RESIZE_OTHER_ERROR, ATTACH_ERROR,
        FINISH_ERROR, CANCELLED, CLOSED
    }
    public enum Report { FAILURE, CLOSED }
    private final long attempt;
    private final long started;
    private final LongSupplier clock;
    private final long[] times = new long[Event.values().length];
    private final boolean[] reported = new boolean[Report.values().length];

    public AttachTrace(long attempt, LongSupplier clock) {
        this.attempt = attempt;
        this.clock = clock;
        started = clock.getAsLong();
        Arrays.fill(times, -1);
        times[Event.REQUEST.ordinal()] = 0;
    }
    public synchronized void mark(Event event) {
        int index = event.ordinal();
        if (times[index] < 0) times[index] = Math.max(0, clock.getAsLong() - started);
    }
    /** Each of two report categories is emitted at most once per attachment. */
    public synchronized String report(Report reason) {
        if (reported[reason.ordinal()]) return null;
        reported[reason.ordinal()] = true;
        StringBuilder text = new StringBuilder("attach_timing attempt=").append(attempt)
                .append(" start_ms=").append(started).append(" report=").append(reason);
        for (Event event : Event.values()) {
            long elapsed = times[event.ordinal()];
            if (elapsed >= 0) text.append(' ').append(event).append('=').append(elapsed);
        }
        return text.toString();
    }
}
