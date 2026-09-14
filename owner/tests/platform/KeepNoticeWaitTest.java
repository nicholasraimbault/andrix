// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server;

public final class KeepNoticeWaitTest {
    static final class Clock implements KeepNoticeWait.Clock {
        long time;
        @Override public long now() { return time; }
        @Override public void sleep(long duration) { assert duration > 0 && duration <= 20; time += duration; }
    }
    static final class Probe implements KeepNoticeWait.Probe {
        final Clock clock;
        long activeAt = 80, activeDelay, finalAllowedDelay;
        int allowedCalls;
        boolean permitted = true;
        Probe(Clock clock) { this.clock = clock; }
        @Override public boolean allowed() {
            ++allowedCalls;
            if (allowedCalls == 2 && activeAt == 0) clock.time += finalAllowedDelay;
            return permitted;
        }
        @Override public boolean active() { clock.time += activeDelay; return clock.time >= activeAt; }
    }
    public static void main(String[] args) {
        Clock clock = new Clock(); Probe probe = new Probe(clock);
        assert KeepNoticeWait.await(probe, clock) && clock.time == 80;
        clock = new Clock(); probe = new Probe(clock); probe.activeAt = 401;
        assert !KeepNoticeWait.await(probe, clock) && clock.time == 400;
        clock = new Clock(); probe = new Probe(clock); probe.permitted = false;
        assert !KeepNoticeWait.await(probe, clock) && clock.time == 0;
        clock = new Clock(); probe = new Probe(clock); probe.activeDelay = 401;
        assert !KeepNoticeWait.await(probe, clock);
        clock = new Clock(); probe = new Probe(clock); probe.activeAt = 0; probe.finalAllowedDelay = 401;
        assert !KeepNoticeWait.await(probe, clock); // Delayed final app/channel check buys no deadline.
        clock = new Clock(); clock.time = Long.MAX_VALUE - 399; probe = new Probe(clock);
        assert !KeepNoticeWait.await(probe, clock);
        clock = new Clock(); probe = new Probe(clock); probe.activeDelay = -1;
        assert !KeepNoticeWait.await(probe, clock);
        System.out.println("Notification acknowledgement deadline checks passed; Android unqualified");
    }
}
