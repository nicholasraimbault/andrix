// SPDX-License-Identifier: Apache-2.0
// Explicit host facade; not Android identity or storage authority.
package android.os;
public final class SystemClock {
    public static long time; public static int sleeps; public static Runnable onSleep;
    public static long uptimeMillis() { return time; }
    public static void sleep(long millis) {
        assert millis == 2500; ++sleeps;
        if (onSleep != null) onSleep.run();
        time += millis;
    }
    private SystemClock() { }
}
