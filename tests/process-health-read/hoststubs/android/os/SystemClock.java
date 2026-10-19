// SPDX-License-Identifier: Apache-2.0
// Host stub of android.os.SystemClock: the script's elapsed times in order, or a clock that fails.
package android.os;

import andrixstub.Script;

public final class SystemClock {
    private static int calls;

    private SystemClock() {}

    public static long elapsedRealtime() {
        if (Script.flag("clock.fails")) throw new IllegalStateException("no clock");
        String[] values = Script.value("clock.elapsed", "").split(",");
        int at = calls++;
        if (at < values.length && !values[at].isEmpty()) return Long.parseLong(values[at]);
        return 60_000L + at;
    }
}
