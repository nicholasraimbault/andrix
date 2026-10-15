// SPDX-License-Identifier: Apache-2.0
package android.util;

import java.util.ArrayList;
import java.util.List;

/** Host model stub: the log lines, kept for the model's checks. */
public final class Log {
    public static final List<String> LINES = new ArrayList<>();

    private Log() {}

    public static int i(String tag, String message) {
        LINES.add("I " + tag + " " + message);
        return 0;
    }

    public static int w(String tag, String message) {
        LINES.add("W " + tag + " " + message);
        return 0;
    }
}
