// SPDX-License-Identifier: Apache-2.0
// Host test adapter only, never an Android build input.
package android.util;
public final class Log {
    public static int e(String t, String m) { System.err.println(t + ": " + m); return 0; }
    public static int w(String t, String m) { return e(t, m); }
    public static int i(String t, String m) { return e(t, m); }
    public static int d(String t, String m) { return e(t, m); }
    public static int v(String t, String m) { return e(t, m); }
}
