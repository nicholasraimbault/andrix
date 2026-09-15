// SPDX-License-Identifier: Apache-2.0
// Explicit host facade; not Android identity or storage authority.
package android.util;
import java.util.ArrayList;
import java.util.List;
public final class Slog {
    public static final List<String> lines = new ArrayList<>();
    public static void i(String tag, String line) { lines.add(tag + ": " + line); }
    public static void e(String tag, String line, Exception error) { lines.add(tag + ": " + line); }
    private Slog() { }
}
