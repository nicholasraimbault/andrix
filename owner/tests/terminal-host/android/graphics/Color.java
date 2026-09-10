// SPDX-License-Identifier: Apache-2.0
// Host test adapter only, never an Android build input.
package android.graphics;
public final class Color {
    public static int red(int argb) { return (argb >>> 16) & 255; }
    public static int green(int argb) { return (argb >>> 8) & 255; }
    public static int blue(int argb) { return argb & 255; }
}
