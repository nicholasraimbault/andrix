// SPDX-License-Identifier: Apache-2.0
// Host test adapter only, never an Android build input.
package android.util;
public final class Base64 {
    public static byte[] decode(String text, int flags) {
        if (flags != 0) throw new IllegalArgumentException("Unmodeled Base64 flags");
        return java.util.Base64.getDecoder().decode(text.replaceAll("\\s", ""));
    }
    public static String encodeToString(byte[] data, int flags) {
        if (flags != 0) throw new IllegalArgumentException("Unmodeled Base64 flags");
        return java.util.Base64.getEncoder().encodeToString(data);
    }
}
