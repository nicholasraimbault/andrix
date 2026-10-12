// SPDX-License-Identifier: Apache-2.0
// Host stub of the one android.util.Base64 operation the native identity diagnostic uses: standard
// padded Base64 with no line breaks. Any other flag is refused, not approximated. Not Android code.
package android.util;

public final class Base64 {
    public static final int NO_WRAP = 2;

    private Base64() {}

    public static String encodeToString(byte[] input, int flags) {
        if (flags != NO_WRAP) throw new UnsupportedOperationException("only NO_WRAP is stubbed");
        return java.util.Base64.getEncoder().encodeToString(input);
    }
}
