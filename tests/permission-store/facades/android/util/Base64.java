// SPDX-License-Identifier: Apache-2.0

package android.util;

/**
 * Compile only host facade for the pinned BinaryXmlPullParser, which calls it only to render or
 * decode base64 attribute values. The permission store reader reads values only after checking
 * that their recorded type is an integer or a string. Reaching either method is a failure; it
 * does not emulate Android behavior.
 */
public final class Base64 {
    // Referenced as a compile time constant by the pinned parser. Inert here: both methods throw.
    public static final int NO_WRAP = 2;

    private Base64() {
    }

    public static String encodeToString(byte[] input, int flags) {
        throw new UnsupportedOperationException("host facade: android.util.Base64.encodeToString");
    }

    public static byte[] decode(String input, int flags) {
        throw new UnsupportedOperationException("host facade: android.util.Base64.decode");
    }
}
