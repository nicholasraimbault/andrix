// SPDX-License-Identifier: Apache-2.0

package android.text;

/**
 * Compile only host facade for the pinned BinaryXmlPullParser, which calls it from
 * isWhitespace(). The permission store reader never calls isWhitespace(). Reaching this method
 * is a failure; it does not emulate Android behavior.
 */
public final class TextUtils {
    private TextUtils() {
    }

    public static boolean isGraphic(CharSequence text) {
        throw new UnsupportedOperationException("host facade: android.text.TextUtils.isGraphic");
    }
}
