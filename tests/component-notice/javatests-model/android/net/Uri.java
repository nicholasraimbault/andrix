// SPDX-License-Identifier: Apache-2.0
package android.net;

/** Host model stub of a URI: its exact text. */
public final class Uri {
    private final String text;

    private Uri(String text) {
        this.text = text;
    }

    public static Uri parse(String text) {
        return new Uri(text);
    }

    @Override
    public String toString() {
        return text;
    }
}
