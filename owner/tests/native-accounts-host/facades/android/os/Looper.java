// SPDX-License-Identifier: Apache-2.0
// Host test input only. Not an Android build input.
package android.os;
public final class Looper {
    private static final Looper MAIN=new Looper();
    private Looper() { }
    public static Looper getMainLooper() { return MAIN; }
}
