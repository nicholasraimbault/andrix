// SPDX-License-Identifier: Apache-2.0
// Host test input only. Not an Android build input.
package dev.andrix.lifecycle;
/** Hand translated AIDL field/constant shape, not generated parceling. */
public final class NativeAccountSnapshot {
    public static final int AVAILABLE=1, UNAVAILABLE=2, UNSUPPORTED_USER=3,
            STORE_READY=1, STORE_MISSING=2, STORE_DAMAGED=3, STORE_CONFLICT=4,
            STORE_NEWER=5, STORE_UNAVAILABLE=6;
    public int userId, status, store;
    public long userSerial;
    public boolean complete;
    public NativeAccountRow[] rows;
}
