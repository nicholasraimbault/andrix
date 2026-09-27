// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

/** Host compilation fault seam. Never included in framework sources or the product. */
final class NativePreparationFaults {
    static int failAt, calls;
    static boolean failAfterIssuance;
    static void reset(int point) { failAt = point; calls = 0; }
    static void mapChanged() {
        if (++calls == failAt) throw new OutOfMemoryError("injected index construction failure");
    }
    static void afterIssuance() {
        if (failAfterIssuance) {
            failAfterIssuance = false;
            throw new OutOfMemoryError("injected failure before handle construction");
        }
    }
    private NativePreparationFaults() {}
}
