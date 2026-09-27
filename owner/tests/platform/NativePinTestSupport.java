// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

/** Core test fixture. This does not stand in for PMS storage or owner admission. */
final class NativePinTestSupport {
    static NativePrincipalPins.Pin prepare(NativePrincipalPins pins, String name, int appId,
            int userId, long serial) {
        synchronized (pins) {
            if (pins.find(name, userId) != null) return pins.retry(name, appId, userId, serial);
            return pins.prepare(pins.previewPrepare(name, appId, userId, serial), new Object());
        }
    }
    private NativePinTestSupport() {}
}
