// SPDX-License-Identifier: Apache-2.0
// Host test input only. Not an Android build input.
package com.android.server;
import java.util.HashMap;
import java.util.Map;
/** Host only lookup table, no platform service registration. */
public final class LocalServices {
    private static final Map<Class<?>, Object> services=new HashMap<>();
    private LocalServices() { }
    public static synchronized <T> void setForHostTest(Class<T> type, T value) {
        if (value==null) services.remove(type); else services.put(type, value);
    }
    public static synchronized void resetForHostTest() { services.clear(); }
    public static synchronized <T> T getService(Class<T> type) { return type.cast(services.get(type)); }
}
