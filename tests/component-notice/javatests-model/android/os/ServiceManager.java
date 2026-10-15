// SPDX-License-Identifier: Apache-2.0
package android.os;

import android.app.IActivityTaskManager;

/** Host model stub: the activity task service the model provides, and the lookups made. */
public final class ServiceManager {
    public static final java.util.List<String> LOOKUPS = new java.util.ArrayList<>();
    public static boolean absent;

    private ServiceManager() {}

    public static IBinder getService(String name) {
        LOOKUPS.add(name);
        return absent || !"activity_task".equals(name) ? null : IActivityTaskManager.Stub.BINDER;
    }
}
