// SPDX-License-Identifier: Apache-2.0
// Host stub of android.os.ServiceManager: a binder for any service unless the script says absent.
package android.os;

import andrixstub.Script;

public final class ServiceManager {
    private ServiceManager() {}

    public static IBinder getService(String name) {
        Script.trace("getService(" + name + ")");
        if (Script.flag("service.absent")) return null;
        return new IBinder() {};
    }
}
