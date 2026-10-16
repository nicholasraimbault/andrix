// SPDX-License-Identifier: Apache-2.0
// Host test stub only: the service lookup. A name listed in the system property andrix.absent has
// no service.
package android.os;

public final class ServiceManager {
    private ServiceManager() {}

    public static IBinder getService(String name) {
        andrixstub.Answers.trace("getService(" + name + ")");
        for (String absent : System.getProperty("andrix.absent", "").split(",")) {
            if (absent.equals(name)) return null;
        }
        return new IBinder() {};
    }
}
