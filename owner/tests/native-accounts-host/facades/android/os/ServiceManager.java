// SPDX-License-Identifier: Apache-2.0
// Host test input only. Not an Android build input.
package android.os;
/** Explicit registry fact, not Binder kernel or Android ServiceManager. */
public final class ServiceManager {
    private static volatile IBinder registered;
    public static volatile int checks;
    public static volatile boolean failLookup;
    private ServiceManager() { }
    public static IBinder checkService(String name) {
        if (!"andrix.owner.accounts".equals(name)) throw new AssertionError("wrong service");
        checks++;
        if (failLookup) throw new IllegalStateException("host lookup failure");
        return registered;
    }
    public static void registerForHostTest(IBinder binder) { registered=binder; }
    public static void resetForHostTest() { registered=null; checks=0; failLookup=false; }
}
