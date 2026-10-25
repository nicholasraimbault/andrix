// SPDX-License-Identifier: Apache-2.0
// Host test input only. Not an Android build input.
package android.os;
/** Caller facts supplied by a test; no identity clearing method exists. */
public final class Binder {
    private static int uid, pid;
    private Binder() { }
    public static int getCallingUid() { return uid; }
    public static int getCallingPid() { return pid; }
    public static void setCallerForHostTest(int newUid, int newPid) { uid=newUid; pid=newPid; }
}
