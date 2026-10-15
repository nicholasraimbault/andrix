// SPDX-License-Identifier: Apache-2.0
package android.os;

/** Host model stub: the process identity the model sets. */
public final class Process {
    public static int uid = 2000;
    public static int pid = 4242;
    public static long start = 1000;

    private Process() {}

    public static int myUid() {
        return uid;
    }

    public static int myPid() {
        return pid;
    }

    public static UserHandle myUserHandle() {
        return new UserHandle(uid / 100000);
    }

    public static long getStartElapsedRealtime() {
        return start;
    }
}
