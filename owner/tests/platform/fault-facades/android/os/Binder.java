// SPDX-License-Identifier: Apache-2.0
// Explicit host facade; not Android identity or storage authority.
package android.os;
import java.io.FileDescriptor;
public class Binder {
    public static int uid = 2000, pid = 200, clears, restores;
    public static int getCallingUid() { return uid; }
    public static int getCallingPid() { return pid; }
    public static long clearCallingIdentity() {
        ++clears; long token = ((long) uid << 32) | (pid & 0xffffffffL);
        uid = 1000; pid = 900; return token;
    }
    public static void restoreCallingIdentity(long token) {
        ++restores; uid = (int) (token >>> 32); pid = (int) token;
    }
    public void onShellCommand(FileDescriptor in, FileDescriptor out, FileDescriptor err,
            String[] args, ShellCallback callback, ResultReceiver result) {
        throw new UnsupportedOperationException("normal Binder has no lab commands");
    }
}
