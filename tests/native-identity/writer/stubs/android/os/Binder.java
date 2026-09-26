// SPDX-License-Identifier: Apache-2.0
package android.os;
/** Host facade only, not Binder caller authentication proof. */
public class Binder {
    public static int callerUid;
    public static int getCallingUid() { return callerUid; }
}
