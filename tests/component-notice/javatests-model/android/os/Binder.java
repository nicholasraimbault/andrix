// SPDX-License-Identifier: Apache-2.0
package android.os;

/**
 * Host model stub: the Binder calling UID the model sets, a count of identity clears, and a local
 * transaction that reaches onTransact directly, as a remote one reaches the object's thread pool.
 */
public class Binder implements IBinder {
    public static int callingUid = 2000;
    public static int clears;

    public static int getCallingUid() {
        return callingUid;
    }

    public static long clearCallingIdentity() {
        clears++;
        return 0;
    }

    public static void restoreCallingIdentity(long token) {}

    @Override
    public boolean transact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
        data.setDataPosition(0);
        return onTransact(code, data, reply, flags);
    }

    protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
        return false;
    }
}
