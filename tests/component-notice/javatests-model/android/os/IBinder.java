// SPDX-License-Identifier: Apache-2.0
package android.os;

/** Host model stub of a Binder object: its one transaction call and the constants used. */
public interface IBinder {
    int FIRST_CALL_TRANSACTION = 1;
    int FLAG_ONEWAY = 1;

    boolean transact(int code, Parcel data, Parcel reply, int flags) throws RemoteException;
}
