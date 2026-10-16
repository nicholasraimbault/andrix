// SPDX-License-Identifier: Apache-2.0
// Host test stub only: the pinned method of core/java/android/os/storage/IStorageManager.aidl.
package android.os.storage;

import android.os.IBinder;
import android.os.RemoteException;

public interface IStorageManager {
    boolean isCeStorageUnlocked(int userId) throws RemoteException;

    abstract class Stub implements IStorageManager {
        public static IStorageManager asInterface(IBinder binder) {
            return userId -> andrixstub.Answers.answer("isCeStorageUnlocked", "isCeStorageUnlocked(" + userId + ")");
        }
    }
}
