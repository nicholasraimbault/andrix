// SPDX-License-Identifier: Apache-2.0
// Host test stub only: the pinned methods of core/java/android/view/IWindowManager.aidl.
package android.view;

import android.os.IBinder;
import android.os.RemoteException;

public interface IWindowManager {
    boolean isKeyguardLocked() throws RemoteException;

    boolean isKeyguardSecure(int userId) throws RemoteException;

    abstract class Stub implements IWindowManager {
        public static IWindowManager asInterface(IBinder binder) {
            return new IWindowManager() {
                @Override
                public boolean isKeyguardLocked() throws RemoteException {
                    return andrixstub.Answers.answer("isKeyguardLocked", "isKeyguardLocked()");
                }

                @Override
                public boolean isKeyguardSecure(int userId) throws RemoteException {
                    return andrixstub.Answers.answer("isKeyguardSecure", "isKeyguardSecure(" + userId + ")");
                }
            };
        }
    }
}
