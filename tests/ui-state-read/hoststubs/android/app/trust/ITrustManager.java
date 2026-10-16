// SPDX-License-Identifier: Apache-2.0
// Host test stub only: the pinned methods of core/java/android/app/trust/ITrustManager.aidl.
package android.app.trust;

import android.os.IBinder;
import android.os.RemoteException;

public interface ITrustManager {
    boolean isDeviceLocked(int userId, int deviceId) throws RemoteException;

    boolean isDeviceSecure(int userId, int deviceId) throws RemoteException;

    abstract class Stub implements ITrustManager {
        public static ITrustManager asInterface(IBinder binder) {
            return new ITrustManager() {
                @Override
                public boolean isDeviceLocked(int userId, int deviceId) throws RemoteException {
                    return andrixstub.Answers.answer("isDeviceLocked", "isDeviceLocked(" + userId + "," + deviceId + ")");
                }

                @Override
                public boolean isDeviceSecure(int userId, int deviceId) throws RemoteException {
                    return andrixstub.Answers.answer("isDeviceSecure", "isDeviceSecure(" + userId + "," + deviceId + ")");
                }
            };
        }
    }
}
