// SPDX-License-Identifier: Apache-2.0
// Host test stub only: the pinned method of core/java/android/os/IPowerManager.aidl.
package android.os;

public interface IPowerManager {
    boolean isInteractive() throws RemoteException;

    abstract class Stub implements IPowerManager {
        public static IPowerManager asInterface(IBinder binder) {
            return () -> andrixstub.Answers.answer("isInteractive", "isInteractive()");
        }
    }
}
