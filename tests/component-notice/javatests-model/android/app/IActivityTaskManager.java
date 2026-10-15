// SPDX-License-Identifier: Apache-2.0
package android.app;

import android.content.Intent;
import android.os.Bundle;
import android.os.IBinder;

/** Host model stub of the interface, with the pinned AIDL's startActivityAndWait signature. */
public interface IActivityTaskManager {
    WaitResult startActivityAndWait(IApplicationThread caller, String callingPackage, String callingFeatureId,
            Intent intent, String resolvedType, IBinder resultTo, String resultWho, int requestCode, int flags,
            ProfilerInfo profilerInfo, Bundle options, int userId);

    /** The model's binder and its interface, which the test installs. */
    final class Stub {
        public static final IBinder BINDER = new android.os.Binder();
        public static IActivityTaskManager manager;

        private Stub() {}

        public static IActivityTaskManager asInterface(IBinder binder) {
            return binder == BINDER ? manager : null;
        }
    }
}
