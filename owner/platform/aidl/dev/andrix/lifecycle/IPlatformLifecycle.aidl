// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lifecycle;

import android.os.IBinder;
import dev.andrix.lifecycle.PlatformState;

// Local experimental API. Endpoint calls require native coordinator UID7500;
// MAC discovery alone is not authorization. No user/key management or terminal I/O.
interface IPlatformLifecycle {
    PlatformState snapshot();
    // NEW kept work only. lifetime is the actual process-lifetime IKeptWork Binder.
    // Positive only after notification post and epoch recheck. Native serializes
    // this RPC with snapshot observation, then confirms a fresh matching grant
    // before admitting work. Zero/exception means no grant; no plain conversion.
    long keepWork(IBinder lifetime, long workId, long platformInstance, long platformGeneration);
}
