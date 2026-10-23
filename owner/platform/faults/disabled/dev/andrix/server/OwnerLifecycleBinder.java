// SPDX-License-Identifier: GPL-3.0-or-later
package dev.andrix.server;

import android.content.Context;

import dev.andrix.lifecycle.IPlatformLifecycle;
import dev.andrix.lifecycle.PlatformState;

/** Normal-image adapter: no additional command endpoint or storage operation. */
abstract class OwnerLifecycleBinder extends IPlatformLifecycle.Stub {
    OwnerLifecycleBinder(Context context) { }
    protected abstract PlatformState captureState();
    final void beforeReply(PlatformState captured) { }
}
