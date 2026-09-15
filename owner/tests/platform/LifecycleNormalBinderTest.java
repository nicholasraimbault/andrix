// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server;

import android.content.Context;
import android.os.Binder;
import android.os.storage.StorageManager;
import dev.andrix.lifecycle.PlatformState;

public final class LifecycleNormalBinderTest {
    public static void main(String[] args) {
        OwnerLifecycleBinder normal = new OwnerLifecycleBinder(new Context()) {
            @Override protected PlatformState captureState() { return new PlatformState(); }
        };
        normal.beforeReply(new PlatformState());
        try {
            normal.onShellCommand(null, null, null, new String[]{"lock-ce-user0"}, null, null);
            throw new AssertionError("normal adapter exposed a lab command");
        } catch (UnsupportedOperationException expected) {
            assert StorageManager.calls == 0 && Binder.clears == 0;
        }
        System.out.println("Normal adapter has no lab endpoint; Android artifact absence still requires inspection");
    }
}
