// SPDX-License-Identifier: Apache-2.0
// Explicit host facade; not Android identity or storage authority.
package android.os.storage;
import android.os.Binder;
public class StorageManager {
    public static boolean unlocked = true, throwOnLock;
    public static int calls; public static Runnable onLock;
    public static boolean isCeStorageUnlocked(int user) { assert user == 0; return unlocked; }
    public void lockCeStorage(int user) {
        assert user == 0 && Binder.uid == 1000 && Binder.pid == 900;
        ++calls; if (onLock != null) onLock.run();
        if (throwOnLock) throw new IllegalStateException("host facade failure");
        unlocked = false;
    }
}
