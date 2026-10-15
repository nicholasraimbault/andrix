// SPDX-License-Identifier: Apache-2.0
package android.content;

import android.os.UserManager;
import java.io.File;

/** Host model stub: a context whose device encrypted data directory is a host directory. */
public class Context {
    public static File dataDir;
    public static int deviceProtectedContexts;

    public Context createDeviceProtectedStorageContext() {
        deviceProtectedContexts++;
        return this;
    }

    public File getDataDir() {
        return dataDir;
    }

    public Context getApplicationContext() {
        return this;
    }

    @SuppressWarnings("unchecked")
    public final <T> T getSystemService(Class<T> type) {
        return type == UserManager.class ? (T) new UserManager() : null;
    }
}
