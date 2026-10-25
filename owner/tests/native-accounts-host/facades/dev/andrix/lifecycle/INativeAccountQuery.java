// SPDX-License-Identifier: Apache-2.0
// Host test input only. Not an Android build input.
package dev.andrix.lifecycle;
import android.os.IBinder;
import java.io.FileDescriptor;
import java.io.PrintWriter;
/** Hand translated AIDL shape. No Binder driver, transact, parceling or permission layer. */
public interface INativeAccountQuery {
    NativeAccountSnapshot inspectCurrentUser();
    abstract class Stub implements INativeAccountQuery, IBinder {
        public static INativeAccountQuery asInterface(IBinder binder) {
            return (INativeAccountQuery) binder;
        }
        @Override public boolean isBinderAlive() { return true; }
        protected void dump(FileDescriptor fd, PrintWriter out, String[] args) { }
    }
}
