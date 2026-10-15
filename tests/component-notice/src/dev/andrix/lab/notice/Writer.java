// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.notice;

import android.content.Context;
import android.util.Log;
import java.io.File;
import java.security.SecureRandom;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The app's one receipt store and its one writer thread. The app has one process per user, so one
 * thread serializes every write of that user's store. Only the activity's presentation code hands
 * it a row; the provider only lists.
 */
final class Writer {
    static final String TAG = "AndrixNotice";
    private static final ExecutorService THREAD = Executors.newSingleThreadExecutor();
    private static ReceiptStore store;

    private Writer() {}

    /** The store in the app's device encrypted data directory. Opening it creates nothing. */
    static synchronized ReceiptStore store(Context context) {
        if (store == null) {
            File data = context.createDeviceProtectedStorageContext().getDataDir();
            final SecureRandom random = new SecureRandom();
            store = new ReceiptStore(new AndroidDisk(new File(data, "receipts")), new ReceiptStore.Nonces() {
                @Override
                public String next() {
                    byte[] nonce = new byte[8];
                    random.nextBytes(nonce);
                    return Forms.hex(nonce);
                }
            });
        }
        return store;
    }

    /** Hands a candidate row to the writer thread. The outcome is logged, never shown. */
    static void record(Context context, final ReceiptRow row) {
        final ReceiptStore target = store(context.getApplicationContext());
        THREAD.execute(new Runnable() {
            @Override
            public void run() {
                Log.i(TAG, "record " + target.record(row) + " " + row.key());
            }
        });
    }
}
