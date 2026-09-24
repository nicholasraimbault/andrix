// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.nativeruntime;

import android.app.KeyguardManager;
import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.SystemClock;
import org.json.JSONObject;

/** Ordinary SDK bootstrap control. No permission or foreground policy changes. */
public final class ManagedProbeService extends Service {
    private long created;
    private volatile String nonce = "";
    private volatile boolean bound;
    private final Binder endpoint = new Binder() {
        { attachInterface(null, RuntimeProfile.DESCRIPTOR); }
        @Override protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
            if (code == INTERFACE_TRANSACTION) {
                reply.writeString(RuntimeProfile.DESCRIPTOR);
                return true;
            }
            if (code != RuntimeProfile.QUERY || reply == null) return false;
            data.enforceInterface(RuntimeProfile.DESCRIPTOR);
            if (data.dataAvail() != 0 || !bound) throw new IllegalStateException("invalid query");
            try {
                JSONObject value = RuntimeProfile.capture(ManagedProbeService.this,
                        "managed", nonce, created);
                // This construction required authentic application shared state in the
                // earlier standalone ART reference. Do not fabricate that state here.
                KeyguardManager keyguard = getSystemService(KeyguardManager.class);
                if (keyguard == null) throw new IllegalStateException("keyguard unavailable");
                value.put("keyguard_constructed", true);
                reply.writeString(value.toString());
                return true;
            } catch (Exception error) {
                throw new IllegalStateException("managed profile failed", error);
            }
        }
    };

    @Override public void onCreate() {
        super.onCreate();
        created = SystemClock.elapsedRealtime();
        RuntimeProfile.lifecycle("create", nonce, created);
    }
    @Override public IBinder onBind(Intent intent) {
        if (bound || intent == null || intent.getData() != null)
            throw new IllegalStateException("unexpected binding");
        nonce = RuntimeProfile.nonce(intent.getAction());
        bound = true;
        RuntimeProfile.lifecycle("bind", nonce, created);
        return endpoint;
    }
    @Override public boolean onUnbind(Intent intent) {
        if (!bound || !nonce.equals(intent.getAction()))
            throw new IllegalStateException("unexpected unbind");
        bound = false;
        RuntimeProfile.lifecycle("unbind", nonce, created);
        return false;
    }
    @Override public void onDestroy() {
        RuntimeProfile.lifecycle("destroy", nonce, created);
        super.onDestroy();
    }
}
