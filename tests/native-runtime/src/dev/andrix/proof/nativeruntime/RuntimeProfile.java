// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.nativeruntime;

import android.content.Context;
import android.os.Binder;
import android.os.Process;
import android.os.SystemClock;
import android.system.Os;
import android.util.Log;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;

final class RuntimeProfile {
    static final String DESCRIPTOR = "dev.andrix.proof.nativeruntime.IProfile";
    static final int QUERY = 1;
    static final String PACKAGE = "dev.andrix.proof.nativeruntime";

    static String nonce(String value) {
        if (value == null || !value.matches("[A-Za-z0-9_]{1,64}"))
            throw new IllegalArgumentException("invalid public nonce");
        return value;
    }

    static String read(String path, int bound) throws Exception {
        try (FileInputStream in = new FileInputStream(path);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            for (int n; (n = in.read(buffer)) != -1;) {
                if (out.size() + n > bound) throw new IllegalStateException("profile bound");
                out.write(buffer, 0, n);
            }
            return out.toString(StandardCharsets.UTF_8.name());
        }
    }

    static JSONObject capture(Context context, String kind, String nonce, long created)
            throws Exception {
        JSONObject result = new JSONObject();
        result.put("version", 1).put("kind", kind).put("nonce", nonce)
                .put("pid", Process.myPid()).put("uid", Process.myUid())
                .put("gid", Os.getgid()).put("caller_pid", Binder.getCallingPid())
                .put("caller_uid", Binder.getCallingUid()).put("created_elapsed_ms", created)
                .put("elapsed_ms", SystemClock.elapsedRealtime())
                .put("status", read("/proc/self/status", 8192))
                .put("cgroup", read("/proc/self/cgroup", 8192))
                .put("selinux", read("/proc/self/attr/current", 1024).replace("\u0000", "").trim())
                .put("exe", Os.readlink("/proc/self/exe"))
                .put("art_present", read("/proc/self/maps", 1024 * 1024).contains("/libart.so"))
                .put("package", context.getPackageName())
                .put("application_uid", context.getApplicationInfo().uid)
                .put("attribution_uid", context.getAttributionSource().getUid())
                .put("attribution_package", context.getAttributionSource().getPackageName());
        return result;
    }

    static void lifecycle(String event, String nonce, long created) {
        try {
            JSONObject value = new JSONObject().put("version", 1).put("kind", "managed")
                    .put("event", event).put("nonce", nonce).put("pid", Process.myPid())
                    .put("uid", Process.myUid()).put("created_elapsed_ms", created)
                    .put("elapsed_ms", SystemClock.elapsedRealtime());
            Log.i("AndrixRuntime", "ANDRIX_RUNTIME " + value);
        } catch (Exception error) {
            throw new IllegalStateException("lifecycle observation failed", error);
        }
    }
    private RuntimeProfile() {}
}
