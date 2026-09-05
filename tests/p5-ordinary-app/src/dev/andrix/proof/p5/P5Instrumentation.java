package dev.andrix.proof.p5;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.os.Build;
import android.os.Bundle;
import android.os.Process;

import java.io.FileInputStream;
import java.security.MessageDigest;

import org.json.JSONArray;
import org.json.JSONObject;

/** Self-targeting, public-API-only instrumentation; all execs happen in this app. */
public final class P5Instrumentation extends Instrumentation {
    private static native String[] probe(String filesDirectory);

    @Override
    public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        start();
    }

    private static String sha256(String path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream input = new FileInputStream(path)) {
            byte[] buffer = new byte[16384];
            int count;
            while ((count = input.read(buffer)) != -1) {
                digest.update(buffer, 0, count);
            }
        }
        StringBuilder hex = new StringBuilder(64);
        for (byte value : digest.digest()) {
            hex.append(Character.forDigit((value & 0xff) >>> 4, 16));
            hex.append(Character.forDigit(value & 0xf, 16));
        }
        return hex.toString();
    }

    @Override
    public void onStart() {
        Bundle result = new Bundle();
        try {
            Context context = getTargetContext();
            PackageInfo info = context.getPackageManager().getPackageInfo(
                    context.getPackageName(), android.content.pm.PackageManager.GET_PERMISSIONS);
            ApplicationInfo app = context.getApplicationInfo();
            JSONObject report = new JSONObject();
            report.put("schema", 1);
            report.put("package", context.getPackageName());
            report.put("instrumentation_package", getContext().getPackageName());
            report.put("uid", Process.myUid());
            report.put("package_uid", app.uid);
            report.put("app_flags", app.flags);
            report.put("shared_user_id", info.sharedUserId == null ? JSONObject.NULL : info.sharedUserId);
            report.put("permissions", new JSONArray(info.requestedPermissions == null
                    ? new String[0] : info.requestedPermissions));
            report.put("source_dir", app.sourceDir);
            report.put("files_dir", context.getFilesDir().getCanonicalPath());
            report.put("min_sdk", app.minSdkVersion);
            report.put("target_sdk", app.targetSdkVersion);
            report.put("sdk", Build.VERSION.SDK_INT);
            report.put("fingerprint", Build.FINGERPRINT);
            report.put("abis", new JSONArray(Build.SUPPORTED_ABIS));
            report.put("is_64_bit", Process.is64Bit());
            report.put("system_sh_sha256_before", sha256("/system/bin/sh"));
            System.loadLibrary("andrix_p5_probe");
            String[] pairs = probe(context.getFilesDir().getCanonicalPath());
            if (pairs == null || pairs.length % 2 != 0) {
                throw new IllegalStateException("Invalid JNI report");
            }
            JSONObject nativeReport = new JSONObject();
            for (int index = 0; index < pairs.length; index += 2) {
                if (pairs[index] == null || pairs[index + 1] == null
                        || nativeReport.has(pairs[index])) {
                    throw new IllegalStateException("Invalid/duplicate JNI field");
                }
                nativeReport.put(pairs[index], pairs[index + 1]);
            }
            report.put("native", nativeReport);
            report.put("system_sh_sha256_after", sha256("/system/bin/sh"));
            result.putString("p5", report.toString());
            // Completion is NOT a proof verdict: the host checks every observation.
            finish(Activity.RESULT_OK, result);
        } catch (Throwable error) {
            result.putString("p5_error", error.toString());
            finish(Activity.RESULT_CANCELED, result);
        }
    }
}
