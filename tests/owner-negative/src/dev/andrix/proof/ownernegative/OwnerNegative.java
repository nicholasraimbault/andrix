// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.ownernegative;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Process;

import org.json.JSONObject;
import org.json.JSONArray;

/** Ordinary same-signer/different-package negative, not a trusted-controller test. */
public final class OwnerNegative extends Instrumentation {
    static { System.loadLibrary("andrix_owner_negative"); }
    private static native String nativeProbe();
    private static native String nativeWorkLaunchProbe(String serviceReference);
    private static native String nativeWorkServiceProbe(String endpoint);
    private String workLaunchReference;
    private String workServiceEndpoint;

    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        workLaunchReference = arguments == null ? null : arguments.getString("work_launch_reference");
        workServiceEndpoint = arguments == null ? null : arguments.getString("work_service_endpoint");
        start();
    }

    @Override public void onStart() {
        Bundle result = new Bundle();
        try {
            PackageInfo info = getContext().getPackageManager().getPackageInfo(
                    getContext().getPackageName(), PackageManager.GET_PERMISSIONS);
            ApplicationInfo app = info.applicationInfo;
            if (Build.VERSION.SDK_INT != 37 || !Build.PRODUCT.equals("andrix_gos_cf_arm64_only_phone"))
                throw new IllegalStateException("wrong platform profile");
            if ((app.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
                    || info.sharedUserId != null || Process.myUid() < 10000 || !app.sourceDir.startsWith("/data/app/"))
                throw new IllegalStateException("not an ordinary installed app");
            if (info.requestedPermissions == null || info.requestedPermissions.length != 1
                    || !"android.permission.OTHER_SENSORS".equals(info.requestedPermissions[0]))
                throw new IllegalStateException("unexpected PM permission metadata");
            String nativeText = nativeProbe();
            if (nativeText == null) throw new IllegalStateException("native observation failed");
            JSONObject report = new JSONObject(nativeText);
            report.put("package", getContext().getPackageName());
            report.put("fingerprint", Build.FINGERPRINT);
            report.put("source_dir", app.sourceDir);
            report.put("apk_permissions_expected", new JSONArray());
            report.put("pm_implicit_permissions", new JSONArray(info.requestedPermissions));
            report.put("android_permission_grants_measured", false);
            // A positive control proving the service/home exist in this same window
            // is REQUIRED on the host; these negatives alone cannot establish that.
            boolean rejected = report.getInt("uid") == Process.myUid()
                    && report.getInt("euid") == Process.myUid()
                    && report.getString("sid").startsWith("u:r:untrusted_app:")
                    && !report.getBoolean("service_found")
                    && !report.getBoolean("lifecycle_service_found")
                    && !report.getBoolean("scope_a_found") && !report.getBoolean("scope_b_found")
                    && !report.getBoolean("factory_found") && report.getInt("home_errno") == 13;
            if (workLaunchReference != null) {
                String workText = nativeWorkLaunchProbe(workLaunchReference);
                if (workText == null) throw new IllegalStateException("work launch observation failed");
                JSONObject work = new JSONObject(workText);
                report.put("work_launch", work);
                rejected = rejected && work.getInt("uid") == Process.myUid()
                        && work.getInt("connect_errno") == 13
                        && work.getInt("launcher_exec_errno") == 13
                        && work.getInt("entry_exec_errno") == 13
                        && work.getInt("ctl_start_result") != 0
                        && work.getInt("ctl_stop_result") != 0;
            }
            if (workServiceEndpoint != null) {
                String serviceText = nativeWorkServiceProbe(workServiceEndpoint);
                if (serviceText == null) throw new IllegalStateException("work service observation failed");
                JSONObject service = new JSONObject(serviceText);
                report.put("work_service", service);
                // The owner client must prove both live listeners and a populated
                // protected locator in the same window. Missing service is not denial.
                rejected = rejected && service.getInt("uid") == Process.myUid()
                        && service.getInt("management_connect_errno") == 13
                        && service.getInt("control_connect_errno") == 13
                        && service.getInt("locator_length") == 0
                        && service.getInt("ctl_start_result") != 0
                        && service.getInt("ctl_stop_result") != 0;
            }
            report.put("status", rejected ? "NEGATIVES_OBSERVED_REQUIRE_POSITIVE_CONTROL" : "FAIL");
            result.putString("owner_negative", report.toString());
            finish(rejected ? Activity.RESULT_OK : Activity.RESULT_CANCELED, result);
        } catch (Throwable error) {
            result.putString("owner_negative_error", error.toString());
            finish(Activity.RESULT_CANCELED, result);
        }
    }
}
