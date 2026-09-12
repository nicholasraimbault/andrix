// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.debugboundary;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Process;
import android.os.SystemClock;

import org.json.JSONArray;
import org.json.JSONObject;

/** Ordinary test identity, held briefly for reverse-direction native controls. */
public final class DebugBoundary extends Instrumentation {
    static { System.loadLibrary("andrix_debug_boundary"); }
    private static native String nativeProbe(int ownerPid, int managerPid, String pty);
    private Bundle arguments;

    @Override public void onCreate(Bundle args) {
        super.onCreate(args);
        arguments = args == null ? new Bundle() : new Bundle(args);
        start();
    }

    private static int positivePid(String value) {
        if (value == null || !value.matches("[1-9][0-9]{0,8}"))
            throw new IllegalArgumentException("invalid PID");
        int pid = Integer.parseInt(value);
        if (pid <= 1 || pid == Process.myPid()) throw new IllegalArgumentException("invalid PID");
        return pid;
    }

    private static boolean denied(int error) { return error == 1 || error == 13; }

    @Override public void onStart() {
        Bundle result = new Bundle();
        try {
            if (Build.VERSION.SDK_INT != 37 || !Build.PRODUCT.equals("andrix_gos_cf_arm64_only_phone"))
                throw new IllegalStateException("wrong platform profile");
            int ownerPid = positivePid(arguments.getString("owner_pid"));
            int managerPid = positivePid(arguments.getString("manager_pid"));
            String pty = arguments.getString("pty");
            if (ownerPid == managerPid || pty == null || !pty.matches("/dev/pts/[0-9]{1,8}"))
                throw new IllegalArgumentException("invalid target selection");
            PackageInfo info = getContext().getPackageManager().getPackageInfo(
                    getContext().getPackageName(), PackageManager.GET_PERMISSIONS);
            ApplicationInfo app = info.applicationInfo;
            if ((app.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
                    || (app.flags & ApplicationInfo.FLAG_DEBUGGABLE) == 0 || info.sharedUserId != null
                    || Process.myUid() < 10000 || !app.sourceDir.startsWith("/data/app/"))
                throw new IllegalStateException("not the ordinary debuggable test APK");
            if (info.requestedPermissions == null || info.requestedPermissions.length != 1
                    || !"android.permission.OTHER_SENSORS".equals(info.requestedPermissions[0]))
                throw new IllegalStateException("unexpected PM permission metadata");
            String nativeText = nativeProbe(ownerPid, managerPid, pty);
            if (nativeText == null) throw new IllegalStateException("native observation failed");
            JSONObject report = new JSONObject(nativeText);
            report.put("package", getContext().getPackageName());
            report.put("fingerprint", Build.FINGERPRINT);
            report.put("source_dir", app.sourceDir);
            report.put("debuggable_test_apk", true);
            report.put("apk_permissions_expected", new JSONArray());
            report.put("pm_implicit_permissions", new JSONArray(info.requestedPermissions));
            report.put("runtime_permission_grants_measured", false);
            report.put("pty", pty);
            boolean observed = report.getInt("uid") == Process.myUid()
                    && report.getInt("euid") == Process.myUid()
                    && report.getInt("pid") == Process.myPid()
                    && report.getString("sid").startsWith("u:r:untrusted_app:")
                    && report.getInt("self_complete") == 1 && report.getInt("self_errno") == 0
                    && report.getInt("owner_complete") == 1 && denied(report.getInt("owner_errno"))
                    && report.getInt("manager_complete") == 1 && denied(report.getInt("manager_errno"))
                    && denied(report.getInt("pty_errno"));
            if (!observed) {
                result.putString("debug_boundary", report.toString());
                finish(Activity.RESULT_CANCELED, result);
                return;
            }
            report.put("status", "APP_CONTROLS_OBSERVED_REQUIRE_LIVE_OWNER_AND_REVERSE_CONTROLS");
            result.putString("debug_boundary_ready", report.toString());
            sendStatus(1, result);
            // A finite, ordinary instrumentation process; no service/identity grant.
            // Host/native observers must validate this PID while it is still alive.
            SystemClock.sleep(180000);
            result.remove("debug_boundary_ready");
            result.putString("debug_boundary", report.toString());
            finish(Activity.RESULT_OK, result);
        } catch (Throwable error) {
            result.putString("debug_boundary_error", error.toString());
            finish(Activity.RESULT_CANCELED, result);
        }
    }
}
