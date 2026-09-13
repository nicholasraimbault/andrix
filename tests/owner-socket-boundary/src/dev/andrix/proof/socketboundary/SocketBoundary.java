// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.socketboundary;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Process;
import android.system.OsConstants;

import org.json.JSONObject;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Ordinary app connects to its own socket, then attempts only a held owner path. */
public final class SocketBoundary extends Instrumentation {
    static { System.loadLibrary("andrix_socket_boundary"); }
    private Bundle arguments;
    private static native String nativeProbe(String cache, String path);

    @Override public void onCreate(Bundle values) {
        super.onCreate(values);
        arguments = values == null ? new Bundle() : new Bundle(values);
        start();
    }

    private static void require(boolean value, String message) {
        if (!value) throw new IllegalStateException(message);
    }

    @Override public void onStart() {
        Bundle output = new Bundle();
        try {
            require(Build.VERSION.SDK_INT == 37
                    && Build.PRODUCT.equals("andrix_gos_cf_arm64_only_phone"), "unexpected platform");
            String path = arguments.getString("socket_path", "");
            require(path.matches("/data/misc_ce/0/andrix/\\.tmp/tmux-7500/[A-Za-z0-9][A-Za-z0-9_.-]{0,39}"),
                    "not a bounded owner tmux socket path");
            PackageManager pm = getContext().getPackageManager();
            PackageInfo pkg = pm.getPackageInfo(getContext().getPackageName(), PackageManager.GET_PERMISSIONS);
            ApplicationInfo app = pkg.applicationInfo;
            require(app != null && app.uid == Process.myUid() && app.uid >= 10000 && app.uid < 100000,
                    "unexpected APK UID");
            require((app.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) == 0
                    && app.sourceDir.startsWith("/data/app/") && pkg.sharedUserId == null,
                    "not an ordinary data APK");
            Set<String> perms = pkg.requestedPermissions == null ? Set.of()
                    : new HashSet<>(Arrays.asList(pkg.requestedPermissions));
            require(perms.equals(Set.of("android.permission.OTHER_SENSORS")), "unexpected PM permission metadata");
            JSONObject report = new JSONObject(nativeProbe(getContext().getCacheDir().getAbsolutePath(), path));
            require(report.getInt("uid") == Process.myUid() && report.getInt("euid") == Process.myUid()
                    && report.getInt("pid") == Process.myPid(), "native identity mismatch");
            require(report.getString("sid").startsWith("u:r:untrusted_app:"), "unexpected native MAC role");
            require(report.getInt("self_errno") == 0, "own named-socket control failed");
            int error = report.getInt("owner_connect_errno");
            require(error == OsConstants.EACCES || error == OsConstants.EPERM,
                    "owner connect denial not established (missing target is not a pass)");
            report.put("package", getContext().getPackageName());
            report.put("socket_path", path);
            report.put("status", "DENIAL_OBSERVED_REQUIRE_LIVE_OWNER_SOCKET_CONTROLS");
            report.put("permission_grants_measured", false);
            output.putString("socket_boundary", report.toString());
            finish(Activity.RESULT_OK, output);
        } catch (Exception error) {
            output.putString("failure", error.getClass().getSimpleName()+": "+error.getMessage());
            finish(Activity.RESULT_CANCELED, output);
        }
    }
}
