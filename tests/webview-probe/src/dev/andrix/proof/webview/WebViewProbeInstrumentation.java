package dev.andrix.proof.webview;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Process;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.json.JSONArray;
import org.json.JSONObject;

/** Self-targeting instrumentation: only this ordinary app process invokes WebView. */
public final class WebViewProbeInstrumentation extends Instrumentation {
    static volatile ProbeSession activeSession;
    private Bundle arguments;

    @Override
    public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        this.arguments = arguments == null ? new Bundle() : new Bundle(arguments);
        start();
    }

    @Override
    public void onStart() {
        ProbeSession session = new ProbeSession();
        boolean interrupted = false;
        try {
            session.config = ProbeConfig.parse(arguments.getString("good_url"),
                    arguments.getString("bad_url"), arguments.getString("expected_provider"));
            ProbePlatformProfile platform = ProbePlatformProfile.parse(
                    arguments.getString("platform_profile", ProbePlatformProfile.AOSP));
            session.record("arguments", "good_url", session.config.goodUrl,
                    "bad_url", session.config.badUrl, "good_origin", session.config.goodOrigin,
                    "expected_provider", session.config.expectedProvider,
                    "platform_profile", platform.name);
            ApplicationInfo app = getTargetContext().getApplicationInfo();
            PackageInfo info = getTargetContext().getPackageManager().getPackageInfo(
                    getTargetContext().getPackageName(), PackageManager.GET_PERMISSIONS);
            session.record("app", "package", info.packageName,
                    "instrumentation_package", getContext().getPackageName(),
                    "uid", Process.myUid(), "package_uid", app.uid, "app_flags", app.flags,
                    "source_dir", app.sourceDir, "shared_user_id", info.sharedUserId,
                    "permissions", new JSONArray(info.requestedPermissions == null
                            ? new String[0] : info.requestedPermissions),
                    "sdk", Build.VERSION.SDK_INT, "min_sdk", app.minSdkVersion,
                    "target_sdk", app.targetSdkVersion, "fingerprint", Build.FINGERPRINT,
                    "platform_product", Build.PRODUCT, "platform_profile", platform.name,
                    "apk_manifest_permissions_expected", new JSONArray(platform.expectedApkPermissions()),
                    "pm_implicit_permissions_expected", new JSONArray(platform.expectedImplicitPmPermissions()),
                    "implicit_sensor_grant_measured", false,
                    "is_64_bit", Process.is64Bit());
            if (Process.myUid() != app.uid || Process.myUid() < 10000
                    || (app.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
                    || info.sharedUserId != null
                    || !"dev.andrix.proof.webview".equals(info.packageName)
                    || !info.packageName.equals(getContext().getPackageName())
                    || app.minSdkVersion != 37 || app.targetSdkVersion != 37) {
                throw new IllegalStateException("Not the expected ordinary self-instrumented SDK-37 app");
            }
            platform.validate(Build.FINGERPRINT, Build.PRODUCT, Build.VERSION.SDK_INT,
                    info.requestedPermissions);
            activeSession = session;
            session.post("local_network_permission", () -> {
                if (!session.failed.get() && !session.closing) {
                    getTargetContext().startActivity(new Intent(getTargetContext(), ProbeActivity.class)
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
                }
            });
            // All waiting is on Instrumentation's runner thread, never the UI thread.
            for (String stage : new String[] {
                    "local_network_permission", "initialization", "safe_browsing",
                    "javascript_fetch", "wrong_host_tls"}) {
                if (!session.awaitStage(stage)) {
                    break;
                }
            }
        } catch (Throwable error) {
            interrupted = error instanceof InterruptedException;
            session.fail("runner", error);
        } finally {
            session.post("cleanup", session::close);
            try {
                if (!session.cleaned.await(ProbeSession.STAGE_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    session.fail("cleanup", new TimeoutException("Activity/WebView cleanup exceeded 180s"));
                }
            } catch (InterruptedException error) {
                interrupted = true;
                session.fail("cleanup", error);
            }
            activeSession = null; // A late Activity launch must not initialize WebView.
        }
        String status = session.failed.get() ? "FAIL" : "PASS";
        JSONObject report = ProbeSession.object("schema", 1, "status", status,
                "package", getTargetContext().getPackageName(), "uid", Process.myUid(),
                "stage_timeout_seconds", ProbeSession.STAGE_TIMEOUT_SECONDS,
                "safe_browsing_protection_verified", false,
                "observations", new JSONArray(session.observations));
        Bundle result = new Bundle();
        result.putString("webview_probe", report.toString());
        result.putString("webview_probe_status", status);
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
        finish(session.failed.get() ? Activity.RESULT_CANCELED : Activity.RESULT_OK, result);
    }
}
