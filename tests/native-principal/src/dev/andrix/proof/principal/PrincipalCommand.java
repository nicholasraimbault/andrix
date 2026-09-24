// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.principal;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Looper;
import android.os.Process;
import android.os.SystemClock;
import android.service.notification.StatusBarNotification;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

/** Lab command for run-as + app_process. This is not a product native binding.
 * Private framework bootstrap access may fail. Never disable hidden API, permission,
 * SELinux or verification checks to manufacture a successful result.
 */
public final class PrincipalCommand {
    private static final String CHANNEL = "andrix_principal_probe";
    private static final String ATTRIBUTION = "native-principal-proof";

    private PrincipalCommand() {}

    public static void main(String[] rawArguments) {
        String phase = "arguments";
        ProbeArguments arguments = null;
        try {
            arguments = ProbeArguments.parse(rawArguments);
            phase = "kernel_identity";
            ProbeIdentity identity = ProbeIdentity.parse(
                    readOwnFile("/proc/self/status", 32768),
                    readOwnFile("/proc/self/attr/current", 256));
            identity.requireOrdinaryRunAs(Process.myUid());
            JSONObject entry = base(arguments, "entry");
            entry.put("kernel_fields", new JSONObject(identity.fields()));
            entry.put("selinux_context", identity.securityContext);
            entry.put("cgroup", readOwnFile("/proc/self/cgroup", 8192).trim());
            emit(entry);

            phase = "package_context";
            Context context = packageContext();
            JSONObject facts = base(arguments, "context");
            facts.put("context_package", context.getPackageName());
            facts.put("context_uid", context.getApplicationInfo().uid);
            facts.put("target_sdk", context.getApplicationInfo().targetSdkVersion);
            facts.put("attribution_uid", context.getAttributionSource().getUid());
            facts.put("attribution_package", context.getAttributionSource().getPackageName());
            facts.put("attribution_tag", context.getAttributionSource().getAttributionTag());
            facts.put("notification_permission", context.checkSelfPermission(
                    Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED);
            emit(facts);
            phase = "verify_attribution";
            ProbePrincipal.requireOwnContext(Process.myUid(),
                    context.getApplicationInfo().packageName, context.getApplicationInfo().uid,
                    context.getPackageName(), context.getAttributionSource().getUid(),
                    context.getAttributionSource().getPackageName());
            boolean ownTarget = context.getPackageName().equals(arguments.targetPackage);
            if (!ownTarget && !"post".equals(arguments.action)) {
                throw new IllegalArgumentException("foreign target is only a post negative control");
            }
            if ("info".equals(arguments.action)) {
                emit(base(arguments, "complete"));
                System.exit(0);
            }

            phase = "notification_manager";
            NotificationManager manager = context.getSystemService(NotificationManager.class);
            if (manager == null) throw new IllegalStateException("notification service absent");
            if ("post".equals(arguments.action)) {
                phase = "create_channel";
                manager.createNotificationChannel(new NotificationChannel(CHANNEL,
                        "Andrix principal reference", NotificationManager.IMPORTANCE_DEFAULT));
                phase = "build_notification";
                // Ordinary notification. No media/call style, foreground-service flag or intent.
                Notification notification = new Notification.Builder(context, CHANNEL)
                        .setSmallIcon(android.R.drawable.stat_notify_more)
                        .setContentTitle("Andrix principal reference")
                        .setContentText("Public fixture " + arguments.nonce)
                        .setOnlyAlertOnce(true)
                        .build();
                phase = "post";
                if (ownTarget) {
                    manager.notify(arguments.nonce, ProbeArguments.NOTIFICATION_ID, notification);
                } else {
                    // Documented delegation entry. No delegate grant is configured: the native
                    // service must reject the real caller's attempt to post for another package.
                    manager.notifyAsPackage(arguments.targetPackage, arguments.nonce,
                            ProbeArguments.NOTIFICATION_ID, notification);
                    phase = "foreign_submission_returned";
                    throw new IllegalStateException("foreign submission unexpectedly returned");
                }
                JSONObject submitted = base(arguments, "submission_returned");
                submitted.put("not_a_delivery_acknowledgement", true);
                emit(submitted);
            } else if ("cancel".equals(arguments.action)) {
                phase = "cancel";
                manager.cancel(arguments.nonce, ProbeArguments.NOTIFICATION_ID);
                emit(base(arguments, "cancel_returned"));
            }

            phase = "observe";
            long end = SystemClock.elapsedRealtime() + arguments.observeMillis;
            Boolean previous = null;
            boolean active;
            do {
                active = contains(manager.getActiveNotifications(), arguments);
                if (previous == null || previous != active) {
                    JSONObject event = base(arguments, "observation");
                    event.put("active", active);
                    event.put("notifications_enabled", manager.areNotificationsEnabled());
                    emit(event);
                    previous = active;
                }
                long remaining = end - SystemClock.elapsedRealtime();
                if (remaining <= 0) break;
                Thread.sleep(Math.min(100, remaining));
            } while (true);
            JSONObject finished = base(arguments, "complete");
            finished.put("active_at_last_observation", active);
            finished.put("not_a_health_or_runtime_qualification", true);
            emit(finished);
            System.exit(0);
        } catch (Throwable failure) {
            while (failure instanceof InvocationTargetException && failure.getCause() != null) {
                failure = failure.getCause();
            }
            try {
                JSONObject result = arguments == null ? new JSONObject() : base(arguments, phase);
                result.put("schema", 1);
                result.put("phase", phase);
                result.put("status", "refused_or_failed");
                result.put("error_class", failure.getClass().getName());
                // Only this disposable, fixed-input fixture. Not a product logging default.
                String message = failure.getMessage();
                if (message != null) result.put("diagnostic_message",
                        message.substring(0, Math.min(512, message.length())));
                JSONArray stack = new JSONArray();
                StackTraceElement[] frames = failure.getStackTrace();
                for (int i = 0; i < Math.min(12, frames.length); i++) {
                    StackTraceElement frame = frames[i];
                    stack.put(frame.getClassName() + "." + frame.getMethodName()
                            + ":" + frame.getLineNumber());
                }
                result.put("diagnostic_stack", stack);
                if (arguments != null) result.put("nonce", arguments.nonce);
                emit(result);
            } catch (Throwable ignored) {
                System.out.println("{\"schema\":1,\"status\":\"report_failed\"}");
            }
            System.exit(1);
        }
    }

    private static Context packageContext() throws Exception {
        if (Looper.getMainLooper() == null) Looper.prepareMainLooper();
        Class<?> activityThread = Class.forName("android.app.ActivityThread");
        Object thread = activityThread.getMethod("systemMain").invoke(null);
        Context systemContext = (Context) activityThread.getMethod("getSystemContext").invoke(thread);
        PackageManager packages = systemContext.getPackageManager();
        String principal = ProbePrincipal.fixtureForUid(packages.getPackagesForUid(Process.myUid()));
        ApplicationInfo application = packages.getApplicationInfo(principal, 0);
        ProbePrincipal.requireOwnApplication(Process.myUid(), application.uid);
        if (!principal.equals(application.packageName)) {
            throw new SecurityException("Package Manager returned a different application");
        }

        Class<?> compatibility = Class.forName("android.content.res.CompatibilityInfo");
        Object defaults = compatibility.getField("DEFAULT_COMPATIBILITY_INFO").get(null);
        // The checked package-info path, with resource-only flags. No INCLUDE_CODE,
        // IGNORE_SECURITY, getPackageInfoNoCheck, foreign package or caller-supplied identity.
        Object loaded = activityThread.getMethod("getPackageInfo", ApplicationInfo.class,
                compatibility, int.class).invoke(thread, application, defaults, 0);
        Class<?> loadedApk = Class.forName("android.app.LoadedApk");
        Class<?> contextImpl = Class.forName("android.app.ContextImpl");
        Method create = contextImpl.getDeclaredMethod("createAppContext", activityThread, loadedApk);
        // Bounded access to Java package visibility for this private diagnostic factory.
        // This does not exempt ART hidden APIs or change native permission/MAC enforcement.
        // Refuse if the lookup/access fails. Never override the operation-package field.
        create.setAccessible(true);
        Context context = (Context) create.invoke(null, thread, loaded);
        ProbePrincipal.requireOwnContext(Process.myUid(), principal, context.getApplicationInfo().uid,
                context.getPackageName(), context.getAttributionSource().getUid(),
                context.getAttributionSource().getPackageName());
        return context.createAttributionContext(ATTRIBUTION);
    }

    private static boolean contains(StatusBarNotification[] values, ProbeArguments args) {
        for (StatusBarNotification value : values) {
            if (args.targetPackage.equals(value.getPackageName())
                    && args.nonce.equals(value.getTag())
                    && value.getId() == ProbeArguments.NOTIFICATION_ID) return true;
        }
        return false;
    }

    private static JSONObject base(ProbeArguments arguments, String phase) throws Exception {
        JSONObject value = new JSONObject();
        value.put("schema", 1);
        value.put("phase", phase);
        value.put("action", arguments.action);
        value.put("target_package", arguments.targetPackage);
        value.put("nonce", arguments.nonce);
        value.put("uid", Process.myUid());
        value.put("pid", Process.myPid());
        value.put("user_id_display_only", Process.myUid() / 100000);
        value.put("elapsed_realtime_ms", SystemClock.elapsedRealtime());
        return value;
    }

    private static String readOwnFile(String fixedPath, int maximum) throws Exception {
        try (FileInputStream input = new FileInputStream(fixedPath);
                ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (output.size() + count > maximum) throw new IllegalStateException("observation bound");
                output.write(buffer, 0, count);
            }
            return output.toString(StandardCharsets.UTF_8.name());
        }
    }

    private static void emit(JSONObject value) {
        System.out.println(value.toString());
        System.out.flush();
    }
}
