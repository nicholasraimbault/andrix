// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.principal;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.location.LocationRequest;
import android.os.Process;
import android.os.SystemClock;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Fixed mock-provider reference only. Never requests GPS/fused data or prints coordinates. */
public final class LocationCommand {
    private final LocationArguments arguments;
    private final AtomicInteger callbacks = new AtomicInteger();
    private final AtomicBoolean closing = new AtomicBoolean();
    private final AtomicReference<Throwable> callbackFailure = new AtomicReference<>();
    private long sequence;
    private String phase = "kernel_identity";

    private LocationCommand(LocationArguments arguments) { this.arguments = arguments; }

    public static void main(String[] raw) {
        LocationCommand command = null;
        try {
            command = new LocationCommand(LocationArguments.parse(raw));
            command.run();
            System.exit(0);
        } catch (Throwable failure) {
            while (failure instanceof InvocationTargetException && failure.getCause() != null) {
                failure = failure.getCause();
            }
            try {
                JSONObject detail = failureDetails(failure);
                if (command == null) {
                    detail.put("schema", 1).put("phase", "arguments");
                    System.out.println(detail.toString());
                } else {
                    command.emit(command.phase, detail);
                }
            } catch (Throwable ignored) {
                System.out.println("{\"schema\":1,\"status\":\"report_failed\"}");
            }
            System.exit(1);
        }
    }

    private void run() throws Exception {
        ProbeIdentity identity = ProbeIdentity.parse(readOwnFile("/proc/self/status", 32768),
                readOwnFile("/proc/self/attr/current", 256));
        identity.requireOrdinaryRunAs(Process.myUid());
        emit("entry", new JSONObject().put("kernel_fields", new JSONObject(identity.fields()))
                .put("selinux_context", identity.securityContext)
                .put("cgroup", readOwnFile("/proc/self/cgroup", 8192).trim()));

        phase = "package_context";
        Context context = PrincipalContext.create();
        ProbePrincipal.requireOwnContext(Process.myUid(), context.getApplicationInfo().packageName,
                context.getApplicationInfo().uid, context.getPackageName(),
                context.getAttributionSource().getUid(), context.getAttributionSource().getPackageName());
        phase = "context_observation";
        JSONObject facts = permissions(context);
        facts.put("context_package", context.getPackageName());
        facts.put("context_uid", context.getApplicationInfo().uid);
        facts.put("target_sdk", context.getApplicationInfo().targetSdkVersion);
        facts.put("attribution_uid", context.getAttributionSource().getUid());
        facts.put("attribution_package", context.getAttributionSource().getPackageName());
        facts.put("attribution_tag", context.getAttributionSource().getAttributionTag());
        emit("context", facts);

        phase = "location_manager";
        LocationManager manager = context.getSystemService(LocationManager.class);
        if (manager == null) throw new IllegalStateException("location service absent");
        boolean present = manager.getAllProviders().contains(LocationArguments.PROVIDER);
        emit("provider", new JSONObject().put("fixed_provider_present", present));
        if ("info".equals(arguments.action)) {
            emit("complete", new JSONObject().put("not_a_delivery_qualification", true));
            return;
        }
        if (!present) throw new IllegalStateException("fixed mock provider absent; no fallback");

        ExecutorService executor = Executors.newSingleThreadExecutor();
        LocationListener listener = new LocationListener() {
            @Override public void onLocationChanged(Location location) { locationEvent(location); }
            @Override public void onProviderEnabled(String provider) { providerEvent(true, provider); }
            @Override public void onProviderDisabled(String provider) { providerEvent(false, provider); }
        };
        boolean registered = false;
        boolean removed = false;
        boolean retired;
        try {
            phase = "request";
            LocationRequest request = new LocationRequest.Builder(1000)
                    .setMinUpdateIntervalMillis(1000)
                    .setMinUpdateDistanceMeters(0)
                    .build();
            // No bypass, WorkSource, hidden-AppOps or background throttle exemption flags.
            manager.requestLocationUpdates(LocationArguments.PROVIDER, request, executor, listener);
            registered = true;
            // Same diagnostic formatter as the pinned AppOpsManager.toReceiverId and
            // CallerIdentity dump. This label is not authority or a process Stop handle.
            String receiverId = listener.getClass().getName() + "@" + System.identityHashCode(listener);
            emit("registered", new JSONObject().put("request_returned_not_delivery", true)
                    .put("listener_diagnostic_hash", String.format(Locale.ROOT, "%08X", receiverId.hashCode()))
                    .put("interval_ms", 1000).put("minimum_update_interval_ms", 1000)
                    .put("client_duration_ms", arguments.durationMillis)
                    .put("service_duration_or_count_limit_requested", false));
            phase = "watch";
            long end = SystemClock.elapsedRealtime() + arguments.durationMillis;
            long nextHeartbeat = 0;
            while (SystemClock.elapsedRealtime() < end) {
                Throwable error = callbackFailure.get();
                if (error != null) throw new IllegalStateException("callback validation failed", error);
                long now = SystemClock.elapsedRealtime();
                if (now >= nextHeartbeat) {
                    emit("heartbeat", permissions(context));
                    nextHeartbeat = now + 2000;
                }
                Thread.sleep(Math.min(200, Math.max(1, end - now)));
            }
        } finally {
            closing.set(true);
            try {
                if (registered) {
                    manager.removeUpdates(listener);
                    removed = true;
                }
            } finally {
                executor.shutdown();
                retired = executor.awaitTermination(5, TimeUnit.SECONDS);
                if (!retired) executor.shutdownNow();
                emit("cleanup", new JSONObject().put("registered", registered)
                        .put("remove_updates_returned", removed).put("executor_retired", retired));
            }
        }
        if (!retired) throw new IllegalStateException("callback executor did not retire");
        if (callbackFailure.get() != null) throw new IllegalStateException("callback validation failed");
        emit("complete", new JSONObject().put("callback_count", callbacks.get())
                .put("not_a_health_or_location_policy_qualification", true));
    }

    private synchronized void locationEvent(Location location) {
        if (closing.get()) return;
        try {
            if (!location.isMock() || !LocationArguments.PROVIDER.equals(location.getProvider())) {
                throw new IllegalStateException("unexpected nonfixture location suppressed");
            }
            // The shell fixture supplies this public timestamp as a correlation marker.
            // Never read or emit coordinates, altitude or Location.toString().
            if (callbacks.get() >= 128) throw new IllegalStateException("callback count bound reached");
            callbacks.incrementAndGet();
            emit("callback", new JSONObject().put("mock", true).put("marker_time_ms", location.getTime())
                    .put("location_elapsed_realtime_ns", location.getElapsedRealtimeNanos()));
        } catch (Throwable error) {
            callbackFailure.compareAndSet(null, error);
        }
    }

    private void providerEvent(boolean enabled, String provider) {
        if (closing.get()) return;
        try {
            if (!LocationArguments.PROVIDER.equals(provider)) {
                throw new IllegalStateException("unexpected provider event");
            }
            emit("provider_state", new JSONObject().put("enabled", enabled));
        } catch (Throwable error) {
            callbackFailure.compareAndSet(null, error);
        }
    }

    private synchronized void emit(String event, JSONObject details) throws Exception {
        details.put("schema", 1).put("phase", event).put("sequence", ++sequence)
                .put("action", arguments.action).put("nonce", arguments.nonce)
                .put("provider", LocationArguments.PROVIDER).put("uid", Process.myUid())
                .put("pid", Process.myPid()).put("elapsed_realtime_ms", SystemClock.elapsedRealtime())
                .put("callback_count", callbacks.get());
        System.out.println(details.toString());
        System.out.flush();
    }

    private static JSONObject permissions(Context context) throws Exception {
        return new JSONObject().put("coarse_granted", granted(context, Manifest.permission.ACCESS_COARSE_LOCATION))
                .put("fine_granted", granted(context, Manifest.permission.ACCESS_FINE_LOCATION))
                .put("background_granted", granted(context, Manifest.permission.ACCESS_BACKGROUND_LOCATION));
    }

    private static boolean granted(Context context, String permission) {
        return context.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED;
    }

    private static JSONObject failureDetails(Throwable failure) throws Exception {
        JSONObject details = new JSONObject().put("status", "refused_or_failed")
                .put("error_class", failure.getClass().getName());
        String message = failure.getMessage();
        if (message != null) details.put("diagnostic_message", message.substring(0, Math.min(512, message.length())));
        JSONArray stack = new JSONArray();
        StackTraceElement[] frames = failure.getStackTrace();
        for (int i = 0; i < Math.min(12, frames.length); i++) {
            stack.put(frames[i].getClassName() + "." + frames[i].getMethodName() + ":" + frames[i].getLineNumber());
        }
        return details.put("diagnostic_stack", stack);
    }

    private static String readOwnFile(String path, int maximum) throws Exception {
        try (FileInputStream input = new FileInputStream(path);
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
}
