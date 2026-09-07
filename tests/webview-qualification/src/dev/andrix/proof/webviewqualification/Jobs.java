package dev.andrix.proof.webviewqualification;

import android.Manifest;
import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.os.PersistableBundle;
import android.os.Process;
import android.os.SystemClock;

import java.util.concurrent.TimeUnit;

import org.json.JSONObject;

/** Only the frozen DEX's job 83, through the real provider-UID JobScheduler. */
final class Jobs {
    static final int ID = 83;
    static final long ONE_DAY_MS = 24L * 60 * 60 * 1000;
    static final String MARKER = "dev.andrix.proof.webviewqualification.marker";
    private final Context context;
    private final Session s;
    private final JobScheduler scheduler;
    // A marker is not authentication. The host must ensure exclusive test ownership.
    boolean stageAttempted;
    boolean ownedObserved;

    Jobs(Context context, Session s) {
        this.context = context;
        this.s = s;
        Arguments.check(Pins.PROVIDER.equals(context.getPackageName())
                        && context.getApplicationInfo().uid == Process.myUid(),
                "JobScheduler operations require the real provider target UID");
        scheduler = context.getSystemService(JobScheduler.class);
        Arguments.check(scheduler != null, "No provider JobScheduler");
    }

    JobInfo read(String point) {
        JobInfo job = scheduler.getPendingJob(ID);
        s.record("job_83", "point", point, "uid", Process.myUid(), "job", describe(job));
        return job;
    }

    void requireAbsent(String point) {
        Arguments.check(read(point) == null, "Unexpected pending provider job 83");
    }

    void stage() throws Exception {
        requireAbsent("before_stage"); // Never replace any existing job, including an old test job.
        Arguments.check(context.getPackageManager().checkPermission(Manifest.permission.RECEIVE_BOOT_COMPLETED,
                        Pins.PROVIDER) == PackageManager.PERMISSION_GRANTED,
                "Provider lacks its own RECEIVE_BOOT_COMPLETED permission for persisted jobs");
        ServiceInfo service = context.getPackageManager().getServiceInfo(Pins.JOB_SERVICE, 0);
        s.record("job_service", "component", Pins.JOB_SERVICE.flattenToString(),
                "uid", service.applicationInfo.uid, "permission", service.permission,
                "enabled", service.enabled, "process_name", service.processName);
        Arguments.check(service.applicationInfo.uid == Process.myUid() && service.enabled
                        && "android.permission.BIND_JOB_SERVICE".equals(service.permission),
                "Unexpected provider JobService identity/permission");
        PersistableBundle extras = new PersistableBundle();
        extras.putBoolean("RequestFastMode", true);
        extras.putBoolean("PeriodicFastMode", false);
        extras.putInt("RequestCount", 0);
        extras.putString(MARKER, s.args.marker);
        JobInfo job = new JobInfo.Builder(ID, Pins.JOB_SERVICE)
                .setPersisted(true)
                .setMinimumLatency(ONE_DAY_MS)
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .setExtras(extras)
                .build();
        s.requireRunning();
        stageAttempted = true;
        s.cleanupRequired = true; // Before IPC: even a timeout can have scheduled it.
        s.record("job_schedule_attempt", "requested_job", describe(job));
        int result = scheduler.schedule(job);
        s.record("job_schedule", "result", result, "requested_job", describe(job));
        Arguments.check(result == JobScheduler.RESULT_SUCCESS, "JobScheduler rejected the synthetic job");
        JobInfo pending = read("after_stage");
        requireOwned(pending);
        ownedObserved = true;
        Arguments.check(pending.getMinLatencyMillis() == ONE_DAY_MS, "Stage minimum latency changed");
    }

    void present() {
        JobInfo pending = read("present");
        requireOwned(pending);
        ownedObserved = true;
        s.cleanupRequired = true;
        // JobStore may rebase minimum latency across reboot. Record, do not
        // require the original one-day value after persistence/restoration.
    }

    void absent() throws Exception {
        long deadline = SystemClock.elapsedRealtime() + TimeUnit.SECONDS.toMillis(Session.TIMEOUT_SECONDS);
        JobInfo pending = read("before_absence_wait");
        while (pending != null) {
            s.requireRunning();
            requireOwned(pending); // Do not wait on, or later clean up, somebody else's replacement.
            ownedObserved = true;
            s.cleanupRequired = true;
            Arguments.check(SystemClock.elapsedRealtime() < deadline, "Callback did not remove job 83");
            Thread.sleep(250); // Worker only. The enclosing runner stage also has a 180s bound.
            pending = scheduler.getPendingJob(ID);
        }
        s.record("job_83", "point", "absent", "uid", Process.myUid(), "job", null);
        ownedObserved = false;
        s.cleanupRequired = false;
        s.record("job_absence_scope", "marker", s.args.marker,
                "requires_host_prior_stage_and_callback_evidence", true);
    }

    void cancelMarkedIfPresent(String point) {
        JobInfo pending = read(point);
        if (pending == null) {
            return;
        }
        requireOwned(pending); // Never cancel an unknown component, extras or marker.
        ownedObserved = true; // Retain ownership if cancellation throws/times out.
        s.cleanupRequired = true;
        s.record("job_cancel_attempt", "id", ID, "verified_marker", s.args.marker);
        scheduler.cancel(ID);
        s.record("job_cancel", "id", ID, "verified_marker", s.args.marker);
        requireAbsent("after_marker_cancel");
    }

    void rollback() {
        if (stageAttempted || ownedObserved) {
            cancelMarkedIfPresent("error_cleanup");
            s.cleanupRequired = false;
        }
    }

    boolean isOwned(JobInfo job) {
        if (job == null || s.args.marker == null || job.getId() != ID
                || !Pins.JOB_SERVICE.equals(job.getService()) || !job.isPersisted()
                || job.isPeriodic() || !hasAnyNetwork(job)) {
            return false;
        }
        PersistableBundle extras = job.getExtras();
        return extras != null && extras.size() == 4
                && Boolean.TRUE.equals(extras.get("RequestFastMode"))
                && Boolean.FALSE.equals(extras.get("PeriodicFastMode"))
                && Integer.valueOf(0).equals(extras.get("RequestCount"))
                && s.args.marker.equals(extras.get(MARKER));
    }

    private void requireOwned(JobInfo job) {
        Arguments.check(isOwned(job), "Job 83 is missing or not this exact marked persisted test job; preserved");
    }

    private static boolean hasAnyNetwork(JobInfo job) {
        // Compare public NetworkRequests, not an older/hidden network-type accessor.
        return new JobInfo.Builder(ID, Pins.JOB_SERVICE)
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY).build()
                .getRequiredNetwork().equals(job.getRequiredNetwork());
    }

    private static JSONObject describe(JobInfo job) {
        if (job == null) {
            return null;
        }
        PersistableBundle extras = job.getExtras();
        JSONObject raw = new JSONObject();
        for (String key : extras.keySet()) {
            Object value = extras.get(key);
            // Preserve scalar values and types without arbitrary object toString calls.
            try {
                raw.put(key, Session.object("type", value == null ? null : value.getClass().getName(),
                        "value", value instanceof String || value instanceof Number || value instanceof Boolean
                                ? value : JSONObject.NULL));
            } catch (org.json.JSONException error) {
                throw new IllegalStateException(error);
            }
        }
        return Session.object("id", job.getId(), "service", job.getService().flattenToString(),
                "persisted", job.isPersisted(), "periodic", job.isPeriodic(),
                "minimum_latency_ms", job.getMinLatencyMillis(),
                "network_any", hasAnyNetwork(job),
                "required_network", job.getRequiredNetwork() == null ? null
                        : job.getRequiredNetwork().toString(), "extras", raw);
    }
}
