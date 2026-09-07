package dev.andrix.proof.webviewqualification;

import android.app.job.JobInfo;
import android.content.Context;

import java.util.Collections;

final class ModeOperations {
    private final Context context;
    private final Session s;
    private final boolean providerTarget;
    private SafeModeConnection safe;
    private Jobs jobs;
    private boolean ownSafeState;

    ModeOperations(Context context, Session s, boolean providerTarget) {
        this.context = context;
        this.s = s;
        this.providerTarget = providerTarget;
    }

    void open() throws Exception {
        s.requireRunning();
        if (providerTarget) {
            jobs = new Jobs(context, s);
        }
        if (!s.args.mode.startsWith("job-")) {
            safe = new SafeModeConnection(context, s);
            safe.open();
        }
    }

    void run() throws Exception {
        s.requireRunning();
        switch (s.args.mode) {
            case "different-uid":
                differentUid();
                break;
            case "fast-on":
                // A clean control excludes clearing someone else's pre-existing actions on error.
                safe.read("before_fast_on").requireOff();
                jobs.requireAbsent("before_fast_on");
                s.requireRunning();
                ownSafeState = true;
                s.cleanupRequired = true;
                safe.set(Collections.singletonList(SafeModeConnection.FAST));
                safe.read("after_fast_on").requireOn();
                jobs.requireAbsent("after_fast_on");
                s.record("intentional_persistence", "actions", SafeModeConnection.FAST,
                        "cleanup_required", true);
                break;
            case "fast-off":
            case "cleanup":
                Arguments.check(safe.read("before_fast_off").knownActions(),
                        "Unknown existing SafeMode actions; preserved");
                jobs.read("before_fast_off");
                s.requireRunning();
                if (s.args.mode.equals("cleanup") && s.args.marker != null) {
                    jobs.cancelMarkedIfPresent("explicit_cleanup");
                }
                s.requireRunning();
                ownSafeState = true;
                s.cleanupRequired = true;
                // The existing Binder service is the only writer of actions,
                // timestamps and alias state. No direct preferences/files/PM writes.
                safe.set(Collections.emptyList());
                safe.read("after_fast_off").requireOff();
                jobs.requireAbsent("after_fast_off");
                ownSafeState = false;
                s.cleanupRequired = false;
                break;
            case "job-stage":
                jobs.stage();
                break;
            case "job-present":
                jobs.present();
                break;
            case "job-absent":
                jobs.absent();
                break;
            default:
                throw new IllegalStateException("Not a Binder/job mode");
        }
    }

    private void differentUid() throws Exception {
        // The denial request is an empty list from an already-clear baseline:
        // even unexpected authorization cannot introduce fast-mode state.
        safe.read("different_uid_control").requireOff();
        s.requireRunning();
        safe.requireSetterDenied();
        safe.read("after_denied_setter").requireOff();
    }

    /** Called on the same worker after the operation, even after its timeout. */
    void cleanup() {
        boolean rollbackAttempted = false;
        if (s.failed.get()) {
            rollbackAttempted = true;
            rollbackGuarded();
        }
        try {
            if (safe != null) {
                safe.close();
            }
        } catch (Throwable error) {
            s.fail("service_unbind", error);
            if (!rollbackAttempted) {
                rollbackGuarded();
            }
        }
        s.record("provider_state_cleanup", "cleanup_required", s.cleanupRequired,
                "successful_test_state_left_intentionally", !s.failed.get() && s.cleanupRequired);
    }

    private void rollbackGuarded() {
        try {
            if (jobs != null) {
                jobs.rollback();
            }
            if (ownSafeState) {
                Arguments.check(safe.read("error_cleanup_control").knownActions(),
                        "Error cleanup found unknown actions; preserved");
                JobInfo pending = jobs.read("error_cleanup_control");
                Arguments.check(pending == null || jobs.isOwned(pending),
                        "Error cleanup would affect an unowned job 83; preserved");
                safe.set(Collections.emptyList());
                safe.read("after_error_cleanup").requireOff();
                jobs.requireAbsent("after_error_cleanup");
                ownSafeState = false;
                s.cleanupRequired = false;
            }
        } catch (Throwable error) {
            // Keep the primary failure AND the cleanup failure; never convert
            // failure into PASS or silently erase uncertain/foreign state.
            s.cleanupRequired = true;
            s.fail("provider_state_error_cleanup", error);
        }
    }
}
