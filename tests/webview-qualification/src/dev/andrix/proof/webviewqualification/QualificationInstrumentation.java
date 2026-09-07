package dev.andrix.proof.webviewqualification;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Intent;
import android.os.Bundle;
import android.os.Process;

import org.json.JSONArray;
import org.json.JSONObject;

/** Two manifest entries share mechanics, never authority or mode defaults. */
public abstract class QualificationInstrumentation extends Instrumentation {
    static volatile Session activeSession;
    private Bundle arguments;

    abstract boolean providerTarget();

    @Override
    public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        this.arguments = arguments == null ? new Bundle() : new Bundle(arguments);
        start();
    }

    @Override
    public void onStart() {
        Session s = new Session();
        ModeOperations operations = new ModeOperations(getTargetContext(), s, providerTarget());
        boolean interrupted = false;
        try {
            s.args = new Arguments(arguments, providerTarget());
            s.record("arguments", "mode", s.args.mode, "expected_fingerprint", s.args.fingerprint,
                    "marker", s.args.marker, "expected_config_version",
                    s.args.configVersion < 0 ? null : s.args.configVersion);
            s.step("guard", () -> {
                Pins.guard(this, s, providerTarget());
                return null;
            });
            if (s.args.configMode()) {
                activeSession = s;
                ClassLoader loader = s.step("webview_initialization", () -> {
                    Session.await(s.post(() -> {
                        s.requireRunning();
                        s.launchRequested = true;
                        try {
                            getTargetContext().startActivity(new Intent(getTargetContext(),
                                    QualificationActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
                        } catch (Throwable error) {
                            s.launchRequested = false;
                            throw error;
                        }
                    }));
                    return Session.await(s.initialized);
                });
                s.step("config_fields", () -> {
                    ConfigCheck.inspect(getTargetContext(), s, loader);
                    return null;
                });
            } else {
                s.step("mode_setup", () -> {
                    operations.open();
                    return null;
                });
                s.step(s.args.mode, () -> {
                    operations.run();
                    return null;
                });
            }
        } catch (Throwable error) {
            interrupted = error instanceof InterruptedException;
            // step() already retains its named failure; parse failures reach here directly.
            if (!s.failed.get()) {
                s.fail("runner", error);
            }
        } finally {
            s.closing = true; // Prevent late launch/bind/mutation after a timed-out stage.
            try {
                s.step("activity_cleanup", () -> {
                    Session.await(s.post(() -> {
                        if (s.activity != null) {
                            s.activity.close();
                        } else if (!s.launchRequested) {
                            s.record("activity_cleanup", "launch_requested", false);
                            s.destroyed.complete(null);
                        }
                        // If launch was requested but onCreate has not run,
                        // wait for its late closing path and real onDestroy.
                    }));
                    Session.await(s.destroyed);
                    return null;
                });
            } catch (Throwable error) {
                interrupted |= error instanceof InterruptedException;
            }
            try {
                s.step("provider_and_bind_cleanup", () -> {
                    operations.cleanup();
                    return null;
                });
            } catch (Throwable error) {
                interrupted |= error instanceof InterruptedException;
            }
            activeSession = null;
            s.shutdown();
        }
        String status = s.failed.get() ? "FAIL" : "PASS";
        JSONObject report = Session.object("schema", 1, "status", status,
                "mode", s.args == null ? arguments.getString("mode") : s.args.mode,
                "authority", providerTarget() ? "provider-uid-white-box" : "own-uid",
                "process_uid", Process.myUid(), "target_package", getTargetContext().getPackageName(),
                "stage_timeout_seconds", Session.TIMEOUT_SECONDS,
                "cleanup_required", s.cleanupRequired,
                "different_signer_ordinary_authority_proved", false,
                "network_js_tls_or_all_policy_proved", false,
                "observations", new JSONArray(s.observations));
        Bundle result = new Bundle();
        result.putString("webview_qualification", report.toString());
        result.putString("webview_qualification_status", status);
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
        finish(s.failed.get() ? Activity.RESULT_CANCELED : Activity.RESULT_OK, result);
    }
}
