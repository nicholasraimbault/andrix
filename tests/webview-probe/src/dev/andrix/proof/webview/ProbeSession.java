package dev.andrix.proof.webview;

import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.util.Log;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.json.JSONException;
import org.json.JSONObject;

/** Immutable queued observations cross from the UI thread to the runner thread. */
final class ProbeSession {
    static final long STAGE_TIMEOUT_SECONDS = 180;
    final Handler main = new Handler(Looper.getMainLooper());
    final ConcurrentLinkedQueue<JSONObject> observations = new ConcurrentLinkedQueue<>();
    final AtomicBoolean failed = new AtomicBoolean();
    final CountDownLatch cleaned = new CountDownLatch(1);
    private final BlockingQueue<String> stages = new LinkedBlockingQueue<>();
    private final long started = SystemClock.elapsedRealtime();

    // Config is assigned before volatile publication. Activity/closing are UI-thread-only.
    ProbeConfig config;
    ProbeActivity activity;
    boolean closing;

    static JSONObject object(Object... pairs) {
        JSONObject result = new JSONObject();
        try {
            for (int i = 0; i < pairs.length; i += 2) {
                result.put((String) pairs[i], pairs[i + 1] == null ? JSONObject.NULL : pairs[i + 1]);
            }
        } catch (JSONException error) {
            throw new IllegalStateException("Cannot encode probe evidence", error);
        }
        return result;
    }

    void record(String event, Object... fields) {
        observations.add(object("event", event, "elapsed_ms", SystemClock.elapsedRealtime() - started,
                "data", object(fields)));
    }

    void fail(String stage, Throwable error) {
        record("failure", "stage", stage, "exception", error.toString(),
                "stack_trace", Log.getStackTraceString(error));
        if (failed.compareAndSet(false, true)) {
            stages.add("failure");
        }
    }

    void complete(String stage) {
        record("stage_complete", "stage", stage);
        stages.add(stage);
    }

    boolean awaitStage(String expected) throws InterruptedException {
        String actual = stages.poll(STAGE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        if (actual == null) {
            fail(expected, new TimeoutException(expected + " exceeded " + STAGE_TIMEOUT_SECONDS + "s"));
            return false;
        }
        if (failed.get()) {
            return false;
        }
        if (!expected.equals(actual)) {
            fail(expected, new IllegalStateException("Unexpected stage: " + actual));
            return false;
        }
        return true;
    }

    void post(String stage, Runnable action) {
        if (!main.post(() -> {
            try {
                action.run();
            } catch (Throwable error) {
                fail(stage, error);
            }
        })) {
            fail(stage, new IllegalStateException("Main looper refused work"));
        }
    }

    void close() {
        closing = true;
        if (activity == null) {
            record("cleanup", "activity_attached", false, "webview_created", false);
            cleaned.countDown();
        } else {
            activity.close(); // onDestroy acknowledges cleanup, not merely finish().
        }
    }
}
