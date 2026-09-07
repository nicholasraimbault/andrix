package dev.andrix.proof.webviewqualification;

import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.util.Log;

import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.json.JSONException;
import org.json.JSONObject;

/** One serialized worker, asynchronous main-thread work, bounded runner waits. */
final class Session {
    static final int TIMEOUT_SECONDS = 180;
    final Handler main = new Handler(Looper.getMainLooper());
    final ConcurrentLinkedQueue<JSONObject> observations = new ConcurrentLinkedQueue<>();
    final AtomicBoolean failed = new AtomicBoolean();
    final CompletableFuture<ClassLoader> initialized = new CompletableFuture<>();
    final CompletableFuture<Void> destroyed = new CompletableFuture<>();
    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
        Thread thread = new Thread(r, "webview-qualification-worker");
        thread.setDaemon(true);
        return thread;
    });
    private final long started = SystemClock.elapsedRealtime();
    volatile boolean closing;
    volatile boolean cleanupRequired;
    String providerSource;
    Arguments args;
    // Main-thread-only lifecycle state; initialized/destroyed publish observations.
    QualificationActivity activity;
    boolean launchRequested;

    <T> T step(String name, Callable<T> action) throws Throwable {
        record("stage_start", "stage", name);
        Future<T> future = null;
        try {
            future = worker.submit(action);
            T result = await(future);
            record("stage_complete", "stage", name);
            return result;
        } catch (Throwable error) {
            if (future != null) {
                future.cancel(true); // Cannot forcibly interrupt a synchronous Binder transaction.
            }
            fail(name, error);
            throw error;
        }
    }

    static <T> T await(Future<T> future) throws Exception {
        try {
            return future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (ExecutionException error) {
            Throwable cause = error.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw new IllegalStateException(cause);
        } catch (TimeoutException error) {
            throw new TimeoutException("Stage exceeded 180 seconds; completion/state may be unknown");
        }
    }

    CompletableFuture<Void> post(Runnable action) {
        CompletableFuture<Void> result = new CompletableFuture<>();
        if (!main.post(() -> {
            try {
                action.run();
                result.complete(null);
            } catch (Throwable error) {
                fail("main_callback", error); // Retain errors even if the waiting stage timed out.
                result.completeExceptionally(error);
            }
        })) {
            IllegalStateException error = new IllegalStateException("Main looper rejected work");
            fail("main_post", error);
            result.completeExceptionally(error);
        }
        return result;
    }

    void requireRunning() {
        Arguments.check(!closing && !failed.get() && !Thread.currentThread().isInterrupted(),
                "Run is closing/failed/interrupted; refusing new operation");
    }

    void shutdown() {
        // Cleanup was queued on the SAME worker after timed-out work. Do not
        // start a competing writer if Binder never returns. Host reconciles.
        worker.shutdownNow();
    }

    void record(String event, Object... fields) {
        observations.add(object("event", event, "elapsed_ms", SystemClock.elapsedRealtime() - started,
                "data", object(fields)));
    }

    void fail(String stage, Throwable error) {
        failed.set(true);
        record("failure", "stage", stage, "exception", error.toString(),
                "stack_trace", Log.getStackTraceString(error));
    }

    static JSONObject object(Object... pairs) {
        JSONObject result = new JSONObject();
        try {
            for (int i = 0; i < pairs.length; i += 2) {
                result.put((String) pairs[i], pairs[i + 1] == null ? JSONObject.NULL : pairs[i + 1]);
            }
        } catch (JSONException error) {
            throw new IllegalStateException("Cannot encode qualification evidence", error);
        }
        return result;
    }
}
