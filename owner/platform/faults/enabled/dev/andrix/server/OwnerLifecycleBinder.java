// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server;

import android.content.Context;
import android.os.Binder;
import android.os.Build;
import android.os.ResultReceiver;
import android.os.ShellCallback;
import android.os.ShellCommand;
import android.os.SystemClock;
import android.os.storage.StorageManager;
import android.util.Slog;

import dev.andrix.lifecycle.IPlatformLifecycle;
import dev.andrix.lifecycle.PlatformState;

import java.io.FileDescriptor;
import java.io.PrintWriter;

/** Selected ONLY by the additional debug-product fault-test opt-in. */
abstract class OwnerLifecycleBinder extends IPlatformLifecycle.Stub {
    private static final String TAG = "AndrixLifecycleFault";
    private static final int OWNER_USER = 0;
    private final Context context;
    private final LifecycleFaultGate faults = new LifecycleFaultGate();

    OwnerLifecycleBinder(Context context) { this.context = context; }
    protected abstract PlatformState captureState();

    private static LifecycleFaultGate.Target target(PlatformState state) {
        return new LifecycleFaultGate.Target(state.instance, state.generation,
                state.available, state.keptWorkId, state.keepRegistration);
    }

    /** Called only after the service authenticated the native snapshot caller. */
    final void beforeReply(PlatformState captured) {
        if (!Build.IS_DEBUGGABLE) return;
        LifecycleFaultGate.Target ticket = faults.takeDelay(target(captured), SystemClock.uptimeMillis());
        if (ticket == null) return;
        // Keep the REAL captured response. A later positive reply must not buy a
        // fresh native lease. No lifecycle, storage or fault-gate monitor is held.
        final int caller = Binder.getCallingPid();
        try {
            Slog.i(TAG, "snapshot_delay_begin pid=" + caller + " " + ticket);
            SystemClock.sleep(LifecycleFaultGate.REPLY_DELAY_MILLIS);
        } finally {
            faults.finishDelay(ticket);
            Slog.i(TAG, "snapshot_delay_end pid=" + caller + " " + ticket);
        }
    }

    @Override public final void onShellCommand(FileDescriptor in, FileDescriptor out,
            FileDescriptor err, String[] args, ShellCallback callback, ResultReceiver result) {
        // Real Binder identity, not supplied UID/PID or service discovery. This
        // command implementation is absent from normal products; debuggable alone
        // cannot enable it. No general Shell storage permission is added.
        if (!Build.IS_DEBUGGABLE || Binder.getCallingUid() != android.os.Process.SHELL_UID
                || Binder.getCallingPid() <= 1) {
            if (result != null) result.send(-1, null);
            throw new SecurityException("lab lifecycle control requires the debug Shell caller");
        }
        new ShellCommand() {
            @Override public int onCommand(String command) {
                if (getNextArg() != null) {
                    getErrPrintWriter().println("No arguments are accepted");
                    return 1;
                }
                if (command == null || "help".equals(command) || "-h".equals(command)) {
                    onHelp(); return 0;
                }
                switch (command) {
                    case "lock-ce-user0": return lockOwnerCe(getOutPrintWriter());
                    case "delay-next-snapshot": return armDelay(getOutPrintWriter());
                    default:
                        getErrPrintWriter().println("Unknown fixed lab command");
                        return 1;
                }
            }
            @Override public void onHelp() {
                PrintWriter out = getOutPrintWriter();
                out.println("LAB ONLY: one accepted use of each fault per platform lifetime");
                out.println("  lock-ce-user0          real Android CE-storage lock for user0");
                out.println("  delay-next-snapshot    one matching captured reply delayed 2500ms");
                out.println("Active Keep required; no arguments; delay arm expires after 5000ms");
                out.println("Requests and cache metadata are not key/cleanup completion proof");
            }
        }.exec(this, in, out, err, args, callback, result);
    }

    private int armDelay(PrintWriter out) {
        LifecycleFaultGate.Target current = target(captureState());
        if (!faults.armDelay(current, SystemClock.uptimeMillis())) {
            out.println("not_armed: active Keep, unused delay budget and no concurrent fault required");
            return 1;
        }
        Slog.i(TAG, "snapshot_delay_armed " + current);
        out.println("armed: " + current + " delay_ms=" + LifecycleFaultGate.REPLY_DELAY_MILLIS
                + " arm_window_ms=" + LifecycleFaultGate.ARM_WINDOW_MILLIS);
        return 0;
    }

    private int lockOwnerCe(PrintWriter out) {
        LifecycleFaultGate.Target ticket = faults.beginKeyLock(target(captureState()),
                SystemClock.uptimeMillis());
        if (ticket == null) {
            out.println("not_attempted: active Keep, unused key budget and no concurrent fault required");
            return 1;
        }
        // This is the explicitly owner-approved system_server delegation for ONE
        // fixed lab operation, after authenticating the actual Shell endpoint.
        // No lifecycle/storage/gate monitor is held, and key withdrawal never waits
        // for native cleanup. This is not a general borrowed-identity facility.
        final long identity = Binder.clearCallingIdentity();
        try {
            StorageManager storage = context.getSystemService(StorageManager.class);
            if (storage == null) throw new IllegalStateException("Android storage service unavailable");
            boolean before = StorageManager.isCeStorageUnlocked(OWNER_USER);
            if (!before || !ticket.matches(target(captureState()))) {
                out.println("not_attempted: target changed or Android CE cache already locked");
                return 1;
            }
            Slog.i(TAG, "ce_lock_call_begin user=0 " + ticket);
            storage.lockCeStorage(OWNER_USER); // REAL existing Android method, never a state flag.
            boolean after = StorageManager.isCeStorageUnlocked(OWNER_USER);
            PlatformState observation = captureState();
            String message = "ce_lock_call_returned user=0 framework_ce_cache_before=" + before
                    + " framework_ce_cache_after=" + after + " observed_generation="
                    + observation.generation + " observed_available=" + observation.available;
            Slog.i(TAG, message); out.println(message);
            out.println("Inspect Android/vold busy/errors and actual group cleanup separately");
            return after ? 1 : 0;
        } catch (RuntimeException error) {
            Slog.e(TAG, "ce_lock_call_failed user=0 " + ticket, error);
            out.println("call_failed: " + error.getClass().getSimpleName());
            return 1;
        } finally {
            Binder.restoreCallingIdentity(identity);
            faults.finishKeyLock(ticket);
        }
    }
}
