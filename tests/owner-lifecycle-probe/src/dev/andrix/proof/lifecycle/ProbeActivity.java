// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.lifecycle;

import android.Manifest;
import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Process;
import android.os.RemoteException;
import android.os.SystemClock;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

/** Visible controls for the lab-only lifecycle service. No native owner access. */
public final class ProbeActivity extends Activity {
    private final Handler main = new Handler(Looper.getMainLooper());
    private ILifecycleProbe witness;
    private TextView status;
    private boolean bound, resumed, pendingStart;
    private String message = "No monitor bound";
    private final ServiceConnection connection = new ServiceConnection() {
        @Override public void onServiceConnected(ComponentName name, IBinder binder) {
            witness = ILifecycleProbe.Stub.asInterface(binder);
            message = "Monitor connected";
            update();
        }
        @Override public void onServiceDisconnected(ComponentName name) {
            witness = null;
            message = "Monitor process disconnected; no authority implied";
            update();
        }
        @Override public void onBindingDied(ComponentName name) {
            unbindMonitor();
            message = "Monitor binding died; explicit Start required";
            update();
        }
    };
    private final Runnable poll = new Runnable() {
        @Override public void run() {
            if (!resumed) return;
            update();
            main.postDelayed(this, 1000);
        }
    };

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(24, 48, 24, 24);
        TextView title = new TextView(this);
        title.setText("Lifecycle probe — no owner-job authority");
        title.setTextSize(20);
        layout.addView(title);
        status = new TextView(this);
        status.setTextSize(16);
        status.setMinLines(15);
        layout.addView(status);
        add(layout, "Start monitor", this::requestStart);
        add(layout, "Stop monitor", () -> {
            pendingStart = false;
            unbindMonitor();
            stopService(new Intent(this, WitnessService.class));
            message = "Explicit Stop requested";
            update();
        });
        add(layout, "Close this UI process", () -> {
            if (resumed && hasWindowFocus()) Process.killProcess(Process.myPid());
        });
        setContentView(layout);
    }

    private void add(LinearLayout layout, String text, Runnable action) {
        Button button = new Button(this);
        button.setText(text);
        button.setFilterTouchesWhenObscured(true);
        button.setOnClickListener(v -> { if (resumed && hasWindowFocus()) action.run(); });
        layout.addView(button);
    }

    private void requestStart() {
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            pendingStart = true;
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 7);
        } else startMonitor();
    }

    private void startMonitor() {
        if (!resumed || !hasWindowFocus()) return;
        try {
            startForegroundService(new Intent(this, WitnessService.class).setAction(WitnessService.START));
            bindMonitor();
            message = "Monitor requested explicitly";
        } catch (RuntimeException e) {
            message = "Monitor start failed: " + e.getClass().getSimpleName();
        }
        update();
    }

    @Override public void onRequestPermissionsResult(int request, String[] permissions, int[] grants) {
        super.onRequestPermissionsResult(request, permissions, grants);
        if (request != 7) return;
        boolean start = pendingStart && grants.length == 1 && grants[0] == PackageManager.PERMISSION_GRANTED;
        pendingStart = false;
        message = start ? "Notification permission granted; tap Start monitor"
                : "Notification permission not granted; monitor not started";
        update();
    }

    private void bindMonitor() {
        if (bound) return;
        // Binding observes an explicitly started service; it must not itself
        // create or restart a witness after process death.
        bound = bindService(new Intent(this, WitnessService.class), connection, 0);
    }

    private void unbindMonitor() {
        witness = null;
        if (bound) { unbindService(connection); bound = false; }
    }

    private void update() {
        if (status == null) return;
        String text = "UI PID=" + Process.myPid() + " UID=" + Process.myUid() + "\n" + message;
        if (witness != null) {
            try {
                Bundle b = witness.snapshot();
                text += "\nWitness PID=" + b.getInt("pid", -1) + " UID=" + b.getInt("uid", -1)
                        + "\nEpoch=" + b.getLong("epoch", -1) + " Sample=" + b.getLong("sequence", 0)
                        + "\nActive=" + b.getBoolean("active") + " Fresh=" + b.getBoolean("fresh")
                        + "\nRunning before/after=" + b.getBoolean("running_before") + "/" + b.getBoolean("running_after")
                        + "\nUnlocked=" + b.getBoolean("unlocked") + " Usable=" + b.getBoolean("usable")
                        + "\nDevice locked=" + b.getBoolean("device_locked") + " Interactive=" + b.getBoolean("interactive")
                        + "\nSample age ms=" + (SystemClock.elapsedRealtime() - b.getLong("observed_ms", 0))
                        + "\nQuery ms=" + b.getLong("query_ms", -1);
            } catch (RemoteException | RuntimeException e) {
                text += "\nSnapshot unavailable: " + e.getClass().getSimpleName();
            }
        }
        status.setText(text);
    }

    @Override protected void onResume() {
        super.onResume(); resumed = true; bindMonitor(); main.post(poll);
    }
    @Override protected void onPause() {
        resumed = false; main.removeCallbacks(poll); super.onPause();
    }
    @Override protected void onDestroy() {
        main.removeCallbacks(poll); unbindMonitor(); super.onDestroy();
    }
}
