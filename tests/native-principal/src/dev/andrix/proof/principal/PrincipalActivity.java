// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.principal;

import android.Manifest;
import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Process;
import android.provider.Settings;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * Disposable test probe: an optional visible control for Android's own permission UI
 * while the test controller launches command processes independently.
 *
 * <p>It only reads and requests this package's permissions. It never starts, keeps,
 * supervises or promotes a command process, never grants anything itself and stores nothing.
 * While it is visible, it can affect Android's foreground classification for the UID and
 * permission checks for other processes sharing that UID. Close it and measure the actual
 * UID/process state before testing background behavior; this UI does not attest that state.
 */
public final class PrincipalActivity extends Activity {
    private static final int REQUEST_NOTIFICATIONS = 1;
    private static final int REQUEST_FOREGROUND_LOCATION = 2;
    // Value of the hidden UserHandle.PER_USER_RANGE. Used to derive userId for display only.
    private static final int PER_USER_RANGE = 100000;

    private TextView status;
    private String lastEvent = "none";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        int pad = Math.round(16 * getResources().getDisplayMetrics().density);
        LinearLayout column = new LinearLayout(this);
        column.setOrientation(LinearLayout.VERTICAL);
        column.setPadding(pad, pad, pad, pad);

        TextView note = new TextView(this);
        note.setText("Andrix principal probe (test only). Grant states come from Android."
                + " uid and userId are shown for identification, not authorization.");
        column.addView(note);
        status = new TextView(this);
        status.setPadding(0, pad, 0, pad);
        column.addView(status);

        // Labels are stable so an external observer can find each button by its text.
        addButton(column, "Refresh", v -> refresh());
        addButton(column, "Request notification permission", v -> requestRuntime(
                REQUEST_NOTIFICATIONS, Build.VERSION_CODES.TIRAMISU,
                Manifest.permission.POST_NOTIFICATIONS));
        // Foreground location only. Background location is never requested here; the
        // owner may choose it in application settings where Android offers it.
        addButton(column, "Request foreground location permission", v -> requestRuntime(
                REQUEST_FOREGROUND_LOCATION, Build.VERSION_CODES.M,
                Manifest.permission.ACCESS_COARSE_LOCATION,
                Manifest.permission.ACCESS_FINE_LOCATION));
        addButton(column, "Open application settings", v -> openApplicationSettings());
        addButton(column, "Close permission UI", v -> finish());

        ScrollView scroll = new ScrollView(this);
        scroll.setFitsSystemWindows(true);
        scroll.addView(column);
        setContentView(scroll);
    }

    @Override
    protected void onResume() {
        super.onResume();
        refresh();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(requestCode, permissions, results);
        // Show exactly what the platform returned. Empty arrays mean cancelled or interrupted.
        StringBuilder event = new StringBuilder("platform result:");
        if (permissions.length == 0) {
            event.append(" empty (cancelled or interrupted)");
        }
        for (int i = 0; i < permissions.length && i < results.length; i++) {
            event.append(' ').append(shortName(permissions[i])).append('=')
                    .append(describe(results[i]));
        }
        report(event.toString());
    }

    private void addButton(LinearLayout column, String label, View.OnClickListener action) {
        Button button = new Button(this);
        button.setText(label);
        button.setAllCaps(false); // Some themes uppercase labels; keep the exact text.
        button.setOnClickListener(action);
        column.addView(button);
    }

    /** Asks Android to show its own permission UI. The result arrives later. */
    private void requestRuntime(int requestCode, int sinceApi, String... permissions) {
        if (Build.VERSION.SDK_INT < sinceApi) {
            report("not requested: no runtime request before API " + sinceApi);
            return;
        }
        requestPermissions(permissions, requestCode);
    }

    private void openApplicationSettings() {
        Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.fromParts("package", getPackageName(), null));
        try {
            startActivity(intent);
            report("started application details settings");
        } catch (ActivityNotFoundException e) {
            report("application details settings not available");
        }
    }

    private void report(String event) {
        lastEvent = event;
        refresh();
    }

    private void refresh() {
        int uid = Process.myUid();
        StringBuilder text = new StringBuilder()
                .append("package: ").append(getPackageName()).append('\n')
                .append("uid: ").append(uid).append('\n')
                .append("userId (display only): ").append(uid / PER_USER_RANGE).append('\n')
                .append("api level: ").append(Build.VERSION.SDK_INT).append('\n');
        appendState(text, Manifest.permission.POST_NOTIFICATIONS, Build.VERSION_CODES.TIRAMISU);
        appendState(text, Manifest.permission.ACCESS_COARSE_LOCATION, Build.VERSION_CODES.M);
        appendState(text, Manifest.permission.ACCESS_FINE_LOCATION, Build.VERSION_CODES.M);
        appendState(text, Manifest.permission.ACCESS_BACKGROUND_LOCATION, Build.VERSION_CODES.Q);
        text.append("last event: ").append(lastEvent);
        status.setText(text);
    }

    private void appendState(StringBuilder text, String permission, int sinceApi) {
        String state = Build.VERSION.SDK_INT < sinceApi
                ? "not a runtime permission before API " + sinceApi
                : describe(checkSelfPermission(permission));
        text.append(shortName(permission)).append(": ").append(state).append('\n');
    }

    private static String describe(int grantResult) {
        return grantResult == PackageManager.PERMISSION_GRANTED ? "granted" : "denied";
    }

    private static String shortName(String permission) {
        return permission.substring(permission.lastIndexOf('.') + 1);
    }
}
