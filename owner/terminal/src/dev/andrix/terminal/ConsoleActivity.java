// SPDX-License-Identifier: Apache-2.0
package dev.andrix.terminal;

import android.app.Activity;
import android.app.KeyguardManager;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Binder;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.os.UserManager;
import android.system.Os;
import android.system.OsConstants;
import android.text.InputType;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import dev.andrix.session.Attachment;
import dev.andrix.session.IOwnerSession;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

/** First line-oriented Android console; not a VT emulator or a privileged shell APK. */
public final class ConsoleActivity extends Activity {
    private static final String SERVICE = "andrix.owner.session";
    private static final Binder PROCESS_LIFETIME = new Binder();
    private final ScheduledExecutorService control = Executors.newSingleThreadScheduledExecutor();
    private final ExecutorService reader = Executors.newSingleThreadExecutor();
    private final Object outputLock = new Object();
    private final StringBuilder pendingOutput = new StringBuilder();
    private boolean outputPosted;
    private volatile boolean resumed;
    private volatile boolean focused;
    private volatile boolean destroyed;
    private volatile Connection connection;
    private TextView output;
    private TextView state;
    private EditText command;
    private UserManager users;
    private KeyguardManager keyguard;
    private PowerManager power;

    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        users = getSystemService(UserManager.class);
        keyguard = getSystemService(KeyguardManager.class);
        power = getSystemService(PowerManager.class);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int padding = Math.round(12 * getResources().getDisplayMetrics().density);
        layout.setPadding(padding, padding * 3, padding, padding);
        state = new TextView(this);
        state.setText("Andrix: detached (primary user only)");
        layout.addView(state);
        LinearLayout actions = new LinearLayout(this);
        addButton(actions, "Attach", () -> control.execute(this::attach));
        addButton(actions, "Detach", this::detach);
        addButton(actions, "End session", () -> control.execute(this::endSession));
        layout.addView(actions);
        output = new TextView(this);
        output.setTypeface(Typeface.MONOSPACE);
        output.setTextSize(13);
        output.setTextIsSelectable(true);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(output);
        layout.addView(scroll, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        command = new EditText(this);
        command.setSingleLine(true);
        command.setFilterTouchesWhenObscured(true);
        command.setHint("Command (line-oriented PTY console)");
        command.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        layout.addView(command);
        Button send = new Button(this);
        send.setText("Send");
        send.setFilterTouchesWhenObscured(true);
        send.setOnClickListener(view -> {
            String line = command.getText().toString();
            if (line.getBytes(StandardCharsets.UTF_8).length > 2048) {
                showState("Command too long");
                return;
            }
            command.setText("");
            control.execute(() -> send(line + "\n"));
        });
        layout.addView(send);
        setContentView(layout);
        control.scheduleWithFixedDelay(this::heartbeat, 200, 400, TimeUnit.MILLISECONDS);
    }

    private void addButton(LinearLayout parent, String label, Runnable action) {
        Button button = new Button(this);
        button.setText(label);
        button.setFilterTouchesWhenObscured(true);
        button.setOnClickListener(view -> action.run());
        parent.addView(button, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
    }

    private boolean eligible() {
        // This named/signature-mapped console is the UI policy TCB. Never infer
        // unlock from a writable property, intent extra or a client-supplied UID.
        return !destroyed && resumed && focused && UserHandle.myUserId() == 0
                && users.isUserUnlocked() && !keyguard.isDeviceLocked()
                && !keyguard.isKeyguardLocked() && power.isInteractive();
    }

    private void attach() {
        if (!eligible()) { showState("Attachment refused: locked or not foreground"); return; }
        disconnect(connection, false);
        ParcelFileDescriptor stream = null;
        try {
            IBinder binder = ServiceManager.checkService(SERVICE);
            if (binder == null) { showState("Owner service unavailable (check CE/resource admission)"); return; }
            IOwnerSession service = IOwnerSession.Stub.asInterface(binder);
            service.registerController(PROCESS_LIFETIME);
            Attachment attachment = service.attach(24, 80, eligible(), users.isUserUnlocked());
            stream = attachment.stream;
            if (stream == null || attachment.generation <= 0) throw new IOException("invalid attachment");
            if (!eligible()) {
                service.detach(attachment.generation);
                stream.close();
                return;
            }
            Connection next = new Connection(service, attachment.generation, stream);
            stream = null;
            connection = next;
            reader.execute(() -> readOutput(next));
            showState("Attached: " + service.status());
        } catch (Exception error) {
            showState("Attach failed: " + error.getClass().getSimpleName() + ": " + error.getMessage());
            if (stream != null) try { stream.close(); } catch (IOException ignored) {}
        }
    }

    private void heartbeat() {
        Connection current = connection;
        if (current == null || destroyed) return;
        try {
            boolean unlocked = users.isUserUnlocked();
            if (!current.service.renew(current.generation, eligible(), unlocked)) {
                disconnect(current, true);
                showState("Detached: UI lock/focus/lease changed; session files are preserved");
            }
        } catch (Exception error) {
            disconnect(current, false);
            showState("Detached: owner service or lease unavailable");
        }
    }

    private void send(String text) {
        Connection current = connection;
        if (current == null || !eligible()) { showState("Attach while unlocked before sending input"); return; }
        try {
            if (!current.service.renew(current.generation, eligible(), users.isUserUnlocked())) {
                disconnect(current, true);
                showState("Input refused: expired attachment");
                return;
            }
            current.output.write(text.getBytes(StandardCharsets.UTF_8));
        } catch (Exception error) {
            disconnect(current, false);
            showState("Input failed; attachment closed");
        }
    }

    private void readOutput(Connection current) {
        char[] buffer = new char[4096];
        try {
            int count;
            while (!destroyed && (count = current.input.read(buffer)) >= 0) {
                if (connection != current) break;
                appendOutput(new String(buffer, 0, count));
            }
        } catch (IOException ignored) {
            // Local shutdown and daemon lease expiry both intentionally wake this read.
        } finally {
            disconnect(current, false);
            runOnUiThread(() -> {
                if (!destroyed && connection == null)
                    state.setText("Detached (shell may persist unless explicitly ended or reclaimed)");
            });
        }
    }

    private void detach() {
        Connection current = connection;
        disconnect(current, false); // shutdown immediately, even if control RPC is stalled
        if (current != null && !control.isShutdown()) control.execute(() -> {
            try { current.service.detach(current.generation); } catch (Exception ignored) {}
        });
        showState("Detached; reopen and Attach to return");
    }

    private void endSession() {
        Connection current = connection;
        if (current == null || !eligible()) return;
        try { current.service.endSession(current.generation); }
        catch (Exception error) { showState("End failed: " + error.getMessage()); }
        finally { disconnect(current, false); }
    }

    private synchronized void disconnect(Connection target, boolean remote) {
        if (target == null) return;
        if (connection == target) connection = null;
        target.close();
        if (remote) try { target.service.detach(target.generation); } catch (Exception ignored) {}
    }

    private void showState(String text) {
        runOnUiThread(() -> { if (!destroyed) state.setText(text); });
    }

    private void appendOutput(String text) {
        synchronized (outputLock) {
            pendingOutput.append(text);
            if (pendingOutput.length() > 16384)
                pendingOutput.delete(0, pendingOutput.length() - 16384);
            if (outputPosted) return;
            outputPosted = true;
        }
        runOnUiThread(() -> {
            String next;
            synchronized (outputLock) {
                next = pendingOutput.toString();
                pendingOutput.setLength(0);
                outputPosted = false;
            }
            if (destroyed) return;
            String previous = output.getText().toString();
            String combined = previous + next;
            output.setText(combined.length() > 65536 ? combined.substring(combined.length() - 65536) : combined);
        });
    }

    @Override protected void onResume() { super.onResume(); resumed = true; }
    @Override protected void onPause() { resumed = false; detach(); super.onPause(); }
    @Override public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        focused = hasFocus;
        if (!hasFocus) detach();
    }
    @Override protected void onDestroy() {
        destroyed = true;
        detach();
        control.shutdownNow();
        reader.shutdownNow();
        super.onDestroy();
    }

    private static final class Connection {
        final IOwnerSession service;
        final long generation;
        final ParcelFileDescriptor stream;
        final InputStreamReader input;
        final OutputStream output;
        private boolean closed;
        Connection(IOwnerSession service, long generation, ParcelFileDescriptor stream) throws IOException {
            this.service = service;
            this.generation = generation;
            this.stream = stream;
            ParcelFileDescriptor readFd = ParcelFileDescriptor.dup(stream.getFileDescriptor());
            ParcelFileDescriptor writeFd;
            try {
                writeFd = ParcelFileDescriptor.dup(stream.getFileDescriptor());
            } catch (IOException error) {
                readFd.close();
                throw error;
            }
            input = new InputStreamReader(new ParcelFileDescriptor.AutoCloseInputStream(readFd), StandardCharsets.UTF_8);
            output = new ParcelFileDescriptor.AutoCloseOutputStream(writeFd);
        }
        synchronized void close() {
            if (closed) return;
            closed = true;
            try { Os.shutdown(stream.getFileDescriptor(), OsConstants.SHUT_RDWR); } catch (Exception ignored) {}
            try { input.close(); } catch (IOException ignored) {}
            try { output.close(); } catch (IOException ignored) {}
            try { stream.close(); } catch (IOException ignored) {}
        }
    }
}
