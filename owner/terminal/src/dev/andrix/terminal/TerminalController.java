// SPDX-License-Identifier: Apache-2.0
package dev.andrix.terminal;

import android.app.KeyguardManager;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Binder;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.os.UserManager;
import android.system.Os;
import android.system.OsConstants;

import com.termux.terminal.TerminalSession;
import dev.andrix.session.Attachment;
import dev.andrix.session.IOwnerSession;
import dev.andrix.terminal.protocol.InputQueue;
import dev.andrix.terminal.protocol.OutputProtocol;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicLong;

/** Process-lifetime terminal state. Activity changes never replace the parser checkpoint. */
final class TerminalController implements TerminalSession.Host {
    interface Listener {
        void sessionChanged(TerminalSession session);
        void screenChanged();
        void stateChanged(String text, boolean attached, boolean inputAllowed);
    }
    private static final Binder PROCESS_LIFETIME = new Binder();
    private static TerminalController instance;
    static synchronized TerminalController get(Context context) {
        if (instance == null) instance = new TerminalController(context.getApplicationContext());
        return instance;
    }

    private static final class Checkpoint {
        final long session, next;
        Checkpoint(long session, long next) { this.session = session; this.next = next; }
    }
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ScheduledExecutorService control = Executors.newSingleThreadScheduledExecutor();
    private final ExecutorService reader = ioExecutor();
    private final ExecutorService writer = ioExecutor();
    private static ExecutorService ioExecutor() {
        // At most one retiring worker and one replacement. Never accumulate FDs/
        // queued sessions if an old Binder or stream operation stalls.
        return new ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(1));
    }
    private final AtomicBoolean attaching = new AtomicBoolean();
    private final AtomicBoolean resizing = new AtomicBoolean();
    private final AtomicBoolean ending = new AtomicBoolean();
    private final AtomicLong resizeVersion = new AtomicLong();
    private final AtomicReference<Checkpoint> checkpoint = new AtomicReference<>(new Checkpoint(0, 0));
    private final OutputProtocol.Cursor cursor = new OutputProtocol.Cursor(); // main thread only
    private final UserManager users;
    private final KeyguardManager keyguard;
    private final PowerManager power;
    private final ClipboardManager clipboard;
    private volatile Listener listener;
    private volatile boolean resumed, focused;
    private volatile long uiEpoch; // main-thread changes cancel in-flight attach intent
    private volatile Connection connection;
    private volatile int rows = 24, columns = 80;
    private TerminalSession session; // main/parser thread only
    private String state = "Detached — unlock and Attach";

    private TerminalController(Context context) {
        users = context.getSystemService(UserManager.class);
        keyguard = context.getSystemService(KeyguardManager.class);
        power = context.getSystemService(PowerManager.class);
        clipboard = context.getSystemService(ClipboardManager.class);
        session = new TerminalSession(this, columns, rows, 8, 16);
        control.scheduleWithFixedDelay(this::heartbeat, 200, 400, TimeUnit.MILLISECONDS);
    }

    private void requireMain() {
        if (Looper.myLooper() != Looper.getMainLooper()) throw new IllegalStateException("Parser thread");
    }
    void bind(Listener target) {
        requireMain();
        if (listener != target) detach();
        listener = target; resumed = false; focused = false;
        target.sessionChanged(session); publish();
    }
    void foreground(Listener target, boolean isResumed, boolean hasFocus) {
        requireMain();
        if (listener != target) return;
        resumed = isResumed; focused = hasFocus;
        if (!isResumed || !hasFocus) detach();
        else publish();
    }
    void unbind(Listener target) {
        requireMain();
        if (listener != target) return;
        resumed = false; focused = false; detach(); listener = null;
    }
    private boolean eligible() {
        return listener != null && resumed && focused && UserHandle.myUserId() == 0
                && users.isUserUnlocked() && !keyguard.isDeviceLocked()
                && !keyguard.isKeyguardLocked() && power.isInteractive();
    }

    void attach() {
        requireMain();
        if (!eligible()) { show("Attach refused: locked or not foreground"); return; }
        if (ending.get() || !attaching.compareAndSet(false, true)) return;
        final long requestEpoch = ++uiEpoch;
        disconnect(connection);
        final Listener target = listener;
        final Checkpoint resume = checkpoint.get();
        final int requestedRows = rows, requestedColumns = columns;
        control.execute(() -> {
            ParcelFileDescriptor fd = null;
            try {
                if (uiEpoch != requestEpoch || listener != target || !eligible())
                    throw new IOException("UI changed");
                IBinder binder = ServiceManager.checkService("andrix.owner.session");
                if (binder == null) throw new IOException("Owner service unavailable");
                IOwnerSession service = IOwnerSession.Stub.asInterface(binder);
                service.registerController(PROCESS_LIFETIME);
                Attachment a = service.attach(requestedRows, requestedColumns, eligible(),
                        users.isUserUnlocked(), resume.session, resume.next);
                fd = a.stream;
                if (fd == null || a.generation <= 0 || a.sessionId <= 0 || a.firstOutputOffset < 0)
                    throw new IOException("Invalid native attachment");
                Connection next = new Connection(service, a, fd); fd = null;
                main.post(() -> finishAttach(requestEpoch, target, next));
            } catch (Exception error) {
                if (fd != null) try { fd.close(); } catch (IOException ignored) { }
                main.post(() -> { attaching.set(false); show("Attach failed: " + error.getMessage()); });
            }
        });
    }

    private void finishAttach(long requestEpoch, Listener target, Connection next) {
        requireMain(); attaching.set(false);
        if (uiEpoch != requestEpoch || listener != target || !eligible()) {
            next.close();
            control.execute(() -> remoteDetach(next));
            return;
        }
        try {
            OutputProtocol.AttachmentState result = cursor.attach(next.session, next.firstOffset);
            if (result == OutputProtocol.AttachmentState.NEW_SESSION) {
                session = new TerminalSession(this, columns, rows, 8, 16);
                if (listener != null) listener.sessionChanged(session);
            }
            checkpoint.set(new Checkpoint(cursor.session(), cursor.nextOffset()));
            connection = next;
            next.inputAllowed = cursor.inputAllowed();
            state = next.inputAllowed ? "Attached — native owner UID7500"
                    : "Output gap: input blocked. End session, then Attach to start fresh.";
            reader.execute(() -> readOutput(next));
            writer.execute(() -> writeInput(next));
            resize(session, rows, columns);
            publish();
        } catch (IOException | RuntimeException error) {
            disconnect(next); control.execute(() -> remoteDetach(next));
            show("Attachment state failed; End/restart required");
        }
    }

    private void heartbeat() {
        Connection current = connection;
        if (current == null) return;
        try {
            if (!current.service.renew(current.generation, eligible(), users.isUserUnlocked())) {
                if (disconnect(current)) show("Detached: lock, focus or lease changed");
            }
        } catch (Exception error) {
            if (disconnect(current)) show("Detached: owner service unavailable");
        }
    }

    private void readOutput(Connection current) {
        try {
            while (connection == current && !current.closed.get()) {
                OutputProtocol.Frame frame = OutputProtocol.read(current.input);
                if (frame == null) break;
                CountDownLatch applied = new CountDownLatch(1);
                long[] ack = {-2};
                main.post(() -> {
                    try {
                        if (connection != current || current.closed.get()) return;
                        ack[0] = cursor.accept(frame, session::applyOutput);
                        checkpoint.set(new Checkpoint(cursor.session(), cursor.nextOffset()));
                        if (ack[0] < 0) {
                            current.inputAllowed = false; current.queue.discard();
                            show("Output gap: input blocked. End session, then Attach to start fresh.");
                        }
                    } catch (IOException | RuntimeException error) {
                        current.inputAllowed = false; current.queue.discard();
                        show("Terminal state failed: input blocked; End/restart required");
                    } finally { applied.countDown(); }
                });
                // Exactly one bounded frame queued on the UI; never silently drop
                // output to keep up, and never enqueue an unbounded series of posts.
                if (!applied.await(5, TimeUnit.SECONDS)) break;
                if (ack[0] >= 0 && connection == current && !current.closed.get()
                        && !current.service.acknowledgeOutput(current.generation, ack[0])) break;
            }
        } catch (Exception ignored) {
            // EOF/revocation wakes readFully. Incomplete frames were never parsed/acked.
        } finally {
            if (disconnect(current)) show("Detached — reopen and Attach to return");
        }
    }

    private void writeInput(Connection current) {
        try {
            for (byte[] data; (data = current.queue.take()) != null;) {
                if (connection != current || !current.inputAllowed || !eligible()) continue;
                if (!current.service.renew(current.generation, eligible(), users.isUserUnlocked())) break;
                if (connection != current || !current.inputAllowed || !eligible()) continue;
                current.output.write(data);
            }
        } catch (Exception ignored) { }
        finally {
            if (disconnect(current)) show("Detached: input stream closed");
        }
    }

    void detach() {
        requireMain(); ++uiEpoch;
        Connection old = connection;
        disconnect(old); // shutdown before any potentially stalled Binder operation
        if (old != null) control.execute(() -> remoteDetach(old));
        state = "Detached — reopen and Attach to return"; publish();
    }
    private void remoteDetach(Connection old) {
        try { old.service.detach(old.generation); } catch (Exception ignored) { }
    }
    void endSession() {
        requireMain();
        Connection current = connection;
        if (current == null || !eligible() || !ending.compareAndSet(false, true)) return;
        // End remains available after a gap; it never depends on healthy input.
        control.execute(() -> {
            boolean requested = false;
            try { current.service.endSession(current.generation); requested = true; }
            catch (Exception error) { show("End failed: " + error.getMessage()); }
            finally {
                disconnect(current); ending.set(false);
                if (requested) show("End requested — Attach again after the service restarts");
            }
        });
    }
    private synchronized boolean disconnect(Connection target) {
        if (target == null) return false;
        boolean active = connection == target;
        if (active) connection = null;
        target.close();
        return active;
    }

    @Override public void send(TerminalSession source, byte[] bytes, int offset, int count) {
        requireMain();
        Connection current = connection;
        if (source != session || current == null || !current.inputAllowed || !eligible()) {
            show("Input refused: Attach while unlocked; gaps require End/restart"); return;
        }
        if (!current.queue.offer(bytes, offset, count)) show("Input queue full; input was not submitted");
    }
    @Override public void inputRejected(TerminalSession source) {
        requireMain();
        if (source == session) show("Input too large; it was not submitted");
    }
    @Override public void resize(TerminalSession source, int newRows, int newColumns) {
        requireMain(); if (source != session) return;
        newRows = TerminalSession.rows(newRows); newColumns = TerminalSession.columns(newColumns);
        boolean changed = newRows != rows || newColumns != columns;
        rows = newRows; columns = newColumns;
        if (changed) resizeVersion.incrementAndGet();
        if (connection == null || !resizing.compareAndSet(false, true)) return;
        control.execute(() -> {
            Connection current = connection;
            long version = resizeVersion.get();
            try {
                if (current != null && eligible()) current.service.resize(current.generation, rows, columns);
            } catch (Exception error) {
                if (disconnect(current)) show("Detached: resize failed");
            } finally {
                resizing.set(false);
                if (version != resizeVersion.get()) main.post(() -> resize(session, rows, columns));
            }
        });
    }
    @Override public void changed(TerminalSession source) {
        requireMain();
        if (source == session && listener != null) listener.screenChanged();
    }
    @Override public void copyRequested(TerminalSession source, String text) {
        requireMain();
        if (source != session || !eligible() || text == null || text.length() > 8192) return;
        clipboard.setPrimaryClip(ClipData.newPlainText("Andrix terminal selection", text));
    }
    @Override public void pasteRequested(TerminalSession source) {
        requireMain();
        Connection current = connection;
        if (source != session || current == null || !current.inputAllowed || !eligible()) return;
        ClipData clip = clipboard.getPrimaryClip();
        if (clip == null || clip.getItemCount() == 0) return;
        // Plain text only: no URI resolution/provider reads or implicit conversion.
        CharSequence text = clip.getItemAt(0).getText();
        if (text != null && text.length() <= 4096) source.getEmulator().paste(text.toString());
    }
    private void show(String text) {
        if (Looper.myLooper() != Looper.getMainLooper()) { main.post(() -> show(text)); return; }
        state = text.length() > 240 ? text.substring(0, 240) : text;
        publish();
    }
    private void publish() {
        requireMain();
        Listener target = listener;
        Connection current = connection;
        if (target != null) target.stateChanged(state, current != null,
                current != null && current.inputAllowed && eligible());
    }

    private static final class Connection {
        final IOwnerSession service;
        final long generation, session, firstOffset;
        final ParcelFileDescriptor stream;
        final InputStream input;
        final OutputStream output;
        final InputQueue queue = new InputQueue();
        final AtomicBoolean closed = new AtomicBoolean();
        volatile boolean inputAllowed;
        Connection(IOwnerSession service, Attachment a, ParcelFileDescriptor fd) throws IOException {
            this.service = service; generation = a.generation; session = a.sessionId;
            firstOffset = a.firstOutputOffset; stream = fd;
            ParcelFileDescriptor read = ParcelFileDescriptor.dup(fd.getFileDescriptor());
            ParcelFileDescriptor write;
            try { write = ParcelFileDescriptor.dup(fd.getFileDescriptor()); }
            catch (IOException error) { read.close(); throw error; }
            input = new ParcelFileDescriptor.AutoCloseInputStream(read);
            output = new ParcelFileDescriptor.AutoCloseOutputStream(write);
        }
        void close() {
            if (!closed.compareAndSet(false, true)) return;
            inputAllowed = false; queue.close();
            try { Os.shutdown(stream.getFileDescriptor(), OsConstants.SHUT_RDWR); } catch (Exception ignored) { }
            try { input.close(); } catch (IOException ignored) { }
            try { output.close(); } catch (IOException ignored) { }
            try { stream.close(); } catch (IOException ignored) { }
        }
    }
}
