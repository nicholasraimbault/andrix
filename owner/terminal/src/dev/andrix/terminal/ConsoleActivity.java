// SPDX-License-Identifier: Apache-2.0
package dev.andrix.terminal;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.util.Log;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.ViewGroup;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.termux.terminal.TerminalSession;
import com.termux.view.TerminalView;
import com.termux.view.TerminalViewClient;

/** Native Android VT view. Process/session authority remains in andrixd. */
public final class ConsoleActivity extends Activity implements TerminalController.Listener, TerminalViewClient {
    private TerminalController controller;
    private TerminalView terminal;
    private TextView state;
    private Button end, controlKey;
    private boolean resumed, focused, control;

    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        controller = TerminalController.get(getApplicationContext());
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setBackgroundColor(Color.BLACK);
        // Use actual insets rather than a fixed guessed status/navigation-bar height.
        layout.setOnApplyWindowInsetsListener((view, insets) -> {
            android.graphics.Insets bars = insets.getInsets(android.view.WindowInsets.Type.systemBars());
            int keyboard = insets.getInsets(android.view.WindowInsets.Type.ime()).bottom;
            view.setPadding(bars.left, bars.top, bars.right, Math.max(bars.bottom, keyboard));
            return insets;
        });
        state = new TextView(this);
        state.setTextColor(Color.WHITE);
        state.setTextSize(12);
        state.setMinLines(2); state.setMaxLines(2);
        layout.addView(state);
        LinearLayout actions = new LinearLayout(this);
        add(actions, "Attach", controller::attach);
        add(actions, "Detach", controller::detach);
        end = add(actions, "End", controller::endSession);
        layout.addView(actions);
        terminal = new TerminalView(this, null);
        terminal.setTerminalViewClient(this);
        terminal.setIsTerminalViewKeyLoggingEnabled(false);
        terminal.setTextSize(Math.round(14 * getResources().getDisplayMetrics().scaledDensity));
        terminal.setTypeface(Typeface.MONOSPACE);
        terminal.setFilterTouchesWhenObscured(true);
        terminal.setFocusableInTouchMode(true);
        layout.addView(terminal, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        LinearLayout keys = new LinearLayout(this);
        add(keys, "Esc", () -> key(KeyEvent.KEYCODE_ESCAPE));
        controlKey = add(keys, "Ctrl", () -> { control = !control; controlKey.setText(control ? "Ctrl•" : "Ctrl"); });
        add(keys, "Tab", () -> key(KeyEvent.KEYCODE_TAB));
        add(keys, "←", () -> key(KeyEvent.KEYCODE_DPAD_LEFT));
        add(keys, "↓", () -> key(KeyEvent.KEYCODE_DPAD_DOWN));
        add(keys, "↑", () -> key(KeyEvent.KEYCODE_DPAD_UP));
        add(keys, "→", () -> key(KeyEvent.KEYCODE_DPAD_RIGHT));
        add(keys, "Keys", this::keyboard);
        layout.addView(keys);
        setContentView(layout);
        terminal.requestFocus();
        controller.bind(this);
    }

    private Button add(LinearLayout row, String text, Runnable action) {
        Button button = new Button(this);
        button.setText(text); button.setTextSize(12);
        button.setMinWidth(0); button.setMinimumWidth(0); button.setPadding(0, 0, 0, 0);
        button.setFilterTouchesWhenObscured(true);
        button.setOnClickListener(view -> action.run());
        row.addView(button, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        return button;
    }
    private void key(int code) {
        if (terminal.isEnabled()) terminal.handleKeyCode(code, 0);
    }
    private void keyboard() {
        terminal.requestFocus();
        getSystemService(InputMethodManager.class).showSoftInput(terminal, InputMethodManager.SHOW_IMPLICIT);
    }
    @Override public void sessionChanged(TerminalSession next) {
        terminal.attachSession(next);
        terminal.setTerminalCursorBlinkerState(false, false);
    }
    @Override public void screenChanged() { terminal.onScreenUpdated(); }
    @Override public void stateChanged(String message, boolean attached, boolean inputAllowed) {
        state.setText(message);
        terminal.setEnabled(inputAllowed);
        end.setEnabled(attached && resumed && focused);
        if (!inputAllowed) { control = false; controlKey.setText("Ctrl"); }
    }
    @Override protected void onResume() {
        super.onResume(); resumed = true; controller.foreground(this, true, focused);
    }
    @Override protected void onPause() {
        resumed = false; controller.foreground(this, false, focused);
        terminal.setTerminalCursorBlinkerState(false, false);
        super.onPause();
    }
    @Override public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus); focused = hasFocus;
        if (controller != null) controller.foreground(this, resumed, hasFocus);
    }
    @Override protected void onDestroy() {
        controller.unbind(this); super.onDestroy();
    }

    @Override public float onScale(float scale) { return 1; } // fixed, bounded initial cell size
    @Override public void onSingleTapUp(MotionEvent event) { keyboard(); }
    @Override public boolean shouldBackButtonBeMappedToEscape() { return false; }
    @Override public boolean shouldEnforceCharBasedInput() { return false; }
    @Override public boolean shouldUseCtrlSpaceWorkaround() { return false; }
    @Override public boolean isTerminalViewSelected() { return terminal.hasFocus(); }
    @Override public void copyModeChanged(boolean active) { }
    @Override public boolean onKeyDown(int code, KeyEvent event, TerminalSession current) { return false; }
    @Override public boolean onKeyUp(int code, KeyEvent event) { return false; }
    @Override public boolean onLongPress(MotionEvent event) { return false; }
    @Override public boolean readControlKey() { return control; }
    @Override public boolean readAltKey() { return false; }
    @Override public boolean readShiftKey() { return false; }
    @Override public boolean readFnKey() { return false; }
    @Override public boolean onCodePoint(int point, boolean ctrlDown, TerminalSession current) {
        // Ctrl is a one-shot touch modifier. The view has already captured its
        // value for this code point, so clearing the latch does not alter it.
        if (control) { control = false; controlKey.setText("Ctrl"); }
        return false;
    }
    @Override public void onEmulatorSet() { }
    @Override public void logError(String tag, String message) { Log.e(tag, message); }
    @Override public void logWarn(String tag, String message) { Log.w(tag, message); }
    @Override public void logInfo(String tag, String message) { Log.i(tag, message); }
    @Override public void logDebug(String tag, String message) { /* no key/IME logging */ }
    @Override public void logVerbose(String tag, String message) { /* no key/IME logging */ }
    @Override public void logStackTraceWithMessage(String tag, String message, Exception e) { Log.e(tag, message, e); }
    @Override public void logStackTrace(String tag, Exception e) { Log.e(tag, "Terminal view error", e); }
}
