// SPDX-License-Identifier: Apache-2.0
package com.termux.terminal;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Andrix adapter for the unmodified terminal view API. This is NOT Termux's JNI
 * session: it owns no process, PTY master, UID, environment or native entry point.
 * All methods run on the console's main/parser thread.
 */
public final class TerminalSession {
    public interface Host {
        void send(TerminalSession source, byte[] bytes, int offset, int count);
        void resize(TerminalSession source, int rows, int columns);
        void changed(TerminalSession source);
        void copyRequested(TerminalSession source, String text);
        void pasteRequested(TerminalSession source);
        void inputRejected(TerminalSession source);
    }

    private final Host host;
    private final TerminalEmulator emulator;

    public TerminalSession(Host host, int columns, int rows, int cellWidth, int cellHeight) {
        this.host = host;
        // Only this private output object receives escape-triggered operations.
        // The public clipboard methods below are reserved for explicit view actions.
        TerminalOutput output = new TerminalOutput() {
            @Override public void write(byte[] data, int offset, int count) {
                host.send(TerminalSession.this, data, offset, count);
            }
            @Override public void titleChanged(String oldTitle, String newTitle) {
                host.changed(TerminalSession.this);
            }
            @Override public void onCopyTextToClipboard(String text) { /* no automatic OSC52 */ }
            @Override public void onPasteTextFromClipboard() { /* no automatic clipboard read */ }
            @Override public void onBell() { /* no automatic audio/vibration authority */ }
            @Override public void onColorsChanged() { host.changed(TerminalSession.this); }
        };
        emulator = new TerminalEmulator(output, columns(columns), rows(rows),
                Math.max(1, cellWidth), Math.max(1, cellHeight), 512, null);
    }

    public static int columns(int value) { return Math.max(10, Math.min(400, value)); }
    public static int rows(int value) { return Math.max(2, Math.min(200, value)); }
    public TerminalEmulator getEmulator() { return emulator; }
    public String getTitle() { return emulator.getTitle(); }

    public void updateSize(int columns, int rows, int cellWidth, int cellHeight) {
        columns = columns(columns); rows = rows(rows);
        if (columns != emulator.mColumns || rows != emulator.mRows)
            emulator.resize(columns, rows, Math.max(1, cellWidth), Math.max(1, cellHeight));
        host.resize(this, rows, columns);
    }

    public void applyOutput(byte[] bytes, int offset, int count) {
        if (count < 0 || count > 4096 || offset < 0 || offset > bytes.length - count)
            throw new IllegalArgumentException("Output frame bounds");
        // The parser has its own incremental UTF-8 state. Never decode a transport
        // fragment independently or retain an InputStreamReader across sockets.
        emulator.append(Arrays.copyOfRange(bytes, offset, offset + count), count);
        host.changed(this);
    }

    public void write(String text) {
        if (text == null) return;
        if (text.length() > 16384) { host.inputRejected(this); return; }
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        host.send(this, bytes, 0, bytes.length);
    }

    public void writeCodePoint(boolean prependEscape, int codePoint) {
        if (!Character.isValidCodePoint(codePoint) || codePoint >= 0xd800 && codePoint <= 0xdfff)
            throw new IllegalArgumentException("Invalid Unicode code point");
        write((prependEscape ? "\033" : "") + new String(Character.toChars(codePoint)));
    }

    // Called by the view's user-initiated selection actions, never by the parser.
    public void onCopyTextToClipboard(String text) { host.copyRequested(this, text); }
    public void onPasteTextFromClipboard() { host.pasteRequested(this); }
}
