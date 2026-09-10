// SPDX-License-Identifier: Apache-2.0
package com.termux.terminal;

/** Bounded text of the displayed rows, not a complete terminal transcript. */
public final class TerminalViewportText {
    public static final int MAX_CHARS = 8192;
    public static final String TRUNCATED = "\n[viewport truncated]";
    private TerminalViewportText() {}

    public static String capture(TerminalEmulator emulator, int requestedTopRow) {
        if (emulator == null) return "";
        if (emulator.mRows < 2 || emulator.mRows > 200
                || emulator.mColumns < 10 || emulator.mColumns > 400)
            throw new IllegalArgumentException("Terminal viewport dimensions");
        TerminalBuffer screen = emulator.getScreen();
        int top = Math.max(-screen.getActiveTranscriptRows(), Math.min(0, requestedTopRow));
        int contentLimit = MAX_CHARS - TRUNCATED.length();
        StringBuilder result = new StringBuilder(Math.min(1024, contentLimit));
        for (int line = 0; line < emulator.mRows; ++line) {
            // Extract at most one bounded row at a time. Do not allocate a full
            // transcript (including combining characters) before truncating it.
            String row = screen.getSelectedText(0, top + line, emulator.mColumns - 1, top + line);
            int available = contentLimit - result.length();
            if (row.length() > available) {
                int cut = available;
                if (cut > 0 && Character.isHighSurrogate(row.charAt(cut - 1))) --cut;
                result.append(row, 0, cut).append(TRUNCATED);
                return result.toString();
            }
            result.append(row);
            if (line + 1 < emulator.mRows) {
                if (result.length() == contentLimit) {
                    result.append(TRUNCATED);
                    return result.toString();
                }
                result.append('\n');
            }
        }
        return result.toString();
    }
}
