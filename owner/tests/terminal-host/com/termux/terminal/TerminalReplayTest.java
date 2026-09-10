// SPDX-License-Identifier: Apache-2.0
package com.termux.terminal;

import dev.andrix.terminal.protocol.OutputProtocol;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Run the real pinned parser behind the new portable output cursor. */
public final class TerminalReplayTest extends TerminalTestCase {
    private static OutputProtocol.Frame frame(long offset, byte[] bytes) throws Exception {
        byte[] wire = ByteBuffer.allocate(24 + bytes.length).putInt(0x41545831)
                .putInt(bytes.length).putLong(7).putLong(offset).put(bytes).array();
        return OutputProtocol.read(new ByteArrayInputStream(wire));
    }
    private void append(byte[] bytes, int offset, int size) {
        mTerminal.append(Arrays.copyOfRange(bytes, offset, offset + size), size);
    }
    public void testSplitUtf8AndEscapeSequencesWithReplayedFrames() throws Exception {
        withTerminalSized(8, 3);
        byte[] data = "a\r\n\033[31mλ\033[0m".getBytes(StandardCharsets.UTF_8);
        OutputProtocol.Cursor cursor = new OutputProtocol.Cursor();
        cursor.attach(7, 0);
        for (int i = 0; i < data.length; ++i) {
            OutputProtocol.Frame f = frame(i, new byte[]{data[i]});
            assertEquals(i + 1, cursor.accept(f, this::append));
            // A socket replacement can replay bytes already parsed but whose ACK
            // did not arrive. It must not repeat a UTF-8 byte or escape action.
            cursor.attach(7, i);
            assertEquals(i + 1, cursor.accept(f, this::append));
        }
        assertLinesAre("a       ", "λ       ", "        ");
        assertCursorAt(1, 1);
    }
    public void testGapDoesNotFeedAnInventedScreen() throws Exception {
        withTerminalSized(8, 3);
        OutputProtocol.Cursor cursor = new OutputProtocol.Cursor(); cursor.attach(7, 0);
        cursor.accept(frame(0, "safe".getBytes(StandardCharsets.UTF_8)), this::append);
        assertEquals(-1, cursor.accept(frame(20, "corrupt".getBytes(StandardCharsets.UTF_8)), this::append));
        assertFalse(cursor.inputAllowed());
        assertLinesAre("safe    ", "        ", "        ");
    }
    public void testDuplicateTitleEscapeDoesNotRepeatCallback() throws Exception {
        withTerminalSized(8, 3);
        byte[] title = "\033]0;owner\007".getBytes(StandardCharsets.UTF_8);
        OutputProtocol.Cursor cursor = new OutputProtocol.Cursor(); cursor.attach(7, 0);
        OutputProtocol.Frame f = frame(0, title);
        cursor.accept(f, this::append); cursor.accept(f, this::append);
        assertEquals(1, mOutput.titleChanges.size());
        assertEquals("owner", mTerminal.getTitle());
    }
}
