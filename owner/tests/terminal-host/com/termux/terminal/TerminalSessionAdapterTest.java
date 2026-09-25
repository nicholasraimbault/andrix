// SPDX-License-Identifier: Apache-2.0
package com.termux.terminal;

import dev.andrix.terminal.protocol.InputQueue;
import junit.framework.TestCase;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public final class TerminalSessionAdapterTest extends TestCase {
    private static final class Host implements TerminalSession.Host {
        final ByteArrayOutputStream sent = new ByteArrayOutputStream();
        int copies, pastes, rows, columns, rejected;
        @Override public void send(TerminalSession s, byte[] b, int o, int n) { sent.write(b, o, n); }
        @Override public void resize(TerminalSession s, int r, int c) { rows=r; columns=c; }
        @Override public void changed(TerminalSession s) { }
        @Override public void copyRequested(TerminalSession s, String text) { copies++; }
        @Override public void pasteRequested(TerminalSession s) { pastes++; }
        @Override public void inputRejected(TerminalSession s) { rejected++; }
    }
    public void testParserDiagnosticsDoNotLogTerminalContents() throws Exception {
        String canary = "audit_private_canary_xx"; // Odd length reaches the unguarded DCS error.
        assertEquals(1, canary.length() % 2);
        StringBuilder encoded = new StringBuilder();
        for (byte value : canary.getBytes(StandardCharsets.UTF_8)) {
            encoded.append(Character.forDigit((value & 0xff) >>> 4, 16));
            encoded.append(Character.forDigit(value & 15, 16));
        }
        String[] cases = {
            "\033P+q" + canary + "\033\\",
            "\033P+qzz" + canary + "x\033\\", // Invalid hex, with an even length.
            "\033P+q" + encoded + "\033\\", // Unknown decoded name, through Log.w.
            "\033]52;c;" + canary + "*\007", // Invalid Base64 clipboard request.
        };
        PrintStream original = System.err;
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        try (PrintStream diagnostic = new PrintStream(captured, true, StandardCharsets.UTF_8)) {
            System.setErr(diagnostic);
            for (String text : cases) {
                byte[] data = text.getBytes(StandardCharsets.UTF_8);
                Host controlHost = new Host();
                TerminalSession control = new TerminalSession(controlHost, 80, 24, 8, 16);
                // Deliberate oracle: the unchanged parser's null-client route really
                // reaches Android Log, represented by the existing host facade.
                control.getEmulator().updateTerminalSessionClient(null);
                captured.reset();
                control.applyOutput(data, 0, data.length);
                assertTrue("Logging negative has no matching positive", captured.toString(
                        StandardCharsets.UTF_8).contains(canary));

                Host host = new Host();
                TerminalSession protectedSession = new TerminalSession(host, 80, 24, 8, 16);
                captured.reset();
                // Fragmented delivery must have the same privacy boundary.
                for (int i = 0; i < data.length; ++i) protectedSession.applyOutput(data, i, 1);
                assertEquals("Parser output reached shared logging", "", captured.toString(
                        StandardCharsets.UTF_8));
                assertEquals(0, host.copies); assertEquals(0, host.pastes);
                byte[] visible = "visible\033[?25l\033[?25h".getBytes(StandardCharsets.UTF_8);
                protectedSession.applyOutput(visible, 0, visible.length);
                assertTrue(TerminalViewportText.capture(protectedSession.getEmulator(), 0)
                        .contains("visible"));
                assertEquals(control.getEmulator().getCursorStyle(),
                        protectedSession.getEmulator().getCursorStyle());
            }
        } finally { System.setErr(original); }
    }

    public void testParserDiagnosticFloodStaysLocal() throws Exception {
        TerminalSession session = new TerminalSession(new Host(), 80, 24, 8, 16);
        byte[] data = "\033P+qodd\033\\".getBytes(StandardCharsets.UTF_8);
        PrintStream original = System.err;
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        try (PrintStream diagnostic = new PrintStream(captured, true, StandardCharsets.UTF_8)) {
            System.setErr(diagnostic);
            for (int i = 0; i < 1000; ++i) session.applyOutput(data, 0, data.length);
            assertEquals("", captured.toString(StandardCharsets.UTF_8));
        } finally { System.setErr(original); }
    }

    public void testEscapeClipboardIsNotUserClipboardAction() {
        Host host = new Host(); TerminalSession s = new TerminalSession(host, 80, 24, 8, 16);
        byte[] copy = "\033]52;c;aGVsbG8=\007".getBytes(StandardCharsets.UTF_8);
        s.applyOutput(copy,0,copy.length);
        assertEquals(0,host.copies); assertEquals(0,host.pastes);
        s.onCopyTextToClipboard("explicit selection"); s.onPasteTextFromClipboard();
        assertEquals(1,host.copies); assertEquals(1,host.pastes);
    }
    public void testBoundedDimensionsAndUtf8Input() {
        Host host = new Host(); TerminalSession s = new TerminalSession(host, 80,24,8,16);
        s.updateSize(5000,9000,8,16);
        assertEquals(400,host.columns); assertEquals(200,host.rows);
        s.updateSize(1,1,8,16);
        assertEquals(10,s.getEmulator().mColumns); assertEquals(2,s.getEmulator().mRows);
        s.writeCodePoint(true,0x3bb);
        assertEquals("\033λ",host.sent.toString(StandardCharsets.UTF_8));
        s.write("a".repeat(16385)); assertEquals(1,host.rejected);
        assertEquals("\033λ",host.sent.toString(StandardCharsets.UTF_8));
        for(int invalid:new int[]{-1,0xd800,0x110000}) {
            try { s.writeCodePoint(false,invalid); fail("bad code point"); }
            catch(IllegalArgumentException expected) { }
        }
    }
    public void testViewportFollowsVisibleRowsNotEntireHistory() {
        Host host = new Host(); TerminalSession s = new TerminalSession(host,10,3,8,16);
        byte[] bytes = "old0\r\nold1\r\nold2\r\nvisible".getBytes(StandardCharsets.UTF_8);
        s.applyOutput(bytes,0,bytes.length);
        assertEquals("old1\nold2\nvisible", TerminalViewportText.capture(s.getEmulator(),0));
        assertEquals("old0\nold1\nold2", TerminalViewportText.capture(s.getEmulator(),-1));
        assertEquals(TerminalViewportText.capture(s.getEmulator(),-1),
                TerminalViewportText.capture(s.getEmulator(),Integer.MIN_VALUE));
        assertEquals(TerminalViewportText.capture(s.getEmulator(),0),
                TerminalViewportText.capture(s.getEmulator(),Integer.MAX_VALUE));
    }
    public void testViewportUnicodeAndExplicitTruncation() {
        Host host = new Host(); TerminalSession s = new TerminalSession(host,400,50,8,16);
        byte[] bytes = ("éλ😃" + "😃".repeat(5000)).getBytes(StandardCharsets.UTF_8);
        for (int i=0;i<bytes.length;i+=4096) s.applyOutput(bytes,i,Math.min(4096,bytes.length-i));
        String text = TerminalViewportText.capture(s.getEmulator(),0);
        assertTrue(text.startsWith("éλ😃"));
        assertTrue(text.endsWith(TerminalViewportText.TRUNCATED));
        assertTrue(text.length()<=TerminalViewportText.MAX_CHARS);
        for (int i=0;i<text.length();i++) {
            char c=text.charAt(i);
            if(Character.isHighSurrogate(c)) {
                assertTrue(i+1<text.length() && Character.isLowSurrogate(text.charAt(++i)));
            } else assertFalse(Character.isLowSurrogate(c));
        }
    }
    public void testViewportBlankAndInvalidDimensions() {
        Host host = new Host(); TerminalSession s = new TerminalSession(host,10,2,8,16);
        assertEquals("\n",TerminalViewportText.capture(s.getEmulator(),0));
        assertEquals("",TerminalViewportText.capture(null,0));
        s.getEmulator().mRows = 201;
        try { TerminalViewportText.capture(s.getEmulator(),0); fail("Unbounded viewport"); }
        catch(IllegalArgumentException expected) { }
    }
    public void testInputQueueHasAtomicBudgetAndClosesBlockedWriter() throws Exception {
        InputQueue q = new InputQueue(); byte[] data = new byte[InputQueue.CAPACITY];
        assertTrue(q.offer(data,0,data.length));
        assertFalse(q.offer(new byte[]{1},0,1)); assertEquals(InputQueue.CAPACITY,q.size());
        assertEquals(InputQueue.CHUNK,q.take().length);
        q.discard(); assertEquals(0,q.size());
        CountDownLatch done = new CountDownLatch(1);
        Thread writer = new Thread(() -> {
            try { if(q.take()==null) done.countDown(); }
            catch(InterruptedException e) { throw new AssertionError(e); }
        });
        writer.start(); q.close();
        assertTrue(done.await(2,TimeUnit.SECONDS)); writer.join(2000);
        assertFalse(q.offer(data,0,1)); assertNull(q.take());
    }
}
