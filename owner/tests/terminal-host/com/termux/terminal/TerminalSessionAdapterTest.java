// SPDX-License-Identifier: Apache-2.0
package com.termux.terminal;

import dev.andrix.terminal.protocol.InputQueue;
import junit.framework.TestCase;
import java.io.ByteArrayOutputStream;
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
