// SPDX-License-Identifier: Apache-2.0
import dev.andrix.terminal.protocol.OutputProtocol;
import dev.andrix.terminal.protocol.OutputProtocol.Cursor;
import dev.andrix.terminal.protocol.OutputProtocol.Frame;
import dev.andrix.terminal.protocol.OutputProtocol.AttachmentState;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public final class OutputProtocolTest {
    private static byte[] frame(long session, long offset, byte[] payload) {
        return ByteBuffer.allocate(24 + payload.length).putInt(0x41545831)
                .putInt(payload.length).putLong(session).putLong(offset).put(payload).array();
    }
    private static Frame decoded(long session, long offset, String data) throws IOException {
        return OutputProtocol.read(new ByteArrayInputStream(
                frame(session, offset, data.getBytes(StandardCharsets.UTF_8))));
    }
    @FunctionalInterface private interface Action { void run() throws Exception; }
    private static void rejected(Action action) throws Exception {
        try { action.run(); throw new AssertionError("invalid input accepted"); }
        catch (IOException expected) { }
    }
    private static void check(boolean value) {
        if (!value) throw new AssertionError();
    }
    private static void frames() throws Exception {
        byte[] bytes = frame(1, 0, new byte[]{1, 2, 3});
        for (int end = 1; end < bytes.length; end++) {
            final byte[] truncated = Arrays.copyOf(bytes, end);
            rejected(() -> OutputProtocol.read(new ByteArrayInputStream(truncated)));
        }
        check(OutputProtocol.read(new ByteArrayInputStream(new byte[0])) == null);
        for (int length : new int[]{0, -1, 4097, Integer.MAX_VALUE}) {
            byte[] bad = frame(1, 0, new byte[]{1});
            ByteBuffer.wrap(bad).putInt(4, length);
            rejected(() -> OutputProtocol.read(new ByteArrayInputStream(bad)));
        }
        for (long id : new long[]{0, -1, Long.MIN_VALUE})
            rejected(() -> OutputProtocol.read(new ByteArrayInputStream(frame(id, 0, new byte[]{1}))));
        for (long offset : new long[]{-1, Long.MIN_VALUE, Long.MAX_VALUE})
            rejected(() -> OutputProtocol.read(new ByteArrayInputStream(frame(1, offset, new byte[]{1}))));
        byte[] badMagic = bytes.clone(); badMagic[0] = 0;
        rejected(() -> OutputProtocol.read(new ByteArrayInputStream(badMagic)));
        check(OutputProtocol.read(new ByteArrayInputStream(frame(Long.MAX_VALUE,
                Long.MAX_VALUE - 1, new byte[]{0}))).end() == Long.MAX_VALUE);
        // Underlying I/O can split any header/payload boundary and temporarily
        // return zero without causing unbounded allocation or a busy loop.
        InputStream slow = new ByteArrayInputStream(bytes) {
            private boolean zero;
            @Override public synchronized int read(byte[] b, int o, int n) {
                zero = !zero;
                return zero ? 0 : super.read(b, o, Math.min(n, 1));
            }
        };
        Frame f = OutputProtocol.read(slow);
        check(f.length() == 3 && f.session == 1 && f.offset == 0);
        check(OutputProtocol.read(slow) == null);
    }
    private static void replay() throws Exception {
        Cursor c = new Cursor();
        ByteArrayOutputStream parsed = new ByteArrayOutputStream();
        check(!c.inputAllowed());
        check(c.attach(1, 0) == AttachmentState.NEW_SESSION);
        check(c.accept(decoded(1, 0, "abc"), parsed::write) == 3);
        check(c.attach(1, 0) == AttachmentState.CONTINUING);
        check(c.accept(decoded(1, 0, "abc"), parsed::write) == 3);
        check(c.accept(decoded(1, 1, "bcde"), parsed::write) == 5);
        check(parsed.toString(StandardCharsets.UTF_8).equals("abcde"));
        rejected(() -> c.accept(decoded(2, 5, "wrong"), parsed::write));
        check(c.nextOffset() == 5);
        check(c.accept(decoded(1, 8, "gap"), parsed::write) == -1);
        check(c.gapObserved() && !c.inputAllowed() && c.nextOffset() == 5);
        check(c.attach(1, 0) == AttachmentState.GAP); // reconnect never hides the gap
        check(c.accept(decoded(1, 5, "fg"), parsed::write) == -1);
        check(parsed.toString(StandardCharsets.UTF_8).equals("abcde"));
        check(c.attach(2, 3) == AttachmentState.GAP); // new parser lacks the prefix
        check(c.attach(3, 0) == AttachmentState.NEW_SESSION);
        check(c.inputAllowed() && c.nextOffset() == 0);
        rejected(() -> c.accept(decoded(3, 0, "part"), (b, o, n) -> {
            parsed.write(b, o, 1); throw new IOException("parser failed after mutation");
        }));
        check(!c.inputAllowed() && c.nextOffset() == 0);
        check(c.attach(3, 0) == AttachmentState.GAP);
        check(c.attach(4, 0) == AttachmentState.NEW_SESSION);
        try {
            c.accept(decoded(4, 0, "x"), (b, o, n) -> { throw new IllegalArgumentException(); });
            throw new AssertionError();
        } catch (IllegalArgumentException expected) { }
        check(!c.inputAllowed());
        rejected(() -> c.attach(0, 0));
        rejected(() -> c.attach(5, -1));
    }
    public static void main(String[] args) throws Exception {
        frames(); replay();
        byte[] fixture = Files.readAllBytes(Path.of(args[0]));
        Frame f = OutputProtocol.read(new ByteArrayInputStream(fixture));
        check(f.session == 74565 && f.offset == 3 && f.length() == 7);
        Cursor c = new Cursor(); c.attach(74565, 0);
        c.accept(decoded(74565, 0, "abc"), (b, o, n) -> {});
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        check(c.accept(f, out::write) == 10);
        check(Arrays.equals(out.toByteArray(), "\033[31mλ".getBytes(StandardCharsets.UTF_8)));
        System.out.println("PASS: Java framing/replay and C++ wire fixture; Android adapter not yet integrated");
    }
}
