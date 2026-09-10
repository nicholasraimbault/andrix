// SPDX-License-Identifier: Apache-2.0
package dev.andrix.terminal.protocol;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/** Output framing/replay core for the next terminal frontend, not an authority grant. */
public final class OutputProtocol {
    public static final int HEADER_SIZE = 24;
    public static final int MAX_PAYLOAD = 4096;
    private static final int MAGIC = 0x41545831; // ATX1

    private OutputProtocol() {}

    public static final class Frame {
        public final long session;
        public final long offset;
        private final byte[] payload;

        private Frame(long session, long offset, byte[] payload) {
            this.session = session;
            this.offset = offset;
            this.payload = payload;
        }
        public int length() { return payload.length; }
        public long end() { return offset + payload.length; }
    }

    /** Null means clean EOF between frames. A truncated header/payload is an error. */
    public static Frame read(InputStream input) throws IOException {
        byte[] header = new byte[HEADER_SIZE];
        int first = input.read();
        if (first < 0) return null;
        header[0] = (byte) first;
        readFully(input, header, 1, HEADER_SIZE - 1);
        ByteBuffer b = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN);
        if (b.getInt() != MAGIC) throw new IOException("Unknown terminal frame version");
        int length = b.getInt();
        long session = b.getLong();
        long offset = b.getLong();
        if (length <= 0 || length > MAX_PAYLOAD || session <= 0 || offset < 0
                || offset > Long.MAX_VALUE - length)
            throw new IOException("Invalid terminal output frame bounds");
        // Never allocate based on an unvalidated peer length.
        byte[] payload = new byte[length];
        readFully(input, payload, 0, length);
        return new Frame(session, offset, payload);
    }

    private static void readFully(InputStream input, byte[] bytes, int start, int length)
            throws IOException {
        int end = start + length;
        while (start < end) {
            int count = input.read(bytes, start, end - start);
            if (count < 0) throw new EOFException("Truncated terminal output frame");
            if (count == 0) {
                // A defensive fallback for streams returning zero without progress.
                int next = input.read();
                if (next < 0) throw new EOFException("Truncated terminal output frame");
                bytes[start++] = (byte) next;
            } else start += count;
        }
    }

    @FunctionalInterface
    public interface Sink {
        /** Return only once these exact bytes have been applied to terminal state. */
        void append(byte[] bytes, int offset, int count) throws IOException;
    }

    public enum AttachmentState { NEW_SESSION, CONTINUING, GAP }

    /**
     * Lives with the emulator/parser in the console process, not with a socket or
     * Activity. Call only on the parser's serial thread. The outer adapter must
     * reject callbacks from stale attachment generations before invoking this.
     */
    public static final class Cursor {
        private long session;
        private long next;
        private boolean gap;
        private boolean failed;

        public long session() { return session; }
        public long nextOffset() { return next; }
        public boolean inputAllowed() { return session > 0 && !gap && !failed; }
        public boolean gapObserved() { return gap; }

        public AttachmentState attach(long newSession, long firstOffset) throws IOException {
            if (newSession <= 0 || firstOffset < 0)
                throw new IOException("Invalid terminal attachment offsets");
            boolean changed = newSession != session;
            if (changed) {
                session = newSession;
                next = 0;
                gap = false;
                failed = false;
            }
            if (firstOffset > next) gap = true;
            // Reattaching the same session cannot clear an observed gap/parser failure.
            if (gap || failed) return AttachmentState.GAP;
            return changed ? AttachmentState.NEW_SESSION : AttachmentState.CONTINUING;
        }

        /**
         * Returns the next parsed offset to acknowledge. -1 means a gap/failure:
         * do not feed bytes, enable input or acknowledge an invented screen state.
         * Duplicate/replayed prefixes are skipped without re-running escape actions.
         */
        public long accept(Frame frame, Sink parser) throws IOException {
            if (session == 0 || frame.session != session)
                throw new IOException("Output belongs to a different native session");
            if (gap || failed) return -1;
            if (frame.offset > next) {
                gap = true;
                return -1;
            }
            if (frame.end() <= next) return next;
            int skip = (int) (next - frame.offset); // within this <=4096-byte frame
            try {
                parser.append(frame.payload, skip, frame.length() - skip);
            } catch (IOException | RuntimeException error) {
                // The parser may have partially changed state. Replaying after this
                // exception is not safe; only a genuinely new session resets failure.
                failed = true;
                throw error;
            }
            next = frame.end();
            return next;
        }
    }
}
