// SPDX-License-Identifier: Apache-2.0
package dev.andrix.terminal.protocol;

import java.util.ArrayDeque;
import java.util.Arrays;

/** Per-attachment input queue. Closure discards unsent bytes and wakes its writer. */
public final class InputQueue {
    public static final int CAPACITY = 16384;
    public static final int CHUNK = 4096;
    private final ArrayDeque<byte[]> queue = new ArrayDeque<>();
    private int size;
    private boolean closed;

    public synchronized boolean offer(byte[] data, int offset, int count) {
        if (closed || count < 0 || offset < 0 || offset > data.length - count
                || count > CAPACITY - size) return false;
        for (int end = offset + count; offset < end;) {
            int next = Math.min(end, offset + CHUNK);
            queue.add(Arrays.copyOfRange(data, offset, next));
            offset = next;
        }
        size += count;
        notifyAll();
        return true;
    }

    public synchronized byte[] take() throws InterruptedException {
        while (!closed && queue.isEmpty()) wait();
        if (closed) return null;
        byte[] data = queue.remove();
        size -= data.length;
        return data;
    }
    public synchronized void discard() { queue.clear(); size = 0; }
    public synchronized void close() { closed = true; discard(); notifyAll(); }
    public synchronized int size() { return size; }
}
