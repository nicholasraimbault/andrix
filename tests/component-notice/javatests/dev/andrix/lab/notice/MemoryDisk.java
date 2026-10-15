// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.notice;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A host model of the store directory that knows what is durable. File bytes become durable only
 * through a sync of their own descriptor, and names (creations, renames, the directory itself)
 * only through a sync of their directory. A process restart keeps everything visible, durable or
 * not, as a new app process on the same kernel finds it. A crash keeps a chosen part of what was
 * not durable, so that every honest prefix a real loss could leave can be produced. It records
 * every operation in order and can fail any one of them. It models no Android file system and
 * proves no durability.
 */
final class MemoryDisk implements Disk {
    /** What a crash keeps of the bytes and names that were not yet durable. */
    enum Loss { DURABLE_ONLY, HALF_OF_UNSYNCED_BYTES, ALL_WRITTEN }

    private static final class Inode {
        byte[] data = new byte[0];
        byte[] durable = new byte[0];
        boolean regular = true;
    }

    private static final class Open implements Handle {
        final Inode inode;
        boolean closed;

        Open(Inode inode) {
            this.inode = inode;
        }
    }

    private boolean directory;
    private boolean durableDirectory;
    private Map<String, Inode> names = new LinkedHashMap<>();
    private Map<String, Inode> durableNames = new LinkedHashMap<>();
    final List<String> operations = new ArrayList<>();
    private String failOperation;
    private int failOccurrence;
    private int seen;
    boolean failListing;
    boolean failReads;

    /** Makes the n-th later operation of this name, counting from 1, throw. */
    void failAt(String operation, int occurrence) {
        failOperation = operation;
        failOccurrence = occurrence;
        seen = 0;
    }

    private void step(String operation, String detail) throws IOException {
        operations.add(detail == null ? operation : operation + " " + detail);
        if (operation.equals(failOperation) && ++seen == failOccurrence) {
            failOperation = null;
            throw new IOException("injected failure of " + operation);
        }
    }

    @Override
    public List<String> names() throws IOException {
        step("list", null);
        if (failListing) throw new IOException("the directory cannot be listed");
        return directory ? new ArrayList<>(names.keySet()) : null;
    }

    @Override
    public void ensureDirectory() throws IOException {
        if (!directory) {
            step("mkdir", null);
            directory = true;
        }
        step("sync-parent", null);
        durableDirectory = true;
    }

    @Override
    public Handle create(String name) throws IOException {
        step("create", name);
        if (!directory || names.containsKey(name)) throw new IOException("exists or no directory");
        Inode inode = new Inode();
        names.put(name, inode);
        return new Open(inode);
    }

    @Override
    public void write(Handle handle, byte[] data) throws IOException {
        step("write", Integer.toString(data.length));
        Open open = (Open) handle;
        if (open.closed) throw new IOException("closed");
        byte[] grown = Arrays.copyOf(open.inode.data, open.inode.data.length + data.length);
        System.arraycopy(data, 0, grown, open.inode.data.length, data.length);
        open.inode.data = grown;
    }

    @Override
    public void sync(Handle handle) throws IOException {
        step("sync", null);
        Open open = (Open) handle;
        open.inode.durable = open.inode.data.clone();
    }

    @Override
    public void close(Handle handle) throws IOException {
        step("close", null);
        ((Open) handle).closed = true;
    }

    @Override
    public boolean exists(String name) throws IOException {
        step("exists", name);
        return directory && names.containsKey(name);
    }

    @Override
    public void rename(String from, String to) throws IOException {
        step("rename", from + " " + to);
        Inode inode = names.remove(from);
        if (inode == null) throw new IOException("no such file");
        names.put(to, inode);
    }

    @Override
    public void syncDirectory() throws IOException {
        step("sync-directory", null);
        durableNames = new LinkedHashMap<>(names);
    }

    @Override
    public byte[] read(String name, int bound) throws IOException {
        step("read", name);
        if (failReads) throw new IOException("unreadable");
        Inode inode = directory ? names.get(name) : null;
        if (inode == null) throw new IOException("no such file");
        if (!inode.regular) return null;
        return Arrays.copyOf(inode.data, Math.min(inode.data.length, bound + 1));
    }

    /** Puts a file in place directly, durable at once, as an earlier writer or damage left it. */
    void place(String name, byte[] data, boolean regular) {
        directory = durableDirectory = true;
        Inode inode = new Inode();
        inode.data = data.clone();
        inode.durable = data.clone();
        inode.regular = regular;
        names.put(name, inode);
        durableNames.put(name, inode);
    }

    byte[] bytes(String name) {
        Inode inode = names.get(name);
        return inode == null ? null : inode.data.clone();
    }

    List<String> listing() {
        return new ArrayList<>(names.keySet());
    }

    /**
     * A new app process on this same kernel, which is no crash: every name and byte the old
     * process left stays exactly as it was, durable or not, until a later crash. A failure armed
     * for the old process is dropped and the operation log starts again. Its open files need no
     * closing here, since a close makes nothing durable.
     */
    MemoryDisk restart() {
        failOperation = null;
        operations.clear();
        return this;
    }

    /** The state after a crash: what was durable, and the chosen part of what was not. */
    MemoryDisk crash(Loss loss, boolean keepUnsyncedNames) {
        MemoryDisk after = new MemoryDisk();
        after.directory = durableDirectory || (keepUnsyncedNames && directory);
        after.durableDirectory = after.directory;
        Map<String, Inode> kept = keepUnsyncedNames ? names : durableNames;
        Map<Inode, Inode> copies = new LinkedHashMap<>();
        for (Map.Entry<String, Inode> e : kept.entrySet()) {
            Inode old = e.getValue();
            Inode copy = copies.get(old);
            if (copy == null) {
                copy = new Inode();
                copy.regular = old.regular;
                byte[] data = old.durable;
                if (loss == Loss.ALL_WRITTEN) {
                    data = old.data;
                } else if (loss == Loss.HALF_OF_UNSYNCED_BYTES && old.data.length > old.durable.length) {
                    data = Arrays.copyOf(old.data, old.durable.length + (old.data.length - old.durable.length) / 2);
                }
                copy.data = data.clone();
                copy.durable = data.clone();
                copies.put(old, copy);
            }
            if (after.directory) {
                after.names.put(e.getKey(), copy);
                after.durableNames.put(e.getKey(), copy);
            }
        }
        return after;
    }
}
