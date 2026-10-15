// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.notice;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The app's immutable receipt rows in its device encrypted directory. Plain Java over a
 * {@link Disk}, so the host tests run it with a model that loses unsynced writes.
 *
 * <p>One serialized writer. A new row goes to an exclusive temporary file, is synced through its
 * writing descriptor and closed, is renamed to its immutable key, and then the directory is synced.
 * A key that exists is never written again: the writer reads and parses the whole existing row and
 * compares it with the new one. The same request is a repeat, which keeps the first row and its
 * time; anything else is a conflict or a corrupt row, and nothing is written. A failed write, sync
 * or read latches the writer, so this process writes nothing more.
 *
 * <p>A process restart is no crash: the names an earlier process left stay visible whether or not
 * they are durable. So a process's first transaction ensures the directory, which syncs its parent
 * even when the directory exists, and a repeat of a key whose name this process has not made
 * durable syncs the directory before it is accepted. Only then is a row WRITTEN or a REPEAT. A
 * key's bytes were synced before the rename that named it, and a repeat keeps them and their time.
 *
 * <p>Before anything is shown, the activity asks what its request's key already holds. Only an
 * absent key or the same request may be shown; a conflicting, corrupt or unreadable key refuses
 * the request. The question reads and writes nothing else.
 *
 * <p>The listing reads every entry for the provider. It never gives an incomplete row as a row:
 * a temporary is a partial write, and an entry that does not parse as its own key and this app's
 * identity is corrupt. A directory that cannot be listed or read is unreadable, never empty.
 */
public final class ReceiptStore {
    public static final String STORE = "andrix-notice-store-v1";
    public static final int MAX_ENTRIES = 64;

    public enum Outcome { WRITTEN, REPEAT, CONFLICT, CORRUPT, FAILED, LATCHED }

    /** What a request's key holds before a presentation: nothing, the same request, a conflicting
     * row, bytes that are no row of that key, or a store that cannot be read. */
    public enum Existing { ABSENT, SAME, CONFLICT, CORRUPT, UNREADABLE }

    /** The source of the temporaries' nonces: 16 lowercase hexadecimal digits each. */
    public interface Nonces {
        String next();
    }

    private final Disk disk;
    private final Nonces nonces;
    private String failure;
    /** Whether this process has ensured the directory, and so synced its parent. */
    private boolean directoryDurable;
    /** The keys whose names this process made durable by a directory sync after it saw them. */
    private final Set<String> durableKeys = new HashSet<>();

    public ReceiptStore(Disk disk, Nonces nonces) {
        this.disk = disk;
        this.nonces = nonces;
    }

    /** Whether an earlier failure latched the writer, and why. Null when it did not. */
    public synchronized String failure() {
        return failure;
    }

    /** Writes a new row under its key once. Called only by the app's presentation code. */
    public synchronized Outcome record(ReceiptRow row) {
        if (failure != null) return Outcome.LATCHED;
        byte[] data = row.encode();
        String key = row.key();
        try {
            if (!directoryDurable) {
                disk.ensureDirectory();
                directoryDurable = true;
            }
            if (disk.exists(key)) {
                ReceiptRow first = first(key);
                if (first == null) return Outcome.CORRUPT;
                if (!first.sameRequest(row)) return Outcome.CONFLICT;
                if (!durableKeys.contains(key)) {
                    // An earlier process may have renamed the row and died before this sync.
                    disk.syncDirectory();
                    durableKeys.add(key);
                }
                return Outcome.REPEAT;
            }
            String temporary = ReceiptRow.temporaryName(key, nonces.next());
            Disk.Handle handle = disk.create(temporary);
            IOException problem = null;
            try {
                disk.write(handle, data);
                disk.sync(handle);
            } catch (IOException e) {
                problem = e;
            }
            try {
                disk.close(handle);
            } catch (IOException e) {
                if (problem == null) problem = e;
            }
            if (problem != null) throw problem;
            disk.rename(temporary, key);
            disk.syncDirectory();
            durableKeys.add(key);
            return Outcome.WRITTEN;
        } catch (IOException | RuntimeException e) {
            failure = e.getClass().getName();
            return Outcome.FAILED;
        }
    }

    /** What the request's key holds now, for the app of this UID and serial. Reads only. */
    public synchronized Existing existing(NoticeRequest request, int uid, long serial) {
        String key = ReceiptRow.keyOf(request, uid, serial);
        try {
            if (!disk.exists(key)) return Existing.ABSENT;
            ReceiptRow first = first(key);
            if (first == null) return Existing.CORRUPT;
            return first.matches(request, uid, serial) ? Existing.SAME : Existing.CONFLICT;
        } catch (IOException | RuntimeException e) {
            return Existing.UNREADABLE;
        }
    }

    /** The whole first row under a key, or null when its bytes are no row of that key. */
    private ReceiptRow first(String key) throws IOException {
        byte[] existing = disk.read(key, ReceiptRow.MAX_BYTES);
        if (existing == null || existing.length > ReceiptRow.MAX_BYTES) return null;
        ReceiptRow first;
        try {
            first = ReceiptRow.parse(existing);
        } catch (IllegalArgumentException e) {
            return null;
        }
        return first.key().equals(key) ? first : null;
    }

    /** The provider's whole listing of the store, for the app of this UID and serial. */
    public Listing list(int uid, long serial) {
        int user = uid / Forms.PER_USER_RANGE;
        List<String> entries = new ArrayList<>();
        int rows = 0;
        int corrupt = 0;
        int partial = 0;
        String status = "OK";
        try {
            List<String> names = disk.names();
            if (names == null) {
                status = "ABSENT";
            } else if (names.size() > MAX_ENTRIES) {
                status = "OVERFLOW";
            } else {
                List<String> sorted = new ArrayList<>(names);
                Collections.sort(sorted);
                for (String name : sorted) {
                    String line = entry(name, uid, user, serial);
                    entries.add(line);
                    if (line.startsWith("row ")) {
                        rows++;
                    } else if (line.startsWith("partial ")) {
                        partial++;
                    } else {
                        corrupt++;
                    }
                }
            }
        } catch (IOException | RuntimeException e) {
            status = "UNREADABLE";
        }
        if (!"OK".equals(status)) {
            entries.clear();
            rows = corrupt = partial = 0;
        }
        List<String> lines = new ArrayList<>();
        lines.add(STORE + " user=" + user + " serial=" + serial + " uid=" + uid + " status=" + status);
        lines.addAll(entries);
        StringBuilder all = new StringBuilder();
        for (String line : lines) all.append(line).append('\n');
        lines.add("end rows=" + rows + " corrupt=" + corrupt + " partial=" + partial + " listing="
                + Forms.sha256(all.toString()));
        return new Listing(status, lines);
    }

    private String entry(String name, int uid, int user, long serial) throws IOException {
        boolean key = ReceiptRow.isKeyName(name);
        boolean temporary = !key && ReceiptRow.isTemporaryName(name);
        if (!key && !temporary) {
            return "corrupt unknown:" + Forms.hex(name.getBytes(java.nio.charset.StandardCharsets.UTF_8))
                    + " - - - unknown-name";
        }
        byte[] data = disk.read(name, ReceiptRow.MAX_BYTES);
        if (data == null) return "corrupt " + name + " - - - not-regular";
        if (data.length > ReceiptRow.MAX_BYTES) return "corrupt " + name + " - - - oversize";
        String bytes = data.length + " " + Forms.sha256(data) + " " + (data.length == 0 ? "-" : Forms.hex(data));
        if (temporary) return "partial " + name + " " + bytes;
        ReceiptRow row;
        try {
            row = ReceiptRow.parse(data);
        } catch (IllegalArgumentException e) {
            return "corrupt " + name + " " + bytes + " unparseable";
        }
        if (!row.key().equals(name)) return "corrupt " + name + " " + bytes + " key";
        if (row.uid != uid || row.user != user || row.serial != serial) {
            return "corrupt " + name + " " + bytes + " identity";
        }
        return "row " + name + " " + bytes;
    }

    /** One whole listing: its status and its lines, the first a header and the last an end line
     * that counts the entries and digests every line before it. */
    public static final class Listing {
        public final String status;
        public final List<String> lines;

        Listing(String status, List<String> lines) {
            this.status = status;
            this.lines = Collections.unmodifiableList(new ArrayList<>(lines));
        }
    }
}
