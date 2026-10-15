// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.notice;

import java.io.IOException;
import java.util.List;

/**
 * The receipt store's directory: the few file operations its one writer and its readers use. The
 * app implements it with android.system.Os on its device encrypted storage; the host tests with a
 * model that loses whatever was not synced when it crashes.
 */
public interface Disk {
    /** An open file of the writer. */
    interface Handle {}

    /** The names in the store directory, or null when the directory does not exist. Throws when
     * it cannot be listed. */
    List<String> names() throws IOException;

    /** Creates the store directory when it is absent, then syncs its parent in either case: an
     * earlier process may have made the directory and died before that sync, and a process restart
     * keeps the name visible without making it durable. Throws when the path is something other
     * than a directory. */
    void ensureDirectory() throws IOException;

    /** Creates a new file exclusively, without following a link, for writing. Throws when the
     * name exists. */
    Handle create(String name) throws IOException;

    /** Writes all of the bytes at the end of the file. */
    void write(Handle handle, byte[] data) throws IOException;

    /** Syncs the file through its writing descriptor. */
    void sync(Handle handle) throws IOException;

    void close(Handle handle) throws IOException;

    /** Whether a name exists, as a link or anything else, without following it. */
    boolean exists(String name) throws IOException;

    void rename(String from, String to) throws IOException;

    /** Syncs the store directory itself, so that a rename in it is durable, whichever process made
     * it. */
    void syncDirectory() throws IOException;

    /**
     * The bytes of a regular file opened without following a link: at most {@code bound} bytes,
     * or {@code bound + 1} bytes when the file is larger. Null when the name is not a regular
     * file. Throws when it cannot be read.
     */
    byte[] read(String name, int bound) throws IOException;
}
