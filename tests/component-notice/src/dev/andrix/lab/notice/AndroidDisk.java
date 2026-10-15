// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.notice;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The receipt store's directory in the app's device encrypted storage, through android.system.Os:
 * exclusive creation without following links, writes and fsync on the writing descriptor, rename,
 * and fsync of the directory, and of its parent whenever the directory is ensured, whether this
 * process made it or found it. Nothing here deletes a file.
 */
final class AndroidDisk implements Disk {
    private final String directory;
    private final String parent;

    AndroidDisk(File directory) {
        this.directory = directory.getPath();
        this.parent = directory.getParent();
    }

    private static final class FileHandle implements Handle {
        final FileDescriptor fd;

        FileHandle(FileDescriptor fd) {
            this.fd = fd;
        }
    }

    private String path(String name) {
        if (name.isEmpty() || name.indexOf('/') >= 0 || ".".equals(name) || "..".equals(name)) {
            throw new IllegalArgumentException("a name in the store");
        }
        return directory + "/" + name;
    }

    private static StructStat lstat(String path) throws IOException {
        try {
            return Os.lstat(path);
        } catch (ErrnoException e) {
            if (e.errno == OsConstants.ENOENT) return null;
            throw e.rethrowAsIOException();
        }
    }

    @Override
    public List<String> names() throws IOException {
        StructStat stat = lstat(directory);
        if (stat == null) return null;
        if (!OsConstants.S_ISDIR(stat.st_mode)) throw new IOException("the store is not a directory");
        String[] names = new File(directory).list();
        if (names == null) throw new IOException("the store cannot be listed");
        return new ArrayList<>(Arrays.asList(names));
    }

    @Override
    public void ensureDirectory() throws IOException {
        StructStat stat = lstat(directory);
        if (stat == null) {
            try {
                Os.mkdir(directory, 0700);
            } catch (ErrnoException e) {
                throw e.rethrowAsIOException();
            }
        } else if (!OsConstants.S_ISDIR(stat.st_mode)) {
            throw new IOException("the store is not a directory");
        }
        // A directory an earlier process made may still lack this sync: a process restart keeps its
        // name visible, not durable.
        sync(parent);
    }

    @Override
    public Handle create(String name) throws IOException {
        try {
            return new FileHandle(Os.open(path(name), OsConstants.O_WRONLY | OsConstants.O_CREAT | OsConstants.O_EXCL
                    | OsConstants.O_NOFOLLOW | OsConstants.O_CLOEXEC, 0600));
        } catch (ErrnoException e) {
            throw e.rethrowAsIOException();
        }
    }

    @Override
    public void write(Handle handle, byte[] data) throws IOException {
        FileDescriptor fd = ((FileHandle) handle).fd;
        int done = 0;
        try {
            while (done < data.length) {
                int wrote = Os.write(fd, data, done, data.length - done);
                if (wrote <= 0) throw new IOException("no progress writing a row");
                done += wrote;
            }
        } catch (ErrnoException e) {
            throw e.rethrowAsIOException();
        }
    }

    @Override
    public void sync(Handle handle) throws IOException {
        try {
            Os.fsync(((FileHandle) handle).fd);
        } catch (ErrnoException e) {
            throw e.rethrowAsIOException();
        }
    }

    @Override
    public void close(Handle handle) throws IOException {
        try {
            Os.close(((FileHandle) handle).fd);
        } catch (ErrnoException e) {
            throw e.rethrowAsIOException();
        }
    }

    @Override
    public boolean exists(String name) throws IOException {
        return lstat(path(name)) != null;
    }

    @Override
    public void rename(String from, String to) throws IOException {
        try {
            Os.rename(path(from), path(to));
        } catch (ErrnoException e) {
            throw e.rethrowAsIOException();
        }
    }

    @Override
    public void syncDirectory() throws IOException {
        sync(directory);
    }

    private static void sync(String directoryPath) throws IOException {
        FileDescriptor fd;
        try {
            fd = Os.open(directoryPath, OsConstants.O_RDONLY | OsConstants.O_CLOEXEC, 0);
        } catch (ErrnoException e) {
            throw e.rethrowAsIOException();
        }
        IOException problem = null;
        try {
            Os.fsync(fd);
        } catch (ErrnoException e) {
            problem = new IOException("directory sync failed", e);
        }
        try {
            Os.close(fd);
        } catch (ErrnoException e) {
            if (problem == null) problem = new IOException("directory close failed", e);
        }
        if (problem != null) throw problem;
    }

    @Override
    public byte[] read(String name, int bound) throws IOException {
        FileDescriptor fd;
        try {
            fd = Os.open(path(name), OsConstants.O_RDONLY | OsConstants.O_NOFOLLOW | OsConstants.O_NONBLOCK
                    | OsConstants.O_CLOEXEC, 0);
        } catch (ErrnoException e) {
            if (e.errno == OsConstants.ELOOP) return null;
            throw e.rethrowAsIOException();
        }
        try {
            StructStat stat = Os.fstat(fd);
            if (!OsConstants.S_ISREG(stat.st_mode)) return null;
            byte[] buffer = new byte[bound + 1];
            int done = 0;
            while (done < buffer.length) {
                int got = Os.read(fd, buffer, done, buffer.length - done);
                if (got <= 0) break;
                done += got;
            }
            return Arrays.copyOf(buffer, done);
        } catch (ErrnoException e) {
            throw e.rethrowAsIOException();
        } finally {
            try {
                Os.close(fd);
            } catch (ErrnoException e) {
                // The bytes were read whole. A failed close of a read only descriptor loses
                // nothing.
            }
        }
    }
}
