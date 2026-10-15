// SPDX-License-Identifier: Apache-2.0
package android.system;

import java.io.FileDescriptor;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Host model stub of android.system.Os over host files: the calls the receipt store's disk makes,
 * recorded with their flags. fsync forces the file channel; a directory's fsync is recorded only.
 * It models the call sequence, not Android's file system or its durability.
 */
public final class Os {
    public static final List<String> CALLS = new ArrayList<>();
    private static final Map<FileDescriptor, Object[]> OPEN = new IdentityHashMap<>();

    private Os() {}

    static String flags(int flags) {
        StringBuilder out = new StringBuilder((flags & OsConstants.O_WRONLY) != 0 ? "WRONLY" : "RDONLY");
        String[] names = {"CREAT", "EXCL", "NONBLOCK", "NOFOLLOW", "CLOEXEC"};
        int[] bits = {OsConstants.O_CREAT, OsConstants.O_EXCL, OsConstants.O_NONBLOCK, OsConstants.O_NOFOLLOW,
            OsConstants.O_CLOEXEC};
        for (int i = 0; i < bits.length; i++) if ((flags & bits[i]) != 0) out.append('|').append(names[i]);
        return out.toString();
    }

    private static ErrnoException errno(String call, int errno) {
        return new ErrnoException(call, errno);
    }

    public static StructStat lstat(String path) throws ErrnoException {
        CALLS.add("lstat " + path);
        Path p = Paths.get(path);
        try {
            if (Files.isSymbolicLink(p)) return new StructStat(OsConstants.S_IFLNK, 0);
            if (!Files.exists(p, LinkOption.NOFOLLOW_LINKS)) throw errno("lstat", OsConstants.ENOENT);
            if (Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS)) return new StructStat(OsConstants.S_IFDIR, 0);
            return new StructStat(OsConstants.S_IFREG, Files.size(p));
        } catch (IOException e) {
            throw errno("lstat", OsConstants.EIO);
        }
    }

    public static void mkdir(String path, int mode) throws ErrnoException {
        CALLS.add("mkdir " + path + " " + Integer.toOctalString(mode));
        try {
            Files.createDirectory(Paths.get(path));
        } catch (FileAlreadyExistsException e) {
            throw errno("mkdir", OsConstants.EEXIST);
        } catch (IOException e) {
            throw errno("mkdir", OsConstants.EIO);
        }
    }

    public static FileDescriptor open(String path, int flags, int mode) throws ErrnoException {
        CALLS.add("open " + path + " " + flags(flags) + " " + Integer.toOctalString(mode));
        Path p = Paths.get(path);
        if ((flags & OsConstants.O_NOFOLLOW) != 0 && Files.isSymbolicLink(p)) throw errno("open", OsConstants.ELOOP);
        FileDescriptor fd = new FileDescriptor();
        try {
            if (Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS) && (flags & OsConstants.O_WRONLY) == 0) {
                OPEN.put(fd, new Object[] {path, null});
                return fd;
            }
            Set<OpenOption> options = new HashSet<>();
            if ((flags & OsConstants.O_WRONLY) != 0) {
                options.add(StandardOpenOption.WRITE);
                if ((flags & OsConstants.O_EXCL) != 0) options.add(StandardOpenOption.CREATE_NEW);
                else if ((flags & OsConstants.O_CREAT) != 0) options.add(StandardOpenOption.CREATE);
            } else {
                options.add(StandardOpenOption.READ);
            }
            if ((flags & OsConstants.O_NOFOLLOW) != 0) options.add(LinkOption.NOFOLLOW_LINKS);
            OPEN.put(fd, new Object[] {path, FileChannel.open(p, options)});
            return fd;
        } catch (FileAlreadyExistsException e) {
            throw errno("open", OsConstants.EEXIST);
        } catch (NoSuchFileException e) {
            throw errno("open", OsConstants.ENOENT);
        } catch (IOException e) {
            throw errno("open", OsConstants.EIO);
        }
    }

    private static Object[] handle(FileDescriptor fd, String call) throws ErrnoException {
        Object[] open = OPEN.get(fd);
        if (open == null) throw errno(call, 9);
        return open;
    }

    public static int write(FileDescriptor fd, byte[] bytes, int offset, int count) throws ErrnoException {
        Object[] open = handle(fd, "write");
        CALLS.add("write " + open[0] + " " + count);
        try {
            return ((FileChannel) open[1]).write(ByteBuffer.wrap(bytes, offset, count));
        } catch (IOException e) {
            throw errno("write", OsConstants.EIO);
        }
    }

    public static int read(FileDescriptor fd, byte[] bytes, int offset, int count) throws ErrnoException {
        Object[] open = handle(fd, "read");
        try {
            int got = ((FileChannel) open[1]).read(ByteBuffer.wrap(bytes, offset, count));
            return got < 0 ? 0 : got;
        } catch (IOException e) {
            throw errno("read", OsConstants.EIO);
        }
    }

    public static StructStat fstat(FileDescriptor fd) throws ErrnoException {
        Object[] open = handle(fd, "fstat");
        try {
            if (open[1] == null) return new StructStat(OsConstants.S_IFDIR, 0);
            return new StructStat(OsConstants.S_IFREG, ((FileChannel) open[1]).size());
        } catch (IOException e) {
            throw errno("fstat", OsConstants.EIO);
        }
    }

    public static void fsync(FileDescriptor fd) throws ErrnoException {
        Object[] open = handle(fd, "fsync");
        CALLS.add("fsync " + open[0]);
        try {
            if (open[1] != null) ((FileChannel) open[1]).force(true);
        } catch (IOException e) {
            throw errno("fsync", OsConstants.EIO);
        }
    }

    public static void close(FileDescriptor fd) throws ErrnoException {
        Object[] open = OPEN.remove(fd);
        if (open == null) throw errno("close", 9);
        CALLS.add("close " + open[0]);
        try {
            if (open[1] != null) ((FileChannel) open[1]).close();
        } catch (IOException e) {
            throw errno("close", OsConstants.EIO);
        }
    }

    public static void rename(String from, String to) throws ErrnoException {
        CALLS.add("rename " + from + " " + to);
        try {
            Files.move(Paths.get(from), Paths.get(to), StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw errno("rename", OsConstants.EIO);
        }
    }
}
