// SPDX-License-Identifier: Apache-2.0
package android.system;

/** Host model stub of OsConstants: distinct flag bits, and the Linux errno and mode values. */
public final class OsConstants {
    public static final int O_RDONLY = 0;
    public static final int O_WRONLY = 1;
    public static final int O_CREAT = 0x40;
    public static final int O_EXCL = 0x80;
    public static final int O_NONBLOCK = 0x800;
    public static final int O_NOFOLLOW = 0x20000;
    public static final int O_CLOEXEC = 0x80000;
    public static final int EIO = 5;
    public static final int ENOENT = 2;
    public static final int EEXIST = 17;
    public static final int ELOOP = 40;
    static final int S_IFMT = 0xf000;
    static final int S_IFREG = 0x8000;
    static final int S_IFDIR = 0x4000;
    static final int S_IFLNK = 0xa000;

    private OsConstants() {}

    public static boolean S_ISREG(int mode) {
        return (mode & S_IFMT) == S_IFREG;
    }

    public static boolean S_ISDIR(int mode) {
        return (mode & S_IFMT) == S_IFDIR;
    }
}
