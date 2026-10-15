// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.principalclosed;

import android.content.Context;
import android.os.Process;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import java.io.File;
import java.io.FileDescriptor;
import java.util.Arrays;
import java.util.Set;

/** No create calls in the read path. ENOENT alone means absent. */
final class StateFiles {
    final File ceRoot, deRoot, ceFiles, deFiles, ceDir, deDir, ce, de, intent, sentinel;
    StateFiles(Context context) throws Exception {
        Context device = context.createDeviceProtectedStorageContext();
        ceRoot = context.getDataDir(); deRoot = device.getDataDir();
        if (ceRoot == null || deRoot == null || !ceRoot.isAbsolute() || !deRoot.isAbsolute()
                || ceRoot.equals(deRoot) || context.isDeviceProtectedStorage()
                || !device.isDeviceProtectedStorage()) throw new IllegalStateException("data roots");
        directory(ceRoot); directory(deRoot);
        ceFiles = new File(ceRoot, "files"); deFiles = new File(deRoot, "files");
        ceDir = new File(ceFiles, "b2-state"); deDir = new File(deFiles, "b2-state");
        ce = new File(ceDir, "canary.bin"); de = new File(deDir, "canary.bin");
        intent = new File(deDir, "setup.intent"); sentinel = new File(deDir, "unexpected-job");
    }
    static boolean exists(File file) throws Exception {
        try { Os.lstat(file.toString()); return true; }
        catch (ErrnoException e) { if (e.errno == OsConstants.ENOENT) return false; throw e; }
    }
    static void directory(File file) throws Exception {
        StructStat st = Os.lstat(file.toString());
        if (!OsConstants.S_ISDIR(st.st_mode) || st.st_uid != Process.myUid()) {
            throw new IllegalStateException("directory type or owner");
        }
    }
    static void sync(File directory) throws Exception {
        FileDescriptor fd = Os.open(directory.toString(), OsConstants.O_RDONLY
                | OsConstants.O_NOFOLLOW | OsConstants.O_CLOEXEC | OsConstants.O_NONBLOCK, 0);
        try {
            if (!OsConstants.S_ISDIR(Os.fstat(fd).st_mode)) {
                throw new IllegalStateException("directory changed type");
            }
            Os.fsync(fd);
        } finally { Os.close(fd); }
    }
    static void make(File directory) throws Exception {
        Os.mkdir(directory.toString(), 0700); // Exclusive, EEXIST is never success.
        sync(directory); sync(directory.getParentFile());
    }
    static void newFile(File file, byte[] data) throws Exception {
        FileDescriptor fd = Os.open(file.toString(), OsConstants.O_WRONLY | OsConstants.O_CREAT
                | OsConstants.O_EXCL | OsConstants.O_NOFOLLOW | OsConstants.O_CLOEXEC, 0600);
        try {
            int offset = 0;
            while (offset < data.length) {
                int n = Os.write(fd, data, offset, data.length - offset);
                if (n <= 0) throw new IllegalStateException("short write");
                offset += n;
            }
            Os.fsync(fd);
        } finally { Os.close(fd); }
        sync(file.getParentFile());
    }
    static byte[] readExact(File file, byte[] expected) throws Exception {
        FileDescriptor fd = Os.open(file.toString(), OsConstants.O_RDONLY
                | OsConstants.O_NOFOLLOW | OsConstants.O_CLOEXEC | OsConstants.O_NONBLOCK, 0);
        try {
            StructStat before = Os.fstat(fd);
            if (!OsConstants.S_ISREG(before.st_mode) || before.st_uid != Process.myUid()
                    || before.st_nlink != 1 || before.st_size != expected.length
                    || expected.length > 4096) throw new IllegalStateException("file metadata");
            byte[] bytes = new byte[expected.length + 1];
            int offset = 0, n;
            while (offset < bytes.length && (n = Os.read(fd, bytes, offset,
                    bytes.length - offset)) > 0) offset += n;
            StructStat after = Os.fstat(fd);
            if (offset != expected.length || after.st_size != before.st_size
                    || after.st_ino != before.st_ino || after.st_mtime != before.st_mtime
                    || after.st_ctime != before.st_ctime
                    || !Arrays.equals(Arrays.copyOf(bytes, offset), expected)) {
                throw new IllegalStateException("file changed or wrong bytes");
            }
            return Arrays.copyOf(bytes, offset);
        } finally { Os.close(fd); }
    }
    void preflight() throws Exception {
        if (exists(ceFiles)) directory(ceFiles);
        if (exists(deFiles)) directory(deFiles);
        if (exists(ceDir) || exists(deDir)) throw new IllegalStateException("partial or old state");
    }
    private static void listing(File dir, Set<String> wanted) throws Exception {
        directory(dir);
        String[] names = dir.list();
        if (names == null || names.length != wanted.size()
                || !new java.util.HashSet<>(Arrays.asList(names)).equals(wanted)) {
            throw new IllegalStateException("unexpected fixture files or callback sentinel");
        }
    }
    void existing() throws Exception {
        directory(ceFiles); directory(deFiles);
        listing(ceDir, Set.of("canary.bin"));
        listing(deDir, Set.of("canary.bin", "setup.intent"));
    }
}
