// SPDX-License-Identifier: Apache-2.0
// Host facade. Not Android parsing, syscall, permission or integrity qualification.
package android.os;
import java.io.*;
public final class ParcelFileDescriptor implements AutoCloseable {
 private final FileDescriptor fd;private ParcelFileDescriptor(FileDescriptor fd){this.fd=fd;}
 public static ParcelFileDescriptor dup(FileDescriptor fd)throws IOException {return new ParcelFileDescriptor(fd);}
 public FileDescriptor getFileDescriptor(){return fd;}
 public void close(){} // No real duplicated FD; used only by the no-op integrity facade.
}
