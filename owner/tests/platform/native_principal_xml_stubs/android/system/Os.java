// SPDX-License-Identifier: Apache-2.0
// Host facade. Not Android parsing, syscall, permission or integrity qualification.
package android.system;
import java.io.*;import java.nio.channels.FileChannel;import java.nio.file.*;import java.util.IdentityHashMap;
public final class Os {
 private static final IdentityHashMap<FileDescriptor,FileChannel> channels=new IdentityHashMap<>();
 private static final IdentityHashMap<FileDescriptor,Path> paths=new IdentityHashMap<>();
 public static boolean failSync;
 public static int syncCalls, failSyncAt;
 public static void chmod(String path,int mode)throws ErrnoException {
  try{Files.setAttribute(Path.of(path),"unix:mode",mode);}
  catch(IOException e){throw new ErrnoException("chmod",e);}
 }
 public static FileDescriptor open(String path,int flags,int mode)throws ErrnoException {
  try{FileDescriptor key=new FileDescriptor();channels.put(key,FileChannel.open(Path.of(path),StandardOpenOption.READ));paths.put(key,Path.of(path));return key;}
  catch(IOException e){throw new ErrnoException("open",e);}
 }
 public static void fsync(FileDescriptor fd)throws ErrnoException {
  ++syncCalls;
  if(failSync || syncCalls==failSyncAt)throw new ErrnoException("injected directory sync failure",null);
  try{channels.get(fd).force(true);}catch(IOException e){throw new ErrnoException("fsync",e);}
 }
 public static StructStat fstat(FileDescriptor fd)throws ErrnoException {
  try{return new StructStat((Integer)Files.getAttribute(paths.get(fd),"unix:mode"));}
  catch(IOException e){throw new ErrnoException("fstat",e);}
 }
 public static void close(FileDescriptor fd)throws ErrnoException {
  try{paths.remove(fd);channels.remove(fd).close();}catch(IOException e){throw new ErrnoException("close",e);}
 }
 public static boolean allClosed(){return channels.isEmpty();}
 private Os(){}
}
