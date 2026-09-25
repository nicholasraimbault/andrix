// SPDX-License-Identifier: Apache-2.0
// Host facade. Not Android parsing, syscall, permission or integrity qualification.
package android.os;
import java.io.*;
public final class FileUtils {
 public static int uncheckedSyncs;
 public static boolean sync(FileOutputStream stream){uncheckedSyncs++;try{stream.getFD().sync();return true;}catch(IOException e){return false;}}
 public static int setPermissions(FileDescriptor fd,int mode,int uid,int gid){return 0;}
 public static long copy(InputStream in,OutputStream out)throws IOException{return in.transferTo(out);}
 private FileUtils(){}
}
