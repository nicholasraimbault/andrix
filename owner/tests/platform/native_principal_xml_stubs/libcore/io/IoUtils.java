// SPDX-License-Identifier: Apache-2.0
// Host facade. Not Android parsing, syscall, permission or integrity qualification.
package libcore.io;
public final class IoUtils {public static void closeQuietly(AutoCloseable fd){if(fd!=null)try{fd.close();}catch(Exception ignored){}}private IoUtils(){}}
