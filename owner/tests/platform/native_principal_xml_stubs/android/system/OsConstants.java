// SPDX-License-Identifier: Apache-2.0
// Host facade. Not Android parsing, syscall, permission or integrity qualification.
package android.system;
public final class OsConstants {public static final int O_RDONLY=0,O_CLOEXEC=524288;public static boolean S_ISDIR(int mode){return (mode & 0170000)==0040000;}private OsConstants(){}}
