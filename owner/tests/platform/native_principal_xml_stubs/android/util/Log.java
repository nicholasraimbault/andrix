// SPDX-License-Identifier: Apache-2.0
// Host facade. Not Android parsing, syscall, permission or integrity qualification.
package android.util;public final class Log {public static final int INFO=4,WARN=5,ERROR=6;public static String getStackTraceString(Throwable error){return error.toString();}private Log(){}}
