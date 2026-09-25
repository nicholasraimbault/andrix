// SPDX-License-Identifier: Apache-2.0
// Host facade. Not Android parsing, syscall, permission or integrity qualification.
package android.system;
public final class ErrnoException extends Exception {
 private static final long serialVersionUID=1L;
 public ErrnoException(String message,Throwable cause){super(message,cause);}
}
