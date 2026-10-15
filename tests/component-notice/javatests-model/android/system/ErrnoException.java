// SPDX-License-Identifier: Apache-2.0
package android.system;

import java.io.IOException;

/** Host model stub of ErrnoException. */
public final class ErrnoException extends Exception {
    private static final long serialVersionUID = 1L;
    public final int errno;

    public ErrnoException(String functionName, int errno) {
        super(functionName + " failed: errno " + errno);
        this.errno = errno;
    }

    public IOException rethrowAsIOException() throws IOException {
        throw new IOException(getMessage(), this);
    }
}
