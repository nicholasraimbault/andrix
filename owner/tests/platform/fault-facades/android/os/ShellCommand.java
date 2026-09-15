// SPDX-License-Identifier: Apache-2.0
// Explicit host facade; not Android identity or storage authority.
package android.os;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.io.StringWriter;
public abstract class ShellCommand {
    public static String lastOut = "", lastError = "";
    private final StringWriter out = new StringWriter(), err = new StringWriter();
    private final PrintWriter outWriter = new PrintWriter(out), errWriter = new PrintWriter(err);
    private String[] args; private int index;
    public abstract int onCommand(String command);
    public abstract void onHelp();
    public String getNextArg() { return index < args.length ? args[index++] : null; }
    public PrintWriter getOutPrintWriter() { return outWriter; }
    public PrintWriter getErrPrintWriter() { return errWriter; }
    public int exec(Binder target, FileDescriptor in, FileDescriptor output, FileDescriptor error,
            String[] arguments, ShellCallback callback, ResultReceiver result) {
        args = arguments == null ? new String[0] : arguments; index = args.length == 0 ? 0 : 1;
        int rc = onCommand(args.length == 0 ? null : args[0]);
        outWriter.flush(); errWriter.flush(); lastOut = out.toString(); lastError = err.toString();
        if (result != null) result.send(rc, null);
        return rc;
    }
}
