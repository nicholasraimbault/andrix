// SPDX-License-Identifier: Apache-2.0
// Host test stubs only, never part of the helper: the answers the stub services give and the
// trace of every call they receive. A system property andrix.answer.<method> is true, false,
// security (a SecurityException) or remote (a RemoteException); andrix.trace names the file
// each call is appended to.
package andrixstub;

import java.io.FileWriter;
import java.io.IOException;

public final class Answers {
    private Answers() {}

    public static synchronized void trace(String call) {
        String path = System.getProperty("andrix.trace");
        if (path == null) return;
        try (FileWriter out = new FileWriter(path, true)) {
            out.write(call + "\n");
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public static boolean answer(String method, String call) throws android.os.RemoteException {
        trace(call);
        String value = System.getProperty("andrix.answer." + method, "false");
        switch (value) {
            case "true":
                return true;
            case "false":
                return false;
            case "security":
                throw new SecurityException("stub refusal");
            case "remote":
                throw new android.os.RemoteException();
            default:
                throw new IllegalStateException("no stub answer " + value);
        }
    }
}
