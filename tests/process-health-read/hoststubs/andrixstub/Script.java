// SPDX-License-Identifier: Apache-2.0
// The host stubs' script: a properties file named by -Dandrix.script, and a trace of every call,
// one per line, in the file named by -Dandrix.trace.
package andrixstub;

import android.os.RemoteException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public final class Script {
    private static final Properties VALUES = load();

    private Script() {}

    private static Properties load() {
        Properties values = new Properties();
        String path = System.getProperty("andrix.script");
        if (path == null || path.isEmpty()) return values;
        try (InputStream in = new FileInputStream(path)) {
            values.load(in);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return values;
    }

    public static String value(String key, String otherwise) {
        return VALUES.getProperty(key, otherwise);
    }

    public static boolean flag(String key) {
        return "true".equals(VALUES.getProperty(key));
    }

    // Each row key prefix + 0, 1, ... in order, its value's fields split at tabs.
    public static List<String[]> rows(String prefix) {
        List<String[]> found = new ArrayList<>();
        for (int i = 0; VALUES.getProperty(prefix + i) != null; i++) {
            found.add(VALUES.getProperty(prefix + i).split("\t", -1));
        }
        return found;
    }

    public static String nullable(String field) {
        return field.equals("\u0000null") ? null : field;
    }

    // An answer of the form throw:<class> throws that exception from the call.
    public static void raise(String answer) throws RemoteException {
        if (answer.equals("throw:android.os.RemoteException")) throw new RemoteException();
        if (answer.equals("throw:java.lang.SecurityException")) throw new SecurityException("denied");
        if (answer.equals("throw:java.lang.IllegalArgumentException")) throw new IllegalArgumentException("user");
    }

    public static void trace(String call) {
        String path = System.getProperty("andrix.trace");
        if (path == null || path.isEmpty()) return;
        try (OutputStream out = new FileOutputStream(path, true)) {
            out.write((call + "\n").getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
