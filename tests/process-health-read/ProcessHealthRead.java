// SPDX-License-Identifier: Apache-2.0
// A fixed read only probe for a disposable Andrix test guest. Run as the shell user with
// CLASSPATH=<this jar> app_process /system/bin ProcessHealthRead <user>
// It makes two reads of the activity manager through its own Binder proxy and nothing else:
// SystemUI's process exit history for one user, getHistoricalProcessExitReasons with no PID and no
// count filter, and the whole list of processes now in an error state, getProcessesInErrorState.
// It samples the elapsed time since boot and the wall clock right before and right after each
// call, and prints every row of each reply with its numeric fields, or why the read has none. It
// has no path that kills, crashes, stops or restarts a process, clears or writes the exit history,
// sets a process state summary, or opens a trace file or a tombstone.
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public final class ProcessHealthRead {
    private static final String HEADER = "andrix-process-health-read-v1";
    private static final String PACKAGE = "com.android.systemui";
    private static final String CAPABILITIES = "history,current-errors";
    // Context.ACTIVITY_SERVICE.
    private static final String SERVICE = "activity";
    private static final String MANAGER = "android.app.IActivityManager";
    private static final String SLICE = "android.content.pm.ParceledListSlice";
    private static final String EXIT_INFO = "android.app.ApplicationExitInfo";
    private static final String ERROR_INFO = "android.app.ActivityManager$ProcessErrorStateInfo";
    // UserHandle.MAX_SECONDARY_USER_ID.
    private static final int MAX_USER = 21473;
    // The most rows of one read printed whole; more is an overflow, never a list cut short.
    private static final int MAX_ROWS = 64;
    // A longer process name is an overflow; a diagnostic string is cut to this, with its length.
    private static final int MAX_TEXT = 256;
    private static final String SAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:";
    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private final StringBuilder out = new StringBuilder();
    private int lines;
    private Method clock;

    private ProcessHealthRead() {}

    public static void main(String[] args) {
        ProcessHealthRead read = new ProcessHealthRead();
        int code = read.run(args);
        System.out.print(read.out.toString());
        System.out.flush();
        System.exit(code);
    }

    private int run(String[] args) {
        int user = args.length == 1 ? user(args[0]) : -1;
        line(HEADER);
        if (user < 0) return end("error=arguments", 2);
        try {
            clock = Class.forName("android.os.SystemClock").getMethod("elapsedRealtime");
            if (clock.getReturnType() != long.class) return end("error=clock", 3);
            sample();
        } catch (ReflectiveOperationException | RuntimeException e) {
            return end("error=clock", 3);
        }
        line("user=" + user);
        line("package=" + PACKAGE);
        line("capabilities=" + CAPABILITIES);
        Object manager = null;
        String problem = null;
        try {
            Class<?> services = Class.forName("android.os.ServiceManager");
            Object binder = services.getMethod("getService", String.class).invoke(null, SERVICE);
            if (binder == null) {
                problem = "UNAVAILABLE reason=service-absent";
            } else {
                Class<?> ibinder = Class.forName("android.os.IBinder");
                manager = Class.forName(MANAGER + "$Stub").getMethod("asInterface", ibinder).invoke(null, binder);
                if (manager == null) problem = "UNAVAILABLE reason=service-absent";
            }
        } catch (InvocationTargetException e) {
            problem = error(e.getCause());
        } catch (ReflectiveOperationException | RuntimeException e) {
            problem = error(e);
        }
        boolean complete;
        try {
            boolean history = history(manager, problem, user);
            boolean errors = errors(manager, problem);
            complete = history && errors;
        } catch (IllegalStateException e) {
            return end("error=clock", 3);
        }
        line("status=" + (complete ? "complete" : "unavailable"));
        return end(null, complete ? 0 : 5);
    }

    // The exit history of SystemUI for the user: every row the reply holds, or why there are none.
    private boolean history(Object manager, String problem, int user) {
        String failure = problem;
        Method call = null;
        if (failure == null) {
            try {
                call = Class.forName(MANAGER).getMethod("getHistoricalProcessExitReasons", String.class, int.class,
                        int.class, int.class);
                if (!call.getReturnType().getName().equals(SLICE)) failure = "ERROR reason=not-a-list-slice";
            } catch (ReflectiveOperationException | RuntimeException e) {
                failure = error(e);
            }
        }
        Object reply = null;
        long[] before = sample();
        if (failure == null) {
            try {
                reply = call.invoke(manager, PACKAGE, 0, 0, user);
            } catch (InvocationTargetException e) {
                failure = error(e.getCause());
            } catch (ReflectiveOperationException | RuntimeException e) {
                failure = error(e);
            }
        }
        long[] after = sample();
        List<String> rows = new ArrayList<>();
        if (failure == null) {
            try {
                Object list = reply == null ? null : Class.forName(SLICE).getMethod("getList").invoke(reply);
                if (!(list instanceof List)) {
                    failure = "ERROR reason=not-a-list";
                } else if (((List<?>) list).size() > MAX_ROWS) {
                    failure = "ERROR reason=overflow";
                } else {
                    List<?> items = (List<?>) list;
                    for (int i = 0; i < items.size() && failure == null; i++) {
                        failure = exitRow(i, items.get(i), rows);
                    }
                }
            } catch (InvocationTargetException e) {
                failure = error(e.getCause());
            } catch (ReflectiveOperationException | RuntimeException e) {
                failure = error(e);
            }
        }
        line("history sample=before elapsed=" + before[0] + " wall=" + before[1]);
        if (failure == null) {
            line("history status=OK count=" + rows.size());
            for (String row : rows) line(row);
        } else {
            line("history status=" + failure);
        }
        line("history sample=after elapsed=" + after[0] + " wall=" + after[1]);
        return failure == null;
    }

    private String exitRow(int index, Object info, List<String> rows) throws ReflectiveOperationException {
        if (info == null || !info.getClass().getName().equals(EXIT_INFO)) return "ERROR reason=not-an-exit-info";
        Object process = get(info, "getProcessName");
        if (process != null && (!(process instanceof String) || ((String) process).length() > MAX_TEXT)) {
            return "ERROR reason=overflow";
        }
        Object handle = get(info, "getUserHandle");
        Object userId = handle.getClass().getMethod("getIdentifier").invoke(handle);
        rows.add("history row=" + index + " timestamp=" + (Long) get(info, "getTimestamp")
                + " pid=" + (Integer) get(info, "getPid") + " real-uid=" + (Integer) get(info, "getRealUid")
                + " package-uid=" + (Integer) get(info, "getPackageUid")
                + " defining-uid=" + (Integer) get(info, "getDefiningUid") + " user=" + (Integer) userId
                + " process=" + text((String) process) + " reason=" + (Integer) get(info, "getReason")
                + " subreason=" + (Integer) get(info, "getSubReason") + " status=" + (Integer) get(info, "getStatus"));
        return null;
    }

    // The whole list of processes in an error state. Android answers null when there are none.
    private boolean errors(Object manager, String problem) {
        String failure = problem;
        Method call = null;
        if (failure == null) {
            try {
                call = Class.forName(MANAGER).getMethod("getProcessesInErrorState");
                if (call.getReturnType() != List.class) failure = "ERROR reason=not-a-list";
            } catch (ReflectiveOperationException | RuntimeException e) {
                failure = error(e);
            }
        }
        Object reply = null;
        long[] before = sample();
        if (failure == null) {
            try {
                reply = call.invoke(manager);
            } catch (InvocationTargetException e) {
                failure = error(e.getCause());
            } catch (ReflectiveOperationException | RuntimeException e) {
                failure = error(e);
            }
        }
        long[] after = sample();
        List<String> rows = new ArrayList<>();
        if (failure == null && reply != null) {
            try {
                if (!(reply instanceof List)) {
                    failure = "ERROR reason=not-a-list";
                } else if (((List<?>) reply).size() > MAX_ROWS) {
                    failure = "ERROR reason=overflow";
                } else {
                    List<?> items = (List<?>) reply;
                    for (int i = 0; i < items.size() && failure == null; i++) {
                        failure = errorRow(i, items.get(i), rows);
                    }
                }
            } catch (ReflectiveOperationException | RuntimeException e) {
                failure = error(e);
            }
        }
        line("current-errors sample=before elapsed=" + before[0] + " wall=" + before[1]);
        if (failure == null) {
            line("current-errors status=OK count=" + rows.size() + " returned=" + (reply == null ? "null" : "list"));
            for (String row : rows) line(row);
        } else {
            line("current-errors status=" + failure);
        }
        line("current-errors sample=after elapsed=" + after[0] + " wall=" + after[1]);
        return failure == null;
    }

    private String errorRow(int index, Object info, List<String> rows) throws ReflectiveOperationException {
        if (info == null || !info.getClass().getName().equals(ERROR_INFO)) return "ERROR reason=not-an-error-state";
        Class<?> type = info.getClass();
        Object process = type.getField("processName").get(info);
        if (process != null && (!(process instanceof String) || ((String) process).length() > MAX_TEXT)) {
            return "ERROR reason=overflow";
        }
        rows.add("current-errors entry=" + index + " condition=" + type.getField("condition").getInt(info)
                + " pid=" + type.getField("pid").getInt(info) + " uid=" + type.getField("uid").getInt(info)
                + " process=" + text((String) process) + bounded("tag", type.getField("tag").get(info))
                + bounded("short", type.getField("shortMsg").get(info))
                + bounded("long", type.getField("longMsg").get(info))
                + bounded("stack", type.getField("stackTrace").get(info)));
        return null;
    }

    private static Object get(Object target, String method) throws ReflectiveOperationException {
        return target.getClass().getMethod(method).invoke(target);
    }

    // A diagnostic string cut to MAX_TEXT, never inside a surrogate pair, with its whole length.
    private static String bounded(String name, Object value) {
        if (value == null) return " " + name + "=- " + name + "-length=-1";
        String whole = (String) value;
        int end = Math.min(whole.length(), MAX_TEXT);
        if (end < whole.length() && Character.isHighSurrogate(whole.charAt(end - 1))) end--;
        return " " + name + "=" + text(whole.substring(0, end)) + " " + name + "-length=" + whole.length();
    }

    // A string as one token: its UTF-8 bytes, a safe byte as itself, others as %XX; null as -.
    private static String text(String value) {
        if (value == null) return "-";
        StringBuilder b = new StringBuilder();
        for (byte x : value.getBytes(StandardCharsets.UTF_8)) {
            int c = x & 0xff;
            if (c < 0x80 && SAFE.indexOf(c) >= 0) {
                b.append((char) c);
            } else {
                b.append('%').append(HEX[c >> 4]).append(HEX[c & 15]);
            }
        }
        return b.toString();
    }

    private static String error(Throwable e) {
        return "ERROR reason=" + (e == null ? "unknown" : e.getClass().getName());
    }

    // The elapsed time since boot and the wall clock, in milliseconds, read one after the other.
    private long[] sample() {
        try {
            long elapsed = (Long) clock.invoke(null);
            return new long[] {elapsed, System.currentTimeMillis()};
        } catch (ReflectiveOperationException | RuntimeException e) {
            throw new IllegalStateException(e);
        }
    }

    // A decimal user ID without sign or leading zero, at most MAX_USER, or -1.
    private static int user(String text) {
        if (!text.matches("0|[1-9][0-9]{0,4}")) return -1;
        int value = Integer.parseInt(text);
        return value <= MAX_USER ? value : -1;
    }

    private void line(String text) {
        out.append(text).append('\n');
        lines++;
    }

    // The end marker: the count of the lines before it and the SHA-256 of their bytes.
    private int end(String error, int code) {
        if (error != null) line(error);
        String digest;
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(out.toString().getBytes(StandardCharsets.UTF_8));
            StringBuilder b = new StringBuilder();
            for (byte x : hash) b.append(Character.forDigit((x >> 4) & 15, 16)).append(Character.forDigit(x & 15, 16));
            digest = b.toString();
        } catch (NoSuchAlgorithmException e) {
            digest = "unavailable";
        }
        out.append("end=").append(HEADER).append(" lines=").append(lines).append(" sha256=").append(digest).append('\n');
        return code;
    }
}
