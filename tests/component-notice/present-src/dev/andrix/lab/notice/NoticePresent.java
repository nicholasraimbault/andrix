// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.notice;

import android.app.ActivityOptions;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;
import android.os.RemoteException;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * The fixed shell presentation helper, run as the shell user with
 * {@code CLASSPATH=<jar> app_process /system/bin dev.andrix.lab.notice.NoticePresent <arguments>}.
 * Never part of the APK or an image.
 *
 * <p>It makes one call: {@code IActivityTaskManager.startActivityAndWait} as
 * {@code com.android.shell}, for the explicit fixture activity in the request's user, with the
 * request as typed extras and {@code ActivityOptions.setShareIdentityEnabled(true)}, so that the
 * activity can observe the shell user as its launcher. It finds that method by its exact
 * parameter and return types, and refuses before calling anything when they differ. The shell
 * command {@code am start -W} makes the same call without identity sharing.
 *
 * <p>The request also carries a report binder. The activity sends it one decision before it shows
 * anything: presented, or refused and why, a conflicting row under the request's key included.
 * After a successful start the helper waits a bounded time for that decision from an app of the
 * request's user.
 *
 * <p>Output: the header line, then either {@code error=<token>} with a nonzero status before any
 * start was asked, or the wait result's five fields, the activity's decision and the reporting
 * UID. Status 0 only for START_SUCCESS and a presented decision, 9 for START_SUCCESS and a refused
 * one, 10 for START_SUCCESS without a decision, 7 for another start result. A presented decision
 * says that the fixture accepted the request, never that a user saw it.
 */
public final class NoticePresent {
    public static final String HEADER = "andrix-notice-present-v2";
    static final String PACKAGE = "dev.andrix.lab.notice";
    static final String ACTIVITY = PACKAGE + ".NoticeActivity";
    static final String ACTION = "dev.andrix.lab.notice.action.PRESENT";
    static final String SHELL_PACKAGE = "com.android.shell";
    static final String SERVICE = "activity_task";
    static final String MANAGER = "android.app.IActivityTaskManager";
    static final int SHELL_UID = 2000;
    static final long REPORT_WAIT_MS = 5000;

    private NoticePresent() {}

    public static void main(String[] args) {
        System.exit(run(args, System.out));
    }

    /** Runs the helper and returns its exit status. */
    static int run(String[] args, PrintStream out) {
        return run(args, out, REPORT_WAIT_MS);
    }

    /** Runs the helper, waiting at most this long for the activity's decision. */
    static int run(String[] args, PrintStream out, long reportWaitMillis) {
        out.println(HEADER);
        if (Process.myUid() != SHELL_UID) return error(out, "identity", 3);
        NoticeRequest request;
        try {
            request = NoticeRequest.fromArguments(args);
        } catch (IllegalArgumentException refused) {
            return error(out, "arguments", 2);
        }
        Object manager;
        Method start;
        try {
            Class<?> services = Class.forName("android.os.ServiceManager");
            Object binder = services.getMethod("getService", String.class).invoke(null, SERVICE);
            if (binder == null) return error(out, "service-absent", 4);
            Class<?> type = Class.forName(MANAGER);
            manager = Class.forName(MANAGER + "$Stub").getMethod("asInterface", IBinder.class).invoke(null, binder);
            // The exact signature of IActivityTaskManager.aidl's startActivityAndWait, in order.
            start = type.getMethod("startActivityAndWait", Class.forName("android.app.IApplicationThread"),
                    String.class, String.class, Intent.class, String.class, IBinder.class, String.class, int.class,
                    int.class, Class.forName("android.app.ProfilerInfo"), Bundle.class, int.class);
            if (start.getReturnType() != Class.forName("android.app.WaitResult") || !type.isInstance(manager)) {
                return error(out, "signature", 5);
            }
        } catch (ReflectiveOperationException | RuntimeException e) {
            return error(out, "signature", 5);
        }
        Intent intent = new Intent(ACTION);
        intent.setComponent(new ComponentName(PACKAGE, ACTIVITY));
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        Report report = new Report(request.user);
        Bundle reportExtra = new Bundle();
        reportExtra.putBinder(NoticeRequest.KEY_REPORT, report);
        intent.putExtras(reportExtra);
        request.write(new NoticeRequest.Sink() {
            @Override
            public void string(String key, String value) {
                intent.putExtra(key, value);
            }

            @Override
            public void integer(String key, int value) {
                intent.putExtra(key, value);
            }

            @Override
            public void longValue(String key, long value) {
                intent.putExtra(key, value);
            }
        });
        ActivityOptions options = ActivityOptions.makeBasic();
        options.setShareIdentityEnabled(true);
        Object result;
        try {
            result = start.invoke(manager, null, SHELL_PACKAGE, null, intent, null, null, null, 0, 0, null,
                    options.toBundle(), request.user);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            return error(out, "start:" + (cause == null ? "unknown" : cause.getClass().getName()), 6);
        } catch (ReflectiveOperationException | RuntimeException e) {
            return error(out, "start:" + e.getClass().getName(), 6);
        }
        try {
            Class<?> wait = result.getClass();
            int code = field(wait, "result").getInt(result);
            Object who = field(wait, "who").get(result);
            out.println("result=" + code);
            out.println("timeout=" + field(wait, "timeout").getBoolean(result));
            String name = who instanceof ComponentName ? ((ComponentName) who).flattenToShortString() : "null";
            out.println("who=" + name);
            out.println("total_time=" + field(wait, "totalTime").getLong(result));
            out.println("launch_state=" + field(wait, "launchState").getInt(result));
            String decision = code == 0 ? report.await(reportWaitMillis) : null;
            out.println("activity=" + (decision == null ? "unreported" : decision));
            out.println("reporter=" + (decision == null ? -1 : report.reporter()));
            if (code != 0) return 7;
            if (decision == null) return 10;
            return NoticeRequest.PRESENTED.equals(decision) ? 0 : 9;
        } catch (ReflectiveOperationException | RuntimeException e) {
            out.println("error=result:" + e.getClass().getName());
            return 8;
        }
    }

    /**
     * The activity's one decision, sent one way to this binder. Only the first report of known form
     * from an ordinary application UID of the request's user counts; anything else is ignored.
     */
    static final class Report extends Binder {
        private final int user;
        private final CountDownLatch reported = new CountDownLatch(1);
        private String decision;
        private int reporter = -1;

        Report(int user) {
            this.user = user;
        }

        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
            if (code != FIRST_CALL_TRANSACTION) return super.onTransact(code, data, reply, flags);
            int uid = Binder.getCallingUid();
            int app = uid % 100000;
            if (uid / 100000 != user || app < 10000 || app > 19999) return true;
            try {
                data.enforceInterface(NoticeRequest.REPORT_DESCRIPTOR);
                if (data.readInt() != NoticeRequest.REPORT_VERSION) return true;
                String text = data.readString();
                if (!NoticeRequest.decision(text)) return true;
                synchronized (this) {
                    if (decision == null) {
                        decision = text;
                        reporter = uid;
                        reported.countDown();
                    }
                }
            } catch (RuntimeException unknownForm) {
                // A report of no known form is no report.
            }
            return true;
        }

        /** The first decision within the bound, or null. */
        String await(long millis) {
            try {
                if (!reported.await(millis, TimeUnit.MILLISECONDS)) return null;
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return null;
            }
            synchronized (this) {
                return decision;
            }
        }

        synchronized int reporter() {
            return reporter;
        }
    }

    private static Field field(Class<?> type, String name) throws NoSuchFieldException {
        return type.getField(name);
    }

    private static int error(PrintStream out, String token, int status) {
        out.println("error=" + token);
        return status;
    }
}
