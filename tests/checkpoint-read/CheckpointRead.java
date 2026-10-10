// SPDX-License-Identifier: Apache-2.0
// A fixed read only probe for a disposable Andrix test guest. Run as the shell user with
// CLASSPATH=<this jar> app_process /system/bin CheckpointRead
// It asks the framework's storage service two questions and nothing else:
// supportsCheckpoint() and needsCheckpoint(). It takes no arguments and has no path that starts,
// resets, prepares, commits or aborts a checkpoint.
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public final class CheckpointRead {
    private static final String HEADER = "andrix-checkpoint-read-v1";

    public static void main(String[] args) {
        if (args.length != 0) {
            System.out.println(HEADER);
            System.out.println("error=arguments");
            System.exit(2);
        }
        Object storage;
        Class<?> iface;
        try {
            Class<?> sm = Class.forName("android.os.ServiceManager");
            Object binder = sm.getMethod("getService", String.class).invoke(null, "mount");
            if (binder == null) {
                System.out.println(HEADER);
                System.out.println("error=service-absent");
                System.exit(3);
                return;
            }
            Class<?> stub = Class.forName("android.os.storage.IStorageManager$Stub");
            Class<?> ibinder = Class.forName("android.os.IBinder");
            storage = stub.getMethod("asInterface", ibinder).invoke(null, binder);
            iface = Class.forName("android.os.storage.IStorageManager");
        } catch (ReflectiveOperationException | RuntimeException e) {
            fail("lookup", e);
            return;
        }
        String supports = call(iface, storage, "supportsCheckpoint");
        String needs = call(iface, storage, "needsCheckpoint");
        System.out.println(HEADER);
        System.out.println("supports=" + supports);
        System.out.println("needs=" + needs);
        System.exit(supports.equals("true") || supports.equals("false") ? (needs.equals("true") || needs.equals("false") ? 0 : 5) : 5);
    }

    private static String call(Class<?> iface, Object target, String name) {
        try {
            Method method = iface.getMethod(name);
            Object value = method.invoke(target);
            if (value instanceof Boolean) return ((Boolean) value) ? "true" : "false";
            return "error:not-boolean";
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            return "error:" + (cause == null ? "unknown" : cause.getClass().getName());
        } catch (ReflectiveOperationException | RuntimeException e) {
            return "error:" + e.getClass().getName();
        }
    }

    private static void fail(String stage, Throwable e) {
        System.out.println(HEADER);
        System.out.println("error=" + stage + ":" + e.getClass().getName());
        System.exit(4);
    }
}
