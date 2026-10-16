// SPDX-License-Identifier: Apache-2.0
// A fixed read only probe for a disposable Andrix test guest. Run as the shell user with
// CLASSPATH=<this jar> app_process /system/bin UiStateRead <user>
// It asks four framework services six questions about the UI state of one user and nothing else:
// whether the device is interactive, whether the keyguard shows and is secure, whether the device
// is locked and secure for the user, and whether the user's CE storage is unlocked. Each call goes
// to the service's own Binder proxy with its exact AIDL signature, never through a manager class
// that answers false when the call fails. A call that fails is unavailable, never false. It has no
// path that locks or unlocks a user, dismisses or disables the keyguard, wakes or sleeps the
// device, reports an unlock attempt, or starts, commits or aborts a checkpoint.
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public final class UiStateRead {
    private static final String HEADER = "andrix-ui-state-read-v1";
    private static final String CAPABILITIES =
            "interactive,keyguard_locked,keyguard_secure,device_locked,device_secure,ce_unlocked";
    // Context.DEVICE_ID_DEFAULT: the trust service answers false for any other device.
    private static final int DEFAULT_DEVICE = 0;
    // UserHandle.MAX_SECONDARY_USER_ID.
    private static final int MAX_USER = 21473;
    private static final Class<?>[] NONE = {};
    private static final Class<?>[] USER = {int.class};
    private static final Class<?>[] USER_DEVICE = {int.class, int.class};

    public static void main(String[] args) {
        int user = args.length == 1 ? user(args[0]) : -1;
        System.out.println(HEADER);
        if (user < 0) {
            System.out.println("error=arguments");
            System.out.println("end=" + HEADER);
            System.exit(2);
            return;
        }
        System.out.println("user=" + user);
        System.out.println("capabilities=" + CAPABILITIES);
        String[] names = CAPABILITIES.split(",");
        String[] values = {
            ask("power", "android.os.IPowerManager", "isInteractive", NONE),
            ask("window", "android.view.IWindowManager", "isKeyguardLocked", NONE),
            ask("window", "android.view.IWindowManager", "isKeyguardSecure", USER, user),
            ask("trust", "android.app.trust.ITrustManager", "isDeviceLocked", USER_DEVICE, user, DEFAULT_DEVICE),
            ask("trust", "android.app.trust.ITrustManager", "isDeviceSecure", USER_DEVICE, user, DEFAULT_DEVICE),
            ask("mount", "android.os.storage.IStorageManager", "isCeStorageUnlocked", USER, user),
        };
        boolean complete = true;
        for (int i = 0; i < names.length; i++) {
            System.out.println(names[i] + "=" + values[i]);
            complete &= values[i].equals("true") || values[i].equals("false");
        }
        System.out.println("status=" + (complete ? "complete" : "unavailable"));
        System.out.println("end=" + HEADER);
        System.exit(complete ? 0 : 5);
    }

    // A decimal user ID without sign or leading zero, at most MAX_USER, or -1.
    private static int user(String text) {
        if (!text.matches("0|[1-9][0-9]{0,4}")) return -1;
        int value = Integer.parseInt(text);
        return value <= MAX_USER ? value : -1;
    }

    // One call on the named service's Binder proxy: true, false, or unavailable with the reason.
    private static String ask(String service, String name, String method, Class<?>[] types, Object... args) {
        try {
            Class<?> manager = Class.forName("android.os.ServiceManager");
            Object binder = manager.getMethod("getService", String.class).invoke(null, service);
            if (binder == null) return "unavailable:service-absent";
            Class<?> ibinder = Class.forName("android.os.IBinder");
            Object proxy = Class.forName(name + "$Stub").getMethod("asInterface", ibinder).invoke(null, binder);
            Method call = Class.forName(name).getMethod(method, types);
            if (call.getReturnType() != boolean.class) return "unavailable:not-boolean";
            Object value = call.invoke(proxy, args);
            if (!(value instanceof Boolean)) return "unavailable:not-boolean";
            return ((Boolean) value) ? "true" : "false";
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            return "unavailable:" + (cause == null ? "unknown" : cause.getClass().getName());
        } catch (ReflectiveOperationException | RuntimeException e) {
            return "unavailable:" + e.getClass().getName();
        }
    }
}
