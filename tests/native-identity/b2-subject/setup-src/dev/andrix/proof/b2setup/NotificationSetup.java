// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.b2setup;

import android.app.NotificationChannel;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;
import java.lang.reflect.Method;
import org.json.JSONObject;

/** Setup only, ordinary shell UID. Never included in the subject APK or a product image. */
public final class NotificationSetup {
    private static final String PACKAGE = "dev.andrix.proof.principalclosed";
    private static final String CHANNEL = "andrix.b2.state";
    private static final String DESCRIPTOR = "android.app.INotificationManager";

    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    private static NotificationChannel copyChannel(NotificationChannel original) {
        Parcel parcel = Parcel.obtain();
        try {
            original.writeToParcel(parcel, 0);
            parcel.setDataPosition(0);
            return NotificationChannel.CREATOR.createFromParcel(parcel);
        } finally { parcel.recycle(); }
    }

    /** Returns an acknowledgement, not independent evidence of preference or persistence. */
    public static JSONObject run(String[] args) throws Exception {
        require(Process.myUid() == 2000, "ordinary shell UID required; root and app UID refused");
        require(args != null && args.length == 4 && args[0].matches("1[0-9]{4}")
                && args[1].matches("[0-9a-f]{32}") && args[2].matches("[0-9a-f]{32}")
                && args[3].matches("[0-9a-f]{64}"), "bounded setup arguments");
        int uid = Integer.parseInt(args[0]);
        // These existing framework interfaces are used only from the shell command process.
        // No hidden API exemption, privilege adoption, local NMS stub or target UID entry.
        Class<?> services = Class.forName("android.os.ServiceManager");
        IBinder binder = (IBinder) services.getMethod("getService", String.class)
                .invoke(null, "notification");
        require(binder != null && binder.isBinderAlive()
                && binder.queryLocalInterface(DESCRIPTOR) == null, "remote notification binder");
        Class<?> manager = Class.forName(DESCRIPTOR);
        Object proxy = Class.forName(DESCRIPTOR + "$Stub").getMethod("asInterface", IBinder.class)
                .invoke(null, binder);
        Method get = manager.getMethod("getNotificationChannel", String.class, int.class,
                String.class, String.class);
        Method update = manager.getMethod("updateNotificationChannelForPackage", String.class,
                int.class, NotificationChannel.class);
        NotificationChannel original = (NotificationChannel) get.invoke(proxy,
                "com.android.shell", 0, PACKAGE, CHANNEL);
        require(original != null && CHANNEL.equals(original.getId())
                && "Andrix B2 state".contentEquals(original.getName())
                && original.getDescription() == null && original.getImportance() == 2
                && original.getSound() == null && !original.shouldVibrate()
                && !original.shouldShowLights() && original.canShowBadge()
                && original.getGroup() == null && original.getParentChannelId() == null
                && original.getConversationId() == null && !original.canBubble(),
                "existing pristine fixture channel required");
        // Public toString prints these exact scalar fields. This is an extra setup guard,
        // not the host oracle. Full dumps and stored records are still mandatory bookends.
        String before = original.toString();
        require(before.contains(", mUserLockedFields=0, ")
                && before.contains(", mAllowBubbles=-1, "), "no old preference or user lock");
        NotificationChannel changed = copyChannel(original);
        require(changed != original && before.equals(changed.toString()), "independent exact copy");
        changed.setAllowBubbles(true);
        require(!original.canBubble() && changed.canBubble() && before.equals(original.toString()),
                "copy mutation must not alias the fetched channel");
        update.invoke(proxy, PACKAGE, uid, changed); // Exactly one effect, never retried.
        return new JSONObject().put("version", 1).put("operation", "channel-bubbles-copy-v1")
                .put("package", PACKAGE).put("uid", uid).put("user", 0).put("channel", CHANNEL)
                .put("process_uid", Process.myUid()).put("nonce", args[1]).put("setup", args[2])
                .put("contract_sha256", args[3]).put("stage", "update_returned")
                .put("setter_calls", 1).put("state_proven", false);
    }

    public static void main(String[] args) {
        try {
            System.out.println("ANDRIX_B2_NOTIFICATION_SETUP: " + run(args).toString());
        } catch (Exception error) {
            System.err.println("ANDRIX_B2_NOTIFICATION_SETUP_REFUSED: " + error.getClass().getName());
            System.exit(1);
        }
    }
}
