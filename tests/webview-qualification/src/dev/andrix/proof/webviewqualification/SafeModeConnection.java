package dev.andrix.proof.webviewqualification;

import android.content.Context;
import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.IBinder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import org.json.JSONArray;

/** Explicit public service bind. Typed calls come from the UNCHANGED upstream AIDL. */
final class SafeModeConnection implements ServiceConnection {
    static final String FAST = "fast_variations_seed";
    private static final Uri ACTIONS = Uri.parse("content://dev.andrix.experiment.webview."
            + "SafeModeContentProvider/safe-mode-actions");
    private final Context context;
    private final Session session;
    private final CompletableFuture<IBinder> connected = new CompletableFuture<>();
    private SafeModeContract contract; // Generated typed adapter; see prepare_contract.py.
    // Main-thread-only registration state.
    private boolean bound;
    private boolean unbinding;

    SafeModeConnection(Context context, Session session) {
        this.context = context;
        this.session = session;
    }

    void open() throws Exception {
        Session.await(session.post(() -> {
            session.requireRunning();
            bound = context.bindService(new Intent().setComponent(Pins.SAFE_SERVICE), this,
                    Context.BIND_AUTO_CREATE);
            session.record("service_bind", "component", Pins.SAFE_SERVICE.flattenToString(),
                    "accepted", bound, "caller_uid", android.os.Process.myUid());
            Arguments.check(bound, "SafeModeService bind was not accepted");
        }));
        IBinder binder = Session.await(connected);
        session.requireRunning();
        String descriptor = binder.getInterfaceDescriptor();
        boolean remote = binder.queryLocalInterface(SafeModeContract.DESCRIPTOR) == null;
        session.record("service_connected", "descriptor", descriptor,
                "remote_binder", remote, "alive", binder.isBinderAlive());
        Arguments.check(SafeModeContract.DESCRIPTOR.equals(descriptor) && binder.isBinderAlive(),
                "Unexpected/dead SafeMode Binder");
        // In the different-UID negative a local Java call cannot substitute for Binder.
        if (session.args.mode.equals("different-uid")) {
            Arguments.check(remote, "Different-UID control must use a remote Binder proxy");
        }
        contract = new SafeModeContract(binder);
    }

    State read(String point) throws Exception {
        Arguments.check(contract != null, "No connected typed Binder");
        // A successful real getter is mandatory before any setter/denial test.
        long timestamp = contract.timestamp();
        session.record("safe_mode_getter", "point", point, "timestamp", timestamp);
        Arguments.check(timestamp >= 0, "Negative SafeMode timestamp");
        List<String> actions = new ArrayList<>();
        try (Cursor cursor = context.getContentResolver().query(ACTIONS, null, null, null, null)) {
            Arguments.check(cursor != null, "SafeMode public query returned null cursor");
            session.record("safe_mode_query", "point", point, "uri", ACTIONS.toString(),
                    "columns", new JSONArray(cursor.getColumnNames()), "row_count", cursor.getCount());
            Arguments.check(cursor.getColumnCount() == 1, "Unexpected public actions cursor schema");
            while (cursor.moveToNext()) {
                Arguments.check(actions.size() < 64 && cursor.getType(0) == Cursor.FIELD_TYPE_STRING,
                        "Unexpected/beyond-bound public action row");
                String action = cursor.getString(0);
                Arguments.check(action != null && action.length() <= 256 && !actions.contains(action),
                        "Invalid/duplicate public action");
                actions.add(action);
            }
        }
        PackageManager pm = context.getPackageManager();
        int alias = pm.getComponentEnabledSetting(Pins.SAFE_ALIAS);
        ActivityInfo info = pm.getActivityInfo(Pins.SAFE_ALIAS, PackageManager.MATCH_DISABLED_COMPONENTS);
        boolean effectiveEnabled = info.applicationInfo.enabled
                && (alias == PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                    || (alias == PackageManager.COMPONENT_ENABLED_STATE_DEFAULT && info.enabled));
        session.record("safe_mode_state", "point", point, "timestamp", timestamp,
                "actions", new JSONArray(actions), "alias", Pins.SAFE_ALIAS.flattenToString(),
                "alias_setting", alias, "alias_activity_info_enabled", info.enabled,
                "alias_application_enabled", info.applicationInfo.enabled,
                "alias_effective_enabled", effectiveEnabled);
        return new State(timestamp, actions, alias, effectiveEnabled);
    }

    void set(List<String> actions) throws Exception {
        Arguments.check(contract != null, "No connected typed Binder");
        session.record("safe_mode_set_attempt", "actions", new JSONArray(actions),
                "caller_uid", android.os.Process.myUid());
        contract.setActions(actions);
        session.record("safe_mode_set_returned", "actions", new JSONArray(actions));
    }

    void requireSetterDenied() throws Exception {
        Arguments.check(contract != null, "No connected typed Binder");
        List<String> actions = Collections.emptyList();
        session.record("safe_mode_set_attempt", "actions", new JSONArray(actions),
                "caller_uid", android.os.Process.myUid());
        try {
            contract.setActions(actions); // ONLY the real typed Binder call is in this try block.
        } catch (SecurityException expected) {
            session.record("setter_security_exception", "exception", expected.toString(),
                    "caller_uid", android.os.Process.myUid(), "different_signer_proof", false);
            return;
        }
        session.record("safe_mode_set_returned", "actions", new JSONArray(actions));
        throw new IllegalStateException("Real Binder setSafeMode unexpectedly succeeded at a different UID");
    }

    void close() throws Exception {
        Session.await(session.post(() -> {
            unbinding = true;
            boolean registered = bound;
            if (bound) {
                context.unbindService(this);
                bound = false;
            }
            session.record("service_unbound", "was_registered", registered);
        }));
    }

    @Override
    public void onServiceConnected(ComponentName name, IBinder binder) {
        if (!Pins.SAFE_SERVICE.equals(name) || binder == null) {
            lost("Invalid onServiceConnected");
        } else {
            connected.complete(binder); // No synchronous Binder work on the main thread.
        }
    }

    @Override
    public void onServiceDisconnected(ComponentName name) {
        if (!unbinding && !session.closing) {
            lost("SafeModeService disconnected: " + name);
        }
    }

    @Override
    public void onBindingDied(ComponentName name) {
        if (!unbinding && !session.closing) {
            lost("SafeModeService binding died: " + name);
        }
    }

    @Override
    public void onNullBinding(ComponentName name) {
        lost("SafeModeService returned a null binding: " + name);
    }

    private void lost(String message) {
        IllegalStateException error = new IllegalStateException(message);
        session.fail("service_callback", error);
        connected.completeExceptionally(error);
    }

    static final class State {
        final long timestamp;
        final List<String> actions;
        final int alias;
        final boolean aliasEnabled;

        State(long timestamp, List<String> actions, int alias, boolean aliasEnabled) {
            this.timestamp = timestamp;
            this.actions = actions;
            this.alias = alias;
            this.aliasEnabled = aliasEnabled;
        }

        boolean knownActions() {
            return actions.isEmpty() || (actions.size() == 1 && actions.contains(FAST));
        }

        void requireOff() {
            Arguments.check(actions.isEmpty() && timestamp == 0 && !aliasEnabled
                            && alias == PackageManager.COMPONENT_ENABLED_STATE_DEFAULT,
                    "Expected empty actions, timestamp 0, alias DEFAULT/effectively disabled");
        }

        void requireOn() {
            Arguments.check(actions.size() == 1 && actions.contains(FAST) && timestamp > 0
                            && alias == PackageManager.COMPONENT_ENABLED_STATE_ENABLED && aliasEnabled,
                    "Expected only fast_variations_seed, positive timestamp, enabled alias");
        }
    }
}
