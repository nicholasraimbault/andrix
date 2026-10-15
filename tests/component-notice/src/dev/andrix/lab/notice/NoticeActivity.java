// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.notice;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;
import android.os.RemoteException;
import android.os.SystemClock;
import android.os.UserManager;
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import java.util.Set;

/**
 * The full screen notice. The manifest makes it direct boot aware, guards it with DUMP, shows it
 * when locked and turns the screen on; nothing here dismisses the keyguard. It asks for no consent
 * and no acknowledgement, and closing it changes nothing.
 *
 * <p>It refuses, finishing at once with nothing shown or written, unless its observed launching
 * UID is the shell user's. Android reveals that UID only when the launcher shared its identity, as
 * the fixed shell helper does. A Binder calling UID in a callback is not that proof. The user and
 * serial come from the app's own process and UserManager and must equal the request's. It also
 * refuses a request whose key already holds a conflicting or corrupt row, or cannot be read, so a
 * conflicting notice is never shown. It sends its decision to the helper's report binder before it
 * sets any content, so the helper's result shows a refusal.
 *
 * <p>It shows the component, the plan or control, the interruption, the exact text and its
 * SHA-256, and the unpredictable challenge. The first frame commit seen while the window has focus
 * gives the candidate row, which only the presentation code hands to the store's writer.
 */
public final class NoticeActivity extends Activity {
    static final String ACTION = "dev.andrix.lab.notice.action.PRESENT";

    private Delivery delivery;
    private final Runnable commit = new Runnable() {
        @Override
        public void run() {
            frameCommitted();
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent intent = getIntent();
        Bundle extras = intent.getExtras();
        IBinder report = extras == null ? null : extras.getBinder(NoticeRequest.KEY_REPORT);
        NoticeRequest request;
        try {
            if (!ACTION.equals(intent.getAction()) || intent.getData() != null || intent.getType() != null
                    || intent.getCategories() != null
                    || !new ComponentName(this, NoticeActivity.class).equals(intent.getComponent())) {
                throw new IllegalArgumentException("intent form");
            }
            request = NoticeRequest.fromExtras(new IntentExtras(extras));
        } catch (IllegalArgumentException refused) {
            report(report, NoticeRequest.REFUSED + "request");
            refuse("request " + refused.getMessage());
            return;
        }
        int launched;
        try {
            launched = getLaunchedFromUid();
        } catch (RuntimeException unknown) {
            launched = Process.INVALID_UID;
        }
        int uid = Process.myUid();
        long serial = getSystemService(UserManager.class).getSerialNumberForUser(Process.myUserHandle());
        String decision = Delivery.decide(launched, uid, serial, request, Writer.store(getApplicationContext()));
        report(report, decision);
        if (!NoticeRequest.PRESENTED.equals(decision)) {
            refuse(decision);
            return;
        }
        delivery = new Delivery(request, uid, serial, Process.myPid(), Process.getStartElapsedRealtime());
        setContentView(R.layout.notice);
        boolean notice = NoticeRequest.TICKET_NOTICE.equals(request.purpose);
        show(R.id.title, getString(notice ? R.string.title_notice : R.string.title_qualification));
        show(R.id.challenge, request.event);
        show(R.id.text, request.text);
        show(R.id.interruption, getString(notice ? R.string.interruption_notice : R.string.interruption_qualification));
        show(R.id.component, getString(R.string.component_label, request.component));
        show(R.id.plan, notice ? getString(R.string.plan_label, request.plan, request.ticket, request.index)
                : getString(R.string.control_label, request.control));
        show(R.id.text_sha256, getString(R.string.text_sha256_label, request.textSha256));
    }

    private void show(int id, CharSequence value) {
        ((TextView) findViewById(id)).setText(value);
    }

    private void refuse(String why) {
        Log.w(Writer.TAG, "refused " + why);
        finish();
    }

    /** Sends the decision to the helper's report binder, one way, when the intent carries one. */
    private static void report(IBinder binder, String decision) {
        if (binder == null) return;
        Parcel data = Parcel.obtain();
        try {
            data.writeInterfaceToken(NoticeRequest.REPORT_DESCRIPTOR);
            data.writeInt(NoticeRequest.REPORT_VERSION);
            data.writeString(decision);
            binder.transact(IBinder.FIRST_CALL_TRANSACTION, data, null, IBinder.FLAG_ONEWAY);
        } catch (RemoteException | RuntimeException lost) {
            Log.w(Writer.TAG, "the decision was not reported");
        } finally {
            data.recycle();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (delivery != null) delivery.resumed(SystemClock.elapsedRealtime());
    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        if (delivery != null && hasFocus && delivery.focused(SystemClock.elapsedRealtime())) {
            View decor = getWindow().getDecorView();
            decor.getViewTreeObserver().registerFrameCommitCallback(commit);
            decor.invalidate();
        }
    }

    private void frameCommitted() {
        if (delivery == null) return;
        ReceiptRow row;
        try {
            row = delivery.committed(SystemClock.elapsedRealtime(), hasWindowFocus());
        } catch (IllegalArgumentException refused) {
            Log.w(Writer.TAG, "no row: " + refused.getMessage());
            return;
        }
        if (row != null) Writer.record(this, row);
    }

    /** An intent's extras through the strict typed reads: a typed getter gives a value only when
     * the key holds that type, so two defaults that disagree mean absent or another type. */
    private static final class IntentExtras implements NoticeRequest.Extras {
        private final Bundle extras;

        IntentExtras(Bundle extras) {
            if (extras == null) throw new IllegalArgumentException("no extras");
            this.extras = extras;
        }

        @Override
        public Set<String> keys() {
            return extras.keySet();
        }

        @Override
        public String string(String key) {
            return extras.getString(key);
        }

        @Override
        public Integer integer(String key) {
            int low = extras.getInt(key, Integer.MIN_VALUE);
            int high = extras.getInt(key, Integer.MAX_VALUE);
            return low == high ? Integer.valueOf(low) : null;
        }

        @Override
        public Long longValue(String key) {
            long low = extras.getLong(key, Long.MIN_VALUE);
            long high = extras.getLong(key, Long.MAX_VALUE);
            return low == high ? Long.valueOf(low) : null;
        }
    }
}
