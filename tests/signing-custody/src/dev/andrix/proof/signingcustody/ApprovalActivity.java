// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.signingcustody;

import android.app.Activity;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/** Exact request confirmation, followed by a system credential CryptoObject prompt. */
public final class ApprovalActivity extends Activity {
    private ProofBroker broker;
    private SigningRequest request;
    private TextView text;
    private Button approve;
    private Button cancel;

    @Override protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE
                | WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        if (android.os.Process.myUid() / 100000 != 0
                || !("userdebug".equals(Build.TYPE) || "eng".equals(Build.TYPE))
                || !Build.FINGERPRINT.startsWith("Andrix/andrix_gos_cf_arm64_only_phone/")) {
            finish(); return;
        }
        broker = ProofBroker.get(this);
        if (!bindPresentation(getIntent())) { finish(); return; }
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(28, 48, 28, 28);
        text = new TextView(this); text.setTextSize(17); text.setTextIsSelectable(true);
        layout.addView(text);
        approve = new Button(this); approve.setText("Approve this exact request");
        approve.setFilterTouchesWhenObscured(true);
        approve.setOnClickListener(view -> { approve.setEnabled(false); broker.approve(this, request); });
        layout.addView(approve);
        cancel = new Button(this); cancel.setText("Decline or cancel this request");
        cancel.setFilterTouchesWhenObscured(true);
        cancel.setOnClickListener(view -> { broker.cancel(request.id()); refresh(); });
        layout.addView(cancel);
        ScrollView scroll = new ScrollView(this); scroll.addView(layout); setContentView(scroll);
        refresh();
    }

    private boolean bindPresentation(Intent intent) {
        String id = intent.getStringExtra("request");
        if (id == null || id.length() > SigningRequest.MAX_REQUEST_ID_CHARS) return false;
        final SigningRequest candidate;
        try { candidate = broker.find(id); }
        catch (RuntimeException refused) { return false; }
        if (!SigningRequest.mayReplacePresentation(request, candidate)) return false;
        request = candidate;
        setIntent(intent);
        return true;
    }

    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        // A new intent is only a request to view stored metadata. It cannot
        // approve, replace the bytes of, or cancel an active operation.
        if (broker != null) bindPresentation(intent);
        refresh();
    }

    void refresh() {
        if (isDestroyed() || text == null || request == null) return;
        text.setText("LAB ONLY: disposable signing\n\n"
                + "Request: " + request.id() + "\n"
                + "Requester UID: " + request.requesterUid() + ", user " + request.androidUser() + "\n"
                + "Purpose: " + request.purpose() + "\n\n"
                + "Certificate SHA256:\n" + request.certificateSha256() + "\n\n"
                + "Payload SHA256:\n" + request.payloadSha256() + "\n"
                + "Payload bytes: " + request.payload().length + "\n\n"
                + "State: " + request.state() + "\n\n"
                + "This signs only this immutable test payload. It does not install software, "
                + "grant root or authorize other requests. Device authentication follows approval.");
        approve.setEnabled(request.state() == SigningRequest.State.PENDING);
        cancel.setEnabled(request.state() == SigningRequest.State.PENDING
                || request.state() == SigningRequest.State.AUTHENTICATING
                || request.state() == SigningRequest.State.SIGNING);
    }

    @Override protected void onDestroy() {
        if (request != null && broker != null
                && (request.state() == SigningRequest.State.PENDING
                    || request.state() == SigningRequest.State.AUTHENTICATING)) {
            broker.cancel(request.id());
        }
        // Accepted SIGNING work owns its immutable request independently of
        // presentation. Do not discard its outcome because this Activity ends.
        super.onDestroy();
    }
}
