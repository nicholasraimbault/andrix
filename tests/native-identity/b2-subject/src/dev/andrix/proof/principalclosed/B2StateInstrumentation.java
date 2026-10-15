// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.principalclosed;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Process;
import android.os.SystemClock;
import android.os.UserManager;
import java.security.KeyStore;
import org.json.JSONObject;

/** Ordinary self instrumentation. No UiAutomation, privilege adoption or deferred UID bypass. */
public final class B2StateInstrumentation extends Instrumentation {
    private Bundle arguments;
    @Override public void onCreate(Bundle args) { super.onCreate(args); arguments = args; start(); }
    @Override public void onStart() {
        JSONObject result = new JSONObject();
        boolean passed = false;
        String stage = "request";
        try {
            Contract request = new Contract(arguments);
            request.validateContract();
            stage = "identity";
            Context context = getTargetContext();
            UserManager users = context.getSystemService(UserManager.class);
            PackageInfo info = context.getPackageManager().getPackageInfo(Contract.PACKAGE,
                    PackageManager.GET_SIGNING_CERTIFICATES);
            android.content.pm.Signature[] signers = info.signingInfo.getApkContentsSigners();
            if (!Contract.PACKAGE.equals(context.getPackageName()) || Process.myUid() != request.uid
                    || context.getApplicationInfo().uid != request.uid
                    || users.getSerialNumberForUser(Process.myUserHandle()) != request.serial
                    || !users.isUserUnlocked() || signers == null || signers.length != 1
                    || !Contract.SIGNER.equals(Contract.hash(signers[0].toByteArray()))
                    || info.getLongVersionCode() != 1 || context.getApplicationInfo().targetSdkVersion != 37) {
                throw new IllegalStateException("identity, signer or unlock mismatch");
            }
            result.put("version", 1).put("operation", request.operation).put("nonce", request.nonce)
                    .put("setup", request.setup).put("contract_sha256", request.contract)
                    .put("phase", request.phase).put("guest_binding_sha256", request.guest)
                    .put("package", Contract.PACKAGE).put("uid", Process.myUid())
                    .put("user_serial", request.serial).put("apk_signer_sha256", Contract.SIGNER)
                    .put("pid", Process.myPid()).put("elapsed_ms", SystemClock.elapsedRealtime())
                    .put("user_unlocked", true);
            StateFiles files = new StateFiles(context);
            KeyStore keys = KeyStore.getInstance("AndroidKeyStore"); keys.load(null);
            boolean k0 = keys.containsAlias(Contract.ALIASES[0]);
            boolean k1 = keys.containsAlias(Contract.ALIASES[1]);
            boolean ce = StateFiles.exists(files.ce), de = StateFiles.exists(files.de);
            boolean intent = StateFiles.exists(files.intent);
            result.put("key0_existed_before", k0).put("key1_existed_before", k1)
                    .put("ce_existed_before", ce).put("de_existed_before", de)
                    .put("intent_existed_before", intent);
            stage = "existing_state";
            if (request.operation.equals("initialize")) {
                stage = "initialize";
                InitializeState.run(context, request, files, keys);
            } else if (!(k0 && k1 && ce && de && intent)) {
                throw new IllegalStateException("missing state; no repair");
            }
            stage = "observe";
            ObserveState.run(context, request, files, keys, result);
            passed = true; stage = "complete";
        } catch (Exception error) {
            try { result.put("error_class", error.getClass().getName()); }
            catch (Exception ignored) { }
        } finally {
            try { result.put("stage", stage).put("passed", passed); }
            catch (Exception ignored) { }
            Bundle output = new Bundle(); output.putString("b2_state_result", result.toString());
            finish(passed ? Activity.RESULT_OK : Activity.RESULT_CANCELED, output);
        }
    }
}
