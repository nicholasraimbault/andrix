// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.artifactpayload;

import android.app.Instrumentation;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Process;
import java.security.MessageDigest;
import org.json.JSONObject;

/** Ordinary installed execution and public signer observation only. */
public final class ArtifactPayload extends Instrumentation {
    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        start();
    }

    @Override public void onStart() {
        Bundle response = new Bundle();
        try {
            String name = getTargetContext().getPackageName();
            PackageInfo info = getTargetContext().getPackageManager().getPackageInfo(name,
                    PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES));
            if (!name.equals("dev.andrix.proof.artifactpayload") || info.getLongVersionCode() != 1
                    || info.signingInfo == null || info.signingInfo.getApkContentsSigners().length != 1) {
                throw new IllegalStateException("unexpected installed artifact");
            }
            byte[] certificate = info.signingInfo.getApkContentsSigners()[0].toByteArray();
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate);
            StringBuilder hash = new StringBuilder(64);
            for (byte item : digest) hash.append(String.format(java.util.Locale.ROOT, "%02x", item & 255));
            JSONObject record = new JSONObject().put("marker", "OWNED_APK_ARTIFACT_EXECUTED")
                    .put("package", name).put("version", info.getLongVersionCode())
                    .put("uid", Process.myUid()).put("user", Process.myUid() / 100000)
                    .put("certificate_sha256", hash.toString());
            response.putString("artifact_execution", record.toString());
            finish(-1, response);
        } catch (Exception failure) {
            response.putString("error_class", failure.getClass().getName());
            finish(0, response);
        }
    }
}
