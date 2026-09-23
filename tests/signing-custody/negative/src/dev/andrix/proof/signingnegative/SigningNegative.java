// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.signingnegative;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Context;
import android.net.Uri;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;

public final class SigningNegative extends Instrumentation {
    private Bundle args;
    private static final String ALIAS = "andrix.proof.disposable.signing";
    @Override public void onCreate(Bundle arguments) { super.onCreate(arguments); args = arguments; start(); }
    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
    private static String sha(byte[] bytes) throws Exception {
        StringBuilder result = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest(bytes)) {
            result.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
        }
        return result.toString();
    }
    @Override public void onStart() {
        Bundle result = new Bundle();
        try {
            Context context = getTargetContext();
            int uid = android.os.Process.myUid();
            int brokerUid = context.getPackageManager().getApplicationInfo(
                    "dev.andrix.proof.signingcustody", 0).uid;
            require(uid >= 10000 && uid < 90000 && brokerUid >= 10000
                    && brokerUid < 90000 && brokerUid != uid, "actual distinct user0 application UIDs");
            String expectedSpki = args.getString("expected_spki");
            require(expectedSpki != null && expectedSpki.matches("[0-9a-f]{64}"),
                    "trusted public comparison required");
            Uri provider = Uri.parse("content://dev.andrix.proof.signingcustody");
            boolean callDenied = false, importDenied = false;
            try { context.getContentResolver().call(provider, "status", null, null); }
            catch (SecurityException denied) { callDenied = true; }
            try (android.os.ParcelFileDescriptor unexpected = context.getContentResolver()
                    .openFileDescriptor(Uri.withAppendedPath(provider, "import"), "w")) {
                // Close any unexpectedly returned descriptor before reporting
                // the authorization failure. Do not leave an import writer open.
            } catch (SecurityException denied) { importDenied = true; }
            require(callDenied && importDenied, "broker entry must deny actual foreign caller");
            KeyStore store = KeyStore.getInstance("AndroidKeyStore"); store.load(null);
            require(!store.containsAlias(ALIAS) && store.getKey(ALIAS, null) == null,
                    "same alias does not expose broker's APP namespace key");
            boolean generated = false;
            String ownSpki = null;
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
                generator.initialize(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                        .setKeySize(2048).setDigests(KeyProperties.DIGEST_SHA256)
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1).build());
                generator.generateKeyPair(); generated = true;
                Certificate certificate = store.getCertificate(ALIAS);
                ownSpki = sha(certificate.getPublicKey().getEncoded());
                require(!ownSpki.equals(expectedSpki), "ordinary key distinct from broker key");
                byte[] message = "ANDRIX_ORDINARY_KEYSTORE_POSITIVE".getBytes(StandardCharsets.US_ASCII);
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initSign((PrivateKey) store.getKey(ALIAS, null));
                signature.update(message); byte[] signed = signature.sign();
                signature.initVerify(certificate); signature.update(message);
                require(signature.verify(signed), "ordinary namespace positive");
            } finally {
                if (generated) {
                    require(ownSpki != null && ownSpki.equals(sha(store.getCertificate(ALIAS)
                            .getPublicKey().getEncoded())), "cleanup only exact new ordinary identity");
                    store.deleteEntry(ALIAS); require(!store.containsAlias(ALIAS), "own key retired");
                }
            }
            JSONObject report = new JSONObject().put("uid", uid).put("broker_uid", brokerUid)
                    .put("broker_call_denied", callDenied).put("import_stream_denied", importDenied)
                    .put("broker_alias_not_visible", true).put("own_same_alias_key_distinct", true)
                    .put("own_keystore_sign_verify_positive", true).put("own_key_deleted", true)
                    .put("status", "DENIALS_WITH_ORDINARY_KEYSTORE_POSITIVE_REQUIRE_BROKER_BRACKETS");
            result.putString("signing_negative", report.toString());
            finish(Activity.RESULT_OK, result);
        } catch (Throwable failure) {
            result.putString("failure_class", failure.getClass().getName());
            finish(Activity.RESULT_CANCELED, result);
        }
    }
}
