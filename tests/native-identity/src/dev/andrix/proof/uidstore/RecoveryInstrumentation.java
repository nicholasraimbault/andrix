// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.uidstore;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Context;
import android.os.Bundle;
import android.os.Process;
import android.os.SystemClock;
import android.os.UserManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import org.json.JSONObject;

/**
 * Ordinary app UID fixture, not native entry, designation or protected signing custody.
 * Only initialize creates dummy state. Observe and absent never create a key or a file.
 * Partial initialization is an owned unknown result, not permission to rerun initialization.
 */
public final class RecoveryInstrumentation extends Instrumentation {
    private RecoveryRequest request;

    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        request = new RecoveryRequest(arguments == null ? null : arguments.getString("operation"),
                arguments == null ? null : arguments.getString("nonce"),
                arguments == null ? null : arguments.getString("setup"),
                arguments == null ? null : arguments.getString("expected_key"));
        start();
    }

    private static String digest(byte[] bytes) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder text = new StringBuilder(64);
        for (byte value : hash) {
            text.append(Character.forDigit((value & 0xff) >>> 4, 16));
            text.append(Character.forDigit(value & 15, 16));
        }
        return text.toString();
    }

    private static byte[] read(File file) throws Exception {
        try (FileInputStream in = new FileInputStream(file)) {
            byte[] bytes = in.readNBytes(513);
            if (bytes.length > 512) throw new IllegalStateException("canary bounds");
            return bytes;
        }
    }

    private static void writeNew(File file, byte[] bytes) throws Exception {
        if (!file.createNewFile()) throw new IllegalStateException("canary already exists");
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(bytes);
            out.flush();
            out.getFD().sync();
        }
    }

    @Override public void onStart() {
        JSONObject result = new JSONObject();
        boolean passed = false;
        String stage = "identity";
        try {
            Context ce = getTargetContext();
            String name = ce.getPackageName();
            if (!name.equals("dev.andrix.proof.uidstore")
                    && !name.equals("dev.andrix.proof.uidstorepeer")) {
                throw new IllegalStateException("unexpected fixture package");
            }
            int uid = Process.myUid();
            if (uid != ce.getApplicationInfo().uid || uid < 10000 || uid > 19999) {
                throw new IllegalStateException("ordinary user zero UID required");
            }
            android.content.pm.Signature[] apkSigners = ce.getPackageManager().getPackageInfo(name,
                    android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES).signingInfo.getApkContentsSigners();
            if (apkSigners == null || apkSigners.length != 1) throw new IllegalStateException("fixture APK signer count");
            result.put("apk_signer_sha256", digest(apkSigners[0].toByteArray()));
            long userSerial = ce.getSystemService(UserManager.class).getSerialNumberForUser(Process.myUserHandle());
            if (userSerial < 0) throw new IllegalStateException("user serial unavailable");
            result.put("user_serial", userSerial);
            result.put("version", 1).put("operation", request.operation).put("nonce", request.nonce)
                    .put("setup", request.setup).put("package", name).put("uid", uid)
                    .put("pid", Process.myPid()).put("elapsed_ms", SystemClock.elapsedRealtime())
                    .put("user_unlocked", ce.getSystemService(UserManager.class).isUserUnlocked());
            Context de = ce.createDeviceProtectedStorageContext();
            // Context.getFilesDir() creates directories. Observation must not
            // repair missing fixture state, even as a side effect of path lookup.
            File ceRoot = ce.getDataDir();
            File deRoot = de.getDataDir();
            if (ceRoot == null || deRoot == null || !ceRoot.isAbsolute() || !deRoot.isAbsolute()
                    || ce.isDeviceProtectedStorage() || !de.isDeviceProtectedStorage()) {
                throw new IllegalStateException("missing app storage paths");
            }
            File ceDirectory = new File(ceRoot, "files");
            File deDirectory = new File(deRoot, "files");
            File ceFile = new File(ceDirectory, request.fileName());
            File deFile = new File(deDirectory, request.fileName());
            byte[] expected = ("Andrix dummy UID recovery canary\n" + name + "\n" + uid + "\n"
                    + request.setup + "\n").getBytes(StandardCharsets.UTF_8);
            KeyStore keys = KeyStore.getInstance("AndroidKeyStore");
            keys.load(null);
            boolean existingKey = keys.containsAlias(request.alias());
            result.put("key_existed_before", existingKey).put("ce_existed_before", ceFile.exists())
                    .put("de_existed_before", deFile.exists());

            if (request.operation.equals("absent")) {
                stage = "absence";
                passed = !existingKey && !ceFile.exists() && !deFile.exists();
                if (!passed) throw new IllegalStateException("unexpected fixture state");
            } else {
                if (request.operation.equals("initialize")) {
                    stage = "initialize_precondition";
                    if (existingKey || ceFile.exists() || deFile.exists()) {
                        throw new IllegalStateException("initialization already has effects");
                    }
                    if (!ce.getFilesDir().equals(ceDirectory) || !de.getFilesDir().equals(deDirectory)) {
                        throw new IllegalStateException("unexpected fixture storage layout");
                    }
                    stage = "key_generation";
                    KeyPairGenerator generator = KeyPairGenerator.getInstance(
                            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
                    generator.initialize(new KeyGenParameterSpec.Builder(request.alias(),
                            KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                            .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setUserAuthenticationRequired(false).build());
                    generator.generateKeyPair();
                    stage = "de_canary"; writeNew(deFile, expected);
                    stage = "ce_canary"; writeNew(ceFile, expected);
                }
                stage = "observe_existing";
                if (!keys.containsAlias(request.alias()) || !ceFile.isFile() || !deFile.isFile()) {
                    throw new IllegalStateException("fixture state missing; no regeneration");
                }
                byte[] ceBytes = read(ceFile), deBytes = read(deFile);
                boolean ceMatches = Arrays.equals(expected, ceBytes);
                boolean deMatches = Arrays.equals(expected, deBytes);
                PublicKey publicKey = keys.getCertificate(request.alias()).getPublicKey();
                String publicDigest = digest(publicKey.getEncoded());
                boolean keyMatches = request.expectedKey == null || request.expectedKey.equals(publicDigest);
                byte[] challenge = ("Andrix UID recovery challenge/" + request.nonce)
                        .getBytes(StandardCharsets.UTF_8);
                stage = "existing_key_sign";
                Signature signer = Signature.getInstance("SHA256withECDSA");
                signer.initSign((PrivateKey) keys.getKey(request.alias(), null));
                signer.update(challenge);
                byte[] signature = signer.sign();
                Signature verifier = Signature.getInstance("SHA256withECDSA");
                verifier.initVerify(publicKey); verifier.update(challenge);
                boolean verified = verifier.verify(signature);
                result.put("ce_matches", ceMatches).put("de_matches", deMatches)
                        .put("ce_sha256", digest(ceBytes)).put("de_sha256", digest(deBytes))
                        .put("key_matches", keyMatches).put("key_sha256", publicDigest)
                        .put("public_key_der_b64", Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP))
                        .put("signature_b64", Base64.encodeToString(signature, Base64.NO_WRAP))
                        .put("signature_verified", verified);
                passed = ceMatches && deMatches && keyMatches && verified;
            }
            stage = "complete";
        } catch (Exception error) {
            try { result.put("error_class", error.getClass().getName()); }
            catch (Exception ignored) { }
        } finally {
            try { result.put("stage", stage).put("passed", passed); }
            catch (Exception ignored) { }
            Bundle output = new Bundle();
            output.putString("uid_recovery_result", result.toString());
            finish(passed ? Activity.RESULT_OK : Activity.RESULT_CANCELED, output);
        }
    }
}
