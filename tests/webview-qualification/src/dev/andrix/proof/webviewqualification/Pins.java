package dev.andrix.proof.webviewqualification;

import android.app.Instrumentation;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Process;
import android.webkit.WebView;

import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.json.JSONArray;
import org.json.JSONObject;

final class Pins {
    static final String SELF = "dev.andrix.proof.webviewqualification";
    static final String PROVIDER = "dev.andrix.experiment.webview";
    static final String CONFIG = "dev.andrix.experiment.webviewconfig";
    static final String SIGNER = "6c292164d3710a4fd44b91d90fd3a2c894fe4c6945dd41f52493ffb19389b5b3";
    static final String DEX = "1a2dcd3b0af00bbb4c52ba215245dfc7c86011b8a4b2318d445d5db2ad7cf755";
    static final ComponentName SAFE_SERVICE = new ComponentName(PROVIDER,
            "org.chromium.android_webview.services.SafeModeService");
    static final ComponentName SAFE_ALIAS = new ComponentName(PROVIDER,
            "org.chromium.android_webview.SafeModeState");
    static final ComponentName JOB_SERVICE = new ComponentName(PROVIDER,
            "org.chromium.android_webview.services.AwVariationsSeedFetcher");

    static void guard(Instrumentation runner, Session s, boolean providerTarget) throws Exception {
        Context target = runner.getTargetContext();
        PackageManager pm = target.getPackageManager();
        s.record("identity", "sdk", Build.VERSION.SDK_INT, "fingerprint", Build.FINGERPRINT,
                "expected_fingerprint", s.args.fingerprint, "process_uid", Process.myUid(),
                "target_package", target.getPackageName(),
                "target_uid", target.getApplicationInfo().uid,
                "instrumentation_package", runner.getContext().getPackageName(),
                "authority", providerTarget ? "provider-uid-white-box" : "own-uid",
                "different_signer_ordinary_authority_proved", false);
        Arguments.check(Build.VERSION.SDK_INT == 37, "Only API 37 is qualified");
        Arguments.check(s.args.fingerprint.equals(Build.FINGERPRINT), "Fingerprint mismatch");
        Arguments.check(SELF.equals(runner.getContext().getPackageName()), "Unexpected test package");

        PackageInfo self = packageInfo(pm, SELF);
        PackageInfo provider = packageInfo(pm, PROVIDER);
        int testPlatform = pm.checkSignatures(SELF, "android");
        int providerPlatform = pm.checkSignatures(PROVIDER, "android");
        s.record("packages", "test", describe(self), "provider", describe(provider),
                "test_provider_signature_match", pm.checkSignatures(SELF, PROVIDER),
                "test_platform_signature_match", testPlatform,
                "provider_platform_signature_match", providerPlatform);
        Arguments.check(testPlatform == PackageManager.SIGNATURE_NO_MATCH
                        && providerPlatform == PackageManager.SIGNATURE_NO_MATCH,
                "Fixture and provider must not use the platform signer");
        ApplicationInfo app = self.applicationInfo;
        Arguments.check(app != null && app.uid >= 10000 && self.sharedUserId == null
                        && (app.flags & (ApplicationInfo.FLAG_SYSTEM
                                | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) == 0
                        && (app.flags & ApplicationInfo.FLAG_TEST_ONLY) != 0
                        && app.minSdkVersion == 37 && app.targetSdkVersion == 37
                        && (self.requestedPermissions == null || self.requestedPermissions.length == 0),
                "Expected an unprivileged, permission-free, SDK-37 test-only installation");
        Arguments.check(provider.applicationInfo != null
                        && PROVIDER.equals(provider.packageName)
                        && provider.sharedUserId == null
                        && provider.applicationInfo.uid >= 10000
                        && provider.applicationInfo.uid != app.uid,
                "Provider and fixture must have distinct application UIDs, without shared UID");
        String expectedTarget = providerTarget ? PROVIDER : SELF;
        int expectedUid = providerTarget ? provider.applicationInfo.uid : app.uid;
        Arguments.check(expectedTarget.equals(target.getPackageName())
                        && target.getApplicationInfo().uid == expectedUid
                        && Process.myUid() == expectedUid,
                "Mode/target/process UID mismatch");
        if (providerTarget) {
            Arguments.check(pm.checkSignatures(SELF, PROVIDER) == PackageManager.SIGNATURE_MATCH,
                    "Provider instrumentation requires the real provider signer");
        }
        Signature[] signers = provider.signingInfo == null ? null
                : provider.signingInfo.getApkContentsSigners();
        Arguments.check(signers != null && signers.length == 1
                        && SIGNER.equals(sha256(signers[0].toByteArray()))
                        && pm.hasSigningCertificate(PROVIDER, unhex(SIGNER),
                                PackageManager.CERT_INPUT_SHA256),
                "Provider current signer does not match the frozen disposable certificate");
        s.providerSource = provider.applicationInfo.publicSourceDir;
        Arguments.check(s.providerSource != null, "No public provider APK source");
        String dex = hashDex(s.providerSource, s);
        s.record("provider_dex", "public_source_dir", s.providerSource,
                "entry", "classes.dex", "sha256", dex, "expected_sha256", DEX);
        Arguments.check(DEX.equals(dex), "Provider classes.dex mismatch; no operation permitted");
        selectedProvider(s, "guard");
        s.requireRunning();
    }

    static void selectedProvider(Session s, String point) throws Exception {
        PackageInfo selected = WebView.getCurrentWebViewPackage();
        s.record("selected_webview", "point", point,
                "package", selected == null ? null : selected.packageName,
                "version_code", selected == null ? null : selected.getLongVersionCode(),
                "version_name", selected == null ? null : selected.versionName,
                "public_source_dir", selected == null || selected.applicationInfo == null
                        ? null : selected.applicationInfo.publicSourceDir);
        Arguments.check(selected != null && PROVIDER.equals(selected.packageName)
                        && selected.applicationInfo != null
                        && s.providerSource.equals(selected.applicationInfo.publicSourceDir),
                "Selected/loaded WebView is not the guarded provider APK");
    }

    static PackageInfo packageInfo(PackageManager pm, String name) throws Exception {
        return pm.getPackageInfo(name,
                PackageManager.GET_SIGNING_CERTIFICATES | PackageManager.GET_PERMISSIONS);
    }

    static JSONObject describe(PackageInfo info) throws Exception {
        JSONArray current = new JSONArray();
        JSONArray history = new JSONArray();
        if (info.signingInfo != null) {
            for (Signature signer : info.signingInfo.getApkContentsSigners()) {
                current.put(sha256(signer.toByteArray()));
            }
            Signature[] past = info.signingInfo.getSigningCertificateHistory();
            if (past != null) {
                for (Signature signer : past) {
                    history.put(sha256(signer.toByteArray()));
                }
            }
        }
        ApplicationInfo app = info.applicationInfo;
        return Session.object("package", info.packageName, "version_code", info.getLongVersionCode(),
                "version_name", info.versionName, "uid", app == null ? null : app.uid,
                "source_dir", app == null ? null : app.sourceDir,
                "public_source_dir", app == null ? null : app.publicSourceDir,
                "flags", app == null ? null : app.flags, "shared_user_id", info.sharedUserId,
                "requested_permissions", new JSONArray(info.requestedPermissions == null
                        ? new String[0] : info.requestedPermissions),
                "current_signer_sha256", current, "signing_history_sha256", history);
    }

    private static String hashDex(String source, Session s) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (ZipFile zip = new ZipFile(source)) {
            int count = 0;
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                String name = entries.nextElement().getName();
                if (name.endsWith(".dex")) {
                    Arguments.check(name.equals("classes.dex"), "Unexpected extra DEX entry: " + name);
                    count++;
                }
            }
            Arguments.check(count == 1, "Expected exactly one classes.dex entry");
            ZipEntry entry = zip.getEntry("classes.dex");
            long total = 0;
            try (InputStream input = zip.getInputStream(entry)) {
                byte[] buffer = new byte[32768];
                int read;
                while ((read = input.read(buffer)) != -1) {
                    s.requireRunning();
                    total += read;
                    Arguments.check(total <= 64 * 1024 * 1024, "Provider DEX exceeds bounded input size");
                    digest.update(buffer, 0, read);
                }
            }
            Arguments.check(total > 0 && total == entry.getSize(), "Incomplete provider DEX read");
        }
        return hex(digest.digest());
    }

    static String sha256(byte[] bytes) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    static String hex(byte[] bytes) {
        char[] chars = new char[bytes.length * 2];
        String digits = "0123456789abcdef";
        for (int i = 0; i < bytes.length; i++) {
            chars[2 * i] = digits.charAt((bytes[i] & 255) >>> 4);
            chars[2 * i + 1] = digits.charAt(bytes[i] & 15);
        }
        return new String(chars);
    }

    static byte[] unhex(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }
}
