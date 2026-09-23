// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.signingcustody;

import android.content.Context;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.CancellationSignal;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Lab only, one key in this APK's APP namespace. No installer or root authority. */
final class ProofBroker {
    static final String ALIAS = "andrix.proof.disposable.signing";
    static final String PURPOSE = "sign-disposable-test-payload";
    private static final byte[] MAGIC = "ANDRK001".getBytes(StandardCharsets.US_ASCII);
    private static final int MAX_IMPORT = 131072;
    private static ProofBroker instance;

    static synchronized ProofBroker get(Context context) {
        if (instance == null) instance = new ProofBroker(context.getApplicationContext());
        return instance;
    }

    final String epoch = UUID.randomUUID().toString();
    private final Context context;
    private final ExecutorService signer = Executors.newSingleThreadExecutor();
    private final LinkedHashMap<String, SigningRequest> requests = new LinkedHashMap<>();
    private final LinkedHashMap<String, String> failures = new LinkedHashMap<>();
    private long next = 1;
    private String expectedCertificate;
    private String expectedSpki;
    private String importState = "UNCONFIGURED";
    private String importFailure;
    private boolean importPending;
    private boolean importCancelled;
    private static final class Operation {
        final SigningRequest request;
        final CancellationSignal cancellation = new CancellationSignal();
        Signature signature;
        X509Certificate certificate;
        boolean preparing = true;
        boolean retiring;
        Operation(SigningRequest request) { this.request = request; }
    }
    private Operation active;

    private ProofBroker(Context context) { this.context = context; }

    static String sha(byte[] data) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);
        StringBuilder result = new StringBuilder();
        for (byte b : hash) result.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
        return result.toString();
    }

    private static void require(boolean value, String message) {
        if (!value) throw new IllegalStateException(message);
    }

    private static KeyStore store() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        return store;
    }

    private static String errorClasses(Throwable error) {
        // Class names only. Do not log input bytes, private objects or exception
        // messages which might incorporate an untrusted request or key encoding.
        StringBuilder result = new StringBuilder();
        for (int i = 0; error != null && i < 8; i++, error = error.getCause()) {
            if (i != 0) result.append(" <- ");
            result.append(error.getClass().getName());
        }
        return result.toString();
    }

    synchronized JSONObject configure(String certificate, String spki) throws Exception {
        require(!importPending && requests.isEmpty(), "operation still owned");
        require(certificate != null && certificate.matches("[0-9a-f]{64}")
                && spki != null && spki.matches("[0-9a-f]{64}"), "public commitments required");
        if (expectedCertificate != null) {
            require(expectedCertificate.equals(certificate) && expectedSpki.equals(spki),
                    "cannot replace configured identity");
        }
        expectedCertificate = certificate;
        expectedSpki = spki;
        if (store().containsAlias(ALIAS)) {
            checkedCertificate(store());
            importState = "EXISTING_EXPECTED_KEY";
        } else {
            importState = "CONFIGURED";
        }
        return status();
    }

    synchronized ParcelFileDescriptor importPipe() throws Exception {
        require(expectedCertificate != null && !importPending && requests.isEmpty(),
                "import not available");
        require(!store().containsAlias(ALIAS), "refusing to overwrite a key");
        ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createReliablePipe();
        importPending = true;
        importCancelled = false;
        importState = "READING";
        importFailure = null;
        Thread reader = new Thread(() -> consumeImport(pipe[0]), "disposable-key-import");
        try { reader.start(); }
        catch (RuntimeException | Error notStarted) {
            try { pipe[0].close(); } catch (java.io.IOException error) { notStarted.addSuppressed(error); }
            try { pipe[1].close(); } catch (java.io.IOException error) { notStarted.addSuppressed(error); }
            importPending = false; importState = "READER_NOT_STARTED"; throw notStarted;
        }
        return pipe[1];
    }

    synchronized JSONObject cancelImport() throws Exception {
        if (importPending) importCancelled = true;
        // Ownership remains until the actual reader/import returns.
        return new JSONObject().put("import_cancel_requested", importCancelled)
                .put("import_pending", importPending).put("import_state", importState);
    }

    private void consumeImport(ParcelFileDescriptor input) {
        byte[] packet = null;
        byte[] privateDer = null;
        try (ParcelFileDescriptor.AutoCloseInputStream stream =
                     new ParcelFileDescriptor.AutoCloseInputStream(input)) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            long end = SystemClock.elapsedRealtime() + 30000;
            while (true) {
                synchronized (this) { require(!importCancelled, "import cancelled"); }
                require(SystemClock.elapsedRealtime() < end, "import input deadline");
                StructPollfd item = new StructPollfd();
                item.fd = input.getFileDescriptor();
                item.events = (short) (OsConstants.POLLIN | OsConstants.POLLHUP);
                int ready = Os.poll(new StructPollfd[]{item}, 250);
                if (ready == 0) continue;
                require((item.revents & (OsConstants.POLLERR | OsConstants.POLLNVAL)) == 0,
                        "import descriptor failed");
                int count = stream.read(buffer);
                if (count < 0) break;
                require(bytes.size() + count <= MAX_IMPORT, "import size bound");
                bytes.write(buffer, 0, count);
            }
            Arrays.fill(buffer, (byte) 0);
            packet = bytes.toByteArray();
            require(packet.length >= 20, "truncated import");
            ByteBuffer frame = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN);
            byte[] magic = new byte[8]; frame.get(magic);
            int version = frame.getInt(), privateSize = frame.getInt(), certSize = frame.getInt();
            require(Arrays.equals(magic, MAGIC) && version == 1 && privateSize > 0
                    && privateSize <= 65536 && certSize > 0 && certSize <= 65536
                    && frame.remaining() == privateSize + certSize, "invalid import frame");
            privateDer = new byte[privateSize]; frame.get(privateDer);
            byte[] certDer = new byte[certSize]; frame.get(certDer);
            PrivateKey software = KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(privateDer));
            ByteArrayInputStream certInput = new ByteArrayInputStream(certDer);
            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(certInput);
            require(certInput.available() == 0 && Arrays.equals(certificate.getEncoded(), certDer),
                    "certificate encoding mismatch");
            synchronized (this) {
                require(!importCancelled && sha(certDer).equals(expectedCertificate)
                        && sha(certificate.getPublicKey().getEncoded()).equals(expectedSpki),
                        "unexpected import identity");
                importState = "IMPORTING";
            }
            // Fixed internal proof of key/certificate association, not a caller's
            // arbitrary signing request. The protected device copy is not used.
            byte[] challenge = ("ANDRIX_DISPOSABLE_IMPORT_CHECK:" + expectedCertificate
                    + ":" + expectedSpki).getBytes(StandardCharsets.US_ASCII);
            Signature check = Signature.getInstance("SHA256withRSA");
            check.initSign(software); check.update(challenge); byte[] association = check.sign();
            check.initVerify(certificate); check.update(challenge);
            require(check.verify(association), "private/certificate disagreement");
            KeyProtection protection = new KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(0, KeyProperties.AUTH_DEVICE_CREDENTIAL)
                    .setUnlockedDeviceRequired(true)
                    .build();
            KeyStore store = store();
            synchronized (this) {
                require(!importCancelled && !store.containsAlias(ALIAS), "import cancelled or occupied");
            }
            store.setEntry(ALIAS, new KeyStore.PrivateKeyEntry(software,
                    new Certificate[]{certificate}), protection);
            checkedCertificate(store);
            synchronized (this) {
                // Cancellation during the synchronous import does not pretend
                // the key was never created. Report the owned result explicitly.
                importState = importCancelled ? "IMPORTED_AFTER_CANCELLATION" : "READY";
            }
        } catch (Throwable error) {
            synchronized (this) { importState = "FAILED_OUTCOME_REQUIRES_INSPECTION";
                importFailure = errorClasses(error); }
        } finally {
            if (packet != null) Arrays.fill(packet, (byte) 0);
            if (privateDer != null) Arrays.fill(privateDer, (byte) 0);
            // This does not erase all provider/VM copies or prove physical erasure.
            synchronized (this) { importPending = false; }
        }
    }

    private synchronized X509Certificate checkedCertificate(KeyStore store) throws Exception {
        require(expectedCertificate != null, "identity not configured");
        X509Certificate certificate = (X509Certificate) store.getCertificate(ALIAS);
        require(certificate != null && sha(certificate.getEncoded()).equals(expectedCertificate)
                && sha(certificate.getPublicKey().getEncoded()).equals(expectedSpki),
                "device identity differs from owner record");
        return certificate;
    }

    private PrivateKey checkedPrivateKey(KeyStore store) throws Exception {
        checkedCertificate(store);
        PrivateKey key = (PrivateKey) store.getKey(ALIAS, null);
        require(key != null && key.getEncoded() == null && key.getFormat() == null,
                "device key unexpectedly exportable");
        KeyInfo info = KeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore")
                .getKeySpec(key, KeyInfo.class);
        require(info.isUserAuthenticationRequired()
                && info.getUserAuthenticationValidityDurationSeconds() == 0
                && info.getUserAuthenticationType() == KeyProperties.AUTH_DEVICE_CREDENTIAL,
                "unexpected authentication policy");
        return key;
    }

    synchronized JSONObject status() throws Exception {
        JSONObject result = new JSONObject();
        result.put("epoch", epoch).put("uid", android.os.Process.myUid())
                .put("user", android.os.Process.myUid() / 100000)
                .put("import_state", importState).put("import_pending", importPending)
                .put("import_cancel_requested", importCancelled)
                .put("operation_owned", active != null)
                .put("operation_preparing", active != null && active.preparing)
                .put("operation_retiring", active != null && active.retiring)
                .put("import_failure_classes", importFailure == null ? JSONObject.NULL : importFailure);
        KeyStore store = store();
        boolean present = store.containsAlias(ALIAS); result.put("key_present", present);
        if (present && expectedCertificate != null) {
            X509Certificate cert = checkedCertificate(store);
            PrivateKey key = checkedPrivateKey(store);
            KeyInfo info = KeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore")
                    .getKeySpec(key, KeyInfo.class);
            result.put("certificate_sha256", sha(cert.getEncoded()))
                    .put("spki_sha256", sha(cert.getPublicKey().getEncoded()))
                    .put("private_encoding_absent", key.getEncoded() == null)
                    .put("authentication_required", info.isUserAuthenticationRequired())
                    .put("authentication_duration", info.getUserAuthenticationValidityDurationSeconds())
                    .put("authentication_type", info.getUserAuthenticationType())
                    .put("reported_security_level", info.getSecurityLevel())
                    .put("physical_hardware_proved", false);
        }
        JSONArray rows = new JSONArray();
        for (SigningRequest request : requests.values()) rows.put(requestStatus(request));
        result.put("requests", rows);
        return result;
    }

    synchronized SigningRequest request(int uid, String purpose, String certificate, byte[] payload)
            throws Exception {
        require(!importPending && active == null && requests.size() < 16
                && next > 0 && next < Long.MAX_VALUE,
                "request capacity or import busy");
        for (SigningRequest old : requests.values()) {
            SigningRequest.State state = old.state();
            require(state == SigningRequest.State.COMPLETE || state == SigningRequest.State.CANCELLED
                    || state == SigningRequest.State.FAILED, "another request is active");
        }
        require(PURPOSE.equals(purpose) && expectedCertificate != null
                && expectedCertificate.equals(certificate), "wrong purpose or key");
        checkedPrivateKey(store());
        SigningRequest request = new SigningRequest(epoch + "." + next++, uid, 0,
                purpose, certificate, payload);
        requests.put(request.id(), request);
        return request;
    }

    synchronized SigningRequest find(String id) {
        SigningRequest result = requests.get(id);
        require(result != null, "unknown or stale request");
        return result;
    }

    synchronized JSONObject requestStatus(SigningRequest request) throws Exception {
        JSONObject result = new JSONObject();
        result.put("id", request.id()).put("requester_uid", request.requesterUid())
                .put("user", request.androidUser()).put("purpose", request.purpose())
                .put("certificate_sha256", request.certificateSha256())
                .put("payload_sha256", request.payloadSha256()).put("payload_bytes", request.payload().length)
                .put("state", request.state().name()).put("cancel_requested", request.cancellationRequested());
        byte[] signature = request.signature();
        result.put("signature_base64", signature == null ? JSONObject.NULL
                : Base64.encodeToString(signature, Base64.NO_WRAP));
        result.put("failure_classes", failures.containsKey(request.id())
                ? failures.get(request.id()) : JSONObject.NULL);
        return result;
    }

    synchronized JSONObject preAuthenticationNegative() throws Exception {
        require(!importPending && active == null, "negative requires idle key");
        for (SigningRequest request : requests.values()) {
            require(request.state() == SigningRequest.State.COMPLETE
                    || request.state() == SigningRequest.State.CANCELLED
                    || request.state() == SigningRequest.State.FAILED, "request still active");
        }
        Signature signature = Signature.getInstance("SHA256withRSA");
        X509Certificate certificate = checkedCertificate(store());
        try {
            signature.initSign(checkedPrivateKey(store()));
            signature.update("ANDRIX_NO_AUTH_NEGATIVE".getBytes(StandardCharsets.US_ASCII));
            signature.sign();
            throw new AssertionError("signature produced without fresh authentication");
        } catch (java.security.GeneralSecurityException error) {
            boolean authenticationRequired = false;
            for (Throwable cause = error; cause != null; cause = cause.getCause()) {
                if (cause instanceof android.security.keystore.UserNotAuthenticatedException) {
                    authenticationRequired = true;
                }
                if (cause instanceof android.security.KeyStoreException) {
                    android.security.KeyStoreException keyError = (android.security.KeyStoreException) cause;
                    authenticationRequired |= keyError.requiresUserAuthentication()
                            && keyError.getNumericErrorCode()
                               == android.security.KeyStoreException.ERROR_USER_AUTHENTICATION_REQUIRED;
                }
            }
            require(authenticationRequired, "failure was not an authentication refusal");
            return new JSONObject().put("refused_without_authentication", true)
                    .put("exception_classes", errorClasses(error));
        } finally {
            // Reinitialization explicitly asks the provider to abort its old
            // operation. The provider can log a daemon error while dropping its
            // reference, so this is not a physical/backend erasure assertion.
            signature.initVerify(certificate);
        }
    }

    void approve(ApprovalActivity activity, SigningRequest request) {
        final Operation current;
        synchronized (this) {
            // A stale or duplicate presentation cannot fail, replace or abort
            // someone else's live operation, including this request's signer.
            if (requests.get(request.id()) != request || active != null
                    || !request.beginAuthentication()) {
                activity.refresh(); return;
            }
            current = new Operation(request);
            active = current;
        }
        try {
            KeyStore store = store();
            X509Certificate certificate = checkedCertificate(store);
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(checkedPrivateKey(store));
            synchronized (this) {
                current.certificate = certificate;
                current.signature = signature;
                current.preparing = false;
            }
            if (request.state() != SigningRequest.State.AUTHENTICATING) {
                retire(current); activity.refresh(); return;
            }
            BiometricPrompt prompt = new BiometricPrompt.Builder(activity)
                    .setTitle("Authorize disposable signing")
                    .setSubtitle("Key " + request.certificateSha256().substring(0, 16))
                    .setDescription("Payload " + request.payloadSha256())
                    .setAllowedAuthenticators(BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                    .build();
            prompt.authenticate(new BiometricPrompt.CryptoObject(signature), current.cancellation,
                    activity.getMainExecutor(), new BiometricPrompt.AuthenticationCallback() {
                        @Override public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                            boolean claimed = false;
                            synchronized (ProofBroker.this) {
                                if (active == current && !current.preparing && !current.retiring
                                        && request.state() == SigningRequest.State.AUTHENTICATING) {
                                    if (result.getCryptoObject() != null
                                            && result.getCryptoObject().getSignature() == signature
                                            && result.getAuthenticationType()
                                               == BiometricPrompt.AUTHENTICATION_RESULT_TYPE_DEVICE_CREDENTIAL) {
                                        claimed = request.claimSigning();
                                    } else {
                                        request.fail(); failures.put(request.id(), "wrong_authentication_binding");
                                    }
                                }
                            }
                            if (!claimed) { retire(current); activity.refresh(); return; }
                            try { signer.execute(() -> finishSignature(activity, current)); }
                            catch (RuntimeException rejected) {
                                request.fail();
                                synchronized (ProofBroker.this) { failures.put(request.id(), errorClasses(rejected)); }
                                retire(current); activity.refresh();
                            }
                        }
                        @Override public void onAuthenticationError(int errorCode, CharSequence message) {
                            synchronized (ProofBroker.this) {
                                if (active != current
                                        || request.state() != SigningRequest.State.AUTHENTICATING) return;
                                request.cancel(); failures.put(request.id(), "authentication_error_" + errorCode);
                            }
                            retire(current); activity.refresh();
                        }
                    });
        } catch (Throwable error) {
            synchronized (this) {
                request.fail(); failures.put(request.id(), errorClasses(error));
                current.preparing = false;
            }
            retire(current); activity.refresh();
        }
    }

    private void finishSignature(ApprovalActivity activity, Operation current) {
        SigningRequest request = current.request;
        try {
            current.signature.update(request.payload());
            byte[] result = current.signature.sign();
            Signature verify = Signature.getInstance("SHA256withRSA");
            verify.initVerify(current.certificate); verify.update(request.payload());
            require(verify.verify(result), "signature does not match expected public identity");
            require(request.complete(result), "unexpected signing completion");
        } catch (Throwable error) {
            request.fail(); synchronized (this) { failures.put(request.id(), errorClasses(error)); }
        } finally {
            retire(current);
            activity.runOnUiThread(activity::refresh);
        }
    }

    private void retire(Operation current) {
        synchronized (this) {
            if (active != current || current.preparing || current.retiring
                    || current.request.state() == SigningRequest.State.SIGNING) return;
            current.retiring = true;
        }
        boolean done = false;
        try {
            if (current.signature != null) current.signature.initVerify(current.certificate);
            done = true;
        } catch (Exception error) {
            synchronized (this) {
                failures.put(current.request.id(), "operation_retirement_" + errorClasses(error));
            }
        } finally {
            synchronized (this) {
                current.retiring = false;
                if (done && active == current) active = null;
            }
        }
        // Public JCA reinitialization requests provider abort. The provider's
        // hidden error handling and daemon resource release are separate facts;
        // no synchronous hardware erasure guarantee is inferred here.
    }

    void cancel(String id) {
        final Operation current;
        synchronized (this) {
            SigningRequest request = find(id); request.cancel();
            current = active != null && active.request == request ? active : null;
        }
        if (current != null) {
            current.cancellation.cancel();
            retire(current); // SIGNING remains owned until its actual callback.
        }
    }

    synchronized JSONObject deleteKey() throws Exception {
        require(!importPending && active == null, "operation remains owned");
        for (SigningRequest request : requests.values()) {
            require(request.state() == SigningRequest.State.COMPLETE
                    || request.state() == SigningRequest.State.CANCELLED
                    || request.state() == SigningRequest.State.FAILED, "request remains active");
        }
        KeyStore store = store(); checkedCertificate(store); store.deleteEntry(ALIAS);
        require(!store.containsAlias(ALIAS), "key still present");
        importState = "DELETED";
        return status();
    }
}
