/* SPDX-License-Identifier: Apache-2.0 */
package dev.andrix.proof.apksigning;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;
import com.android.apksig.KeyConfig;
import com.android.apksig.SignerEngine;
import com.android.apksig.kms.KmsSignerEngineProvider;
import com.android.apksig.util.DataSink;
import com.android.apksig.util.DataSinks;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.DataSources;
import com.android.apksig.util.ReadableDataSink;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/** Host API probe only. No Android caller authentication or protected key claim. */
public final class ApkCallbackProbe {
    private static final int MAX_APK = 1024 * 1024;
    private static final String TYPE = "andrix-local-host-fixture";
    private static final ThreadLocal<Context> ACTIVE = new ThreadLocal<>();
    private enum Mode { SIGN, REFUSE, BAD_SIGNATURE }

    private static final class Context {
        final String alias = UUID.randomUUID().toString();
        final PrivateKey key;
        final String artifactHash;
        final String certificateHash;
        final Mode mode;
        boolean open = true;
        int calls;
        int aliasRefusals;
        long partialOutput;
        String algorithm;
        String signedDataHash;
        int signedDataBytes;
        Context(PrivateKey key, String artifactHash, String certificateHash, Mode mode) {
            this.key = key;
            this.artifactHash = artifactHash;
            this.certificateHash = certificateHash;
            this.mode = mode;
        }
    }

    /** Registered only on the deliberately controlled probe classpath. */
    public static final class CallbackProvider implements KmsSignerEngineProvider {
        public CallbackProvider() {}
        @Override public String getKmsType() { return TYPE; }
        @Override public SignerEngine getInstance(KeyConfig.Kms config, String algorithm,
                AlgorithmParameterSpec parameters) {
            Context context = ACTIVE.get();
            if (context == null || !context.open) throw new IllegalStateException("no operation");
            if (!context.alias.equals(config.keyAlias)) {
                context.aliasRefusals++;
                throw new IllegalArgumentException("wrong operation alias");
            }
            if (!"SHA256withRSA".equals(algorithm) || parameters != null) {
                throw new IllegalArgumentException("unqualified signature algorithm or parameters");
            }
            return data -> {
                if (ACTIVE.get() != context || !context.open) {
                    throw new SignatureException("operation retired");
                }
                if (++context.calls != 1) throw new SignatureException("unexpected second call");
                // Trusted library data is copied before any backend work. This
                // thread context is plumbing, not a user authorization boundary.
                byte[] immutableData = data.clone();
                context.algorithm = algorithm;
                context.signedDataBytes = immutableData.length;
                context.signedDataHash = digest(immutableData);
                if (context.mode == Mode.REFUSE) throw new SignatureException("fixture refusal");
                Signature signer = Signature.getInstance(algorithm);
                signer.initSign(context.key);
                signer.update(immutableData);
                byte[] signature = signer.sign();
                if (context.mode == Mode.BAD_SIGNATURE) signature[signature.length - 1] ^= 1;
                return signature;
            };
        }
    }

    private static final class BoundedSink implements ReadableDataSink {
        private final ReadableDataSink sink = DataSinks.newInMemoryDataSink();
        private void room(int count) throws IOException {
            if (count < 0 || sink.size() > 2L * MAX_APK - count) {
                throw new IOException("fixture output bound");
            }
        }
        @Override public void consume(byte[] bytes, int offset, int length) throws IOException {
            room(length); sink.consume(bytes, offset, length);
        }
        @Override public void consume(ByteBuffer bytes) throws IOException {
            room(bytes.remaining()); sink.consume(bytes);
        }
        @Override public long size() { return sink.size(); }
        @Override public void feed(long offset, long size, DataSink target) throws IOException {
            sink.feed(offset, size, target);
        }
        @Override public ByteBuffer getByteBuffer(long offset, int size) throws IOException {
            return sink.getByteBuffer(offset, size).asReadOnlyBuffer();
        }
        @Override public void copyTo(long offset, int size, ByteBuffer target) throws IOException {
            sink.copyTo(offset, size, target);
        }
        @Override public DataSource slice(long offset, long size) { return sink.slice(offset, size); }
    }

    private static String digest(byte[] bytes) {
        try {
            byte[] value = MessageDigest.getInstance("SHA-256").digest(bytes);
            StringBuilder text = new StringBuilder(64);
            for (byte item : value) text.append(String.format("%02x", item & 255));
            return text.toString();
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static byte[] sign(byte[] callerBytes, Context context, X509Certificate certificate,
            String alias, boolean mutateCaller) throws Exception {
        if (callerBytes.length == 0 || callerBytes.length > MAX_APK || ACTIVE.get() != null) {
            throw new IllegalStateException("fixture input or overlapping operation");
        }
        byte[] owned = callerBytes.clone();
        if (!digest(owned).equals(context.artifactHash)
                || !digest(certificate.getEncoded()).equals(context.certificateHash)) {
            throw new IllegalArgumentException("wrong expected artifact or certificate");
        }
        if (mutateCaller) Arrays.fill(callerBytes, (byte) 0);
        DataSource input = DataSources.asDataSource(ByteBuffer.wrap(owned).asReadOnlyBuffer());
        BoundedSink output = new BoundedSink();
        ApkSigner.SignerConfig signer = new ApkSigner.SignerConfig.Builder("ANDRIX_TEST",
                new KeyConfig.Kms(TYPE, alias), List.of(certificate)).build();
        ACTIVE.set(context);
        try {
            new ApkSigner.Builder(List.of(signer)).setInputApk(input).setOutputApk(output)
                    .setMinSdkVersion(37).setV1SigningEnabled(false).setV2SigningEnabled(true)
                    .setV3SigningEnabled(false).setV4SigningEnabled(false)
                    .setOtherSignersSignaturesPreserved(false).build().sign();
            if (!digest(owned).equals(context.artifactHash)) throw new AssertionError("input changed");
            ApkVerifier.Result result = new ApkVerifier.Builder(output)
                    .setMinCheckedPlatformVersion(37).setMaxCheckedPlatformVersion(37).build().verify();
            if (!result.isVerified() || !result.isVerifiedUsingV2Scheme()
                    || result.isVerifiedUsingV1Scheme() || result.isVerifiedUsingV3Scheme()
                    || result.getSignerCertificates().size() != 1
                    || !Arrays.equals(result.getSignerCertificates().get(0).getEncoded(),
                                      certificate.getEncoded())) {
                throw new SignatureException("output verification or identity mismatch");
            }
            byte[] complete = new byte[(int) output.size()];
            output.copyTo(0, complete.length, ByteBuffer.wrap(complete));
            return complete;
        } finally {
            context.partialOutput = output.size();
            context.open = false;
            ACTIVE.remove();
        }
    }

    private static void refused(String label, byte[] input, Context context,
            X509Certificate certificate, boolean wrongAlias, Path output) throws Exception {
        if (Files.exists(output)) throw new AssertionError("unexpected prior output");
        boolean rejected = false;
        try {
            byte[] complete = sign(input, context, certificate,
                    wrongAlias ? "not-the-bound-operation" : context.alias, false);
            // This branch must never publish any artifact for the negative.
            if (complete.length > 0) throw new AssertionError("negative unexpectedly signed");
        } catch (SignatureException | IllegalArgumentException expected) {
            rejected = true;
        }
        if (!rejected || Files.exists(output) || ACTIVE.get() != null) {
            throw new AssertionError("refusal or ownership failure");
        }
        if (wrongAlias ? context.aliasRefusals != 1 || context.calls != 0 : context.calls != 1) {
            throw new AssertionError("negative did not reach intended layer");
        }
        System.out.println("NEGATIVE_PASS " + label + " callbacks=" + context.calls
                + " local_partial_bytes=" + context.partialOutput + " published=false");
    }

    public static void main(String[] args) {
        try { run(args); }
        catch (Throwable failure) {
            // The private frame must not be included in provider exception text.
            System.err.println("HOST_APK_PROBE_FAILURE " + failure.getClass().getName());
            System.exit(1);
        }
    }

    private static void run(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("APK path, expected hash, output dir");
        Path apk = Path.of(args[0]); Path output = Path.of(args[2]);
        if (Files.size(apk) > MAX_APK || !Files.isDirectory(output)) {
            throw new IllegalArgumentException("fixture paths");
        }
        try (java.util.stream.Stream<Path> files = Files.list(output)) {
            if (files.findAny().isPresent()) throw new IllegalArgumentException("fixture output not empty");
        }
        byte[] input = Files.readAllBytes(apk);
        if (!digest(input).equals(args[1])) throw new IllegalArgumentException("input commitment");
        // Private frame comes only from local stdin. Do not log it or serialize
        // its private key into evidence. These are explicitly disposable keys.
        DataInputStream frame = new DataInputStream(System.in);
        if (!Arrays.equals(frame.readNBytes(8), new byte[]{'A','N','D','R','K','0','0','1'})
                || frame.readInt() != 1) throw new IllegalArgumentException("private frame");
        int keySize = frame.readInt(); int certSize = frame.readInt();
        if (keySize < 1 || keySize > 65536 || certSize < 1 || certSize > 65536) {
            throw new IllegalArgumentException("private frame bounds");
        }
        byte[] privateBytes = frame.readNBytes(keySize); byte[] certBytes = frame.readNBytes(certSize);
        if (privateBytes.length != keySize || certBytes.length != certSize || frame.read() != -1) {
            throw new IllegalArgumentException("private frame completeness");
        }
        PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateBytes));
        Arrays.fill(privateBytes, (byte) 0); // Not comprehensive JVM/provider erasure.
        ByteArrayInputStream encodedCertificate = new ByteArrayInputStream(certBytes);
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(encodedCertificate);
        if (encodedCertificate.available() != 0 || !Arrays.equals(certBytes, certificate.getEncoded())) {
            throw new IllegalArgumentException("exact certificate required");
        }
        String certHash = digest(certBytes);
        Context positive = new Context(key, args[1], certHash, Mode.SIGN);
        byte[] signed = sign(input.clone(), positive, certificate, positive.alias, true);
        if (positive.calls != 1 || positive.open || ACTIVE.get() != null) throw new AssertionError("ownership");
        Files.write(output.resolve("signed-v2.apk"), signed, StandardOpenOption.CREATE_NEW);
        Files.write(output.resolve("expected-certificate.der"), certBytes, StandardOpenOption.CREATE_NEW);
        System.out.println("HOST_APK_CALLBACK_PASS callbacks=" + positive.calls + " algorithm="
                + positive.algorithm + " signed_data_bytes=" + positive.signedDataBytes
                + " signed_data_sha256=" + positive.signedDataHash + " input_sha256=" + args[1]
                + " output_sha256=" + digest(signed) + " certificate_sha256=" + certHash
                + " caller_mutation_did_not_change_snapshot=true");
        refused("backend-refusal", input, new Context(key, args[1], certHash, Mode.REFUSE),
                certificate, false, output.resolve("refused.apk"));
        refused("wrong-signature", input, new Context(key, args[1], certHash, Mode.BAD_SIGNATURE),
                certificate, false, output.resolve("bad-signature.apk"));
        refused("wrong-operation-alias", input, new Context(key, args[1], certHash, Mode.SIGN),
                certificate, true, output.resolve("wrong-alias.apk"));
        System.out.println("NO_ANDROID_CUSTODY_AUTHENTICATION_OR_DURABLE_PUBLICATION_CLAIM");
    }
}
