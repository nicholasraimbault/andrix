// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.signingcustody;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;
import com.android.apksig.KeyConfig;
import com.android.apksig.SignerEngine;
import com.android.apksig.apk.ApkUtils;
import com.android.apksig.internal.apk.v1.V1SchemeVerifier;
import com.android.apksig.internal.zip.CentralDirectoryRecord;
import com.android.apksig.kms.KmsSignerEngineProvider;
import com.android.apksig.util.DataSink;
import com.android.apksig.util.DataSinks;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.DataSources;
import com.android.apksig.util.ReadableDataSink;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Finite APK v2 vehicle. No key export, network provider or authority from an APK. */
public final class ApkArtifactSigner {
    private ApkArtifactSigner() {}
    static final int MAX_APK = 1024 * 1024;
    static final int MAX_OUTPUT = 2 * MAX_APK;
    private static final String PROVIDER_TYPE = "andrix-disposable-local-apk-v2";
    private static final ThreadLocal<Binding> ACTIVE = new ThreadLocal<>();

    interface Backend {
        /** Wait for this exact request and actual crypto operation retirement.
         * A timeout must not abandon an unresolved signing or abort operation.
         * This is not an ambient UID grant or a second result publication channel.
         */
        void awaitSignature(ArtifactRequest artifact, SigningRequest signature)
                throws GeneralSecurityException, InterruptedException;
    }

    static final class Metadata {
        final String packageName;
        final long versionCode;
        final int minSdk;
        final int targetSdk;
        Metadata(String packageName, long versionCode, int minSdk, int targetSdk) {
            this.packageName = packageName; this.versionCode = versionCode;
            this.minSdk = minSdk; this.targetSdk = targetSdk;
        }
    }

    private static final class Binding {
        final ArtifactRequest artifact;
        final Backend backend;
        int calls;
        Binding(ArtifactRequest artifact, Backend backend) {
            this.artifact = artifact; this.backend = backend;
        }
    }

    /** Captive ServiceLoader entry. APK input cannot select this class or its alias. */
    public static final class Provider implements KmsSignerEngineProvider {
        public Provider() {}
        @Override public String getKmsType() { return PROVIDER_TYPE; }
        @Override public SignerEngine getInstance(KeyConfig.Kms config, String algorithm,
                AlgorithmParameterSpec parameters) {
            Binding binding = ACTIVE.get();
            if (binding == null || !binding.artifact.workerOwned()
                    || !binding.artifact.id().equals(config.keyAlias)) {
                throw new IllegalStateException("no bound artifact operation");
            }
            if (!"SHA256withRSA".equals(algorithm) || parameters != null) {
                throw new IllegalArgumentException("unqualified APK signature algorithm");
            }
            return data -> {
                ArtifactRequest artifact = binding.artifact;
                if (ACTIVE.get() != binding || !artifact.workerOwned()
                        || artifact.cancellationRequested() || ++binding.calls != 1) {
                    throw new SignatureException("artifact operation unavailable");
                }
                SigningRequest signature = new SigningRequest(artifact.id(), artifact.requesterUid(),
                        artifact.androidUser(), ArtifactRequest.PURPOSE,
                        artifact.certificateSha256(), data);
                if (!artifact.attachSignature(signature)) {
                    throw new SignatureException("artifact signature request refused");
                }
                try { binding.backend.awaitSignature(artifact, signature); }
                catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new SignatureException("artifact signer interrupted", interrupted);
                } catch (GeneralSecurityException failure) {
                    throw new SignatureException("artifact signer failed", failure);
                }
                byte[] completed = signature.signature();
                if (artifact.cancellationRequested() || signature.state() != SigningRequest.State.COMPLETE
                        || completed == null) {
                    throw new SignatureException("artifact signature not completed for this request");
                }
                return completed;
            };
        }
    }

    static Metadata inspect(byte[] apk) throws Exception {
        if (apk == null || apk.length == 0 || apk.length > MAX_APK) {
            throw new IllegalArgumentException("APK fixture bound");
        }
        byte[] inspected = apk.clone();
        DataSource source = DataSources.asDataSource(ByteBuffer.wrap(inspected).asReadOnlyBuffer());
        List<CentralDirectoryRecord> entries = V1SchemeVerifier.parseZipCentralDirectory(
                source, ApkUtils.findZipSections(source));
        if (entries.isEmpty() || entries.size() > 256) throw new IllegalArgumentException("ZIP entry bound");
        Set<String> names = new HashSet<>();
        long total = 0;
        for (CentralDirectoryRecord entry : entries) {
            if (!names.add(entry.getName())) throw new IllegalArgumentException("duplicate ZIP entry");
            long size = entry.getUncompressedSize();
            if (size < 0 || size > 16L * MAX_APK - total) {
                throw new IllegalArgumentException("uncompressed fixture bound");
            }
            total += size;
            if (entry.getName().equals("AndroidManifest.xml") && (size == 0 || size > 256 * 1024)) {
                throw new IllegalArgumentException("manifest bound");
            }
        }
        ByteBuffer manifest = ApkUtils.getAndroidManifest(source);
        String name = ApkUtils.getPackageNameFromBinaryAndroidManifest(manifest.duplicate());
        long version = ApkUtils.getLongVersionCodeFromBinaryAndroidManifest(manifest.duplicate());
        int minimum = ApkUtils.getMinSdkVersionFromBinaryAndroidManifest(manifest.duplicate());
        int target = ApkUtils.getTargetSdkVersionFromBinaryAndroidManifest(manifest.duplicate());
        if (name == null || version <= 0 || minimum != 37 || target != 37
                || ApkUtils.getDebuggableFromBinaryAndroidManifest(manifest.duplicate())) {
            throw new IllegalArgumentException("unqualified APK metadata");
        }
        return new Metadata(name, version, minimum, target);
    }

    /** Claims only this worker ticket. A false return owns no cleanup for another worker. */
    static boolean execute(ArtifactRequest artifact, byte[] certificateBytes, Backend backend)
            throws Exception {
        if (!artifact.claimWorker()) return false;
        try {
            if (ACTIVE.get() != null || artifact.cancellationRequested()) {
                throw new IllegalStateException("overlapping or cancelled artifact");
            }
            byte[] input = artifact.apk();
            Metadata metadata = inspect(input);
            if (!metadata.packageName.equals(artifact.packageName())
                    || metadata.versionCode != artifact.versionCode()
                    || !sha256(input).equals(artifact.artifactSha256())) {
                throw new IllegalArgumentException("artifact metadata changed");
            }
            if (certificateBytes == null || certificateBytes.length == 0 || certificateBytes.length > 65536) {
                throw new IllegalArgumentException("artifact certificate bound");
            }
            byte[] certificateCopy = certificateBytes.clone();
            if (!sha256(certificateCopy).equals(artifact.certificateSha256())) {
                throw new IllegalArgumentException("expected artifact certificate");
            }
            ByteArrayInputStream encoded = new ByteArrayInputStream(certificateCopy);
            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(encoded);
            if (encoded.available() != 0 || !Arrays.equals(certificateCopy, certificate.getEncoded())
                    || !(certificate.getPublicKey() instanceof RSAPublicKey)
                    || ((RSAPublicKey) certificate.getPublicKey()).getModulus().bitLength() != 2048) {
                throw new IllegalArgumentException("unqualified artifact key or certificate encoding");
            }
            Binding binding = new Binding(artifact, backend);
            BoundedSink output = new BoundedSink();
            ApkSigner.SignerConfig config = new ApkSigner.SignerConfig.Builder("ANDRIX_TEST",
                    new KeyConfig.Kms(PROVIDER_TYPE, artifact.id()), List.of(certificate)).build();
            ACTIVE.set(binding);
            try {
                new ApkSigner.Builder(List.of(config))
                        .setInputApk(DataSources.asDataSource(ByteBuffer.wrap(input).asReadOnlyBuffer()))
                        .setOutputApk(output).setMinSdkVersion(37)
                        .setV1SigningEnabled(false).setV2SigningEnabled(true)
                        .setV3SigningEnabled(false).setV4SigningEnabled(false)
                        .setOtherSignersSignaturesPreserved(false).build().sign();
                if (binding.calls != 1 || !artifact.beginFinalizing()) {
                    throw new SignatureException("artifact completion refused");
                }
                ApkVerifier.Result result = new ApkVerifier.Builder(output)
                        .setMinCheckedPlatformVersion(37).setMaxCheckedPlatformVersion(37).build().verify();
                if (!result.isVerified() || !result.isVerifiedUsingV2Scheme()
                        || result.isVerifiedUsingV1Scheme() || result.isVerifiedUsingV3Scheme()
                        || result.getSignerCertificates().size() != 1
                        || !Arrays.equals(result.getSignerCertificates().get(0).getEncoded(), certificateCopy)) {
                    throw new SignatureException("complete artifact verification failed");
                }
                byte[] complete = new byte[(int) output.size()];
                output.copyTo(0, complete.length, ByteBuffer.wrap(complete));
                if (!artifact.completeVerifiedOutput(complete)) {
                    throw new SignatureException("artifact publication refused");
                }
            } finally {
                ACTIVE.remove();
            }
            return true;
        } finally {
            // fail() does not replace an already published terminal result. It
            // acknowledges cancellation when preparation or verification failed.
            artifact.fail();
            if (!artifact.retireWorker()) throw new IllegalStateException("artifact worker retirement");
        }
    }

    static String sha256(byte[] bytes) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
            StringBuilder value = new StringBuilder(64);
            for (byte item : digest) value.append(String.format("%02x", item & 255));
            return value.toString();
        } catch (GeneralSecurityException unavailable) { throw new AssertionError(unavailable); }
    }

    private static final class BoundedSink implements ReadableDataSink {
        private final ReadableDataSink sink = DataSinks.newInMemoryDataSink();
        private void room(int count) throws IOException {
            if (count < 0 || sink.size() > (long) MAX_OUTPUT - count) throw new IOException("output bound");
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
}
