// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;
import com.android.apksig.Constants;
import com.android.apksig.KeyConfig;
import com.android.apksig.SignerEngine;
import com.android.apksig.internal.apk.v3.V3SchemeConstants;
import com.android.apksig.kms.KmsSignerEngineProvider;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * apksig as the host signer's engine. It runs against the pinned apksigner jar, whose SHA-256 is
 * {@link #PINNED_JAR}, with the options the sealed SystemUI outputs were signed with:
 * {@code apksigner sign --v4-signing-enabled true --min-sdk-version 37} and every other option at
 * the tool's default, except v1. The tool's default also signs v1, a fourth key operation for each
 * APK, and the sealed outputs carry it. Decision 8's transaction has three operations for each APK,
 * v2, v3 and v4, so the transaction's engine signs without v1. The engine with v1 serves only the
 * byte for byte comparison with the sealed outputs. Each key operation goes through a KMS key
 * configuration whose provider calls the host signer's keys, so the signer counts, asks and may
 * refuse every operation. The private key never reaches apksig. Host only.
 */
public final class ApksigEngine implements HostSigner.Engine {
    /** The SHA-256 of the apksigner jar this engine is pinned to. */
    public static final String PINNED_JAR = "6b96559764325d085a6bad6be109cc3053791d63826f84dc0e74032db136a196";
    /** The declared minimum SDK of the signed SystemUI APKs. */
    public static final int MIN_SDK = 37;
    static final String KMS = "andrix-host-signer";
    private static final ThreadLocal<HostSigner.Keys> KEYS = new ThreadLocal<>();

    /** The provider that apksig finds through its service loader. */
    public static final class Provider implements KmsSignerEngineProvider {
        @Override
        public String getKmsType() { return KMS; }

        @Override
        public SignerEngine getInstance(KeyConfig.Kms config, String algorithm, AlgorithmParameterSpec parameters) {
            return data -> {
                HostSigner.Keys keys = KEYS.get();
                if (keys == null) throw new SignatureException("no signing transaction is running");
                try {
                    return keys.sign(data, algorithm);
                } catch (SignatureException e) {
                    throw e;
                } catch (GeneralSecurityException e) {
                    throw new SignatureException(e);
                }
            };
        }
    }

    private final List<X509Certificate> certificates;
    private final Path work;
    private final boolean v1;

    /**
     * @param work a private scratch directory for apksig's files
     * @param v1 whether to sign v1 as the tool's default does: only to reproduce the sealed outputs
     */
    public ApksigEngine(X509Certificate certificate, Path work, boolean v1) {
        this.certificates = List.of(Objects.requireNonNull(certificate, "certificate"));
        this.work = Objects.requireNonNull(work, "work");
        this.v1 = v1;
    }

    @Override
    public HostSigner.Signed sign(byte[] input, HostSigner.Keys keys) throws Exception {
        Path in = work.resolve("input.apk");
        Path out = work.resolve("base.apk");
        Path v4 = work.resolve("base.apk.idsig");
        Files.write(in, input);
        Files.deleteIfExists(out);
        Files.deleteIfExists(v4);
        KEYS.set(keys);
        try {
            ApkSigner.SignerConfig signer = new ApkSigner.SignerConfig.Builder("platform",
                    new KeyConfig.Kms(KMS, "platform"), certificates, false).build();
            new ApkSigner.Builder(List.of(signer))
                    .setInputApk(in.toFile())
                    .setOutputApk(out.toFile())
                    .setOtherSignersSignaturesPreserved(false)
                    .setV1SigningEnabled(v1)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setV4SigningEnabled(true)
                    .setForceSourceStampOverwrite(false)
                    .setSourceStampTimestampEnabled(true)
                    .setAlignFileSize(false)
                    .setVerityEnabled(false)
                    .setV4ErrorReportingEnabled(true)
                    .setDebuggableApkPermitted(true)
                    .setSigningCertificateLineage(null)
                    .setMinSdkVersionForRotation(V3SchemeConstants.DEFAULT_ROTATION_MIN_SDK_VERSION)
                    .setRotationTargetsDevRelease(false)
                    .setAlignmentPreserved(false)
                    .setLibraryPageAlignmentBytes(Constants.LIBRARY_PAGE_ALIGNMENT_BYTES)
                    .setMinSdkVersion(MIN_SDK)
                    .setV4SignatureOutputFile(v4.toFile())
                    .build()
                    .sign();
            return new HostSigner.Signed(Files.readAllBytes(out), Files.readAllBytes(v4));
        } finally {
            KEYS.remove();
            Files.deleteIfExists(in);
            Files.deleteIfExists(out);
            Files.deleteIfExists(v4);
        }
    }

    @Override
    public HostSigner.Verification verify(byte[] apk, byte[] idsig, int sdkMin, int sdkMax) {
        Path a = work.resolve("verify.apk");
        Path v = work.resolve("verify.apk.idsig");
        try {
            Files.write(a, apk);
            Files.write(v, idsig);
            // v2 with a pass below SDK 28, where apksig does not skip it for v3.
            ApkVerifier.Result low = new ApkVerifier.Builder(a.toFile()).setMinCheckedPlatformVersion(24)
                    .setMaxCheckedPlatformVersion(27).build().verify();
            // v3 and v4 over the declared range.
            ApkVerifier.Result range = new ApkVerifier.Builder(a.toFile()).setMinCheckedPlatformVersion(sdkMin)
                    .setMaxCheckedPlatformVersion(sdkMax == 0xffff ? Integer.MAX_VALUE : sdkMax)
                    .setV4SignatureFile(v.toFile()).build().verify();
            List<String[]> signers = new ArrayList<>();
            for (ApkVerifier.Result.V2SchemeSignerInfo s : low.getV2SchemeSigners()) signers.add(identity(s.getCertificate()));
            for (ApkVerifier.Result.V3SchemeSignerInfo s : range.getV3SchemeSigners()) {
                signers.add(identity(s.getCertificate()));
            }
            for (ApkVerifier.Result.V4SchemeSignerInfo s : range.getV4SchemeSigners()) {
                signers.add(identity(s.getCertificate()));
            }
            return new HostSigner.Verification(low.isVerified() && low.isVerifiedUsingV2Scheme(),
                    range.isVerified() && range.isVerifiedUsingV3Scheme(),
                    range.isVerified() && range.isVerifiedUsingV4Scheme(), signers);
        } catch (Exception e) {
            return new HostSigner.Verification(false, false, false, List.of());
        } finally {
            try {
                Files.deleteIfExists(a);
                Files.deleteIfExists(v);
            } catch (IOException ignored) {
                // Scratch only.
            }
        }
    }

    /** A certificate's SHA-256 and its public key's SHA-256. */
    static String[] identity(X509Certificate c) throws CertificateEncodingException {
        return new String[] {DeploymentRecords.sha256Hex(c.getEncoded()),
            DeploymentRecords.sha256Hex(c.getPublicKey().getEncoded())};
    }
}
