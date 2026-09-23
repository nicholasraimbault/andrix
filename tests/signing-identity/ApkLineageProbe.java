// SPDX-License-Identifier: Apache-2.0
// Public artifact observations at one SDK boundary. Not installed signer ownership.
import com.android.apksig.ApkVerifier;
import com.android.apksig.SigningCertificateLineage;
import java.io.File;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

public final class ApkLineageProbe {
    private static String sha(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
    private static String identity(X509Certificate certificate) throws Exception {
        byte[] der = certificate.getEncoded(), spki = certificate.getPublicKey().getEncoded();
        if (der.length > 65536 || spki.length > 65536) throw new IllegalArgumentException("public identity bound");
        return "{\"certificate_sha256\":\"" + sha(der) + "\",\"spki_sha256\":\"" + sha(spki)
                + "\",\"certificate_der\":\"" + Base64.getEncoder().encodeToString(der)
                + "\",\"spki_der\":\"" + Base64.getEncoder().encodeToString(spki) + "\"}";
    }
    private static String lineage(SigningCertificateLineage lineage) throws Exception {
        if (lineage == null) return "null";
        List<X509Certificate> certificates = lineage.getCertificatesInLineage();
        if (certificates.isEmpty() || certificates.size() > 64) throw new IllegalArgumentException("lineage bound");
        StringBuilder result = new StringBuilder("[");
        for (int i = 0; i < certificates.size(); i++) {
            if (i != 0) result.append(',');
            X509Certificate certificate = certificates.get(i);
            SigningCertificateLineage.SignerCapabilities capabilities = lineage.getSignerCapabilities(certificate);
            result.append("{\"identity\":").append(identity(certificate)).append(",\"capabilities\":{")
                    .append("\"installed_data\":").append(capabilities.hasInstalledData())
                    .append(",\"shared_uid\":").append(capabilities.hasSharedUid())
                    .append(",\"permission\":").append(capabilities.hasPermission())
                    .append(",\"rollback\":").append(capabilities.hasRollback())
                    .append(",\"auth\":").append(capabilities.hasAuth()).append("}}");
        }
        return result.append(']').toString();
    }
    private static String signer(ApkVerifier.Result.V3SchemeSignerInfo signer) throws Exception {
        if (signer == null) return "null";
        return "{\"min_sdk\":" + signer.getMinSdkVersion() + ",\"max_sdk\":" + signer.getMaxSdkVersion()
                + ",\"targets_dev_release\":" + signer.getSignerTargetsDevRelease()
                + ",\"contains_errors\":" + signer.containsErrors()
                + ",\"lineage\":" + lineage(signer.getSigningCertificateLineage()) + "}";
    }
    private static String signers(List<ApkVerifier.Result.V3SchemeSignerInfo> signers) throws Exception {
        if (signers.size() > 64) throw new IllegalArgumentException("signer bound");
        StringBuilder result = new StringBuilder("[");
        for (int i = 0; i < signers.size(); i++) {
            if (i != 0) result.append(',');
            result.append(signer(signers.get(i)));
        }
        return result.append(']').toString();
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("APK and SDK required");
        int sdk = Integer.parseInt(args[1]);
        if (sdk < 1 || sdk > 1000) throw new IllegalArgumentException("SDK bound");
        ApkVerifier.Result verified = new ApkVerifier.Builder(new File(args[0]))
                .setMinCheckedPlatformVersion(sdk).setMaxCheckedPlatformVersion(sdk).build().verify();
        if (!verified.isVerified()) {
            for (ApkVerifier.IssueWithParams error : verified.getAllErrors()) {
                System.err.println("APK_ISSUE " + error.getIssue().name());
            }
            System.exit(1);
        }
        List<X509Certificate> current = verified.getSignerCertificates();
        if (current.isEmpty() || current.size() > 64) throw new IllegalArgumentException("current signer bound");
        StringBuilder result = new StringBuilder("{\"version\":1,\"sdk\":").append(sdk)
                .append(",\"artifact_verified\":true,\"schemes_verified\":{")
                .append("\"v1\":").append(verified.isVerifiedUsingV1Scheme())
                .append(",\"v2\":").append(verified.isVerifiedUsingV2Scheme())
                .append(",\"v3\":").append(verified.isVerifiedUsingV3Scheme())
                .append(",\"v31\":").append(verified.isVerifiedUsingV31Scheme())
                .append(",\"v32\":").append(verified.isVerifiedUsingV32Scheme())
                .append("},\"current_signers\":[");
        for (int i = 0; i < current.size(); i++) {
            if (i != 0) result.append(',');
            result.append(identity(current.get(i)));
        }
        result.append("],\"combined_lineage\":").append(lineage(verified.getSigningCertificateLineage()))
                .append(",\"v3_signers\":").append(signers(verified.getV3SchemeSigners()))
                .append(",\"v31_signers\":").append(signers(verified.getV31SchemeSigners()));
        ApkVerifier.Result.V32SchemeSignerInfo hybrid = verified.getV32SchemeSigner();
        result.append(",\"v32_signer\":");
        if (hybrid == null) result.append("null");
        else result.append("{\"classical\":").append(signer(hybrid.getClassicalSignerInfo()))
                .append(",\"pqc\":").append(signer(hybrid.getPqcSignerInfo())).append('}');
        result.append(",\"scope\":\"lineages exposed by successful verification at this SDK\"")
                .append(",\"installed_history_or_key_ownership_proved\":false}");
        System.out.println(result);
    }
}
