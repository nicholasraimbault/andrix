// SPDX-License-Identifier: Apache-2.0
// Public certificate observation through the pinned apksig implementation.
// This verifies an artifact at one SDK level. It does not authorize a signer,
// enumerate its full rotation lineage or prove an installed package's identity.
import com.android.apksig.ApkVerifier;
import java.io.File;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

public final class ApkIdentityProbe {
    private static String sha(byte[] value) throws Exception {
        return java.util.HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(value));
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("APK and SDK required");
        int sdk = Integer.parseInt(args[1]);
        if (sdk < 1 || sdk > 1000) throw new IllegalArgumentException("Invalid SDK");
        ApkVerifier.Result result = new ApkVerifier.Builder(new File(args[0]))
                .setMinCheckedPlatformVersion(sdk)
                .setMaxCheckedPlatformVersion(sdk)
                .build().verify();
        if (!result.isVerified()) {
            // Do not publish a successful observation around unverified input.
            System.err.println("APK signature verification failed");
            System.err.println(result.getErrors());
            System.exit(1);
        }
        List<X509Certificate> certs = result.getSignerCertificates();
        if (certs.isEmpty() || certs.size() > 32) {
            throw new IllegalArgumentException("Unexpected signer count");
        }
        StringBuilder out = new StringBuilder("{\"version\":1,\"sdk\":")
                .append(sdk).append(",\"artifact_signature_verified\":true,\"signers\":[");
        for (int i = 0; i < certs.size(); ++i) {
            X509Certificate cert = certs.get(i);
            byte[] der = cert.getEncoded();
            byte[] spki = cert.getPublicKey().getEncoded();
            if (der.length > 65536 || spki.length > 65536) {
                throw new IllegalArgumentException("Public identity too large");
            }
            if (i != 0) out.append(',');
            out.append("{\"certificate_der_sha256\":\"").append(sha(der))
                    .append("\",\"spki_der_sha256\":\"").append(sha(spki))
                    .append("\",\"certificate_der_base64\":\"")
                    .append(Base64.getEncoder().encodeToString(der))
                    .append("\",\"spki_der_base64\":\"")
                    .append(Base64.getEncoder().encodeToString(spki)).append("\"}");
        }
        out.append("],\"signer_authorized\":false,\"rotation_lineage_enumerated\":false}");
        System.out.println(out);
    }
}
