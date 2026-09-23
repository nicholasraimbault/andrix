// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.signingcustody;
import java.security.MessageDigest;
import java.util.HexFormat;
/** Shape for coordinator metadata tests only. No APK signing implementation. */
final class ApkArtifactSigner {
    interface Backend { void awaitSignature(ArtifactRequest artifact, SigningRequest signature); }
    static void executeClaimed(ArtifactRequest artifact, byte[] certificate, Backend backend) {
        throw new AssertionError("deliberate metadata worker failure, no APK signer executed");
    }
    static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
