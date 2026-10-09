// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A host fake of apksig for the fast suites. It signs a real ZIP with three key operations, v2,
 * v3 and v4, carrying the v2 and v3 signatures in the ZIP comment and the v4 signature in the
 * sidecar, so the entries stay the input's. A fake key's signature is the SHA-256 of its name and
 * the data, and its certificate and public key digests derive from its name. Verification
 * recomputes each signature with the key the output names, so a key that is not the
 * certificate's fails, and reports every signer.
 */
final class FakeEngine implements HostSigner.Engine {
    final String certificate;
    boolean breakV4;

    FakeEngine(String certificate) { this.certificate = certificate; }

    static String certificateDigest(String name) { return DeploymentRecords.sha256Hex(bytes("certificate " + name)); }

    static String keyDigest(String name) { return DeploymentRecords.sha256Hex(bytes("key " + name)); }

    static HostSigner.Keys key(String name) {
        return (data, algorithm) -> DeploymentRecords.sha256(concat(bytes(name + " "), data), name.length() + 1 + data.length);
    }

    @Override
    public HostSigner.Signed sign(byte[] input, HostSigner.Keys keys) throws GeneralSecurityException {
        String entries = ApkEntries.digest(input);
        byte[] v2 = keys.sign(bytes("v2 " + entries), "SHA256withRSA");
        byte[] v3 = keys.sign(bytes("v3 " + entries), "SHA256withRSA");
        byte[] apk = withComment(input, "signed " + certificate + " " + hex(v2) + " " + hex(v3));
        byte[] v4 = keys.sign(bytes("v4 " + DeploymentRecords.sha256Hex(apk)), "SHA256withRSA");
        byte[] idsig = bytes("idsig " + certificate + " " + hex(breakV4 ? new byte[32] : v4));
        return new HostSigner.Signed(apk, idsig);
    }

    @Override
    public HostSigner.Verification verify(byte[] apk, byte[] idsig, int sdkMin, int sdkMax) {
        try {
            String[] sig = comment(apk).split(" ");
            String[] side = new String(idsig, StandardCharsets.US_ASCII).split(" ");
            if (sig.length != 4 || !sig[0].equals("signed") || side.length != 3 || !side[0].equals("idsig")) {
                return new HostSigner.Verification(false, false, false, List.of());
            }
            String entries = ApkEntries.digest(apk);
            boolean v2 = hex(key(sig[1]).sign(bytes("v2 " + entries), "")).equals(sig[2]);
            boolean v3 = hex(key(sig[1]).sign(bytes("v3 " + entries), "")).equals(sig[3]);
            boolean v4 = hex(key(side[1]).sign(bytes("v4 " + DeploymentRecords.sha256Hex(apk)), "")).equals(side[2]);
            List<String[]> signers = new ArrayList<>();
            signers.add(new String[] {certificateDigest(sig[1]), keyDigest(sig[1])});
            signers.add(new String[] {certificateDigest(sig[1]), keyDigest(sig[1])});
            signers.add(new String[] {certificateDigest(side[1]), keyDigest(side[1])});
            return new HostSigner.Verification(v2, v3, v4, signers);
        } catch (GeneralSecurityException | RuntimeException e) {
            return new HostSigner.Verification(false, false, false, List.of());
        }
    }

    static byte[] bytes(String s) { return s.getBytes(StandardCharsets.US_ASCII); }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] c = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x & 0xff));
        return s.toString();
    }

    // Replaces the ZIP comment of an archive written without one.
    static byte[] withComment(byte[] zip, String comment) {
        int eocd = zip.length - 22;
        ByteBuffer b = ByteBuffer.wrap(zip).order(ByteOrder.LITTLE_ENDIAN);
        if (b.getInt(eocd) != 0x06054b50) throw new IllegalArgumentException("a ZIP with a comment");
        byte[] text = bytes(comment);
        byte[] out = Arrays.copyOf(zip, zip.length + text.length);
        ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN).putShort(eocd + 20, (short) text.length);
        System.arraycopy(text, 0, out, zip.length, text.length);
        return out;
    }

    static String comment(byte[] zip) {
        for (int at = zip.length - 22; at >= 0; at--) {
            ByteBuffer b = ByteBuffer.wrap(zip).order(ByteOrder.LITTLE_ENDIAN);
            if (b.getInt(at) == 0x06054b50 && at + 22 + (b.getShort(at + 20) & 0xffff) == zip.length) {
                return new String(zip, at + 22, zip.length - at - 22, StandardCharsets.US_ASCII);
            }
        }
        throw new IllegalArgumentException("no end of central directory");
    }
}
