// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * A host fake of apksig for the fast suites. It signs a real ZIP with three key operations, v2,
 * v3 and v4. The v2 and v3 signatures go into a real APK Signing Block before the central
 * directory, and the v4 signature into the sidecar, so the entries stay the input's. Like apksig,
 * it drops any signing block its input carries. A fake key's signature is the SHA-256 of its name
 * and the data, and its certificate and public key digests derive from its name. Verification
 * recomputes each scheme's signature with the key its signer names, so a key that is not the
 * certificate's fails, and reports each scheme's signer. Its binary manifest parser reads
 * {@code key=value} words from the archive's {@code AndroidManifest.xml}.
 *
 * <p>Modes model engines that must not pass: one that swallows each key operation's exception,
 * one that makes more than three key operations, one that returns its input as the APK, one that
 * discards the operations' results and signs with the key itself, one that names another
 * certificate for a scheme, and one that signs other bytes than its input.
 */
final class FakeEngine implements HostSigner.Engine {
    static final int V2_BLOCK = 0x7109871a;
    static final int V3_BLOCK = 0xf05368c0;

    final String certificate;
    boolean breakV4;
    boolean swallow;
    /** Key operations made after the three, for each APK. */
    int extraOperations;
    /** Returns the input it was given as the APK, with a sidecar for those bytes. */
    boolean returnInput;
    /** Makes its operations over other data, discards their results and signs with the key itself. */
    boolean forge;
    /**
     * The certificate the v2, v3 and v4 signers name, or null for this engine's own. Another
     * certificate's signature is made with that certificate's key, and the operation's result is
     * kept beside it.
     */
    final String[] schemeCertificates = new String[3];
    /** Signs these bytes instead of its input. */
    byte[] substitute;

    FakeEngine(String certificate) { this.certificate = certificate; }

    static String certificateDigest(String name) { return DeploymentRecords.sha256Hex(bytes("certificate " + name)); }

    static String keyDigest(String name) { return DeploymentRecords.sha256Hex(bytes("key " + name)); }

    static HostSigner.Keys key(String name) {
        return (data, algorithm) -> DeploymentRecords.sha256(concat(bytes(name + " "), data), name.length() + 1 + data.length);
    }

    @Override
    public HostSigner.Signed sign(byte[] input, HostSigner.Keys keys) throws GeneralSecurityException {
        byte[] unsigned = ApkEntries.withoutSigningBlock(substitute != null ? substitute : input);
        String entries = ApkEntries.digest(unsigned);
        String prefix = forge ? "other " : "";
        byte[] v2 = operation(keys, bytes(prefix + "v2 " + entries));
        byte[] v3 = operation(keys, bytes(prefix + "v3 " + entries));
        byte[] apk = returnInput ? input.clone() : withBlock(unsigned, block(
                scheme(V2_BLOCK, value(0, "v2 " + entries, v2)), scheme(V3_BLOCK, value(1, "v3 " + entries, v3))));
        String v4Data = "v4 " + DeploymentRecords.sha256Hex(apk);
        byte[] v4 = operation(keys, bytes(prefix + v4Data));
        for (int i = 0; i < extraOperations; i++) operation(keys, bytes("extra " + i));
        byte[] idsig = concat(bytes("idsig"), value(2, v4Data, breakV4 ? new byte[32] : v4));
        return new HostSigner.Signed(apk, idsig);
    }

    private byte[] operation(HostSigner.Keys keys, byte[] data) throws GeneralSecurityException {
        try {
            return keys.sign(data, "SHA256withRSA");
        } catch (GeneralSecurityException refused) {
            if (!swallow) throw refused;
            return new byte[32];
        }
    }

    // One scheme's signer: the certificate it names, the signature verification reads, and the
    // operation's result when the signature is not that result.
    private byte[] value(int scheme, String data, byte[] result) throws GeneralSecurityException {
        String named = schemeCertificates[scheme] == null ? certificate : schemeCertificates[scheme];
        byte[] signature = forge || !named.equals(certificate) ? key(named).sign(bytes(data), "") : result;
        byte[] kept = Arrays.equals(signature, result) || forge ? new byte[0] : result;
        return concat(concat(field(bytes(named)), field(signature)), field(kept));
    }

    @Override
    public HostSigner.Verification verify(byte[] apk, byte[] idsig, int sdkMin, int sdkMax) {
        try {
            Map<Integer, byte[]> block = parseBlock(ApkEntries.signingBlock(apk));
            String entries = ApkEntries.digest(apk);
            byte[] prefix = bytes("idsig");
            if (!block.containsKey(V2_BLOCK) || !block.containsKey(V3_BLOCK) || idsig.length < prefix.length
                    || !Arrays.equals(Arrays.copyOf(idsig, prefix.length), prefix)) {
                return new HostSigner.Verification(false, false, false, List.of());
            }
            byte[][] s2 = fields(block.get(V2_BLOCK));
            byte[][] s3 = fields(block.get(V3_BLOCK));
            byte[][] s4 = fields(Arrays.copyOfRange(idsig, prefix.length, idsig.length));
            boolean v2 = verifies(s2, "v2 " + entries);
            boolean v3 = verifies(s3, "v3 " + entries);
            boolean v4 = verifies(s4, "v4 " + DeploymentRecords.sha256Hex(apk));
            List<String[]> signers = new ArrayList<>();
            for (byte[][] s : List.of(s2, s3, s4)) {
                String name = new String(s[0], StandardCharsets.US_ASCII);
                signers.add(new String[] {certificateDigest(name), keyDigest(name)});
            }
            return new HostSigner.Verification(v2, v3, v4, signers);
        } catch (GeneralSecurityException | RuntimeException e) {
            return new HostSigner.Verification(false, false, false, List.of());
        }
    }

    private static boolean verifies(byte[][] signer, String data) throws GeneralSecurityException {
        String name = new String(signer[0], StandardCharsets.US_ASCII);
        return Arrays.equals(key(name).sign(bytes(data), ""), signer[1]);
    }

    /** The words of the archive's AndroidManifest.xml, or null without one. */
    @Override
    public HostSigner.Facts facts(byte[] apk) {
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(apk))) {
            for (ZipEntry e = zip.getNextEntry(); e != null; e = zip.getNextEntry()) {
                if (!e.getName().equals("AndroidManifest.xml")) continue;
                Map<String, String> words = new HashMap<>();
                for (String word : new String(zip.readAllBytes(), StandardCharsets.US_ASCII).split(" ")) {
                    int at = word.indexOf('=');
                    if (at > 0) words.put(word.substring(0, at), word.substring(at + 1));
                }
                if (!words.containsKey("package") || !words.containsKey("versionCode")) return null;
                return new HostSigner.Facts(words.get("package"), Long.parseLong(words.get("versionCode")),
                        words.getOrDefault("sharedUserId", ""), "true".equals(words.get("persistent")),
                        Integer.parseInt(words.getOrDefault("minSdk", "1")),
                        Integer.parseInt(words.getOrDefault("targetSdk", "1")),
                        Integer.parseInt(words.getOrDefault("maxSdk", "0")));
            }
            return null;
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /** A manifest's words for the fake parser. */
    static String manifest(String packageName, long versionCode, String sharedUserId, boolean persistent, int minSdk) {
        return "package=" + packageName + " versionCode=" + versionCode + " sharedUserId=" + sharedUserId
                + " persistent=" + persistent + " minSdk=" + minSdk + " targetSdk=" + minSdk;
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

    private static byte[] field(byte[] b) {
        return concat(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(b.length).array(), b);
    }

    private static byte[][] fields(byte[] b) {
        ByteBuffer in = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);
        byte[][] out = new byte[3][];
        for (int i = 0; i < 3; i++) {
            out[i] = new byte[in.getInt()];
            in.get(out[i]);
        }
        return out;
    }

    // One ID and value pair of an APK Signing Block.
    private static byte[] scheme(int id, byte[] value) {
        return ByteBuffer.allocate(12 + value.length).order(ByteOrder.LITTLE_ENDIAN).putLong(4 + value.length)
                .putInt(id).put(value).array();
    }

    // An APK Signing Block of the given pairs: its size, the pairs, its size again and its magic.
    static byte[] block(byte[]... pairs) {
        int length = 0;
        for (byte[] p : pairs) length += p.length;
        ByteBuffer b = ByteBuffer.allocate(8 + length + 8 + 16).order(ByteOrder.LITTLE_ENDIAN);
        b.putLong(length + 24);
        for (byte[] p : pairs) b.put(p);
        b.putLong(length + 24).put(bytes("APK Sig Block 42"));
        return b.array();
    }

    private static Map<Integer, byte[]> parseBlock(byte[] block) {
        Map<Integer, byte[]> pairs = new HashMap<>();
        ByteBuffer in = ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN);
        if (block.length < 32) return pairs;
        in.position(8);
        while (in.position() < block.length - 24) {
            long length = in.getLong();
            int id = in.getInt();
            byte[] value = new byte[(int) length - 4];
            in.get(value);
            pairs.put(id, value);
        }
        return pairs;
    }

    // Inserts a signing block before the central directory of an archive that has none.
    static byte[] withBlock(byte[] zip, byte[] block) {
        ByteBuffer b = ByteBuffer.wrap(zip).order(ByteOrder.LITTLE_ENDIAN);
        int eocd = zip.length - 22;
        while (eocd >= 0 && b.getInt(eocd) != 0x06054b50) eocd--;
        int central = b.getInt(eocd + 16);
        byte[] out = new byte[zip.length + block.length];
        System.arraycopy(zip, 0, out, 0, central);
        System.arraycopy(block, 0, out, central, block.length);
        System.arraycopy(zip, central, out, central + block.length, zip.length - central);
        ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN).putInt(eocd + block.length + 16, central + block.length);
        return out;
    }
}
