// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * The identity of an APK's ZIP entries outside its signatures: the SHA-256 over each central
 * directory entry, in order, of its name, method, CRC-32, sizes and the SHA-256 of its stored
 * data. The APK Signing Block, the JAR signature files of v1 ({@code META-INF/MANIFEST.MF} and
 * the {@code .SF}, {@code .RSA}, {@code .DSA}, {@code .EC} and {@code SIG-} files directly in
 * {@code META-INF/}), offsets, local extra fields and the ZIP comment are left out. Those names
 * match with ASCII letters folded and every other byte exact, so a name that differs from a
 * signature file only by a letter outside ASCII, such as the long s, stays an entry. A built APK,
 * its signed output and a realigned copy of either therefore give the same digest exactly when
 * they hold the same entries. ZIP64 archives are refused.
 */
public final class ApkEntries {
    private static final int EOCD = 0x06054b50;
    private static final int CENTRAL = 0x02014b50;
    private static final int LOCAL = 0x04034b50;

    private ApkEntries() {}

    /** The entry digest of a ZIP archive, as lowercase hex. Throws IllegalArgumentException if it is no plain ZIP. */
    public static String digest(byte[] zip) { return walk(zip, new boolean[1]); }

    /** Whether the archive holds a v1 signature file. Throws IllegalArgumentException if it is no plain ZIP. */
    public static boolean hasSignatureFiles(byte[] zip) {
        boolean[] seen = new boolean[1];
        walk(zip, seen);
        return seen[0];
    }

    /**
     * The archive's APK Signing Block, from its first size field to its magic, or an empty array
     * when it has none. Throws IllegalArgumentException if it is no plain ZIP.
     */
    public static byte[] signingBlock(byte[] zip) {
        int[] at = block(zip);
        return at == null ? new byte[0] : java.util.Arrays.copyOfRange(zip, at[0], at[1]);
    }

    /**
     * The archive without its APK Signing Block, with the central directory offset moved to where
     * the block began: the input that signing sees. An archive without a block is returned as a
     * copy. Throws IllegalArgumentException if it is no plain ZIP.
     */
    public static byte[] withoutSigningBlock(byte[] zip) {
        int[] at = block(zip);
        if (at == null) return zip.clone();
        int removed = at[1] - at[0];
        byte[] out = new byte[zip.length - removed];
        System.arraycopy(zip, 0, out, 0, at[0]);
        System.arraycopy(zip, at[1], out, at[0], zip.length - at[1]);
        ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN).putInt(eocd(zip) - removed + 16, at[0]);
        return out;
    }

    private static final byte[] BLOCK_MAGIC = "APK Sig Block 42".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    // The signing block's start and end, which is the central directory's offset, or null.
    private static int[] block(byte[] zip) {
        ByteBuffer b = ByteBuffer.wrap(zip).order(ByteOrder.LITTLE_ENDIAN);
        int eocd = eocd(zip);
        long offset = b.getInt(eocd + 16) & 0xffffffffL;
        if (offset > eocd) throw DeploymentRecords.invalid("a central directory outside the archive");
        if (offset < 32 || !java.util.Arrays.equals(zip, (int) offset - 16, (int) offset, BLOCK_MAGIC, 0, 16)) {
            return null;
        }
        long size = b.getLong((int) offset - 24);
        if (size < 24 || size > offset - 8 || b.getLong((int) (offset - size - 8)) != size) {
            throw DeploymentRecords.invalid("APK Signing Block sizes");
        }
        return new int[] {(int) (offset - size - 8), (int) offset};
    }

    private static int eocd(byte[] zip) {
        ByteBuffer b = ByteBuffer.wrap(zip).order(ByteOrder.LITTLE_ENDIAN);
        for (int at = zip.length - 22; at >= Math.max(0, zip.length - 22 - 0xffff); at--) {
            if (b.getInt(at) == EOCD && at + 22 + (b.getShort(at + 20) & 0xffff) == zip.length) return at;
        }
        throw DeploymentRecords.invalid("no end of central directory");
    }

    private static String walk(byte[] zip, boolean[] signatureFiles) {
        ByteBuffer b = ByteBuffer.wrap(zip).order(ByteOrder.LITTLE_ENDIAN);
        int eocd = eocd(zip);
        int count = b.getShort(eocd + 10) & 0xffff;
        long size = b.getInt(eocd + 12) & 0xffffffffL;
        long offset = b.getInt(eocd + 16) & 0xffffffffL;
        if (count == 0xffff || size == 0xffffffffL || offset == 0xffffffffL || offset + size > eocd) {
            throw DeploymentRecords.invalid("ZIP64 or a central directory outside the archive");
        }
        MessageDigest all = sha256();
        int at = (int) offset;
        for (int i = 0; i < count; i++) {
            if (at + 46 > eocd || b.getInt(at) != CENTRAL) throw DeploymentRecords.invalid("central directory entry");
            int method = b.getShort(at + 10) & 0xffff;
            int crc = b.getInt(at + 16);
            long compressed = b.getInt(at + 20) & 0xffffffffL;
            long uncompressed = b.getInt(at + 24) & 0xffffffffL;
            int nameLength = b.getShort(at + 28) & 0xffff;
            int extraLength = b.getShort(at + 30) & 0xffff;
            int commentLength = b.getShort(at + 32) & 0xffff;
            long local = b.getInt(at + 42) & 0xffffffffL;
            if (compressed == 0xffffffffL || uncompressed == 0xffffffffL || local == 0xffffffffL) {
                throw DeploymentRecords.invalid("ZIP64 entry");
            }
            if ((long) at + 46 + nameLength + extraLength + commentLength > offset + size) {
                throw DeploymentRecords.invalid("central directory entry past the central directory");
            }
            byte[] name = new byte[nameLength];
            b.get(at + 46, name);
            if (signatureFile(name)) {
                signatureFiles[0] = true;
                at += 46 + nameLength + extraLength + commentLength;
                continue;
            }
            if (local + 30 > offset || b.getInt((int) local) != LOCAL) throw DeploymentRecords.invalid("local entry");
            int data = (int) local + 30 + (b.getShort((int) local + 26) & 0xffff) + (b.getShort((int) local + 28) & 0xffff);
            if (data + compressed > offset) throw DeploymentRecords.invalid("entry data outside the entries");
            MessageDigest entry = sha256();
            entry.update(zip, data, (int) compressed);
            ByteBuffer head = ByteBuffer.allocate(4 + nameLength + 2 + 4 + 8 + 8).order(ByteOrder.LITTLE_ENDIAN);
            head.putInt(nameLength).put(name).putShort((short) method).putInt(crc).putLong(compressed)
                    .putLong(uncompressed);
            all.update(head.array());
            all.update(entry.digest());
            at += 46 + nameLength + extraLength + commentLength;
        }
        if (at != offset + size) throw DeploymentRecords.invalid("central directory size");
        return hex(all.digest());
    }

    // A v1 signature file: signing output, like the APK Signing Block. Only ASCII letters fold, and
    // a byte outside ASCII never matches.
    static boolean signatureFile(byte[] raw) {
        char[] folded = new char[raw.length];
        for (int i = 0; i < raw.length; i++) {
            int c = raw[i] & 0xff;
            folded[i] = (char) (c >= 'a' && c <= 'z' ? c - ('a' - 'A') : c);
        }
        String n = new String(folded);
        if (n.equals("META-INF/MANIFEST.MF")) return true;
        if (!n.startsWith("META-INF/") || n.indexOf('/', 9) >= 0) return false;
        return n.endsWith(".SF") || n.endsWith(".RSA") || n.endsWith(".DSA") || n.endsWith(".EC")
                || n.startsWith("META-INF/SIG-");
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder s = new StringBuilder();
        for (byte x : bytes) s.append(String.format("%02x", x & 0xff));
        return s.toString();
    }
}
