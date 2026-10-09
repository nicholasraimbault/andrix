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
 * {@code META-INF/}), offsets, local extra fields and the ZIP comment are left out. A built APK,
 * its signed output and a realigned copy of either therefore give the same digest exactly when
 * they hold the same entries. ZIP64 archives are refused.
 */
public final class ApkEntries {
    private static final int EOCD = 0x06054b50;
    private static final int CENTRAL = 0x02014b50;
    private static final int LOCAL = 0x04034b50;

    private ApkEntries() {}

    /** The entry digest of a ZIP archive, as lowercase hex. Throws IllegalArgumentException if it is no plain ZIP. */
    public static String digest(byte[] zip) {
        ByteBuffer b = ByteBuffer.wrap(zip).order(ByteOrder.LITTLE_ENDIAN);
        int eocd = -1;
        for (int at = zip.length - 22; at >= Math.max(0, zip.length - 22 - 0xffff); at--) {
            if (b.getInt(at) == EOCD && at + 22 + (b.getShort(at + 20) & 0xffff) == zip.length) {
                eocd = at;
                break;
            }
        }
        if (eocd < 0) throw DeploymentRecords.invalid("no end of central directory");
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
            byte[] name = new byte[nameLength];
            b.get(at + 46, name);
            if (signatureFile(new String(name, java.nio.charset.StandardCharsets.UTF_8))) {
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

    // A v1 signature file: signing output, like the APK Signing Block.
    static boolean signatureFile(String name) {
        String n = name.toUpperCase(java.util.Locale.ROOT);
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
