// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.notice;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** The strict value grammars that the request, the row and the store share. Plain Java. */
final class Forms {
    /** The ledger bound of a ticket, as the deployment records define it. */
    static final int MAX_LEDGER = 140;
    /** Android's per user UID range, so the user of a UID is uid / PER_USER_RANGE. */
    static final int PER_USER_RANGE = 100000;
    /** The largest user ID whose UIDs still fit an int. */
    static final int MAX_USER = (Integer.MAX_VALUE - (PER_USER_RANGE - 1)) / PER_USER_RANGE;
    /** User serials are ints in UserManagerService; -1 means no such user. */
    static final long MAX_SERIAL = Integer.MAX_VALUE;
    static final int FIRST_APPLICATION_UID = 10000;
    static final int LAST_APPLICATION_UID = 19999;
    static final int MAX_COMPONENT = 255;

    private Forms() {}

    static IllegalArgumentException refused(String what) {
        return new IllegalArgumentException(what);
    }

    /** Lowercase hexadecimal of exactly {@code bytes} bytes, not all zero. */
    static boolean id(String value, int bytes) {
        if (value == null || value.length() != 2 * bytes) return false;
        boolean nonzero = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
            nonzero |= c != '0';
        }
        return nonzero;
    }

    /** An Android package name: two or more dot separated segments, each a letter, then letters,
     * digits or underscores. */
    static boolean component(String value) {
        if (value == null || value.isEmpty() || value.length() > MAX_COMPONENT) return false;
        int segments = 0;
        int start = 0;
        while (true) {
            int end = value.indexOf('.', start);
            String segment = end < 0 ? value.substring(start) : value.substring(start, end);
            if (segment.isEmpty() || !letter(segment.charAt(0))) return false;
            for (int i = 1; i < segment.length(); i++) {
                char c = segment.charAt(i);
                if (!letter(c) && !(c >= '0' && c <= '9') && c != '_') return false;
            }
            segments++;
            if (end < 0) break;
            start = end + 1;
        }
        return segments >= 2;
    }

    private static boolean letter(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    }

    /** Printable ASCII, 0x20 to 0x7e, of 1 to {@code max} characters. */
    static boolean printable(String value, int max) {
        if (value == null || value.isEmpty() || value.length() > max) return false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c > 0x7e) return false;
        }
        return true;
    }

    /** A canonical decimal, "0" or a nonzero digit then digits, at most 19, within bounds. */
    static long decimal(String text, long min, long max, String what) {
        if (text == null || text.isEmpty() || text.length() > 19) throw refused(what);
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < '0' || c > '9') throw refused(what);
        }
        if (text.length() > 1 && text.charAt(0) == '0') throw refused(what);
        long value;
        try {
            value = Long.parseLong(text);
        } catch (NumberFormatException e) {
            throw refused(what);
        }
        if (value < min || value > max) throw refused(what);
        return value;
    }

    static String sha256(byte[] data) {
        try {
            return hex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("no SHA-256", e);
        }
    }

    static String sha256(String ascii) {
        return sha256(ascii.getBytes(StandardCharsets.US_ASCII));
    }

    static String hex(byte[] data) {
        char[] out = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            out[2 * i] = Character.forDigit((data[i] >> 4) & 15, 16);
            out[2 * i + 1] = Character.forDigit(data[i] & 15, 16);
        }
        return new String(out);
    }

    /** The bytes of lowercase hexadecimal of even length, or a refusal. */
    static byte[] unhex(String text, int maxBytes, String what) {
        if (text == null || text.length() % 2 != 0 || text.length() > 2 * maxBytes) throw refused(what);
        byte[] out = new byte[text.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int high = nibble(text.charAt(2 * i));
            int low = nibble(text.charAt(2 * i + 1));
            if (high < 0 || low < 0) throw refused(what);
            out[i] = (byte) (high << 4 | low);
        }
        return out;
    }

    private static int nibble(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    }

    /** Whether a UID is an ordinary application UID of its user. */
    static boolean applicationUid(int uid) {
        int app = uid % PER_USER_RANGE;
        return uid >= 0 && app >= FIRST_APPLICATION_UID && app <= LAST_APPLICATION_UID;
    }
}
