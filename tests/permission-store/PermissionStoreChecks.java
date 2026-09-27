// SPDX-License-Identifier: Apache-2.0

import com.android.modules.utils.BinaryXmlPullParser;
import com.android.modules.utils.BinaryXmlSerializer;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Host checks for {@link PermissionStoreReader}. Documents are written by the pinned
 * BinaryXmlSerializer. Malformed inputs are derived from those bytes, or written by hand where
 * the serializer cannot produce them. Flag values are stored samples; nothing here gives them a
 * policy meaning.
 */
public final class PermissionStoreChecks {
    static final String PASS = "PERMISSION_STORE_HOST_CHECKS_PASS_NO_ANDROID_CLAIM";
    static final String POST = PermissionStoreReader.TARGET_PERMISSION;
    static final String CAMERA = "android.permission.CAMERA";
    static final String INTERNET = "android.permission.INTERNET";
    // A different permission name with the same length as POST.
    static final String SAME_LENGTH = "android.permission.READ_PHONE_NUMBERS";
    static final String FLAGS = PermissionStoreReader.STATE_FLAGS;
    static final String NO_PERMISSION = PermissionStoreReader.STATE_PERMISSION_ABSENT;
    static final String NO_APP_ID = PermissionStoreReader.STATE_APP_ID_ABSENT;
    static final int[] IDS = {10123, 10124, 10125, 10126, 10127, 10999};
    static final int CANONICAL_ELEMENTS = 23;
    static final int CANONICAL_TOKENS = 2 * CANONICAL_ELEMENTS + 1;
    // The pinned intern pool holds this many strings (FastDataInput.MAX_UNSIGNED_SHORT).
    static final int POOL = 65_535;
    // Strings interned before the pool names: the extraction path's eight and "pool".
    static final int POOL_PREFIX = 9;
    static final String LAST_INTERNED = "s" + (POOL - POOL_PREFIX - 1);

    // Magic, START_DOCUMENT, a start tag naming interned reference 5 while nothing is interned,
    // its end tag and END_DOCUMENT. The serializer cannot write this.
    static final byte[] UNASSIGNED_NAME = {
        0x41, 0x42, 0x58, 0x00, 0x10, 0x32, 0x00, 0x05, 0x33, 0x00, 0x05, 0x11,
    };

    /** Writes part of a document with the pinned serializer. */
    interface Body {
        void write(BinaryXmlSerializer out) throws IOException;
    }

    static final Body NOTHING = out -> {
    };

    /** One typed reading of the current token through the parser API. */
    interface Reading {
        Object read() throws XmlPullParserException;
    }

    /** The pinned serializer writing to memory, with the offset of what it has written. */
    static final class Output {
        final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        final BinaryXmlSerializer out = new BinaryXmlSerializer();

        Output() throws IOException {
            out.setOutput(bytes, null);
        }

        int offset() throws IOException {
            out.flush();
            return bytes.size();
        }

        byte[] toByteArray() throws IOException {
            out.flush();
            return bytes.toByteArray();
        }
    }

    private final List<String> failures = new ArrayList<>();
    private int passed;

    private PermissionStoreChecks() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 2 && "--write-fixtures".equals(args[0])) {
            writeFixtures(Path.of(args[1]));
            return;
        }
        if (args.length != 0) {
            System.err.println("usage: PermissionStoreChecks [--write-fixtures EMPTY_DIRECTORY]");
            System.exit(2);
        }
        final PermissionStoreChecks checks = new PermissionStoreChecks();
        checks.encodings();
        checks.positives();
        checks.layoutRefusals();
        checks.eventRefusals();
        checks.stringRefusals();
        checks.internPool();
        checks.endFence();
        checks.integrityLimits();
        checks.parserObservations();
        checks.arguments();
        checks.json();
        for (String failure : checks.failures) {
            System.err.println("FAIL " + failure);
        }
        if (!checks.failures.isEmpty()) {
            System.exit(1);
        }
        System.out.println(PASS + " checks=" + checks.passed);
    }

    // Documents written by the pinned serializer.

    static byte[] written(Body body) throws IOException {
        final Output output = new Output();
        body.write(output.out);
        return output.toByteArray();
    }

    static byte[] document(Body body) throws IOException {
        return written(out -> {
            out.startDocument(null, true);
            body.write(out);
            out.endDocument();
        });
    }

    static void tag(BinaryXmlSerializer out, String name, Body body) throws IOException {
        out.startTag(null, name);
        body.write(out);
        out.endTag(null, name);
    }

    /** As the pinned AppIdPermissionPersistence writes one permission. */
    static void permission(BinaryXmlSerializer out, String name, int flags) throws IOException {
        out.startTag(null, "permission");
        out.attributeInterned(null, "name", name);
        out.attributeInt(null, "flags", flags);
        out.endTag(null, "permission");
    }

    /** As the pinned AppIdPermissionPersistence writes one app id. */
    static void appId(BinaryXmlSerializer out, int id, Body body) throws IOException {
        out.startTag(null, "app-id");
        out.attributeInt(null, "id", id);
        body.write(out);
        out.endTag(null, "app-id");
    }

    static byte[] section(Body body) throws IOException {
        return document(out -> tag(out, "access", root -> tag(root, "app-id-permissions", body)));
    }

    /** As the pinned AccessPolicy writes package versions. */
    static void packageVersions(BinaryXmlSerializer out) throws IOException {
        tag(out, "package-versions", versions -> {
            versions.startTag(null, "package");
            versions.attributeInterned(null, "name", "dev.andrix.fixture.one");
            versions.attributeInt(null, "version", 3);
            versions.endTag(null, "package");
        });
    }

    /** As the pinned AccessPolicy writes a default permission grant fingerprint. */
    static void defaultGrant(BinaryXmlSerializer out) throws IOException {
        out.startTag(null, "default-permission-grant");
        out.attributeInterned(null, "fingerprint", "fixture/fingerprint:1");
        out.endTag(null, "default-permission-grant");
    }

    static void canonicalSection(BinaryXmlSerializer out) throws IOException {
        tag(out, "app-id-permissions", entries -> {
            appId(entries, 1000, app -> permission(app, INTERNET, 1));
            appId(entries, 10123, app -> {
                permission(app, CAMERA, 0);
                permission(app, POST, 24624);
            });
            appId(entries, 10124, app -> permission(app, POST, 24608));
            appId(entries, 10125, app -> permission(app, POST, 24672));
            appId(entries, 10126, app -> permission(app, CAMERA, 16));
        });
    }

    static void otherSections(BinaryXmlSerializer out) throws IOException {
        // The same inner names on another path are neither extracted nor duplicates.
        tag(out, "app-id-device-permissions", devices -> {
            devices.startTag(null, "app-id");
            devices.attributeInt(null, "id", 10127);
            devices.startTag(null, "device");
            devices.attributeInterned(null, "id", "fixture-device");
            permission(devices, POST, 24624);
            devices.endTag(null, "device");
            devices.endTag(null, "app-id");
        });
        // Every other attribute encoding, outside the extraction path.
        tag(out, "app-id-app-ops", ops -> {
            ops.startTag(null, "app-id");
            ops.attributeInt(null, "id", 10123);
            ops.startTag(null, "app-op");
            ops.attributeInterned(null, "name", "fixture:op");
            ops.attributeInt(null, "mode", 1);
            ops.attribute(null, "note", "plain string");
            ops.attributeBytesHex(null, "hex", new byte[] {1, 2, 3});
            ops.attributeBytesBase64(null, "base64", new byte[] {4, 5, 6});
            ops.attributeIntHex(null, "int-hex", 255);
            ops.attributeLong(null, "long", 1L << 40);
            ops.attributeLongHex(null, "long-hex", 7L);
            ops.attributeFloat(null, "float", 1.5f);
            ops.attributeDouble(null, "double", 2.5d);
            ops.attributeBoolean(null, "yes", true);
            ops.attributeBoolean(null, "no", false);
            ops.endTag(null, "app-op");
            ops.endTag(null, "app-id");
        });
    }

    /** 23 elements; five app ids and six permissions on the extraction path. */
    static byte[] canonical() throws IOException {
        return document(out -> tag(out, "access", root -> {
            packageVersions(root);
            defaultGrant(root);
            canonicalSection(root);
            otherSections(root);
        }));
    }

    /** One target entry for app id 10123. */
    static byte[] minimal() throws IOException {
        return section(entries -> appId(entries, 10123, app -> permission(app, POST, 24624)));
    }

    /** Two target entries; the second app id's strings are all interned references. */
    static byte[] twoTargets() throws IOException {
        return section(entries -> {
            appId(entries, 10123, app -> permission(app, POST, 24624));
            appId(entries, 10124, app -> permission(app, POST, 24608));
        });
    }

    /** A target that is complete before the rest of the document; cut[0] is its end offset. */
    static byte[] earlyTarget(int[] cut) throws IOException {
        final Output output = new Output();
        final BinaryXmlSerializer out = output.out;
        out.startDocument(null, true);
        out.startTag(null, "access");
        out.startTag(null, "app-id-permissions");
        out.startTag(null, "app-id");
        out.attributeInt(null, "id", 10123);
        permission(out, POST, 24624);
        cut[0] = output.offset();
        out.endTag(null, "app-id");
        appId(out, 10124, app -> permission(app, POST, 24608));
        out.endTag(null, "app-id-permissions");
        out.endTag(null, "access");
        out.endDocument();
        return output.toByteArray();
    }

    /** twoTargets(), with cut[0] to cut[1] the bytes of the second permission element. */
    static byte[] integrity(int[] cut) throws IOException {
        final Output output = new Output();
        final BinaryXmlSerializer out = output.out;
        out.startDocument(null, true);
        out.startTag(null, "access");
        out.startTag(null, "app-id-permissions");
        appId(out, 10123, app -> permission(app, POST, 24624));
        out.startTag(null, "app-id");
        out.attributeInt(null, "id", 10124);
        cut[0] = output.offset();
        permission(out, POST, 24608);
        cut[1] = output.offset();
        out.endTag(null, "app-id");
        out.endTag(null, "app-id-permissions");
        out.endTag(null, "access");
        out.endDocument();
        return output.toByteArray();
    }

    /** A POST_NOTIFICATIONS entry for app id 10123 whose flags attribute the body writes. */
    static byte[] permissionWith(Body flags) throws IOException {
        return section(entries -> appId(entries, 10123, app -> {
            app.startTag(null, "permission");
            app.attributeInterned(null, "name", POST);
            flags.write(app);
            app.endTag(null, "permission");
        }));
    }

    /** minimal() plus a plain string attribute outside the extraction path. */
    static byte[] noted(String value) throws IOException {
        return document(out -> tag(out, "access", root -> {
            tag(root, "app-id-permissions", entries -> appId(entries, 10123,
                    app -> permission(app, POST, 24624)));
            root.startTag(null, "note");
            root.attribute(null, "text", value);
            root.endTag(null, "note");
        }));
    }

    /** Plain string values on both pinned readUTF paths, outside the extraction path. */
    static byte[] longStrings() throws IOException {
        return document(out -> tag(out, "access", root -> {
            tag(root, "app-id-permissions", entries -> appId(entries, 10123,
                    app -> permission(app, POST, 7)));
            root.startTag(null, "long");
            // 32767 bytes fit the buffer, 32768 fill it exactly, 32770 are read directly and
            // 65535 is the largest declared length. The last value holds a surrogate pair, a
            // NUL and an unpaired surrogate, all in the writer's own encoding.
            root.attribute(null, "a", "x".repeat(32_767));
            root.attribute(null, "b", "y".repeat(32_768));
            root.attribute(null, "c", "\u00e9".repeat(16_385));
            root.attribute(null, "d", "\u20ac".repeat(21_845));
            root.attribute(null, "e", "\ud83d\ude00\u0000\ud800");
            root.endTag(null, "long");
        }));
    }

    /** Every other token kind the pinned serializer writes, around a valid section. */
    static byte[] otherTokens() throws IOException {
        return document(out -> {
            out.docdecl("access");
            out.processingInstruction("fixture");
            tag(out, "access", root -> {
                root.comment("c");
                root.text("t");
                root.cdsect("d");
                root.ignorableWhitespace(" ");
                root.entityRef("amp");
                root.entityRef("#65");
                tag(root, "app-id-permissions", NOTHING);
            });
        });
    }

    /** Elements whose references can be made unassigned: "other" is interned reference 2. */
    static byte[] unassignedBase() throws IOException {
        return document(out -> tag(out, "access", root -> {
            tag(root, "app-id-permissions", NOTHING);
            root.startTag(null, "other");
            root.attributeInt(null, "x", 1);
            root.attributeInterned(null, "y", "v");
            root.endTag(null, "other");
        }));
    }

    static Body wide(int attributes) {
        return out -> {
            out.startTag(null, "wide");
            for (int i = 0; i < attributes; i++) {
                out.attributeInt(null, "a" + i, i);
            }
            out.endTag(null, "wide");
        };
    }

    static Body nested(int levels) {
        return out -> {
            for (int i = 0; i < levels; i++) {
                out.startTag(null, "n" + i);
            }
            for (int i = levels - 1; i >= 0; i--) {
                out.endTag(null, "n" + i);
            }
        };
    }

    /**
     * A document whose intern pool fills. After the POOL_PREFIX strings, the names s0 to
     * LAST_INTERNED take the remaining places, so the pinned writer then defines "overflow" at
     * every use. offsets[0] is the start of a final reference to LAST_INTERNED.
     */
    static byte[] poolCeiling(int[] offsets) throws IOException {
        final Output output = new Output();
        final BinaryXmlSerializer out = output.out;
        out.startDocument(null, true);
        out.startTag(null, "access");
        tag(out, "app-id-permissions", entries -> appId(entries, 10123,
                app -> permission(app, POST, 24624)));
        out.startTag(null, "pool");
        for (int i = 0; i < POOL - POOL_PREFIX; i++) {
            tag(out, "s" + i, NOTHING);
        }
        tag(out, "overflow", NOTHING);
        tag(out, "overflow", NOTHING);
        offsets[0] = output.offset();
        tag(out, LAST_INTERNED, NOTHING);
        out.endTag(null, "pool");
        out.endTag(null, "access");
        out.endDocument();
        return output.toByteArray();
    }

    // Byte level variants.

    static byte[] bytes(int... values) {
        final byte[] result = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            result[i] = (byte) values[i];
        }
        return result;
    }

    static byte[] ascii(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    static byte[] int32(int value) {
        return bytes(value >>> 24, value >>> 16, value >>> 8, value);
    }

    /** A string as the pinned readUTF reads it: a two byte declared length, then the bytes. */
    static byte[] declared(int length, byte[] body) {
        return concat(bytes(length >>> 8, length), body);
    }

    static byte[] declared(byte[] body) {
        return declared(body.length, body);
    }

    /** A definition as the pinned readInternedUTF reads it. */
    static byte[] definition(byte[] body) {
        return concat(bytes(0xff, 0xff), declared(body));
    }

    static byte[] concat(byte[]... parts) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }

    static byte[] spliced(byte[] data, int index, int remove, byte[] insert) {
        final byte[] result = new byte[data.length - remove + insert.length];
        System.arraycopy(data, 0, result, 0, index);
        System.arraycopy(insert, 0, result, index, insert.length);
        System.arraycopy(data, index + remove, result, index + insert.length,
                data.length - index - remove);
        return result;
    }

    static byte[] patched(byte[] data, int index, int value) {
        return spliced(data, index, 1, bytes(value));
    }

    static byte[] removed(byte[] data, int index) {
        return spliced(data, index, 1, new byte[0]);
    }

    static byte[] inserted(byte[] data, int index, byte[] extra) {
        return spliced(data, index, 0, extra);
    }

    static int onlyIndexOf(byte[] data, int value) {
        return onlyIndexOf(data, bytes(value));
    }

    static int onlyIndexOf(byte[] data, byte[] pattern) {
        int found = -1;
        for (int i = 0; i + pattern.length <= data.length; i++) {
            if (Arrays.equals(data, i, i + pattern.length, pattern, 0, pattern.length)) {
                if (found >= 0) {
                    throw new IllegalStateException("fixture bytes are not unique");
                }
                found = i;
            }
        }
        if (found < 0) {
            throw new IllegalStateException("fixture bytes missing");
        }
        return found;
    }

    static int occurrences(byte[] data, byte[] pattern) {
        int count = 0;
        for (int i = 0; i + pattern.length <= data.length; i++) {
            if (Arrays.equals(data, i, i + pattern.length, pattern, 0, pattern.length)) {
                count++;
            }
        }
        return count;
    }

    static byte[] replacedOnce(byte[] data, byte[] pattern, byte[] replacement) {
        return spliced(data, onlyIndexOf(data, pattern), pattern.length, replacement);
    }

    /** Replaces the 40000 byte plain string of noted(value) with body under its own length. */
    static byte[] longReplaced(String value, byte[] body) throws IOException {
        final byte[] data = noted(value);
        final int index = onlyIndexOf(data, concat(bytes(0x9c, 0x40), ascii("xxxx")));
        return spliced(data, index, 2 + 40_000, declared(body));
    }

    // Noncanonical strings and intern definitions the pinned writer never produces.

    static byte[] overlongAccess() throws IOException {
        return replacedOnce(minimal(), declared(ascii("access")),
                declared(concat(ascii("acces"), bytes(0xc1, 0xb3))));
    }

    static byte[] overlongTarget() throws IOException {
        return replacedOnce(minimal(), declared(ascii(POST)), declared(concat(ascii("android"),
                bytes(0xc0, 0xae), ascii("permission.POST_NOTIFICATIONS"))));
    }

    static byte[] rawNul() throws IOException {
        return replacedOnce(noted("\u0000"), declared(bytes(0xc0, 0x80)), declared(bytes(0x00)));
    }

    /** "a" as an overlong form and U+0000 as a raw NUL: the declared length still matches. */
    static byte[] offsetNul() throws IOException {
        return replacedOnce(noted("a\u0000"), declared(bytes(0x61, 0xc0, 0x80)),
                declared(bytes(0xc1, 0xa1, 0x00)));
    }

    static byte[] fourByteForm() throws IOException {
        return replacedOnce(noted("\ud83d\ude00"),
                declared(bytes(0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80)),
                declared(bytes(0xf0, 0x9f, 0x98, 0x80)));
    }

    /** The final end tag defines "access" again instead of referring to it. */
    static byte[] duplicateTagDefinition() throws IOException {
        final byte[] data = document(out -> tag(out, "access", root -> tag(root,
                "app-id-permissions", NOTHING)));
        return spliced(data, data.length - 3, 2, definition(ascii("access")));
    }

    /** The second target name defines POST_NOTIFICATIONS again instead of referring to it. */
    static byte[] duplicateValueDefinition() throws IOException {
        return replacedOnce(twoTargets(), bytes(0x3f, 0x00, 0x05, 0x00, 0x06),
                concat(bytes(0x3f, 0x00, 0x05), definition(ascii(POST))));
    }

    /** The second id attribute defines "id" again instead of referring to it. */
    static byte[] duplicateNameDefinition() throws IOException {
        return replacedOnce(twoTargets(), bytes(0x6f, 0x00, 0x03),
                concat(bytes(0x6f), definition(ascii("id"))));
    }

    // Assertions without Java assert, so results do not depend on -ea.

    private void check(String name, boolean condition, String detail) {
        if (condition) {
            passed++;
            System.out.println("ok: " + name);
        } else {
            failures.add(name + ": " + detail);
        }
    }

    private void expectParsed(String name, byte[] data, int[] ids, String[] states, int[] values) {
        final PermissionStoreReader.Result result = PermissionStoreReader.read(data, ids);
        boolean matches = result.parsed && Arrays.equals(result.appIds, ids)
                && Arrays.equals(result.states, states);
        for (int i = 0; matches && i < ids.length; i++) {
            if (FLAGS.equals(states[i]) && result.flags[i] != values[i]) {
                matches = false;
            }
        }
        check(name, matches, result.toJson());
    }

    private void expectRefused(String name, byte[] data, String code) {
        final PermissionStoreReader.Result result = PermissionStoreReader.read(data, IDS);
        check(name, !result.parsed && code.equals(result.code) && result.appIds.length == 0,
                result.toJson());
    }

    // Check groups.

    private void encodings() throws Exception {
        final byte[] data = canonical();
        check("canonical framing", data[0] == 0x41 && data[1] == 0x42 && data[2] == 0x58
                && data[3] == 0 && (data[4] & 0xff) == 0x10 && (data[5] & 0xff) == 0x32
                && (data[data.length - 4] & 0xff) == 0x33 && (data[data.length - 1] & 0xff) == 0x11,
                Arrays.toString(Arrays.copyOf(data, 6)));
        check("reader event constants", PermissionStoreReader.EVENT_START_DOCUMENT == 0x10
                && PermissionStoreReader.EVENT_END_DOCUMENT == 0x11
                && PermissionStoreReader.EVENT_START_TAG == 0x32
                && PermissionStoreReader.EVENT_END_TAG == 0x33
                && PermissionStoreReader.TYPE_NULL == 0x10
                && PermissionStoreReader.TYPE_STRING == 0x20
                && PermissionStoreReader.TYPE_STRING_INTERNED == 0x30
                && PermissionStoreReader.TYPE_INT == 0x60
                && PermissionStoreReader.TYPE_INT_HEX == 0x70
                && PermissionStoreReader.TYPE_BOOLEAN_FALSE == 0xd0, "constants");
        final byte[] attributes = document(out -> {
            out.startTag(null, "a");
            out.attributeInt(null, "i", 1);
            out.attributeIntHex(null, "h", 1);
            out.attributeInterned(null, "n", "v");
            out.attribute(null, "s", "v");
            out.attributeBoolean(null, "t", true);
            out.endTag(null, "a");
        });
        final PermissionStoreReader.RecordingParser parser =
                new PermissionStoreReader.RecordingParser();
        parser.setInput(new PermissionStoreReader.OneByteSource(attributes), null);
        final int[] start = parser.input().drain();
        final int first = parser.nextToken();
        final int[] tag = parser.input().drain();
        final int second = parser.nextToken();
        final int[] end = parser.input().drain();
        final int third = parser.nextToken();
        final int[] last = parser.input().drain();
        check("serializer event bytes as recorded", Arrays.equals(start, new int[] {0x10})
                && first == XmlPullParser.START_TAG
                && Arrays.equals(tag, new int[] {0x32, 0x6f, 0x7f, 0x3f, 0x2f, 0xcf})
                && second == XmlPullParser.END_TAG && Arrays.equals(end, new int[] {0x33})
                && third == XmlPullParser.END_DOCUMENT && Arrays.equals(last, new int[] {0x11}),
                Arrays.toString(start) + Arrays.toString(tag) + Arrays.toString(end)
                        + Arrays.toString(last));
        check("recording parser decodes like the plain parser", sameDecoding(data), "differs");
        check("recording parser decodes long strings like the plain parser",
                sameDecoding(longStrings()), "differs");
        check("recording parser decodes other tokens like the plain parser",
                sameDecoding(otherTokens()), "differs");
        check("recording parser decodes a full intern pool like the plain parser",
                sameDecoding(poolCeiling(new int[1])), "differs");
    }

    private void positives() throws IOException {
        final byte[] data = canonical();
        expectParsed("canonical values", data, IDS,
                new String[] {FLAGS, FLAGS, FLAGS, NO_PERMISSION, NO_APP_ID, NO_APP_ID},
                new int[] {24624, 24608, 24672, 0, 0, 0});
        final PermissionStoreReader.Result result = PermissionStoreReader.read(data, IDS);
        check("canonical counts and input binding", result.parsed
                && result.elements == CANONICAL_ELEMENTS && result.appIdEntries == 5
                && result.permissionEntries == 6 && result.length == data.length
                && PermissionStoreReader.sha256(data).equals(result.sha256), result.toJson());
        expectParsed("request order kept", data, new int[] {10125, 10123},
                new String[] {FLAGS, FLAGS}, new int[] {24672, 24624});
        expectParsed("flag and app id bounds", section(entries -> {
            appId(entries, 10001, app -> permission(app, POST, 0));
            appId(entries, 10002, app -> permission(app, POST, -1));
            appId(entries, 10003, app -> permission(app, POST, Integer.MIN_VALUE));
            appId(entries, 10004, app -> permission(app, POST, Integer.MAX_VALUE));
            appId(entries, 10000, app -> permission(app, POST, 1));
            appId(entries, 19999, app -> permission(app, POST, 2));
            appId(entries, 0, app -> permission(app, POST, 3));
            appId(entries, -5, app -> permission(app, POST, 4));
            appId(entries, Integer.MAX_VALUE, app -> permission(app, POST, 5));
        }), new int[] {10001, 10002, 10003, 10004, 10000, 19999},
                new String[] {FLAGS, FLAGS, FLAGS, FLAGS, FLAGS, FLAGS},
                new int[] {0, -1, Integer.MIN_VALUE, Integer.MAX_VALUE, 1, 2});
        expectParsed("empty section", section(NOTHING), new int[] {10123},
                new String[] {NO_APP_ID}, new int[] {0});
        expectParsed("app id without permissions", section(entries -> appId(entries, 10123,
                NOTHING)), new int[] {10123}, new String[] {NO_PERMISSION}, new int[] {0});
        expectParsed("attribute bound fits", document(out -> tag(out, "access", root -> {
            tag(root, "app-id-permissions", entries -> appId(entries, 10123,
                    app -> permission(app, POST, 7)));
            wide(PermissionStoreReader.MAX_ATTRIBUTES).write(root);
        })), new int[] {10123}, new String[] {FLAGS}, new int[] {7});
        expectParsed("depth bound fits", document(out -> tag(out, "access", root -> {
            tag(root, "app-id-permissions", NOTHING);
            nested(PermissionStoreReader.MAX_DEPTH - 1).write(root);
        })), new int[] {10123}, new String[] {NO_APP_ID}, new int[] {0});
        expectParsed("long strings in the writer's encoding", longStrings(), new int[] {10123},
                new String[] {FLAGS}, new int[] {7});
    }

    private void layoutRefusals() throws IOException {
        expectRefused("wrong root", document(out -> tag(out, "permissions",
                root -> canonicalSection(root))), "wrong_root");
        expectRefused("root attribute", document(out -> {
            out.startTag(null, "access");
            out.attributeInt(null, "version", 1);
            canonicalSection(out);
            out.endTag(null, "access");
        }), "unexpected_attribute");
        expectRefused("missing section", document(out -> tag(out, "access",
                root -> packageVersions(root))), "missing_section");
        expectRefused("duplicate section", document(out -> tag(out, "access", root -> {
            canonicalSection(root);
            tag(root, "app-id-permissions", NOTHING);
        })), "duplicate_section");
        expectRefused("duplicate requested app id", section(entries -> {
            appId(entries, 10123, app -> permission(app, POST, 24624));
            appId(entries, 10123, app -> permission(app, POST, 24608));
        }), "duplicate_app_id");
        expectRefused("duplicate other app id", section(entries -> {
            appId(entries, 1000, NOTHING);
            appId(entries, 1000, NOTHING);
        }), "duplicate_app_id");
        expectRefused("duplicate target permission", section(entries -> appId(entries, 10123,
                app -> {
                    permission(app, POST, 24624);
                    permission(app, POST, 24608);
                })), "duplicate_permission");
        expectRefused("duplicate other permission", section(entries -> appId(entries, 10126,
                app -> {
                    permission(app, CAMERA, 0);
                    permission(app, CAMERA, 0);
                })), "duplicate_permission");
        expectRefused("unexpected section child", section(entries -> tag(entries, "package",
                NOTHING)), "unexpected_element");
        expectRefused("unexpected app id child", section(entries -> appId(entries, 10123,
                app -> tag(app, "device", NOTHING))), "unexpected_element");
        expectRefused("permission child", section(entries -> appId(entries, 10123, app -> {
            app.startTag(null, "permission");
            app.attributeInterned(null, "name", POST);
            app.attributeInt(null, "flags", 24624);
            tag(app, "extra", NOTHING);
            app.endTag(null, "permission");
        })), "unexpected_element");
        expectRefused("app id without id", section(entries -> tag(entries, "app-id", NOTHING)),
                "unexpected_attribute");
        expectRefused("app id extra attribute", section(entries -> {
            entries.startTag(null, "app-id");
            entries.attributeInt(null, "id", 10123);
            entries.attributeInt(null, "uid", 10123);
            entries.endTag(null, "app-id");
        }), "unexpected_attribute");
        expectRefused("permission without flags", section(entries -> appId(entries, 10123,
                app -> {
                    app.startTag(null, "permission");
                    app.attributeInterned(null, "name", POST);
                    app.endTag(null, "permission");
                })), "unexpected_attribute");
        expectRefused("permission extra attribute", section(entries -> appId(entries, 10123,
                app -> {
                    app.startTag(null, "permission");
                    app.attributeInterned(null, "name", POST);
                    app.attributeInt(null, "flags", 24624);
                    app.attributeBoolean(null, "granted", true);
                    app.endTag(null, "permission");
                })), "unexpected_attribute");
        expectRefused("flags before name", section(entries -> appId(entries, 10123, app -> {
            app.startTag(null, "permission");
            app.attributeInt(null, "flags", 24624);
            app.attributeInterned(null, "name", POST);
            app.endTag(null, "permission");
        })), "unexpected_attribute");
        expectRefused("section attribute", document(out -> tag(out, "access", root -> {
            root.startTag(null, "app-id-permissions");
            root.attributeInt(null, "version", 1);
            root.endTag(null, "app-id-permissions");
        })), "unexpected_attribute");
        expectRefused("id as string", section(entries -> {
            entries.startTag(null, "app-id");
            entries.attribute(null, "id", "10123");
            entries.endTag(null, "app-id");
        }), "attribute_encoding");
        expectRefused("id as int hex", section(entries -> {
            entries.startTag(null, "app-id");
            entries.attributeIntHex(null, "id", 10123);
            entries.endTag(null, "app-id");
        }), "attribute_encoding");
        expectRefused("flags as string", permissionWith(app -> app.attribute(null, "flags",
                "24624")), "attribute_encoding");
        expectRefused("flags as int hex", permissionWith(app -> app.attributeIntHex(null,
                "flags", 24624)), "attribute_encoding");
        expectRefused("flags as long", permissionWith(app -> app.attributeLong(null, "flags",
                24624L)), "attribute_encoding");
        expectRefused("flags as boolean", permissionWith(app -> app.attributeBoolean(null,
                "flags", true)), "attribute_encoding");
        expectRefused("name as int", section(entries -> appId(entries, 10123, app -> {
            app.startTag(null, "permission");
            app.attributeInt(null, "name", 1);
            app.attributeInt(null, "flags", 24624);
            app.endTag(null, "permission");
        })), "attribute_encoding");
        expectRefused("name as plain string", section(entries -> appId(entries, 10123, app -> {
            app.startTag(null, "permission");
            app.attribute(null, "name", POST);
            app.attributeInt(null, "flags", 24624);
            app.endTag(null, "permission");
        })), "attribute_encoding");
        expectRefused("empty permission name", section(entries -> appId(entries, 10123,
                app -> permission(app, "", 1))), "invalid_value");
        expectRefused("duplicate attribute", section(entries -> {
            entries.startTag(null, "app-id");
            entries.attributeInt(null, "id", 10123);
            entries.attributeInt(null, "id", 10124);
            entries.endTag(null, "app-id");
        }), "duplicate_attribute");
        expectRefused("mismatched end tag", document(out -> {
            out.startTag(null, "access");
            canonicalSection(out);
            out.endTag(null, "other");
        }), "mismatched_end_tag");
        expectRefused("unclosed root", document(out -> {
            out.startTag(null, "access");
            canonicalSection(out);
        }), "unclosed_elements");
        expectRefused("multiple roots", document(out -> {
            tag(out, "access", root -> canonicalSection(root));
            tag(out, "access", NOTHING);
        }), "multiple_roots");
        expectRefused("no root", document(NOTHING), "no_root");
        expectRefused("depth bound", document(out -> tag(out, "access", root -> {
            tag(root, "app-id-permissions", NOTHING);
            nested(PermissionStoreReader.MAX_DEPTH).write(root);
        })), "depth_bound");
        expectRefused("attribute bound", document(out -> tag(out, "access", root -> {
            tag(root, "app-id-permissions", NOTHING);
            wide(PermissionStoreReader.MAX_ATTRIBUTES + 1).write(root);
        })), "attribute_bound");
    }

    private void eventRefusals() throws IOException {
        final byte[] data = canonical();
        expectRefused("text token", section(entries -> entries.text("x")), "unexpected_token");
        expectRefused("whitespace text", document(out -> tag(out, "access", root -> {
            root.text("\n");
            canonicalSection(root);
        })), "unexpected_token");
        expectRefused("comment token", section(entries -> entries.comment("c")),
                "unexpected_token");
        expectRefused("cdata section", section(entries -> entries.cdsect("c")),
                "unexpected_token");
        expectRefused("processing instruction", section(entries -> entries.processingInstruction(
                "p")), "unexpected_token");
        expectRefused("ignorable whitespace", section(entries -> entries.ignorableWhitespace(
                " ")), "unexpected_token");
        expectRefused("document type declaration before the root", document(out -> {
            out.docdecl("access");
            tag(out, "access", root -> canonicalSection(root));
        }), "unexpected_token");
        expectRefused("named entity", section(entries -> entries.entityRef("amp")),
                "unexpected_token");
        expectRefused("decimal entity", section(entries -> entries.entityRef("#65")),
                "unexpected_token");
        expectRefused("unknown entity", section(entries -> entries.entityRef("unknown")),
                "parser_error");
        expectRefused("empty entity", section(entries -> entries.entityRef("")), "parser_error");
        expectRefused("number sign entity", section(entries -> entries.entityRef("#")),
                "parser_error");
        expectRefused("hexadecimal entity", section(entries -> entries.entityRef("#x41")),
                "parser_error");
        expectRefused("overflowing entity", section(entries -> entries.entityRef(
                "#99999999999")), "parser_error");
        expectRefused("stray attribute", section(entries -> {
            appId(entries, 10123, app -> permission(app, POST, 24624));
            entries.attributeInt(null, "flags", 24608);
        }), "stray_attribute");
        expectRefused("stray attribute before START_DOCUMENT", written(out -> {
            out.attributeInt(null, "x", 1);
            out.startDocument(null, true);
            tag(out, "access", root -> tag(root, "app-id-permissions", NOTHING));
            out.endDocument();
        }), "stray_attribute");
        expectRefused("stray attribute before END_DOCUMENT", written(out -> {
            out.startDocument(null, true);
            tag(out, "access", root -> tag(root, "app-id-permissions", NOTHING));
            out.attributeInt(null, "x", 1);
            out.endDocument();
        }), "stray_attribute");
        expectRefused("noncanonical start document", patched(data, 4, 0x00),
                "noncanonical_event");
        expectRefused("noncanonical start tag", patched(data, 5, 0x02), "noncanonical_event");
        expectRefused("noncanonical end tag", patched(data, data.length - 4, 0x03),
                "noncanonical_event");
        expectRefused("noncanonical end document", patched(data, data.length - 1, 0x01),
                "noncanonical_event");
        expectRefused("missing start document", removed(data, 4), "missing_start_document");
        expectRefused("repeated start document", inserted(data, 5, new byte[] {0x10}),
                "unexpected_token");
        final byte[] flagged = document(out -> tag(out, "access", root -> {
            tag(root, "app-id-permissions", NOTHING);
            root.startTag(null, "flagged");
            root.attributeBoolean(null, "b", true);
            root.endTag(null, "flagged");
        }));
        expectParsed("boolean attribute control", flagged, new int[] {10123},
                new String[] {NO_APP_ID}, new int[] {0});
        final int attribute = onlyIndexOf(flagged, 0xcf);
        expectRefused("null typed attribute", patched(flagged, attribute, 0x1f),
                "attribute_encoding");
        expectRefused("unknown attribute type", patched(flagged, attribute, 0xef),
                "parser_error");
        expectRefused("unknown token", inserted(data, 5, new byte[] {0x0b}), "parser_error");
        expectRefused("bad magic", patched(data, 3, 0x01), "header");
        expectRefused("empty input", new byte[0], "header");
        expectRefused("short magic", Arrays.copyOf(data, 3), "header");
        expectRefused("unassigned interned name", UNASSIGNED_NAME, "invalid_name");
        final byte[] base = unassignedBase();
        expectParsed("unassigned reference control", base, new int[] {10123},
                new String[] {NO_APP_ID}, new int[] {0});
        expectRefused("unassigned interned attribute name", replacedOnce(base,
                bytes(0x6f, 0xff, 0xff, 0x00, 0x01, 0x78), bytes(0x6f, 0x00, 0x10)),
                "invalid_name");
        expectRefused("unassigned interned attribute value", replacedOnce(base,
                bytes(0xff, 0xff, 0x00, 0x01, 0x76), bytes(0x00, 0x10)), "invalid_value");
        expectRefused("unassigned interned end tag", replacedOnce(base,
                bytes(0x33, 0x00, 0x02), bytes(0x33, 0x00, 0x10)), "mismatched_end_tag");
    }

    private void stringRefusals() throws IOException {
        expectParsed("string control", minimal(), new int[] {10123}, new String[] {FLAGS},
                new int[] {24624});
        expectRefused("overlong access name", overlongAccess(), "noncanonical_string");
        expectRefused("overlong target name", overlongTarget(), "noncanonical_string");
        expectRefused("three byte overlong target name", replacedOnce(minimal(),
                declared(ascii(POST)), declared(concat(ascii("android.permission.POST_"),
                        bytes(0xe0, 0x81, 0x8e), ascii("OTIFICATIONS")))),
                "noncanonical_string");
        expectRefused("overlong attribute name", replacedOnce(minimal(), declared(ascii("flags")),
                declared(concat(ascii("flag"), bytes(0xc1, 0xb3)))), "noncanonical_string");
        expectParsed("NUL in the writer's encoding", noted("\u0000"), new int[] {10123},
                new String[] {FLAGS}, new int[] {24624});
        expectRefused("raw single NUL", rawNul(), "noncanonical_string");
        expectParsed("NUL after a character in the writer's encoding", noted("a\u0000"),
                new int[] {10123}, new String[] {FLAGS}, new int[] {24624});
        expectRefused("overlong form offset by a raw NUL", offsetNul(), "noncanonical_string");
        expectRefused("four byte form", fourByteForm(), "parser_error");
        final String longValue = "x".repeat(40_000);
        expectParsed("long string control", noted(longValue), new int[] {10123},
                new String[] {FLAGS}, new int[] {24624});
        expectRefused("overlong form in a long string", longReplaced(longValue,
                concat(ascii("x".repeat(20_000)), bytes(0xc1, 0xb8), ascii("x".repeat(19_999)))),
                "noncanonical_string");
        final String nulValue = "x".repeat(19_999) + "\u0000" + "x".repeat(19_999);
        expectParsed("long string with NUL control", noted(nulValue), new int[] {10123},
                new String[] {FLAGS}, new int[] {24624});
        expectRefused("overlong form offset by a raw NUL in a long string",
                longReplaced(nulValue, concat(ascii("x".repeat(19_998)),
                        bytes(0xc1, 0xb8, 0x00), ascii("x".repeat(19_999)))),
                "noncanonical_string");
    }

    private void internPool() throws IOException {
        expectParsed("interned reference control", twoTargets(), new int[] {10123, 10124},
                new String[] {FLAGS, FLAGS}, new int[] {24624, 24608});
        expectRefused("duplicate definition of a tag name", duplicateTagDefinition(),
                "duplicate_interned_string");
        expectRefused("duplicate definition of an interned value", duplicateValueDefinition(),
                "duplicate_interned_string");
        expectRefused("duplicate definition of an attribute name", duplicateNameDefinition(),
                "duplicate_interned_string");
        final int[] offsets = new int[1];
        final byte[] ceiling = poolCeiling(offsets);
        final int overflow = occurrences(ceiling, definition(ascii("overflow")));
        final byte[] last = Arrays.copyOfRange(ceiling, offsets[0], offsets[0] + 3);
        check("pool ceiling document reaches the writer's ceiling", overflow == 4
                && Arrays.equals(last, bytes(0x32, 0xff, 0xfe)),
                overflow + " " + Arrays.toString(last));
        expectParsed("pool ceiling keeps repeated uncached definitions", ceiling,
                new int[] {10123}, new String[] {FLAGS}, new int[] {24624});
        expectRefused("definition of the last interned string after the ceiling",
                spliced(ceiling, offsets[0] + 1, 2, definition(ascii(LAST_INTERNED))),
                "duplicate_interned_string");
    }

    private void endFence() throws IOException {
        final byte[] data = canonical();
        expectRefused("missing end document", Arrays.copyOf(data, data.length - 1),
                "missing_end_document");
        final Set<String> incomplete = Set.of("header", "truncated", "missing_end_document");
        final Set<String> codes = new TreeSet<>();
        int refused = 0;
        for (int length = 0; length < data.length; length++) {
            final PermissionStoreReader.Result result =
                    PermissionStoreReader.read(Arrays.copyOf(data, length), IDS);
            if (!result.parsed) {
                codes.add(result.code);
                if (incomplete.contains(result.code)) {
                    refused++;
                }
            }
        }
        check("every proper prefix refused as incomplete", refused == data.length,
                refused + " of " + data.length + " " + codes);
        int trailing = 0;
        for (int value = 0; value < 256; value++) {
            final PermissionStoreReader.Result result =
                    PermissionStoreReader.read(concat(data, new byte[] {(byte) value}), IDS);
            if (!result.parsed && "trailing_bytes".equals(result.code)) {
                trailing++;
            }
        }
        check("every single trailing byte refused", trailing == 256, trailing + " of 256");
        expectRefused("second document appended", concat(data, data), "trailing_bytes");
        final int[] cut = new int[1];
        final byte[] early = earlyTarget(cut);
        expectParsed("early target control", early, new int[] {10123, 10124},
                new String[] {FLAGS, FLAGS}, new int[] {24624, 24608});
        final byte[] target = Arrays.copyOf(early, cut[0]);
        expectRefused("truncated after target", target, "truncated");
        expectRefused("end document after target", concat(target, new byte[] {0x11}),
                "unclosed_elements");
        expectRefused("unknown token after target", patched(early, cut[0], 0x0b),
                "parser_error");
        expectRefused("invalid reference after target",
                concat(target, new byte[] {0x33, 0x7f, 0x7f}), "parser_error");
        expectRefused("missing end document after target", Arrays.copyOf(early, early.length - 1),
                "missing_end_document");
    }

    // Well formed changes are not detected: parsing is not authentication or damage detection.
    private void integrityLimits() throws IOException {
        final int[] cut = new int[2];
        final byte[] data = integrity(cut);
        final int[] ids = {10123, 10124};
        expectParsed("limit control", data, ids, new String[] {FLAGS, FLAGS},
                new int[] {24624, 24608});
        expectParsed("limit: a valid target name substitution stays well formed",
                replacedOnce(data, declared(ascii(POST)), declared(ascii(SAME_LENGTH))), ids,
                new String[] {NO_PERMISSION, NO_PERMISSION}, new int[] {0, 0});
        expectParsed("limit: a valid flags substitution stays well formed",
                replacedOnce(data, int32(24624), int32(24608)), ids,
                new String[] {FLAGS, FLAGS}, new int[] {24608, 24608});
        expectParsed("limit: a clean deletion stays well formed",
                spliced(data, cut[0], cut[1] - cut[0], new byte[0]), ids,
                new String[] {FLAGS, NO_PERMISSION}, new int[] {24624, 0});
    }

    // The pinned parser's own behavior, which the reader's checks answer. Each observation must
    // stay true; a stricter parser would make the corresponding explanation stale.
    private void parserObservations() throws IOException {
        final byte[] data = canonical();
        check("parser reports end of input as END_DOCUMENT",
                "END_DOCUMENT".equals(rawOutcome(Arrays.copyOf(data, data.length - 1))), "");
        check("parser reports end of input inside a name as END_DOCUMENT",
                "END_DOCUMENT".equals(rawOutcome(Arrays.copyOf(data, 8))), "");
        final String afterStart = rawOutcome(Arrays.copyOf(data, 16));
        check("parser propagates end of input after a start tag",
                "java.io.EOFException".equals(afterStart), afterStart);
        final byte[] tail = concat(data, new byte[] {0x00});
        final PermissionStoreReader.OneByteSource source =
                new PermissionStoreReader.OneByteSource(tail);
        final String outcome = rawOutcome(source);
        check("parser reads nothing after END_DOCUMENT", "END_DOCUMENT".equals(outcome)
                && source.delivered() == data.length && source.endReports() == 0,
                outcome + " delivered=" + source.delivered());
        check("parser accepts a missing start document",
                "END_DOCUMENT".equals(rawOutcome(removed(data, 4))), "");
        check("parser accepts noncanonical event types",
                "END_DOCUMENT".equals(rawOutcome(patched(data, 5, 0x02))), "");
        check("parser accepts mismatched end tags", "END_DOCUMENT".equals(rawOutcome(document(
                out -> {
                    out.startTag(null, "access");
                    out.endTag(null, "other");
                }))), "");
        check("parser accepts END_DOCUMENT inside an element", "END_DOCUMENT".equals(rawOutcome(
                document(out -> out.startTag(null, "access")))), "");
        check("parser discards stray attributes", "END_DOCUMENT".equals(rawOutcome(section(
                entries -> {
                    appId(entries, 10123, NOTHING);
                    entries.attributeInt(null, "flags", 1);
                }))), "");
        check("parser returns null for an unassigned interned name",
                rawNullName(UNASSIGNED_NAME), "");
        check("parser decodes an overlong name as the plain name",
                "access".equals(rawFirstName(overlongAccess()))
                        && "END_DOCUMENT".equals(rawOutcome(overlongTarget())), "");
        check("parser accepts raw NUL bytes", "END_DOCUMENT".equals(rawOutcome(rawNul()))
                && "END_DOCUMENT".equals(rawOutcome(offsetNul())), "");
        check("parser accepts duplicate intern definitions",
                "END_DOCUMENT".equals(rawOutcome(duplicateTagDefinition()))
                        && "END_DOCUMENT".equals(rawOutcome(duplicateValueDefinition()))
                        && "END_DOCUMENT".equals(rawOutcome(duplicateNameDefinition())), "");
        final int[] offsets = new int[1];
        final byte[] ceiling = poolCeiling(offsets);
        check("parser accepts a definition of an interned string after the ceiling",
                "END_DOCUMENT".equals(rawOutcome(spliced(ceiling, offsets[0] + 1, 2,
                        definition(ascii(LAST_INTERNED))))), "");
        final String four = rawOutcome(fourByteForm());
        check("parser refuses a four byte form", "java.io.UTFDataFormatException".equals(four),
                four);
        final String unknown = rawOutcome(section(entries -> entries.entityRef("unknown")));
        check("parser raises XmlPullParserException for an unknown entity",
                "org.xmlpull.v1.XmlPullParserException".equals(unknown), unknown);
        final String hexadecimal = rawOutcome(section(entries -> entries.entityRef("#x41")));
        check("parser raises NumberFormatException for a hexadecimal entity",
                "java.lang.NumberFormatException".equals(hexadecimal), hexadecimal);
        check("parser returns other tokens and known entities",
                "END_DOCUMENT".equals(rawOutcome(otherTokens())), "");
    }

    private void arguments() {
        check("valid app ids", Arrays.equals(PermissionStoreReader.parseAppIds(
                new String[] {"10000", "19999", "12345"}), new int[] {10000, 19999, 12345}), "");
        final String[][] invalid = {
            {}, {"9999"}, {"20000"}, {"010000"}, {"+10000"}, {"-10000"}, {"1e4"}, {" 10000"},
            {"10000 "}, {"10000", "10000"}, {"\uff11\uff10\uff10\uff10\uff10"}, {"100000"}, {""},
            {"0x2710"}, {null},
        };
        for (String[] args : invalid) {
            check("invalid app ids " + Arrays.toString(args), rejectsArguments(args), "accepted");
        }
        final String[] many = new String[PermissionStoreReader.MAX_REQUESTED_APP_IDS + 1];
        for (int i = 0; i < many.length; i++) {
            many[i] = Integer.toString(10000 + i);
        }
        check("too many app ids", rejectsArguments(many), "accepted");
        check("maximum app ids", !rejectsArguments(Arrays.copyOf(many, many.length - 1)),
                "refused");
        check("read refuses invalid app ids", rejectsRead(new int[] {9999})
                && rejectsRead(new int[] {20000}) && rejectsRead(new int[0])
                && rejectsRead(new int[] {10000, 10000}), "accepted");
        final PermissionStoreReader.Result large = PermissionStoreReader.read(
                new byte[PermissionStoreReader.MAX_INPUT_BYTES + 1], IDS);
        check("oversize input", !large.parsed && "input_too_large".equals(large.code)
                && large.sha256 == null, large.toJson());
        final PermissionStoreReader.Result limit = PermissionStoreReader.read(
                new byte[PermissionStoreReader.MAX_INPUT_BYTES], IDS);
        check("input at the limit reaches the parser", !limit.parsed
                && "header".equals(limit.code)
                && limit.length == PermissionStoreReader.MAX_INPUT_BYTES, limit.toJson());
    }

    private void json() throws IOException {
        final byte[] data = canonical();
        final String parsed = PermissionStoreReader.read(data, new int[] {10123, 10126, 10999})
                .toJson();
        final String expectedParsed = "{\"schema\":\"andrix.permission-store.reader.v1\","
                + "\"result\":\"parsed\",\"input\":{\"length\":" + data.length
                + ",\"sha256\":\"" + PermissionStoreReader.sha256(data) + "\"},"
                + "\"document\":{\"elements\":23,\"app_id_entries\":5,\"permission_entries\":6},"
                + "\"app_ids\":[{\"app_id\":10123,\"state\":\"flags\",\"flags\":24624},"
                + "{\"app_id\":10126,\"state\":\"permission_absent\",\"flags\":null},"
                + "{\"app_id\":10999,\"state\":\"app_id_absent\",\"flags\":null}]}";
        check("parsed json", parsed.equals(expectedParsed), parsed);
        final byte[] tail = concat(data, new byte[] {0x11});
        final String refused = PermissionStoreReader.read(tail, IDS).toJson();
        final String expectedRefused = "{\"schema\":\"andrix.permission-store.reader.v1\","
                + "\"result\":\"refused\",\"input\":{\"length\":" + tail.length
                + ",\"sha256\":\"" + PermissionStoreReader.sha256(tail) + "\"},"
                + "\"refusal\":{\"code\":\"trailing_bytes\",\"exception\":null,"
                + "\"offset\":" + data.length + ",\"step\":" + CANONICAL_TOKENS + "}}";
        check("refused json", refused.equals(expectedRefused), refused);
        final String string = PermissionStoreReader.read(overlongTarget(), IDS).toJson();
        check("string refusal json names no exception", string.contains(
                "\"refusal\":{\"code\":\"noncanonical_string\",\"exception\":null,"), string);
        check("json string escaping", PermissionStoreReader.quote("a\"b\\c\u0001\u00e9")
                .equals("\"a\\\"b\\\\c\\u0001\\u00e9\""), PermissionStoreReader.quote("\u0001"));
    }

    // Helpers for observations and argument checks.

    static String rawOutcome(byte[] data) {
        return rawOutcome(new ByteArrayInputStream(data));
    }

    /** Runs the plain pinned parser to its first END_DOCUMENT; otherwise names the failure. */
    static String rawOutcome(InputStream in) {
        try {
            final BinaryXmlPullParser parser = new BinaryXmlPullParser();
            parser.setInput(in, null);
            for (int steps = 0; steps < 1_000_000; steps++) {
                if (parser.nextToken() == XmlPullParser.END_DOCUMENT) {
                    return "END_DOCUMENT";
                }
            }
            return "NO_END_DOCUMENT";
        } catch (XmlPullParserException | IOException | RuntimeException error) {
            return error.getClass().getName();
        }
    }

    static boolean rawNullName(byte[] data) {
        try {
            final BinaryXmlPullParser parser = new BinaryXmlPullParser();
            parser.setInput(new ByteArrayInputStream(data), null);
            return parser.nextToken() == XmlPullParser.START_TAG && parser.getName() == null;
        } catch (XmlPullParserException | IOException | RuntimeException error) {
            return false;
        }
    }

    static String rawFirstName(byte[] data) {
        try {
            final BinaryXmlPullParser parser = new BinaryXmlPullParser();
            parser.setInput(new ByteArrayInputStream(data), null);
            return parser.nextToken() == XmlPullParser.START_TAG ? parser.getName() : null;
        } catch (XmlPullParserException | IOException | RuntimeException error) {
            return null;
        }
    }

    /**
     * Recording changes no decoding: tokens, names, text, depth, attribute names, values and
     * every typed attribute reading match the plain parser, and the recording input refuses
     * nothing.
     */
    static boolean sameDecoding(byte[] data) throws XmlPullParserException, IOException {
        final BinaryXmlPullParser plain = new BinaryXmlPullParser();
        plain.setInput(new ByteArrayInputStream(data), null);
        final PermissionStoreReader.RecordingParser recording =
                new PermissionStoreReader.RecordingParser();
        recording.setInput(new PermissionStoreReader.OneByteSource(data), null);
        recording.input().drain();
        while (true) {
            final int token = plain.nextToken();
            if (token != recording.nextToken() || !describe(plain).equals(describe(recording))) {
                return false;
            }
            recording.input().drain();
            if (token == XmlPullParser.END_DOCUMENT) {
                return recording.input().refusal() == null;
            }
        }
    }

    /** What the parser API reports for the current token. */
    static List<String> describe(BinaryXmlPullParser parser) {
        final List<String> result = new ArrayList<>();
        result.add(String.valueOf(parser.getName()));
        result.add(String.valueOf(parser.getText()));
        result.add(Integer.toString(parser.getDepth()));
        final int count = parser.getAttributeCount();
        result.add(Integer.toString(count));
        for (int i = 0; i < count; i++) {
            final int index = i;
            result.add(String.valueOf(parser.getAttributeName(index)));
            // Each reading depends on the attribute's recorded type. Readings that reach a
            // compile only facade fail there, which both parsers must do alike.
            result.add(reading(() -> parser.getAttributeValue(index)));
            result.add(reading(() -> parser.getAttributeInt(index)));
            result.add(reading(() -> parser.getAttributeIntHex(index)));
            result.add(reading(() -> parser.getAttributeLong(index)));
            result.add(reading(() -> parser.getAttributeLongHex(index)));
            result.add(reading(() -> parser.getAttributeFloat(index)));
            result.add(reading(() -> parser.getAttributeDouble(index)));
            result.add(reading(() -> parser.getAttributeBoolean(index)));
            result.add(reading(() -> parser.getAttributeBytesHex(index)));
            result.add(reading(() -> parser.getAttributeBytesBase64(index)));
        }
        return result;
    }

    static String reading(Reading reading) {
        try {
            final Object value = reading.read();
            return value instanceof byte[] array ? Arrays.toString(array) : String.valueOf(value);
        } catch (XmlPullParserException | RuntimeException error) {
            return error.getClass().getName();
        }
    }

    static boolean rejectsArguments(String[] args) {
        try {
            PermissionStoreReader.parseAppIds(args);
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }

    static boolean rejectsRead(int[] ids) {
        try {
            PermissionStoreReader.read(new byte[0], ids);
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }

    /** Writes the fixtures used by the Python tool tests into an existing empty directory. */
    static void writeFixtures(Path directory) throws IOException {
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("fixture directory missing");
        }
        final byte[] data = canonical();
        final int[] cut = new int[1];
        final byte[] early = earlyTarget(cut);
        final Map<String, byte[]> fixtures = new LinkedHashMap<>();
        fixtures.put("canonical.abx", data);
        fixtures.put("missing-end-document.abx", Arrays.copyOf(data, data.length - 1));
        fixtures.put("trailing-byte.abx", concat(data, new byte[] {0x11}));
        fixtures.put("truncated-after-target.abx", Arrays.copyOf(early, cut[0]));
        fixtures.put("unclosed-after-target.abx",
                concat(Arrays.copyOf(early, cut[0]), new byte[] {0x11}));
        fixtures.put("duplicate-app-id.abx", section(entries -> {
            appId(entries, 10123, app -> permission(app, POST, 24624));
            appId(entries, 10123, app -> permission(app, POST, 24608));
        }));
        fixtures.put("duplicate-permission.abx", section(entries -> appId(entries, 10123,
                app -> {
                    permission(app, POST, 24624);
                    permission(app, POST, 24608);
                })));
        fixtures.put("wrong-root.abx", document(out -> tag(out, "permissions",
                root -> canonicalSection(root))));
        fixtures.put("int-hex-flags.abx", permissionWith(app -> app.attributeIntHex(null,
                "flags", 24624)));
        fixtures.put("noncanonical-name.abx", overlongTarget());
        fixtures.put("duplicate-definition.abx", duplicateValueDefinition());
        fixtures.put("flag-bounds.abx", section(entries -> {
            appId(entries, 10000, app -> permission(app, POST, Integer.MIN_VALUE));
            appId(entries, 19999, app -> permission(app, POST, Integer.MAX_VALUE));
            appId(entries, 10001, app -> permission(app, POST, -1));
        }));
        for (Map.Entry<String, byte[]> fixture : fixtures.entrySet()) {
            Files.write(directory.resolve(fixture.getKey()), fixture.getValue(),
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        }
    }
}
