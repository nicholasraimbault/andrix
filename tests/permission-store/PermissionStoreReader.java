// SPDX-License-Identifier: Apache-2.0

import com.android.modules.utils.BinaryXmlPullParser;
import com.android.modules.utils.FastDataInput;
import com.android.modules.utils.ModifiedUtf8;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Offline host reader for stored {@code POST_NOTIFICATIONS} flags in one Android permission
 * store file ({@code access.abx}).
 *
 * <p>The pinned {@link BinaryXmlPullParser} performs all binary XML decoding. This class feeds it
 * one byte per read. Through the parser's own {@code obtainFastDataInput} hook it records the
 * event bytes the parser consumes and checks each string the parser reads against the pinned
 * writer's encoding and intern rules. It then checks the document structure and the exact writer
 * layout of the extraction path. It reports stored integers only. It does not interpret flags,
 * establish live permission state or write anything except its JSON result.
 */
public final class PermissionStoreReader {
    static final String SCHEMA = "andrix.permission-store.reader.v1";
    static final int MAX_INPUT_BYTES = 8 * 1024 * 1024;
    static final int MIN_APP_ID = 10_000;
    static final int MAX_APP_ID = 19_999;
    static final int MAX_REQUESTED_APP_IDS = 64;
    static final int MAX_DEPTH = 32;
    static final int MAX_ATTRIBUTES = 64;

    // Extraction path, as the pinned AccessPolicy and AppIdPermissionPersistence write it:
    // /access/app-id-permissions/app-id[@id]/permission[@name, @flags].
    static final String ROOT = "access";
    static final String SECTION = "app-id-permissions";
    static final String APP_ID = "app-id";
    static final String PERMISSION = "permission";
    static final String ATTR_ID = "id";
    static final String ATTR_NAME = "name";
    static final String ATTR_FLAGS = "flags";
    static final String TARGET_PERMISSION = "android.permission.POST_NOTIFICATIONS";

    // An event byte holds a token in its low nibble and a data type in its high nibble. The
    // values follow the pinned BinaryXmlSerializer, whose constants are package private.
    static final int TOKEN_MASK = 0x0f;
    static final int TYPE_MASK = 0xf0;
    static final int ATTRIBUTE = 15;
    static final int TYPE_NULL = 1 << 4;
    static final int TYPE_STRING = 2 << 4;
    static final int TYPE_STRING_INTERNED = 3 << 4;
    static final int TYPE_INT = 6 << 4;
    static final int TYPE_INT_HEX = 7 << 4;
    static final int TYPE_BOOLEAN_FALSE = 13 << 4;
    static final int EVENT_START_DOCUMENT = XmlPullParser.START_DOCUMENT | TYPE_NULL;
    static final int EVENT_END_DOCUMENT = XmlPullParser.END_DOCUMENT | TYPE_NULL;
    static final int EVENT_START_TAG = XmlPullParser.START_TAG | TYPE_STRING_INTERNED;
    static final int EVENT_END_TAG = XmlPullParser.END_TAG | TYPE_STRING_INTERNED;

    static final String STATE_FLAGS = "flags";
    static final String STATE_PERMISSION_ABSENT = "permission_absent";
    static final String STATE_APP_ID_ABSENT = "app_id_absent";

    static final int EXIT_PARSED = 0;
    static final int EXIT_REFUSED = 1;
    static final int EXIT_USAGE = 2;
    static final int EXIT_FAILURE = 70;

    private static final Pattern APP_ID_TEXT = Pattern.compile("[1-9][0-9]{4}");
    private static final String USAGE = "usage: PermissionStoreReader APP_ID... < access.abx"
            + " (1 to 64 distinct decimal app ids, 10000 to 19999)";

    private PermissionStoreReader() {
    }

    public static void main(String[] args) {
        int status;
        try {
            status = run(args, System.in, System.out, System.err);
        } catch (Throwable error) {
            // Never print a message or stack trace: parser messages can quote input bytes.
            System.err.println("permission store reader failure: " + error.getClass().getName());
            status = EXIT_FAILURE;
        }
        System.exit(status);
    }

    static int run(String[] args, InputStream in, PrintStream out, PrintStream err)
            throws IOException {
        final int[] appIds;
        try {
            appIds = parseAppIds(args);
        } catch (IllegalArgumentException error) {
            err.println(USAGE);
            return EXIT_USAGE;
        }
        final byte[] data = in.readNBytes(MAX_INPUT_BYTES + 1);
        final Result result = read(data, appIds);
        out.print(result.toJson());
        out.print('\n');
        out.flush();
        if (out.checkError()) {
            throw new IOException("result output failed");
        }
        return result.parsed ? EXIT_PARSED : EXIT_REFUSED;
    }

    static int[] parseAppIds(String[] args) {
        if (args == null || args.length == 0 || args.length > MAX_REQUESTED_APP_IDS) {
            throw new IllegalArgumentException("app id count");
        }
        final int[] result = new int[args.length];
        for (int i = 0; i < args.length; i++) {
            if (args[i] == null || !APP_ID_TEXT.matcher(args[i]).matches()) {
                throw new IllegalArgumentException("app id syntax");
            }
            result[i] = Integer.parseInt(args[i]);
        }
        validateAppIds(result);
        return result;
    }

    static void validateAppIds(int[] appIds) {
        if (appIds == null || appIds.length == 0 || appIds.length > MAX_REQUESTED_APP_IDS) {
            throw new IllegalArgumentException("app id count");
        }
        final Set<Integer> seen = new HashSet<>();
        for (int appId : appIds) {
            if (appId < MIN_APP_ID || appId > MAX_APP_ID || !seen.add(appId)) {
                throw new IllegalArgumentException("app id value");
            }
        }
    }

    /** Decodes one complete document. Never returns partial per app results on refusal. */
    static Result read(byte[] data, int[] appIds) {
        Objects.requireNonNull(data, "data");
        validateAppIds(appIds);
        if (data.length > MAX_INPUT_BYTES) {
            return Result.refused(-1, null, "input_too_large", null, 0, 0);
        }
        return new Decoder(data, appIds.clone()).run(sha256(data));
    }

    static String sha256(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 unavailable", error);
        }
    }

    static String quote(String value) {
        final StringBuilder out = new StringBuilder(value.length() + 2).append('"');
        for (int i = 0; i < value.length(); i++) {
            final char c = value.charAt(i);
            if (c == '"' || c == '\\') {
                out.append('\\').append(c);
            } else if (c < 0x20 || c > 0x7e) {
                final int code = c;
                out.append(String.format("\\u%04x", code));
            } else {
                out.append(c);
            }
        }
        return out.append('"').toString();
    }

    /**
     * Delivers at most one byte per read. The pinned FastDataInput fills its buffer only until a
     * request is satisfied, so the bytes delivered here equal the bytes the parser has consumed,
     * plus the single event byte it peeks after a start tag. A returned -1 is counted: the
     * parser converts most end of input conditions into END_DOCUMENT.
     */
    static final class OneByteSource extends InputStream {
        private final byte[] data;
        private int delivered;
        private int endReports;

        OneByteSource(byte[] data) {
            this.data = data;
        }

        @Override
        public int read() {
            if (delivered == data.length) {
                endReports++;
                return -1;
            }
            return data[delivered++] & 0xff;
        }

        @Override
        public int read(byte[] target, int offset, int length) {
            Objects.checkFromIndexSize(offset, length, target.length);
            if (length == 0) {
                return 0;
            }
            if (delivered == data.length) {
                endReports++;
                return -1;
            }
            target[offset] = data[delivered++];
            return 1;
        }

        int delivered() {
            return delivered;
        }

        int endReports() {
            return endReports;
        }

        /** Whether bytes already delivered from offset on equal expected. */
        boolean deliveredEquals(int offset, byte[] expected) {
            return offset >= 0 && expected.length <= delivered - offset
                    && Arrays.equals(data, offset, offset + expected.length, expected, 0,
                            expected.length);
        }
    }

    /** Raised inside the pinned parser when the recording input refuses the document. */
    static final class InputRefusedException extends IOException {
        private static final long serialVersionUID = 1L;

        InputRefusedException() {
            super("input refused");
        }
    }

    /**
     * The pinned FastDataInput with three checked reads, each of which returns the pinned result
     * unchanged or refuses the whole document.
     *
     * <p>readByte() records every event byte and enforces the attribute bound. In the pinned
     * parser it reads only token event bytes; names and values use the short, int, long and UTF
     * readers.
     *
     * <p>readUTF() accepts a string only when its bytes are exactly what the pinned writer
     * produces for the decoded value: FastDataOutput.writeUTF declares
     * ModifiedUtf8.countBytes(value, false) bytes and writes ModifiedUtf8.encode(value). The
     * pinned parser calls it for plain string values, text tokens and entity names, and the
     * pinned readInternedUTF() calls it virtually for every definition.
     *
     * <p>readInternedUTF() mirrors the pinned intern pool in a set of at most MAX_UNSIGNED_SHORT
     * strings. The pinned writer defines a string again only when it is not interned, which
     * happens only after the pool is full. A definition of a string that is already interned did
     * not come from that writer.
     */
    static final class RecordingInput extends FastDataInput {
        private final OneByteSource source;
        private final byte[] events = new byte[MAX_ATTRIBUTES + 1];
        private final Set<String> interned = new HashSet<>();
        private int count;
        private int strings;
        private String refusal;

        RecordingInput(OneByteSource source) {
            super(source, DEFAULT_BUFFER_SIZE);
            this.source = source;
        }

        @Override
        public byte readByte() throws IOException {
            if (count == events.length) {
                throw refuse("attribute_bound");
            }
            final byte value = super.readByte();
            events[count++] = value;
            return value;
        }

        @Override
        public String readUTF() throws IOException {
            final int start = consumed();
            final String value = super.readUTF();
            // The pinned readUTF consumed a two byte declared length and then exactly that many
            // bytes, so the declared length is what it consumed after the first two bytes.
            final int declared = consumed() - start - 2;
            if (ModifiedUtf8.countBytes(value, false) != declared) {
                throw refuse("noncanonical_string");
            }
            // Equal lengths alone would still accept a raw NUL byte that offsets an overlong form.
            final byte[] canonical = new byte[declared];
            ModifiedUtf8.encode(canonical, 0, value);
            if (!source.deliveredEquals(start + 2, canonical)) {
                throw refuse("noncanonical_string");
            }
            strings++;
            return value;
        }

        @Override
        public String readInternedUTF() throws IOException {
            final int before = strings;
            final String value = super.readInternedUTF();
            if (strings != before) {
                // The pinned method read a definition rather than a reference.
                if (interned.contains(value)) {
                    throw refuse("duplicate_interned_string");
                }
                if (interned.size() < MAX_UNSIGNED_SHORT) {
                    interned.add(value);
                }
            }
            return value;
        }

        /** Bytes the pinned input has consumed: delivered by the source and no longer buffered. */
        private int consumed() {
            return source.delivered() - (mBufferLim - mBufferPos);
        }

        private InputRefusedException refuse(String code) {
            refusal = code;
            return new InputRefusedException();
        }

        int[] drain() {
            final int[] result = new int[count];
            for (int i = 0; i < count; i++) {
                result[i] = events[i] & 0xff;
            }
            count = 0;
            return result;
        }

        /** The refusal code if this input refused the document, otherwise null. */
        String refusal() {
            return refusal;
        }
    }

    /** The pinned parser, unchanged except for the input it obtains through its own hook. */
    static final class RecordingParser extends BinaryXmlPullParser {
        private RecordingInput input;

        // @Override makes compilation fail if the pinned hook ever changes its signature.
        @Override
        protected FastDataInput obtainFastDataInput(InputStream in) {
            if (input != null) {
                throw new IllegalStateException("one document per parser");
            }
            if (!(in instanceof OneByteSource source)) {
                throw new IllegalArgumentException("the recording parser reads a OneByteSource");
            }
            input = new RecordingInput(source);
            return input;
        }

        RecordingInput input() {
            return input;
        }
    }

    static final class Refusal extends Exception {
        private static final long serialVersionUID = 1L;

        final String code;
        final String exception;

        Refusal(String code, String exception) {
            super(code, null, false, false);
            this.code = code;
            this.exception = exception;
        }
    }

    static final class Result {
        final boolean parsed;
        final int length;
        final String sha256;
        final String code;
        final String exception;
        final int offset;
        final int step;
        final int elements;
        final int appIdEntries;
        final int permissionEntries;
        final int[] appIds;
        final String[] states;
        final int[] flags;

        private Result(boolean parsed, int length, String sha256, String code, String exception,
                int offset, int step, int elements, int appIdEntries, int permissionEntries,
                int[] appIds, String[] states, int[] flags) {
            this.parsed = parsed;
            this.length = length;
            this.sha256 = sha256;
            this.code = code;
            this.exception = exception;
            this.offset = offset;
            this.step = step;
            this.elements = elements;
            this.appIdEntries = appIdEntries;
            this.permissionEntries = permissionEntries;
            this.appIds = appIds;
            this.states = states;
            this.flags = flags;
        }

        static Result refused(int length, String sha256, String code, String exception,
                int offset, int step) {
            return new Result(false, length, sha256, code, exception, offset, step, 0, 0, 0,
                    new int[0], new String[0], new int[0]);
        }

        static Result parsed(int length, String sha256, int elements, int appIdEntries,
                int permissionEntries, int[] appIds, String[] states, int[] flags) {
            return new Result(true, length, sha256, null, null, length, 0, elements,
                    appIdEntries, permissionEntries, appIds, states, flags);
        }

        String toJson() {
            final StringBuilder out = new StringBuilder(256);
            out.append("{\"schema\":").append(quote(SCHEMA));
            out.append(",\"result\":").append(quote(parsed ? "parsed" : "refused"));
            out.append(",\"input\":{\"length\":");
            if (sha256 == null) {
                out.append("null,\"sha256\":null}");
            } else {
                out.append(length).append(",\"sha256\":").append(quote(sha256)).append('}');
            }
            if (parsed) {
                out.append(",\"document\":{\"elements\":").append(elements);
                out.append(",\"app_id_entries\":").append(appIdEntries);
                out.append(",\"permission_entries\":").append(permissionEntries).append('}');
                out.append(",\"app_ids\":[");
                for (int i = 0; i < appIds.length; i++) {
                    if (i > 0) {
                        out.append(',');
                    }
                    out.append("{\"app_id\":").append(appIds[i]);
                    out.append(",\"state\":").append(quote(states[i]));
                    out.append(",\"flags\":");
                    if (STATE_FLAGS.equals(states[i])) {
                        out.append(flags[i]);
                    } else {
                        out.append("null");
                    }
                    out.append('}');
                }
                out.append(']');
            } else {
                out.append(",\"refusal\":{\"code\":").append(quote(code));
                out.append(",\"exception\":");
                out.append(exception == null ? "null" : quote(exception));
                out.append(",\"offset\":").append(offset);
                out.append(",\"step\":").append(step).append('}');
            }
            return out.append('}').toString();
        }
    }

    /** Single use walk of one document through the pinned parser. */
    static final class Decoder {
        private final byte[] data;
        private final int[] requested;
        private final Set<Integer> requestedSet = new HashSet<>();
        private final OneByteSource source;
        private final RecordingParser parser = new RecordingParser();
        private final ArrayList<String> open = new ArrayList<>();
        private final Set<Integer> appIds = new HashSet<>();
        private final Set<String> permissions = new HashSet<>();
        private final Set<Integer> present = new HashSet<>();
        private final Map<Integer, Integer> flags = new HashMap<>();
        private int steps;
        private int elements;
        private int appIdEntries;
        private int permissionEntries;
        private int appId;
        private boolean rootSeen;
        private boolean sectionSeen;
        private boolean sectionOpen;

        Decoder(byte[] data, int[] requested) {
            this.data = data;
            this.requested = requested;
            this.source = new OneByteSource(data);
            for (int id : requested) {
                requestedSet.add(id);
            }
        }

        Result run(String sha256) {
            try {
                begin();
                while (true) {
                    final int token = next();
                    final int[] events = events();
                    if (token == XmlPullParser.END_DOCUMENT) {
                        endDocument(events);
                        break;
                    }
                    if (source.endReports() != 0) {
                        throw refusal("truncated", null);
                    }
                    if (token == XmlPullParser.START_TAG) {
                        startTag(events);
                    } else if (token == XmlPullParser.END_TAG) {
                        endTag(events);
                    } else {
                        throw refusal("unexpected_token", null);
                    }
                }
            } catch (Refusal refusal) {
                return Result.refused(data.length, sha256, refusal.code, refusal.exception,
                        source.delivered(), steps);
            }
            final String[] states = new String[requested.length];
            final int[] values = new int[requested.length];
            for (int i = 0; i < requested.length; i++) {
                final Integer value = flags.get(requested[i]);
                if (value != null) {
                    states[i] = STATE_FLAGS;
                    values[i] = value;
                } else if (present.contains(requested[i])) {
                    states[i] = STATE_PERMISSION_ABSENT;
                } else {
                    states[i] = STATE_APP_ID_ABSENT;
                }
            }
            return Result.parsed(data.length, sha256, elements, appIdEntries, permissionEntries,
                    requested.clone(), states, values);
        }

        private void begin() throws Refusal {
            try {
                parser.setInput(source, null);
            } catch (XmlPullParserException | RuntimeException error) {
                throw failure("header", error);
            }
            requireInputAccepted();
            final int[] events = events();
            if (events.length == 0) {
                throw refusal("missing_start_document", null);
            }
            requireToken(events, XmlPullParser.START_DOCUMENT, EVENT_START_DOCUMENT);
            if (events.length != 1) {
                throw refusal("event_accounting", null);
            }
        }

        private int next() throws Refusal {
            final int token;
            try {
                token = parser.nextToken();
            } catch (XmlPullParserException | IOException | RuntimeException error) {
                throw failure(source.endReports() != 0 ? "truncated" : "parser_error", error);
            }
            steps++;
            requireInputAccepted();
            return token;
        }

        private void startTag(int[] events) throws Refusal {
            requireToken(events, XmlPullParser.START_TAG, EVENT_START_TAG);
            final int count = parser.getAttributeCount();
            if (count != events.length - 1) {
                throw refusal("event_accounting", null);
            }
            // events[0] is the start tag; events[i + 1] is the event that attribute i came from.
            final int[] types = new int[count];
            for (int i = 0; i < count; i++) {
                final int event = events[i + 1];
                if ((event & TOKEN_MASK) != ATTRIBUTE) {
                    throw refusal("event_accounting", null);
                }
                types[i] = event & TYPE_MASK;
                if (types[i] < TYPE_STRING || types[i] > TYPE_BOOLEAN_FALSE) {
                    throw refusal("attribute_encoding", null);
                }
            }
            final String name = parser.getName();
            if (name == null || name.isEmpty()) {
                throw refusal("invalid_name", null);
            }
            final Set<String> names = new HashSet<>();
            for (int i = 0; i < count; i++) {
                final String attribute = parser.getAttributeName(i);
                if (attribute == null || attribute.isEmpty()) {
                    throw refusal("invalid_name", null);
                }
                if (!names.add(attribute)) {
                    throw refusal("duplicate_attribute", null);
                }
                if (types[i] == TYPE_STRING_INTERNED && parser.getAttributeValue(i) == null) {
                    throw refusal("invalid_value", null);
                }
            }
            final int depth = open.size() + 1;
            if (depth > MAX_DEPTH) {
                throw refusal("depth_bound", null);
            }
            if (depth == 1) {
                if (rootSeen) {
                    throw refusal("multiple_roots", null);
                }
                rootSeen = true;
                if (!ROOT.equals(name)) {
                    throw refusal("wrong_root", null);
                }
                // The pinned AccessPolicy writes tag(TAG_ACCESS) without attributes.
                if (count != 0) {
                    throw refusal("unexpected_attribute", null);
                }
            } else if (depth == 2 && SECTION.equals(name)) {
                if (sectionSeen) {
                    throw refusal("duplicate_section", null);
                }
                if (count != 0) {
                    throw refusal("unexpected_attribute", null);
                }
                sectionSeen = true;
                sectionOpen = true;
            } else if (sectionOpen && depth == 3) {
                appIdEntry(name, types);
            } else if (sectionOpen && depth == 4) {
                permissionEntry(name, types);
            } else if (sectionOpen) {
                throw refusal("unexpected_element", null);
            }
            open.add(name);
            elements++;
        }

        /** The pinned writer: tag(TAG_APP_ID) { attributeInt(ATTR_ID, appId); ... }. */
        private void appIdEntry(String name, int[] types) throws Refusal {
            if (!APP_ID.equals(name)) {
                throw refusal("unexpected_element", null);
            }
            if (types.length != 1 || !ATTR_ID.equals(parser.getAttributeName(0))) {
                throw refusal("unexpected_attribute", null);
            }
            final int id = intAttribute(0, types[0]);
            if (!appIds.add(id)) {
                throw refusal("duplicate_app_id", null);
            }
            appId = id;
            permissions.clear();
            appIdEntries++;
            if (requestedSet.contains(id)) {
                present.add(id);
            }
        }

        /**
         * The pinned writer: tag(TAG_PERMISSION) { attributeInterned(ATTR_NAME, name);
         * attributeInt(ATTR_FLAGS, serializedFlags) }, in that order and with no children.
         */
        private void permissionEntry(String name, int[] types) throws Refusal {
            if (!PERMISSION.equals(name)) {
                throw refusal("unexpected_element", null);
            }
            if (types.length != 2 || !ATTR_NAME.equals(parser.getAttributeName(0))
                    || !ATTR_FLAGS.equals(parser.getAttributeName(1))) {
                throw refusal("unexpected_attribute", null);
            }
            if (types[0] != TYPE_STRING_INTERNED) {
                throw refusal("attribute_encoding", null);
            }
            final String permission = parser.getAttributeValue(0);
            if (permission == null || permission.isEmpty()) {
                throw refusal("invalid_value", null);
            }
            final int value = intAttribute(1, types[1]);
            if (!permissions.add(permission)) {
                throw refusal("duplicate_permission", null);
            }
            permissionEntries++;
            if (TARGET_PERMISSION.equals(permission) && requestedSet.contains(appId)) {
                flags.put(appId, value);
            }
        }

        private void endTag(int[] events) throws Refusal {
            requireToken(events, XmlPullParser.END_TAG, EVENT_END_TAG);
            if (events.length != 1) {
                throw refusal("event_accounting", null);
            }
            if (open.isEmpty()) {
                throw refusal("mismatched_end_tag", null);
            }
            final String expected = open.remove(open.size() - 1);
            if (!expected.equals(parser.getName())) {
                throw refusal("mismatched_end_tag", null);
            }
            if (open.size() == 1 && sectionOpen && SECTION.equals(expected)) {
                sectionOpen = false;
            }
        }

        private void endDocument(int[] events) throws Refusal {
            if (source.endReports() != 0) {
                // The parser reached the end of input and reported it as END_DOCUMENT.
                final boolean boundary = events.length == 0 && rootSeen && open.isEmpty();
                throw refusal(boundary ? "missing_end_document" : "truncated", null);
            }
            requireToken(events, XmlPullParser.END_DOCUMENT, EVENT_END_DOCUMENT);
            if (events.length != 1) {
                throw refusal("event_accounting", null);
            }
            if (!open.isEmpty()) {
                throw refusal("unclosed_elements", null);
            }
            if (!rootSeen) {
                throw refusal("no_root", null);
            }
            if (source.delivered() != data.length) {
                throw refusal("trailing_bytes", null);
            }
            if (!sectionSeen) {
                throw refusal("missing_section", null);
            }
            // Ask the parser for one more token: it must find the end of input itself, without
            // consuming another byte or event.
            final int token;
            try {
                token = parser.nextToken();
            } catch (XmlPullParserException | IOException | RuntimeException error) {
                throw failure("post_end_probe", error);
            }
            requireInputAccepted();
            if (token != XmlPullParser.END_DOCUMENT || events().length != 0
                    || source.endReports() != 1 || source.delivered() != data.length) {
                throw refusal("post_end_probe", null);
            }
        }

        private void requireToken(int[] events, int token, int canonical) throws Refusal {
            if (events.length == 0) {
                throw refusal("event_accounting", null);
            }
            if ((events[0] & TOKEN_MASK) == ATTRIBUTE) {
                throw refusal("stray_attribute", null);
            }
            if ((events[0] & TOKEN_MASK) != token) {
                throw refusal("event_accounting", null);
            }
            if (events[0] != canonical) {
                throw refusal("noncanonical_event", null);
            }
        }

        private int intAttribute(int index, int type) throws Refusal {
            if (type != TYPE_INT) {
                throw refusal("attribute_encoding", null);
            }
            try {
                return parser.getAttributeInt(index);
            } catch (XmlPullParserException | RuntimeException error) {
                throw refusal("event_accounting", error);
            }
        }

        private int[] events() {
            return parser.input().drain();
        }

        /** The recording input's own refusal takes precedence over the exception it caused. */
        private Refusal failure(String code, Throwable error) {
            final String refused = inputRefusal();
            return refused != null ? refusal(refused, null) : refusal(code, error);
        }

        /** Defensive: the pinned parser propagates every IOException except EOFException. */
        private void requireInputAccepted() throws Refusal {
            final String refused = inputRefusal();
            if (refused != null) {
                throw refusal(refused, null);
            }
        }

        private String inputRefusal() {
            final RecordingInput input = parser.input();
            return input == null ? null : input.refusal();
        }

        private Refusal refusal(String code, Throwable cause) {
            return new Refusal(code, cause == null ? null : cause.getClass().getName());
        }
    }
}
