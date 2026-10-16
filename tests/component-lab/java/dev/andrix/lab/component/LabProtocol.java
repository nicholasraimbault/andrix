// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Versions 1 and 2 of the lab bridge protocol, the Java side of {@code lab_protocol.py}: the typed
 * frames between the bridge and the broker. Every frame is little endian:
 *
 * <pre>
 * u32  magic      0x424c5841, "AXLB" in file order
 * u16  version    1
 * u16  type       odd for a request, its request's type plus one for a reply
 * u32  length     of the whole frame, checksum included
 * id   request    16 bytes, nonzero, fresh for each request; a reply repeats it
 * d32  manifest   32 bytes, the admitted source manifest digest, nonzero
 *      body       the type's fields, in order
 * d32  checksum   SHA-256 of every preceding byte
 * </pre>
 *
 * <p>Decoding checks the size, magic, version, type, length and checksum first, then every field's
 * bound, the absence of trailing bytes and every relation of the type. It never repairs input, and
 * every valid message has exactly one encoding. The goldens of both codecs are the same bytes.
 *
 * <p>Version 2, the next campaign profile's, differs only in the OBSERVE reply: a status, a control
 * record, a list of {@link Envelope}s and a reason. An envelope names its group, its mode, its
 * evidence digest, a block of exact layout for its mode and one deployment observation record. A
 * channel speaks exactly one version.
 */
public final class LabProtocol {
    private LabProtocol() {}

    public static final int MAGIC = 0x424c5841;
    public static final int VERSION = 1;
    public static final int VERSION_2 = 2;
    /** Envelope modes of version 2. */
    public static final int SIMPLE_CURRENT = 1, RECEIPT_EVENT = 2, COMPOSED_HEALTH = 3;
    /** Criterion row statuses of a composition. */
    public static final int HELD = 1, BAD = 2, UNKNOWN = 3;
    /** The deployment records' HEALTH classification codes. */
    public static final int HEALTH_HELD = 1, HEALTH_DEGRADED = 2, HEALTH_CRASH = 3, HEALTH_INCONCLUSIVE = 4;
    public static final int CRITERIA = 7, CRITERIA_ALL = 0x7f, NO_CRASH_OR_ANR = 1;
    static final int OBSERVATION_MAGIC = 0x52445841, OBSERVATION_TYPE = 4, KIND_HEALTH = 9, KIND_RECEIPT = 12;
    static final int RECEIPT_FULL_SCREEN = 2;
    public static final int HEADER = 60;
    public static final int CHECKSUM = 32;
    public static final int MIN_FRAME = HEADER + CHECKSUM;
    public static final int MAX_FRAME = 4 * 1024 * 1024;
    public static final int MAX_TEXT = 1024;
    public static final int MAX_STAGE_DIR = 255;
    public static final int MAX_RECORD = 65536;
    public static final int MAX_FRAMES = 256;
    public static final int MAX_LEDGER = 140;
    public static final String ZERO_ID = "0".repeat(32);
    public static final String ZERO_DIGEST = "0".repeat(64);
    /** The coordinator's only lab point, {@code Coordinator.BETWEEN_WRITES}. */
    public static final String POINT_BETWEEN_WRITES = "selection-written";
    /** Reference presence bits, as the deployment records define them. */
    public static final int SESSION = 1, CREATED = 2, STAGE_DIR = 4, INSTALLER = 8, NONCE = 16;
    public static final int BOUND_REFERENCE = SESSION | CREATED | INSTALLER | NONCE;
    public static final int SCOPE_COMPONENT = 1, SCOPE_TICKET = 2;
    public static final int TARGET_ESTABLISHED_EMPTY = 1, TARGET_HELD = 2, TARGET_UNKNOWN = 3;
    public static final int ACTOR_NONE = 0, ACTOR_GRANT_HOLDER = 1, ACTOR_LAB_OPERATOR = 2;
    public static final int HOST_SIGN = 1, HOST_PUBLISH = 2, PHASE_BEGIN = 1, PHASE_END = 2;
    public static final int OUTCOME_NONE = 0, OUTCOME_REPLY = 1, OUTCOME_NULL = 2, OUTCOME_THREW = 3;
    public static final int STATE_COUNT = 28;

    private static final Pattern PACKAGE = Pattern.compile("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+");
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    /** Thrown for a frame or message that breaks a rule of the protocol. */
    public static final class ProtocolError extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;

        ProtocolError(String reason) { super(reason); }
    }

    static ProtocolError fail(String reason) {
        return new ProtocolError(reason);
    }

    /** Message types: odd for a request, the request's type plus one for its reply. */
    public enum Type {
        HELLO(1), HELLO_REPLY(2), CLOCK(3), CLOCK_REPLY(4), OBSERVE(5), OBSERVE_REPLY(6), CROSS(7), CROSS_REPLY(8),
        POINT(9), POINT_REPLY(10), HOST(11), HOST_REPLY(12), REPORT(13), REPORT_REPLY(14);

        public final int code;

        Type(int code) { this.code = code; }

        public boolean request() { return code % 2 == 1; }

        /** The reply type that answers this request type. */
        public Type reply() {
            if (!request()) throw fail("not a request type");
            return of(code + 1);
        }

        static Type of(int code) {
            for (Type t : values()) if (t.code == code) return t;
            throw fail("an unknown message type " + code);
        }
    }

    /** Reply statuses. REFUSED answers a request that breaks the protocol or the admission. */
    public enum Status {
        OK(1), UNAVAILABLE(2), STOPPED(3), HALT(4), WITHHELD(5), NO_REPLY(6), REFUSED(7);

        public final int code;

        Status(int code) { this.code = code; }

        static Status of(long code) {
            for (Status s : values()) if (s.code == code) return s;
            throw fail("an unknown status " + code);
        }
    }

    enum Kind { U8, U16, U32, I32, I64, ID, D32, TEXT, BLOB, REF, FRAMES, CODES, ENVELOPES, ROWS }

    private static final class Field {
        final String name;
        final Kind kind;

        Field(String name, Kind kind) {
            this.name = name;
            this.kind = kind;
        }
    }

    private static final Map<Type, List<Field>> BODIES = new EnumMap<>(Type.class);
    private static final Map<Type, List<Field>> BODIES_2 = new EnumMap<>(Type.class);
    /** Each mode's block layout. Both compound blocks begin with the current read's bracket. */
    private static final Map<Integer, List<Field>> BLOCKS = new java.util.HashMap<>();

    private static List<Field> fields(Object... pairs) {
        List<Field> fields = new ArrayList<>();
        for (int i = 0; i < pairs.length; i += 2) fields.add(new Field((String) pairs[i], (Kind) pairs[i + 1]));
        return Collections.unmodifiableList(fields);
    }

    private static void body(Type type, Object... pairs) {
        BODIES.put(type, fields(pairs));
    }

    static List<Field> layout(int version, Type type) {
        if (version == VERSION) return BODIES.get(type);
        if (version == VERSION_2) return BODIES_2.get(type);
        throw fail("protocol version " + version + " is not 1 or 2");
    }

    static {
        body(Type.HELLO, "installation", Kind.ID, "coordinator", Kind.ID, "config", Kind.D32, "component", Kind.TEXT,
                "trust", Kind.D32, "route", Kind.U8);
        body(Type.HELLO_REPLY, "status", Kind.U8, "generation", Kind.U32, "target", Kind.U8, "reason", Kind.TEXT);
        body(Type.CLOCK);
        body(Type.CLOCK_REPLY, "status", Kind.U8, "boot", Kind.ID, "instance", Kind.I64, "elapsed", Kind.I64,
                "wall", Kind.I64, "group", Kind.U32, "reason", Kind.TEXT);
        body(Type.OBSERVE, "scope", Kind.U8, "component", Kind.TEXT, "boot", Kind.ID, "ticket", Kind.ID,
                "plan", Kind.ID, "state", Kind.U8);
        body(Type.OBSERVE_REPLY, "status", Kind.U8, "frames", Kind.FRAMES, "reason", Kind.TEXT);
        body(Type.CROSS, "ticket", Kind.ID, "ticket_digest", Kind.D32, "plan", Kind.ID, "plan_digest", Kind.D32,
                "attempt", Kind.I32, "component", Kind.TEXT, "index", Kind.U16, "crossing", Kind.U8,
                "occurrence", Kind.U16, "entry_boot", Kind.ID, "entry_instance", Kind.I64, "entry_elapsed", Kind.I64,
                "grant", Kind.ID, "reference", Kind.ID, "native", Kind.REF, "bundle_apk", Kind.D32, "actor", Kind.U8,
                "granted", Kind.I64, "window", Kind.I64);
        body(Type.CROSS_REPLY, "status", Kind.U8, "record", Kind.U32, "frame", Kind.BLOB, "reason", Kind.TEXT);
        body(Type.POINT, "point", Kind.TEXT, "ticket", Kind.ID, "plan", Kind.ID, "attempt", Kind.I32);
        body(Type.POINT_REPLY, "status", Kind.U8, "record", Kind.U32, "reason", Kind.TEXT);
        body(Type.HOST, "phase", Kind.U8, "crossing", Kind.U8, "ticket", Kind.ID, "plan", Kind.ID, "attempt", Kind.I32,
                "index", Kind.U16, "occurrence", Kind.U16, "reference", Kind.ID, "outcome", Kind.U8, "reply", Kind.D32);
        body(Type.HOST_REPLY, "status", Kind.U8, "record", Kind.U32, "reason", Kind.TEXT);
        body(Type.REPORT, "ticket", Kind.ID, "state", Kind.U8, "flags", Kind.U8, "cause", Kind.U8,
                "ledger", Kind.CODES, "note", Kind.TEXT);
        body(Type.REPORT_REPLY, "status", Kind.U8, "record", Kind.U32, "reason", Kind.TEXT);
        BODIES_2.putAll(BODIES);
        BODIES_2.put(Type.OBSERVE_REPLY, fields("status", Kind.U8, "control_record", Kind.U32, "envelopes",
                Kind.ENVELOPES, "reason", Kind.TEXT));
        Object[] bracket = {"read_boot", Kind.ID, "read_instance", Kind.I64, "read_begin_elapsed", Kind.I64,
                "read_end_elapsed", Kind.I64};
        BLOCKS.put(SIMPLE_CURRENT, fields());
        BLOCKS.put(RECEIPT_EVENT, fields(concat(bracket, "plan", Kind.ID, "ticket", Kind.ID, "notice_index", Kind.U16,
                "issue_ticket_digest", Kind.D32, "event", Kind.ID, "row", Kind.D32, "delivery_group", Kind.D32,
                "delivery_instance", Kind.I64, "delivery_begin", Kind.I64, "proven_elapsed", Kind.I64,
                "delivery_end", Kind.I64)));
        BLOCKS.put(COMPOSED_HEALTH, fields(concat(bracket, "plan", Kind.ID, "ticket", Kind.ID, "window_boot", Kind.ID,
                "window_start", Kind.I64, "publication", Kind.D32, "active_apk", Kind.D32, "baseline", Kind.D32,
                "preparation_root", Kind.D32, "probe_begin", Kind.I64, "probe_end", Kind.I64, "criteria", Kind.U8,
                "rows", Kind.ROWS)));
    }

    private static Object[] concat(Object[] head, Object... tail) {
        Object[] all = Arrays.copyOf(head, head.length + tail.length);
        System.arraycopy(tail, 0, all, head.length, tail.length);
        return all;
    }

    /** The exact size of a mode's block. */
    public static int blockSize(int mode) {
        int size = 0;
        for (Field f : BLOCKS.get(mode)) {
            size += f.kind == Kind.ROWS ? CRITERIA * 34 : f.kind == Kind.ID ? 16 : f.kind == Kind.D32 ? 32 : width(f.kind);
        }
        return size;
    }

    /**
     * The HEALTH classification code that seven criterion row statuses, in bit order, give: a BAD
     * no crash or ANR row is a witnessed failure, CRASH; any other BAD row, DEGRADED; every row
     * HELD, HELD; anything else, INCONCLUSIVE. The broker applies the same rule.

     */
    public static int healthClassification(List<Integer> statuses) {
        if (statuses.size() != CRITERIA) throw fail("seven criterion row statuses");
        for (int s : statuses) if (s < HELD || s > UNKNOWN) throw fail("a criterion row of no known status");
        if (statuses.get(NO_CRASH_OR_ANR) == BAD) return HEALTH_CRASH;
        if (statuses.contains(BAD)) return HEALTH_DEGRADED;
        for (int s : statuses) if (s != HELD) return HEALTH_INCONCLUSIVE;
        return HEALTH_HELD;
    }

    // The deployment records' crossing codes and the most entries of each in one ledger.
    static final int CREATE = 3, WRITE = 4, COMMIT = 5, ABANDON = 6, REBOOT = 7, NOTICE = 8;
    private static final int[] BOUNDS = {0, 2, 2, 1, 1, 1, 16, 16, 17, 4};

    /** A native session reference, the deployment records' reference block. */
    public static final class Ref {
        public static final Ref NONE = new Ref(0, 0, 0, "", 0, ZERO_ID);
        public final int presence;
        public final int session;
        public final long created;
        public final String stageDir;
        public final int installer;
        public final String nonce;

        public Ref(int presence, int session, long created, String stageDir, int installer, String nonce) {
            this.presence = presence;
            this.session = session;
            this.created = created;
            this.stageDir = Objects.requireNonNull(stageDir, "stageDir");
            this.installer = installer;
            this.nonce = Objects.requireNonNull(nonce, "nonce");
            if ((presence & ~31) != 0) throw fail("unknown reference presence bits");
            checkHex(nonce, 16, "nonce", true);
            if (has(SESSION) ? session <= 0 : session != 0) throw fail("session and its presence differ");
            if (has(CREATED) ? created < 0 : created != 0) throw fail("createdMillis and its presence differ");
            if (has(STAGE_DIR)) {
                checkText(stageDir, MAX_STAGE_DIR, "stage directory");
                if (stageDir.isEmpty()) throw fail("an empty stage directory");
            } else if (!stageDir.isEmpty()) {
                throw fail("stage directory and its presence differ");
            }
            if (has(INSTALLER) ? installer < 0 : installer != 0) throw fail("installer and its presence differ");
            if (has(NONCE) == nonce.equals(ZERO_ID)) throw fail("nonce and its presence differ");
        }

        public boolean has(int bit) { return (presence & bit) != 0; }

        @Override
        public boolean equals(Object other) {
            if (!(other instanceof Ref)) return false;
            Ref r = (Ref) other;
            return presence == r.presence && session == r.session && created == r.created
                    && stageDir.equals(r.stageDir) && installer == r.installer && nonce.equals(r.nonce);
        }

        @Override
        public int hashCode() { return Objects.hash(presence, session, created, stageDir, installer, nonce); }

        @Override
        public String toString() { return "Ref{" + presence + "}"; }
    }

    /** One observation record in an OBSERVE reply, with the ledger entry of its group. */
    public static final class Frame {
        public final long group;
        private final byte[] record;

        public Frame(long group, byte[] record) {
            this.group = group;
            this.record = record.clone();
        }

        public byte[] record() { return record.clone(); }

        @Override
        public boolean equals(Object other) {
            return other instanceof Frame && ((Frame) other).group == group
                    && Arrays.equals(((Frame) other).record, record);
        }

        @Override
        public int hashCode() { return 31 * Long.hashCode(group) + Arrays.hashCode(record); }
    }

    /** One criterion row of a composition: its bit, its status and the digest of its child. */
    public static final class Row {
        public final int bit;
        public final int status;
        public final String child;

        public Row(int bit, int status, String child) {
            this.bit = bit;
            this.status = status;
            this.child = Objects.requireNonNull(child, "child");
            checkHex(child, 32, "criterion child", true);
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof Row && ((Row) other).bit == bit && ((Row) other).status == status
                    && ((Row) other).child.equals(child);
        }

        @Override
        public int hashCode() { return Objects.hash(bit, status, child); }
    }

    /**
     * One version 2 observation: its group, its mode, its evidence digest, its mode's block by
     * field name (numbers as Long, IDs and digests as hexadecimal, rows as a list of {@link Row})
     * and one whole deployment observation record.

     */
    public static final class Envelope {
        public final long group;
        public final int mode;
        public final String evidence;
        private final Map<String, Object> block;
        private final byte[] observation;

        public Envelope(long group, int mode, String evidence, Map<String, Object> block, byte[] observation) {
            this.group = group;
            this.mode = mode;
            this.evidence = Objects.requireNonNull(evidence, "evidence");
            this.block = Collections.unmodifiableMap(new LinkedHashMap<>(block));
            this.observation = observation.clone();
        }

        public long number(String name) { return (Long) value(name, Kind.U8, Kind.U16, Kind.I64); }

        public String id(String name) { return (String) value(name, Kind.ID, Kind.D32); }

        public List<Row> rows() {
            List<Row> rows = new ArrayList<>();
            for (Object o : (List<?>) value("rows", Kind.ROWS)) rows.add((Row) o);
            return rows;
        }

        public byte[] observation() { return observation.clone(); }

        Map<String, Object> block() { return block; }

        private Object value(String name, Kind... kinds) {
            for (Field f : BLOCKS.get(mode)) {
                if (f.name.equals(name) && Arrays.asList(kinds).contains(f.kind)) return block.get(name);
            }
            throw new IllegalArgumentException("mode " + mode + " has no such field " + name);
        }

        @Override
        public boolean equals(Object other) {
            if (!(other instanceof Envelope)) return false;
            Envelope e = (Envelope) other;
            return e.group == group && e.mode == mode && e.evidence.equals(evidence) && e.block.equals(block)
                    && Arrays.equals(e.observation, observation);
        }

        @Override
        public int hashCode() { return Objects.hash(group, mode, evidence, block, Arrays.hashCode(observation)); }
    }

    /**
     * The common fields of one whole deployment observation record of version 1, with a RECEIPT's
     * subject and sequence or a HEALTH's criteria: its frame and checksum checked, its tail left to
     * the deployment codec.
     */
    public static final class Head {
        public String installation, observation, component, boot, raw;
        public long user, serial, kind, route, instance, elapsed, wall, classification, number = -1, sequence = -1;
        public String subject;
    }

    /** The head of one observation record, or a protocol error. */
    public static Head observationHead(byte[] record) {
        if (record.length < 12 + CHECKSUM || record.length > MAX_RECORD) throw fail("an observation record outside its bounds");
        ByteBuffer b = ByteBuffer.wrap(record, 0, record.length - CHECKSUM).order(ByteOrder.LITTLE_ENDIAN);
        int magic = b.getInt();
        int kind = b.getShort() & 0xffff;
        int version = b.getShort() & 0xffff;
        long length = b.getInt() & 0xffffffffL;
        if (magic != OBSERVATION_MAGIC || kind != OBSERVATION_TYPE || version != 1 || length != record.length) {
            throw fail("not a version 1 observation record");
        }
        if (!MessageDigest.isEqual(sha256(Arrays.copyOf(record, record.length - CHECKSUM)),
                Arrays.copyOfRange(record, record.length - CHECKSUM, record.length))) {
            throw fail("an observation record whose checksum differs");
        }
        Head h = new Head();
        h.installation = hex(take(b, 16, "installation"));
        h.observation = hex(take(b, 16, "observation"));
        h.component = text(b, MAX_STAGE_DIR, "component");
        h.boot = hex(take(b, 16, "boot"));
        h.user = integer(b, Kind.I32, "user");
        h.serial = integer(b, Kind.I64, "serial");
        h.kind = integer(b, Kind.U8, "kind");
        h.route = integer(b, Kind.U8, "route");
        h.instance = integer(b, Kind.I64, "instance");
        h.elapsed = integer(b, Kind.I64, "elapsed");
        h.wall = integer(b, Kind.I64, "wall");
        h.raw = hex(take(b, 32, "raw"));
        h.classification = integer(b, Kind.U8, "classification");
        if (h.kind == KIND_RECEIPT) {
            h.subject = hex(take(b, 16, "subject"));
            h.sequence = integer(b, Kind.U16, "sequence");
        } else if (h.kind == KIND_HEALTH) {
            h.number = integer(b, Kind.U16, "criteria");
        }
        if (h.observation.equals(ZERO_ID)) throw fail("an observation without its ID");
        return h;
    }

    /** One message: its version, type, request ID, manifest digest and its layout's body fields. */
    public static final class Message {
        public final int version;
        public final Type type;
        public final String request;
        public final String manifest;
        private final Map<String, Object> fields;

        private Message(int version, Type type, String request, String manifest, Map<String, Object> fields) {
            this.version = version;
            this.type = type;
            this.request = request;
            this.manifest = manifest;
            this.fields = Collections.unmodifiableMap(new LinkedHashMap<>(fields));
        }

        /**
         * A builder of version 1 for one type: every body field must be set before
         * {@link Builder#build}.
         */
        public static Builder of(Type type, String request, String manifest) {
            return new Builder(VERSION, type, request, manifest);
        }

        /** A builder of one protocol version for one type. */
        public static Builder of(int version, Type type, String request, String manifest) {
            layout(version, type);
            return new Builder(version, type, request, manifest);
        }

        public long number(String name) { return (Long) field(name, Kind.U8, Kind.U16, Kind.U32, Kind.I32, Kind.I64); }

        public String id(String name) { return (String) field(name, Kind.ID, Kind.D32); }

        public String text(String name) { return (String) field(name, Kind.TEXT); }

        public byte[] bytes(String name) { return ((byte[]) field(name, Kind.BLOB)).clone(); }

        public Ref ref(String name) { return (Ref) field(name, Kind.REF); }

        public List<Frame> frames(String name) {
            List<Frame> frames = new ArrayList<>();
            for (Object o : (List<?>) field(name, Kind.FRAMES)) frames.add((Frame) o);
            return frames;
        }

        public List<Integer> codes(String name) {
            List<Integer> codes = new ArrayList<>();
            for (Object o : (List<?>) field(name, Kind.CODES)) codes.add((Integer) o);
            return codes;
        }

        public List<Envelope> envelopes(String name) {
            List<Envelope> envelopes = new ArrayList<>();
            for (Object o : (List<?>) field(name, Kind.ENVELOPES)) envelopes.add((Envelope) o);
            return envelopes;
        }

        public Status status() { return Status.of(number("status")); }

        private Object field(String name, Kind... kinds) {
            Kind kind = kindOf(version, type, name);
            if (!Arrays.asList(kinds).contains(kind)) throw new IllegalArgumentException(name + " is a " + kind);
            return fields.get(name);
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof Message && Arrays.equals(encode(this), encode((Message) other));
        }

        @Override
        public int hashCode() { return Arrays.hashCode(encode(this)); }

        @Override
        public String toString() { return "Message{" + type + "}"; }
    }

    /** A mutable builder of one message. */
    public static final class Builder {
        private final int version;
        private final Type type;
        private final String request;
        private final String manifest;
        private final Map<String, Object> fields = new LinkedHashMap<>();

        private Builder(int version, Type type, String request, String manifest) {
            this.version = version;
            this.type = Objects.requireNonNull(type, "type");
            this.request = request;
            this.manifest = manifest;
        }

        public Builder number(String name, long value) { return put(name, value, Kind.U8, Kind.U16, Kind.U32, Kind.I32, Kind.I64); }

        public Builder id(String name, String value) { return put(name, value, Kind.ID, Kind.D32); }

        public Builder text(String name, String value) { return put(name, value, Kind.TEXT); }

        public Builder bytes(String name, byte[] value) { return put(name, value.clone(), Kind.BLOB); }

        public Builder ref(String name, Ref value) { return put(name, value, Kind.REF); }

        public Builder frames(String name, List<Frame> value) { return put(name, new ArrayList<>(value), Kind.FRAMES); }

        public Builder codes(String name, List<Integer> value) { return put(name, new ArrayList<>(value), Kind.CODES); }

        public Builder envelopes(String name, List<Envelope> value) {
            return put(name, new ArrayList<>(value), Kind.ENVELOPES);
        }

        /** Every unset field at its zero value: 0, the zero ID or digest, empty text, bytes and lists. */
        public Builder zeros() {
            for (Field f : layout(version, type)) {
                if (fields.containsKey(f.name)) continue;
                switch (f.kind) {
                    case ID: fields.put(f.name, ZERO_ID); break;
                    case D32: fields.put(f.name, ZERO_DIGEST); break;
                    case TEXT: fields.put(f.name, ""); break;
                    case BLOB: fields.put(f.name, new byte[0]); break;
                    case REF: fields.put(f.name, Ref.NONE); break;
                    case FRAMES:
                    case ENVELOPES:
                    case CODES: fields.put(f.name, new ArrayList<>()); break;
                    default: fields.put(f.name, 0L); break;
                }
            }
            return this;
        }

        private Builder put(String name, Object value, Kind... kinds) {
            Kind kind = kindOf(version, type, name);
            if (!Arrays.asList(kinds).contains(kind)) throw new IllegalArgumentException(name + " is a " + kind);
            fields.put(name, Objects.requireNonNull(value, name));
            return this;
        }

        /** The message, checked as {@link #encode} checks it. */
        public Message build() {
            Message m = new Message(version, type, request, manifest, fields);
            encode(m);
            return m;
        }
    }

    static Kind kindOf(int version, Type type, String name) {
        for (Field f : layout(version, type)) if (f.name.equals(name)) return f.kind;
        throw new IllegalArgumentException(type + " has no field " + name);
    }

    // ---------------------------------------------------------------- primitive checks

    static void checkHex(String value, int bytes, String name, boolean zeroAllowed) {
        if (value == null || value.length() != 2 * bytes) throw fail(name + " is not " + bytes + " hexadecimal bytes");
        boolean zero = true;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) throw fail(name + " is not lowercase hexadecimal");
            zero &= c == '0';
        }
        if (zero && !zeroAllowed) throw fail(name + " is zero");
    }

    static void checkText(String value, int limit, String name) {
        if (value == null || value.length() > limit) throw fail(name + " is longer than " + limit);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c > 0x7e) throw fail(name + " is not printable ASCII");
        }
    }

    /** A package name: dot separated segments, each a letter, then letters, digits or '_'. */
    public static void checkPackage(String value, String name) {
        checkText(value, 255, name);
        if (!PACKAGE.matcher(value).matches()) throw fail(name + " is not a package name");
    }

    private static void checkRange(Kind kind, long value, String name) {
        long low, high;
        switch (kind) {
            case U8: low = 0; high = 0xff; break;
            case U16: low = 0; high = 0xffff; break;
            case U32: low = 0; high = 0xffffffffL; break;
            case I32: low = Integer.MIN_VALUE; high = Integer.MAX_VALUE; break;
            default: return;
        }
        if (value < low || value > high) throw fail(name + " is outside " + kind);
    }

    // ---------------------------------------------------------------- relations

    private static Status status(Message m, Status... allowed) {
        Status status = Status.of(m.number("status"));
        if (status != Status.REFUSED && !Arrays.asList(allowed).contains(status)) {
            throw fail("status " + status + " is not allowed in " + m.type);
        }
        if ((status == Status.OK) != m.text("reason").isEmpty()) throw fail("a reason exactly when not OK");
        return status;
    }

    private static void relations(Message m) {
        if (m.type == Type.OBSERVE_REPLY && m.version == VERSION_2) {
            observeReply2(m);
            return;
        }
        switch (m.type) {
            case HELLO:
                checkHex(m.id("installation"), 16, "installation", false);
                checkHex(m.id("coordinator"), 16, "coordinator", false);
                checkHex(m.id("config"), 32, "config", false);
                checkHex(m.id("trust"), 32, "trust", false);
                checkPackage(m.text("component"), "component");
                if (m.number("route") != 1) throw fail("the lab bridge has only the shell route");
                break;
            case HELLO_REPLY: {
                Status s = status(m, Status.OK, Status.STOPPED);
                if ((s == Status.OK) != (m.number("generation") >= 1)) throw fail("a generation exactly with OK");
                long target = m.number("target");
                if (s == Status.OK ? target < 1 || target > 3 : target != 0) throw fail("a target exactly with OK");
                break;
            }
            case CLOCK_REPLY: {
                Status s = status(m, Status.OK, Status.UNAVAILABLE, Status.STOPPED);
                if (s == Status.OK) {
                    checkHex(m.id("boot"), 16, "boot", false);
                    if (m.number("instance") < -1 || m.number("elapsed") < 0 || m.number("group") < 1) {
                        throw fail("a clock reading outside its bounds");
                    }
                } else if (!m.id("boot").equals(ZERO_ID) || m.number("instance") != 0 || m.number("elapsed") != 0
                        || m.number("wall") != 0) {
                    throw fail("a reading without OK");
                }
                if ((s == Status.STOPPED || s == Status.REFUSED) && m.number("group") != 0) {
                    throw fail("a stopped or refused clock read nothing");
                }
                break;
            }
            case OBSERVE: {
                checkPackage(m.text("component"), "component");
                checkHex(m.id("boot"), 16, "boot", false);
                long scope = m.number("scope");
                if (scope == SCOPE_COMPONENT) {
                    if (!m.id("ticket").equals(ZERO_ID) || !m.id("plan").equals(ZERO_ID) || m.number("state") != 0) {
                        throw fail("a component observation names no ticket");
                    }
                } else if (scope == SCOPE_TICKET) {
                    checkHex(m.id("ticket"), 16, "ticket", false);
                    checkHex(m.id("plan"), 16, "plan", false);
                    if (m.number("state") < 1 || m.number("state") > STATE_COUNT) throw fail("a ticket state outside 1..28");
                } else {
                    throw fail("an unknown observation scope");
                }
                break;
            }
            case OBSERVE_REPLY: {
                Status s = status(m, Status.OK, Status.STOPPED);
                List<Frame> frames = m.frames("frames");
                if (s != Status.OK && !frames.isEmpty()) throw fail("frames only with OK");
                for (Frame f : frames) {
                    if (f.group < 1 || f.record.length < 1 || f.record.length > MAX_RECORD) {
                        throw fail("a frame without its group or outside the record bound");
                    }
                }
                break;
            }
            case CROSS:
                crossRelations(m);
                break;
            case CROSS_REPLY: {
                Status s = status(m, Status.OK, Status.NO_REPLY, Status.WITHHELD, Status.HALT, Status.STOPPED);
                int frame = m.bytes("frame").length;
                if ((s == Status.OK) != (frame > 0)) throw fail("a reply frame exactly with OK");
                if (frame > MAX_RECORD) throw fail("a reply frame outside the record bound");
                boolean recorded = s == Status.OK || s == Status.NO_REPLY || s == Status.WITHHELD || s == Status.HALT;
                if (recorded && m.number("record") < 1) throw fail("a crossing outcome names its record");
                break;
            }
            case POINT:
                if (!POINT_BETWEEN_WRITES.equals(m.text("point"))) throw fail("an unknown lab point");
                checkHex(m.id("ticket"), 16, "ticket", false);
                checkHex(m.id("plan"), 16, "plan", false);
                if (m.number("attempt") < 1) throw fail("an attempt below 1");
                break;
            case POINT_REPLY: {
                Status s = status(m, Status.OK, Status.HALT);
                if ((s == Status.HALT) != (m.number("record") >= 1)) throw fail("a fault record exactly with HALT");
                break;
            }
            case HOST: {
                long phase = m.number("phase"), crossing = m.number("crossing");
                if (phase < 1 || phase > 2 || crossing < 1 || crossing > 2) throw fail("an unknown host phase or crossing");
                checkHex(m.id("ticket"), 16, "ticket", false);
                checkHex(m.id("plan"), 16, "plan", false);
                checkHex(m.id("reference"), 16, "reference", false);
                if (m.number("attempt") < 1 || m.number("index") >= MAX_LEDGER || m.number("occurrence") < 1
                        || m.number("occurrence") > 2) {
                    throw fail("a host call outside its bounds");
                }
                long outcome = m.number("outcome");
                boolean digest = !m.id("reply").equals(ZERO_DIGEST);
                if (phase == PHASE_BEGIN) {
                    if (outcome != 0 || digest) throw fail("a host call begins without an outcome");
                } else {
                    if (outcome < 1 || outcome > 3) throw fail("an unknown host outcome");
                    if ((outcome == OUTCOME_REPLY) != digest) throw fail("a reply digest exactly when the host replied");
                }
                break;
            }
            case HOST_REPLY: {
                Status s = status(m, Status.OK, Status.HALT, Status.WITHHELD);
                if (s != Status.REFUSED && m.number("record") < 1) throw fail("a host outcome names its record");
                break;
            }
            case REPORT:
                checkHex(m.id("ticket"), 16, "ticket", false);
                if (m.number("state") < 1 || m.number("state") > STATE_COUNT || (m.number("flags") & ~7) != 0
                        || m.number("cause") > 6) {
                    throw fail("a report outside the ticket codes");
                }
                for (int code : m.codes("ledger")) if (code < 1 || code > 9) throw fail("an unknown crossing");
                break;
            case REPORT_REPLY:
                if (status(m, Status.OK) == Status.OK && m.number("record") < 1) throw fail("a report names its record");
                break;
            default:
                break;
        }
    }

    // Version 2's OBSERVE reply: envelopes only with OK, a fault record exactly with HALT, and no
    // observation ID twice. Each envelope's relations are its mode's.
    private static void observeReply2(Message m) {
        Status s = status(m, Status.OK, Status.HALT, Status.STOPPED);
        List<Envelope> envelopes = m.envelopes("envelopes");
        long control = m.number("control_record");
        if (s == Status.HALT) {
            if (control < 1 || !envelopes.isEmpty()) throw fail("a halt names its fault record and carries no envelope");
        } else if (control != 0) {
            throw fail("a control record only with HALT");
        }
        if (s != Status.OK && !envelopes.isEmpty()) throw fail("envelopes only with OK");
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (Envelope e : envelopes) {
            if (!seen.add(envelopeRelations(e).observation)) throw fail("an observation ID twice in one reply");
        }
    }

    /**
     * Checks one version 2 envelope against its mode and returns its observation's head: the same
     * relations as the Python codec's. The evidence digest is the observation's raw digest; a
     * simple envelope carries no HEALTH and no RECEIPT; a compound block's read bracket is one boot
     * and one running framework instance, the observation's own; a receipt's event lies within its
     * delivery group, before the read's end, and is the observation's time; a probe lies in its
     * window from its start, ends at the read's end, which is the observation's time, and is
     * classified as its seven rows give.

     */
    public static Head envelopeRelations(Envelope e) {
        checkRange(Kind.U32, e.group, "group");
        if (e.group < 1) throw fail("an envelope without its group");
        List<Field> layout = BLOCKS.get(e.mode);
        if (layout == null) throw fail("an envelope of no known mode");
        if (!e.block.keySet().equals(namesOf(layout))) throw fail("an envelope's block is not exactly its mode's layout");
        for (Field f : layout) blockField(f, e.block.get(f.name), null);
        checkHex(e.evidence, 32, "evidence", false);
        Head head = observationHead(e.observation);
        if (!head.raw.equals(e.evidence)) throw fail("an envelope's evidence is not its observation's raw digest");
        if (e.mode == SIMPLE_CURRENT) {
            if (head.kind == KIND_HEALTH || head.kind == KIND_RECEIPT) {
                throw fail("a receipt or health fact only in its compound mode");
            }
            return head;
        }
        checkHex(e.id("read_boot"), 16, "read boot", false);
        long instance = e.number("read_instance"), begin = e.number("read_begin_elapsed");
        long end = e.number("read_end_elapsed");
        if (instance < 0 || begin < 0 || begin > end) {
            throw fail("a read bracket without a running framework or with its times out of order");
        }
        if (!head.boot.equals(e.id("read_boot")) || head.instance != instance) {
            throw fail("a compound fact not of its read's boot and framework instance");
        }
        if (e.mode == RECEIPT_EVENT) {
            for (String n : new String[] {"plan", "ticket", "event"}) checkHex(e.id(n), 16, n, false);
            for (String n : new String[] {"issue_ticket_digest", "row", "delivery_group"}) checkHex(e.id(n), 32, n, false);
            if (e.number("notice_index") >= MAX_LEDGER) throw fail("a notice index outside the ledger bound");
            long delivery = e.number("delivery_instance");
            if (delivery < 0 || delivery > instance) throw fail("a delivery in a later framework instance than the read");
            long from = e.number("delivery_begin"), proven = e.number("proven_elapsed"), to = e.number("delivery_end");
            if (from < 0 || from > proven || proven > to || to > end) {
                throw fail("a receipt event outside its delivery group or after the read");
            }
            if (head.kind != KIND_RECEIPT || head.classification != RECEIPT_FULL_SCREEN) {
                throw fail("a receipt envelope carries a full screen RECEIPT");
            }
            if (head.elapsed != proven || !head.subject.equals(e.id("ticket")) || head.sequence != e.number("notice_index")) {
                throw fail("a receipt fact not at its proven event, or of another ticket or notice");
            }
            return head;
        }
        for (String n : new String[] {"plan", "ticket", "window_boot"}) checkHex(e.id(n), 16, n, false);
        for (String n : new String[] {"publication", "active_apk", "baseline", "preparation_root"}) {
            checkHex(e.id(n), 32, n, false);
        }
        long start = e.number("window_start"), probeBegin = e.number("probe_begin"), probeEnd = e.number("probe_end");
        if (!e.id("window_boot").equals(e.id("read_boot")) || start < 0 || start > probeBegin || probeBegin > begin
                || probeEnd != end) {
            throw fail("a probe outside its window or not completed by its read");
        }
        List<Row> rows = e.rows();
        boolean ordered = e.number("criteria") == CRITERIA_ALL;
        for (int i = 0; i < rows.size(); i++) ordered &= rows.get(i).bit == i;
        if (!ordered) throw fail("a composition declares every criterion, one row for each bit in order");
        List<Integer> statuses = new ArrayList<>();
        for (Row r : rows) {
            if (r.status < HELD || r.status > UNKNOWN) throw fail("a criterion row of no known status");
            checkHex(r.child, 32, "criterion child", false);
            statuses.add(r.status);
        }
        if (head.kind != KIND_HEALTH || head.number != CRITERIA_ALL || head.elapsed != probeEnd) {
            throw fail("a health envelope carries one HEALTH fact of every criterion at its probe end");
        }
        if (head.classification != healthClassification(statuses)) {
            throw fail("a health classification that its criterion rows do not give");
        }
        return head;
    }

    // Checks one block field's type and bound, and writes it when an output is given.
    private static void blockField(Field f, Object value, Out out) {
        switch (f.kind) {
            case ID:
            case D32: {
                int width = f.kind == Kind.ID ? 16 : 32;
                if (!(value instanceof String)) throw fail(f.name + " is not hexadecimal");
                checkHex((String) value, width, f.name, true);
                if (out != null) out.hex((String) value);
                break;
            }
            case ROWS: {
                if (!(value instanceof List) || ((List<?>) value).size() != CRITERIA) {
                    throw fail(f.name + " holds exactly " + CRITERIA + " criterion rows");
                }
                for (Object o : (List<?>) value) {
                    if (!(o instanceof Row)) throw fail("a criterion row is a bit, a status and a child digest");
                    Row r = (Row) o;
                    checkRange(Kind.U8, r.bit, "bit");
                    checkRange(Kind.U8, r.status, "status");
                    if (out != null) {
                        out.integer(r.bit, 1);
                        out.integer(r.status, 1);
                        out.hex(r.child);
                    }
                }
                break;
            }
            default: {
                if (!(value instanceof Long)) throw fail(f.name + " is not a number");
                checkRange(f.kind, (Long) value, f.name);
                if (out != null) out.integer((Long) value, width(f.kind));
                break;
            }
        }
    }

    private static void crossRelations(Message m) {
        checkHex(m.id("ticket"), 16, "ticket", false);
        checkHex(m.id("plan"), 16, "plan", false);
        checkHex(m.id("entry_boot"), 16, "entry boot", false);
        checkHex(m.id("ticket_digest"), 32, "ticket digest", false);
        checkHex(m.id("plan_digest"), 32, "plan digest", false);
        checkPackage(m.text("component"), "component");
        if (m.number("attempt") < 1) throw fail("an attempt below 1");
        int crossing = (int) m.number("crossing");
        if (crossing < CREATE || crossing > NOTICE) throw fail("not a device crossing");
        long index = m.number("index"), occurrence = m.number("occurrence");
        if (index >= MAX_LEDGER || occurrence < 1 || occurrence > Math.min(BOUNDS[crossing], index + 1)) {
            throw fail("an entry index or occurrence outside the ledger bounds");
        }
        boolean framework = crossing <= ABANDON;
        if (m.number("entry_instance") < (framework ? 0 : -1) || m.number("entry_elapsed") < 0) {
            throw fail("an entry instance or elapsed time outside its bounds");
        }
        boolean granted = crossing == CREATE || crossing == COMMIT || crossing == REBOOT || crossing == NOTICE;
        boolean grant = !m.id("grant").equals(ZERO_ID);
        if (granted != grant) throw fail("a grant exactly for CREATE, COMMIT, REBOOT and NOTICE");
        long actor = m.number("actor");
        if ((actor != 0) != grant || actor > 2) throw fail("an actor class exactly with a grant");
        if (crossing == COMMIT || crossing == REBOOT || crossing == NOTICE) {
            if (m.number("granted") < 1 || m.number("window") < 1) {
                throw fail("an ACTIVATE crossing carries its grant's time and the plan's activation window");
            }
        } else if (m.number("granted") != 0 || m.number("window") != 0) {
            throw fail("a grant time and window exactly for COMMIT, REBOOT and NOTICE");
        }
        if ((crossing == CREATE) == m.id("reference").equals(ZERO_ID)) throw fail("an entry reference exactly for CREATE");
        Ref ref = m.ref("native");
        if (crossing == CREATE && (ref.presence != NONCE || !ref.nonce.equals(m.id("reference")))) {
            throw fail("CREATE carries exactly the ticket's nonce");
        }
        if ((crossing == WRITE || crossing == COMMIT || crossing == ABANDON)
                && (ref.presence & BOUND_REFERENCE) != BOUND_REFERENCE) {
            throw fail("a session crossing needs the session with its createdMillis, installer and nonce");
        }
        if ((crossing == WRITE) == m.id("bundle_apk").equals(ZERO_DIGEST)) {
            throw fail("the bundle's APK digest exactly for WRITE");
        }
    }

    // ---------------------------------------------------------------- encoding

    private static final class Out {
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();

        void integer(long value, int width) {
            for (int i = 0; i < width; i++) bytes.write((int) (value >>> (8 * i)) & 0xff);
        }

        void raw(byte[] data) { bytes.write(data, 0, data.length); }

        void hex(String value) { raw(unhex(value)); }

        void text(String value) {
            byte[] data = value.getBytes(StandardCharsets.US_ASCII);
            integer(data.length, 2);
            raw(data);
        }
    }

    /** The one encoding of a valid message, in its own protocol version. */
    public static byte[] encode(Message m) {
        checkHex(m.request, 16, "request", false);
        checkHex(m.manifest, 32, "manifest", false);
        List<Field> layout = layout(m.version, m.type);
        if (!m.fields.keySet().equals(namesOf(layout))) throw fail("the fields of " + m.type + " are not its layout");
        Out out = new Out();
        for (Field f : layout) {
            Object value = m.fields.get(f.name);
            switch (f.kind) {
                case U8: case U16: case U32: case I32: case I64: {
                    long v = (Long) value;
                    checkRange(f.kind, v, f.name);
                    out.integer(v, width(f.kind));
                    break;
                }
                case ID: checkHex((String) value, 16, f.name, true); out.hex((String) value); break;
                case D32: checkHex((String) value, 32, f.name, true); out.hex((String) value); break;
                case TEXT: checkText((String) value, MAX_TEXT, f.name); out.text((String) value); break;
                case BLOB: {
                    byte[] data = (byte[]) value;
                    if (data.length > MAX_RECORD) throw fail(f.name + " is above the record bound");
                    out.integer(data.length, 4);
                    out.raw(data);
                    break;
                }
                case REF: {
                    Ref r = (Ref) value;
                    out.integer(r.presence, 1);
                    out.integer(r.session, 4);
                    out.integer(r.created, 8);
                    out.text(r.stageDir);
                    out.integer(r.installer, 4);
                    out.hex(r.nonce);
                    break;
                }
                case FRAMES: {
                    List<?> frames = (List<?>) value;
                    if (frames.size() > MAX_FRAMES) throw fail(f.name + " holds more than " + MAX_FRAMES);
                    out.integer(frames.size(), 2);
                    for (Object o : frames) {
                        Frame frame = (Frame) o;
                        checkRange(Kind.U32, frame.group, f.name);
                        if (frame.record.length > MAX_RECORD) throw fail("a frame above the record bound");
                        out.integer(frame.group, 4);
                        out.integer(frame.record.length, 4);
                        out.raw(frame.record);
                    }
                    break;
                }
                case ENVELOPES: {
                    List<?> envelopes = (List<?>) value;
                    if (envelopes.size() > MAX_FRAMES) throw fail(f.name + " holds more than " + MAX_FRAMES + " envelopes");
                    out.integer(envelopes.size(), 2);
                    for (Object o : envelopes) {
                        Envelope e = (Envelope) o;
                        List<Field> block = BLOCKS.get(e.mode);
                        if (block == null) throw fail("an envelope of no known mode");
                        if (!e.block.keySet().equals(namesOf(block))) {
                            throw fail("an envelope's block is not exactly its mode's layout");
                        }
                        checkRange(Kind.U32, e.group, "group");
                        checkHex(e.evidence, 32, "evidence", true);
                        if (e.observation.length < 1 || e.observation.length > MAX_RECORD) {
                            throw fail("an envelope observation outside the record bound");
                        }
                        out.integer(e.group, 4);
                        out.integer(e.mode, 1);
                        out.hex(e.evidence);
                        out.integer(blockSize(e.mode), 2);
                        for (Field bf : block) blockField(bf, e.block.get(bf.name), out);
                        out.integer(e.observation.length, 4);
                        out.raw(e.observation);
                    }
                    break;
                }
                default: {
                    List<?> codes = (List<?>) value;
                    if (codes.size() > MAX_LEDGER) throw fail(f.name + " holds more than " + MAX_LEDGER);
                    out.integer(codes.size(), 2);
                    for (Object o : codes) {
                        int code = (Integer) o;
                        checkRange(Kind.U8, code, f.name);
                        out.integer(code, 1);
                    }
                    break;
                }
            }
        }
        relations(m);
        byte[] body = out.bytes.toByteArray();
        int length = HEADER + body.length + CHECKSUM;
        if (length > MAX_FRAME) throw fail("a frame above the frame bound");
        Out frame = new Out();
        frame.integer(MAGIC, 4);
        frame.integer(m.version, 2);
        frame.integer(m.type.code, 2);
        frame.integer(length, 4);
        frame.hex(m.request);
        frame.hex(m.manifest);
        frame.raw(body);
        byte[] head = frame.bytes.toByteArray();
        frame.raw(sha256(head));
        return frame.bytes.toByteArray();
    }

    private static java.util.Set<String> namesOf(List<Field> layout) {
        java.util.Set<String> names = new java.util.LinkedHashSet<>();
        for (Field f : layout) names.add(f.name);
        return names;
    }

    private static int width(Kind kind) {
        switch (kind) {
            case U8: return 1;
            case U16: return 2;
            case U32: case I32: return 4;
            default: return 8;
        }
    }

    // ---------------------------------------------------------------- decoding

    /** The whole frame's length from its first 12 bytes, checked against the frame bounds. */
    public static int frameLength(byte[] header) {
        if (header.length < 12) throw fail("a header cut short");
        ByteBuffer b = ByteBuffer.wrap(header, 0, 12).order(ByteOrder.LITTLE_ENDIAN);
        int magic = b.getInt();
        int version = b.getShort() & 0xffff;
        int type = b.getShort() & 0xffff;
        long length = b.getInt() & 0xffffffffL;
        if (magic != MAGIC) throw fail("not a lab bridge frame");
        if (version != VERSION && version != VERSION_2) throw fail("protocol version " + version + " is not 1 or 2");
        Type.of(type);
        if (length < MIN_FRAME || length > MAX_FRAME) throw fail("a frame length outside its bounds");
        return (int) length;
    }

    /** The message one exact frame of version 1 holds. */
    public static Message decode(byte[] data) {
        return decode(data, VERSION);
    }

    /** The message one exact frame of one protocol version holds. Another version is refused. */
    public static Message decode(byte[] data, int version) {
        if (data.length < MIN_FRAME) throw fail("a frame below the minimum size");
        if (frameLength(data) != data.length) throw fail("the length field differs from the frame");
        int framed = (data[4] & 0xff) | ((data[5] & 0xff) << 8);
        if (framed != version) throw fail("a frame of protocol version " + framed + " on a version " + version + " channel");
        byte[] head = Arrays.copyOf(data, data.length - CHECKSUM);
        if (!MessageDigest.isEqual(sha256(head), Arrays.copyOfRange(data, data.length - CHECKSUM, data.length))) {
            throw fail("the checksum differs");
        }
        ByteBuffer b = ByteBuffer.wrap(data, 0, data.length - CHECKSUM).order(ByteOrder.LITTLE_ENDIAN);
        b.position(6);
        Type type = Type.of(b.getShort() & 0xffff);
        b.position(12);
        String request = hex(take(b, 16, "request"));
        String manifest = hex(take(b, 32, "manifest"));
        Map<String, Object> fields = new LinkedHashMap<>();
        for (Field f : layout(version, type)) fields.put(f.name, read(b, f));
        if (b.hasRemaining()) throw fail("trailing bytes after the body");
        Message m = new Message(version, type, request, manifest, fields);
        checkHex(request, 16, "request", false);
        checkHex(manifest, 32, "manifest", false);
        relations(m);
        return m;
    }

    private static byte[] take(ByteBuffer b, long count, String name) {
        if (count < 0 || count > b.remaining()) throw fail(name + " runs past the body");
        byte[] out = new byte[(int) count];
        b.get(out);
        return out;
    }

    private static long integer(ByteBuffer b, Kind kind, String name) {
        int width = width(kind);
        if (b.remaining() < width) throw fail(name + " runs past the body");
        switch (kind) {
            case U8: return b.get() & 0xffL;
            case U16: return b.getShort() & 0xffffL;
            case U32: return b.getInt() & 0xffffffffL;
            case I32: return b.getInt();
            default: return b.getLong();
        }
    }

    private static String text(ByteBuffer b, int limit, String name) {
        byte[] raw = take(b, integer(b, Kind.U16, name), name);
        if (raw.length > limit) throw fail(name + " is longer than " + limit);
        for (byte c : raw) if (c < 0x20 || c > 0x7e) throw fail(name + " is not printable ASCII");
        return new String(raw, StandardCharsets.US_ASCII);
    }

    private static Object read(ByteBuffer b, Field f) {
        switch (f.kind) {
            case U8: case U16: case U32: case I32: case I64: return integer(b, f.kind, f.name);
            case ID: return hex(take(b, 16, f.name));
            case D32: return hex(take(b, 32, f.name));
            case TEXT: return text(b, MAX_TEXT, f.name);
            case BLOB: {
                long size = integer(b, Kind.U32, f.name);
                if (size > MAX_RECORD) throw fail(f.name + " is above the record bound");
                return take(b, size, f.name);
            }
            case REF: {
                int presence = (int) integer(b, Kind.U8, f.name);
                int session = (int) integer(b, Kind.I32, f.name);
                long created = integer(b, Kind.I64, f.name);
                String stage = text(b, MAX_STAGE_DIR, f.name);
                int installer = (int) integer(b, Kind.I32, f.name);
                String nonce = hex(take(b, 16, f.name));
                return new Ref(presence, session, created, stage, installer, nonce);
            }
            case FRAMES: {
                long count = integer(b, Kind.U16, f.name);
                if (count > MAX_FRAMES) throw fail(f.name + " holds more than " + MAX_FRAMES);
                List<Frame> frames = new ArrayList<>();
                for (long i = 0; i < count; i++) {
                    long group = integer(b, Kind.U32, f.name);
                    long size = integer(b, Kind.U32, f.name);
                    if (size > MAX_RECORD) throw fail("a frame above the record bound");
                    frames.add(new Frame(group, take(b, size, f.name)));
                }
                return frames;
            }
            case ENVELOPES: {
                long count = integer(b, Kind.U16, f.name);
                if (count > MAX_FRAMES) throw fail(f.name + " holds more than " + MAX_FRAMES + " envelopes");
                List<Envelope> envelopes = new ArrayList<>();
                for (long i = 0; i < count; i++) envelopes.add(envelope(b));
                return envelopes;
            }
            default: {
                long count = integer(b, Kind.U16, f.name);
                if (count > MAX_LEDGER) throw fail(f.name + " holds more than " + MAX_LEDGER);
                List<Integer> codes = new ArrayList<>();
                for (long i = 0; i < count; i++) codes.add((int) integer(b, Kind.U8, f.name));
                return codes;
            }
        }
    }

    private static Envelope envelope(ByteBuffer b) {
        long group = integer(b, Kind.U32, "group");
        int mode = (int) integer(b, Kind.U8, "mode");
        String evidence = hex(take(b, 32, "evidence"));
        List<Field> layout = BLOCKS.get(mode);
        if (layout == null) throw fail("an envelope of no known mode");
        long size = integer(b, Kind.U16, "block length");
        if (size != blockSize(mode)) throw fail("an envelope block that is not its mode's exact size");
        ByteBuffer block = ByteBuffer.wrap(take(b, size, "block")).order(ByteOrder.LITTLE_ENDIAN);
        Map<String, Object> fields = new LinkedHashMap<>();
        for (Field f : layout) {
            switch (f.kind) {
                case ID: fields.put(f.name, hex(take(block, 16, f.name))); break;
                case D32: fields.put(f.name, hex(take(block, 32, f.name))); break;
                case ROWS: {
                    List<Row> rows = new ArrayList<>();
                    for (int i = 0; i < CRITERIA; i++) {
                        int bit = (int) integer(block, Kind.U8, f.name);
                        int status = (int) integer(block, Kind.U8, f.name);
                        rows.add(new Row(bit, status, hex(take(block, 32, f.name))));
                    }
                    fields.put(f.name, rows);
                    break;
                }
                default: fields.put(f.name, integer(block, f.kind, f.name)); break;
            }
        }
        if (block.hasRemaining()) throw fail("an envelope block of another layout");
        long observation = integer(b, Kind.U32, "observation");
        if (observation > MAX_RECORD) throw fail("an envelope observation above the record bound");
        return new Envelope(group, mode, evidence, fields, take(b, observation, "observation"));
    }

    // ---------------------------------------------------------------- helpers

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 unavailable", error);
        }
    }

    public static String sha256Hex(byte[] data) { return hex(sha256(data)); }

    public static String hex(byte[] data) {
        char[] out = new char[2 * data.length];
        for (int i = 0; i < data.length; i++) {
            out[2 * i] = HEX[(data[i] & 0xff) >>> 4];
            out[2 * i + 1] = HEX[data[i] & 0xf];
        }
        return new String(out);
    }

    static byte[] unhex(String value) {
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(value.substring(2 * i, 2 * i + 2), 16);
        return out;
    }
}
