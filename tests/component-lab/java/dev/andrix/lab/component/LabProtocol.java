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
 * Version 1 of the lab bridge protocol, the Java side of {@code lab_protocol.py}: the typed frames
 * between the bridge and the broker. Every frame is little endian:
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
 */
public final class LabProtocol {
    private LabProtocol() {}

    public static final int MAGIC = 0x424c5841;
    public static final int VERSION = 1;
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

    enum Kind { U8, U16, U32, I32, I64, ID, D32, TEXT, BLOB, REF, FRAMES, CODES }

    private static final class Field {
        final String name;
        final Kind kind;

        Field(String name, Kind kind) {
            this.name = name;
            this.kind = kind;
        }
    }

    private static final Map<Type, List<Field>> BODIES = new EnumMap<>(Type.class);

    private static void body(Type type, Object... pairs) {
        List<Field> fields = new ArrayList<>();
        for (int i = 0; i < pairs.length; i += 2) fields.add(new Field((String) pairs[i], (Kind) pairs[i + 1]));
        BODIES.put(type, Collections.unmodifiableList(fields));
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

    /** One message: its type, request ID, manifest digest and the body fields of its layout. */
    public static final class Message {
        public final Type type;
        public final String request;
        public final String manifest;
        private final Map<String, Object> fields;

        private Message(Type type, String request, String manifest, Map<String, Object> fields) {
            this.type = type;
            this.request = request;
            this.manifest = manifest;
            this.fields = Collections.unmodifiableMap(new LinkedHashMap<>(fields));
        }

        /** A builder for one type: every body field must be set before {@link Builder#build}. */
        public static Builder of(Type type, String request, String manifest) {
            return new Builder(type, request, manifest);
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

        public Status status() { return Status.of(number("status")); }

        private Object field(String name, Kind... kinds) {
            Kind kind = kindOf(type, name);
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
        private final Type type;
        private final String request;
        private final String manifest;
        private final Map<String, Object> fields = new LinkedHashMap<>();

        private Builder(Type type, String request, String manifest) {
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

        /** Every unset field at its zero value: 0, the zero ID or digest, empty text, bytes and lists. */
        public Builder zeros() {
            for (Field f : BODIES.get(type)) {
                if (fields.containsKey(f.name)) continue;
                switch (f.kind) {
                    case ID: fields.put(f.name, ZERO_ID); break;
                    case D32: fields.put(f.name, ZERO_DIGEST); break;
                    case TEXT: fields.put(f.name, ""); break;
                    case BLOB: fields.put(f.name, new byte[0]); break;
                    case REF: fields.put(f.name, Ref.NONE); break;
                    case FRAMES:
                    case CODES: fields.put(f.name, new ArrayList<>()); break;
                    default: fields.put(f.name, 0L); break;
                }
            }
            return this;
        }

        private Builder put(String name, Object value, Kind... kinds) {
            Kind kind = kindOf(type, name);
            if (!Arrays.asList(kinds).contains(kind)) throw new IllegalArgumentException(name + " is a " + kind);
            fields.put(name, Objects.requireNonNull(value, name));
            return this;
        }

        /** The message, checked as {@link #encode} checks it. */
        public Message build() {
            Message m = new Message(type, request, manifest, fields);
            encode(m);
            return m;
        }
    }

    static Kind kindOf(Type type, String name) {
        for (Field f : BODIES.get(type)) if (f.name.equals(name)) return f.kind;
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

    /** The one encoding of a valid message. */
    public static byte[] encode(Message m) {
        checkHex(m.request, 16, "request", false);
        checkHex(m.manifest, 32, "manifest", false);
        List<Field> layout = BODIES.get(m.type);
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
        frame.integer(VERSION, 2);
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
        if (version != VERSION) throw fail("protocol version " + version + " is not 1");
        Type.of(type);
        if (length < MIN_FRAME || length > MAX_FRAME) throw fail("a frame length outside its bounds");
        return (int) length;
    }

    /** The message one exact frame holds. */
    public static Message decode(byte[] data) {
        if (data.length < MIN_FRAME) throw fail("a frame below the minimum size");
        if (frameLength(data) != data.length) throw fail("the length field differs from the frame");
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
        for (Field f : BODIES.get(type)) fields.put(f.name, read(b, f));
        if (b.hasRemaining()) throw fail("trailing bytes after the body");
        Message m = new Message(type, request, manifest, fields);
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
            default: {
                long count = integer(b, Kind.U16, f.name);
                if (count > MAX_LEDGER) throw fail(f.name + " holds more than " + MAX_LEDGER);
                List<Integer> codes = new ArrayList<>();
                for (long i = 0; i < count; i++) codes.add((int) integer(b, Kind.U8, f.name));
                return codes;
            }
        }
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
