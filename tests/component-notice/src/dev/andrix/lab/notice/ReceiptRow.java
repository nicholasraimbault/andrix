// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.notice;

import java.nio.charset.StandardCharsets;

/**
 * One immutable receipt row, {@code andrix-notice-receipt-v1}: the request it presented, the
 * app's actual identity and the times of its own callbacks. Plain Java.
 *
 * <p>The bytes are the magic line, then one {@code name=value} line for each field in a fixed
 * order, each ending in a line feed, in ASCII. An absent field is "-". Decimals are canonical,
 * identifiers lowercase hexadecimal. The user comes from the app's process UID and the serial from
 * UserManager, never from the request. The candidate time is the first frame commit the app saw
 * while its window had focus. A committed frame may not yet be visible, so the candidate is
 * unqualified metadata: only the host's independent visibility group can prove delivery.
 *
 * <p>The immutable key is the purpose, installation, boot token, ticket and index or control
 * action, user and serial. A repeat of the same key never rewrites a row.
 */
public final class ReceiptRow {
    public static final String MAGIC = "andrix-notice-receipt-v1";
    public static final String CANDIDATE_RULE = "focus-then-frame-commit";
    public static final int MAX_BYTES = 2048;
    public static final String KEY_SUFFIX = ".row";
    public static final String TEMPORARY_SUFFIX = ".tmp";
    static final String[] NAMES = {"purpose", "installation", "component", "plan", "ticket", "index", "control",
        "boot", "text_sha256", "event", "uid", "user", "serial", "process_pid", "process_start_elapsed",
        "resumed_elapsed", "focus_elapsed", "candidate_rule", "candidate_elapsed"};

    public final String purpose;
    public final String installation;
    public final String component;
    public final String plan;
    public final String ticket;
    public final int index;
    public final String control;
    public final String boot;
    public final String textSha256;
    public final String event;
    public final int uid;
    public final int user;
    public final long serial;
    public final int pid;
    public final long processStart;
    public final long resumed;
    public final long focus;
    public final long candidate;

    private ReceiptRow(String purpose, String installation, String component, String plan, String ticket, int index,
            String control, String boot, String textSha256, String event, int uid, int user, long serial, int pid,
            long processStart, long resumed, long focus, long candidate) {
        boolean notice = NoticeRequest.TICKET_NOTICE.equals(purpose);
        if (!notice && !NoticeRequest.QUALIFICATION.equals(purpose)) throw Forms.refused("row purpose");
        if (!Forms.id(installation, 16) || !Forms.component(component)) throw Forms.refused("row installation");
        if (notice != (plan != null) || notice != (ticket != null) || notice != (index >= 0)
                || notice == (control != null)) {
            throw Forms.refused("row names a notice or a control");
        }
        if (notice && (!Forms.id(plan, 16) || !Forms.id(ticket, 16) || index >= Forms.MAX_LEDGER)) {
            throw Forms.refused("row notice");
        }
        if (!notice && (!Forms.id(control, 16) || index != -1)) throw Forms.refused("row control");
        if (!Forms.id(boot, 16) || !Forms.id(event, 16) || !Forms.id(textSha256, 32)) throw Forms.refused("row ids");
        if (!Forms.applicationUid(uid) || uid / Forms.PER_USER_RANGE != user) throw Forms.refused("row uid");
        if (serial < 0 || serial > Forms.MAX_SERIAL) throw Forms.refused("row serial");
        if (pid <= 0) throw Forms.refused("row pid");
        if (processStart < 0 || resumed < processStart || focus < resumed || candidate < focus) {
            throw Forms.refused("row times");
        }
        this.purpose = purpose;
        this.installation = installation;
        this.component = component;
        this.plan = plan;
        this.ticket = ticket;
        this.index = index;
        this.control = control;
        this.boot = boot;
        this.textSha256 = textSha256;
        this.event = event;
        this.uid = uid;
        this.user = user;
        this.serial = serial;
        this.pid = pid;
        this.processStart = processStart;
        this.resumed = resumed;
        this.focus = focus;
        this.candidate = candidate;
    }

    /** The row of a presented request, with the app's own identity and callback times. */
    public static ReceiptRow of(NoticeRequest request, int uid, long serial, int pid, long processStart,
            long resumed, long focus, long candidate) {
        return new ReceiptRow(request.purpose, request.installation, request.component, request.plan,
                request.ticket, request.index, request.control, request.boot, request.textSha256, request.event, uid,
                uid / Forms.PER_USER_RANGE, serial, pid, processStart, resumed, focus, candidate);
    }

    private String[] values() {
        return new String[] {purpose, installation, component, orDash(plan), orDash(ticket),
            index < 0 ? "-" : Integer.toString(index), orDash(control), boot, textSha256, event,
            Integer.toString(uid), Integer.toString(user), Long.toString(serial), Integer.toString(pid),
            Long.toString(processStart), Long.toString(resumed), Long.toString(focus), CANDIDATE_RULE,
            Long.toString(candidate)};
    }

    private static String orDash(String value) {
        return value == null ? "-" : value;
    }

    /** The row's exact bytes. */
    public byte[] encode() {
        StringBuilder out = new StringBuilder(MAGIC).append('\n');
        String[] values = values();
        for (int i = 0; i < NAMES.length; i++) out.append(NAMES[i]).append('=').append(values[i]).append('\n');
        byte[] data = out.toString().getBytes(StandardCharsets.US_ASCII);
        if (data.length > MAX_BYTES) throw Forms.refused("row size");
        return data;
    }

    /** The row of exactly these bytes, or a refusal: any other form is no row. */
    public static ReceiptRow parse(byte[] data) {
        if (data == null || data.length == 0 || data.length > MAX_BYTES) throw Forms.refused("row size");
        for (byte b : data) {
            if (b != '\n' && (b < 0x20 || b > 0x7e)) throw Forms.refused("row bytes");
        }
        String text = new String(data, StandardCharsets.US_ASCII);
        if (!text.endsWith("\n")) throw Forms.refused("row end");
        String[] lines = text.substring(0, text.length() - 1).split("\n", -1);
        if (lines.length != NAMES.length + 1 || !MAGIC.equals(lines[0])) throw Forms.refused("row lines");
        String[] v = new String[NAMES.length];
        for (int i = 0; i < NAMES.length; i++) {
            String prefix = NAMES[i] + "=";
            if (!lines[i + 1].startsWith(prefix)) throw Forms.refused("row field " + NAMES[i]);
            v[i] = lines[i + 1].substring(prefix.length());
        }
        if (!CANDIDATE_RULE.equals(v[17])) throw Forms.refused("row candidate rule");
        boolean notice = NoticeRequest.TICKET_NOTICE.equals(v[0]);
        int index = notice ? (int) Forms.decimal(v[5], 0, Forms.MAX_LEDGER - 1, "row index") : dashed(v[5]);
        ReceiptRow row = new ReceiptRow(v[0], v[1], v[2], notice ? v[3] : nulled(v[3]), notice ? v[4] : nulled(v[4]),
                index, notice ? nulled(v[6]) : v[6], v[7], v[8], v[9],
                (int) Forms.decimal(v[10], 0, Integer.MAX_VALUE, "row uid"),
                (int) Forms.decimal(v[11], 0, Forms.MAX_USER, "row user"),
                Forms.decimal(v[12], 0, Forms.MAX_SERIAL, "row serial"),
                (int) Forms.decimal(v[13], 1, Integer.MAX_VALUE, "row pid"),
                Forms.decimal(v[14], 0, Long.MAX_VALUE, "row process start"),
                Forms.decimal(v[15], 0, Long.MAX_VALUE, "row resumed"),
                Forms.decimal(v[16], 0, Long.MAX_VALUE, "row focus"),
                Forms.decimal(v[18], 0, Long.MAX_VALUE, "row candidate"));
        // The bytes must be the canonical encoding of what they say.
        if (!java.util.Arrays.equals(row.encode(), data)) throw Forms.refused("row not canonical");
        return row;
    }

    private static String nulled(String value) {
        if (!"-".equals(value)) throw Forms.refused("row absent field");
        return null;
    }

    private static int dashed(String value) {
        nulled(value);
        return -1;
    }

    /** The immutable key, which is also the row's file name. */
    public String key() {
        return key(purpose, installation, boot, ticket, index, control, user, serial);
    }

    /** The key a presentation of this request by the app of this UID and serial would write. */
    public static String keyOf(NoticeRequest request, int uid, long serial) {
        return key(request.purpose, request.installation, request.boot, request.ticket, request.index, request.control,
                uid / Forms.PER_USER_RANGE, serial);
    }

    private static String key(String purpose, String installation, String boot, String ticket, int index,
            String control, int user, long serial) {
        if (NoticeRequest.TICKET_NOTICE.equals(purpose)) {
            return purpose + "." + installation + "." + boot + "." + ticket + "." + index + "." + user + "." + serial
                    + KEY_SUFFIX;
        }
        return purpose + "." + installation + "." + boot + "." + control + "." + user + "." + serial + KEY_SUFFIX;
    }

    /**
     * Whether another row presents the same request to the same app identity: every field but the
     * process and callback times. A repeat of the key with these equal is a redisplay; with any
     * of them different it is a conflict.
     */
    public boolean sameRequest(ReceiptRow other) {
        return purpose.equals(other.purpose) && installation.equals(other.installation)
                && component.equals(other.component) && java.util.Objects.equals(plan, other.plan)
                && java.util.Objects.equals(ticket, other.ticket) && index == other.index
                && java.util.Objects.equals(control, other.control) && boot.equals(other.boot)
                && textSha256.equals(other.textSha256) && event.equals(other.event) && uid == other.uid
                && user == other.user && serial == other.serial;
    }

    /**
     * Whether this row presents exactly this request to the app of this UID and serial: the same
     * fields {@link #sameRequest} compares. A row under the request's key that does not is a
     * conflict, and the request is refused before anything is shown.
     */
    public boolean matches(NoticeRequest request, int uid, long serial) {
        return purpose.equals(request.purpose) && installation.equals(request.installation)
                && component.equals(request.component) && java.util.Objects.equals(plan, request.plan)
                && java.util.Objects.equals(ticket, request.ticket) && index == request.index
                && java.util.Objects.equals(control, request.control) && boot.equals(request.boot)
                && textSha256.equals(request.textSha256) && event.equals(request.event) && this.uid == uid
                && user == uid / Forms.PER_USER_RANGE && this.serial == serial;
    }

    /** Whether a file name has the form of a key. Only a parsed row can show it is its own key. */
    public static boolean isKeyName(String name) {
        if (name == null || !name.endsWith(KEY_SUFFIX) || name.length() > 200) return false;
        String[] parts = name.substring(0, name.length() - KEY_SUFFIX.length()).split("\\.", -1);
        boolean notice = parts.length == 7 && NoticeRequest.TICKET_NOTICE.equals(parts[0]);
        boolean qualification = parts.length == 6 && NoticeRequest.QUALIFICATION.equals(parts[0]);
        if (!notice && !qualification) return false;
        if (!Forms.id(parts[1], 16) || !Forms.id(parts[2], 16) || !Forms.id(parts[3], 16)) return false;
        int at = 4;
        if (notice && !decimal(parts[at++], Forms.MAX_LEDGER - 1)) return false;
        return decimal(parts[at], Forms.MAX_USER) && decimal(parts[at + 1], Forms.MAX_SERIAL);
    }

    private static boolean decimal(String text, long max) {
        try {
            Forms.decimal(text, 0, max, "decimal");
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** The name of a writer's exclusive temporary for a key: a dot, the key, a nonce, ".tmp". */
    public static String temporaryName(String key, String nonce) {
        if (!isKeyName(key) || !Forms.id(nonce, 8)) throw Forms.refused("temporary name");
        return "." + key + "." + nonce + TEMPORARY_SUFFIX;
    }

    /** Whether a file name has the form of a writer's temporary. */
    public static boolean isTemporaryName(String name) {
        if (name == null || !name.startsWith(".") || !name.endsWith(TEMPORARY_SUFFIX)) return false;
        String body = name.substring(1, name.length() - TEMPORARY_SUFFIX.length());
        int dot = body.lastIndexOf('.');
        return dot > 0 && Forms.id(body.substring(dot + 1), 8) && isKeyName(body.substring(0, dot));
    }
}
