// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.notice;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * One presentation request, in one strict form. The fixed shell helper builds it from its
 * arguments and puts it in its explicit intent as typed extras; the activity reads it back from
 * those extras. Plain Java, so that the host tests run this class as it is.
 *
 * <p>A request is a ticket's NOTICE, with its plan, ticket and ledger index, or a QUALIFICATION
 * control, with its control action ID, never both. The user and serial name the recipient the host
 * expects. They are a check, not an identity: the activity compares them with the user of its own
 * process UID and the serial UserManager gives for it, and refuses a difference.
 *
 * <p>Beside the request, the intent may carry the helper's report binder under {@link #KEY_REPORT}.
 * The activity sends it one decision before anything is shown: {@link #PRESENTED}, or
 * {@code refused:} and one of {@link #REFUSALS}. A decision says what the app did with the request,
 * never that a user saw it.
 */
public final class NoticeRequest {
    public static final int VERSION = 1;
    public static final String TICKET_NOTICE = "TICKET_NOTICE";
    public static final String QUALIFICATION = "QUALIFICATION";
    public static final int MAX_TEXT = 1024;
    /** The helper's arguments: the version, then the fields in this order. */
    public static final int ARGUMENTS = 14;

    private static final String EXTRA = "dev.andrix.lab.notice.extra.";
    public static final String KEY_VERSION = EXTRA + "VERSION";
    public static final String KEY_PURPOSE = EXTRA + "PURPOSE";
    public static final String KEY_INSTALLATION = EXTRA + "INSTALLATION";
    public static final String KEY_COMPONENT = EXTRA + "COMPONENT";
    public static final String KEY_PLAN = EXTRA + "PLAN";
    public static final String KEY_TICKET = EXTRA + "TICKET";
    public static final String KEY_INDEX = EXTRA + "INDEX";
    public static final String KEY_CONTROL = EXTRA + "CONTROL";
    public static final String KEY_BOOT = EXTRA + "BOOT";
    public static final String KEY_EVENT = EXTRA + "EVENT";
    public static final String KEY_TEXT = EXTRA + "TEXT";
    public static final String KEY_TEXT_SHA256 = EXTRA + "TEXT_SHA256";
    public static final String KEY_USER = EXTRA + "USER";
    public static final String KEY_SERIAL = EXTRA + "SERIAL";
    /** The helper's report binder: not part of the request. */
    public static final String KEY_REPORT = EXTRA + "REPORT";
    public static final String REPORT_DESCRIPTOR = "dev.andrix.lab.notice.PresentationReport";
    public static final int REPORT_VERSION = 1;
    public static final String PRESENTED = "presented";
    public static final String REFUSED = "refused:";
    /** Why the activity refuses a request, in its decision: a request of no known form, a launcher
     * other than the shell user, an app UID, user or serial other than expected, and an existing
     * row under the key that conflicts, is corrupt, or cannot be read. */
    public static final Set<String> REFUSALS = set("request", "launcher", "uid", "user", "serial", "conflict",
            "corrupt", "store");

    private static final Set<String> COMMON = set(KEY_VERSION, KEY_PURPOSE, KEY_INSTALLATION, KEY_COMPONENT,
            KEY_BOOT, KEY_EVENT, KEY_TEXT, KEY_TEXT_SHA256, KEY_USER, KEY_SERIAL);
    private static final Set<String> NOTICE_KEYS = with(COMMON, KEY_PLAN, KEY_TICKET, KEY_INDEX);
    private static final Set<String> QUALIFICATION_KEYS = with(COMMON, KEY_CONTROL);

    public final String purpose;
    public final String installation;
    public final String component;
    /** The plan, ticket and index of a ticket's NOTICE; null, null and -1 for a qualification. */
    public final String plan;
    public final String ticket;
    public final int index;
    /** The control action of a qualification; null for a ticket's NOTICE. */
    public final String control;
    /** The host's boot token. An ordinary app cannot read the kernel boot ID; the host binds it. */
    public final String boot;
    /** The unpredictable public challenge, which is also the row's event ID. */
    public final String event;
    public final String text;
    public final String textSha256;
    public final int user;
    public final long serial;

    /** Typed read access to an intent's extras: the key set, and a value only when it has the
     * type asked for. */
    public interface Extras {
        Set<String> keys();

        /** The value when the key holds a String, else null. */
        String string(String key);

        /** The value when the key holds an int, else null. */
        Integer integer(String key);

        /** The value when the key holds a long, else null. */
        Long longValue(String key);
    }

    /** Where the helper puts the typed extras. */
    public interface Sink {
        void string(String key, String value);

        void integer(String key, int value);

        void longValue(String key, long value);
    }

    private NoticeRequest(String purpose, String installation, String component, String plan, String ticket,
            int index, String control, String boot, String event, String text, String textSha256, int user,
            long serial) {
        boolean notice = TICKET_NOTICE.equals(purpose);
        if (!notice && !QUALIFICATION.equals(purpose)) throw Forms.refused("purpose");
        if (!Forms.id(installation, 16)) throw Forms.refused("installation");
        if (!Forms.component(component)) throw Forms.refused("component");
        if (notice) {
            if (!Forms.id(plan, 16) || !Forms.id(ticket, 16)) throw Forms.refused("plan or ticket");
            if (index < 0 || index >= Forms.MAX_LEDGER) throw Forms.refused("index");
            if (control != null) throw Forms.refused("a notice names no control");
        } else {
            if (plan != null || ticket != null || index != -1) throw Forms.refused("a qualification names no ticket");
            if (!Forms.id(control, 16)) throw Forms.refused("control");
        }
        if (!Forms.id(boot, 16)) throw Forms.refused("boot");
        if (!Forms.id(event, 16)) throw Forms.refused("event");
        if (!Forms.printable(text, MAX_TEXT)) throw Forms.refused("text");
        if (!Forms.id(textSha256, 32) || !Forms.sha256(text).equals(textSha256)) throw Forms.refused("text digest");
        if (user < 0 || user > Forms.MAX_USER) throw Forms.refused("user");
        if (serial < 0 || serial > Forms.MAX_SERIAL) throw Forms.refused("serial");
        this.purpose = purpose;
        this.installation = installation;
        this.component = component;
        this.plan = plan;
        this.ticket = ticket;
        this.index = index;
        this.control = control;
        this.boot = boot;
        this.event = event;
        this.text = text;
        this.textSha256 = textSha256;
        this.user = user;
        this.serial = serial;
    }

    /** The request of a ticket's NOTICE. */
    public static NoticeRequest notice(String installation, String component, String plan, String ticket, int index,
            String boot, String event, String text, int user, long serial) {
        return new NoticeRequest(TICKET_NOTICE, installation, component, plan, ticket, index, null, boot, event, text,
                text == null ? null : Forms.sha256(text), user, serial);
    }

    /** The request of a qualification control. */
    public static NoticeRequest qualification(String installation, String component, String control, String boot,
            String event, String text, int user, long serial) {
        return new NoticeRequest(QUALIFICATION, installation, component, null, null, -1, control, boot, event, text,
                text == null ? null : Forms.sha256(text), user, serial);
    }

    /**
     * The request from the helper's arguments: version, user, serial, purpose, installation,
     * component, plan, ticket, index, control, boot, event, text SHA-256 and the text as
     * lowercase hexadecimal of its ASCII bytes. An absent field is "-". Every other form is
     * refused.
     */
    public static NoticeRequest fromArguments(String[] args) {
        if (args == null || args.length != ARGUMENTS) throw Forms.refused("arguments");
        if (!Integer.toString(VERSION).equals(args[0])) throw Forms.refused("version");
        int user = (int) Forms.decimal(args[1], 0, Forms.MAX_USER, "user");
        long serial = Forms.decimal(args[2], 0, Forms.MAX_SERIAL, "serial");
        boolean notice = TICKET_NOTICE.equals(args[3]);
        String plan = absent(args[6], !notice, "plan");
        String ticket = absent(args[7], !notice, "ticket");
        int index = notice ? (int) Forms.decimal(args[8], 0, Forms.MAX_LEDGER - 1, "index") : dash(args[8], "index");
        String control = absent(args[9], notice, "control");
        byte[] text = Forms.unhex(args[13], MAX_TEXT, "text");
        return new NoticeRequest(args[3], args[4], args[5], plan, ticket, index, control, args[10], args[11],
                new String(text, StandardCharsets.US_ASCII), args[12], user, serial);
    }

    private static String absent(String value, boolean absent, String what) {
        if (absent) {
            dash(value, what);
            return null;
        }
        return value;
    }

    private static int dash(String value, String what) {
        if (!"-".equals(value)) throw Forms.refused(what);
        return -1;
    }

    /** Whether a text is one decision of the activity: {@link #PRESENTED}, or {@link #REFUSED}
     * and one of {@link #REFUSALS}. */
    public static boolean decision(String text) {
        return PRESENTED.equals(text) || (text != null && text.startsWith(REFUSED)
                && REFUSALS.contains(text.substring(REFUSED.length())));
    }

    /** The request from typed extras: exactly the keys of its purpose, each of its type, and at
     * most the report binder beside them. */
    public static NoticeRequest fromExtras(Extras extras) {
        if (extras == null) throw Forms.refused("extras");
        String purpose = extras.string(KEY_PURPOSE);
        boolean notice = TICKET_NOTICE.equals(purpose);
        if (!notice && !QUALIFICATION.equals(purpose)) throw Forms.refused("purpose");
        Set<String> keys = new HashSet<>(extras.keys());
        keys.remove(KEY_REPORT);
        if (!keys.equals(notice ? NOTICE_KEYS : QUALIFICATION_KEYS)) throw Forms.refused("extra keys");
        Integer version = extras.integer(KEY_VERSION);
        if (version == null || version != VERSION) throw Forms.refused("version");
        Integer user = extras.integer(KEY_USER);
        Long serial = extras.longValue(KEY_SERIAL);
        if (user == null || serial == null) throw Forms.refused("user or serial");
        Integer index = notice ? extras.integer(KEY_INDEX) : Integer.valueOf(-1);
        if (index == null) throw Forms.refused("index");
        String plan = notice ? required(extras, KEY_PLAN) : null;
        String ticket = notice ? required(extras, KEY_TICKET) : null;
        String control = notice ? null : required(extras, KEY_CONTROL);
        return new NoticeRequest(purpose, required(extras, KEY_INSTALLATION), required(extras, KEY_COMPONENT), plan,
                ticket, index, control, required(extras, KEY_BOOT), required(extras, KEY_EVENT),
                required(extras, KEY_TEXT), required(extras, KEY_TEXT_SHA256), user, serial);
    }

    private static String required(Extras extras, String key) {
        String value = extras.string(key);
        if (value == null) throw Forms.refused("extra " + key.substring(EXTRA.length()));
        return value;
    }

    /** Writes the typed extras of this request, exactly the keys of its purpose. */
    public void write(Sink sink) {
        sink.integer(KEY_VERSION, VERSION);
        sink.string(KEY_PURPOSE, purpose);
        sink.string(KEY_INSTALLATION, installation);
        sink.string(KEY_COMPONENT, component);
        if (TICKET_NOTICE.equals(purpose)) {
            sink.string(KEY_PLAN, plan);
            sink.string(KEY_TICKET, ticket);
            sink.integer(KEY_INDEX, index);
        } else {
            sink.string(KEY_CONTROL, control);
        }
        sink.string(KEY_BOOT, boot);
        sink.string(KEY_EVENT, event);
        sink.string(KEY_TEXT, text);
        sink.string(KEY_TEXT_SHA256, textSha256);
        sink.integer(KEY_USER, user);
        sink.longValue(KEY_SERIAL, serial);
    }

    /** The helper's arguments for this request, the inverse of {@link #fromArguments}. */
    public String[] arguments() {
        boolean notice = TICKET_NOTICE.equals(purpose);
        return new String[] {Integer.toString(VERSION), Integer.toString(user), Long.toString(serial), purpose,
            installation, component, notice ? plan : "-", notice ? ticket : "-",
            notice ? Integer.toString(index) : "-", notice ? "-" : control, boot, event, textSha256,
            Forms.hex(text.getBytes(StandardCharsets.US_ASCII))};
    }

    private static Set<String> set(String... keys) {
        return Collections.unmodifiableSet(new HashSet<>(Arrays.asList(keys)));
    }

    private static Set<String> with(Set<String> base, String... keys) {
        Set<String> all = new HashSet<>(base);
        all.addAll(Arrays.asList(keys));
        return Collections.unmodifiableSet(all);
    }
}
