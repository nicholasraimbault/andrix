// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.notice;

import static dev.andrix.lab.notice.Cases.check;
import static dev.andrix.lab.notice.Cases.refused;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Host tests of the fixture's plain Java: the request and row framing, the activity's identity
 * and callback decisions, the store's write order, repeats, conflicts, failures, crash prefixes and
 * process restarts, the provider's listing and policy. With a directory argument it also writes
 * goldens for the Python reader, and with a second argument it checks the Python route's argument
 * vectors.
 * Host evidence only: no Android class runs here.
 */
public final class NoticeHostTests {
    static final String INSTALLATION = "00112233445566778899aabbccddeeff";
    static final String COMPONENT = "com.android.systemui";
    static final String PLAN = "01010101010101010101010101010101";
    static final String TICKET = "04040404040404040404040404040404";
    static final String BOOT = "3b8f0e2d9c4a6b1f7e5d2c0a8b6f4e13";
    static final String EVENT = "8c0e3f7a91b24d6e5a17c3f9d2e4b608";
    static final String CONTROL = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf";
    static final int INDEX = 2;
    static final int USER = 10;
    static final long SERIAL = 5;
    static final int UID = USER * 100000 + 10123;
    static final String TEXT = "Andrix will restart this device to change " + COMPONENT
            + ". The device owner approved it. Notice " + EVENT + ", ticket " + TICKET + ", entry " + INDEX + ".";

    static NoticeRequest notice() {
        return NoticeRequest.notice(INSTALLATION, COMPONENT, PLAN, TICKET, INDEX, BOOT, EVENT, TEXT, USER, SERIAL);
    }

    static NoticeRequest qualification() {
        return NoticeRequest.qualification(INSTALLATION, COMPONENT, CONTROL, BOOT, EVENT,
                "Andrix notice screen check " + EVENT + ".", USER, SERIAL);
    }

    static ReceiptRow row(NoticeRequest request, long candidate) {
        return ReceiptRow.of(request, UID, SERIAL, 4242, 1000, 2000, 2100, candidate);
    }

    /** Typed extras over a map, with the same typed read rule as the activity's Bundle reads. */
    static final class MapExtras implements NoticeRequest.Extras, NoticeRequest.Sink {
        final Map<String, Object> values = new HashMap<>();

        @Override
        public Set<String> keys() {
            return values.keySet();
        }

        @Override
        public String string(String key) {
            Object v = values.get(key);
            return v instanceof String ? (String) v : null;
        }

        @Override
        public Integer integer(String key) {
            Object v = values.get(key);
            return v instanceof Integer ? (Integer) v : null;
        }

        @Override
        public Long longValue(String key) {
            Object v = values.get(key);
            return v instanceof Long ? (Long) v : null;
        }

        @Override
        public void string(String key, String value) {
            values.put(key, value);
        }

        @Override
        public void integer(String key, int value) {
            values.put(key, value);
        }

        @Override
        public void longValue(String key, long value) {
            values.put(key, value);
        }
    }

    static final class Counter implements ReceiptStore.Nonces {
        int n;

        @Override
        public String next() {
            return String.format("%016x", ++n);
        }
    }

    /** A new process's nonces, which never repeat a temporary that an earlier process left. */
    static Counter later() {
        Counter counter = new Counter();
        counter.n = 1000;
        return counter;
    }

    /** Whether a store lists this whole row as its one row, beside partial writes only. */
    static boolean holdsOnly(MemoryDisk disk, ReceiptRow row) {
        ReceiptStore.Listing listing = new ReceiptStore(disk, new Counter()).list(UID, SERIAL);
        String whole = "row " + row.key() + " " + row.encode().length + " " + Forms.sha256(row.encode()) + " "
                + Forms.hex(row.encode());
        int rows = 0;
        for (String line : listing.lines.subList(1, listing.lines.size() - 1)) {
            if (line.equals(whole)) {
                rows++;
            } else if (!line.startsWith("partial .")) {
                return false;
            }
        }
        return listing.status.equals("OK") && rows == 1;
    }

    private NoticeHostTests() {}

    public static void main(String[] args) throws IOException {
        Cases cases = new Cases();
        requests(cases);
        rows(cases);
        delivery(cases);
        store(cases);
        listing(cases);
        policy(cases);
        if (args.length >= 1) goldens(cases, Paths.get(args[0]));
        if (args.length >= 2) vectors(cases, Paths.get(args[1]));
        System.exit(cases.finish());
    }

    // ------------------------------------------------------------------ request framing

    static void requests(Cases cases) {
        cases.run("request / the helper's arguments round trip, for both purposes", problems -> {
            for (NoticeRequest r : Arrays.asList(notice(), qualification())) {
                NoticeRequest back = NoticeRequest.fromArguments(r.arguments());
                check(problems, Arrays.equals(back.arguments(), r.arguments()), "round trip " + r.purpose);
                check(problems, back.text.equals(r.text) && back.textSha256.equals(Forms.sha256(r.text)),
                        "text and digest " + r.purpose);
            }
            NoticeRequest q = qualification();
            check(problems, q.plan == null && q.ticket == null && q.index == -1 && CONTROL.equals(q.control),
                    "a qualification names its control only");
        });
        cases.run("request / every argument outside its strict form is refused", problems -> {
            String[] good = notice().arguments();
            Map<String, String[]> bad = new HashMap<>();
            bad.put("too few", Arrays.copyOf(good, 13));
            bad.put("too many", Arrays.copyOf(good, 15));
            bad.put("version", with(good, 0, "2"));
            bad.put("user leading zero", with(good, 1, "010"));
            bad.put("user above its bound", with(good, 1, "21474"));
            bad.put("negative serial", with(good, 2, "-5"));
            bad.put("serial above an int", with(good, 2, "2147483648"));
            bad.put("unknown purpose", with(good, 3, "NOTICE"));
            bad.put("uppercase installation", with(good, 4, INSTALLATION.toUpperCase()));
            bad.put("zero installation", with(good, 4, "0".repeat(32)));
            bad.put("component of one segment", with(good, 5, "systemui"));
            bad.put("absent plan", with(good, 6, "-"));
            bad.put("short ticket", with(good, 7, "0404"));
            bad.put("index at the ledger bound", with(good, 8, "140"));
            bad.put("a notice naming a control", with(good, 9, CONTROL));
            bad.put("zero boot", with(good, 10, "0".repeat(32)));
            bad.put("event of other length", with(good, 11, EVENT + "00"));
            bad.put("text digest of other text", with(good, 12, Forms.sha256("other")));
            bad.put("text hex uppercase", with(good, 13, good[13].toUpperCase()));
            bad.put("text hex odd", with(good, 13, good[13] + "0"));
            bad.put("text with a line feed", textArguments(good, TEXT + "\n"));
            bad.put("text not ASCII", textArguments(good, TEXT + "\u00e9"));
            bad.put("empty text", textArguments(good, ""));
            String[] q = qualification().arguments();
            bad.put("a qualification naming a plan", with(q, 6, PLAN));
            bad.put("a qualification naming an index", with(q, 8, "0"));
            bad.put("a qualification without its control", with(q, 9, "-"));
            for (Map.Entry<String, String[]> e : bad.entrySet()) {
                check(problems, refused(() -> NoticeRequest.fromArguments(e.getValue())), e.getKey());
            }
            check(problems, refused(() -> NoticeRequest.fromArguments(null)), "no arguments");
        });
        cases.run("request / typed extras are exactly the purpose's keys, each of its type", problems -> {
            for (NoticeRequest r : Arrays.asList(notice(), qualification())) {
                MapExtras extras = new MapExtras();
                r.write(extras);
                check(problems, Arrays.equals(NoticeRequest.fromExtras(extras).arguments(), r.arguments()),
                        "extras round trip " + r.purpose);
            }
            MapExtras good = new MapExtras();
            notice().write(good);
            Map<String, Object> changes = new HashMap<>();
            changes.put(NoticeRequest.KEY_INDEX, "2");
            changes.put(NoticeRequest.KEY_USER, 10L);
            changes.put(NoticeRequest.KEY_SERIAL, 5);
            changes.put(NoticeRequest.KEY_VERSION, 2);
            changes.put(NoticeRequest.KEY_EVENT, 7);
            changes.put(NoticeRequest.KEY_PURPOSE, "QUALIFICATION");
            changes.put("dev.andrix.lab.notice.extra.EXTRA", "x");
            changes.put(NoticeRequest.KEY_CONTROL, CONTROL);
            for (Map.Entry<String, Object> c : changes.entrySet()) {
                MapExtras changed = new MapExtras();
                changed.values.putAll(good.values);
                changed.values.put(c.getKey(), c.getValue());
                check(problems, refused(() -> NoticeRequest.fromExtras(changed)), "changed " + c.getKey());
            }
            for (String key : good.values.keySet()) {
                MapExtras missing = new MapExtras();
                missing.values.putAll(good.values);
                missing.values.remove(key);
                check(problems, refused(() -> NoticeRequest.fromExtras(missing)), "missing " + key);
            }
            check(problems, refused(() -> NoticeRequest.fromExtras(null)), "no extras");
            MapExtras reported = new MapExtras();
            reported.values.putAll(good.values);
            reported.values.put(NoticeRequest.KEY_REPORT, new Object());
            check(problems, Arrays.equals(NoticeRequest.fromExtras(reported).arguments(), notice().arguments()),
                    "the report binder beside the request");
            for (String decision : new String[] {"presented", "refused:request", "refused:launcher", "refused:uid",
                "refused:user", "refused:serial", "refused:conflict", "refused:corrupt", "refused:store"}) {
                check(problems, NoticeRequest.decision(decision), "decision " + decision);
            }
            for (String decision : new String[] {null, "", "Presented", "refused:", "refused:other", "refused",
                "presented ", "refused:conflict\n"}) {
                check(problems, !NoticeRequest.decision(decision), "no decision " + decision);
            }
        });
    }

    static String[] with(String[] args, int at, String value) {
        String[] copy = args.clone();
        copy[at] = value;
        return copy;
    }

    static String[] textArguments(String[] args, String text) {
        String[] copy = args.clone();
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        copy[12] = Forms.sha256(bytes);
        copy[13] = Forms.hex(bytes);
        return copy;
    }

    // ------------------------------------------------------------------ row framing

    static void rows(Cases cases) {
        cases.run("row / encoding and parsing are exact inverses, and the key binds purpose to serial", problems -> {
            for (NoticeRequest r : Arrays.asList(notice(), qualification())) {
                ReceiptRow row = row(r, 2500);
                byte[] data = row.encode();
                ReceiptRow back = ReceiptRow.parse(data);
                check(problems, Arrays.equals(back.encode(), data) && back.sameRequest(row), "round trip " + r.purpose);
                check(problems, ReceiptRow.isKeyName(row.key()) && back.key().equals(row.key()), "key " + r.purpose);
            }
            check(problems, row(notice(), 2500).key().equals("TICKET_NOTICE." + INSTALLATION + "." + BOOT + "."
                    + TICKET + "." + INDEX + "." + USER + "." + SERIAL + ".row"), "notice key form");
            check(problems, row(qualification(), 2500).key().equals("QUALIFICATION." + INSTALLATION + "." + BOOT
                    + "." + CONTROL + "." + USER + "." + SERIAL + ".row"), "qualification key form");
            String temporary = ReceiptRow.temporaryName(row(notice(), 2500).key(), "0123456789abcdef");
            check(problems, ReceiptRow.isTemporaryName(temporary) && !ReceiptRow.isKeyName(temporary),
                    "temporary form");
            check(problems, !ReceiptRow.isTemporaryName(row(notice(), 2500).key()), "a key is no temporary");
        });
        cases.run("row / every change of the bytes outside the canonical form is refused", problems -> {
            String good = new String(row(notice(), 2500).encode(), StandardCharsets.US_ASCII);
            Map<String, String> bad = new HashMap<>();
            bad.put("magic", good.replace("andrix-notice-receipt-v1", "andrix-notice-receipt-v2"));
            bad.put("no final line feed", good.substring(0, good.length() - 1));
            bad.put("carriage return", good.replace("\nuid=", "\r\nuid="));
            bad.put("extra line", good + "extra=1\n");
            bad.put("blank line", good + "\n");
            bad.put("fields reordered", good.replace("uid=1010123\nuser=10\n", "user=10\nuid=1010123\n"));
            bad.put("leading zero", good.replace("\nserial=5\n", "\nserial=05\n"));
            bad.put("uppercase hex", good.replace(BOOT, BOOT.toUpperCase()));
            bad.put("uid of another user", good.replace("uid=1010123", "uid=1110123"));
            bad.put("system UID", good.replace("uid=1010123", "uid=1001000"));
            bad.put("user of another uid", good.replace("\nuser=10\n", "\nuser=11\n"));
            bad.put("candidate before focus", good.replace("candidate_elapsed=2500", "candidate_elapsed=2099"));
            bad.put("focus before resume", good.replace("focus_elapsed=2100", "focus_elapsed=1999"));
            bad.put("another candidate rule", good.replace(ReceiptRow.CANDIDATE_RULE, "draw"));
            bad.put("a notice naming a control", good.replace("\ncontrol=-\n", "\ncontrol=" + CONTROL + "\n"));
            bad.put("absent plan", good.replace("\nplan=" + PLAN + "\n", "\nplan=-\n"));
            bad.put("index at the bound", good.replace("\nindex=2\n", "\nindex=140\n"));
            bad.put("zero pid", good.replace("process_pid=4242", "process_pid=0"));
            bad.put("non ASCII", good.replace("systemui", "system\u00fcui"));
            for (Map.Entry<String, String> e : bad.entrySet()) {
                byte[] data = e.getValue().getBytes(StandardCharsets.UTF_8);
                check(problems, refused(() -> ReceiptRow.parse(data)), e.getKey());
            }
            check(problems, refused(() -> ReceiptRow.parse(new byte[0])), "empty");
            check(problems, refused(() -> ReceiptRow.parse(new byte[ReceiptRow.MAX_BYTES + 1])), "oversize");
        });
    }

    // ------------------------------------------------------------------ the activity's decisions

    static void delivery(Cases cases) {
        cases.run("identity / only the shell user as the observed launcher presents", problems -> {
            NoticeRequest r = notice();
            check(problems, Delivery.refusal(2000, UID, SERIAL, r) == null, "the shell user presents");
            for (int launcher : new int[] {-1, 0, 1000, 1010123, 10123, 2001}) {
                check(problems, Delivery.refusal(launcher, UID, SERIAL, r) != null, "launcher " + launcher);
            }
        });
        cases.run("identity / the actual user and serial, never the supplied ones, are bound", problems -> {
            NoticeRequest r = notice();
            check(problems, Delivery.refusal(2000, 11 * 100000 + 10123, SERIAL, r) != null, "another user");
            check(problems, Delivery.refusal(2000, UID, 6, r) != null, "another serial");
            check(problems, Delivery.refusal(2000, UID, -1, r) != null, "a removed user's serial");
            check(problems, Delivery.refusal(2000, 10 * 100000 + 1000, SERIAL, r) != null, "a system app UID");
            Delivery delivery = new Delivery(r, UID, SERIAL, 4242, 1000);
            delivery.resumed(2000);
            delivery.focused(2100);
            ReceiptRow row = delivery.committed(2500, true);
            check(problems, row != null && row.user == USER && row.uid == UID && row.serial == SERIAL,
                    "the row carries the process user and serial");
        });
        cases.run("callbacks / no resume, focus or committed frame gives no row; one row once", problems -> {
            Delivery none = new Delivery(notice(), UID, SERIAL, 4242, 1000);
            check(problems, none.committed(3000, true) == null, "no row before a resume");
            check(problems, !none.focused(2100), "no frame request before a resume");
            Delivery resumed = new Delivery(notice(), UID, SERIAL, 4242, 1000);
            resumed.resumed(2000);
            check(problems, resumed.committed(3000, true) == null, "no row without focus");
            check(problems, resumed.focused(2100), "a frame request after focus");
            check(problems, resumed.committed(2200, false) == null, "no row when focus was lost again");
            check(problems, resumed.focused(2300), "a new frame request on the next focus");
            ReceiptRow row = resumed.committed(2400, true);
            check(problems, row != null && row.resumed == 2000 && row.focus == 2100 && row.candidate == 2400,
                    "the first focus and the first committed frame with focus");
            check(problems, resumed.committed(2500, true) == null && !resumed.focused(2600), "only one row");
        });
    }

    // ------------------------------------------------------------------ the store

    static void store(Cases cases) {
        cases.run("store / a new row: exclusive temporary, write, fd sync, close, rename, directory sync",
                problems -> {
            MemoryDisk disk = new MemoryDisk();
            ReceiptStore store = new ReceiptStore(disk, new Counter());
            ReceiptRow row = row(notice(), 2500);
            check(problems, store.record(row) == ReceiptStore.Outcome.WRITTEN, "written");
            String temporary = "." + row.key() + ".0000000000000001.tmp";
            List<String> expected = Arrays.asList("mkdir", "sync-parent", "exists " + row.key(),
                    "create " + temporary, "write " + row.encode().length, "sync", "close",
                    "rename " + temporary + " " + row.key(), "sync-directory");
            check(problems, disk.operations.equals(expected), "operations " + disk.operations);
            check(problems, Arrays.equals(disk.bytes(row.key()), row.encode()), "the row's bytes");
            check(problems, disk.listing().equals(Arrays.asList(row.key())), "no temporary left");
        });
        cases.run("store / a repeat compares the whole first row and never rewrites its time", problems -> {
            MemoryDisk disk = new MemoryDisk();
            ReceiptStore store = new ReceiptStore(disk, new Counter());
            ReceiptRow first = row(notice(), 2500);
            store.record(first);
            disk.operations.clear();
            ReceiptRow later = ReceiptRow.of(notice(), UID, SERIAL, 5151, 9000, 9100, 9200, 9300);
            check(problems, store.record(later) == ReceiptStore.Outcome.REPEAT, "repeat");
            check(problems, Arrays.equals(disk.bytes(first.key()), first.encode()), "first time kept");
            check(problems, disk.operations.equals(Arrays.asList("exists " + first.key(), "read " + first.key())),
                    "only a read " + disk.operations);
        });
        cases.run("store / a request whose key holds a conflicting row is refused before it is shown",
                problems -> {
            NoticeRequest request = notice();
            ReceiptRow first = row(request, 2500);
            NoticeRequest[] conflicts = {
                NoticeRequest.notice(INSTALLATION, COMPONENT, "02".repeat(16), TICKET, INDEX, BOOT, EVENT, TEXT, USER,
                    SERIAL),
                NoticeRequest.notice(INSTALLATION, COMPONENT, PLAN, TICKET, INDEX, BOOT, "9d".repeat(16), TEXT, USER,
                    SERIAL),
                NoticeRequest.notice(INSTALLATION, COMPONENT, PLAN, TICKET, INDEX, BOOT, EVENT, TEXT + " Again.", USER,
                    SERIAL),
                NoticeRequest.notice(INSTALLATION, "com.android.other", PLAN, TICKET, INDEX, BOOT, EVENT, TEXT, USER,
                    SERIAL)};
            MemoryDisk honest = new MemoryDisk();
            honest.place(first.key(), first.encode(), true);
            ReceiptStore store = new ReceiptStore(honest, new Counter());
            check(problems, store.existing(request, UID, SERIAL) == ReceiptStore.Existing.SAME, "the honest repeat");
            check(problems, Delivery.decide(2000, UID, SERIAL, request, store).equals("presented"),
                    "the honest repeat is shown");
            for (NoticeRequest other : conflicts) {
                check(problems, ReceiptRow.keyOf(other, UID, SERIAL).equals(first.key()), "same key");
                check(problems, store.existing(other, UID, SERIAL) == ReceiptStore.Existing.CONFLICT, "a conflict");
                check(problems, Delivery.decide(2000, UID, SERIAL, other, store).equals("refused:conflict"),
                        "a conflict is refused");
            }
            for (String operation : honest.operations) {
                check(problems, operation.equals("exists " + first.key()) || operation.equals("read " + first.key()),
                        "the check only reads: " + operation);
            }
            check(problems, Arrays.equals(honest.bytes(first.key()), first.encode()) && honest.listing().size() == 1,
                    "nothing written");
            ReceiptStore empty = new ReceiptStore(new MemoryDisk(), new Counter());
            check(problems, empty.existing(request, UID, SERIAL) == ReceiptStore.Existing.ABSENT
                    && Delivery.decide(2000, UID, SERIAL, request, empty).equals("presented"), "an absent key");
            MemoryDisk damaged = new MemoryDisk();
            damaged.place(first.key(), "damaged".getBytes(StandardCharsets.US_ASCII), true);
            check(problems, Delivery.decide(2000, UID, SERIAL, request, new ReceiptStore(damaged, new Counter()))
                    .equals("refused:corrupt"), "a corrupt key");
            MemoryDisk misplaced = new MemoryDisk();
            misplaced.place(first.key(), row(qualification(), 2500).encode(), true);
            check(problems, Delivery.decide(2000, UID, SERIAL, request, new ReceiptStore(misplaced, new Counter()))
                    .equals("refused:corrupt"), "another key's row");
            MemoryDisk odd = new MemoryDisk();
            odd.place(first.key(), first.encode(), false);
            check(problems, Delivery.decide(2000, UID, SERIAL, request, new ReceiptStore(odd, new Counter()))
                    .equals("refused:corrupt"), "no regular file");
            MemoryDisk unreadable = new MemoryDisk();
            unreadable.place(first.key(), first.encode(), true);
            unreadable.failReads = true;
            check(problems, Delivery.decide(2000, UID, SERIAL, request, new ReceiptStore(unreadable, new Counter()))
                    .equals("refused:store"), "an unreadable key");
            check(problems, Delivery.decide(-1, UID, SERIAL, conflicts[0], store).equals("refused:launcher"),
                    "the identity comes first");
            check(problems, Delivery.decide(2000, 11 * 100000 + 10123, SERIAL, request, store).equals("refused:user")
                    && Delivery.decide(2000, UID, 6, request, store).equals("refused:serial")
                    && Delivery.decide(2000, 10 * 100000 + 1000, SERIAL, request, store).equals("refused:uid"),
                    "identity refusals");
        });
        cases.run("store / a duplicate key with conflicting bytes is never written", problems -> {
            NoticeRequest base = notice();
            NoticeRequest[] others = {
                NoticeRequest.notice(INSTALLATION, COMPONENT, "02".repeat(16), TICKET, INDEX, BOOT, EVENT, TEXT, USER,
                    SERIAL),
                NoticeRequest.notice(INSTALLATION, COMPONENT, PLAN, TICKET, INDEX, BOOT, "9d".repeat(16), TEXT, USER,
                    SERIAL),
                NoticeRequest.notice(INSTALLATION, COMPONENT, PLAN, TICKET, INDEX, BOOT, EVENT, TEXT + " Again.", USER,
                    SERIAL),
                NoticeRequest.notice(INSTALLATION, "com.android.other", PLAN, TICKET, INDEX, BOOT, EVENT, TEXT, USER,
                    SERIAL)};
            for (NoticeRequest other : others) {
                MemoryDisk disk = new MemoryDisk();
                ReceiptStore store = new ReceiptStore(disk, new Counter());
                ReceiptRow first = row(base, 2500);
                store.record(first);
                ReceiptRow conflict = row(other, 3000);
                check(problems, conflict.key().equals(first.key()), "same key");
                check(problems, store.record(conflict) == ReceiptStore.Outcome.CONFLICT, "conflict");
                check(problems, Arrays.equals(disk.bytes(first.key()), first.encode())
                        && disk.listing().size() == 1, "first bytes kept");
            }
            MemoryDisk damaged = new MemoryDisk();
            ReceiptRow row = row(base, 2500);
            damaged.place(row.key(), "damaged".getBytes(StandardCharsets.US_ASCII), true);
            ReceiptStore store = new ReceiptStore(damaged, new Counter());
            check(problems, store.record(row) == ReceiptStore.Outcome.CORRUPT, "an unparseable first row is corrupt");
            MemoryDisk misplaced = new MemoryDisk();
            misplaced.place(row.key(), row(qualification(), 2500).encode(), true);
            check(problems, new ReceiptStore(misplaced, new Counter()).record(row) == ReceiptStore.Outcome.CORRUPT,
                    "another key's row under this key is corrupt");
            check(problems, Arrays.equals(damaged.bytes(row.key()), "damaged".getBytes(StandardCharsets.US_ASCII)),
                    "a corrupt row is kept as it is");
        });
        cases.run("store / a failed write, sync or read latches the writer for this process", problems -> {
            String[] operations = {"mkdir", "sync-parent", "exists", "create", "write", "sync", "close", "rename",
                "sync-directory"};
            for (String operation : operations) {
                MemoryDisk disk = new MemoryDisk();
                ReceiptStore store = new ReceiptStore(disk, new Counter());
                disk.failAt(operation, 1);
                check(problems, store.record(row(notice(), 2500)) == ReceiptStore.Outcome.FAILED, "fail " + operation);
                check(problems, store.failure() != null, "latched by " + operation);
                int before = disk.operations.size();
                check(problems, store.record(row(qualification(), 2600)) == ReceiptStore.Outcome.LATCHED
                        && disk.operations.size() == before, "nothing after " + operation);
            }
            MemoryDisk reads = new MemoryDisk();
            ReceiptStore store = new ReceiptStore(reads, new Counter());
            store.record(row(notice(), 2500));
            reads.failAt("read", 1);
            check(problems, store.record(row(notice(), 2600)) == ReceiptStore.Outcome.FAILED
                    && store.record(row(qualification(), 2600)) == ReceiptStore.Outcome.LATCHED,
                    "a failed read of the first row latches too");
        });
        cases.run("store / every crash prefix lists a whole row or none, and a restart completes it",
                problems -> {
            String[] operations = {"mkdir", "sync-parent", "exists", "create", "write", "sync", "close", "rename",
                "sync-directory", "none"};
            ReceiptRow row = row(notice(), 2500);
            int checked = 0;
            for (String operation : operations) {
                for (MemoryDisk.Loss loss : MemoryDisk.Loss.values()) {
                    for (boolean names : new boolean[] {false, true}) {
                        MemoryDisk disk = new MemoryDisk();
                        ReceiptStore store = new ReceiptStore(disk, new Counter());
                        if (!operation.equals("none")) disk.failAt(operation, 1);
                        store.record(row);
                        MemoryDisk after = disk.crash(loss, names);
                        String where = operation + "/" + loss + "/" + names;
                        ReceiptStore.Listing listing = new ReceiptStore(after, new Counter()).list(UID, SERIAL);
                        int whole = 0;
                        for (String line : listing.lines.subList(1, listing.lines.size() - 1)) {
                            if (line.startsWith("row ")) {
                                whole++;
                                String expected = "row " + row.key() + " " + row.encode().length + " "
                                        + Forms.sha256(row.encode()) + " " + Forms.hex(row.encode());
                                check(problems, line.equals(expected), "whole " + where);
                            } else {
                                check(problems, line.startsWith("partial ."), "only a partial beside " + where);
                            }
                        }
                        check(problems, whole <= 1 && !listing.status.equals("UNREADABLE"), "listing " + where);
                        // A new process draws new nonces: it never reuses a kept temporary's name.
                        Counter later = new Counter();
                        later.n = 1000;
                        ReceiptStore.Outcome again = new ReceiptStore(after, later).record(row);
                        check(problems, whole == 1 ? again == ReceiptStore.Outcome.REPEAT
                                : again == ReceiptStore.Outcome.WRITTEN, "restart " + where + " " + again);
                        checked++;
                    }
                }
            }
            check(problems, checked == 60, "every prefix " + checked);
        });
        // A process restart is no crash: the new process finds the old one's names as they were,
        // durable or not, and a later loss may still take what was never synced.
        cases.run("store / after a process restart, a new row is accepted once the directory's name is durable",
                problems -> {
            ReceiptRow row = row(notice(), 2500);
            // The first process makes the directory and dies before it syncs the parent.
            MemoryDisk disk = new MemoryDisk();
            disk.failAt("sync-parent", 1);
            check(problems, new ReceiptStore(disk, new Counter()).record(row) == ReceiptStore.Outcome.FAILED
                    && disk.operations.equals(Arrays.asList("mkdir", "sync-parent")), "first " + disk.operations);
            // Control: a loss at this point keeps no directory.
            check(problems, new ReceiptStore(disk.crash(MemoryDisk.Loss.DURABLE_ONLY, false), new Counter())
                    .list(UID, SERIAL).status.equals("ABSENT"), "the directory's name is not yet durable");
            // A new process still sees the directory, and syncs its parent before anything else.
            ReceiptStore second = new ReceiptStore(disk.restart(), later());
            String temporary = "." + row.key() + ".00000000000003e9.tmp";
            check(problems, second.record(row) == ReceiptStore.Outcome.WRITTEN, "written after the restart");
            check(problems, disk.operations.equals(Arrays.asList("sync-parent", "exists " + row.key(),
                    "create " + temporary, "write " + row.encode().length, "sync", "close",
                    "rename " + temporary + " " + row.key(), "sync-directory")), "operations " + disk.operations);
            check(problems, holdsOnly(disk.crash(MemoryDisk.Loss.DURABLE_ONLY, false), row),
                    "the row survives the later loss");
            // When that parent sync fails, nothing is accepted and nothing more is tried.
            MemoryDisk failing = new MemoryDisk();
            failing.failAt("sync-parent", 1);
            new ReceiptStore(failing, new Counter()).record(row);
            failing.restart().failAt("sync-parent", 1);
            check(problems, new ReceiptStore(failing, later()).record(row) == ReceiptStore.Outcome.FAILED
                    && failing.operations.equals(Arrays.asList("sync-parent")), "not accepted " + failing.operations);
        });
        cases.run("store / after a process restart, a repeat is accepted once the row's name is durable",
                problems -> {
            ReceiptRow row = row(notice(), 2500);
            // The first process renames its row and dies before it syncs the directory.
            MemoryDisk disk = new MemoryDisk();
            disk.failAt("sync-directory", 1);
            check(problems, new ReceiptStore(disk, new Counter()).record(row) == ReceiptStore.Outcome.FAILED
                    && disk.listing().equals(Arrays.asList(row.key())), "first " + disk.operations);
            // Control: a loss at this point drops the row's name.
            ReceiptStore.Listing lost = new ReceiptStore(disk.crash(MemoryDisk.Loss.DURABLE_ONLY, false),
                    new Counter()).list(UID, SERIAL);
            check(problems, lost.status.equals("OK") && lost.lines.size() == 2,
                    "the row's name is not yet durable " + lost.lines);
            // A new process finds the same request: a repeat, accepted after the directory sync.
            ReceiptStore second = new ReceiptStore(disk.restart(), later());
            ReceiptRow again = ReceiptRow.of(notice(), UID, SERIAL, 5151, 9000, 9100, 9200, 9300);
            check(problems, second.record(again) == ReceiptStore.Outcome.REPEAT, "a repeat after the restart");
            check(problems, disk.operations.equals(Arrays.asList("sync-parent", "exists " + row.key(),
                    "read " + row.key(), "sync-directory")), "operations " + disk.operations);
            check(problems, Arrays.equals(disk.bytes(row.key()), row.encode()), "the first row and its time kept");
            check(problems, holdsOnly(disk.crash(MemoryDisk.Loss.DURABLE_ONLY, false), row),
                    "the row survives the later loss");
            // This process made the name durable, so its next repeat only reads.
            disk.operations.clear();
            check(problems, second.record(again) == ReceiptStore.Outcome.REPEAT
                    && disk.operations.equals(Arrays.asList("exists " + row.key(), "read " + row.key())),
                    "one sync for each process " + disk.operations);
            // When that directory sync fails, the repeat is not accepted; the row stays as it was.
            MemoryDisk failing = new MemoryDisk();
            failing.failAt("sync-directory", 1);
            new ReceiptStore(failing, new Counter()).record(row);
            failing.restart().failAt("sync-directory", 1);
            check(problems, new ReceiptStore(failing, later()).record(again) == ReceiptStore.Outcome.FAILED
                    && Arrays.equals(failing.bytes(row.key()), row.encode()), "not accepted " + failing.operations);
        });
        cases.run("store / after every restart prefix, an accepted row survives a later loss", problems -> {
            String[] operations = {"mkdir", "sync-parent", "exists", "create", "write", "sync", "close", "rename",
                "sync-directory", "none"};
            ReceiptRow row = row(notice(), 2500);
            int checked = 0;
            for (String operation : operations) {
                for (MemoryDisk.Loss loss : MemoryDisk.Loss.values()) {
                    for (boolean names : new boolean[] {false, true}) {
                        MemoryDisk disk = new MemoryDisk();
                        if (!operation.equals("none")) disk.failAt(operation, 1);
                        new ReceiptStore(disk, new Counter()).record(row);
                        ReceiptStore.Outcome outcome = new ReceiptStore(disk.restart(), later()).record(row);
                        boolean named = operation.equals("sync-directory") || operation.equals("none");
                        String where = operation + "/" + loss + "/" + names;
                        check(problems, outcome == (named ? ReceiptStore.Outcome.REPEAT : ReceiptStore.Outcome.WRITTEN),
                                "restart " + where + " " + outcome);
                        check(problems, holdsOnly(disk.crash(loss, names), row), "later loss " + where);
                        checked++;
                    }
                }
            }
            check(problems, checked == 60, "every prefix " + checked);
        });
    }

    // ------------------------------------------------------------------ the listing

    static void listing(Cases cases) {
        cases.run("listing / rows, partial writes and corrupt entries are each named, never an empty store",
                problems -> {
            ReceiptRow good = row(notice(), 2500);
            ReceiptRow other = ReceiptRow.of(notice(), 11 * 100000 + 10123, 7, 1, 1, 1, 1, 1);
            MemoryDisk disk = new MemoryDisk();
            disk.place(good.key(), good.encode(), true);
            disk.place("." + good.key() + ".00000000000000aa.tmp", Arrays.copyOf(good.encode(), 40), true);
            disk.place(row(qualification(), 2500).key(), "not a row".getBytes(StandardCharsets.US_ASCII), true);
            disk.place(other.key(), other.encode(), true);
            disk.place("stray file", new byte[] {1}, true);
            ReceiptStore.Listing listing = new ReceiptStore(disk, new Counter()).list(UID, SERIAL);
            List<String> lines = listing.lines;
            check(problems, lines.get(0).equals(ReceiptStore.STORE + " user=10 serial=5 uid=1010123 status=OK"),
                    "header " + lines.get(0));
            check(problems, lines.size() == 7, "five entries " + lines.size());
            check(problems, lines.contains("row " + good.key() + " " + good.encode().length + " "
                    + Forms.sha256(good.encode()) + " " + Forms.hex(good.encode())), "the whole row");
            check(problems, lines.stream().anyMatch(l -> l.startsWith("partial ." + good.key())), "the partial write");
            check(problems, lines.stream().anyMatch(l -> l.startsWith("corrupt QUALIFICATION.")
                    && l.endsWith(" unparseable")), "an unparseable row");
            check(problems, lines.stream().anyMatch(l -> l.startsWith("corrupt " + other.key())
                    && l.endsWith(" identity")), "another user's row");
            check(problems, lines.stream().anyMatch(l -> l.startsWith("corrupt unknown:")
                    && l.endsWith(" unknown-name")), "an unknown name");
            check(problems, lines.get(6).startsWith("end rows=1 corrupt=3 partial=1 listing="), "end " + lines.get(6));
            StringBuilder before = new StringBuilder();
            for (String line : lines.subList(0, 6)) before.append(line).append('\n');
            check(problems, lines.get(6).endsWith("listing=" + Forms.sha256(before.toString())), "end digest");
            List<String> names = new ArrayList<>();
            for (String line : lines.subList(1, 6)) names.add(line.split(" ")[1]);
            List<String> sorted = new ArrayList<>(names);
            java.util.Collections.sort(sorted);
            check(problems, names.equals(sorted), "name order");
        });
        cases.run("listing / absent, unreadable and overflowing stores have their own status", problems -> {
            ReceiptStore.Listing absent = new ReceiptStore(new MemoryDisk(), new Counter()).list(UID, SERIAL);
            check(problems, absent.status.equals("ABSENT") && absent.lines.size() == 2, "absent");
            MemoryDisk unlisted = new MemoryDisk();
            unlisted.place(row(notice(), 2500).key(), row(notice(), 2500).encode(), true);
            unlisted.failListing = true;
            ReceiptStore.Listing a = new ReceiptStore(unlisted, new Counter()).list(UID, SERIAL);
            check(problems, a.status.equals("UNREADABLE") && a.lines.size() == 2, "unlistable");
            MemoryDisk unread = new MemoryDisk();
            unread.place(row(notice(), 2500).key(), row(notice(), 2500).encode(), true);
            unread.failReads = true;
            ReceiptStore.Listing b = new ReceiptStore(unread, new Counter()).list(UID, SERIAL);
            check(problems, b.status.equals("UNREADABLE") && b.lines.size() == 2
                    && b.lines.get(1).startsWith("end rows=0 corrupt=0 partial=0"), "unreadable row");
            MemoryDisk full = new MemoryDisk();
            for (int i = 0; i <= ReceiptStore.MAX_ENTRIES; i++) {
                full.place(String.format(".x%03d", i), new byte[] {1}, true);
            }
            check(problems, new ReceiptStore(full, new Counter()).list(UID, SERIAL).status.equals("OVERFLOW"),
                    "overflow");
            MemoryDisk odd = new MemoryDisk();
            ReceiptRow row = row(notice(), 2500);
            odd.place(row.key(), row.encode(), false);
            check(problems, new ReceiptStore(odd, new Counter()).list(UID, SERIAL).lines.get(1)
                    .equals("corrupt " + row.key() + " - - - not-regular"), "not regular");
            MemoryDisk big = new MemoryDisk();
            big.place(row.key(), new byte[ReceiptRow.MAX_BYTES + 5], true);
            check(problems, new ReceiptStore(big, new Counter()).list(UID, SERIAL).lines.get(1)
                    .equals("corrupt " + row.key() + " - - - oversize"), "oversize");
            MemoryDisk moved = new MemoryDisk();
            ReceiptRow q = row(qualification(), 2500);
            moved.place(row.key(), q.encode(), true);
            check(problems, new ReceiptStore(moved, new Counter()).list(UID, SERIAL).lines.get(1).endsWith(" key"),
                    "a row under another key");
        });
    }

    // ------------------------------------------------------------------ the provider's policy

    static void policy(Cases cases) {
        cases.run("provider / only the shell user, only the one whole read", problems -> {
            check(problems, ProviderPolicy.caller(2000) == null, "the shell user");
            for (int uid : new int[] {0, 1000, 1010123, 10123, -1, 2001}) {
                check(problems, ProviderPolicy.caller(uid) != null, "caller " + uid);
            }
            check(problems, ProviderPolicy.query(ProviderPolicy.ROWS, null, true) == null, "whole read");
            check(problems, ProviderPolicy.query(ProviderPolicy.ROWS, new String[] {"line"}, true) == null,
                    "its one column");
            check(problems, ProviderPolicy.query(ProviderPolicy.ROWS + "/1", null, true) != null, "a row URI");
            check(problems, ProviderPolicy.query("content://" + ProviderPolicy.AUTHORITY + "/rows?x=1", null, true)
                    != null, "a query string");
            check(problems, ProviderPolicy.query(ProviderPolicy.ROWS, new String[] {"line", "x"}, true) != null,
                    "another projection");
            check(problems, ProviderPolicy.query(ProviderPolicy.ROWS, null, false) != null, "a selection");
            check(problems, ProviderPolicy.query(null, null, true) != null, "no URI");
        });
    }

    // ------------------------------------------------------------------ goldens and vectors

    static void goldens(Cases cases, Path directory) {
        cases.run("goldens / written for the Python reader", problems -> {
            Files.createDirectories(directory);
            for (NoticeRequest r : Arrays.asList(notice(), qualification())) {
                String name = r.purpose.toLowerCase();
                Files.write(directory.resolve("request-" + name + ".args"),
                        (String.join("\n", r.arguments()) + "\n").getBytes(StandardCharsets.US_ASCII));
                ReceiptRow row = row(r, 2500);
                Files.write(directory.resolve("row-" + name + ".row"), row.encode());
                Files.write(directory.resolve("row-" + name + ".name"),
                        (row.key() + "\n").getBytes(StandardCharsets.US_ASCII));
            }
            MemoryDisk disk = new MemoryDisk();
            ReceiptRow good = row(notice(), 2500);
            disk.place(good.key(), good.encode(), true);
            disk.place("." + good.key() + ".00000000000000aa.tmp", Arrays.copyOf(good.encode(), 40), true);
            disk.place(row(qualification(), 2500).key(), "not a row".getBytes(StandardCharsets.US_ASCII), true);
            disk.place("." + good.key() + ".00000000000000bb.tmp", new byte[0], false);
            disk.place("stray file", new byte[] {1}, true);
            write(directory.resolve("listing-ok.txt"), new ReceiptStore(disk, new Counter()).list(UID, SERIAL));
            write(directory.resolve("listing-absent.txt"),
                    new ReceiptStore(new MemoryDisk(), new Counter()).list(UID, SERIAL));
            MemoryDisk unread = new MemoryDisk();
            unread.place(good.key(), good.encode(), true);
            unread.failReads = true;
            write(directory.resolve("listing-unreadable.txt"),
                    new ReceiptStore(unread, new Counter()).list(UID, SERIAL));
        });
    }

    static void write(Path path, ReceiptStore.Listing listing) throws IOException {
        StringBuilder out = new StringBuilder();
        for (String line : listing.lines) out.append(line).append('\n');
        Files.write(path, out.toString().getBytes(StandardCharsets.US_ASCII));
    }

    /** Each line of the file: "accept" or "refuse", a tab, then the helper's arguments separated by
     * spaces, as the Python route builds them. */
    static void vectors(Cases cases, Path file) {
        cases.run("vectors / the Python route's helper arguments are this request's", problems -> {
            List<String> lines = Files.readAllLines(file, StandardCharsets.US_ASCII);
            check(problems, !lines.isEmpty(), "vectors given");
            for (String line : lines) {
                String[] parts = line.split("\t", -1);
                String[] args = parts[1].isEmpty() ? new String[0] : parts[1].split(" ", -1);
                boolean accept = parts[0].equals("accept");
                boolean ok;
                try {
                    ok = Arrays.equals(NoticeRequest.fromArguments(args).arguments(), args);
                } catch (IllegalArgumentException e) {
                    ok = false;
                }
                check(problems, ok == accept, parts[0] + " " + parts[1]);
            }
        });
    }
}
