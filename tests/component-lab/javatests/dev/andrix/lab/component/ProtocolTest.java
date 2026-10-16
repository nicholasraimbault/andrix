// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

import dev.andrix.lab.component.LabProtocol.Envelope;
import dev.andrix.lab.component.LabProtocol.Frame;
import dev.andrix.lab.component.LabProtocol.Message;
import dev.andrix.lab.component.LabProtocol.ProtocolError;
import dev.andrix.lab.component.LabProtocol.Ref;
import dev.andrix.lab.component.LabProtocol.Row;
import dev.andrix.lab.component.LabProtocol.Type;
import dev.andrix.server.deployment.DeploymentRecords;
import dev.andrix.server.deployment.DeploymentRecords.Cause;
import dev.andrix.server.deployment.DeploymentRecords.Classification;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.Route;
import dev.andrix.server.deployment.DeploymentRecords.CoordinatorClass;
import dev.andrix.server.deployment.DeploymentRecords.Crossing;
import dev.andrix.server.deployment.DeploymentRecords.Entry;
import dev.andrix.server.deployment.DeploymentRecords.State;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;

/**
 * The Java codec of the bridge protocol: the same goldens as the Python codec, one encoding for
 * each message, and refusal of every malformed frame. With a directory argument it also compares
 * each golden with the file the Python suite wrote there. Host JVM only.
 */
public final class ProtocolTest {
    static final String REQUEST = "0f".repeat(16);
    static final String MANIFEST = "ad".repeat(32);
    static final String NONCE = "5e1f0c9a7d3b4e2f8a6c1d0b9e7f3a25";
    static final String BOOT = "1f0d016e80904303a3ff9eb193eb403d";
    static final Ref BOUND = new Ref(31, 1189842383, 1791504012345L, "/data/app-staging/session_1189842383", 2000, NONCE);

    /** The Python suite's pinned golden digests. */
    static final Map<String, String> GOLDENS = new LinkedHashMap<>();

    static {
        GOLDENS.put("HELLO", "abc3267476f4f4e2e51a6832ba154484a1307a33f2e60063e90136937f5c6c0c");
        GOLDENS.put("HELLO_REPLY", "73b98362f536dad8ef61fbe23d8b761158dcae9f9ee916894210e369866b5793");
        GOLDENS.put("CLOCK", "ac5895b1ec24658af76bddfc40d1130f858ae948f736b9c33337587ced1cad99");
        GOLDENS.put("CLOCK_REPLY", "529fbab76241756678696d9cacca78a3b7a52cc323119d82af2e7a842a91e6b0");
        GOLDENS.put("OBSERVE", "f97df0c52813b9daca05caa0ea649042a68a4e389a2fd30fc930fa70835f0cd7");
        GOLDENS.put("OBSERVE_REPLY", "281344f7d8ca5879fe31ea999408229d8efb9290ceab4536e47221e61ce9e5da");
        GOLDENS.put("CROSS", "0c2d43765e4be9be7652f06b5f979212d7ec1c5a3e70bc4d66e5224b328713eb");
        GOLDENS.put("CROSS_REPLY", "b90aa2fa2a1b758d2161235a37d55210ee1c9b95207ba84e5ea7013d3ad0d31a");
        GOLDENS.put("POINT", "7e3da79951886f9683a7b4b7b1bd7cba13efde47dda642a36c28224d150ecfe0");
        GOLDENS.put("POINT_REPLY", "e66de80bc95223d73a327321e4ef215a4be116374b2ba68f13ebfc5fb9ff79f0");
        GOLDENS.put("HOST", "bd7707720c837772ad7753b44b125c874044685e17e74c492a8f2abe410aba36");
        GOLDENS.put("HOST_REPLY", "7daad1982144430f2cbb437f9f8909ff4c8a31e4a2e07fc30753a3dd54a57baf");
        GOLDENS.put("REPORT", "7156a50db3f8f21d7d33a054ce9f096646051828c9ffd111514350fc80bf6800");
        GOLDENS.put("REPORT_REPLY", "e677104dd5b782e941c16d27527ea46a3126c7fbc707ffe6c2719d1597414217");
        GOLDENS.put("V2_HELLO", "3cee5db9c1c8275b7229593e9982ecbafc6b71bd9047dff6c8d4dbb1e2b0914b");
        GOLDENS.put("V2_OBSERVE_REPLY_SIMPLE", "dbadf2f6dad5902efb2ef6292043ca87fa6c1eeccd8b4cc45e6d6d617afe940f");
        GOLDENS.put("V2_OBSERVE_REPLY_RECEIPT", "e94660e93465e8501e144c9073fafd0e653b69992006eaf674ba931a7816bab8");
        GOLDENS.put("V2_OBSERVE_REPLY_HEALTH", "02e1bccb844388b74c22cbdcac5a48422877731d879898c36ad72273ea42af35");
        GOLDENS.put("V2_OBSERVE_REPLY_HALT", "6c4068854ca984bb686f868056b2242dc851911b6c9a1f2185499bae74b460d7");
        GOLDENS.put("V2_OBSERVE_REPLY_STOPPED", "25b4529be3d26438f63d06478c037730a94744d468428ccc856d2fcb75f11e0f");
    }

    static final String INSTALLATION = "00112233445566778899aabbccddeeff";
    static final String SYSTEMUI = "com.android.systemui";

    static LabProtocol.Builder of2(Type type) { return Message.of(2, type, REQUEST, MANIFEST); }

    /** The Python suite's version 2 observation records, built by the public deployment codec. */
    static byte[] checkpoint(String id) {
        return DeploymentRecords.encodeObservation(new Observation.Builder().installation(INSTALLATION)
                .observationId(id).boot(BOOT).route(Route.SHELL).at(-1, 812400, 1791504812400L).raw("33".repeat(32))
                .classification(Classification.CHECKPOINT_COMMITTED).build());
    }

    static byte[] receiptRecord(long elapsed, Classification c, int index) {
        return DeploymentRecords.encodeObservation(new Observation.Builder().installation(INSTALLATION)
                .observationId("6e".repeat(16)).component(SYSTEMUI).boot(BOOT).user(10, 11).route(Route.SHELL)
                .at(4021, elapsed, 1791504000000L + elapsed).raw("44".repeat(32)).classification(c)
                .receipt("04".repeat(16), index).build());
    }

    static byte[] healthRecord(Classification c, int criteria, long elapsed) {
        return DeploymentRecords.encodeObservation(new Observation.Builder().installation(INSTALLATION)
                .observationId("6d".repeat(16)).component(SYSTEMUI).boot(BOOT).user(0, 0).route(Route.SHELL)
                .at(4021, elapsed, 1791504000000L + elapsed).raw("99".repeat(32)).classification(c).number(criteria)
                .build());
    }

    static Map<String, Object> receiptBlock() {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("read_boot", BOOT);
        b.put("read_instance", 4021L);
        b.put("read_begin_elapsed", 1000L);
        b.put("read_end_elapsed", 1200L);
        b.put("plan", "01".repeat(16));
        b.put("ticket", "04".repeat(16));
        b.put("notice_index", 3L);
        b.put("issue_ticket_digest", "55".repeat(32));
        b.put("event", "66".repeat(16));
        b.put("row", "77".repeat(32));
        b.put("delivery_group", "88".repeat(32));
        b.put("delivery_instance", 4021L);
        b.put("delivery_begin", 400L);
        b.put("proven_elapsed", 500L);
        b.put("delivery_end", 500L);
        return b;
    }

    static List<Row> rows(int... statuses) {
        List<Row> rows = new ArrayList<>();
        for (int bit = 0; bit < 7; bit++) rows.add(new Row(bit, statuses[bit], ("d" + bit).repeat(32)));
        return rows;
    }

    static Map<String, Object> healthBlock() {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("read_boot", BOOT);
        b.put("read_instance", 4021L);
        b.put("read_begin_elapsed", 94000L);
        b.put("read_end_elapsed", 95000L);
        b.put("plan", "01".repeat(16));
        b.put("ticket", "04".repeat(16));
        b.put("window_boot", BOOT);
        b.put("window_start", 90000L);
        b.put("publication", "a3".repeat(32));
        b.put("active_apk", "a1".repeat(32));
        b.put("baseline", "b4".repeat(32));
        b.put("preparation_root", "c5".repeat(32));
        b.put("probe_begin", 92000L);
        b.put("probe_end", 95000L);
        b.put("criteria", 127L);
        b.put("rows", rows(1, 1, 1, 1, 1, 1, 1));
        return b;
    }

    static Envelope simple(String id) {
        return new Envelope(18, LabProtocol.SIMPLE_CURRENT, "33".repeat(32), Collections.emptyMap(), checkpoint(id));
    }

    static Envelope receipt(Map<String, Object> block, byte[] record) {
        return new Envelope(21, LabProtocol.RECEIPT_EVENT, "44".repeat(32), block, record);
    }

    static Envelope health(Map<String, Object> block, byte[] record) {
        return new Envelope(22, LabProtocol.COMPOSED_HEALTH, "99".repeat(32), block, record);
    }

    static LabProtocol.Builder reply2(List<Envelope> envelopes) {
        return of2(Type.OBSERVE_REPLY).number("status", 1).number("control_record", 0).envelopes("envelopes", envelopes)
                .text("reason", "");
    }

    /** Version 2's goldens, the same values as the Python suite's. */
    static Map<String, Message> goldens2() {
        Map<String, Message> m = new LinkedHashMap<>();
        m.put("V2_HELLO", of2(Type.HELLO).id("installation", INSTALLATION).id("coordinator", "c0".repeat(16))
                .id("config", "3c".repeat(32)).text("component", SYSTEMUI).id("trust", "7a".repeat(32)).number("route", 1)
                .build());
        m.put("V2_OBSERVE_REPLY_SIMPLE", reply2(Collections.singletonList(simple("6f".repeat(16)))).build());
        m.put("V2_OBSERVE_REPLY_RECEIPT", reply2(Collections.singletonList(receipt(receiptBlock(),
                receiptRecord(500, Classification.RECEIPT_FULL_SCREEN, 3)))).build());
        m.put("V2_OBSERVE_REPLY_HEALTH", reply2(Collections.singletonList(health(healthBlock(),
                healthRecord(Classification.HEALTH_HELD, 127, 95000)))).build());
        m.put("V2_OBSERVE_REPLY_HALT", of2(Type.OBSERVE_REPLY).number("status", 4).number("control_record", 46)
                .envelopes("envelopes", Collections.emptyList()).text("reason", "admitted read loss").build());
        m.put("V2_OBSERVE_REPLY_STOPPED", of2(Type.OBSERVE_REPLY).number("status", 3).number("control_record", 0)
                .envelopes("envelopes", Collections.emptyList()).text("reason", "the stop file exists").build());
        return m;
    }

    static Map<String, Object> with(Map<String, Object> block, String name, Object value) {
        Map<String, Object> changed = new LinkedHashMap<>(block);
        changed.put(name, value);
        return changed;
    }

    static LabProtocol.Builder of(Type type) { return Message.of(type, REQUEST, MANIFEST); }

    /** One fixed message of every type, the same values as the Python suite's. */
    static Map<String, Message> goldens() {
        Map<String, Message> m = new LinkedHashMap<>();
        m.put("HELLO", of(Type.HELLO).id("installation", "00112233445566778899aabbccddeeff").id("coordinator", "c0".repeat(16))
                .id("config", "3c".repeat(32)).text("component", "com.android.systemui").id("trust", "7a".repeat(32))
                .number("route", 1).build());
        m.put("HELLO_REPLY", of(Type.HELLO_REPLY).number("status", 1).number("generation", 3).number("target", 1)
                .text("reason", "").build());
        m.put("CLOCK", of(Type.CLOCK).build());
        m.put("CLOCK_REPLY", of(Type.CLOCK_REPLY).number("status", 1).id("boot", BOOT).number("instance", 4021)
                .number("elapsed", 812345).number("wall", 1791504812345L).number("group", 17).text("reason", "").build());
        m.put("OBSERVE", of(Type.OBSERVE).number("scope", 2).text("component", "com.android.systemui").id("boot", BOOT)
                .id("ticket", "04".repeat(16)).id("plan", "01".repeat(16)).number("state", 7).build());
        m.put("OBSERVE_REPLY", of(Type.OBSERVE_REPLY).number("status", 1)
                .frames("frames", Arrays.asList(new Frame(18, new byte[] {1, 2}), new Frame(19, new byte[] {3})))
                .text("reason", "").build());
        m.put("CROSS", cross().build());
        m.put("CROSS_REPLY", of(Type.CROSS_REPLY).number("status", 1).number("record", 42)
                .bytes("frame", "reply-record".getBytes(StandardCharsets.US_ASCII)).text("reason", "").build());
        m.put("POINT", of(Type.POINT).text("point", "selection-written").id("ticket", "04".repeat(16))
                .id("plan", "01".repeat(16)).number("attempt", 2).build());
        m.put("POINT_REPLY", of(Type.POINT_REPLY).number("status", 4).number("record", 43)
                .text("reason", "admitted fault cell").build());
        m.put("HOST", of(Type.HOST).number("phase", 2).number("crossing", 1).id("ticket", "04".repeat(16))
                .id("plan", "01".repeat(16)).number("attempt", 2).number("index", 0).number("occurrence", 1)
                .id("reference", "9b".repeat(16)).number("outcome", 1).id("reply", "ab".repeat(32)).build());
        m.put("HOST_REPLY", of(Type.HOST_REPLY).number("status", 5).number("record", 44)
                .text("reason", "admitted dropped host reply").build());
        m.put("REPORT", of(Type.REPORT).id("ticket", "04".repeat(16)).number("state", 24).number("flags", 0)
                .number("cause", 0).codes("ledger", Arrays.asList(1, 2, 3, 6)).text("note", "settle").build());
        m.put("REPORT_REPLY", of(Type.REPORT_REPLY).number("status", 1).number("record", 45).text("reason", "").build());
        return m;
    }

    static LabProtocol.Builder cross() {
        return of(Type.CROSS).id("ticket", "04".repeat(16)).id("ticket_digest", "11".repeat(32)).id("plan", "01".repeat(16))
                .id("plan_digest", "22".repeat(32)).number("attempt", 2).text("component", "com.android.systemui")
                .number("index", 4).number("crossing", 5).number("occurrence", 1).id("entry_boot", BOOT)
                .number("entry_instance", 4021).number("entry_elapsed", 812000).id("grant", "2a".repeat(16))
                .id("reference", LabProtocol.ZERO_ID).ref("native", BOUND).id("bundle_apk", LabProtocol.ZERO_DIGEST)
                .number("actor", 2).number("granted", 1791504000000L).number("window", 3600000);
    }

    static boolean refused(Runnable action) {
        try {
            action.run();
            return false;
        } catch (ProtocolError expected) {
            return true;
        }
    }

    static byte[] reframe(byte[] data, UnaryOperator<byte[]> body) {
        byte[] changed = body.apply(Arrays.copyOfRange(data, LabProtocol.HEADER, data.length - LabProtocol.CHECKSUM));
        byte[] out = new byte[LabProtocol.HEADER + changed.length + LabProtocol.CHECKSUM];
        System.arraycopy(data, 0, out, 0, LabProtocol.HEADER);
        System.arraycopy(changed, 0, out, LabProtocol.HEADER, changed.length);
        ByteBuffer.wrap(out, 8, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(out.length);
        byte[] sum = LabProtocol.sha256(Arrays.copyOf(out, out.length - LabProtocol.CHECKSUM));
        System.arraycopy(sum, 0, out, out.length - LabProtocol.CHECKSUM, LabProtocol.CHECKSUM);
        return out;
    }

    public static void main(String[] args) throws Exception {
        LabCases cases = new LabCases();
        Path pythonGoldens = args.length > 0 ? Paths.get(args[0]) : null;

        cases.run("protocol / every golden is the Python codec's", problems -> {
            Map<String, Message> all = new LinkedHashMap<>(goldens());
            all.putAll(goldens2());
            for (Map.Entry<String, Message> e : all.entrySet()) {
                byte[] data = LabProtocol.encode(e.getValue());
                LabCases.check(problems, LabProtocol.sha256Hex(data).equals(GOLDENS.get(e.getKey())),
                        e.getKey() + " differs from the pinned golden");
                if (pythonGoldens != null) {
                    byte[] theirs = Files.readAllBytes(pythonGoldens.resolve(e.getKey() + ".bin"));
                    LabCases.check(problems, Arrays.equals(data, theirs), e.getKey() + " differs from the Python bytes");
                }
            }
        });

        cases.run("protocol / every type has one encoding", problems -> {
            for (Map.Entry<String, Message> e : goldens().entrySet()) {
                byte[] data = LabProtocol.encode(e.getValue());
                Message decoded = LabProtocol.decode(data);
                LabCases.check(problems, Arrays.equals(LabProtocol.encode(decoded), data), e.getKey());
                LabCases.check(problems, decoded.equals(e.getValue()), e.getKey() + " decodes to another message");
            }
        });

        cases.run("protocol / the frame is checked first", problems -> {
            byte[] data = LabProtocol.encode(goldens().get("CROSS"));
            Map<String, byte[]> bad = new LinkedHashMap<>();
            bad.put("short", Arrays.copyOf(data, LabProtocol.MIN_FRAME - 1));
            byte[] magic = data.clone();
            magic[3] = 'C';
            bad.put("magic", magic);
            byte[] version = data.clone();
            version[4] = 2;
            bad.put("version", version);
            byte[] type = data.clone();
            type[6] = 99;
            bad.put("type", type);
            byte[] length = data.clone();
            length[8]++;
            bad.put("length", length);
            byte[] checksum = data.clone();
            checksum[checksum.length - 1] ^= 1;
            bad.put("checksum", checksum);
            bad.put("trailing", reframe(data, body -> Arrays.copyOf(body, body.length + 1)));
            bad.put("cut", reframe(data, body -> Arrays.copyOf(body, body.length - 1)));
            byte[] zero = data.clone();
            Arrays.fill(zero, 12, 28, (byte) 0);
            bad.put("zero request", reframe(zero, body -> body));
            for (Map.Entry<String, byte[]> e : bad.entrySet()) {
                LabCases.check(problems, refused(() -> LabProtocol.decode(e.getValue())), e.getKey() + " was decoded");
            }
        });

        cases.run("protocol / cross relations", problems -> {
            List<UnaryOperator<LabProtocol.Builder>> bad = Arrays.asList(
                    b -> b.number("crossing", 1),
                    b -> b.number("crossing", 9),
                    b -> b.id("grant", LabProtocol.ZERO_ID).number("actor", 0),
                    b -> b.number("actor", 0),
                    b -> b.id("bundle_apk", "a1".repeat(32)),
                    b -> b.ref("native", new Ref(1, 1189842383, 0, "", 0, LabProtocol.ZERO_ID)),
                    b -> b.ref("native", new Ref(15, 1189842383, 1791504012345L, "/data/app-staging/session_1189842383",
                            2000, LabProtocol.ZERO_ID)),
                    b -> b.number("entry_instance", -1),
                    b -> b.number("occurrence", 2),
                    b -> b.number("index", 140),
                    b -> b.number("granted", 0),
                    b -> b.number("window", 0),
                    b -> b.number("granted", -1),
                    b -> b.number("crossing", 3).id("reference", NONCE).number("granted", 0).number("window", 0)
                            .ref("native", new Ref(16, 0, 0, "", 0, "77".repeat(16))),
                    b -> b.number("crossing", 3).id("reference", NONCE).number("granted", 0).number("window", 0),
                    // CREATE is under a STAGE grant, which carries no activation window.
                    b -> b.number("crossing", 3).id("reference", NONCE).ref("native", new Ref(16, 0, 0, "", 0, NONCE)));
            int i = 0;
            for (UnaryOperator<LabProtocol.Builder> change : bad) {
                int at = i++;
                LabCases.check(problems, refused(() -> change.apply(cross()).build()), "relation " + at + " accepted");
            }
            Message create = cross().number("crossing", 3).id("reference", NONCE).ref("native", new Ref(16, 0, 0, "", 0, NONCE))
                    .number("granted", 0).number("window", 0).build();
            LabCases.check(problems, LabProtocol.decode(LabProtocol.encode(create)).number("crossing") == 3, "CREATE");
        });

        cases.run("protocol / reply relations", problems -> {
            Map<String, Runnable> bad = new LinkedHashMap<>();
            bad.put("a clock without its boot", () -> of(Type.CLOCK_REPLY).number("status", 1).id("boot", LabProtocol.ZERO_ID)
                    .number("instance", 1).number("elapsed", 1).number("wall", 1).number("group", 1).text("reason", "")
                    .build());
            bad.put("an ok reply with a reason", () -> of(Type.HELLO_REPLY).number("status", 1).number("generation", 1)
                    .number("target", 1).text("reason", "x").build());
            bad.put("a cross reply ok without a frame", () -> of(Type.CROSS_REPLY).number("status", 1).number("record", 1)
                    .bytes("frame", new byte[0]).text("reason", "").build());
            bad.put("a withheld reply without its record", () -> of(Type.CROSS_REPLY).number("status", 5)
                    .number("record", 0).bytes("frame", new byte[0]).text("reason", "x").build());
            bad.put("a point halt without its record", () -> of(Type.POINT_REPLY).number("status", 4).number("record", 0)
                    .text("reason", "x").build());
            bad.put("a hello unavailable", () -> of(Type.HELLO_REPLY).number("status", 2).number("generation", 0)
                    .number("target", 0).text("reason", "x").build());
            for (Map.Entry<String, Runnable> e : bad.entrySet()) {
                LabCases.check(problems, refused(e.getValue()), e.getKey() + " accepted");
            }
            Message refusedClock = of(Type.CLOCK_REPLY).number("status", 7).zeros().text("reason", "HELLO first").build();
            LabCases.check(problems, LabProtocol.decode(LabProtocol.encode(refusedClock)).number("status") == 7,
                    "a refused clock");
        });

        cases.run("protocol / the record codes are the canonical encoding's", problems -> {
            String component = "com.android.systemui";
            int stateAt = 12 + 16 + 16 + 2 + component.length() + 16 + 4 + 1 + 16;
            Ticket.Builder base = new Ticket.Builder().installation(LabFixtures.INSTALLATION).ticketId(LabFixtures.id(9))
                    .component(component).planId(LabFixtures.id(8)).attempt(1)
                    .coordinator(CoordinatorClass.HOST, LabFixtures.COORDINATOR);
            Ticket planned = base.build();
            Ticket cancelled = planned.toBuilder().state(State.CANCELLED).cause(Cause.CANCELLED).build();
            Ticket signing = planned.toBuilder().state(State.SIGNING).append(new Entry(Crossing.SIGN,
                    DeploymentRecords.NO_ID, -1, 0, LabFixtures.id(7), LabFixtures.id(6), 0)).build();
            for (Ticket t : Arrays.asList(planned, cancelled, signing)) {
                byte[] data = DeploymentRecords.encodeTicket(t);
                LabCases.check(problems, (data[stateAt] & 0xff) == RecordCodes.state(t.state), t.state + " code");
                LabCases.check(problems, (data[stateAt + 2] & 0xff) == RecordCodes.cause(t.cause), t.cause + " code");
            }
            byte[] data = DeploymentRecords.encodeTicket(signing);
            int ledgerAt = data.length - 32 - (1 + 16 + 8 + 8 + 16 + 16 + 8);
            LabCases.check(problems, (data[ledgerAt] & 0xff) == RecordCodes.crossing(Crossing.SIGN), "SIGN code");
            LabCases.check(problems, RecordCodes.crossing(Crossing.CREATE) == 3 && RecordCodes.crossing(Crossing.NOTICE) == 8
                    && RecordCodes.state(State.SUPERSEDED) == 28 && RecordCodes.cause(Cause.OTHER_BYTES) == 6,
                    "the documented ends of each table");
        });

        cases.run("protocol / version 2 has one encoding, and a channel speaks one version", problems -> {
            for (Map.Entry<String, Message> e : goldens2().entrySet()) {
                byte[] data = LabProtocol.encode(e.getValue());
                Message decoded = LabProtocol.decode(data, 2);
                LabCases.check(problems, Arrays.equals(LabProtocol.encode(decoded), data) && decoded.equals(e.getValue()),
                        e.getKey());
                LabCases.check(problems, refused(() -> LabProtocol.decode(data)), e.getKey() + " read on a version 1 channel");
            }
            byte[] one = LabProtocol.encode(goldens().get("HELLO"));
            LabCases.check(problems, refused(() -> LabProtocol.decode(one, 2)), "a version 1 frame on a version 2 channel");
            byte[] three = one.clone();
            three[4] = 3;
            LabCases.check(problems, refused(() -> LabProtocol.frameLength(three)), "protocol version 3");
            LabCases.check(problems, LabProtocol.blockSize(2) == 218 && LabProtocol.blockSize(3) == 479, "block sizes");
            boolean noFrames;
            try {
                of2(Type.OBSERVE_REPLY).frames("frames", Collections.emptyList());
                noFrames = false;
            } catch (IllegalArgumentException expected) {
                noFrames = true;
            }
            LabCases.check(problems, noFrames, "version 2's OBSERVE reply took frames");
        });

        cases.run("protocol / version 2 envelope relations", problems -> {
            byte[] goodReceipt = receiptRecord(500, Classification.RECEIPT_FULL_SCREEN, 3);
            byte[] goodHealth = healthRecord(Classification.HEALTH_HELD, 127, 95000);
            Map<String, Envelope> bad = new LinkedHashMap<>();
            bad.put("a simple block", new Envelope(18, 1, "33".repeat(32), receiptBlock(), checkpoint("6f".repeat(16))));
            bad.put("a simple receipt", new Envelope(21, 1, "44".repeat(32), Collections.emptyMap(), goodReceipt));
            bad.put("a simple health fact", new Envelope(22, 1, "99".repeat(32), Collections.emptyMap(), goodHealth));
            bad.put("evidence that is not the raw digest", new Envelope(18, 1, "34".repeat(32), Collections.emptyMap(),
                    checkpoint("6f".repeat(16))));
            bad.put("an unknown mode", new Envelope(18, 4, "33".repeat(32), Collections.emptyMap(), checkpoint("6f".repeat(16))));
            bad.put("an event before its delivery group", receipt(with(receiptBlock(), "proven_elapsed", 399L), goodReceipt));
            bad.put("a delivery that ends after the read", receipt(with(receiptBlock(), "delivery_end", 1201L), goodReceipt));
            bad.put("a delivery in a later framework", receipt(with(receiptBlock(), "delivery_instance", 4022L), goodReceipt));
            bad.put("a read without a running framework", receipt(with(receiptBlock(), "read_instance", -1L), goodReceipt));
            bad.put("a zero event", receipt(with(receiptBlock(), "event", LabProtocol.ZERO_ID), goodReceipt));
            bad.put("a zero delivery group", receipt(with(receiptBlock(), "delivery_group", LabProtocol.ZERO_DIGEST),
                    goodReceipt));
            bad.put("a read time substituted for the event", receipt(receiptBlock(),
                    receiptRecord(1200, Classification.RECEIPT_FULL_SCREEN, 3)));
            bad.put("a SystemUI receipt", receipt(receiptBlock(), receiptRecord(500, Classification.RECEIPT_SYSTEMUI, 3)));
            bad.put("a receipt of another notice", receipt(receiptBlock(),
                    receiptRecord(500, Classification.RECEIPT_FULL_SCREEN, 4)));
            bad.put("a receipt of another boot", receipt(with(receiptBlock(), "read_boot", "2f".repeat(16)), goodReceipt));
            bad.put("a partial HELD", health(with(healthBlock(), "rows", rows(1, 1, 1, 3, 1, 1, 1)), goodHealth));
            bad.put("a DEGRADED of all HELD rows", health(healthBlock(), healthRecord(Classification.HEALTH_DEGRADED, 127, 95000)));
            bad.put("a CRASH without its witnessed row", health(with(healthBlock(), "rows", rows(1, 1, 1, 1, 2, 1, 1)),
                    healthRecord(Classification.HEALTH_CRASH, 127, 95000)));
            bad.put("a mask of fewer criteria", health(with(healthBlock(), "criteria", 63L), goodHealth));
            bad.put("a probe before its window", health(with(healthBlock(), "probe_begin", 89999L), goodHealth));
            bad.put("a probe not completed by its read", health(with(healthBlock(), "probe_end", 94999L), goodHealth));
            bad.put("a zero baseline", health(with(healthBlock(), "baseline", LabProtocol.ZERO_DIGEST), goodHealth));
            bad.put("a health fact of fewer criteria", health(healthBlock(), healthRecord(Classification.HEALTH_HELD, 63, 95000)));
            bad.put("a health fact not at its probe end", health(healthBlock(), healthRecord(Classification.HEALTH_HELD, 127,
                    94000)));
            for (Map.Entry<String, Envelope> e : bad.entrySet()) {
                LabCases.check(problems, refused(() -> reply2(Collections.singletonList(e.getValue())).build()),
                        e.getKey() + " accepted");
            }
            LabCases.check(problems, refused(() -> reply2(Arrays.asList(simple("6f".repeat(16)), simple("6f".repeat(16))))
                    .build()), "one observation ID twice");
            LabCases.check(problems, refused(() -> of2(Type.OBSERVE_REPLY).number("status", 4).number("control_record", 0)
                    .envelopes("envelopes", Collections.emptyList()).text("reason", "halt").build()), "a halt without its record");
            LabCases.check(problems, refused(() -> reply2(Collections.singletonList(simple("6f".repeat(16))))
                    .number("control_record", 46).build()), "a control record with OK");
            LabCases.check(problems, refused(() -> of2(Type.OBSERVE_REPLY).number("status", 5).number("control_record", 0)
                    .envelopes("envelopes", Collections.emptyList()).text("reason", "withheld").build()), "a withheld observation");
            // Each mapping of rows to a classification that the relation does allow.
            reply2(Collections.singletonList(health(with(healthBlock(), "rows", rows(1, 2, 3, 3, 3, 3, 3)),
                    healthRecord(Classification.HEALTH_CRASH, 127, 95000)))).build();
            reply2(Collections.singletonList(health(with(healthBlock(), "rows", rows(1, 1, 2, 3, 1, 1, 1)),
                    healthRecord(Classification.HEALTH_DEGRADED, 127, 95000)))).build();
            reply2(Collections.singletonList(health(with(healthBlock(), "rows", rows(1, 1, 1, 3, 1, 1, 1)),
                    healthRecord(Classification.HEALTH_INCONCLUSIVE, 127, 95000)))).build();
            byte[] data = LabProtocol.encode(goldens2().get("V2_OBSERVE_REPLY_RECEIPT"));
            int at = LabProtocol.HEADER + 1 + 4 + 2 + 4 + 1 + 32;
            LabCases.check(problems, refused(() -> LabProtocol.decode(reframe(data, body -> {
                byte[] changed = body.clone();
                changed[at - LabProtocol.HEADER] = (byte) 219;
                return changed;
            }), 2)), "a block of another length");
        });

        cases.run("protocol / the health classification follows the rows", problems -> {
            int[][] rows = {{1, 1, 1, 1, 1, 1, 1}, {1, 2, 1, 1, 1, 1, 1}, {3, 2, 3, 3, 3, 3, 3}, {2, 1, 1, 1, 1, 1, 1},
                    {1, 1, 1, 1, 1, 3, 2}, {1, 3, 1, 1, 1, 1, 1}, {3, 3, 3, 3, 3, 3, 3}};
            int[] expected = {1, 3, 3, 2, 2, 4, 4};
            for (int i = 0; i < rows.length; i++) {
                List<Integer> statuses = new ArrayList<>();
                for (int s : rows[i]) statuses.add(s);
                LabCases.check(problems, LabProtocol.healthClassification(statuses) == expected[i], "rows " + i);
            }
            LabCases.check(problems, refused(() -> LabProtocol.healthClassification(Arrays.asList(1, 1, 1, 1, 1, 1))),
                    "six rows");
            LabCases.check(problems, refused(() -> LabProtocol.healthClassification(Arrays.asList(1, 1, 1, 1, 1, 1, 0))),
                    "a row of no known status");
        });

        cases.finish("Lab bridge protocol checks passed");
    }
}
