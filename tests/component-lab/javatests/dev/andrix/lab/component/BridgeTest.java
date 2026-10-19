// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

import dev.andrix.lab.component.BridgeErrors.BridgeRefusal;
import dev.andrix.lab.component.BridgeErrors.GenerationStopped;
import dev.andrix.lab.component.BrokerChannel.ChannelLost;
import dev.andrix.lab.component.LabProtocol.Envelope;
import dev.andrix.lab.component.LabProtocol.Frame;
import dev.andrix.lab.component.LabProtocol.Message;
import dev.andrix.lab.component.LabProtocol.Row;
import dev.andrix.lab.component.LabProtocol.Status;
import dev.andrix.lab.component.LabProtocol.Type;
import dev.andrix.server.deployment.Coordinator;
import dev.andrix.server.deployment.DeploymentRecords;
import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.Classification;
import dev.andrix.server.deployment.DeploymentRecords.Crossing;
import dev.andrix.server.deployment.DeploymentRecords.Entry;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Reference;
import dev.andrix.server.deployment.DeploymentRecords.Route;
import dev.andrix.server.deployment.DeploymentRecords.State;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import dev.andrix.server.deployment.DeploymentStore;
import dev.andrix.server.deployment.Reconciler.Clock;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * The Java bridge against an in process broker stand in: the channel's pairing rules, the shell
 * device's clock, strict frame checks and crossing rules, the host fault wrapper, the lab point, the
 * device route's refusal of lab points, reopening from the store alone, and the process entry's exit
 * statuses. The accepted coordinator runs unchanged. Host JVM only.
 */
public final class BridgeTest {
    static final String MANIFEST = "ad".repeat(32);
    static final String BUNDLE_APK = "a1".repeat(32), RESTORATION_APK = "a2".repeat(32);
    static final long WINDOW = 120_000;

    /** A simulated halt: it unwinds the generation as a process exit would end it. */
    static final class Halted extends Error {
        private static final long serialVersionUID = 1L;
        final int status;

        Halted(int status) {
            super("halted " + status);
            this.status = status;
        }
    }

    /** A store, its plan and ticket, the bridge's configuration and a broker stand in. */
    static final class Rig {
        final Path dir;
        final DeploymentStore store;
        final Plan plan;
        final Ticket ticket;
        final LabConfig config;
        final FakeBroker broker = new FakeBroker(MANIFEST);
        final List<Integer> halts = new ArrayList<>();
        final Halter halter = status -> {
            halts.add(status);
            throw new Halted(status);
        };

        Rig(Path base, String name) throws IOException {
            this(base, name, false);
        }

        /** With `next`, the next campaign profile's version 3 configuration and protocol 2. */
        Rig(Path base, String name, boolean next) throws IOException {
            dir = Files.createDirectories(base.resolve(name));
            store = new DeploymentStore(dir.resolve("store"), LabFixtures.INSTALLATION);
            plan = LabFixtures.plan(LabFixtures.id(0x101), WINDOW);
            ticket = LabFixtures.install(store, plan, LabFixtures.id(0x401), LabFixtures.TIME);
            config = LabConfig.read(next ? LabFixtures.config3(dir, dir.resolve("store"), MANIFEST)
                    : LabFixtures.config(dir, dir.resolve("store"), MANIFEST));
            broker.expectedConfig = config.digest;
            if (next) broker.version = LabProtocol.VERSION_2;
        }

        LabBridge.HostFactory hosts() {
            return (s, c) -> new ScriptedHost(dir.resolve("host"), BUNDLE_APK, RESTORATION_APK);
        }

        LabBridge open() throws IOException {
            return LabBridge.open(config, broker, hosts(), halter, new SecureRandom());
        }

        Ticket stored() { return store.ticket(ticket.ticketId).value; }
    }

    static boolean throwsType(Class<? extends Throwable> type, Runnable action) {
        try {
            action.run();
            return false;
        } catch (Throwable thrown) {
            return type.isInstance(thrown);
        }
    }

    // Answers a CROSS for CREATE with a whole shell reference, and makes the world show the session.
    static Function<Message, LabProtocol.Builder> createSucceeds(FakeBroker broker) {
        return request -> {
            if (request.number("crossing") != 3) {
                return broker.status(request, Status.NO_REPLY, "scripted").number("record", 1);
            }
            String nonce = request.ref("native").nonce;
            Reference session = new Reference(31, 1189842383, LabFixtures.TIME + 31_000,
                    "/data/app-staging/session_1189842383", 2000, nonce);
            broker.session = session;
            return broker.reply(request).number("status", 1).number("record", 7)
                    .bytes("frame", broker.replyFrame(request, Classification.REPLY_SUCCESS, session)).text("reason", "");
        };
    }

    // ---------------------------------------------------------------- the next campaign profile

    static final String PUBLICATION = "a3".repeat(32);

    // A receipt of user 10 for the ticket's notice at an index, proven at an elapsed time, read
    // from a begin time in the broker's framework instance.
    static Envelope receiptEnvelope(FakeBroker b, String ticket, String plan, int index, long proven, long readBegin,
            long instance) {
        Map<String, Object> block = new LinkedHashMap<>();
        block.put("read_boot", b.boot);
        block.put("read_instance", instance);
        block.put("read_begin_elapsed", readBegin);
        block.put("read_end_elapsed", readBegin + 50);
        block.put("plan", plan);
        block.put("ticket", ticket);
        block.put("notice_index", (long) index);
        block.put("issue_ticket_digest", "55".repeat(32));
        block.put("event", "66".repeat(16));
        block.put("row", "77".repeat(32));
        block.put("delivery_group", "88".repeat(32));
        block.put("delivery_instance", instance);
        block.put("delivery_begin", proven - 10);
        block.put("proven_elapsed", proven);
        block.put("delivery_end", proven);
        Observation o = new Observation.Builder().installation(LabFixtures.INSTALLATION).observationId(b.nextId())
                .component(LabFixtures.COMPONENT).boot(b.boot).user(10, 5).route(Route.SHELL)
                .at(instance, proven, LabFixtures.TIME + proven).raw("44".repeat(32))
                .classification(Classification.RECEIPT_FULL_SCREEN).receipt(ticket, index).build();
        return new Envelope(31, LabProtocol.RECEIPT_EVENT, o.raw, block, DeploymentRecords.encodeObservation(o));
    }

    // A HELD full probe of one user for a ticket's window, read over [readBegin, end].
    static Envelope healthEnvelope(FakeBroker b, String ticket, String plan, long start, long readBegin, long end,
            int user, String apk, String publication) {
        Map<String, Object> block = new LinkedHashMap<>();
        block.put("read_boot", b.boot);
        block.put("read_instance", b.instance);
        block.put("read_begin_elapsed", readBegin);
        block.put("read_end_elapsed", end);
        block.put("plan", plan);
        block.put("ticket", ticket);
        block.put("window_boot", b.boot);
        block.put("window_start", start);
        block.put("publication", publication);
        block.put("active_apk", apk);
        block.put("baseline", "b4".repeat(32));
        block.put("preparation_root", "c5".repeat(32));
        block.put("probe_begin", start);
        block.put("probe_end", end);
        block.put("criteria", 127L);
        List<Row> rows = new ArrayList<>();
        for (int bit = 0; bit < 7; bit++) rows.add(new Row(bit, LabProtocol.HELD, ("d" + bit).repeat(32)));
        block.put("rows", rows);
        Observation o = new Observation.Builder().installation(LabFixtures.INSTALLATION).observationId(b.nextId())
                .component(LabFixtures.COMPONENT).boot(b.boot).user(user, user == 0 ? 0 : 5).route(Route.SHELL)
                .at(b.instance, end, LabFixtures.TIME + end).raw("99".repeat(32))
                .classification(Classification.HEALTH_HELD).number(127).build();
        return new Envelope(32, LabProtocol.COMPOSED_HEALTH, o.raw, block, DeploymentRecords.encodeObservation(o));
    }

    // The broker stand in answers OBSERVE with its world as simple envelopes, then the given ones.
    static void observeWith(FakeBroker b, List<Envelope> extra) {
        b.scripts.put(Type.OBSERVE, r -> {
            List<Envelope> envelopes = new ArrayList<>(b.simple(b.world(r.number("scope") == LabProtocol.SCOPE_TICKET)));
            envelopes.addAll(extra);
            return b.reply(r).number("status", 1).number("control_record", 0).envelopes("envelopes", envelopes)
                    .text("reason", "");
        });
    }

    // The store's read of the plan's publication, as the host records it after PUBLISH.
    static void published(Rig rig) {
        rig.store.addObservation(new Observation.Builder().installation(LabFixtures.INSTALLATION)
                .observationId(LabFixtures.id(0x9b0)).component(LabFixtures.COMPONENT).boot(DeploymentRecords.NO_ID)
                .route(Route.HOST).at(-1, 0, 0).raw("9c".repeat(32)).classification(Classification.BUNDLE_PUBLISHED)
                .subject(LabFixtures.id(0x9b1)).plan(rig.plan.planId).digest(PUBLICATION)
                .apks(BUNDLE_APK, RESTORATION_APK).build());
    }

    public static void main(String[] args) throws Exception {
        Path base = Files.createTempDirectory(Paths.get(args.length > 0 ? args[0] : System.getProperty("java.io.tmpdir")),
                "bridge");
        LabCases cases = new LabCases();

        cases.run("config / one exact encoding, every line checked", problems -> {
            byte[] good = LabConfig.encode(LabFixtures.INSTALLATION, LabFixtures.COMPONENT, LabFixtures.COORDINATOR,
                    LabFixtures.TRUST, MANIFEST, Paths.get("/lab/store"));
            LabConfig config = LabConfig.parse(good);
            LabCases.check(problems, config.digest.equals(LabProtocol.sha256Hex(good)), "the digest is the bytes'");
            String text = new String(good, java.nio.charset.StandardCharsets.US_ASCII);
            List<String> bad = Arrays.asList(text.substring(0, text.length() - 1), text + "extra 1\n",
                    text.replace("installation 0011", "installation 00AA"), text.replace("store /lab/store", "store lab"),
                    text.replace("store /lab/store", "store /lab/../store"), text.replace("trust ", "trust  "),
                    text.replace("component com.android.systemui\ncoordinator", "coordinator"),
                    text.replace("andrix-lab-bridge 1", "andrix-lab-bridge 2"));
            for (String b : bad) {
                LabCases.check(problems, throwsType(IllegalArgumentException.class,
                        () -> LabConfig.parse(b.getBytes(java.nio.charset.StandardCharsets.US_ASCII))),
                        "a configuration of another form was read");
            }
        });

        cases.run("config / version 2 names the host configuration's digest, every line checked", problems -> {
            String host = "5e".repeat(32);
            byte[] good = LabConfig.encode(LabFixtures.INSTALLATION, LabFixtures.COMPONENT, LabFixtures.COORDINATOR,
                    LabFixtures.TRUST, MANIFEST, Paths.get("/lab/store"), host);
            LabConfig config = LabConfig.parse(good);
            LabCases.check(problems, host.equals(config.host) && config.digest.equals(LabProtocol.sha256Hex(good)),
                    "the host digest and the file's digest");
            byte[] first = LabConfig.encode(LabFixtures.INSTALLATION, LabFixtures.COMPONENT, LabFixtures.COORDINATOR,
                    LabFixtures.TRUST, MANIFEST, Paths.get("/lab/store"));
            LabCases.check(problems, LabConfig.parse(first).host == null, "version 1 names no host");
            String text = new String(good, java.nio.charset.StandardCharsets.US_ASCII);
            List<String> bad = Arrays.asList(text.replace("\nhost " + host, ""), text.replace("host " + host, "host " + host.toUpperCase()),
                    text.replace("host " + host, "host " + host.substring(2)), text.replace("host " + host, "host " + "00".repeat(32)),
                    text.replace("andrix-lab-bridge 2", "andrix-lab-bridge 1"), text + "extra 1\n",
                    text.replace("store /lab/store\nhost " + host, "host " + host + "\nstore /lab/store"));
            for (String b : bad) {
                LabCases.check(problems, throwsType(IllegalArgumentException.class,
                        () -> LabConfig.parse(b.getBytes(java.nio.charset.StandardCharsets.US_ASCII))),
                        "a version 2 configuration of another form was read");
            }
        });

        cases.run("channel / a reply must answer its request", problems -> {
            FakeBroker broker = new FakeBroker(MANIFEST);
            List<Function<Message, LabProtocol.Builder>> wrong = Arrays.asList(
                    request -> Message.of(Type.HELLO_REPLY, request.request, MANIFEST).number("status", 1)
                            .number("generation", 1).number("target", 1).text("reason", ""),
                    request -> Message.of(Type.CLOCK_REPLY, "77".repeat(16), MANIFEST).number("status", 2).zeros()
                            .text("reason", "x"),
                    request -> Message.of(Type.CLOCK_REPLY, request.request, "ae".repeat(32)).number("status", 2).zeros()
                            .text("reason", "x"));
            for (Function<Message, LabProtocol.Builder> answer : wrong) {
                broker.scripts.put(Type.CLOCK, answer);
                BrokerChannel channel = new BrokerChannel(broker, MANIFEST, new SecureRandom());
                LabCases.check(problems, throwsType(ChannelLost.class,
                        () -> channel.call(channel.request(Type.CLOCK).build())), "a reply to another request was taken");
                LabCases.check(problems, throwsType(ChannelLost.class,
                        () -> channel.call(channel.request(Type.CLOCK).build())), "a lost channel sent again");
            }
            BrokerChannel ended = new BrokerChannel(BrokerChannel.streams(new ByteArrayInputStream(new byte[5]),
                    new ByteArrayOutputStream()), MANIFEST, new SecureRandom());
            LabCases.check(problems, throwsType(ChannelLost.class, () -> ended.call(ended.request(Type.CLOCK).build())),
                    "a stream that ends inside a reply was read");
            BrokerChannel channel = new BrokerChannel(new FakeBroker(MANIFEST), MANIFEST, new SecureRandom());
            String a = channel.request(Type.CLOCK).build().request;
            String b = channel.request(Type.CLOCK).build().request;
            LabCases.check(problems, !a.equals(b) && !a.equals(LabProtocol.ZERO_ID), "request IDs are fresh");
        });

        cases.run("hello / binds the configuration, and a stopped broker ends the generation", problems -> {
            Rig rig = new Rig(base, "hello");
            LabBridge bridge = rig.open();
            Message hello = rig.broker.requests.get(0);
            LabCases.check(problems, hello.type == Type.HELLO && hello.id("config").equals(rig.config.digest)
                    && hello.id("trust").equals(LabFixtures.TRUST) && hello.id("coordinator").equals(LabFixtures.COORDINATOR)
                    && hello.text("component").equals(LabFixtures.COMPONENT) && hello.manifest.equals(MANIFEST),
                    "HELLO carries the configuration");
            LabCases.check(problems, bridge.generation() == 1, "the broker's generation");
            rig.broker.expectedConfig = "ff".repeat(32);
            LabCases.check(problems, throwsType(BridgeRefusal.class, () -> {
                try {
                    rig.open();
                } catch (IOException error) {
                    throw new RuntimeException(error);
                }
            }), "a refused HELLO opened a generation");
            rig.broker.scripts.put(Type.HELLO, request -> rig.broker.status(request, Status.STOPPED, "the stop file exists"));
            LabCases.check(problems, throwsType(GenerationStopped.class, () -> {
                try {
                    rig.open();
                } catch (IOException error) {
                    throw new RuntimeException(error);
                }
            }), "a stopped broker opened a generation");
        });

        cases.run("device / the route is the shell route and only it takes lab points", problems -> {
            Rig rig = new Rig(base, "route");
            LabBridge bridge = rig.open();
            LabCases.check(problems, bridge.device().route() == Route.SHELL, "the shell route");
            Coordinator.Device deviceRoute = new Coordinator.Device() {
                @Override public Route route() { return Route.DEVICE; }
                @Override public Clock clock() { return null; }
                @Override public List<Observation> observe(Ticket t, Plan p) { return Collections.emptyList(); }
                @Override public List<Observation> observe(String c) { return Collections.emptyList(); }
                @Override public Observation cross(Ticket t, Plan p, Entry e) { return null; }
            };
            Coordinator production = new Coordinator(rig.store, deviceRoute,
                    new ScriptedHost(rig.dir.resolve("host"), BUNDLE_APK, RESTORATION_APK), LabFixtures.TRUST,
                    () -> LabFixtures.id(77));
            LabCases.check(problems, !production.labPoints(point -> { }), "the device route took lab points");
            Coordinator shell = new Coordinator(rig.store, bridge.device(),
                    new ScriptedHost(rig.dir.resolve("host"), BUNDLE_APK, RESTORATION_APK), LabFixtures.TRUST,
                    () -> LabFixtures.id(78));
            LabCases.check(problems, shell.labPoints(point -> { }), "the shell route refused lab points");
        });

        cases.run("device / the clock is the broker's reading, and an unreachable device has none", problems -> {
            Rig rig = new Rig(base, "clock");
            LabBridge bridge = rig.open();
            Clock clock = bridge.device().clock();
            LabCases.check(problems, clock.boot.equals(rig.broker.boot) && clock.instance == rig.broker.instance
                    && clock.elapsed == rig.broker.elapsed && clock.wall == rig.broker.wall, "the reading");
            rig.broker.scripts.put(Type.CLOCK, r -> rig.broker.status(r, Status.UNAVAILABLE, "capture 3 did not complete"));
            LabCases.check(problems, bridge.device().clock() == null, "an unavailable clock gave a reading");
            LabCases.check(problems, throwsType(IllegalStateException.class,
                    () -> bridge.device().observe(LabFixtures.COMPONENT)), "an observation without a clock");
            rig.broker.scripts.put(Type.CLOCK, r -> rig.broker.status(r, Status.STOPPED, "the lease is not held"));
            LabCases.check(problems, throwsType(GenerationStopped.class, () -> bridge.device().clock()), "STOPPED");
            rig.broker.scripts.put(Type.CLOCK, r -> rig.broker.status(r, Status.REFUSED, "HELLO first"));
            LabCases.check(problems, throwsType(BridgeRefusal.class, () -> bridge.device().clock()), "REFUSED");
        });

        cases.run("device / frames are decoded strictly and checked against the round", problems -> {
            Rig rig = new Rig(base, "frames");
            LabBridge bridge = rig.open();
            ShellDevice device = bridge.device();
            FakeBroker broker = rig.broker;
            device.clock();
            List<Observation> facts = device.observe(rig.plan.component);
            LabCases.check(problems, facts.size() == 4, "the component's four facts");
            for (Observation o : facts) LabCases.check(problems, device.group(o.observationId) > 0, "a group per fact");
            List<Function<FakeBroker, byte[]>> bad = Arrays.asList(
                    b -> DeploymentRecords.encodeObservation(b.fact(Classification.CHECKPOINT_COMMITTED).route(Route.DEVICE).build()),
                    b -> DeploymentRecords.encodeObservation(b.fact(Classification.CHECKPOINT_COMMITTED)
                            .installation("99".repeat(16)).build()),
                    b -> DeploymentRecords.encodeObservation(b.fact(Classification.CHECKPOINT_COMMITTED)
                            .boot("ab".repeat(16)).build()),
                    b -> DeploymentRecords.encodeObservation(b.fact(Classification.HEALTH_HELD).component(LabFixtures.COMPONENT)
                            .user(0, 0).number(127).build()),
                    b -> DeploymentRecords.encodeObservation(b.fact(Classification.REPLY_SUCCESS).component(LabFixtures.COMPONENT)
                            .reply(rig.ticket.ticketId, 2, Crossing.ABANDON).at(1, 1, 1).build()),
                    b -> DeploymentRecords.encodeObservation(b.fact(Classification.RECEIPT_FULL_SCREEN)
                            .component(LabFixtures.COMPONENT).user(10, 11).receipt(LabFixtures.id(5), 3).build()),
                    b -> DeploymentRecords.encodeObservation(b.fact(Classification.NONE_FOR_PACKAGE)
                            .component("com.android.settings").at(4021, 1, 1).build()),
                    // A listing of an earlier framework than the round's clock, in the same boot.
                    b -> DeploymentRecords.encodeObservation(b.fact(Classification.NONE_FOR_PACKAGE)
                            .component(LabFixtures.COMPONENT).at(b.instance - 1, 1, 1).build()),
                    b -> {
                        byte[] data = DeploymentRecords.encodeObservation(b.fact(Classification.CHECKPOINT_COMMITTED).build());
                        data[data.length - 1] ^= 1;
                        return data;
                    },
                    b -> {
                        byte[] data = DeploymentRecords.encodeObservation(b.fact(Classification.CHECKPOINT_COMMITTED).build());
                        return Arrays.copyOf(data, data.length + 1);
                    });
            int at = 0;
            for (Function<FakeBroker, byte[]> frame : bad) {
                int index = at++;
                broker.scripts.put(Type.OBSERVE, r -> broker.reply(r).number("status", 1)
                        .frames("frames", Collections.singletonList(new Frame(9, frame.apply(broker)))).text("reason", ""));
                LabCases.check(problems, throwsType(BridgeRefusal.class, () -> device.observe(rig.stored(), rig.plan)),
                        "bad frame " + index + " was taken");
            }
            broker.scripts.put(Type.OBSERVE, r -> {
                byte[] once = DeploymentRecords.encodeObservation(broker.fact(Classification.CHECKPOINT_COMMITTED).build());
                return broker.reply(r).number("status", 1).frames("frames", Arrays.asList(new Frame(9, once), new Frame(10, once)))
                        .text("reason", "");
            });
            LabCases.check(problems, throwsType(BridgeRefusal.class, () -> device.observe(rig.stored(), rig.plan)),
                    "one observation ID twice");
            broker.scripts.put(Type.OBSERVE, r -> broker.reply(r).number("status", 1)
                    .frames("frames", Collections.singletonList(new Frame(9, DeploymentRecords.encodeObservation(
                            broker.fact(Classification.NONE_FOR_PACKAGE).component(LabFixtures.COMPONENT)
                                    .at(4021, 1, 1).build())))).text("reason", ""));
            LabCases.check(problems, throwsType(BridgeRefusal.class, () -> device.observe(LabFixtures.COMPONENT)),
                    "a listing in a component observation");
            LabCases.check(problems, device.observe(rig.stored(), rig.plan).size() == 1, "a listing for a ticket");
        });

        cases.run("cross / only the stored ticket's last entry is sent, with its exact fields", problems -> {
            Rig rig = new Rig(base, "cross");
            LabBridge bridge = rig.open();
            bridge.settle(rig.ticket.ticketId, 30);
            Ticket t = rig.stored();
            Message cross = rig.broker.last(Type.CROSS);
            LabCases.check(problems, t.state == State.SESSION_INTENT && t.flag(DeploymentRecords.FLAG_UNRESOLVED),
                    "the lost create left the intent unresolved: " + t.state);
            LabCases.check(problems, rig.broker.count(Type.CROSS) == 1 && rig.broker.count(Type.HOST) == 4,
                    "one CREATE, and SIGN and PUBLISH each begun and ended once");
            Entry create = t.last(Crossing.CREATE);
            Authorization stage = rig.store.authorizationsOf(rig.plan.planId).get(1);
            LabCases.check(problems, cross.id("ticket_digest").equals(LabProtocol.sha256Hex(
                    DeploymentRecords.encodeTicket(rig.store.ticket(t.ticketId).value.toBuilder()
                            .clear(DeploymentRecords.FLAG_UNRESOLVED).build()))), "the stored ticket's digest");
            LabCases.check(problems, cross.number("crossing") == 3 && cross.number("index") == 2
                    && cross.number("occurrence") == 1 && cross.id("reference").equals(create.reference)
                    && cross.ref("native").presence == LabProtocol.NONCE && cross.ref("native").nonce.equals(create.reference)
                    && cross.id("grant").equals(stage.authorizationId) && cross.number("actor") == 2
                    && cross.id("entry_boot").equals(rig.broker.boot) && cross.number("entry_instance") == rig.broker.instance
                    && cross.number("granted") == 0 && cross.number("window") == 0,
                    "the CREATE's fields, with no activation window under its STAGE grant");
            long sent = rig.broker.count(Type.CROSS);
            Ticket other = t.toBuilder().attempt(t.attempt + 1).build();
            LabCases.check(problems, throwsType(BridgeRefusal.class,
                    () -> bridge.device().cross(other, rig.plan, other.last(Crossing.CREATE))), "another ticket's bytes");
            LabCases.check(problems, throwsType(BridgeRefusal.class,
                    () -> bridge.device().cross(t, rig.plan, t.ledger.get(0))), "an entry that is not the last");
            Plan otherPlan = rig.plan.toBuilder().healthWindow(WINDOW + 1).build();
            LabCases.check(problems, throwsType(BridgeRefusal.class,
                    () -> bridge.device().cross(t, otherPlan, create)), "another plan's bytes");
            LabCases.check(problems, rig.broker.count(Type.CROSS) == sent, "a refused crossing was sent");
        });

        cases.run("cross / replies bind, lose or halt, and a session crossing names its whole reference", problems -> {
            Rig rig = new Rig(base, "replies");
            rig.broker.scripts.put(Type.CROSS, createSucceeds(rig.broker));
            LabBridge bridge = rig.open();
            bridge.settle(rig.ticket.ticketId, 30);
            Ticket t = rig.stored();
            LabCases.check(problems, t.state == State.SESSION_BOUND || t.state == State.ABANDON_INTENT,
                    "the reply bound the session: " + t.state);
            LabCases.check(problems, t.reference.sessionId == 1189842383 && t.reference.has(2) && t.reference.has(16),
                    "the bound reference");
            Message write = null;
            for (Message m : rig.broker.requests) if (m.type == Type.CROSS && m.number("crossing") == 4) write = m;
            LabCases.check(problems, write != null && write.ref("native").presence == 31 && write.number("index") == 3
                    && write.id("bundle_apk").equals(BUNDLE_APK) && write.id("grant").equals(LabProtocol.ZERO_ID),
                    "the WRITE names the whole reference and the bound APK");
            LabCases.check(problems, t.state != State.ABANDON_INTENT || t.last(Crossing.ABANDON) != null,
                    "an unanswered write abandons its exact session");

            Rig halting = new Rig(base, "halting");
            halting.broker.scripts.put(Type.CROSS, request -> request.number("crossing") == 3
                    ? createSucceeds(halting.broker).apply(request)
                    : halting.broker.status(request, Status.HALT, "admitted loss after the effect").number("record", 9));
            LabBridge halted = halting.open();
            LabCases.check(problems, throwsType(Halted.class, () -> halted.settle(halting.ticket.ticketId, 30)),
                    "a halt order did not end the generation");
            LabCases.check(problems, halting.halts.equals(Collections.singletonList(99)), "halted with 99 once");
            Ticket afterHalt = halting.stored();
            LabCases.check(problems, afterHalt.state == State.SESSION_BOUND && afterHalt.last(Crossing.WRITE) != null,
                    "the entry stayed synced and no reply was recorded: " + afterHalt.state);

            Rig withheld = new Rig(base, "withheld");
            withheld.broker.scripts.put(Type.CROSS, request -> withheld.broker.status(request, Status.WITHHELD,
                    "admitted dropped reply").number("record", 5));
            withheld.open().settle(withheld.ticket.ticketId, 30);
            LabCases.check(problems, withheld.stored().flag(DeploymentRecords.FLAG_UNRESOLVED), "a withheld reply is lost");

            Rig stopped = new Rig(base, "stopped");
            stopped.broker.scripts.put(Type.CROSS, request -> stopped.broker.status(request, Status.STOPPED,
                    "the stop file exists").number("record", 5));
            LabBridge stopping = stopped.open();
            LabCases.check(problems, throwsType(GenerationStopped.class, () -> stopping.settle(stopped.ticket.ticketId, 30)),
                    "STOPPED did not end the generation");
        });

        cases.run("cross / a reply to another crossing is refused", problems -> {
            Rig rig = new Rig(base, "wrongreply");
            rig.broker.scripts.put(Type.CROSS, request -> {
                Reference session = new Reference(31, 7, 5, "/data/app-staging/session_7", 2000, request.ref("native").nonce);
                byte[] frame = DeploymentRecords.encodeObservation(new Observation.Builder()
                        .installation(LabFixtures.INSTALLATION).observationId(rig.broker.nextId())
                        .component(LabFixtures.COMPONENT).boot(request.id("entry_boot")).route(Route.SHELL)
                        .raw("98".repeat(32)).classification(Classification.REPLY_SUCCESS)
                        .reply(request.id("ticket"), (int) request.number("index") + 1, Crossing.CREATE)
                        .reference(session).at(request.number("entry_instance"), 1, 1).build());
                return rig.broker.reply(request).number("status", 1).number("record", 3).bytes("frame", frame)
                        .text("reason", "");
            });
            LabBridge bridge = rig.open();
            LabCases.check(problems, throwsType(BridgeRefusal.class, () -> bridge.settle(rig.ticket.ticketId, 30)),
                    "a reply to another ledger index was taken");
            LabCases.check(problems, rig.stored().state == State.SESSION_INTENT, "no reply was recorded");
        });

        cases.run("host / BEGIN before the effect, END after, and the broker's cells decide", problems -> {
            Rig rig = new Rig(base, "host");
            Ticket signing = rig.ticket.toBuilder().state(State.SIGNING).append(new Entry(Crossing.SIGN,
                    DeploymentRecords.NO_ID, -1, 0, LabFixtures.id(0x201), LabFixtures.id(0x777), 0)).build();
            Entry sign = signing.last(Crossing.SIGN);
            List<String> calls = new ArrayList<>();
            boolean[] failing = {false};
            ScriptedHost scripted = new ScriptedHost(rig.dir.resolve("host"), BUNDLE_APK, RESTORATION_APK);
            Coordinator.Host counting = new Coordinator.Host() {
                @Override public Observation sign(Ticket t, Plan p, Entry e, Authorization g) {
                    calls.add("sign");
                    if (failing[0]) throw new IllegalStateException("signer failed");
                    return scripted.sign(t, p, e, g);
                }
                @Override public Observation publish(Ticket t, Plan p, Entry e) { calls.add("publish"); return null; }
                @Override public List<Observation> query(Ticket t, Plan p, List<Authorization> g) {
                    calls.add("query");
                    return Collections.emptyList();
                }
            };
            BrokerChannel channel = new BrokerChannel(rig.broker, MANIFEST, new SecureRandom());
            FaultHost host = new FaultHost(counting, channel, rig.halter, true);
            LabCases.check(problems, host.sign(signing, rig.plan, sign, null) != null, "a delivered reply");
            Message begin = rig.broker.requests.get(0), end = rig.broker.requests.get(1);
            LabCases.check(problems, begin.number("phase") == 1 && end.number("phase") == 2 && end.number("outcome") == 1
                    && begin.id("reference").equals(sign.reference) && begin.number("occurrence") == 1, "BEGIN, then END");
            rig.broker.scripts.put(Type.HOST, r -> r.number("phase") == 2
                    ? rig.broker.status(r, Status.WITHHELD, "admitted dropped host reply").number("record", 4)
                    : rig.broker.reply(r).number("status", 1).number("record", 3).text("reason", ""));
            LabCases.check(problems, host.sign(signing, rig.plan, sign, null) == null, "a withheld reply was delivered");
            rig.broker.scripts.put(Type.HOST, r -> r.number("phase") == 1
                    ? rig.broker.status(r, Status.HALT, "admitted loss before the host effect").number("record", 4)
                    : rig.broker.reply(r).number("status", 1).number("record", 3).text("reason", ""));
            int before = calls.size();
            LabCases.check(problems, throwsType(Halted.class, () -> host.sign(signing, rig.plan, sign, null)), "no halt");
            LabCases.check(problems, calls.size() == before, "the effect ran after a halt before it");
            rig.broker.scripts.remove(Type.HOST);
            failing[0] = true;
            LabCases.check(problems, throwsType(IllegalStateException.class, () -> host.sign(signing, rig.plan, sign, null)),
                    "a failing signer");
            Message threw = rig.broker.last(Type.HOST);
            LabCases.check(problems, threw.number("phase") == 2 && threw.number("outcome") == 3, "END THREW");
            FaultHost unfenced = new FaultHost(counting, channel, rig.halter, false);
            LabCases.check(problems, throwsType(BridgeRefusal.class,
                    () -> unfenced.query(signing, rig.plan, Collections.emptyList())), "an unfenced query");
            Entry another = new Entry(Crossing.SIGN, DeploymentRecords.NO_ID, -1, 0, LabFixtures.id(0x201),
                    LabFixtures.id(0x778), 0);
            LabCases.check(problems, throwsType(BridgeRefusal.class, () -> host.sign(signing, rig.plan, another, null)),
                    "a host call for another entry");
            host.query(signing, rig.plan, Collections.emptyList());
            LabCases.check(problems, calls.get(calls.size() - 1).equals("query"), "a fenced query is delegated");
        });

        cases.run("points / BETWEEN_WRITES asks the broker once and halts on its order", problems -> {
            Rig rig = new Rig(base, "points");
            LabBridge bridge = rig.open();
            bridge.prepare(rig.ticket.ticketId);
            bridge.point("another-point");
            LabCases.check(problems, rig.broker.count(Type.POINT) == 0, "another point asked the broker");
            bridge.point(Coordinator.BETWEEN_WRITES);
            Message point = rig.broker.last(Type.POINT);
            LabCases.check(problems, point != null && point.id("ticket").equals(rig.ticket.ticketId)
                    && point.id("plan").equals(rig.plan.planId) && point.number("attempt") == 1, "the point names its ticket");
            rig.broker.scripts.put(Type.POINT, r -> rig.broker.status(r, Status.HALT, "admitted fault cell").number("record", 6));
            LabCases.check(problems, throwsType(Halted.class, () -> bridge.point(Coordinator.BETWEEN_WRITES)), "no halt");
            LabCases.check(problems, rig.halts.equals(Collections.singletonList(99)), "halted with 99");
        });

        cases.run("bridge / each generation reads the store, and another store or target is refused", problems -> {
            Rig rig = new Rig(base, "reopen");
            rig.open().settle(rig.ticket.ticketId, 30);
            State first = rig.stored().state;
            FakeBroker again = new FakeBroker(MANIFEST);
            again.expectedConfig = rig.config.digest;
            LabBridge second = LabBridge.open(rig.config, again, rig.hosts(), rig.halter, new SecureRandom());
            second.settle(rig.ticket.ticketId, 30);
            LabCases.check(problems, first == State.SESSION_INTENT && rig.stored().state == State.SESSION_INTENT
                    && again.count(Type.CROSS) == 0 && again.count(Type.HOST) == 0,
                    "the second generation continued from the store without a replay");
            Path foreign = rig.dir.resolve("foreign.config");
            Files.write(foreign, LabConfig.encode("99".repeat(16), LabFixtures.COMPONENT, LabFixtures.COORDINATOR,
                    LabFixtures.TRUST, MANIFEST, rig.dir.resolve("store")));
            LabConfig other = LabConfig.read(foreign);
            FakeBroker third = new FakeBroker(MANIFEST);
            LabCases.check(problems, throwsType(BridgeRefusal.class, () -> {
                try {
                    LabBridge.open(other, third, rig.hosts(), rig.halter, new SecureRandom());
                } catch (IOException error) {
                    throw new RuntimeException(error);
                }
            }), "a store of another installation was opened");
            FakeBroker unknown = new FakeBroker(MANIFEST);
            unknown.target = LabProtocol.TARGET_UNKNOWN;
            LabBridge unsure = LabBridge.open(rig.config, unknown, rig.hosts(), rig.halter, new SecureRandom());
            LabCases.check(problems, throwsType(BridgeRefusal.class, () -> unsure.round(rig.ticket.ticketId)),
                    "a round without an established target scope");
            LabCases.check(problems, unknown.count(Type.CLOCK) == 0, "the refused round read the device");
            unsure.check();
            LabCases.check(problems, unknown.count(Type.OBSERVE) == 1, "the cohort check needs no target scope");
        });

        cases.run("bridge / the process entry's exit statuses", problems -> {
            Rig rig = new Rig(base, "exits");
            String config = rig.dir.resolve("bridge.config").toString();
            SecureRandom random = new SecureRandom();
            LabCases.check(problems, LabBridge.run(new String[] {config, "check"}, null, rig.broker, rig.halter, random) == 0,
                    "check");
            LabCases.check(problems, LabBridge.run(new String[] {config, "settle", rig.ticket.ticketId, "30"}, null,
                    rig.broker, rig.halter, random) == 64, "settle without a host");
            LabCases.check(problems, LabBridge.run(new String[] {config, "settle", rig.ticket.ticketId, "30"},
                    rig.hosts(), rig.broker, rig.halter, random) == 0, "settle");
            Message report = rig.broker.last(Type.REPORT);
            LabCases.check(problems, report != null && report.number("state") == 6
                    && report.codes("ledger").equals(Arrays.asList(1, 2, 3)), "the report of the settled ticket");
            rig.broker.scripts.put(Type.HELLO, r -> rig.broker.status(r, Status.STOPPED, "the stop file exists"));
            LabCases.check(problems, LabBridge.run(new String[] {config, "check"}, null, rig.broker, rig.halter, random)
                    == 125, "stopped");
            rig.broker.scripts.put(Type.HELLO, r -> rig.broker.status(r, Status.REFUSED, "another manifest"));
            LabCases.check(problems, LabBridge.run(new String[] {config, "check"}, null, rig.broker, rig.halter, random)
                    == 2, "refused");
            LabCases.check(problems, LabBridge.run(new String[] {config}, null, rig.broker, rig.halter, random) == 64,
                    "usage");
        });

        cases.run("bridge / the frames go only over the two pipes the broker names", problems -> {
            int[] good = LabBridge.frameDescriptors("5,6");
            LabCases.check(problems, good[0] == 5 && good[1] == 6, "the replies' pipe, then the requests'");
            LabCases.check(problems, LabBridge.frameDescriptors("1234567,3")[0] == 1234567,
                    "any two descriptors past the standard streams");
            for (String bad : new String[] {"", "5", "5,", ",6", "5,5", "1,6", "2,6", "5,1", "5,2", "0,6", "05,6",
                    "a,6", " 5,6", "5,6 ", "5,6,7", "5;6", "12345678,6", "-5,6", "+5,6"}) {
                LabCases.check(problems, throwsType(IllegalArgumentException.class,
                        () -> LabBridge.frameDescriptors(bad)), "frame pipes of another form were taken: " + bad);
            }
            // Without them there is no channel at all: nothing falls back to the standard streams.
            LabCases.check(problems, throwsType(IllegalArgumentException.class, () -> LabBridge.frameDescriptors(null)),
                    "a generation without its frame pipes");
        });

        cases.run("config / version 3 names the profile, and its generation speaks protocol 2", problems -> {
            byte[] good = LabConfig.encode(LabFixtures.INSTALLATION, LabFixtures.COMPONENT, LabFixtures.COORDINATOR,
                    LabFixtures.TRUST, MANIFEST, Paths.get("/lab/store"), LabFixtures.HOST, LabConfig.PROFILE);
            LabConfig config = LabConfig.parse(good);
            LabCases.check(problems, config.protocol == 2 && LabConfig.PROFILE.equals(config.profile)
                    && LabFixtures.HOST.equals(config.host), "the profile and protocol version");
            LabConfig two = LabConfig.parse(LabConfig.encode(LabFixtures.INSTALLATION, LabFixtures.COMPONENT,
                    LabFixtures.COORDINATOR, LabFixtures.TRUST, MANIFEST, Paths.get("/lab/store"), LabFixtures.HOST));
            LabCases.check(problems, two.protocol == 1 && two.profile == null, "version 2 speaks protocol 1");
            String text = new String(good, java.nio.charset.StandardCharsets.US_ASCII);
            List<String> bad = Arrays.asList(text.replace("profile " + LabConfig.PROFILE, "profile d5-next-vehicle-2"),
                    text.replace("\nprofile " + LabConfig.PROFILE, ""), text.replace("andrix-lab-bridge 3", "andrix-lab-bridge 2"),
                    text.replace("host " + LabFixtures.HOST + "\nprofile", "profile"), text + "extra 1\n");
            for (String b : bad) {
                LabCases.check(problems, throwsType(IllegalArgumentException.class,
                        () -> LabConfig.parse(b.getBytes(java.nio.charset.StandardCharsets.US_ASCII))),
                        "a version 3 configuration of another form was read");
            }
            Rig rig = new Rig(base, "config3", true);
            rig.open();
            LabCases.check(problems, rig.broker.requests.get(0).version == 2, "HELLO on protocol version 2");
            rig.broker.version = LabProtocol.VERSION;
            LabCases.check(problems, throwsType(ChannelLost.class, () -> {
                try {
                    rig.open();
                } catch (IOException error) {
                    throw new RuntimeException(error);
                }
            }), "a version 2 bridge took a version 1 broker");
        });

        cases.run("device v2 / simple envelopes are current facts of the round", problems -> {
            Rig rig = new Rig(base, "simple2", true);
            ShellDevice device = rig.open().device();
            FakeBroker broker = rig.broker;
            device.clock();
            LabCases.check(problems, device.observe(LabFixtures.COMPONENT).size() == 4, "the component's four facts");
            LabCases.check(problems, device.observe(rig.stored(), rig.plan).size() == 6, "the ticket's six facts");
            List<Function<FakeBroker, Observation>> bad = Arrays.asList(
                    b -> b.fact(Classification.CHECKPOINT_COMMITTED).at(-1, b.elapsed - 5_000, b.wall).build(),
                    b -> b.fact(Classification.NONE_FOR_PACKAGE).component(LabFixtures.COMPONENT)
                            .at(b.instance - 1, b.elapsed, b.wall).build(),
                    b -> b.fact(Classification.CHECKPOINT_COMMITTED).boot("ab".repeat(16)).build(),
                    b -> b.fact(Classification.CHECKPOINT_COMMITTED).route(Route.DEVICE).build(),
                    b -> b.fact(Classification.CHECKPOINT_COMMITTED).installation("99".repeat(16)).build(),
                    b -> b.fact(Classification.FACTORY_PRESENT).component("com.android.settings")
                            .digest(LabFixtures.FACTORY_APK).version(LabFixtures.FACTORY_VERSION).build());
            int at = 0;
            for (Function<FakeBroker, Observation> fact : bad) {
                int index = at++;
                broker.scripts.put(Type.OBSERVE, r -> broker.reply(r).number("status", 1).number("control_record", 0)
                        .envelopes("envelopes", broker.simple(Collections.singletonList(fact.apply(broker))))
                        .text("reason", ""));
                LabCases.check(problems, throwsType(BridgeRefusal.class, () -> device.observe(rig.stored(), rig.plan)),
                        "bad simple fact " + index + " was taken");
            }
            broker.scripts.remove(Type.OBSERVE);
        });

        cases.run("device v2 / a receipt keeps its proven time only with its notice's provenance", problems -> {
            Rig rig = new Rig(base, "receipt2", true);
            ShellDevice device = rig.open().device();
            FakeBroker b = rig.broker;
            Entry notice = new Entry(Crossing.NOTICE, b.boot, -1, 10_000, LabFixtures.id(0x203), DeploymentRecords.NO_ID,
                    LabFixtures.TIME);
            Ticket noticed = rig.ticket.toBuilder().append(notice).build();
            String t = rig.ticket.ticketId, p = rig.plan.planId;
            device.clock();
            long round = b.elapsed;
            observeWith(b, Collections.singletonList(receiptEnvelope(b, t, p, 0, 20_000, round + 100, b.instance)));
            List<Observation> facts = device.observe(noticed, rig.plan);
            Observation receipt = facts.get(facts.size() - 1);
            LabCases.check(problems, receipt.kind == DeploymentRecords.ObservationKind.RECEIPT && receipt.elapsed == 20_000
                    && receipt.elapsed < round && device.group(receipt.observationId) == 31, "the receipt at its event");
            Ticket signed = rig.ticket.toBuilder().append(new Entry(Crossing.SIGN, DeploymentRecords.NO_ID, -1, 0,
                    LabFixtures.id(0x201), LabFixtures.id(0x777), 0)).build();
            Ticket elsewhere = rig.ticket.toBuilder().append(new Entry(Crossing.NOTICE, "ab".repeat(16), -1, 10_000,
                    LabFixtures.id(0x203), DeploymentRecords.NO_ID, LabFixtures.TIME)).build();
            Map<String, Function<Long, Envelope>> bad = new LinkedHashMap<>();
            bad.put("a notice the ticket never gave", now -> receiptEnvelope(b, t, p, 1, 20_000, now + 100, b.instance));
            bad.put("an event before its notice", now -> receiptEnvelope(b, t, p, 0, 5_000, now + 100, b.instance));
            bad.put("a read that began before the round's clock", now -> receiptEnvelope(b, t, p, 0, 20_000, now - 200,
                    b.instance));
            bad.put("a read in an earlier framework", now -> receiptEnvelope(b, t, p, 0, 20_000, now + 100, b.instance - 1));
            bad.put("another ticket's receipt", now -> receiptEnvelope(b, LabFixtures.id(0x402), p, 0, 20_000, now + 100,
                    b.instance));
            for (Map.Entry<String, Function<Long, Envelope>> e : bad.entrySet()) {
                device.clock();
                long now = b.elapsed;
                observeWith(b, Collections.singletonList(e.getValue().apply(now)));
                LabCases.check(problems, throwsType(BridgeRefusal.class, () -> device.observe(noticed, rig.plan)),
                        e.getKey() + " was taken");
            }
            for (Ticket other : Arrays.asList(signed, elsewhere)) {
                device.clock();
                observeWith(b, Collections.singletonList(receiptEnvelope(b, t, p, 0, 20_000, b.elapsed + 100, b.instance)));
                LabCases.check(problems, throwsType(BridgeRefusal.class, () -> device.observe(other, rig.plan)),
                        "a receipt of no NOTICE of this boot was taken");
            }
            device.clock();
            observeWith(b, Collections.singletonList(receiptEnvelope(b, t, p, 0, 20_000, b.elapsed + 100, b.instance)));
            LabCases.check(problems, throwsType(BridgeRefusal.class, () -> device.observe(LabFixtures.COMPONENT)),
                    "a receipt in a component observation");
            b.scripts.remove(Type.OBSERVE);
        });

        cases.run("device v2 / a health probe lands only in its ticket's window", problems -> {
            Rig rig = new Rig(base, "health2", true);
            published(rig);
            ShellDevice device = rig.open().device();
            FakeBroker b = rig.broker;
            String t = rig.ticket.ticketId, p = rig.plan.planId;
            long start = 25_000;
            String nonce = LabFixtures.id(0x6e01);
            Ticket window = rig.ticket.toBuilder().reference(Reference.NONE.withNonce(nonce)).append(new Entry(
                    Crossing.CREATE, b.boot, b.instance, 20_000, LabFixtures.id(0x202), nonce, LabFixtures.TIME))
                    .state(State.HEALTH_WINDOW).window(b.boot, start).build();
            device.clock();
            long now = b.elapsed;
            observeWith(b, Collections.singletonList(healthEnvelope(b, t, p, start, now + 100, now + 200, 0, BUNDLE_APK,
                    PUBLICATION)));
            List<Observation> facts = device.observe(window, rig.plan);
            Observation probe = facts.get(facts.size() - 1);
            LabCases.check(problems, probe.classification == Classification.HEALTH_HELD && probe.number == 127
                    && probe.elapsed == now + 200, "one HELD probe at its read's end");
            Map<String, Function<Long, Envelope>> bad = new LinkedHashMap<>();
            bad.put("another window start", n -> healthEnvelope(b, t, p, start + 1, n + 100, n + 200, 0, BUNDLE_APK,
                    PUBLICATION));
            bad.put("a probe that ends after its window", n -> healthEnvelope(b, t, p, start, n + 100, start + WINDOW + 1, 0,
                    BUNDLE_APK, PUBLICATION));
            bad.put("a user not shown running", n -> healthEnvelope(b, t, p, start, n + 100, n + 200, 10, BUNDLE_APK,
                    PUBLICATION));
            bad.put("another active APK", n -> healthEnvelope(b, t, p, start, n + 100, n + 200, 0, RESTORATION_APK,
                    PUBLICATION));
            bad.put("another publication", n -> healthEnvelope(b, t, p, start, n + 100, n + 200, 0, BUNDLE_APK,
                    "a4".repeat(32)));
            bad.put("another plan", n -> healthEnvelope(b, t, LabFixtures.id(0x102), start, n + 100, n + 200, 0, BUNDLE_APK,
                    PUBLICATION));
            bad.put("a read that began before the round's clock", n -> healthEnvelope(b, t, p, start, n - 50, n + 200, 0,
                    BUNDLE_APK, PUBLICATION));
            for (Map.Entry<String, Function<Long, Envelope>> e : bad.entrySet()) {
                device.clock();
                long n = b.elapsed;
                observeWith(b, Collections.singletonList(e.getValue().apply(n)));
                LabCases.check(problems, throwsType(BridgeRefusal.class, () -> device.observe(window, rig.plan)),
                        e.getKey() + " was taken");
            }
            device.clock();
            observeWith(b, Collections.singletonList(healthEnvelope(b, t, p, start, b.elapsed + 100, b.elapsed + 200, 0,
                    BUNDLE_APK, PUBLICATION)));
            LabCases.check(problems, throwsType(BridgeRefusal.class, () -> device.observe(rig.stored(), rig.plan)),
                    "a probe of a ticket outside its window");
            LabCases.check(problems, throwsType(BridgeRefusal.class, () -> device.observe(LabFixtures.COMPONENT)),
                    "a probe in a component observation");
            b.scripts.remove(Type.OBSERVE);
        });

        cases.run("device v2 / an ordered halt in an observation ends the generation", problems -> {
            Rig rig = new Rig(base, "halt2", true);
            LabBridge bridge = rig.open();
            rig.broker.scripts.put(Type.OBSERVE, r -> rig.broker.reply(r).number("status", 4).number("control_record", 9)
                    .envelopes("envelopes", Collections.emptyList()).text("reason", "admitted read loss"));
            int before = rig.store.observations().values.size();
            LabCases.check(problems, throwsType(Halted.class, () -> bridge.round(rig.ticket.ticketId)), "no halt");
            LabCases.check(problems, rig.halts.equals(Collections.singletonList(99)), "halted with 99 once");
            LabCases.check(problems, rig.store.observations().values.size() == before, "a halted observation recorded facts");
        });

        cases.run("round v2 / each public round ends with its boundary, and the broker's answer decides", problems -> {
            Rig rig = new Rig(base, "round2", true);
            String t = rig.ticket.ticketId;
            LabBridge bridge = LabBridge.open(rig.config, rig.broker, rig.hosts(), rig.halter, new SecureRandom(),
                    Collections.singletonMap(t, 2L));
            bridge.round(t);
            Message last = rig.broker.requests.get(rig.broker.requests.size() - 1);
            Ticket after = rig.stored();
            byte[] selection = DeploymentRecords.encodeSelection(rig.store.selection(LabFixtures.COMPONENT).value);
            LabCases.check(problems, last.type == Type.ROUND_DONE && last.id("ticket").equals(t)
                    && last.id("plan").equals(rig.plan.planId) && last.number("attempt") == after.attempt
                    && last.number("checkpoint_ordinal") == 3
                    && last.id("ticket_digest").equals(LabProtocol.sha256Hex(DeploymentRecords.encodeTicket(after)))
                    && last.id("selection_digest").equals(LabProtocol.sha256Hex(selection)),
                    "the boundary names the stored records and the ordinal after the told count");
            bridge.round(t);
            LabCases.check(problems, rig.broker.last(Type.ROUND_DONE).number("checkpoint_ordinal") == 4,
                    "the ordinal counts on after an accepted boundary");
            // The milestone is the shared rule's, from the round's starting state to the stored
            // one: TERMINAL only for the round that closed the ticket.
            LabCases.check(problems, bridge.cancel(t), "the cancellation was not recorded");
            List<Long> milestones = new ArrayList<>();
            for (int i = 0; i < 10 && !rig.stored().state.terminal(); i++) {
                bridge.round(t);
                milestones.add(rig.broker.last(Type.ROUND_DONE).number("milestone"));
            }
            bridge.round(t);
            milestones.add(rig.broker.last(Type.ROUND_DONE).number("milestone"));
            long terminal = LabProtocol.milestoneCode("TERMINAL");
            LabCases.check(problems, rig.stored().state == State.CANCELLED && milestones.size() >= 2
                    && milestones.get(milestones.size() - 2) == terminal && milestones.get(milestones.size() - 1) == 0
                    && Collections.frequency(milestones, terminal) == 1, "TERMINAL once, at the closing round");
            LabCases.check(problems, rig.broker.last(Type.ROUND_DONE).number("checkpoint_ordinal")
                    == 4 + milestones.size(), "the ordinals went on without a gap");
            rig.broker.scripts.put(Type.ROUND_DONE, r -> rig.broker.status(r, Status.STOPPED, "the stop file exists"));
            LabCases.check(problems, throwsType(GenerationStopped.class, () -> bridge.round(t)), "a stop went on");
            rig.broker.scripts.put(Type.ROUND_DONE, r -> rig.broker.status(r, Status.REFUSED, "a stale digest"));
            LabCases.check(problems, throwsType(BridgeRefusal.class, () -> bridge.round(t)), "a refusal went on");
            rig.broker.scripts.put(Type.ROUND_DONE, r -> rig.broker.status(r, Status.HALT, "admitted round loss")
                    .number("record", 9));
            int before2 = rig.broker.requests.size();
            LabCases.check(problems, throwsType(Halted.class, () -> bridge.round(t)), "no halt");
            LabCases.check(problems, rig.halts.equals(Collections.singletonList(99)), "halted with 99 once");
            LabCases.check(problems, rig.broker.requests.size() > before2
                    && rig.broker.requests.get(rig.broker.requests.size() - 1).type == Type.ROUND_DONE,
                    "nothing was sent after the halt order");
            Rig one = new Rig(base, "round1");
            one.open().round(one.ticket.ticketId);
            LabCases.check(problems, one.broker.count(Type.ROUND_DONE) == 0, "a version 1 round sent ROUND_DONE");
        });

        cases.run("round v2 / a settle is one public round at a time, each with its boundary", problems -> {
            Rig rig = new Rig(base, "settle2", true);
            rig.open().settle(rig.ticket.ticketId, 30);
            List<Message> boundaries = new ArrayList<>();
            for (Message m : rig.broker.requests) if (m.type == Type.ROUND_DONE) boundaries.add(m);
            boolean ordered = boundaries.size() >= 2;
            for (int i = 0; i < boundaries.size(); i++) {
                ordered &= boundaries.get(i).number("checkpoint_ordinal") == i + 1;
            }
            LabCases.check(problems, ordered, "the ordinals 1 to n, one for each round");
            Message lastRound = boundaries.get(boundaries.size() - 1);
            Message previous = boundaries.get(boundaries.size() - 2);
            LabCases.check(problems, rig.stored().state == State.SESSION_INTENT
                    && lastRound.id("ticket_digest").equals(previous.id("ticket_digest")),
                    "the settle stopped after a round that changed nothing");
            LabCases.check(problems, rig.broker.count(Type.CLOCK) >= boundaries.size(), "a round without its clock");
        });

        cases.run("bridge / the checkpoint counts a broker tells, and a version 2 generation needs them", problems -> {
            String a = "0a".repeat(16), b = "0b".repeat(16);
            LabCases.check(problems, LabBridge.checkpoints(null) == null, "nothing told");
            LabCases.check(problems, LabBridge.checkpoints("").isEmpty(), "none recorded");
            Map<String, Long> two = LabBridge.checkpoints(a + ":3," + b + ":12");
            LabCases.check(problems, two.size() == 2 && two.get(a) == 3L && two.get(b) == 12L, "two tickets");
            for (String bad : Arrays.asList(a + ":0", a + ":03", a.toUpperCase() + ":1", a + "1", b + ":1," + a + ":1",
                    a + ":1," + a + ":2", LabProtocol.ZERO_ID + ":1", a + ":1,", "," + a + ":1", a + ":12345678901")) {
                LabCases.check(problems, throwsType(IllegalArgumentException.class, () -> LabBridge.checkpoints(bad)),
                        bad + " was read");
            }
            Rig rig = new Rig(base, "told2", true);
            String config = rig.dir.resolve("bridge.config").toString();
            SecureRandom random = new SecureRandom();
            LabCases.check(problems, LabBridge.run(new String[] {config, "check"}, null, rig.broker, rig.halter, random,
                    null) == 64, "a version 2 generation told nothing ran");
            LabCases.check(problems, LabBridge.run(new String[] {config, "check"}, null, rig.broker, rig.halter, random,
                    a + ":0") == 64, "counts of no known form were taken");
            LabCases.check(problems, LabBridge.run(new String[] {config, "check"}, null, rig.broker, rig.halter, random,
                    "") == 0, "a version 2 generation told no boundary yet");
            LabCases.check(problems, rig.broker.count(Type.HELLO) == 1, "a refused generation said HELLO");
        });

        cases.finish("Lab bridge checks passed");
    }
}
