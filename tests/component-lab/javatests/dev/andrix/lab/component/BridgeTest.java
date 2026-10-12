// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

import dev.andrix.lab.component.BridgeErrors.BridgeRefusal;
import dev.andrix.lab.component.BridgeErrors.GenerationStopped;
import dev.andrix.lab.component.BrokerChannel.ChannelLost;
import dev.andrix.lab.component.LabProtocol.Frame;
import dev.andrix.lab.component.LabProtocol.Message;
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
import java.util.List;
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
            dir = Files.createDirectories(base.resolve(name));
            store = new DeploymentStore(dir.resolve("store"), LabFixtures.INSTALLATION);
            plan = LabFixtures.plan(LabFixtures.id(0x101), WINDOW);
            ticket = LabFixtures.install(store, plan, LabFixtures.id(0x401), LabFixtures.TIME);
            config = LabConfig.read(LabFixtures.config(dir, dir.resolve("store"), MANIFEST));
            broker.expectedConfig = config.digest;
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

        cases.finish("Lab bridge checks passed");
    }
}
