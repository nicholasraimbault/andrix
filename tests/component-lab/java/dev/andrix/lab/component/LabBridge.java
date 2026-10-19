// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

import dev.andrix.lab.component.BridgeErrors.BridgeRefusal;
import dev.andrix.lab.component.BridgeErrors.GenerationStopped;
import dev.andrix.lab.component.LabProtocol.Message;
import dev.andrix.lab.component.LabProtocol.Type;
import dev.andrix.server.deployment.Coordinator;
import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords;
import dev.andrix.server.deployment.DeploymentRecords.CoordinatorClass;
import dev.andrix.server.deployment.DeploymentRecords.Crossing;
import dev.andrix.server.deployment.DeploymentRecords.Entry;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Selection;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import dev.andrix.server.deployment.DeploymentStore;
import dev.andrix.server.deployment.DeploymentStore.Found;
import dev.andrix.server.deployment.DeploymentStore.Read;
import dev.andrix.server.deployment.Reconciler;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The lab's public entry to one component's coordinator on the shell route. One instance serves one
 * coordinator generation: a process that the broker started, talking to it over two frame pipes of
 * its own that the broker names in {@link #FRAMES}, never over its standard streams.
 *
 * <p>Opening sends HELLO with the durable configuration, so the broker checks the installation,
 * coordinator, configuration digest, component and trust policy against its admission, and it
 * answers only after every earlier generation and its calls ended. It then opens the public syncing
 * {@link DeploymentStore}, makes the accepted {@link Coordinator} with the shell device and the host
 * behind the fault wrapper, and installs the lab point for BETWEEN_WRITES. Nothing is cached between
 * generations: each one reads the store, and the broker keeps its own ledger.
 *
 * <p>The native target scope is the broker's admitted decision. A round needs it established: held
 * gives the coordinator's VOID_TARGET rule, and unknown refuses to round at all. The cohort check
 * needs neither.
 *
 * <p>On protocol version 2 every public round of a ticket ends with its boundary, ROUND_DONE, after
 * the round returned and before any next round or report: the ticket, plan and attempt, the next
 * checkpoint ordinal, the milestone the round reached from its starting state, and the SHA-256 of
 * the stored ticket and selection. The broker tells each generation, in its environment, how
 * many boundaries of each ticket it has recorded; the bridge counts on from there and the broker
 * verifies every ordinal. A halt order at the boundary ends the generation. A settle on version 2
 * is one public round at a time, each with its boundary, under the coordinator's own stop rule.
 *
 * <p>Exit statuses: 0 done, 2 failed, 64 usage, 99 an ordered halt, 125 stopped by a fence.
 */
public final class LabBridge {
    public static final int EXIT_OK = 0, EXIT_FAILED = 2, EXIT_USAGE = 64, EXIT_STOPPED = 125;
    /** Where a version 3 broker tells a generation its recorded boundaries: the environment. */
    public static final String CHECKPOINTS = "ANDRIX_LAB_CHECKPOINTS";
    /**
     * Where the broker names a generation's frame pipes, in the environment: {@code <in>,<out>},
     * the descriptor the broker's replies arrive on and the one requests go to, each past the
     * three standard streams. Standard output and standard error are the broker's kept output, so
     * the VM's output, its unified logging and anything printed never reach a frame.
     */
    public static final String FRAMES = "ANDRIX_LAB_FRAMES";
    private static final Pattern TOLD = Pattern.compile("[0-9a-f]{32}:[1-9][0-9]{0,9}");
    private static final Pattern DESCRIPTORS = Pattern.compile("([1-9][0-9]{0,6}),([1-9][0-9]{0,6})");

    /** Makes the host signer and publisher that the fault wrapper delegates to. */
    public interface HostFactory {
        Coordinator.Host host(DeploymentStore store, LabConfig config) throws IOException;
    }

    private final LabConfig config;
    private final DeploymentStore store;
    private final BrokerChannel channel;
    private final ShellDevice device;
    private final Coordinator coordinator;
    private final Halter halter;
    private final long generation;
    private final int target;
    private final boolean hosted;
    // Each ticket's recorded round boundaries: as the broker told this generation, then counted on.
    private final Map<String, Long> checkpoints;
    private Ticket rounding;

    private LabBridge(LabConfig config, DeploymentStore store, BrokerChannel channel, ShellDevice device,
            Coordinator.Host host, Halter halter, long generation, int target, boolean hosted, SecureRandom random,
            Map<String, Long> checkpoints) {
        this.config = config;
        this.checkpoints = new HashMap<>(checkpoints);
        this.store = store;
        this.channel = channel;
        this.device = device;
        this.halter = halter;
        this.generation = generation;
        this.target = target;
        this.hosted = hosted;
        this.coordinator = new Coordinator(store, device, new FaultHost(host, channel, halter, true),
                config.trustPolicy, () -> freshId(random));
        coordinator.targetHeld(target == LabProtocol.TARGET_HELD);
        if (!coordinator.labPoints(this::point)) throw new BridgeRefusal("the shell route refused its lab points");
    }

    private static String freshId(SecureRandom random) {
        while (true) {
            byte[] bytes = new byte[16];
            random.nextBytes(bytes);
            String id = LabProtocol.hex(bytes);
            if (!id.equals(LabProtocol.ZERO_ID)) return id;
        }
    }

    /**
     * Opens one generation. With no host factory only the cohort check, cancellation and reports
     * run: a round would query the host.
     */
    public static LabBridge open(LabConfig config, BrokerChannel.Transport transport, HostFactory hosts,
            Halter halter, SecureRandom random) throws IOException {
        return open(config, transport, hosts, halter, random, Collections.emptyMap());
    }

    /**
     * As {@link #open(LabConfig, BrokerChannel.Transport, HostFactory, Halter, SecureRandom)}, with
     * the recorded boundaries of each ticket that the broker told this generation.
     */
    public static LabBridge open(LabConfig config, BrokerChannel.Transport transport, HostFactory hosts,
            Halter halter, SecureRandom random, Map<String, Long> checkpoints) throws IOException {
        // A version 3 configuration's generation speaks protocol version 2, and only it.
        BrokerChannel channel = new BrokerChannel(transport, config.manifest, random, config.protocol);
        Message reply = channel.call(channel.request(Type.HELLO).id("installation", config.installation)
                .id("coordinator", config.coordinator).id("config", config.digest).text("component", config.component)
                .id("trust", config.trustPolicy).number("route", 1).build());
        switch (reply.status()) {
            case OK:
                break;
            case STOPPED:
                throw new GenerationStopped(reply.text("reason"));
            default:
                throw new BridgeRefusal("the broker refused HELLO: " + reply.text("reason"));
        }
        DeploymentStore store = new DeploymentStore(config.store, config.installation);
        Read<Selection> selection = store.selection(config.component);
        if (selection.found != Found.RECORD || !selection.value.installation.equals(config.installation)) {
            throw new BridgeRefusal("the store holds no selection of this installation's component");
        }
        ShellDevice device = new ShellDevice(channel, config, store, halter);
        Coordinator.Host host = hosts == null ? new RefusingHost() : hosts.host(store, config);
        return new LabBridge(config, store, channel, device, host, halter, reply.number("generation"),
                (int) reply.number("target"), hosts != null, random, checkpoints);
    }

    /**
     * The recorded boundaries a broker told a generation: comma separated {@code ticket:count}
     * pairs in ticket order, the empty text for none. Null when nothing was told. Anything else is
     * refused.
     */
    static Map<String, Long> checkpoints(String told) {
        if (told == null) return null;
        Map<String, Long> counts = new HashMap<>();
        if (told.isEmpty()) return counts;
        String last = null;
        for (String pair : told.split(",", -1)) {
            if (!TOLD.matcher(pair).matches()) throw new IllegalArgumentException("a checkpoint count of no known form");
            String ticket = pair.substring(0, 32);
            if (ticket.equals(LabProtocol.ZERO_ID) || (last != null && ticket.compareTo(last) <= 0)) {
                throw new IllegalArgumentException("checkpoint counts of nonzero tickets in order, each once");
            }
            last = ticket;
            counts.put(ticket, Long.parseLong(pair.substring(33)));
        }
        return counts;
    }

    public Coordinator coordinator() { return coordinator; }

    public ShellDevice device() { return device; }

    public DeploymentStore store() { return store; }

    public long generation() { return generation; }

    /** One coordinator round of a ticket this coordinator owns, on version 2 with its boundary. */
    public Reconciler.Step round(String ticketId) {
        Ticket before = prepare(ticketId);
        Reconciler.Step step = coordinator.round(ticketId);
        if (channel.version() == LabProtocol.VERSION_2) roundDone(before);
        return step;
    }

    /**
     * Rounds until a round changes nothing and issues nothing, or the bound is reached. On version
     * 2 one public round at a time, each with its boundary, so no milestone hides inside a loop.
     */
    public Reconciler.Step settle(String ticketId, int maxRounds) {
        if (channel.version() != LabProtocol.VERSION_2) {
            prepare(ticketId);
            return coordinator.settle(ticketId, maxRounds);
        }
        Reconciler.Step step = null;
        for (int i = 0; i < maxRounds; i++) {
            Ticket before = prepare(ticketId);
            step = coordinator.round(ticketId);
            roundDone(before);
            if (step.issue == null && step.ticket.equals(before)) return step;
        }
        return step;
    }

    // The boundary of the round that began at `before`: the stored ticket and selection by their
    // SHA-256, the next ordinal, and the milestone the round reached by the shared rule.
    void roundDone(Ticket before) {
        Read<Ticket> stored = store.ticket(before.ticketId);
        Read<Plan> plan = store.plan(before.planId);
        Read<Selection> selection = store.selection(config.component);
        if (stored.found != Found.RECORD || plan.found != Found.RECORD || selection.found != Found.RECORD) {
            throw new BridgeRefusal("the round's ticket, plan or selection cannot be read for its boundary");
        }
        Ticket after = stored.value;
        Plan p = plan.value;
        String milestone = LabProtocol.boundaryMilestone(before.state.name(), after.state.name(),
                after.count(Crossing.SIGN) > 0, !p.repairs.equals(DeploymentRecords.NO_ID) && p.signing == 0);
        long ordinal = checkpoints.getOrDefault(after.ticketId, 0L) + 1;
        Message reply = channel.call(channel.request(Type.ROUND_DONE).id("ticket", after.ticketId)
                .id("plan", after.planId).number("attempt", after.attempt).number("checkpoint_ordinal", ordinal)
                .number("milestone", LabProtocol.milestoneCode(milestone))
                .id("ticket_digest", LabProtocol.sha256Hex(DeploymentRecords.encodeTicket(after)))
                .id("selection_digest", LabProtocol.sha256Hex(DeploymentRecords.encodeSelection(selection.value)))
                .build());
        switch (reply.status()) {
            case OK:
                checkpoints.put(after.ticketId, ordinal);
                return;
            case HALT:
                halter.halt(Halter.STATUS);
                throw new IllegalStateException("the halter returned");
            case STOPPED:
                throw new GenerationStopped(reply.text("reason"));
            default:
                throw new BridgeRefusal("the broker refused ROUND_DONE: " + reply.text("reason"));
        }
    }

    /** The cohort check of the component with no ticket. */
    public Selection check() { return coordinator.check(config.component); }

    /** Records an owner cancellation, as the coordinator does. */
    public boolean cancel(String ticketId) {
        owned(ticketId);
        return coordinator.cancel(ticketId);
    }

    /** Sends the ticket's state, flags, cause and ledger to the broker's ledger, informational only. */
    public void report(String ticketId, String note) {
        Ticket t = owned(ticketId);
        List<Integer> ledger = new ArrayList<>();
        for (Entry e : t.ledger) ledger.add(RecordCodes.crossing(e.crossing));
        Message reply = channel.call(channel.request(Type.REPORT).id("ticket", t.ticketId)
                .number("state", RecordCodes.state(t.state)).number("flags", t.flags)
                .number("cause", RecordCodes.cause(t.cause)).codes("ledger", ledger).text("note", note).build());
        if (BrokerChannel.refused(reply)) throw new BridgeRefusal("the broker refused REPORT");
    }

    private Ticket owned(String ticketId) {
        Read<Ticket> read = store.ticket(ticketId);
        if (read.found != Found.RECORD) throw new BridgeRefusal("the ticket cannot be read");
        Ticket t = read.value;
        if (t.coordinatorClass != CoordinatorClass.HOST || !t.coordinator.equals(config.coordinator)
                || !t.component.equals(config.component) || !t.installation.equals(config.installation)) {
            throw new BridgeRefusal("a ticket that this coordinator does not own");
        }
        return t;
    }

    // Package private for the bridge's own checks. Returns the ticket as the round begins.
    Ticket prepare(String ticketId) {
        if (!hosted) throw new BridgeRefusal("no host is wired: a round would query it");
        if (target == LabProtocol.TARGET_UNKNOWN) throw new BridgeRefusal("the native target scope is not established");
        rounding = owned(ticketId);
        return rounding;
    }

    // The coordinator's lab point. At BETWEEN_WRITES the broker decides, from its admitted fault cells,
    // whether this generation halts there. It records the consumed cell before it answers.
    void point(String point) {
        if (!Coordinator.BETWEEN_WRITES.equals(point) || rounding == null) return;
        Message reply = channel.call(channel.request(Type.POINT).text("point", point)
                .id("ticket", rounding.ticketId).id("plan", rounding.planId).number("attempt", rounding.attempt)
                .build());
        switch (reply.status()) {
            case OK:
                return;
            case HALT:
                halter.halt(Halter.STATUS);
                throw new IllegalStateException("the halter returned");
            default:
                throw new BridgeRefusal("the broker refused POINT: " + reply.text("reason"));
        }
    }

    /** A host for generations that never sign, publish or query. */
    private static final class RefusingHost implements Coordinator.Host {
        @Override
        public Observation sign(Ticket ticket, Plan plan, Entry entry, Authorization grant) {
            throw new BridgeRefusal("no host is wired");
        }

        @Override
        public Observation publish(Ticket ticket, Plan plan, Entry entry) {
            throw new BridgeRefusal("no host is wired");
        }

        @Override
        public List<Observation> query(Ticket ticket, Plan plan, List<Authorization> grants) {
            throw new BridgeRefusal("no host is wired");
        }
    }

    // ---------------------------------------------------------------- the process entry

    /**
     * Runs one generation's operation and returns its exit status. Arguments: the configuration file,
     * then `check`, `round TICKET`, `settle TICKET ROUNDS`, `cancel TICKET` or `report TICKET`.
     * The frames go over the pipes {@link #FRAMES} names; without them the generation refuses to
     * run and sends nothing. Anything printed goes to standard error.
     */
    public static int run(String[] args, HostFactory hosts) {
        System.setOut(System.err);
        BrokerChannel.Transport frames;
        try {
            frames = frames(System.getenv(FRAMES));
        } catch (IllegalArgumentException | IOException error) {
            return usage(error.getMessage());
        }
        return run(args, hosts, frames, Halter.runtime(), new SecureRandom(), System.getenv(CHECKPOINTS));
    }

    /**
     * The frame pipes {@link #FRAMES} names, opened through {@code /proc/self/fd}: the replies to
     * read, and the requests to write unbuffered, so a write error is never swallowed.
     */
    static BrokerChannel.Transport frames(String value) throws IOException {
        int[] descriptors = frameDescriptors(value);
        return BrokerChannel.streams(new FileInputStream("/proc/self/fd/" + descriptors[0]),
                new FileOutputStream("/proc/self/fd/" + descriptors[1]));
    }

    /**
     * The two frame descriptors of {@link #FRAMES}'s value, {@code <in>,<out>}: decimal, distinct,
     * and never a standard stream. There is no other channel: a missing or malformed value refuses.
     */
    static int[] frameDescriptors(String value) {
        if (value == null) throw new IllegalArgumentException("the broker named no frame pipes in " + FRAMES);
        Matcher m = DESCRIPTORS.matcher(value);
        if (!m.matches()) throw new IllegalArgumentException(FRAMES + " is not <in>,<out>");
        int in = Integer.parseInt(m.group(1)), out = Integer.parseInt(m.group(2));
        if (in < 3 || out < 3 || in == out) {
            throw new IllegalArgumentException(FRAMES + " names a standard stream or one pipe twice");
        }
        return new int[] {in, out};
    }

    /** As {@link #run(String[], HostFactory)}, over a transport and halter, told no boundary. */
    public static int run(String[] args, HostFactory hosts, BrokerChannel.Transport transport, Halter halter,
            SecureRandom random) {
        return run(args, hosts, transport, halter, random, "");
    }

    /**
     * As {@link #run(String[], HostFactory)}, with the checkpoint counts the broker told: a
     * version 2 generation refuses to run without them.
     */
    public static int run(String[] args, HostFactory hosts, BrokerChannel.Transport transport, Halter halter,
            SecureRandom random, String told) {
        Objects.requireNonNull(halter, "halter");
        if (args.length < 2) return usage("arguments: CONFIG check | round TICKET | settle TICKET ROUNDS"
                + " | cancel TICKET | report TICKET");
        String operation = args[1];
        int expected = operation.equals("check") ? 2 : operation.equals("settle") ? 4 : 3;
        if (args.length != expected) return usage("wrong arguments for " + operation);
        if ((operation.equals("round") || operation.equals("settle")) && hosts == null) {
            return usage(operation + " needs a host: the lab driver wires it");
        }
        int rounds = 0;
        if (operation.equals("settle")) {
            try {
                rounds = Integer.parseInt(args[3]);
            } catch (NumberFormatException error) {
                return usage("ROUNDS is a number");
            }
            if (rounds < 1 || rounds > 1000) return usage("ROUNDS is 1 to 1000");
        }
        Map<String, Long> counts;
        try {
            counts = checkpoints(told);
        } catch (IllegalArgumentException error) {
            return usage("the checkpoint counts the broker told are of no known form");
        }
        try {
            LabConfig config = LabConfig.read(Paths.get(args[0]));
            if (config.protocol == LabProtocol.VERSION_2 && counts == null) {
                return usage("a version 2 generation is told its checkpoint counts by its broker");
            }
            LabBridge bridge = open(config, transport, hosts, halter, random,
                    counts == null ? Collections.emptyMap() : counts);
            switch (operation) {
                case "check":
                    bridge.check();
                    break;
                case "round":
                    bridge.round(args[2]);
                    bridge.report(args[2], "round");
                    break;
                case "settle":
                    bridge.settle(args[2], rounds);
                    bridge.report(args[2], "settle");
                    break;
                case "cancel":
                    bridge.cancel(args[2]);
                    bridge.report(args[2], "cancel");
                    break;
                case "report":
                    bridge.report(args[2], "report");
                    break;
                default:
                    return usage("an unknown operation " + operation);
            }
            return EXIT_OK;
        } catch (GenerationStopped stopped) {
            System.err.println("stopped: " + stopped.getMessage());
            return EXIT_STOPPED;
        } catch (IOException | RuntimeException failure) {
            System.err.println("failed: " + failure);
            return EXIT_FAILED;
        }
    }

    private static int usage(String message) {
        System.err.println("usage: " + message);
        return EXIT_USAGE;
    }

    public static void main(String[] args) {
        System.exit(run(args, null));
    }
}
