// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

import dev.andrix.lab.component.BridgeErrors.BridgeRefusal;
import dev.andrix.lab.component.BridgeErrors.GenerationStopped;
import dev.andrix.lab.component.LabProtocol.Message;
import dev.andrix.lab.component.LabProtocol.Type;
import dev.andrix.server.deployment.Coordinator;
import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.CoordinatorClass;
import dev.andrix.server.deployment.DeploymentRecords.Entry;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Selection;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import dev.andrix.server.deployment.DeploymentStore;
import dev.andrix.server.deployment.DeploymentStore.Found;
import dev.andrix.server.deployment.DeploymentStore.Read;
import dev.andrix.server.deployment.Reconciler;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * The lab's public entry to one component's coordinator on the shell route. One instance serves one
 * coordinator generation: a process that the broker started, talking to it over the process's own
 * standard input and output.
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
 * <p>Exit statuses: 0 done, 2 failed, 64 usage, 99 an ordered halt, 125 stopped by a fence.
 */
public final class LabBridge {
    public static final int EXIT_OK = 0, EXIT_FAILED = 2, EXIT_USAGE = 64, EXIT_STOPPED = 125;

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
    private Ticket rounding;

    private LabBridge(LabConfig config, DeploymentStore store, BrokerChannel channel, ShellDevice device,
            Coordinator.Host host, Halter halter, long generation, int target, boolean hosted, SecureRandom random) {
        this.config = config;
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
        BrokerChannel channel = new BrokerChannel(transport, config.manifest, random);
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
                (int) reply.number("target"), hosts != null, random);
    }

    public Coordinator coordinator() { return coordinator; }

    public ShellDevice device() { return device; }

    public DeploymentStore store() { return store; }

    public long generation() { return generation; }

    /** One coordinator round of a ticket this coordinator owns. */
    public Reconciler.Step round(String ticketId) {
        prepare(ticketId);
        return coordinator.round(ticketId);
    }

    /** Rounds until a round changes nothing and issues nothing, or the bound is reached. */
    public Reconciler.Step settle(String ticketId, int maxRounds) {
        prepare(ticketId);
        return coordinator.settle(ticketId, maxRounds);
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

    // Package private for the bridge's own checks.
    void prepare(String ticketId) {
        if (!hosted) throw new BridgeRefusal("no host is wired: a round would query it");
        if (target == LabProtocol.TARGET_UNKNOWN) throw new BridgeRefusal("the native target scope is not established");
        rounding = owned(ticketId);
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
     * Standard output carries only protocol frames: anything else printed goes to standard error.
     */
    public static int run(String[] args, HostFactory hosts) {
        // The frames go straight to file descriptor 1, unbuffered, so a write error is never swallowed.
        FileOutputStream frames = new FileOutputStream(FileDescriptor.out);
        System.setOut(System.err);
        return run(args, hosts, BrokerChannel.streams(new FileInputStream(FileDescriptor.in), frames),
                Halter.runtime(), new SecureRandom());
    }

    /** As {@link #run(String[], HostFactory)}, over a given transport and halter. */
    public static int run(String[] args, HostFactory hosts, BrokerChannel.Transport transport, Halter halter,
            SecureRandom random) {
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
        try {
            LabConfig config = LabConfig.read(Paths.get(args[0]));
            LabBridge bridge = open(config, transport, hosts, halter, random);
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
