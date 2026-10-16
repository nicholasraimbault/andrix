// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

import dev.andrix.server.deployment.DeploymentRecords;
import dev.andrix.server.deployment.DeploymentRecords.ActorClass;
import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.Effect;
import dev.andrix.server.deployment.DeploymentRecords.Entry;
import dev.andrix.server.deployment.DeploymentRecords.GrantScope;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Selection;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import dev.andrix.server.deployment.DeploymentStore;
import dev.andrix.server.deployment.DeploymentStore.Found;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * The coordinator process of the Python end to end suite, which runs it as broker generations. It
 * is the lab entry with the scripted host wired in, plus two operations outside any generation:
 * `setup`, which writes the store's plan, grants, selection and first ticket and the bridge's
 * configuration, and `inspect`, which prints a ticket and the selection from the store.
 *
 * <pre>
 * setup DIR STORE MANIFEST PLAN TICKET HEALTH_WINDOW_MS [ACTIVATE_WINDOW_MS]   prints the configuration digest
 * setup3 DIR STORE MANIFEST PLAN TICKET HEALTH_WINDOW_MS [ACTIVATE_WINDOW_MS]  as setup, version 3
 * ticket STORE PLAN TICKET [SIGN_GRANT]                      the plan's next attempt, with a new SIGN grant
 * inspect STORE TICKET                                       one line of key=value facts
 * CONFIG check | round T | settle T N | cancel T | report T  a generation
 * </pre>
 *
 * The scripted host reads its directory and the plan's bound APKs from the system properties
 * andrix.lab.hostDir, andrix.lab.bundleApk and andrix.lab.restorationApk.
 */
public final class LabBridgeTestMain {
    private LabBridgeTestMain() {}

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && (args[0].equals("setup") || args[0].equals("setup3"))) {
            setup(args);
        } else if (args.length > 0 && args[0].equals("ticket")) {
            ticket(args);
        } else if (args.length > 0 && args[0].equals("inspect")) {
            inspect(args);
        } else {
            LabBridge.HostFactory hosts = (store, config) -> new ScriptedHost(
                    Paths.get(System.getProperty("andrix.lab.hostDir")), System.getProperty("andrix.lab.bundleApk"),
                    System.getProperty("andrix.lab.restorationApk"));
            System.exit(LabBridge.run(args, hosts));
        }
    }

    private static void setup(String[] args) throws IOException {
        Path dir = Paths.get(args[1]);
        Path storeRoot = Paths.get(args[2]);
        Plan plan = args.length > 7 ? LabFixtures.plan(args[4], Long.parseLong(args[6]), Long.parseLong(args[7]))
                : LabFixtures.plan(args[4], Long.parseLong(args[6]));
        DeploymentStore store = new DeploymentStore(storeRoot, LabFixtures.INSTALLATION);
        LabFixtures.install(store, plan, args[5], LabFixtures.TIME);
        Path config = args[0].equals("setup3") ? LabFixtures.config3(dir, storeRoot, args[3])
                : LabFixtures.config(dir, storeRoot, args[3]);
        System.out.println(LabConfig.read(config).digest);
    }

    private static void ticket(String[] args) {
        DeploymentStore store = new DeploymentStore(Paths.get(args[1]), LabFixtures.INSTALLATION);
        Plan plan = store.plan(args[2]).value;
        Ticket ticket = new Ticket.Builder().installation(LabFixtures.INSTALLATION).ticketId(args[3])
                .component(plan.component).planId(plan.planId).attempt(store.ticketsOf(plan.planId).size() + 1)
                .coordinator(DeploymentRecords.CoordinatorClass.HOST,
                        LabFixtures.COORDINATOR).build();
        if (!store.createTicket(ticket)) throw new IllegalStateException("ticket not written");
        if (args.length > 4) {
            int inputs = DeploymentRecords.INPUT_VARIANT | DeploymentRecords.INPUT_RESTORATION;
            Authorization sign = new Authorization(LabFixtures.INSTALLATION, args[4], plan.component, plan.planId,
                    Effect.SIGN, inputs, ActorClass.LAB_OPERATOR, DeploymentRecords.NO_USER, DeploymentRecords.NO_SERIAL,
                    DeploymentRecords.NO_ID, GrantScope.NONE, args[4], LabFixtures.TIME);
            if (!store.addAuthorization(sign)) throw new IllegalStateException("grant not written");
        }
    }

    private static void inspect(String[] args) {
        DeploymentStore store = new DeploymentStore(Paths.get(args[1]), LabFixtures.INSTALLATION);
        DeploymentStore.Read<Ticket> read = store.ticket(args[2]);
        if (read.found != Found.RECORD) throw new IllegalStateException("ticket unreadable");
        Ticket t = read.value;
        List<String> ledger = new ArrayList<>();
        for (Entry e : t.ledger) ledger.add(e.crossing.name());
        Selection s = store.selection(LabFixtures.COMPONENT).value;
        StringBuilder health = new StringBuilder();
        for (DeploymentRecords.Health h : t.health) {
            health.append(h.user).append('/').append(h.serial).append('/').append(h.outcome.name()).append(',');
        }
        System.out.println("state=" + t.state.name() + " flags=" + t.flags + " cause=" + t.cause.name()
                + " boots=" + t.bootCount + " ledger=" + String.join(",", ledger) + " session=" + t.reference.sessionId
                + " health=" + health + " choice=" + s.choice.name() + " plan=" + s.planId + " revision=" + s.revision
                + " realization=" + s.realization.name() + " observations=" + store.observations().values.size());
    }
}
