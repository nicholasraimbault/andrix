// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

import dev.andrix.server.deployment.DeploymentRecords;
import dev.andrix.server.deployment.DeploymentRecords.ActorClass;
import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.ChoiceKind;
import dev.andrix.server.deployment.DeploymentRecords.Crossing;
import dev.andrix.server.deployment.DeploymentRecords.Effect;
import dev.andrix.server.deployment.DeploymentRecords.Entry;
import dev.andrix.server.deployment.DeploymentRecords.GrantScope;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Realization;
import dev.andrix.server.deployment.DeploymentRecords.Selection;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import dev.andrix.server.deployment.DeploymentRecords.UpdateResponsibility;
import dev.andrix.server.deployment.DeploymentStore;
import dev.andrix.server.deployment.DeploymentStore.Found;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The coordinator process of the Python end to end suites, which run it as broker generations. It
 * is the lab entry with the scripted host wired in, plus operations outside any generation:
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
 * For the next campaign's driver it also takes the lab driver entry's command forms, each naming
 * the version 3 bridge configuration where the old forms name the store: {@code init3},
 * {@code plan} and {@code contradict} with the scripted world's fixture plan,
 * {@code ticket CONFIG}, and {@code baseline} and the three repair phases, which run
 * {@link LabRepair} exactly as the lab driver entry does, with the scripted host's publications in
 * place of the artifact store's. The repair the scripted world admits is the system property
 * andrix.lab.repair, the repair plan and the plan it repairs, in place of the version 2 host
 * configuration's line.
 *
 * The scripted host reads its directory and the plan's bound APKs from the system properties
 * andrix.lab.hostDir, andrix.lab.bundleApk and andrix.lab.restorationApk.
 */
public final class LabBridgeTestMain {
    private LabBridgeTestMain() {}

    public static void main(String[] args) throws Exception {
        String operation = args.length > 0 ? args[0] : "";
        boolean config = args.length > 1 && Files.isRegularFile(Paths.get(args[1]), LinkOption.NOFOLLOW_LINKS);
        if (operation.equals("setup") || operation.equals("setup3")) {
            setup(args);
        } else if (operation.equals("ticket") && config) {
            nextTicket(args);
        } else if (operation.equals("ticket")) {
            ticket(args);
        } else if (operation.equals("inspect")) {
            inspect(args);
        } else if (operation.equals("init3")) {
            init3(args);
        } else if (operation.equals("plan") || operation.equals("contradict")) {
            plan(args, operation.equals("contradict"));
        } else if (operation.equals("baseline")) {
            LabConfig lab = LabConfig.read(Paths.get(args[1]));
            LabRepair.Current c = LabRepair.current(store(lab), lab.component, args[2], args[3], publications(lab));
            System.out.println("plan=" + c.plan + " boot=" + c.boot + " fingerprint=" + c.fingerprint + " base=" + c.apk
                    + " version=" + c.version + " uid=" + c.uid + " context=" + c.context + " revision=" + c.revision);
        } else if (operation.equals("repair-plan")) {
            LabConfig lab = LabConfig.read(Paths.get(args[1]));
            requireRepair(args[2], args[3]);
            Plan plan = LabRepair.plan(store(lab), lab, args[2], args[3], args[4], Long.parseLong(args[5]),
                    publications(lab));
            System.out.println("plan=" + plan.planId + " repairs=" + plan.repairs + " signing=" + plan.signing);
        } else if (operation.equals("repair-grants")) {
            LabConfig lab = LabConfig.read(Paths.get(args[1]));
            requireRepair(args[2], null);
            LabRepair.grants(store(lab), lab, args[2], Arrays.asList(args).subList(4, args.length),
                    Long.parseLong(args[3]), new SecureRandom());
        } else if (operation.equals("repair-ticket")) {
            LabConfig lab = LabConfig.read(Paths.get(args[1]));
            requireRepair(args[2], null);
            LabRepair.ticket(store(lab), lab, args[2], args[3]);
        } else {
            LabBridge.HostFactory hosts = (store, configuration) -> new ScriptedHost(
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

    private static void inspect(String[] args) throws IOException {
        Path path = Paths.get(args[1]);
        DeploymentStore store = Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) ? store(LabConfig.read(path))
                : new DeploymentStore(path, LabFixtures.INSTALLATION);
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

    // ------------------------------------------------ the next campaign's driver, scripted world

    private static DeploymentStore store(LabConfig lab) {
        return new DeploymentStore(lab.store, lab.installation);
    }

    /** The next campaign's store and version 3 configuration, as the lab driver entry's init3. */
    private static void init3(String[] args) throws IOException {
        if (args.length != 8) throw new IllegalArgumentException("init3 DIR STORE MANIFEST INSTALLATION COORDINATOR TRUST NOW_MS");
        Path storeRoot = Paths.get(args[2]);
        byte[] config = LabConfig.encode(args[4], LabFixtures.COMPONENT, args[5], args[6], args[3], storeRoot,
                LabFixtures.HOST, LabConfig.PROFILE);
        DeploymentStore store = new DeploymentStore(storeRoot, args[4]);
        store.initialize();
        if (store.selection(LabFixtures.COMPONENT).found != Found.ABSENT) {
            throw new IllegalStateException("the store already holds a selection");
        }
        if (!store.putSelection(null, new Selection(args[4], LabFixtures.COMPONENT, 0, ChoiceKind.FACTORY,
                DeploymentRecords.NO_ID, UpdateResponsibility.REBUILD_WINDOW, 14 * LabFixtures.DAY, Realization.UNCHECKED,
                DeploymentRecords.NO_ID, DeploymentRecords.NO_ID, DeploymentRecords.NO_ID, Long.parseLong(args[7])))) {
            throw new IllegalStateException("the selection was not written");
        }
        Path path = Paths.get(args[1]).resolve("bridge.config");
        Files.write(path, config, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        System.out.println(LabConfig.read(path).digest);
    }

    /**
     * The scripted world's stand in for the lab driver entry's plan: the fixture plan, whose
     * cohort and base are the simulated guest's factory facts, with the design's starting values
     * and the given boot limit, its lab grants and its first ticket. As the cohort refusal control,
     * its cohort's factory copy has its last digit changed. The factory baseline's own guards are
     * the lab driver entry's, which its suite checks.
     */
    private static void plan(String[] args, boolean contradict) throws IOException {
        if (args.length != 7) throw new IllegalArgumentException("plan CONFIG PLAN TICKET BOOT_LIMIT NOW_MS T0");
        LabConfig lab = LabConfig.read(Paths.get(args[1]));
        DeploymentStore store = store(lab);
        long now = Long.parseLong(args[5]);
        String factory = LabFixtures.FACTORY_APK;
        if (contradict) factory = factory.substring(0, 63) + (factory.endsWith("0") ? "1" : "0");
        Plan plan = new Plan.Builder().installation(lab.installation).planId(args[2]).component(lab.component)
                .bundle(LabFixtures.BUNDLE_INPUT, LabFixtures.BUNDLE_VERSION).signer(LabFixtures.SIGNER)
                .restoration(LabFixtures.RESTORATION_INPUT, LabFixtures.RESTORATION_VERSION).signing(1)
                .cohort(LabFixtures.FINGERPRINT, factory, LabFixtures.FACTORY_VERSION)
                .base(LabFixtures.FACTORY_APK, LabFixtures.FACTORY_VERSION, LabFixtures.UID, LabFixtures.CONTEXT)
                .selectionRevision(0).trustPolicy(lab.trustPolicy).healthWindow(15 * 60_000L).notice(120_000, 120_000)
                .limits(Integer.parseInt(args[4]), 300_000, 3, LabFixtures.DAY, 600_000).createdAt(now).build();
        if (!store.addPlan(plan)) throw new IllegalStateException("the plan was not written");
        int inputs = DeploymentRecords.INPUT_VARIANT | DeploymentRecords.INPUT_RESTORATION;
        SecureRandom random = new SecureRandom();
        for (Effect effect : List.of(Effect.SIGN, Effect.STAGE, Effect.ACTIVATE)) {
            grant(store, lab, plan, effect, effect == Effect.SIGN ? inputs : 0, now, random);
        }
        create(store, lab, plan, args[3]);
        System.out.println("plan=" + plan.planId + " boot=" + args[6]);
    }

    /** The plan's next attempt, as the lab driver entry's ticket command makes it. */
    private static void nextTicket(String[] args) throws IOException {
        List<String> options = Arrays.asList(args).subList(Math.min(5, args.length), args.length);
        if (args.length < 5 || !List.of("sign", "activate").containsAll(options)) {
            throw new IllegalArgumentException("ticket CONFIG PLAN TICKET NOW_MS [sign] [activate]");
        }
        LabConfig lab = LabConfig.read(Paths.get(args[1]));
        DeploymentStore store = store(lab);
        Plan plan = store.plan(args[2]).value;
        if (plan == null || !plan.repairs.equals(DeploymentRecords.NO_ID)) {
            throw new IllegalStateException("not a plan whose attempts this command makes");
        }
        long now = Long.parseLong(args[4]);
        SecureRandom random = new SecureRandom();
        grant(store, lab, plan, Effect.STAGE, 0, now, random);
        if (options.contains("sign")) {
            grant(store, lab, plan, Effect.SIGN, DeploymentRecords.INPUT_VARIANT | DeploymentRecords.INPUT_RESTORATION, now,
                    random);
        }
        if (options.contains("activate")) grant(store, lab, plan, Effect.ACTIVATE, 0, now, random);
        create(store, lab, plan, args[3]);
    }

    private static void grant(DeploymentStore store, LabConfig lab, Plan plan, Effect effect, int inputs, long at,
            SecureRandom random) {
        Authorization a = new Authorization(lab.installation, id(random), lab.component, plan.planId, effect, inputs,
                ActorClass.LAB_OPERATOR, DeploymentRecords.NO_USER, DeploymentRecords.NO_SERIAL, DeploymentRecords.NO_ID,
                GrantScope.NONE, id(random), at);
        if (!store.addAuthorization(a)) throw new IllegalStateException("the grant was not written");
    }

    private static void create(DeploymentStore store, LabConfig lab, Plan plan, String ticketId) {
        Ticket ticket = new Ticket.Builder().installation(lab.installation).ticketId(ticketId).component(plan.component)
                .planId(plan.planId).attempt(store.ticketsOf(plan.planId).size() + 1)
                .coordinator(DeploymentRecords.CoordinatorClass.HOST, lab.coordinator).build();
        if (!store.createTicket(ticket)) throw new IllegalStateException("the ticket was not written");
    }

    private static String id(SecureRandom random) {
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        bytes[0] |= 1;
        return LabProtocol.hex(bytes);
    }

    /** The scripted world's admitted repair: the property's repair, and its plan when named. */
    private static void requireRepair(String repair, String repaired) {
        String[] admitted = System.getProperty("andrix.lab.repair", "").split(" ", -1);
        if (admitted.length != 2 || !admitted[0].equals(repair) || (repaired != null && !admitted[1].equals(repaired))) {
            throw new IllegalStateException("the scripted world does not admit this repair of this plan");
        }
    }

    /**
     * The scripted host's publications: a plan reads published once one of its tickets made a
     * PUBLISH whose call the scripted host completed. A repair plan that signs nothing binds the
     * restoration of the plan it repairs as its one bundle; any other plan binds both APKs.
     */
    private static LabRepair.Publications publications(LabConfig lab) {
        Path dir = Paths.get(System.getProperty("andrix.lab.hostDir"));
        String bundle = System.getProperty("andrix.lab.bundleApk");
        String restoration = System.getProperty("andrix.lab.restorationApk");
        DeploymentStore store = store(lab);
        return planId -> {
            DeploymentStore.Read<Plan> plan = store.plan(planId);
            if (plan.found != Found.RECORD) return null;
            boolean published = false;
            for (Ticket t : store.ticketsOf(planId)) {
                for (Entry e : t.ledger) {
                    published |= e.crossing == Crossing.PUBLISH && Files.exists(dir.resolve("publish-" + e.reference));
                }
            }
            if (!published) return null;
            boolean repair = plan.value.signing == 0 && !plan.value.repairs.equals(DeploymentRecords.NO_ID);
            return repair ? List.of(restoration) : List.of(bundle, restoration);
        };
    }
}
