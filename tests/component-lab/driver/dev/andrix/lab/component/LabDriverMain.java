// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

import dev.andrix.server.deployment.ApkEntries;
import dev.andrix.server.deployment.ArtifactRecords;
import dev.andrix.server.deployment.ArtifactStore;
import dev.andrix.server.deployment.DeploymentRecords;
import dev.andrix.server.deployment.DeploymentRecords.ActorClass;
import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.ChoiceKind;
import dev.andrix.server.deployment.DeploymentRecords.Classification;
import dev.andrix.server.deployment.DeploymentRecords.CoordinatorClass;
import dev.andrix.server.deployment.DeploymentRecords.Effect;
import dev.andrix.server.deployment.DeploymentRecords.Entry;
import dev.andrix.server.deployment.DeploymentRecords.GrantScope;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Realization;
import dev.andrix.server.deployment.DeploymentRecords.Selection;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import dev.andrix.server.deployment.DeploymentRecords.UpdateResponsibility;
import dev.andrix.server.deployment.DeploymentStore;
import dev.andrix.server.deployment.DeploymentStore.Found;
import dev.andrix.server.deployment.HostSigner;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.TreeSet;

/**
 * The lab driver's coordinator process: the lab entry with the real host wired in, and the store's
 * setup outside any generation. The lab driver runs each of these as its own process.
 *
 * <pre>
 * init DIR STORE MANIFEST INSTALLATION COORDINATOR TRUST NOW_MS   the store with the factory choice and the version 2
 *                                                                 configuration binding the host; prints its digest
 * selection CONFIG                                               the component's selection: choice, revision, realization, checked boot
 * plan CONFIG PLAN TICKET BOOT_LIMIT NOW_MS T0                    the immutable plan from the T0 boot's facts, its grants and first ticket
 * contradict CONFIG PLAN TICKET BOOT_LIMIT NOW_MS T0              the cohort refusal control: as plan, its cohort's factory copy changed
 * ticket CONFIG PLAN TICKET NOW_MS [sign] [activate]             the plan's next attempt, with a fresh STAGE grant, and a fresh
 *                                                                 SIGN for both inputs or ACTIVATE when asked
 * published CONFIG PLAN OUTDIR                                   the published variant's two members, written for the broker to
 *                                                                 pin; exit 3, writing nothing, while there is no publication yet
 * inspect CONFIG TICKET                                          one line of key=value facts
 * tickets CONFIG PLAN                                            the plan's tickets in attempt order, one line each:
 *                                                                 ticket=ID attempt=N state=STATE
 * CONFIG check | round T | settle T N | cancel T | report T     a generation
 * </pre>
 *
 * Every command after {@code init} reads the bridge configuration only when its exact digest is the
 * one the broker's admission binds, which the lab driver passes from the admission the broker opened as
 * the system property andrix.lab.admittedConfig. {@code init}, {@code plan}, {@code published} and a
 * generation also need the lab host configuration that the system properties name ({@link LabHost}),
 * and refuse one that the bridge configuration does not bind; {@code ticket}, {@code selection} and
 * {@code inspect} only read or write records. A plan is made only after a cohort check of the guest as
 * it is. Its cohort and base are the facts of T0, the boot that the driver's own check established
 * from that generation's reads and names: the selection must record that
 * boot as checked, the store must hold facts of no other boot (nothing in the records orders boots, so
 * wall time never chooses one), and the plan is refused when T0's facts are missing, disagree, show a
 * pending checkpoint or a data copy, or when the selection is not the factory choice found current at
 * revision 0. The signing inputs' entry digests and version codes come from the
 * pinned input APKs themselves, through apksig's manifest parser. The time is the driver's, so that
 * the records carry one clock. Nothing here starts a guest or reads the device.
 */
public final class LabDriverMain {
    /** The design's starting values: a 15 minute health window, 2 minute notice delays, request limit 3,
     *  a 5 minute reboot timeout, a 24 hour ACTIVATE window and a 10 minute verification wait. */
    static final long HEALTH_WINDOW = 15 * 60_000L, NOTICE_DELAY = 2 * 60_000L, REBOOT_TIME = 5 * 60_000L;
    static final long ACTIVATE_WINDOW = 24 * 3600_000L, VERIFICATION_WAIT = 10 * 60_000L;
    static final int REQUEST_LIMIT = 3;
    /** The exit of {@code published} while the plan's publication does not read PUBLISHED. */
    static final int NOT_PUBLISHED = 3;
    /** Decision 6's declared rebuild window, two weeks. */
    static final long REBUILD_WINDOW = 14 * 24 * 3600_000L;

    private LabDriverMain() {}

    public static void main(String[] args) throws Exception {
        String operation = args.length > 0 ? args[0] : "";
        switch (operation) {
            case "init":
                init(args);
                break;
            case "plan":
                plan(args, false);
                break;
            case "contradict":
                plan(args, true);
                break;
            case "tickets":
                tickets(args);
                break;
            case "selection":
                selection(args);
                break;
            case "ticket":
                ticket(args);
                break;
            case "inspect":
                inspect(args);
                break;
            case "published":
                published(args);
                break;
            default:
                System.exit(LabBridge.run(args, LabHost.fromProperties()));
        }
    }

    /** The system property that carries the admitted bridge configuration's digest. */
    static final String ADMITTED_PROPERTY = "andrix.lab.admittedConfig";

    /**
     * The bridge configuration at the path, refused unless its exact digest is the one the broker's
     * admission binds. The digest comes from the admission, never from the file, so a configuration
     * replaced together with the host configuration it names is refused before any record is written.
     */
    static LabConfig admitted(String path, String admittedDigest) throws IOException {
        need(admittedDigest != null, "the admitted bridge configuration digest is not given");
        LabConfig lab = LabConfig.read(Paths.get(path));
        need(lab.digest.equals(admittedDigest), "the bridge configuration is not the one the admission binds");
        return lab;
    }

    private static LabConfig admitted(String path) throws IOException {
        return admitted(path, System.getProperty(ADMITTED_PROPERTY));
    }

    private static void need(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    private static long time(String value) {
        long t = Long.parseLong(value);
        need(t > 0, "a positive time");
        return t;
    }

    private static void init(String[] args) throws IOException {
        need(args.length == 8, "init DIR STORE MANIFEST INSTALLATION COORDINATOR TRUST NOW_MS");
        LabHost host = LabHost.fromProperties();
        need(host != null, "the configuration binds the lab host configuration");
        Path dir = Paths.get(args[1]);
        Path storeRoot = Paths.get(args[2]);
        byte[] config = LabConfig.encode(args[4], "com.android.systemui", args[5], args[6], args[3], storeRoot,
                host.config().digest);
        DeploymentStore store = new DeploymentStore(storeRoot, args[4]);
        store.initialize();
        need(store.selection("com.android.systemui").found == Found.ABSENT, "the store already holds a selection");
        need(store.putSelection(null, new Selection(args[4], "com.android.systemui", 0, ChoiceKind.FACTORY,
                DeploymentRecords.NO_ID, UpdateResponsibility.REBUILD_WINDOW, REBUILD_WINDOW, Realization.UNCHECKED,
                DeploymentRecords.NO_ID, DeploymentRecords.NO_ID, DeploymentRecords.NO_ID, time(args[7]))),
                "the selection was not written");
        Path path = dir.resolve("bridge.config");
        Files.write(path, config, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        System.out.println(LabConfig.read(path).digest);
    }

    /** The cohort and active copy of the T0 boot, exactly as observed. */
    static final class Baseline {
        final String boot, fingerprint, apk, context;
        final long version;
        final int uid;

        Baseline(String boot, String fingerprint, String apk, long version, int uid, String context) {
            this.boot = boot;
            this.fingerprint = fingerprint;
            this.apk = apk;
            this.version = version;
            this.uid = uid;
            this.context = context;
        }
    }

    /**
     * The facts of T0, the boot that the driver's completed check established ({@code t0}), which the
     * selection must record as checked ({@code checked}). The store may hold facts of no other boot:
     * nothing in the records orders boots, so another boot's facts could as well be later than T0's,
     * and wall time, which is informational, orders nothing here.
     */
    static Baseline baseline(DeploymentStore store, String component, String checked, String t0) {
        DeploymentStore.Listing<Observation> listing = store.observations();
        need(listing.footprints.isEmpty() && listing.newer.isEmpty(), "the store holds unreadable or newer observations");
        need(!checked.equals(DeploymentRecords.NO_ID), "the selection names no checked boot: check the guest first");
        need(checked.equals(t0), "the selection's checked boot is not the boot the driver's check established");
        TreeSet<String> others = new TreeSet<>();
        for (Observation o : listing.values) {
            if (!o.boot.equals(t0)) others.add(o.boot);
        }
        need(others.isEmpty(), "the store holds facts of another boot, so the baseline's boot is not established: " + others);
        TreeSet<String> fingerprints = new TreeSet<>(), factories = new TreeSet<>(), actives = new TreeSet<>();
        boolean committed = false;
        Observation active = null;
        for (Observation o : listing.values) {
            switch (o.classification) {
                case BOOT_COMPLETED:
                    fingerprints.add(o.text);
                    break;
                case CHECKPOINT_COMMITTED:
                    committed = true;
                    break;
                case CHECKPOINT_PENDING:
                    throw new IllegalStateException("the baseline boot has a pending checkpoint");
                case FACTORY_PRESENT:
                    if (o.component.equals(component)) factories.add(o.digest + " " + o.version);
                    break;
                case FACTORY_COPY:
                    if (o.component.equals(component)) {
                        actives.add(o.digest + " " + o.version + " " + o.number + " " + o.text);
                        active = o;
                    }
                    break;
                case DATA_COPY:
                    if (o.component.equals(component)) throw new IllegalStateException("a data copy is active at the baseline");
                    break;
                default:
                    break;
            }
        }
        need(committed, "no committed checkpoint is observed in the baseline boot");
        need(fingerprints.size() == 1, "the checked boot's completed fingerprint is not one value: " + fingerprints);
        need(factories.size() == 1, "the factory copy is not one observed value: " + factories);
        need(actives.size() == 1 && active != null, "the active copy is not one observed value: " + actives);
        need(factories.first().equals(active.digest + " " + active.version), "the active copy is not the factory copy");
        return new Baseline(t0, fingerprints.first(), active.digest, active.version, active.number, active.text);
    }

    /** The digest with its last hexadecimal digit changed: a factory copy no guest fact names. */
    static String otherDigest(String digest) {
        char last = digest.charAt(digest.length() - 1);
        return digest.substring(0, digest.length() - 1) + (last == '0' ? '1' : '0');
    }

    /** The selection a plan is made from: the factory choice, found current, at revision 0. */
    static boolean factoryCurrent(Selection s) {
        return s.choice == ChoiceKind.FACTORY && s.revision == 0 && s.realization == Realization.CURRENT;
    }

    private static Authorization grant(SecureRandom random, LabConfig lab, String planId, Effect effect, int inputs,
            long at) {
        return new Authorization(lab.installation, freshId(random), lab.component, planId, effect, inputs,
                ActorClass.LAB_OPERATOR, DeploymentRecords.NO_USER, DeploymentRecords.NO_SERIAL, DeploymentRecords.NO_ID,
                GrantScope.NONE, freshId(random), at);
    }

    /**
     * The immutable plan from T0's facts, its grants and its first ticket. As the lab's cohort refusal
     * control ({@code contradict}), the plan's cohort names a factory copy T0's facts contradict, one
     * digit changed, so that its ticket must close before any crossing.
     */
    private static void plan(String[] args, boolean contradict) throws IOException {
        need(args.length == 7, (contradict ? "contradict" : "plan") + " CONFIG PLAN TICKET BOOT_LIMIT NOW_MS T0");
        LabProtocol.checkHex(args[6], 16, "T0 boot", false);
        LabConfig lab = admitted(args[1]);
        LabHost host = LabHost.fromProperties();
        need(host != null, "a plan needs the lab host configuration");
        host.requireBoundBy(lab);
        LabHost.Config hc = host.config();
        String planId = args[2];
        need(hc.plans.contains(planId), "the host configuration does not admit this plan");
        int bootLimit = Integer.parseInt(args[4]);
        need(bootLimit >= 1 && bootLimit <= 32, "the boot limit is 1 to 32");
        long now = time(args[5]);
        DeploymentStore store = new DeploymentStore(lab.store, lab.installation);
        DeploymentStore.Read<Selection> selection = store.selection(lab.component);
        need(selection.found == Found.RECORD && factoryCurrent(selection.value), "the factory choice is not found current at revision 0");
        need(store.plan(planId).found == Found.ABSENT, "the plan already exists");
        Baseline base = baseline(store, lab.component, selection.value.checkedBoot, args[6]);
        // The inputs' own manifest facts give their version codes; the builder checks them again at signing.
        host.checkInputs();
        byte[] variant = host.variant(), restoration = host.restoration();
        HostSigner.Facts variantFacts = host.facts(variant), restorationFacts = host.facts(restoration);
        need(variantFacts != null && restorationFacts != null && variantFacts.packageName.equals(lab.component)
                && restorationFacts.packageName.equals(lab.component), "an input is not the component's APK");
        need(variantFacts.versionCode > base.version && restorationFacts.versionCode > variantFacts.versionCode,
                "the inputs' versions do not rise above the factory copy, the restoration above the variant");
        Plan plan = new Plan.Builder().installation(lab.installation).planId(planId).component(lab.component)
                .bundle(ApkEntries.digest(variant), variantFacts.versionCode).signer(hc.role.certificate)
                .restoration(ApkEntries.digest(restoration), restorationFacts.versionCode).signing(1)
                .cohort(base.fingerprint, contradict ? otherDigest(base.apk) : base.apk, base.version)
                .base(base.apk, base.version, base.uid, base.context)
                .selectionRevision(selection.value.revision).trustPolicy(lab.trustPolicy).healthWindow(HEALTH_WINDOW)
                .notice(NOTICE_DELAY, NOTICE_DELAY).limits(bootLimit, REBOOT_TIME, REQUEST_LIMIT, ACTIVATE_WINDOW,
                        VERIFICATION_WAIT).createdAt(now).build();
        SecureRandom random = new SecureRandom();
        need(store.addPlan(plan), "the plan was not written");
        int inputs = DeploymentRecords.INPUT_VARIANT | DeploymentRecords.INPUT_RESTORATION;
        need(store.addAuthorization(grant(random, lab, planId, Effect.SIGN, inputs, now)), "the SIGN grant was not written");
        need(store.addAuthorization(grant(random, lab, planId, Effect.STAGE, 0, now)), "the STAGE grant was not written");
        need(store.addAuthorization(grant(random, lab, planId, Effect.ACTIVATE, 0, now)), "the ACTIVATE grant was not written");
        createTicket(store, lab, plan, args[3]);
        System.out.println("plan=" + planId + " boot=" + base.boot + " fingerprint=" + base.fingerprint + " base=" + base.apk
                + " version=" + base.version + " uid=" + base.uid + " context=" + base.context + " variant="
                + plan.bundleInput + "/" + plan.bundleVersion + " restoration=" + plan.restorationInput + "/"
                + plan.restorationVersion);
    }

    private static void createTicket(DeploymentStore store, LabConfig lab, Plan plan, String ticketId) {
        Ticket ticket = new Ticket.Builder().installation(lab.installation).ticketId(ticketId).component(plan.component)
                .planId(plan.planId).attempt(store.ticketsOf(plan.planId).size() + 1)
                .coordinator(CoordinatorClass.HOST, lab.coordinator).build();
        need(store.createTicket(ticket), "the ticket was not written");
    }

    private static void ticket(String[] args) throws IOException {
        List<String> options = Arrays.asList(args).subList(Math.min(5, args.length), args.length);
        need(args.length >= 5 && new java.util.HashSet<>(options).size() == options.size()
                && List.of("sign", "activate").containsAll(options), "ticket CONFIG PLAN TICKET NOW_MS [sign] [activate]");
        LabConfig lab = admitted(args[1]);
        DeploymentStore store = new DeploymentStore(lab.store, lab.installation);
        DeploymentStore.Read<Plan> plan = store.plan(args[2]);
        need(plan.found == Found.RECORD, "the plan cannot be read");
        long now = time(args[4]);
        SecureRandom random = new SecureRandom();
        need(store.addAuthorization(grant(random, lab, plan.value.planId, Effect.STAGE, 0, now)), "the STAGE grant was not written");
        // A SIGN grant serves one signing transaction; an attempt that must sign again needs its own.
        if (options.contains("sign")) {
            int inputs = DeploymentRecords.INPUT_VARIANT | DeploymentRecords.INPUT_RESTORATION;
            need(store.addAuthorization(grant(random, lab, plan.value.planId, Effect.SIGN, inputs, now)), "the SIGN grant was not written");
        }
        if (options.contains("activate")) {
            need(store.addAuthorization(grant(random, lab, plan.value.planId, Effect.ACTIVATE, 0, now)),
                    "the ACTIVATE grant was not written");
        }
        createTicket(store, lab, plan.value, args[3]);
    }

    /**
     * The plan's published variant, read back through the artifact store as the coordinator's own
     * read would: its base.apk, whose digest must be the publication's first APK, and its sidecar.
     * Each is written to a new file and printed with its SHA-256 and size, for the broker to pin.
     */
    private static void published(String[] args) throws IOException {
        need(args.length == 4, "published CONFIG PLAN OUTDIR");
        LabConfig lab = admitted(args[1]);
        LabHost host = LabHost.fromProperties();
        need(host != null, "the publication is read through the lab host configuration");
        host.requireBoundBy(lab);
        ArtifactStore artifacts = new ArtifactStore(host.config().artifacts, lab.installation);
        ArtifactStore.Presence presence = artifacts.planPublication(args[2]);
        if (presence == ArtifactStore.Presence.ABSENT) {
            // Not published yet: the coordinator may still publish it, and nothing is written here.
            System.err.println("the plan has no publication yet");
            System.exit(NOT_PUBLISHED);
        }
        // A publication that is there but mismatched or unreadable is a failure, never a wait.
        need(presence == ArtifactStore.Presence.PUBLISHED, "the plan's publication reads " + presence);
        List<String> apks = artifacts.apks(args[2]);
        ArtifactRecords.Publication publication = artifacts.publication(args[2]);
        need(apks != null && !apks.isEmpty() && publication != null && !publication.bundles.isEmpty(),
                "the plan's publication reads PUBLISHED but cannot be read whole");
        List<byte[]> members = artifacts.members(publication.bundles.get(0));
        need(members != null && members.size() == 2 && DeploymentRecords.sha256Hex(members.get(0)).equals(apks.get(0)),
                "the variant bundle cannot be read whole");
        Path out = Paths.get(args[3]);
        String[] names = {"base.apk", "base.apk.idsig"};
        for (int i = 0; i < names.length; i++) {
            Files.write(out.resolve(names[i]), members.get(i), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            System.out.println(names[i] + " " + DeploymentRecords.sha256Hex(members.get(i)) + " " + members.get(i).length);
        }
    }

    private static void selection(String[] args) throws IOException {
        need(args.length == 2, "selection CONFIG");
        LabConfig lab = admitted(args[1]);
        DeploymentStore store = new DeploymentStore(lab.store, lab.installation);
        DeploymentStore.Read<Selection> read = store.selection(lab.component);
        need(read.found == Found.RECORD, "the selection cannot be read");
        Selection s = read.value;
        System.out.println("choice=" + s.choice.name() + " revision=" + s.revision + " realization=" + s.realization.name()
                + " checked=" + s.checkedBoot);
    }

    private static void inspect(String[] args) throws IOException {
        need(args.length == 3, "inspect CONFIG TICKET");
        LabConfig lab = admitted(args[1]);
        DeploymentStore store = new DeploymentStore(lab.store, lab.installation);
        DeploymentStore.Read<Ticket> read = store.ticket(args[2]);
        need(read.found == Found.RECORD, "the ticket cannot be read");
        Ticket t = read.value;
        List<String> ledger = new ArrayList<>();
        for (Entry e : t.ledger) ledger.add(e.crossing.name());
        Selection s = store.selection(lab.component).value;
        StringBuilder health = new StringBuilder();
        for (DeploymentRecords.Health h : t.health) {
            health.append(h.user).append('/').append(h.serial).append('/').append(h.outcome.name()).append(',');
        }
        System.out.println("state=" + t.state.name() + " flags=" + t.flags + " cause=" + t.cause.name() + " boots="
                + t.bootCount + " ledger=" + String.join(",", ledger) + " session=" + t.reference.sessionId + " health="
                + health + " choice=" + s.choice.name() + " plan=" + s.planId + " revision=" + s.revision + " realization="
                + s.realization.name() + " observations=" + store.observations().values.size());
    }

    /** The plan's tickets as the store holds them, in attempt order: ID, attempt and state. */
    private static void tickets(String[] args) throws IOException {
        need(args.length == 3, "tickets CONFIG PLAN");
        LabConfig lab = admitted(args[1]);
        DeploymentStore store = new DeploymentStore(lab.store, lab.installation);
        need(store.plan(args[2]).found == Found.RECORD, "the plan cannot be read");
        List<Ticket> tickets = new ArrayList<>(store.ticketsOf(args[2]));
        tickets.sort(java.util.Comparator.comparingInt(t -> t.attempt));
        for (Ticket t : tickets) {
            System.out.println("ticket=" + t.ticketId + " attempt=" + t.attempt + " state=" + t.state.name());
        }
    }

    private static String freshId(SecureRandom random) {
        while (true) {
            byte[] bytes = new byte[16];
            random.nextBytes(bytes);
            String id = LabProtocol.hex(bytes);
            if (!id.equals(LabProtocol.ZERO_ID)) return id;
        }
    }
}
