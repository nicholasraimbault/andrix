// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

import dev.andrix.server.deployment.DeploymentRecords;
import dev.andrix.server.deployment.DeploymentRecords.ActorClass;
import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.Cause;
import dev.andrix.server.deployment.DeploymentRecords.ChoiceKind;
import dev.andrix.server.deployment.DeploymentRecords.Classification;
import dev.andrix.server.deployment.DeploymentRecords.CoordinatorClass;
import dev.andrix.server.deployment.DeploymentRecords.Effect;
import dev.andrix.server.deployment.DeploymentRecords.GrantScope;
import dev.andrix.server.deployment.DeploymentRecords.HealthResponse;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Realization;
import dev.andrix.server.deployment.DeploymentRecords.Route;
import dev.andrix.server.deployment.DeploymentRecords.Selection;
import dev.andrix.server.deployment.DeploymentRecords.State;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import dev.andrix.server.deployment.DeploymentStore;
import dev.andrix.server.deployment.DeploymentStore.Found;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Host checks of the next campaign's repair records ({@link LabRepair}): the current baseline from
 * the facts of the newest checked boot alone and each of its refusals, the repair plan the study's
 * row names, its grants by explicit approval only, its ticket, and that a phase cut short
 * authorizes nothing missing. Records are written through the deployment package's public API.
 * No guest, signer or Android is used. Argument: a scratch directory.
 */
public final class RepairTest {
    private static final String A = "0d".repeat(16), R = "0f".repeat(16), OTHER = "0e".repeat(16);
    private static final String BOOT_1 = "b1".repeat(16), BOOT_2 = "b2".repeat(16), BOOT_3 = "b3".repeat(16);
    private static final String VARIANT_APK = "a1".repeat(32), RESTORATION_APK = "a2".repeat(32);
    private static final String DATA_CONTEXT = "u:r:platform_app:s0:c512,c768";
    private static final int DATA_UID = 10112;
    private static int failures;
    private static long ids = 0x900;
    private static Path scratch;
    private static int stores;

    private interface Case {
        void run() throws Exception;
    }

    private RepairTest() {}

    /** Runs named cases and prints PASS or FAIL lines, the lab runner's form. */
    private static final class Cases {
        void run(String name, Case c) {
            try {
                c.run();
                System.out.println("PASS " + name);
            } catch (Throwable t) {
                failures++;
                System.out.println("FAIL " + name + ": " + t);
            }
        }
    }

    private static final Cases cases = new Cases();

    private static void check(boolean ok, String what) {
        if (!ok) throw new AssertionError(what);
    }

    /** The case is refused, for the reason the fragment names. */
    private static void refuses(String fragment, Case c) throws Exception {
        try {
            c.run();
        } catch (IllegalStateException | IllegalArgumentException | IOException e) {
            check(e.getMessage() != null && e.getMessage().contains(fragment), "refused for another reason: " + e.getMessage());
            return;
        }
        throw new AssertionError("not refused: " + fragment);
    }

    private static String id(long n) {
        return String.format("%032x", n);
    }

    private static LabConfig lab(Path store) {
        return LabConfig.parse(LabConfig.encode(LabFixtures.INSTALLATION, LabFixtures.COMPONENT, LabFixtures.COORDINATOR,
                LabFixtures.TRUST, "aa".repeat(32), store, LabFixtures.HOST, LabConfig.PROFILE));
    }

    private static Observation.Builder fact(String boot, Classification c, long elapsed, long wall) {
        return new Observation.Builder().installation(LabFixtures.INSTALLATION).observationId(id(ids++)).boot(boot)
                .route(Route.SHELL).raw("99".repeat(32)).classification(c).at(-1, elapsed, wall);
    }

    private static Observation completed(String boot, long elapsed, long wall, String fingerprint) {
        return fact(boot, Classification.BOOT_COMPLETED, elapsed, wall).text(fingerprint).build();
    }

    private static Observation checkpoint(String boot, long elapsed, Classification c) {
        return fact(boot, c, elapsed, LabFixtures.TIME + elapsed).build();
    }

    private static Observation factory(String boot, long elapsed, String apk, long version) {
        return fact(boot, Classification.FACTORY_PRESENT, elapsed, LabFixtures.TIME + elapsed)
                .component(LabFixtures.COMPONENT).digest(apk).version(version).build();
    }

    private static Observation active(String boot, long elapsed, Classification c, String apk, long version, int uid) {
        return fact(boot, c, elapsed, LabFixtures.TIME + elapsed).component(LabFixtures.COMPONENT).digest(apk)
                .version(version).number(uid).text(DATA_CONTEXT).build();
    }

    /** The first boot, the factory copy active, then the activation boot, the variant active. */
    private static List<Observation> history() {
        List<Observation> facts = new ArrayList<>();
        // The first boot's facts carry later wall times than the second's: time chooses nothing.
        facts.add(completed(BOOT_1, 9000, LabFixtures.TIME + 99_000_000, LabFixtures.FINGERPRINT));
        facts.add(checkpoint(BOOT_1, 9000, Classification.CHECKPOINT_COMMITTED));
        facts.add(factory(BOOT_1, 9000, LabFixtures.FACTORY_APK, LabFixtures.FACTORY_VERSION));
        facts.add(active(BOOT_1, 9000, Classification.FACTORY_COPY, LabFixtures.FACTORY_APK, LabFixtures.FACTORY_VERSION,
                LabFixtures.UID));
        facts.add(completed(BOOT_2, 1000, LabFixtures.TIME, LabFixtures.FINGERPRINT));
        facts.add(checkpoint(BOOT_2, 1000, Classification.CHECKPOINT_PENDING));
        facts.add(checkpoint(BOOT_2, 2000, Classification.CHECKPOINT_COMMITTED));
        facts.add(factory(BOOT_2, 1000, LabFixtures.FACTORY_APK, LabFixtures.FACTORY_VERSION));
        facts.add(active(BOOT_2, 1000, Classification.DATA_COPY, VARIANT_APK, LabFixtures.BUNDLE_VERSION, DATA_UID));
        return facts;
    }

    /** A store after the plan applied: the plan, a terminal ticket, its move checked in BOOT_2. */
    private static DeploymentStore store(List<Observation> facts, Consumer<Plan.Builder> change) throws IOException {
        DeploymentStore store = new DeploymentStore(scratch.resolve("store-" + (++stores)), LabFixtures.INSTALLATION);
        store.initialize();
        Plan.Builder builder = LabFixtures.plan(A, 900_000).toBuilder();
        if (change != null) change.accept(builder);
        Plan plan = builder.build();
        check(store.addPlan(plan), "the plan was written");
        Selection first = LabFixtures.initialSelection();
        check(store.putSelection(null, first), "the first selection was written");
        check(store.putSelection(first, first.chosen(ChoiceKind.PLAN, A, Realization.CURRENT, BOOT_2, LabFixtures.TIME)),
                "the plan's move was written");
        Ticket ticket = new Ticket.Builder().installation(LabFixtures.INSTALLATION).ticketId(id(0x700)).component(
                LabFixtures.COMPONENT).planId(A).attempt(1).coordinator(CoordinatorClass.HOST, LabFixtures.COORDINATOR).build();
        check(store.createTicket(ticket), "the ticket was written");
        check(store.updateTicket(ticket, ticket.toBuilder().state(State.VOID).cause(Cause.VOID_BASE).build()),
                "the ticket closed");
        for (Observation o : facts) check(store.addObservation(o), "an observation was written");
        return store;
    }

    private static LabRepair.Publications published() {
        return plan -> plan.equals(A) ? List.of(VARIANT_APK, RESTORATION_APK) : null;
    }

    private static List<Observation> without(List<Observation> facts, Classification c, String boot) {
        List<Observation> kept = new ArrayList<>();
        for (Observation o : facts) if (!(o.classification == c && o.boot.equals(boot))) kept.add(o);
        return kept;
    }

    private static List<Observation> with(List<Observation> facts, Observation extra) {
        List<Observation> all = new ArrayList<>(facts);
        all.add(extra);
        return all;
    }

    public static void main(String[] args) throws Exception {
        scratch = Files.createTempDirectory(Paths.get(args[0]), "repair");

        cases.run("current / only the checked boot's facts, whatever the other boots and wall times", () -> {
            DeploymentStore store = store(history(), null);
            LabRepair.Current c = LabRepair.current(store, LabFixtures.COMPONENT, A, BOOT_2, published());
            check(c.boot.equals(BOOT_2) && c.apk.equals(VARIANT_APK) && c.version == LabFixtures.BUNDLE_VERSION
                    && c.uid == DATA_UID && c.context.equals(DATA_CONTEXT) && c.revision == 1
                    && c.fingerprint.equals(LabFixtures.FINGERPRINT), "the second boot's own facts");
            // The first boot is never chosen by its later wall time, nor named by the selection.
            refuses("is not the boot the driver's last check established",
                    () -> LabRepair.current(store, LabFixtures.COMPONENT, A, BOOT_1, published()));
        });
        cases.run("current / a boot of no facts, or another boot named, is refused", () -> {
            DeploymentStore store = store(history(), null);
            refuses("is not the boot", () -> LabRepair.current(store, LabFixtures.COMPONENT, A, BOOT_3, published()));
            refuses("is zero", () -> LabRepair.current(store, LabFixtures.COMPONENT, A, "00".repeat(16), published()));
        });
        cases.run("current / the selection must be the plan's own move found current", () -> {
            DeploymentStore unchosen = new DeploymentStore(scratch.resolve("unchosen"), LabFixtures.INSTALLATION);
            unchosen.initialize();
            check(unchosen.addPlan(LabFixtures.plan(A, 900_000)), "plan");
            check(unchosen.putSelection(null, LabFixtures.initialSelection()), "selection");
            refuses("does not choose the plan", () -> LabRepair.current(unchosen, LabFixtures.COMPONENT, A, BOOT_2, published()));
            DeploymentStore store = store(history(), null);
            Selection s = store.selection(LabFixtures.COMPONENT).value;
            check(store.putSelection(s, s.realized(Realization.STALE_BASE, BOOT_2, DeploymentRecords.NO_ID,
                    DeploymentRecords.NO_ID)), "stale");
            refuses("is not found current", () -> LabRepair.current(store, LabFixtures.COMPONENT, A, BOOT_2, published()));
            DeploymentStore moved = store(history(), b -> b.selectionRevision(1));
            refuses("is not the plan's own move", () -> LabRepair.current(moved, LabFixtures.COMPONENT, A, BOOT_2, published()));
        });
        cases.run("current / an open ticket or an unread publication is refused", () -> {
            DeploymentStore store = store(history(), null);
            refuses("does not read published", () -> LabRepair.current(store, LabFixtures.COMPONENT, A, BOOT_2, p -> null));
            Ticket open = new Ticket.Builder().installation(LabFixtures.INSTALLATION).ticketId(id(0x701)).component(
                    LabFixtures.COMPONENT).planId(A).attempt(2).coordinator(CoordinatorClass.HOST, LabFixtures.COORDINATOR)
                    .build();
            check(store.createTicket(open), "an open ticket");
            refuses("a ticket of the component is open", () -> LabRepair.current(store, LabFixtures.COMPONENT, A, BOOT_2,
                    published()));
        });
        cases.run("current / the checkpoint's latest fact in the boot must be committed", () -> {
            DeploymentStore none = store(without(history(), Classification.CHECKPOINT_COMMITTED, BOOT_2), null);
            refuses("no committed checkpoint", () -> LabRepair.current(none, LabFixtures.COMPONENT, A, BOOT_2, published()));
            DeploymentStore late = store(with(history(), checkpoint(BOOT_2, 3000, Classification.CHECKPOINT_PENDING)), null);
            refuses("a pending checkpoint", () -> LabRepair.current(late, LabFixtures.COMPONENT, A, BOOT_2, published()));
            DeploymentStore tied = store(with(history(), checkpoint(BOOT_2, 2000, Classification.CHECKPOINT_PENDING)), null);
            refuses("a pending checkpoint", () -> LabRepair.current(tied, LabFixtures.COMPONENT, A, BOOT_2, published()));
            // A pending fact of another boot, later in elapsed time, is not this boot's.
            DeploymentStore other = store(with(history(), checkpoint(BOOT_1, 99_000, Classification.CHECKPOINT_PENDING)), null);
            check(LabRepair.current(other, LabFixtures.COMPONENT, A, BOOT_2, published()).boot.equals(BOOT_2), "another boot");
        });
        cases.run("current / the boot must show the plan's cohort", () -> {
            String fingerprint = LabFixtures.FINGERPRINT.replace("2026081300", "2026100600");
            DeploymentStore two = store(with(history(), completed(BOOT_2, 1500, LabFixtures.TIME, fingerprint)), null);
            refuses("fingerprint is not one value", () -> LabRepair.current(two, LabFixtures.COMPONENT, A, BOOT_2, published()));
            DeploymentStore image = store(with(without(history(), Classification.BOOT_COMPLETED, BOOT_2),
                    completed(BOOT_2, 1000, LabFixtures.TIME, fingerprint)), null);
            refuses("fingerprint is not the plan's cohort", () -> LabRepair.current(image, LabFixtures.COMPONENT, A, BOOT_2,
                    published()));
            DeploymentStore factory = store(with(without(history(), Classification.FACTORY_PRESENT, BOOT_2),
                    factory(BOOT_2, 1000, "ed".repeat(32), LabFixtures.FACTORY_VERSION)), null);
            refuses("factory copy is not the plan's cohort", () -> LabRepair.current(factory, LabFixtures.COMPONENT, A,
                    BOOT_2, published()));
        });
        cases.run("current / exactly one active copy, the plan's published variant", () -> {
            DeploymentStore two = store(with(history(), active(BOOT_2, 1500, Classification.DATA_COPY, VARIANT_APK,
                    LabFixtures.BUNDLE_VERSION, DATA_UID + 1)), null);
            refuses("active copy is not one observed value", () -> LabRepair.current(two, LabFixtures.COMPONENT, A, BOOT_2,
                    published()));
            DeploymentStore factoryActive = store(with(without(history(), Classification.DATA_COPY, BOOT_2),
                    active(BOOT_2, 1000, Classification.FACTORY_COPY, LabFixtures.FACTORY_APK, LabFixtures.FACTORY_VERSION,
                            LabFixtures.UID)), null);
            refuses("the factory copy is active", () -> LabRepair.current(factoryActive, LabFixtures.COMPONENT, A, BOOT_2,
                    published()));
            DeploymentStore other = store(with(without(history(), Classification.DATA_COPY, BOOT_2),
                    active(BOOT_2, 1000, Classification.DATA_COPY, "ee".repeat(32), LabFixtures.BUNDLE_VERSION, DATA_UID)),
                    null);
            refuses("not the plan's published variant", () -> LabRepair.current(other, LabFixtures.COMPONENT, A, BOOT_2,
                    published()));
            DeploymentStore version = store(with(without(history(), Classification.DATA_COPY, BOOT_2),
                    active(BOOT_2, 1000, Classification.DATA_COPY, VARIANT_APK, LabFixtures.BUNDLE_VERSION + 5, DATA_UID)),
                    null);
            refuses("not the plan's published variant", () -> LabRepair.current(version, LabFixtures.COMPONENT, A, BOOT_2,
                    published()));
        });
        cases.run("repair plan / the study's row, A's restoration, signer and cohort, the current base, revision 1", () -> {
            DeploymentStore store = store(history(), null);
            Plan a = store.plan(A).value;
            Plan r = LabRepair.plan(store, lab(scratch), R, A, BOOT_2, LabFixtures.TIME + 5, published());
            check(r.equals(store.plan(R).value), "written and read back");
            check(r.repairs.equals(A) && r.signing == 0 && !r.hasRestoration() && r.restorationVersion == 0,
                    "repairs A, signs nothing, names no restoration");
            check(r.bundleInput.equals(a.restorationInput) && r.bundleVersion == a.restorationVersion
                    && r.signer.equals(a.signer), "A's restoration input, versionCode and signer");
            check(r.fingerprint.equals(a.fingerprint) && r.factoryApk.equals(a.factoryApk)
                    && r.factoryVersion == a.factoryVersion, "A's original cohort");
            check(r.baseApk.equals(VARIANT_APK) && r.baseVersion == LabFixtures.BUNDLE_VERSION && r.baseUid == DATA_UID
                    && r.baseContext.equals(DATA_CONTEXT), "the current A digest, versionCode, UID and context");
            check(r.selectionRevision == 1 && r.noticeDelayMillis == r.emergencyNoticeMillis
                    && r.healthResponse == HealthResponse.REPORT_AND_WAIT
                    && r.restorationPlan.equals(DeploymentRecords.NO_ID) && r.criteria == a.criteria,
                    "revision 1, equal delays, report and wait, every criterion");
            check(store.authorizationsOf(R).isEmpty() && store.ticketsOf(R).isEmpty(), "no grant and no ticket yet");
        });
        cases.run("repair plan / refused when it exists, another repairs A, or A has no restoration to give", () -> {
            DeploymentStore store = store(history(), null);
            LabRepair.plan(store, lab(scratch), R, A, BOOT_2, LabFixtures.TIME + 5, published());
            refuses("already exists", () -> LabRepair.plan(store, lab(scratch), R, A, BOOT_2, LabFixtures.TIME + 6, published()));
            refuses("already repairs the plan", () -> LabRepair.plan(store, lab(scratch), OTHER, A, BOOT_2, LabFixtures.TIME + 6,
                    published()));
            refuses("cannot repair itself", () -> LabRepair.plan(store, lab(scratch), A, A, BOOT_2, LabFixtures.TIME, published()));
            DeploymentStore bare = store(history(), null);
            refuses("bound no restoration", () -> LabRepair.plan(bare, lab(scratch), R, A, BOOT_2, LabFixtures.TIME,
                    p -> p.equals(A) ? List.of(VARIANT_APK) : null));
            check(bare.plan(R).found == Found.ABSENT, "nothing written on a refusal");
            DeploymentStore unsigned = store(history(), b -> b.restoration(DeploymentRecords.NO_DIGEST, 0));
            refuses("not a signed variant with a restoration", () -> LabRepair.plan(unsigned, lab(scratch), R, A, BOOT_2,
                    LabFixtures.TIME, published()));
            DeploymentStore trust = store(history(), b -> b.trustPolicy("7b".repeat(32)));
            refuses("another trust policy", () -> LabRepair.plan(trust, lab(scratch), R, A, BOOT_2, LabFixtures.TIME,
                    published()));
        });
        cases.run("grants / only the explicit approvals stage and activate, never SIGN", () -> {
            DeploymentStore store = store(history(), null);
            LabRepair.plan(store, lab(scratch), R, A, BOOT_2, LabFixtures.TIME + 5, published());
            SecureRandom random = new SecureRandom();
            refuses("signs nothing", () -> LabRepair.grants(store, lab(scratch), R, List.of("stage", "activate", "sign"),
                    LabFixtures.TIME, random));
            refuses("signs nothing", () -> LabRepair.grants(store, lab(scratch), R, List.of("sign"), LabFixtures.TIME, random));
            refuses("explicit approvals", () -> LabRepair.grants(store, lab(scratch), R, List.of("stage"), LabFixtures.TIME,
                    random));
            refuses("explicit approvals", () -> LabRepair.grants(store, lab(scratch), R, List.of(), LabFixtures.TIME, random));
            refuses("explicit approvals", () -> LabRepair.grants(store, lab(scratch), R, List.of("activate", "stage"),
                    LabFixtures.TIME, random));
            check(store.authorizationsOf(R).isEmpty(), "no grant from a refused phase");
            List<Authorization> written = LabRepair.grants(store, lab(scratch), R, LabRepair.APPROVALS, LabFixtures.TIME, random);
            List<Effect> effects = new ArrayList<>();
            for (Authorization a : store.authorizationsOf(R)) {
                check(a.actorClass == ActorClass.LAB_OPERATOR && a.inputs == 0, "a lab operator grant of no inputs");
                effects.add(a.effect);
            }
            effects.sort(null);
            check(written.size() == 2 && effects.equals(List.of(Effect.STAGE, Effect.ACTIVATE)), "STAGE and ACTIVATE");
            refuses("already has grants", () -> LabRepair.grants(store, lab(scratch), R, LabRepair.APPROVALS, LabFixtures.TIME,
                    random));
            refuses("not a repair plan", () -> LabRepair.grants(store, lab(scratch), A, LabRepair.APPROVALS, LabFixtures.TIME,
                    random));
        });
        cases.run("ticket / only after exactly STAGE and ACTIVATE, as the plan's first attempt", () -> {
            DeploymentStore store = store(history(), null);
            LabRepair.plan(store, lab(scratch), R, A, BOOT_2, LabFixtures.TIME + 5, published());
            refuses("not exactly STAGE and ACTIVATE", () -> LabRepair.ticket(store, lab(scratch), R, id(0x7a0)));
            LabRepair.grants(store, lab(scratch), R, LabRepair.APPROVALS, LabFixtures.TIME, new SecureRandom());
            Ticket t = LabRepair.ticket(store, lab(scratch), R, id(0x7a0));
            check(t.attempt == 1 && t.state == State.PLANNED && store.ticket(id(0x7a0)).found == Found.RECORD, "attempt 1");
            refuses("already has a ticket", () -> LabRepair.ticket(store, lab(scratch), R, id(0x7a1)));
        });
        cases.run("phases / a phase cut short authorizes nothing missing", () -> {
            // The plan and a STAGE grant only, as if the grant phase died between its two grants.
            DeploymentStore store = store(history(), null);
            Plan r = LabRepair.plan(store, lab(scratch), R, A, BOOT_2, LabFixtures.TIME + 5, published());
            check(store.addAuthorization(new Authorization(LabFixtures.INSTALLATION, id(0x7b0), LabFixtures.COMPONENT,
                    r.planId, Effect.STAGE, 0, ActorClass.LAB_OPERATOR, DeploymentRecords.NO_USER,
                    DeploymentRecords.NO_SERIAL, DeploymentRecords.NO_ID, GrantScope.NONE, id(0x7b1), LabFixtures.TIME)),
                    "one grant");
            refuses("already has grants", () -> LabRepair.grants(store, lab(scratch), R, LabRepair.APPROVALS, LabFixtures.TIME,
                    new SecureRandom()));
            refuses("not exactly STAGE and ACTIVATE", () -> LabRepair.ticket(store, lab(scratch), R, id(0x7a0)));
            check(store.ticketsOf(R).isEmpty() && store.authorizationsOf(R).size() == 1, "nothing more written");
            // A SIGN grant put beside them by other means never makes a ticket either.
            DeploymentStore signed = store(history(), null);
            Plan r2 = LabRepair.plan(signed, lab(scratch), R, A, BOOT_2, LabFixtures.TIME + 5, published());
            LabRepair.grants(signed, lab(scratch), R, LabRepair.APPROVALS, LabFixtures.TIME, new SecureRandom());
            check(signed.addAuthorization(new Authorization(LabFixtures.INSTALLATION, id(0x7c0), LabFixtures.COMPONENT,
                    r2.planId, Effect.SIGN, DeploymentRecords.INPUT_VARIANT, ActorClass.LAB_OPERATOR,
                    DeploymentRecords.NO_USER, DeploymentRecords.NO_SERIAL, DeploymentRecords.NO_ID, GrantScope.NONE,
                    id(0x7c1), LabFixtures.TIME)), "a SIGN grant");
            refuses("not exactly STAGE and ACTIVATE", () -> LabRepair.ticket(signed, lab(scratch), R, id(0x7a0)));
        });
        cases.run("phases / no repair while a ticket of the component is open", () -> {
            DeploymentStore store = store(history(), null);
            LabRepair.plan(store, lab(scratch), R, A, BOOT_2, LabFixtures.TIME + 5, published());
            Ticket open = new Ticket.Builder().installation(LabFixtures.INSTALLATION).ticketId(id(0x702)).component(
                    LabFixtures.COMPONENT).planId(A).attempt(2).coordinator(CoordinatorClass.HOST, LabFixtures.COORDINATOR)
                    .build();
            check(store.createTicket(open), "an open ticket of A");
            refuses("a ticket of the component is open", () -> LabRepair.grants(store, lab(scratch), R, LabRepair.APPROVALS,
                    LabFixtures.TIME, new SecureRandom()));
            check(store.authorizationsOf(R).isEmpty(), "no grant beside an open ticket");
        });

        System.out.println(failures == 0 ? "ALL PASS" : failures + " FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }
}
