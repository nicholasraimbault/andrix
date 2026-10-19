// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

import dev.andrix.server.deployment.DeploymentRecords;
import dev.andrix.server.deployment.DeploymentRecords.ActorClass;
import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.ChoiceKind;
import dev.andrix.server.deployment.DeploymentRecords.CoordinatorClass;
import dev.andrix.server.deployment.DeploymentRecords.Effect;
import dev.andrix.server.deployment.DeploymentRecords.GrantScope;
import dev.andrix.server.deployment.DeploymentRecords.HealthResponse;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Realization;
import dev.andrix.server.deployment.DeploymentRecords.Selection;
import dev.andrix.server.deployment.DeploymentRecords.Target;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import dev.andrix.server.deployment.DeploymentStore;
import dev.andrix.server.deployment.DeploymentStore.Found;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

/**
 * The next campaign's repair records, written outside any generation through the deployment
 * package's public API: the current baseline of the chosen plan in the newest checked boot, and
 * the repair plan made from it in three phases. The lab driver's entry gives it the real artifact
 * store's publications, the host test entry the scripted host's. Nothing here signs, publishes,
 * reads the device or decides a ticket.
 *
 * <p>The current baseline uses the facts of one boot only: the boot the driver's own last check
 * established, which the selection must record as checked. Facts of every other boot are left out,
 * and no boot is ever ordered against another by wall time. Within that boot, elapsed time orders
 * the checkpoint's facts. The chosen plan must be the selection's own move, found current, with no
 * open ticket of the component; the boot's facts must show the plan's cohort and one active copy,
 * the plan's published variant at its versionCode.
 *
 * <p>The repair plan repairs the chosen plan and signs nothing: its bundle is the chosen plan's
 * restoration input and versionCode, which the repaired plan's publication bound, its signer and
 * cohort are the chosen plan's, its base is the current baseline's digest, versionCode, UID and
 * context, and it expects the selection's current revision. Its ordinary and emergency notice
 * delays are equal, its health response is report and wait, and it names no restoration. The
 * phases are the plan, its grants by explicit approval, STAGE then ACTIVATE and never SIGN, and its
 * first ticket. Each phase refuses when its own records exist already, so a phase that was cut
 * short authorizes nothing that is missing: the driver stops there.
 */
public final class LabRepair {
    /** The approvals the grant phase needs, in this order: one for each grant it writes. */
    public static final List<String> APPROVALS = List.of("stage", "activate");

    private LabRepair() {}

    /** The APKs a plan's publication binds as the artifact store reads it back. */
    public interface Publications {
        /** The bound APK digests in role order, or null unless the publication reads PUBLISHED. */
        List<String> apks(String planId) throws IOException;
    }

    /** The chosen plan's current baseline: its active copy in the newest checked boot. */
    public static final class Current {
        public final String plan, boot, fingerprint, apk, context;
        public final long version;
        public final int uid;
        public final long revision;

        Current(String plan, String boot, String fingerprint, String apk, long version, int uid, String context,
                long revision) {
            this.plan = plan;
            this.boot = boot;
            this.fingerprint = fingerprint;
            this.apk = apk;
            this.version = version;
            this.uid = uid;
            this.context = context;
            this.revision = revision;
        }
    }

    private static void need(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    private static Plan stored(DeploymentStore store, String planId, String what) {
        DeploymentStore.Read<Plan> read = store.plan(planId);
        need(read.found == Found.RECORD, what + " cannot be read");
        return read.value;
    }

    /** Whether the component has an open ticket, or a tickets listing that could hide one. */
    static boolean openTicket(DeploymentStore store, String component) {
        DeploymentStore.Listing<Ticket> tickets = store.tickets();
        if (!tickets.footprints.isEmpty() || !tickets.newer.isEmpty()) return true;
        for (Ticket t : tickets.values) {
            if (t.component.equals(component) && !t.state.terminal()) return true;
        }
        return false;
    }

    /**
     * The current baseline of the chosen plan, from the facts of the boot the driver's last check
     * established and nothing else. Refused, naming the first reason, unless the selection is the
     * chosen plan's own move found current and checked in that boot, every ticket of the component
     * is terminal, and that boot's facts show the plan's fingerprint and factory copy, a checkpoint
     * whose latest fact is COMMITTED with no pending fact after a committed one, and exactly one
     * active copy: a data copy of the plan's published variant at its versionCode.
     */
    public static Current current(DeploymentStore store, String component, String chosenId, String boot,
            Publications publications) throws IOException {
        LabProtocol.checkHex(boot, 16, "the checked boot", false);
        Plan chosen = stored(store, chosenId, "the chosen plan");
        need(chosen.component.equals(component) && chosen.target == Target.VARIANT,
                "the chosen plan is not a variant of the component");
        DeploymentStore.Read<Selection> read = store.selection(component);
        need(read.found == Found.RECORD, "the selection cannot be read");
        Selection s = read.value;
        need(s.choice == ChoiceKind.PLAN && s.planId.equals(chosenId), "the selection does not choose the plan");
        need(s.revision == chosen.selectionRevision + 1, "the selection is not the plan's own move");
        need(s.realization == Realization.CURRENT, "the chosen plan is not found current");
        need(s.checkedBoot.equals(boot),
                "the selection's checked boot is not the boot the driver's last check established");
        need(!openTicket(store, component), "a ticket of the component is open");
        List<String> apks = publications.apks(chosenId);
        need(apks != null && !apks.isEmpty(), "the chosen plan's publication does not read published");
        DeploymentStore.Listing<Observation> listing = store.observations();
        need(listing.footprints.isEmpty() && listing.newer.isEmpty(), "the store holds unreadable or newer observations");
        TreeSet<String> fingerprints = new TreeSet<>(), factories = new TreeSet<>(), actives = new TreeSet<>();
        long firstCommitted = -1, lastPending = -1;
        Observation active = null;
        for (Observation o : listing.values) {
            if (!o.boot.equals(boot)) continue; // Only the established boot's facts: no other boot is ordered.
            switch (o.classification) {
                case BOOT_COMPLETED:
                    fingerprints.add(o.text);
                    break;
                case CHECKPOINT_COMMITTED:
                    firstCommitted = firstCommitted < 0 ? o.elapsed : Math.min(firstCommitted, o.elapsed);
                    break;
                case CHECKPOINT_PENDING:
                    lastPending = Math.max(lastPending, o.elapsed);
                    break;
                case FACTORY_PRESENT:
                    if (o.component.equals(component)) factories.add(o.digest + " " + o.version);
                    break;
                case FACTORY_COPY:
                case DATA_COPY:
                    if (o.component.equals(component)) {
                        actives.add(o.classification + " " + o.digest + " " + o.version + " " + o.number + " " + o.text);
                        active = o;
                    }
                    break;
                default:
                    break;
            }
        }
        need(firstCommitted >= 0, "no committed checkpoint is observed in the checked boot");
        need(lastPending < firstCommitted, "a pending checkpoint is observed at or after a committed one in the checked boot");
        need(fingerprints.size() == 1, "the checked boot's completed fingerprint is not one value: " + fingerprints);
        need(fingerprints.first().equals(chosen.fingerprint), "the checked boot's fingerprint is not the plan's cohort");
        need(factories.size() == 1, "the factory copy is not one observed value: " + factories);
        need(factories.first().equals(chosen.factoryApk + " " + chosen.factoryVersion),
                "the factory copy is not the plan's cohort");
        need(actives.size() == 1 && active != null, "the active copy is not one observed value: " + actives);
        need(active.classification == DeploymentRecords.Classification.DATA_COPY, "the factory copy is active, not the plan's");
        need(active.digest.equals(apks.get(0)) && active.version == chosen.bundleVersion,
                "the active copy is not the plan's published variant");
        return new Current(chosenId, boot, fingerprints.first(), active.digest, active.version, active.number, active.text,
                s.revision);
    }

    /**
     * Phase 1: the repair plan record, from the current baseline of the plan it repairs. Refused
     * when the plan exists already, when another plan repairs the same plan, or when the repaired
     * plan is not a variant whose publication bound a restoration. Returns the plan written.
     */
    public static Plan plan(DeploymentStore store, LabConfig lab, String repairId, String repairedId, String boot,
            long now, Publications publications) throws IOException {
        LabProtocol.checkHex(repairId, 16, "the repair plan", false);
        LabProtocol.checkHex(repairedId, 16, "the repaired plan", false);
        need(!repairId.equals(repairedId), "a plan cannot repair itself");
        need(now > 0, "a positive time");
        need(store.plan(repairId).found == Found.ABSENT, "the repair plan already exists");
        Plan repaired = stored(store, repairedId, "the repaired plan");
        need(repaired.hasRestoration() && repaired.signing > 0 && repaired.repairs.equals(DeploymentRecords.NO_ID),
                "the repaired plan is not a signed variant with a restoration");
        need(repaired.trustPolicy.equals(lab.trustPolicy), "the repaired plan is of another trust policy");
        DeploymentStore.Listing<Plan> plans = store.plans();
        need(plans.footprints.isEmpty() && plans.newer.isEmpty(), "the store holds unreadable or newer plans");
        for (Plan other : plans.values) {
            need(!other.repairs.equals(repairedId), "a plan already repairs the plan");
        }
        Current current = current(store, lab.component, repairedId, boot, publications);
        List<String> apks = publications.apks(repairedId);
        need(apks != null && apks.size() == 2, "the repaired plan's publication bound no restoration");
        Plan plan = new Plan.Builder().installation(lab.installation).planId(repairId).component(lab.component)
                .target(Target.VARIANT).repairs(repairedId).bundle(repaired.restorationInput, repaired.restorationVersion)
                .signer(repaired.signer).signing(0)
                .cohort(repaired.fingerprint, repaired.factoryApk, repaired.factoryVersion)
                .base(current.apk, current.version, current.uid, current.context).selectionRevision(current.revision)
                .trustPolicy(lab.trustPolicy).commitMode(repaired.commitMode).criteria(repaired.criteria)
                .healthWindow(repaired.healthWindowMillis).healthResponse(HealthResponse.REPORT_AND_WAIT)
                .notice(repaired.noticeDelayMillis, repaired.noticeDelayMillis)
                .limits(repaired.bootLimit, repaired.rebootTimeLimitMillis, repaired.requestLimit,
                        repaired.activateWindowMillis, repaired.verificationWaitMillis)
                .createdAt(now).build();
        need(store.addPlan(plan), "the repair plan was not written");
        need(plan.equals(stored(store, repairId, "the written repair plan")), "the repair plan does not read back");
        return plan;
    }

    private static Plan repairPlan(DeploymentStore store, LabConfig lab, String repairId) {
        Plan plan = stored(store, repairId, "the repair plan");
        need(plan.component.equals(lab.component) && plan.signing == 0 && !plan.repairs.equals(DeploymentRecords.NO_ID),
                "not a repair plan that signs nothing");
        return plan;
    }

    /**
     * Phase 2: the repair plan's STAGE and ACTIVATE grants of the lab operator, written only when
     * the approvals are exactly {@link #APPROVALS}: an explicit approval for each, and SIGN refused
     * by name, since a repair signs nothing. Refused when the plan has any grant already or a
     * ticket of the component is open. Returns the grants written.
     */
    public static List<Authorization> grants(DeploymentStore store, LabConfig lab, String repairId, List<String> approvals,
            long now, SecureRandom random) {
        need(!approvals.contains("sign"), "a repair signs nothing: no SIGN grant is approved");
        need(approvals.equals(APPROVALS), "a repair's grants need the explicit approvals " + APPROVALS);
        need(now > 0, "a positive time");
        Plan plan = repairPlan(store, lab, repairId);
        need(store.authorizationsOf(repairId).isEmpty(), "the repair plan already has grants");
        need(store.ticketsOf(repairId).isEmpty(), "the repair plan already has a ticket");
        need(!openTicket(store, lab.component), "a ticket of the component is open");
        List<Authorization> written = new ArrayList<>();
        for (Effect effect : List.of(Effect.STAGE, Effect.ACTIVATE)) {
            Authorization a = new Authorization(lab.installation, freshId(random), lab.component, plan.planId, effect, 0,
                    ActorClass.LAB_OPERATOR, DeploymentRecords.NO_USER, DeploymentRecords.NO_SERIAL,
                    DeploymentRecords.NO_ID, GrantScope.NONE, freshId(random), now);
            need(store.addAuthorization(a), "the " + effect + " grant was not written");
            written.add(a);
        }
        need(store.authorizationsOf(repairId).size() == written.size(), "the repair plan's grants do not read back");
        return written;
    }

    /**
     * Phase 3: the repair plan's first ticket. Refused unless the plan's grants are exactly the
     * lab operator's STAGE and ACTIVATE, the plan has no ticket and no ticket of the component is
     * open.
     */
    public static Ticket ticket(DeploymentStore store, LabConfig lab, String repairId, String ticketId) {
        LabProtocol.checkHex(ticketId, 16, "the ticket", false);
        Plan plan = repairPlan(store, lab, repairId);
        List<Effect> effects = new ArrayList<>();
        for (Authorization a : store.authorizationsOf(repairId)) {
            need(a.actorClass == ActorClass.LAB_OPERATOR, "a repair grant of another actor");
            effects.add(a.effect);
        }
        effects.sort(null);
        need(effects.equals(List.of(Effect.STAGE, Effect.ACTIVATE)),
                "the repair plan's grants are not exactly STAGE and ACTIVATE");
        need(store.ticketsOf(repairId).isEmpty(), "the repair plan already has a ticket");
        need(!openTicket(store, lab.component), "a ticket of the component is open");
        Ticket ticket = new Ticket.Builder().installation(lab.installation).ticketId(ticketId).component(plan.component)
                .planId(plan.planId).attempt(1).coordinator(CoordinatorClass.HOST, lab.coordinator).build();
        need(store.createTicket(ticket), "the repair ticket was not written");
        return ticket;
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
