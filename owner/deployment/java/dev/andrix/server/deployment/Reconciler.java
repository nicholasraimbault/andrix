// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import static dev.andrix.server.deployment.DeploymentRecords.FLAG_BOOT_LIMIT;
import static dev.andrix.server.deployment.DeploymentRecords.FLAG_REQUEST_LIMIT;
import static dev.andrix.server.deployment.DeploymentRecords.FLAG_UNRESOLVED;
import static dev.andrix.server.deployment.DeploymentRecords.NO_ID;

import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.Cause;
import dev.andrix.server.deployment.DeploymentRecords.ChoiceKind;
import dev.andrix.server.deployment.DeploymentRecords.Classification;
import dev.andrix.server.deployment.DeploymentRecords.CommitMode;
import dev.andrix.server.deployment.DeploymentRecords.ComponentClass;
import dev.andrix.server.deployment.DeploymentRecords.Crossing;
import dev.andrix.server.deployment.DeploymentRecords.Effect;
import dev.andrix.server.deployment.DeploymentRecords.Entry;
import dev.andrix.server.deployment.DeploymentRecords.Health;
import dev.andrix.server.deployment.DeploymentRecords.ActorClass;
import dev.andrix.server.deployment.DeploymentRecords.HealthResponse;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.ObservationKind;
import dev.andrix.server.deployment.DeploymentRecords.Outcome;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Realization;
import dev.andrix.server.deployment.DeploymentRecords.Reference;
import dev.andrix.server.deployment.DeploymentRecords.Route;
import dev.andrix.server.deployment.DeploymentRecords.Selection;
import dev.andrix.server.deployment.DeploymentRecords.State;
import dev.andrix.server.deployment.DeploymentRecords.Target;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Reconciliation from observations. Given the durable records and the observations of the
 * current kernel boot, {@link #step} computes the next ticket value and at most one crossing,
 * and {@link #cohortCheck} computes the selection's realization status. Neither performs I/O.
 *
 * <p>The coordinator writes and syncs the returned ticket, whose ledger already holds the
 * crossing's entry, before it issues the crossing. It then records the reply as an observation,
 * or nothing when the reply is lost, and steps again. A step therefore never sees a crossing in
 * flight: a ledger entry without a settling reply or other evidence is lost or ambiguous. In an
 * intent state that sets UNRESOLVED, and no step issues a crossing while it is set. Only an
 * observation of the exact native reference, a proof of absence, a new boot or a time limit that
 * the rules name resolves it. Each step makes at most one state change.
 */
public final class Reconciler {
    private Reconciler() {}

    /** The device's present, read from the route each round. */
    public static final class Clock {
        public final String boot;
        /** The framework instance, or -1 when none is running or known. */
        public final long instance;
        public final long elapsed;
        public final long wall;

        public Clock(String boot, long instance, long elapsed, long wall) {
            DeploymentRecords.checkId(boot, "boot", false);
            this.boot = boot;
            this.instance = instance;
            this.elapsed = elapsed;
            this.wall = wall;
        }
    }

    /** The observations of one kernel boot for one component, plus the host facts. */
    public static final class View {
        public final String boot;
        private final List<Observation> facts;

        private View(String boot, List<Observation> facts) {
            this.boot = boot;
            this.facts = facts;
        }

        /**
         * The facts of one boot: observations of that boot for the component or the device, host
         * facts of the component and replies, ordered by elapsed time. A route advances the
         * elapsed time between rounds, so the latest fact of a kind is well defined.
         */
        public static View of(String boot, String component, List<Observation> all) {
            List<Observation> facts = new ArrayList<>();
            for (Observation o : all) {
                boolean scope = o.component.isEmpty() || o.component.equals(component);
                boolean thisBoot = o.boot.equals(boot);
                // Host facts and replies belong to their request or ledger entry, not to a boot.
                boolean anyBoot = o.route == Route.HOST || o.kind == ObservationKind.REPLY;
                if (scope && (thisBoot || anyBoot)) facts.add(o);
            }
            facts.sort((x, y) -> Long.compare(x.elapsed, y.elapsed)); // Stable: ties keep their order.
            return new View(boot, Collections.unmodifiableList(facts));
        }

        public List<Observation> facts() { return facts; }

        // The latest fact of a kind: the largest elapsed time, then the later one in order.
        Observation latest(ObservationKind kind) {
            Observation best = null;
            for (Observation o : facts) {
                if (o.kind == kind && o.boot.equals(boot) && (best == null || o.elapsed >= best.elapsed)) best = o;
            }
            return best;
        }

        boolean bootObserved() { return latest(ObservationKind.BOOT) != null; }

        /** When the boot was first seen completed, or -1. */
        long completedAt() {
            long at = -1;
            for (Observation o : facts) {
                if (o.classification == Classification.BOOT_COMPLETED && o.boot.equals(boot)
                        && (at < 0 || o.elapsed < at)) {
                    at = o.elapsed;
                }
            }
            return at;
        }

        Classification checkpoint() {
            Observation o = latest(ObservationKind.CHECKPOINT);
            return o == null ? null : o.classification;
        }

        Observation reply(String ticketId, int index) {
            Observation best = null;
            for (Observation o : facts) {
                if (o.kind == ObservationKind.REPLY && o.subject.equals(ticketId) && o.sequence == index) best = o;
            }
            return best;
        }

        // A signing request has one outcome. Precedence, not order, decides, failing closed.
        Classification signer(String request) {
            List<Classification> order = List.of(Classification.SIGN_PENDING, Classification.SIGN_COMPLETED,
                    Classification.SIGN_REFUSED, Classification.SIGN_CANNOT_COMPLETE);
            Classification best = null;
            for (Observation o : facts) {
                if (o.kind == ObservationKind.SIGNER && o.subject.equals(request)
                        && (best == null || order.indexOf(o.classification) > order.indexOf(best))) {
                    best = o.classification;
                }
            }
            return best;
        }

        // What the store read of the plan's publication after one PUBLISH attempt's call had ended.
        // A published bundle never changes: published wins over absent, and a mismatch over both.
        Classification publication(String attempt, String plan) {
            List<Classification> order = List.of(Classification.BUNDLE_ABSENT, Classification.BUNDLE_PUBLISHED,
                    Classification.BUNDLE_MISMATCH);
            Classification best = null;
            for (Observation o : facts) {
                if (o.kind == ObservationKind.BUNDLE && o.subject.equals(attempt) && o.plan.equals(plan)
                        && (best == null || order.indexOf(o.classification) > order.indexOf(best))) {
                    best = o.classification;
                }
            }
            return best;
        }

        /**
         * The plan's publication as the store read it back complete: a BUNDLE_PUBLISHED fact naming
         * the plan, whose APK digests are those of the bundles the publication binds to the plan's
         * roles. A publication never changes, so any such read serves, whichever attempt it
         * followed. Null when there is none, or when the reads of the plan's publication disagree:
         * two such reads bind other APKs, a read names other bytes, or one attempt read it both
         * published and absent. Store damage never heals on its own. Host facts carry no time that
         * a new coordinator can order them by, so the two reads of one attempt disagree whichever
         * came first. An absent read alone only shows that its attempt had no effect. An unreadable
         * record gives no fact.
         */
        Observation bound(String plan) {
            Observation found = null;
            List<String> absent = new ArrayList<>();
            List<String> read = new ArrayList<>();
            for (Observation o : facts) {
                if (o.kind != ObservationKind.BUNDLE || !o.plan.equals(plan)) continue;
                if (o.classification == Classification.BUNDLE_MISMATCH) return null;
                if (o.classification == Classification.BUNDLE_ABSENT) {
                    absent.add(o.subject);
                    continue;
                }
                if (found != null && (!found.digest.equals(o.digest) || !found.bundleApk.equals(o.bundleApk)
                        || !found.restorationApk.equals(o.restorationApk))) {
                    return null;
                }
                found = o;
                read.add(o.subject);
            }
            for (String attempt : absent) {
                if (read.contains(attempt)) return null;
            }
            return found;
        }

        /** The APK digest the plan's publication binds to its VARIANT role, or null. */
        String boundApk(String plan) {
            Observation o = bound(plan);
            return o == null ? null : o.bundleApk;
        }

        List<Observation> of(ObservationKind kind) {
            List<Observation> result = new ArrayList<>();
            for (Observation o : facts) if (o.kind == kind && o.boot.equals(boot)) result.add(o);
            return result;
        }
    }

    /** Fresh random IDs for nonces and signing requests. */
    public interface Ids extends Supplier<String> {}

    /** Everything one step reads. */
    public static final class Context {
        final Plan plan;
        final Ticket ticket;
        final List<Authorization> authorizations;
        final List<Ticket> planTickets;
        final Selection selection;
        final String trustPolicy;
        final boolean targetHeld;
        final List<Plan> repairs;
        final Plan repaired;
        final View view;
        final Clock now;
        final boolean rebootRequested;
        final Ids ids;

        /**
         * @param authorizations every authorization of the plan
         * @param planTickets every ticket of the plan, this one included, for used grants
         * @param repairs authorized plans that name this plan as the one they repair
         * @param repaired the stored plan this plan repairs, or null when it repairs none or that plan
         *     cannot be read
         * @param rebootRequested the owner asked for the activating reboot now (early commit)
         */
        public Context(Plan plan, Ticket ticket, List<Authorization> authorizations, List<Ticket> planTickets,
                Selection selection, String trustPolicy, boolean targetHeld, List<Plan> repairs, Plan repaired,
                View view, Clock now, boolean rebootRequested, Ids ids) {
            this.plan = Objects.requireNonNull(plan, "plan");
            this.ticket = Objects.requireNonNull(ticket, "ticket");
            this.authorizations = List.copyOf(authorizations);
            this.planTickets = List.copyOf(planTickets);
            this.selection = Objects.requireNonNull(selection, "selection");
            this.trustPolicy = Objects.requireNonNull(trustPolicy, "trustPolicy");
            this.targetHeld = targetHeld;
            this.repairs = List.copyOf(repairs);
            this.repaired = repaired == null || !repaired.planId.equals(plan.repairs) ? null : repaired;
            this.view = Objects.requireNonNull(view, "view");
            this.now = now;
            this.rebootRequested = rebootRequested;
            this.ids = Objects.requireNonNull(ids, "ids");
            if (!ticket.planId.equals(plan.planId)) throw new IllegalArgumentException("ticket of another plan");
            if (now != null && !now.boot.equals(view.boot)) throw new IllegalArgumentException("view of another boot");
        }
    }

    /** The result of one step. */
    public static final class Step {
        /** The next ticket value. Equal to the input when nothing changes. */
        public final Ticket ticket;
        /** The crossing to issue once the ticket is synced: the last ledger entry, or null. */
        public final Entry issue;
        /** The next selection value, or null when the choice and realization do not change. */
        public final Selection selection;
        /** Why, for logs and tests. Never shown as authority. */
        public final String reason;

        Step(Ticket ticket, Entry issue, Selection selection, String reason) {
            this.ticket = ticket;
            this.issue = issue;
            this.selection = selection;
            this.reason = reason;
        }

        @Override
        public String toString() {
            return "Step{" + ticket.state + (issue == null ? "" : ", issue " + issue.crossing) + ", " + reason + "}";
        }
    }

    // ------------------------------------------------------------------ the cohort check

    /**
     * The realization status of a selection in one boot. The choice and revision never change
     * here. While the active bytes are the bundle of an open ticket that has not reached
     * APPLIED, the previous status stands, because the ticket reports that activation. The
     * selection's temporary factory plan, when it names one, is passed as {@code temporary}.
     * Returns the selection unchanged when the boot's facts are incomplete.
     *
     * <p>The repair link names the open ticket's plan when that plan repairs the chosen plan and is
     * no temporary factory plan, while the status needs a repair. A status change keeps the link
     * while the new status still needs one. CURRENT clears it.
     */
    public static Selection cohortCheck(Selection s, Plan chosen, Plan temporary, View view, Ticket open,
            Plan openPlan) {
        Observation boot = view.latest(ObservationKind.BOOT);
        Observation active = view.latest(ObservationKind.ACTIVE);
        Observation factory = view.latest(ObservationKind.FACTORY);
        if (boot == null || active == null || factory == null) return s;
        if (open != null && openPlan != null && !open.state.terminal() && !reachedApplied(open.state)
                && openPlan.target != Target.FACTORY && active.digest.equals(view.boundApk(openPlan.planId))) {
            return s;
        }
        Realization status;
        String standIn = NO_ID;
        if (s.choice == ChoiceKind.FACTORY) {
            status = active.digest.equals(factory.digest) ? Realization.CURRENT : Realization.DIVERGED;
        } else {
            if (chosen == null || !chosen.planId.equals(s.planId)) return s;
            // The chosen and stand in bytes are what their publications bound. Without that read
            // the facts are incomplete.
            String chosenApk = view.boundApk(chosen.planId);
            boolean standing = temporary != null && temporary.planId.equals(s.temporary);
            String temporaryApk = standing ? view.boundApk(temporary.planId) : null;
            if (chosenApk == null || (standing && temporaryApk == null)) return s;
            if (standing && active.digest.equals(temporaryApk)) {
                // Decision 6: the owner's approved stand in from factory source. The choice stays.
                status = Realization.TEMPORARY_FACTORY;
                standIn = temporary.planId;
            } else if (active.digest.equals(chosenApk)) {
                boolean cohort = boot.text.equals(chosen.fingerprint) && factory.digest.equals(chosen.factoryApk);
                status = cohort ? Realization.CURRENT : Realization.STALE_BASE;
            } else if (active.digest.equals(factory.digest) && active.classification == Classification.FACTORY_COPY) {
                status = Realization.DISPLACED;
            } else {
                status = Realization.DIVERGED;
            }
        }
        boolean repairable = status == Realization.STALE_BASE || status == Realization.DISPLACED
                || status == Realization.DIVERGED || status == Realization.TEMPORARY_FACTORY;
        String repair = repairable ? s.repair : NO_ID;
        if (repairable && open != null && openPlan != null && !open.state.terminal() && s.choice == ChoiceKind.PLAN
                && openPlan.repairs.equals(s.planId) && openPlan.target != Target.TEMPORARY_FACTORY) {
            repair = openPlan.planId;
        }
        Selection next = s.realized(status, view.boot, repair, standIn);
        return next.equals(s) ? s : next;
    }

    /**
     * A factory plan chosen while the factory copy is active makes no crossing: its SELECT
     * authorization alone moves the choice. Returns the next selection, or null.
     */
    public static Selection selectFactory(Selection s, Plan plan, List<Authorization> authorizations, View view,
            long wall) {
        if (plan.target != Target.FACTORY || s.revision != plan.selectionRevision) return null;
        boolean selected = false;
        for (Authorization a : authorizations) {
            selected |= a.planId.equals(plan.planId) && a.effect == Effect.SELECT;
        }
        Observation active = view.latest(ObservationKind.ACTIVE);
        Observation factory = view.latest(ObservationKind.FACTORY);
        if (!selected || active == null || factory == null || !active.digest.equals(factory.digest)) return null;
        return s.chosen(ChoiceKind.FACTORY, NO_ID, Realization.CURRENT, view.boot, wall);
    }

    private static boolean reachedApplied(State state) {
        return state == State.APPLIED || state == State.HEALTH_WINDOW || state == State.CLOSED_APPLIED
                || state == State.SUPERSEDED;
    }

    // ------------------------------------------------------------------ the step

    /** One reconciliation step. See the class description. */
    public static Step step(Context c) {
        Ticket t = c.ticket;
        if (t.state.terminal()) return new Step(t, null, null, "terminal");
        Ticket.Builder b = t.toBuilder();
        Plan p = c.plan;

        // A new kernel boot: counted from SESSION_INTENT on, alerting at the limit.
        boolean newBoot = false;
        if (c.now != null && !c.now.boot.equals(t.boot) && !t.boot.equals(NO_ID) && !c.view.bootObserved()) {
            return new Step(t, null, null, "a new boot not yet observed");
        }
        if (c.now != null && c.view.bootObserved()) {
            if (t.boot.equals(NO_ID)) {
                b.boot(c.now.boot);
            } else if (!t.boot.equals(c.now.boot)) {
                newBoot = true;
                b.boot(c.now.boot);
                if (created(t)) {
                    b.bootCount(t.bootCount + 1);
                    if (t.bootCount + 1 >= p.bootLimit) b.set(FLAG_BOOT_LIMIT);
                }
            }
        }
        // Causes are recorded at once. A cause takes effect only once any intent resolves.
        Cause cause = observedCause(c);
        if (cause.code > t.cause.code) b.cause(cause);

        // The bundle's APK digest is signed output: the plan's publication binds it, and a fact that
        // read the publication back carries it. A ticket reaches PUBLISHED only on such a fact, so
        // from there on a missing or disagreeing read is missing evidence, never other bytes. The
        // ticket holds with the alert. A recorded cause still takes effect where no bytes are
        // judged, so a cancellation abandons a live session: an abandon needs no APK digest.
        if (t.state.code >= State.PUBLISHED.code && t.state != State.SIGN_FAILED && bundleApk(c) == null) {
            b.set(FLAG_REQUEST_LIMIT);
            if (b.cause() != Cause.NONE && !judgesBytes(t.state)) {
                Step caused = transition(c, b, newBoot);
                if (caused != null) return caused;
            }
            return done(c, b, null, null, "the plan's publication read is missing or disagrees: holding and alerting");
        }

        Step step = transition(c, b, newBoot);
        if (step != null) return step;
        return done(c, b, null, null, "waiting");
    }

    private static Step transition(Context c, Ticket.Builder b, boolean newBoot) {
        Ticket t = c.ticket;
        Plan p = c.plan;
        switch (t.state) {
            case PLANNED:
                if (b.cause() != Cause.NONE) return close(c, b, "recorded cause before any crossing");
                if (signingNeeded(c) == 0 ? unusedStage(c) != null : signGrants(c, signingNeeded(c)) != null) {
                    return to(c, b, State.AUTHORIZED, "authorized");
                }
                return null;
            case AUTHORIZED:
                if (b.cause() != Cause.NONE) return close(c, b, "recorded cause before any crossing");
                return signNext(c, b, State.SIGNING);
            case SIGNING:
                return signing(c, b);
            case SIGNED:
                if (b.cause() != Cause.NONE) return close(c, b, "recorded cause before publication");
                if (published(c)) return to(c, b, State.PUBLISHED, "bundles read back published");
                return publish(c, b);
            case PUBLISHED:
                return stage(c, b);
            case SESSION_INTENT:
                return sessionIntent(c, b);
            case SESSION_BOUND:
            case WRITTEN:
                return bound(c, b);
            case COMMIT_INTENT:
                return commitIntent(c, b, newBoot);
            case READY:
            case READY_AGAIN:
                return ready(c, b, newBoot);
            case REBOOT_INTENT:
                return rebootIntent(c, b, newBoot);
            case ABANDON_INTENT:
                return abandonIntent(c, b, newBoot);
            case BOOT_OBSERVED:
                return bootObserved(c, b);
            case APPLIED_PROVISIONAL:
                if (newBoot) return to(c, b, State.BOOT_OBSERVED, "another boot while provisional");
                if (crossingAllowed(c) && appliedFacts(c)) return applied(c, b);
                return null;
            case APPLIED:
                return startWindow(c, b);
            case HEALTH_WINDOW:
                return owing(c, window(c, b), b);
            case FAILED_NATIVE:
                if (cohortChanged(c)) b.cause(maxCause(b.cause(), Cause.VOID_BASE));
                return close(c, b, "native failure");
            case NATIVE_RECORD_LOST:
                return recordLost(c, b);
            case SIGN_FAILED:
            case NO_SESSION:
            case ABANDONED:
                return close(c, b, "by the recorded cause");
            default:
                throw new IllegalStateException("state without a rule");
        }
    }

    // ---------------------------------------------------------- signing and publication

    // The inputs this ticket must still sign: none when the plan's bundles are already signed or
    // read back published, as after an earlier attempt of the plan, otherwise every input not yet
    // requested.
    private static int signingNeeded(Context c) {
        Plan p = c.plan;
        if (p.signing == 0) return 0;
        if (published(c)) return 0;
        int all = DeploymentRecords.INPUT_VARIANT | (p.hasRestoration() ? DeploymentRecords.INPUT_RESTORATION : 0);
        for (Entry e : c.ticket.ledger) {
            if (e.crossing == Crossing.SIGN) {
                Authorization a = authorization(c, e.grant);
                if (a != null) all &= ~a.inputs;
            }
        }
        return all;
    }

    // Unused SIGN grants that cover the needed inputs: one covering all under one transaction,
    // one per input under two. Returns null when they are missing.
    private static List<Authorization> signGrants(Context c, int needed) {
        List<Authorization> result = new ArrayList<>();
        int covered = 0;
        for (Authorization a : c.authorizations) {
            if (a.effect != Effect.SIGN || used(c, a) || (a.inputs & ~needed) != 0) continue;
            boolean shape = c.plan.signing == 1 ? a.inputs == needed : Integer.bitCount(a.inputs) == 1;
            if (shape && (a.inputs & covered) == 0) {
                result.add(a);
                covered |= a.inputs;
            }
        }
        return covered == needed ? result : null;
    }

    private static Step signNext(Context c, Ticket.Builder b, State into) {
        int needed = signingNeeded(c);
        if (needed == 0) return to(c, b, into, "nothing left to sign");
        List<Authorization> grants = signGrants(c, needed);
        if (grants == null) return null; // Waits for the SIGN grant.
        Entry e = entry(c, Crossing.SIGN, grants.get(0).authorizationId, c.ids.get());
        return issue(c, b, into, e, "sign");
    }

    private static Step signing(Context c, Ticket.Builder b) {
        Ticket t = c.ticket;
        Entry last = t.last(Crossing.SIGN);
        for (Entry e : t.ledger) {
            if (e.crossing != Crossing.SIGN) continue;
            Classification seen = c.view.signer(e.reference);
            if (seen == Classification.SIGN_REFUSED || seen == Classification.SIGN_CANNOT_COMPLETE) {
                return to(c, b.clear(FLAG_UNRESOLVED), State.SIGN_FAILED, "the signer refused or proved no completion");
            }
        }
        if (last != null && c.view.signer(last.reference) != Classification.SIGN_COMPLETED) {
            return unresolved(c, b, "signing reply missing: resolved only by its request ID");
        }
        b.clear(FLAG_UNRESOLVED);
        if (signingNeeded(c) == 0) return to(c, b, State.SIGNED, "every transaction verified and private");
        return signNext(c, b, State.SIGNING);
    }

    // The plan's publication read back complete after a PUBLISH attempt of any of its tickets, and
    // no attempt read a mismatch. A plan has one publication, which never changes once written.
    private static boolean published(Context c) {
        boolean complete = false;
        for (Ticket other : c.planTickets) {
            for (Entry e : other.ledger) {
                if (e.crossing != Crossing.PUBLISH) continue;
                Classification seen = c.view.publication(e.reference, c.plan.planId);
                if (seen == Classification.BUNDLE_MISMATCH) return false;
                complete |= seen == Classification.BUNDLE_PUBLISHED;
            }
        }
        return complete;
    }

    // Whether any PUBLISH attempt of the plan's tickets read the plan's publication naming other
    // bytes. Store damage never heals on its own.
    private static boolean mismatch(Context c) {
        for (Ticket other : c.planTickets) {
            for (Entry e : other.ledger) {
                if (e.crossing == Crossing.PUBLISH
                        && c.view.publication(e.reference, c.plan.planId) == Classification.BUNDLE_MISMATCH) {
                    return true;
                }
            }
        }
        return false;
    }

    // A lost acknowledgement is resolved by reading, never by publishing again. Only the plan's
    // publication record read absent after the last attempt's call had ended, in a fact naming
    // that attempt, shows that the attempt had no effect. One more attempt then follows, which the
    // store completes from the bundles it already holds. After a second attempt without effect the
    // ticket holds and alerts, and so does a read of other bytes, which never heals on its own.
    // An unreadable record gives no fact, so the ticket waits.
    private static Step publish(Context c, Ticket.Builder b) {
        Ticket t = c.ticket;
        Entry last = t.last(Crossing.PUBLISH);
        if (last == null) return issue(c, b, State.SIGNED, entry(c, Crossing.PUBLISH, NO_ID, c.ids.get()), "publish");
        if (mismatch(c)) {
            b.set(FLAG_REQUEST_LIMIT);
            return done(c, b, null, null, "the publication names other bytes: holding and alerting");
        }
        if (c.view.publication(last.reference, c.plan.planId) != Classification.BUNDLE_ABSENT) return null;
        if (t.count(Crossing.PUBLISH) < Crossing.PUBLISH.bound) {
            return issue(c, b, State.SIGNED, entry(c, Crossing.PUBLISH, NO_ID, c.ids.get()),
                    "the publication had no effect: publish once more from the held bundles");
        }
        b.set(FLAG_REQUEST_LIMIT);
        return done(c, b, null, null, "a second publication had no effect: holding and alerting");
    }

    // ---------------------------------------------------------- staging

    private static Step stage(Context c, Ticket.Builder b) {
        Plan p = c.plan;
        if (b.cause() != Cause.NONE) return close(c, b, "recorded cause before any session");
        // Version 1 stages SystemUI's class only.
        if (p.componentClass != ComponentClass.STAGED_SYSTEM_APK) return null;
        Authorization stage = unusedStage(c);
        if (stage == null) return null;
        Authorization activate = null;
        if (p.commitMode == CommitMode.LATE) {
            activate = validActivate(c);
            if (activate == null) return null; // Late commit: ACTIVATE before SESSION_INTENT.
        }
        if (!crossingAllowed(c) || c.now.instance < 0) return null;
        if (activate != null && !noticeSatisfied(c, activate)) return notice(c, b, activate, null);
        String nonce = c.ids.get();
        b.reference(Reference.NONE.withNonce(nonce));
        return issue(c, b, State.SESSION_INTENT, entry(c, Crossing.CREATE, stage.authorizationId, nonce), "create");
    }

    private static Step sessionIntent(Context c, Ticket.Builder b) {
        Ticket t = c.ticket;
        Entry create = t.last(Crossing.CREATE);
        Observation reply = c.view.reply(t.ticketId, t.indexOf(create));
        if (reply != null && reply.classification == Classification.REPLY_REFUSED) {
            return to(c, b.clear(FLAG_UNRESOLVED), State.NO_SESSION, "create refused");
        }
        if (reply != null && reply.classification == Classification.REPLY_SUCCESS && complete(reply.reference)
                && (!reply.reference.has(Reference.NONCE) || reply.reference.nonce.equals(t.reference.nonce))) {
            b.reference(merge(t.reference, reply.reference));
            return to(c, b.clear(FLAG_UNRESOLVED), State.SESSION_BOUND, "create reply with its reference");
        }
        // The device route finds the session by nonce.
        for (Observation s : c.view.of(ObservationKind.SESSION)) {
            if (s.reference.has(Reference.NONCE) && s.reference.nonce.equals(t.reference.nonce)
                    && complete(s.reference)) {
                b.reference(merge(t.reference, s.reference));
                return to(c, b.clear(FLAG_UNRESOLVED), State.SESSION_BOUND, "session found by its nonce");
            }
        }
        if (absentAfter(c, create)) {
            return to(c, b.clear(FLAG_UNRESOLVED), State.NO_SESSION,
                    "a complete listing in a later instance shows none");
        }
        return unresolved(c, b, "create reply lost or incomplete");
    }

    private static Step bound(Context c, Ticket.Builder b) {
        Ticket t = c.ticket;
        Plan p = c.plan;
        if (b.cause() != Cause.NONE) return abandon(c, b, "recorded cause with a live session");
        if (goneAfter(c, t.last(Crossing.CREATE))) return to(c, b, State.NATIVE_RECORD_LOST, "session gone");
        if (t.state == State.SESSION_BOUND) {
            Entry write = t.last(Crossing.WRITE);
            if (write == null) {
                if (!crossingAllowed(c) || c.now.instance < 0) return null;
                return issue(c, b, State.SESSION_BOUND, entry(c, Crossing.WRITE, NO_ID, NO_ID), "write");
            }
            Observation reply = c.view.reply(t.ticketId, t.indexOf(write));
            if (reply != null && reply.classification == Classification.REPLY_SUCCESS) {
                return to(c, b, State.WRITTEN, "written");
            }
            return abandon(c, b, "write failed or its reply was lost");
        }
        Authorization activate = validActivate(c);
        if (activate == null) return abandon(c, b, "no unexpired ACTIVATE before commit");
        if (!crossingAllowed(c) || c.now.instance < 0) return null;
        return issue(c, b, State.COMMIT_INTENT, entry(c, Crossing.COMMIT, activate.authorizationId, NO_ID), "commit");
    }

    private static Step commitIntent(Context c, Ticket.Builder b, boolean newBoot) {
        Ticket t = c.ticket;
        if (newBoot) return to(c, b.clear(FLAG_UNRESOLVED), State.BOOT_OBSERVED, "a kernel boot during commit");
        Entry commit = t.last(Crossing.COMMIT);
        Observation reply = c.view.reply(t.ticketId, t.indexOf(commit));
        if (reply != null && reply.classification == Classification.REPLY_READY) {
            return to(c, b.clear(FLAG_UNRESOLVED), State.READY, "commit replied ready");
        }
        Observation s = exactSession(c);
        if (reply != null && reply.classification == Classification.REPLY_REFUSED) {
            // A refusal ends the attempt: a session it left live is abandoned first.
            b.clear(FLAG_UNRESOLVED);
            if (s != null && s.classification.live() && s.classification != Classification.SESSION_READY) {
                return abandon(c, b, "commit refused with the session still open");
            }
            if (s == null && !absentSince(c, null, commit)) return done(c, b, null, null, "commit refused; observing");
            if (s == null || !s.classification.live()) return to(c, b, State.FAILED_NATIVE, "commit refused");
        }
        if (s != null) {
            b.clear(FLAG_UNRESOLVED); // The exact native reference was observed.
            switch (s.classification) {
                case SESSION_READY:
                    return to(c, b, State.READY, "session observed ready");
                case SESSION_FAILED:
                case SESSION_REFUSED:
                    return to(c, b, State.FAILED_NATIVE, "session failed or refused at validation");
                case SESSION_ABANDONED:
                    // Destroyed in memory only: a later framework instance tells whether it stuck.
                    return done(c, b, null, null, "session destroyed; confirmed in a later instance");
                default:
                    if (s.classification.live() && later(s, commit)) {
                        return abandon(c, b, "live but not ready in a later framework instance");
                    }
                    return done(c, b, null, null, "verifying");
            }
        }
        if (goneAfter(c, commit)) return to(c, b.clear(FLAG_UNRESOLVED), State.NATIVE_RECORD_LOST, "session gone");
        return unresolved(c, b, "commit reply lost or ambiguous");
    }

    private static Step ready(Context c, Ticket.Builder b, boolean newBoot) {
        Ticket t = c.ticket;
        Plan p = c.plan;
        if (newBoot) return to(c, b, State.BOOT_OBSERVED, "a boot nobody requested");
        Observation s = exactSession(c);
        if (goneAfter(c, t.last(Crossing.COMMIT))) {
            return to(c, b, State.NATIVE_RECORD_LOST, "Android dropped the session");
        }
        if (s != null && s.classification == Classification.SESSION_ABANDONED) {
            return done(c, b, null, null, "session destroyed; confirmed in a later instance");
        }
        if (b.cause() != Cause.NONE) return abandon(c, b, "recorded cause before activation");
        if (p.commitMode == CommitMode.LATE) return activate(c, b);
        // Early commit: any reboot applies the change while an ACTIVATE stands.
        Authorization activate = validActivate(c);
        if (activate == null) return abandon(c, b, "no unexpired ACTIVATE under early commit");
        if (c.rebootRequested) return activate(c, b);
        return null;
    }

    // Late commit, and early commit at the owner's request: as soon as the boot allows a
    // crossing and after any notice, REBOOT_INTENT under an unexpired ACTIVATE that no reboot has
    // used, otherwise ABANDON_INTENT. Waits only for the checkpoint and the notice.
    private static Step activate(Context c, Ticket.Builder b) {
        Ticket t = c.ticket;
        Plan p = c.plan;
        if (!crossingAllowed(c)) return null;
        Authorization activate = validActivate(c);
        if (activate == null) return abandon(c, b, "no unexpired ACTIVATE that no reboot has used");
        if (lostRequests(t, c.now.boot) >= p.requestLimit) return abandon(c, b, "reboot request limit");
        if (t.count(Crossing.REBOOT) >= Crossing.REBOOT.bound) return abandon(c, b, "the ledger holds no more reboots");
        if (!noticeSatisfied(c, activate)) return notice(c, b, activate, "notice not given or its delay not over");
        return issue(c, b, State.REBOOT_INTENT, entry(c, Crossing.REBOOT, activate.authorizationId, NO_ID),
                "activating reboot");
    }

    // The plan's request limit counts lost reboot requests: each request that the same boot
    // outlived, as the next request in that boot or the current boot shows. A request that took
    // effect is no repeated request, and a READY_AGAIN with an unused ACTIVATE still requests.
    private static int lostRequests(Ticket t, String boot) {
        int lost = 0;
        Entry previous = null;
        for (Entry e : t.ledger) {
            if (e.crossing != Crossing.REBOOT) continue;
            if (previous != null && previous.boot.equals(e.boot)) ++lost;
            previous = e;
        }
        if (previous != null && previous.boot.equals(boot)) ++lost;
        return lost;
    }

    private static Step rebootIntent(Context c, Ticket.Builder b, boolean newBoot) {
        Ticket t = c.ticket;
        Plan p = c.plan;
        if (newBoot) return to(c, b.clear(FLAG_UNRESOLVED), State.BOOT_OBSERVED, "a new boot ID after the request");
        Entry reboot = t.last(Crossing.REBOOT);
        if (c.now != null && c.now.boot.equals(reboot.boot)
                && c.now.elapsed - reboot.elapsed >= p.rebootTimeLimitMillis) {
            b.clear(FLAG_UNRESOLVED);
            if (lostRequests(t, c.now.boot) >= p.requestLimit) return abandon(c, b, "reboot request limit");
            return to(c, b, State.READY, "the same boot after the time limit: the request was lost");
        }
        return unresolved(c, b, "reboot requested");
    }

    private static Step abandonIntent(Context c, Ticket.Builder b, boolean newBoot) {
        Ticket t = c.ticket;
        Plan p = c.plan;
        if (newBoot && committed(t)) {
            return to(c, b.clear(FLAG_UNRESOLVED), State.BOOT_OBSERVED, "a kernel boot came first after commit");
        }
        Entry abandon = t.last(Crossing.ABANDON);
        Observation s = exactSession(c);
        if (s != null && later(s, abandon)) {
            b.clear(FLAG_UNRESOLVED);
            if (s.classification == Classification.SESSION_FAILED
                    || s.classification == Classification.SESSION_REFUSED) {
                return to(c, b, State.ABANDONED, "the session is terminal");
            }
            if (!s.classification.live()) return done(c, b, null, null, "not live; gone only in a complete listing");
            // The earlier abandon had no lasting effect. Only Android can remove the session.
            if (t.count(Crossing.ABANDON) >= p.requestLimit) {
                b.set(FLAG_REQUEST_LIMIT);
                return done(c, b, null, null, "abandon request limit: holding and alerting");
            }
            if (!crossingAllowed(c) || c.now.instance < 0) return done(c, b, null, null, "waiting for the checkpoint");
            return issue(c, b, State.ABANDON_INTENT, entry(c, Crossing.ABANDON, NO_ID, NO_ID), "abandon again");
        }
        if (goneAfter(c, abandon)) return to(c, b.clear(FLAG_UNRESOLVED), State.ABANDONED, "gone in a later instance");
        Observation reply = c.view.reply(t.ticketId, t.indexOf(abandon));
        if (reply != null && reply.classification == Classification.REPLY_SUCCESS) {
            return done(c, b.clear(FLAG_UNRESOLVED), null, null, "abandon replied; confirmed in a later instance");
        }
        return unresolved(c, b, "abandon reply lost or ambiguous");
    }

    // ---------------------------------------------------------- activation boots

    private static Step bootObserved(Context c, Ticket.Builder b) {
        Ticket t = c.ticket;
        Plan p = c.plan;
        Observation active = c.view.latest(ObservationKind.ACTIVE);
        if (active == null || c.view.latest(ObservationKind.FACTORY) == null) return null;
        Bytes bytes = bytes(c, active);
        Observation s = exactSession(c);
        if (s != null) {
            switch (s.classification) {
                case SESSION_APPLIED:
                    if (bytes == Bytes.BUNDLE) return to(c, b, State.APPLIED_PROVISIONAL, "applied in this boot");
                    // An image change waits for the record to go, and the lost record decides.
                    if (cohortChanged(c)) return null;
                    // Other or prior bytes replaced the applied bytes: no session of the ticket lives.
                    b.cause(maxCause(b.cause(), Cause.OTHER_BYTES));
                    return close(c, b, State.DIVERGED, "applied, but other or prior bytes are active");
                case SESSION_FAILED:
                case SESSION_REFUSED:
                    return to(c, b, State.FAILED_NATIVE, "failed at boot");
                case SESSION_ABANDONED:
                    return null; // Gone only in a complete listing.
                default:
                    break;
            }
            if (bytes == Bytes.OTHER && !cohortChanged(c)) {
                b.cause(maxCause(b.cause(), Cause.OTHER_BYTES));
                return abandon(c, b, "other bytes active while the session lives");
            }
            if (t.count(Crossing.ABANDON) > 0) return abandon(c, b, "the earlier abandon had no lasting effect");
            if (s.classification == Classification.SESSION_READY) {
                return to(c, b, State.READY_AGAIN, "made ready again after the boot");
            }
            long completed = c.view.completedAt();
            if (completed >= 0 && c.now != null && c.now.elapsed - completed >= p.verificationWaitMillis) {
                return abandon(c, b, "live but still not ready after verification had time to run");
            }
            return null;
        }
        if (!goneNow(c)) return null;
        switch (bytes) {
            case BUNDLE:
                return to(c, b, State.NATIVE_RECORD_LOST, "record lost, the bundle's bytes active");
            case PRIOR:
                if (t.count(Crossing.ABANDON) > 0) return to(c, b, State.ABANDONED, "abandoned, prior bytes active");
                return to(c, b, State.NATIVE_RECORD_LOST, "record lost, prior bytes active");
            default:
                if (cohortChanged(c)) return to(c, b, State.NATIVE_RECORD_LOST, "record lost on another base");
                b.cause(maxCause(b.cause(), Cause.OTHER_BYTES));
                return close(c, b, State.DIVERGED, "other bytes active and no session of the ticket lives");
        }
    }

    private static Step recordLost(Context c, Ticket.Builder b) {
        Ticket t = c.ticket;
        Observation active = c.view.latest(ObservationKind.ACTIVE);
        if (active == null || c.view.latest(ObservationKind.FACTORY) == null) return null;
        switch (bytes(c, active)) {
            case BUNDLE:
                // A lost record counts as applied only after COMMIT_INTENT. Before it, these bytes
                // came from elsewhere.
                if (committed(t)) return to(c, b, State.APPLIED_PROVISIONAL, "the bundle's bytes are active");
                b.cause(maxCause(b.cause(), Cause.OTHER_BYTES));
                return close(c, b, "the bundle's bytes are active, but the ticket never committed");
            case PRIOR:
                return close(c, b, "prior bytes active: by the recorded cause");
            default:
                if (cohortChanged(c)) {
                    b.cause(maxCause(b.cause(), Cause.VOID_BASE));
                    return close(c, b, State.VOID, "record lost across an image change");
                }
                b.cause(maxCause(b.cause(), Cause.OTHER_BYTES));
                return close(c, b, committed(t) ? State.DIVERGED : State.VOID, "other bytes active");
        }
    }

    // Applied: the session applied or its record lost, the bundle's bytes and versionCode active
    // with the base's UID and context, and the checkpoint observed committed, all in this boot.
    private static boolean appliedFacts(Context c) {
        Plan p = c.plan;
        Observation active = c.view.latest(ObservationKind.ACTIVE);
        if (active == null || !active.digest.equals(bundleApk(c)) || active.version != p.bundleVersion
                || active.number != p.baseUid || !active.text.equals(p.baseContext)) {
            return false;
        }
        Observation s = exactSession(c);
        return s != null ? s.classification == Classification.SESSION_APPLIED : committed(c.ticket) && goneNow(c);
    }

    private static Step applied(Context c, Ticket.Builder b) {
        Selection next = move(c, b.cause());
        String why = next != null ? "applied: the choice moves, or the temporary factory copy stands in"
                : ownMove(c) ? "applied: the choice already names the plan"
                : "applied under a recorded cause or another revision: the choice stays";
        return done(c, b.state(State.APPLIED), null, next, why);
    }

    /**
     * The selection an applied plan owes, or null when it owes none or the selection already holds
     * it. A plan with no recorded cause whose expected revision is still the selection's moves the
     * choice to itself at the next revision. A TEMPORARY_FACTORY plan instead keeps the choice and
     * revision of the plan it stands in for and becomes the selection's {@code temporary} (decision
     * 6). It is computed again at APPLIED and in every step of the health window, so a move lost
     * between two writes is made by the next step and never silently dropped.
     *
     * <p>The owed realization comes from this step's cohort facts, as the cohort check reads them,
     * so a step that closes DIVERGED on other bytes moves the choice with DIVERGED, never CURRENT.
     * The temporary factory state is owed only while the stand in's bytes are active. Otherwise the
     * selection keeps the realization that this round's cohort check read from the same facts.
     * When the step's facts are incomplete, the move keeps the realization it names, and the next
     * round's cohort check reads it again.
     */
    private static Selection move(Context c, Cause cause) {
        Plan p = c.plan;
        Selection s = c.selection;
        if (cause != Cause.NONE || s.revision != p.selectionRevision || c.now == null) return null;
        if (p.target == Target.TEMPORARY_FACTORY) {
            if (s.choice != ChoiceKind.PLAN || !s.planId.equals(p.repairs)) return null;
            Observation active = c.view.latest(ObservationKind.ACTIVE);
            if (active != null && !active.digest.equals(bundleApk(c))) return null;
            Selection next = s.realized(Realization.TEMPORARY_FACTORY, c.view.boot, s.repair, p.planId);
            return next.equals(s) ? null : next;
        }
        Selection next = s.chosen(ChoiceKind.PLAN, p.planId, Realization.CURRENT, c.view.boot, c.now.wall);
        return cohortCheck(next, p, null, c.view, null, null);
    }

    // Whether the selection already holds this plan's own move: the plan chosen at the revision
    // after the one it expected. That is no change of revision against the plan.
    private static boolean ownMove(Context c) {
        Plan p = c.plan;
        Selection s = c.selection;
        return p.target != Target.TEMPORARY_FACTORY && s.choice == ChoiceKind.PLAN && s.planId.equals(p.planId)
                && s.revision == p.selectionRevision + 1;
    }

    // ---------------------------------------------------------- the health window

    private static Step startWindow(Context c, Ticket.Builder b) {
        if (c.now == null) return null;
        Selection owed = move(c, c.ticket.cause);
        b.window(c.now.boot, c.now.elapsed);
        b.health(observeUsers(c, b.health(), c.now.elapsed));
        return done(c, b.state(State.HEALTH_WINDOW), null, owed,
                owed == null ? "health window started" : "health window started; the owed choice moves");
    }

    // A choice move that APPLIED owed and the records do not hold yet goes with the window's step.
    private static Step owing(Context c, Step step, Ticket.Builder b) {
        Selection owed = move(c, c.ticket.cause);
        if (owed == null) return step;
        Step s = step != null ? step : done(c, b, null, null, "observing health");
        return new Step(s.ticket, s.issue, owed, s.reason + "; the owed choice moves");
    }

    // Each closing below waits for the checkpoint commit and is decided again in the next step,
    // so nothing here depends on seeing the boot in the step that counted it.
    private static Step window(Context c, Ticket.Builder b) {
        Ticket t = c.ticket;
        Plan p = c.plan;
        if (c.now == null) return null;
        if (cohortChanged(c)) {
            b.health(finish(b.health(), Outcome.INCONCLUSIVE));
            return close(c, b, State.CLOSED_APPLIED, "an image change ends the window");
        }
        if (!t.windowBoot.equals(c.now.boot)) {
            if ((b.flags() & FLAG_BOOT_LIMIT) != 0) {
                b.health(finish(b.health(), Outcome.UNHEALTHY));
                // Decision 3: the boot limit is an observed failure, so the restoration listed in
                // the approval takes over.
                if (p.healthResponse == HealthResponse.RESTORE_AUTOMATICALLY) {
                    b.successor(p.restorationPlan);
                    return close(c, b, State.SUPERSEDED, "boot limit: automatic restoration listed in the approval");
                }
                return close(c, b, State.CLOSED_APPLIED, "boot limit: UNHEALTHY for every user still observed");
            }
            b.window(c.now.boot, c.now.elapsed);
            return done(c, b, null, null, "a reboot restarts the window");
        }
        Observation active = c.view.latest(ObservationKind.ACTIVE);
        if (active != null && !active.digest.equals(bundleApk(c)) && !cohortChanged(c)) {
            b.cause(maxCause(b.cause(), Cause.OTHER_BYTES));
            b.health(finish(b.health(), Outcome.INCONCLUSIVE));
            return close(c, b, State.DIVERGED, "other bytes became active");
        }
        for (Plan repair : c.repairs) {
            // The restoration approved up front takes over only by automatic restoration below.
            if (repair.repairs.equals(p.planId) && !repair.planId.equals(p.restorationPlan)) {
                b.successor(repair.planId);
                b.health(finish(b.health(), Outcome.INCONCLUSIVE));
                return close(c, b, State.SUPERSEDED, "a repair plan took over");
            }
        }
        List<Health> outcomes = observeUsers(c, b.health(), t.windowStart);
        b.health(outcomes);
        // Decision 3: automatic restoration runs only when the approval listed it, and only on an
        // observed failure. An unavailable observation is never one.
        if (p.healthResponse == HealthResponse.RESTORE_AUTOMATICALLY && failed(outcomes)) {
            b.successor(p.restorationPlan);
            b.health(finish(outcomes, Outcome.INCONCLUSIVE));
            return close(c, b, State.SUPERSEDED, "automatic restoration listed in the approval");
        }
        if (c.now.boot.equals(t.windowBoot) && c.now.elapsed - t.windowStart >= p.healthWindowMillis) {
            b.health(judge(c, outcomes));
            return close(c, b, State.CLOSED_APPLIED, "the window completed");
        }
        return done(c, b, null, null, "observing health");
    }

    // Adds each user seen in the window, marks removals and crashes. Bound by serial.
    private static List<Health> observeUsers(Context c, List<Health> current, long from) {
        List<Health> result = new ArrayList<>(current);
        for (Observation o : c.view.facts()) {
            if (o.user == DeploymentRecords.NO_USER || !o.boot.equals(c.view.boot) || o.elapsed < from) continue;
            boolean user = o.kind == ObservationKind.USER;
            boolean running = o.classification == Classification.RUNNING_UNLOCKED
                    || o.classification == Classification.RUNNING_LOCKED;
            Outcome seen;
            if (user && o.classification == Classification.USER_REMOVED) {
                seen = Outcome.REMOVED;
            } else if (o.classification == Classification.HEALTH_CRASH) {
                seen = Outcome.UNHEALTHY;
            } else if ((user && running) || o.kind == ObservationKind.HEALTH) {
                seen = Outcome.OBSERVING;
            } else {
                continue;
            }
            int at = -1;
            for (int i = 0; i < result.size(); i++) {
                if (result.get(i).user == o.user && result.get(i).serial == o.serial) at = i;
            }
            if (at < 0) {
                if (seen == Outcome.REMOVED) continue; // Never observed: no claim.
                result.add(new Health(o.user, o.serial, seen));
            } else if (result.get(at).outcome == Outcome.OBSERVING && seen != Outcome.OBSERVING) {
                result.set(at, new Health(o.user, o.serial, seen));
            }
        }
        result.sort((x, y) -> x.user != y.user ? Integer.compare(x.user, y.user) : Long.compare(x.serial, y.serial));
        if (result.size() > DeploymentRecords.MAX_USERS) return current;
        return result;
    }

    /**
     * The plan declares no probe interval. A user is healthy only when full probes leave no part of
     * the window longer than this share of it unobserved.
     */
    static final int WINDOW_PARTS = 4;

    // Judges each user still observed when the window completes. HEALTHY needs the declared
    // criteria to have held across the whole window for that user: every probe of the user in the
    // window held every declared criterion, and those probes cover the user's span with no gap
    // above a quarter of the window. The span runs from the window's start, or from the user's first
    // observed unlock in the boot when that came later, to the window's declared end. A DEGRADED
    // probe gives DEGRADED. Any other doubt, a gap, or no probe at all gives INCONCLUSIVE, never a
    // failure. A stale base is never healthy.
    private static List<Health> judge(Context c, List<Health> outcomes) {
        Plan p = c.plan;
        long from = c.ticket.windowStart;
        long end = from + p.healthWindowMillis;
        long gap = p.healthWindowMillis / WINDOW_PARTS;
        List<Health> result = new ArrayList<>();
        for (Health h : outcomes) {
            if (h.outcome != Outcome.OBSERVING) {
                result.add(h);
                continue;
            }
            boolean degraded = false, doubt = false;
            List<Long> held = new ArrayList<>();
            for (Observation o : c.view.of(ObservationKind.HEALTH)) {
                if (o.user != h.user || o.serial != h.serial || o.elapsed < from) continue;
                switch (o.classification) {
                    case HEALTH_HELD:
                        if ((o.number & p.criteria) == p.criteria) held.add(o.elapsed); else doubt = true;
                        break;
                    case HEALTH_DEGRADED:
                        degraded = true;
                        break;
                    default:
                        doubt = true;
                        break;
                }
            }
            // The span starts at the window's start. It starts later only with evidence that the
            // user was not yet unlocked: a listing of the users after the window began and before
            // the user's first observed unlock in the boot. The USER reader gives every user or
            // none, so such a listing shows the user locked, stopped or absent. The span then
            // starts at the latest such listing. Without one, time before the first observed unlock
            // was not observed, and the gap leaves the user INCONCLUSIVE.
            long start = from;
            long unlocked = firstUnlock(c, h.user, h.serial);
            if (unlocked > from) {
                for (Observation o : c.view.of(ObservationKind.USER)) {
                    if (o.elapsed < unlocked) start = Math.max(start, o.elapsed);
                }
            }
            Outcome outcome;
            if (degraded) outcome = Outcome.DEGRADED;
            else if (covers(held, start, end, gap) && !doubt && !cohortChanged(c)) outcome = Outcome.HEALTHY;
            else outcome = Outcome.INCONCLUSIVE;
            result.add(new Health(h.user, h.serial, outcome));
        }
        return result;
    }

    // When a user was first observed unlocked in this boot, or -1.
    private static long firstUnlock(Context c, int user, long serial) {
        for (Observation o : c.view.of(ObservationKind.USER)) {
            if (o.user == user && o.serial == serial && o.classification == Classification.RUNNING_UNLOCKED) {
                return o.elapsed;
            }
        }
        return -1;
    }

    // Whether probes at these times, in time order, cover a span with no gap above the bound.
    private static boolean covers(List<Long> times, long start, long end, long gap) {
        if (times.isEmpty()) return false;
        if (times.get(0) - start > gap) return false;
        for (int i = 1; i < times.size(); i++) {
            if (times.get(i) - times.get(i - 1) > gap) return false;
        }
        return end - times.get(times.size() - 1) <= gap;
    }

    private static List<Health> finish(List<Health> outcomes, Outcome open) {
        List<Health> result = new ArrayList<>();
        for (Health h : outcomes) result.add(h.outcome == Outcome.OBSERVING ? new Health(h.user, h.serial, open) : h);
        return result;
    }

    // ---------------------------------------------------------- grants

    private static Authorization authorization(Context c, String id) {
        for (Authorization a : c.authorizations) if (a.authorizationId.equals(id)) return a;
        return null;
    }

    // A grant is used once a ledger entry of the plan relied on it. An ACTIVATE is used only
    // once a reboot requested under it took effect: a later boot was observed after the request.
    private static boolean used(Context c, Authorization a) {
        for (Ticket t : c.planTickets) {
            Ticket current = t.ticketId.equals(c.ticket.ticketId) ? c.ticket : t;
            for (Entry e : current.ledger) {
                if (!e.grant.equals(a.authorizationId)) continue;
                if (a.effect != Effect.ACTIVATE) return true;
                if (e.crossing == Crossing.REBOOT && !current.boot.equals(e.boot)) return true;
            }
        }
        return false;
    }

    private static Authorization unusedStage(Context c) {
        for (Authorization a : c.authorizations) if (a.effect == Effect.STAGE && !used(c, a)) return a;
        return null;
    }

    private static boolean expired(Context c, Authorization a) {
        if (c.now == null) return true;
        long wall = c.now.wall;
        return wall < a.grantedAt || wall - a.grantedAt >= c.plan.activateWindowMillis;
    }

    /** An unexpired ACTIVATE that no reboot has used, or null. */
    private static Authorization validActivate(Context c) {
        for (Authorization a : c.authorizations) {
            if (a.effect == Effect.ACTIVATE && !expired(c, a) && !used(c, a)) return a;
        }
        return null;
    }

    // Decision 7 and the owner's detail of 2026-10-10: other running users get notice and the declared
    // delay first, and cannot block the change. The notice records a receipt for each user it
    // reached. The holder needs none: the ACTIVATE's actor, or user 0 for the lab operator who stands
    // in for the owner. Every other user running in this boot, by its latest USER fact, needs a
    // receipt in this boot of a NOTICE of this ticket, and the delay runs from the last of those
    // users' first receipts. Without this boot's user facts the notice is owed and never satisfied.
    private static boolean noticeSatisfied(Context c, Authorization activate) {
        List<Observation> required = noticeUsers(c, activate);
        if (required == null) return false;
        if (required.isEmpty()) return true;
        long last = -1;
        boolean delivered = false;
        for (Observation u : required) {
            Observation r = firstReceipt(c, u.user, u.serial);
            if (r == null) return false;
            last = Math.max(last, r.elapsed);
            delivered |= r.classification == Classification.RECEIPT_SYSTEMUI;
        }
        return c.now.elapsed - last >= noticeDelay(c, delivered);
    }

    // The other users running in this boot, by the latest USER fact of each user and serial, or null
    // without any USER fact of this boot.
    private static List<Observation> noticeUsers(Context c, Authorization activate) {
        List<Observation> users = c.view.of(ObservationKind.USER);
        if (users.isEmpty()) return null;
        List<Observation> latest = new ArrayList<>();
        for (Observation u : users) { // In time order: a later fact of the same user replaces an earlier one.
            latest.removeIf(o -> o.user == u.user && o.serial == u.serial);
            latest.add(u);
        }
        boolean lab = activate.actorClass == ActorClass.LAB_OPERATOR;
        List<Observation> required = new ArrayList<>();
        for (Observation u : latest) {
            boolean running = u.classification == Classification.RUNNING_UNLOCKED
                    || u.classification == Classification.RUNNING_LOCKED;
            boolean holder = lab ? u.user == 0 : u.user == activate.actorUser && u.serial == activate.actorSerial;
            if (running && !holder) required.add(u);
        }
        return required;
    }

    // A user's first receipt in this boot of a NOTICE that this ticket gave in this boot, or null.
    private static Observation firstReceipt(Context c, int user, long serial) {
        Observation first = null;
        for (Observation r : c.view.of(ObservationKind.RECEIPT)) {
            if (r.user != user || r.serial != serial || !givenNow(c, r)) continue;
            if (first == null || r.elapsed < first.elapsed) first = r;
        }
        return first;
    }

    // Whether a receipt records a NOTICE of this ticket given in this boot.
    private static boolean givenNow(Context c, Observation receipt) {
        Ticket t = c.ticket;
        if (!receipt.subject.equals(t.ticketId) || receipt.sequence >= t.ledger.size()) return false;
        Entry e = t.ledger.get(receipt.sequence);
        return e.crossing == Crossing.NOTICE && e.boot.equals(c.view.boot);
    }

    // Decision 7: only a restoration approved in advance may wait the shorter emergency delay, only
    // under an explicit EMERGENCY_NOTICE policy, and only when SystemUI could not deliver the notice:
    // no required receipt came through SystemUI, so each is Andrix's own full screen notice.
    private static long noticeDelay(Context c, boolean delivered) {
        Plan p = c.plan;
        if (p.emergencyNoticeMillis >= p.noticeDelayMillis) return p.noticeDelayMillis;
        boolean policy = false;
        for (Authorization a : c.authorizations) policy |= a.effect == Effect.EMERGENCY_NOTICE;
        boolean approved = approvedRestoration(c);
        return policy && approved && !delivered ? p.emergencyNoticeMillis : p.noticeDelayMillis;
    }

    // A restoration approved in advance: the plan it repairs names it as its restorationPlan, and it
    // installs exactly that plan's restoration bundle: the same input and versionCode, and the APK
    // that the repaired plan's publication bound to its restoration role. A rebuilt variant, any
    // other repair and a temporary factory plan are none.
    private static boolean approvedRestoration(Context c) {
        Plan p = c.plan;
        Plan r = c.repaired;
        if (r == null) return false;
        Observation listed = c.view.bound(r.planId);
        String own = bundleApk(c);
        return p.target == Target.VARIANT && r.restorationPlan.equals(p.planId) && r.hasRestoration()
                && p.bundleInput.equals(r.restorationInput) && p.bundleVersion == r.restorationVersion
                && listed != null && own != null && own.equals(listed.restorationApk);
    }

    private static boolean failed(List<Health> outcomes) {
        for (Health h : outcomes) if (h.outcome == Outcome.UNHEALTHY) return true;
        return false;
    }

    // Gives the notice, or waits for its receipts and its delay. A NOTICE is safe to repeat, so it is
    // given again when this boot's latest one shows no effect: no reply accepted it and no receipt
    // records it, as after a loss before its effect or a refusal. A required user without a receipt
    // gets it again too, at once when the user was not seen running when the latest notice was
    // given, and otherwise once one declared delay has passed since then. Each boot allows the
    // request limit plus one NOTICE entries, so repeats in one boot never cost a later boot its
    // notice, and the ledger's bound holds across boots. The ACTIVATE's expiry bounds every wait.
    private static Step notice(Context c, Ticket.Builder b, Authorization activate, String why) {
        Ticket t = c.ticket;
        Plan p = c.plan;
        int latest = -1;
        for (int i = 0; i < t.ledger.size(); i++) {
            Entry e = t.ledger.get(i);
            if (e.crossing == Crossing.NOTICE && e.boot.equals(c.now.boot)) latest = i;
        }
        if (latest >= 0 && !noticeAgain(c, activate, latest)) return done(c, b, null, null, "notice delay");
        int inBoot = 0;
        for (Entry e : t.ledger) if (e.crossing == Crossing.NOTICE && e.boot.equals(c.now.boot)) ++inBoot;
        if (inBoot >= p.requestLimit + 1 || t.count(Crossing.NOTICE) >= Crossing.NOTICE.bound) {
            if (created(t)) return abandon(c, b, "notice limit");
            b.set(FLAG_REQUEST_LIMIT);
            return done(c, b, null, null, "notice limit: holding and alerting");
        }
        return issue(c, b, t.state, entry(c, Crossing.NOTICE, activate.authorizationId, NO_ID),
                why == null ? "notice before the session" : latest >= 0 ? "notice again" : "notice");
    }

    // Whether this boot's latest notice, at a ledger index, is owed again.
    private static boolean noticeAgain(Context c, Authorization activate, int latest) {
        Ticket t = c.ticket;
        Observation reply = c.view.reply(t.ticketId, latest);
        boolean accepted = reply != null && reply.classification == Classification.REPLY_SUCCESS;
        boolean recorded = false;
        for (Observation r : c.view.of(ObservationKind.RECEIPT)) {
            recorded |= r.subject.equals(t.ticketId) && r.sequence == latest;
        }
        if (!accepted && !recorded) return true;
        List<Observation> required = noticeUsers(c, activate);
        if (required == null) return false;
        long given = t.ledger.get(latest).elapsed;
        boolean waited = c.now.elapsed - given >= c.plan.noticeDelayMillis;
        for (Observation u : required) {
            if (firstReceipt(c, u.user, u.serial) != null) continue;
            boolean seen = false;
            for (Observation o : c.view.of(ObservationKind.USER)) {
                seen |= o.user == u.user && o.serial == u.serial && o.elapsed <= given
                        && (o.classification == Classification.RUNNING_UNLOCKED
                        || o.classification == Classification.RUNNING_LOCKED);
            }
            if (!seen || waited) return true;
        }
        return false;
    }

    // ---------------------------------------------------------- observations

    private static boolean created(Ticket t) { return t.count(Crossing.CREATE) > 0; }

    private static boolean committed(Ticket t) { return t.count(Crossing.COMMIT) > 0; }

    // A crossing into the device waits until this boot's checkpoint is observed committed.
    private static boolean crossingAllowed(Context c) {
        return c.now != null && c.view.checkpoint() == Classification.CHECKPOINT_COMMITTED;
    }

    private static boolean cohortChanged(Context c) {
        Observation boot = c.view.latest(ObservationKind.BOOT);
        Observation factory = c.view.latest(ObservationKind.FACTORY);
        if (boot == null || factory == null) return false;
        return !boot.text.equals(c.plan.fingerprint) || !factory.digest.equals(c.plan.factoryApk);
    }

    private enum Bytes { BUNDLE, PRIOR, OTHER }

    // The APK digest the plan's publication binds to its VARIANT role, or null before it is read.
    private static String bundleApk(Context c) { return c.view.boundApk(c.plan.planId); }

    private static Bytes bytes(Context c, Observation active) {
        if (active.digest.equals(bundleApk(c))) return Bytes.BUNDLE;
        if (active.digest.equals(c.plan.baseApk)) return Bytes.PRIOR;
        return Bytes.OTHER;
    }

    // The states whose rules compare the active bytes with the bundle's.
    private static boolean judgesBytes(State state) {
        return state == State.BOOT_OBSERVED || state == State.APPLIED_PROVISIONAL || state == State.APPLIED
                || state == State.HEALTH_WINDOW || state == State.NATIVE_RECORD_LOST;
    }

    private static Cause observedCause(Context c) {
        Ticket t = c.ticket;
        Plan p = c.plan;
        Cause cause = Cause.NONE;
        if (!reachedApplied(t.state) && t.state != State.APPLIED_PROVISIONAL) {
            // The plan's own move, written before its ticket, is no change of revision.
            if (c.selection.revision != p.selectionRevision && !ownMove(c)) {
                cause = maxCause(cause, Cause.VOID_SELECTION);
            }
            if (!c.trustPolicy.equals(p.trustPolicy)) cause = maxCause(cause, Cause.VOID_TRUST);
            if (c.targetHeld) cause = maxCause(cause, Cause.VOID_TARGET);
        }
        if (cohortChanged(c)) cause = maxCause(cause, Cause.VOID_BASE);
        Observation active = c.view.latest(ObservationKind.ACTIVE);
        // From PUBLISHED on, bytes are judged only against the bundle that the publication read binds.
        boolean unbound = t.state.code >= State.PUBLISHED.code && t.state != State.SIGN_FAILED && bundleApk(c) == null;
        if (active != null && !cohortChanged(c) && !unbound && bytes(c, active) == Bytes.OTHER
                && t.state != State.HEALTH_WINDOW) {
            cause = maxCause(cause, Cause.OTHER_BYTES);
        }
        return cause;
    }

    private static Cause maxCause(Cause a, Cause b) { return b.code > a.code ? b : a; }

    // A reference good enough to bind a session across framework instances: the ID, its
    // createdMillis and installer, and the stage directory or the nonce.
    private static boolean complete(Reference r) {
        return r.has(Reference.SESSION) && r.has(Reference.CREATED) && r.has(Reference.INSTALLER)
                && (r.has(Reference.STAGE_DIR) || r.has(Reference.NONCE));
    }

    private static Reference merge(Reference ticket, Reference seen) {
        Reference merged = new Reference(seen.presence | Reference.NONCE, seen.sessionId, seen.createdMillis,
                seen.stageDir, seen.installerUid, ticket.nonce);
        return merged;
    }

    /** Whether an observed reference is the ticket's exact native reference. */
    static boolean matches(Reference ticket, Reference seen) {
        if (!ticket.has(Reference.SESSION) || !seen.has(Reference.SESSION) || ticket.sessionId != seen.sessionId) {
            return false;
        }
        if (both(ticket, seen, Reference.CREATED) && ticket.createdMillis != seen.createdMillis) return false;
        if (both(ticket, seen, Reference.STAGE_DIR) && !ticket.stageDir.equals(seen.stageDir)) return false;
        if (both(ticket, seen, Reference.INSTALLER) && ticket.installerUid != seen.installerUid) return false;
        if (both(ticket, seen, Reference.NONCE) && !ticket.nonce.equals(seen.nonce)) return false;
        // Session IDs can be issued again: one field that tells a reused ID apart must agree.
        return both(ticket, seen, Reference.CREATED) || both(ticket, seen, Reference.NONCE);
    }

    private static boolean both(Reference a, Reference b, int field) { return a.has(field) && b.has(field); }

    // Whether the ticket's ID in an observation can be told apart from a reused one.
    private static boolean decidable(Reference ticket, Reference seen) {
        return both(ticket, seen, Reference.CREATED) || both(ticket, seen, Reference.NONCE);
    }

    // The latest observation of the exact native reference in this boot, or null.
    private static Observation latestExact(Context c) {
        Observation best = null;
        for (Observation s : c.view.of(ObservationKind.SESSION)) {
            if (matches(c.ticket.reference, s.reference) && (best == null || s.elapsed >= best.elapsed)) best = s;
        }
        return best;
    }

    // The session's current state: its latest exact observation, unless a complete listing taken
    // after it no longer shows it. The latest evidence decides.
    private static Observation exactSession(Context c) {
        Observation s = latestExact(c);
        return s == null || absentSince(c, s, null) ? null : s;
    }

    // Whether a complete listing later than the entry, and not older than the observation, shows
    // no session of the ticket. A listed session's own round lists it, so a tie means a
    // historical observation beside a listing without the session.
    private static boolean absentSince(Context c, Observation exact, Entry e) {
        for (Observation listing : c.view.of(ObservationKind.LISTING)) {
            if (listing.classification == Classification.LISTING_INCOMPLETE || !later(listing, e)) continue;
            if (exact != null && listing.elapsed < exact.elapsed) continue;
            if (listedWithout(c, listing)) return true;
        }
        return false;
    }

    // An observation in a later framework instance than an entry's: another boot, or a later
    // instance of the same one.
    private static boolean later(Observation o, Entry e) {
        return e == null || !o.boot.equals(e.boot) || o.instance > e.instance;
    }

    // A complete listing of this boot, in a later framework instance than the entry, whose
    // sessions are all observed and none is the ticket's, with no exact observation after it.
    private static boolean goneAfter(Context c, Entry e) {
        return absentSince(c, latestExact(c), e);
    }

    private static boolean goneNow(Context c) { return goneAfter(c, null); }

    private static boolean listedWithout(Context c, Observation listing) {
        Reference r = c.ticket.reference;
        int sessions = 0;
        for (Observation s : c.view.of(ObservationKind.SESSION)) {
            if (s.instance != listing.instance) continue;
            if (!s.classification.live() && s.classification != Classification.SESSION_APPLIED
                    && s.classification != Classification.SESSION_FAILED) {
                continue; // Historical entries are not listed sessions.
            }
            ++sessions;
            if (s.reference.sessionId != r.sessionId) continue;
            if (!decidable(r, s.reference) || matches(r, s.reference)) return false;
        }
        return sessions == listing.number;
    }

    // Proof that a lost create made no session: a complete listing in a later framework instance
    // that shows no staged session for the package at all, or on the device route, whose
    // sessions all carry a nonce and none carries the ticket's.
    private static boolean absentAfter(Context c, Entry create) {
        for (Observation listing : c.view.of(ObservationKind.LISTING)) {
            if (!later(listing, create)) continue;
            if (listing.classification == Classification.NONE_FOR_PACKAGE) return true;
            if (listing.classification != Classification.SESSIONS_FOR_PACKAGE || listing.route != Route.DEVICE) {
                continue;
            }
            int sessions = 0;
            boolean ours = false, unread = false;
            for (Observation s : c.view.of(ObservationKind.SESSION)) {
                if (s.instance != listing.instance || !s.classification.live()
                        && s.classification != Classification.SESSION_APPLIED
                        && s.classification != Classification.SESSION_FAILED) {
                    continue;
                }
                ++sessions;
                if (!s.reference.has(Reference.NONCE)) unread = true;
                else if (s.reference.nonce.equals(c.ticket.reference.nonce)) ours = true;
            }
            if (!ours && !unread && sessions == listing.number) return true;
        }
        return false;
    }

    // ---------------------------------------------------------- transitions

    private static Entry entry(Context c, Crossing crossing, String grant, String reference) {
        String boot = c.now == null ? NO_ID : c.now.boot;
        long instance = c.now == null ? -1 : c.now.instance;
        long elapsed = c.now == null ? 0 : c.now.elapsed;
        long wall = c.now == null ? 0 : c.now.wall;
        if (crossing.framework() && instance < 0) throw new IllegalStateException("no framework instance");
        if (boot.equals(NO_ID)) instance = -1;
        return new Entry(crossing, boot, instance, elapsed, grant, reference, wall);
    }

    private static Step to(Context c, Ticket.Builder b, State state, String why) {
        return done(c, b.state(state), null, null, why);
    }

    private static Step issue(Context c, Ticket.Builder b, State state, Entry e, String why) {
        b.state(state).append(e).clear(FLAG_UNRESOLVED);
        return done(c, b, e, null, why);
    }

    // Abandons the exact session: a crossing, so it waits for the checkpoint commit.
    private static Step abandon(Context c, Ticket.Builder b, String why) {
        Ticket t = c.ticket;
        if (!crossingAllowed(c) || c.now.instance < 0) return done(c, b, null, null, why + "; waiting to abandon");
        if (t.count(Crossing.ABANDON) >= c.plan.requestLimit) {
            b.set(FLAG_REQUEST_LIMIT);
            return done(c, b, null, null, why + "; abandon request limit: holding and alerting");
        }
        b.clear(FLAG_UNRESOLVED);
        return issue(c, b, State.ABANDON_INTENT, entry(c, Crossing.ABANDON, NO_ID, NO_ID), why);
    }

    private static Step unresolved(Context c, Ticket.Builder b, String why) {
        return done(c, b.set(FLAG_UNRESOLVED), null, null, why);
    }

    // Closes by the recorded cause: CANCELLED, VOID, or DIVERGED once COMMIT_INTENT was reached.
    private static Step close(Context c, Ticket.Builder b, String why) {
        Cause cause = b.cause();
        State state;
        if (cause == Cause.CANCELLED) state = State.CANCELLED;
        else if (cause.voids()) state = State.VOID;
        else if (cause == Cause.OTHER_BYTES) state = committed(c.ticket) ? State.DIVERGED : State.VOID;
        else state = State.CLOSED_FAILED;
        return close(c, b, state, why);
    }

    // Nothing irreversible before the checkpoint commit: once a session may exist, a ticket closes
    // only in a boot whose checkpoint is observed committed.
    private static Step close(Context c, Ticket.Builder b, State state, String why) {
        if (created(c.ticket) && !crossingAllowed(c)) {
            return done(c, b, null, null, why + "; waiting for the checkpoint");
        }
        b.clear(FLAG_UNRESOLVED).window(NO_ID, 0);
        return done(c, b.state(state), null, null, why);
    }

    private static Step done(Context c, Ticket.Builder b, Entry issue, Selection selection, String why) {
        Ticket next = b.build();
        String broken = TicketMachine.check(c.ticket, next);
        if (broken != null) throw new IllegalStateException("illegal step: " + broken);
        return new Step(next.equals(c.ticket) ? c.ticket : next, issue, selection, why);
    }
}
