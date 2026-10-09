// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.Cause;
import dev.andrix.server.deployment.DeploymentRecords.ChoiceKind;
import dev.andrix.server.deployment.DeploymentRecords.Entry;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.ObservationKind;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Route;
import dev.andrix.server.deployment.DeploymentRecords.Selection;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import dev.andrix.server.deployment.DeploymentStore.Found;
import dev.andrix.server.deployment.DeploymentStore.Read;
import dev.andrix.server.deployment.Reconciler.Clock;
import dev.andrix.server.deployment.Reconciler.Context;
import dev.andrix.server.deployment.Reconciler.Ids;
import dev.andrix.server.deployment.Reconciler.Step;
import dev.andrix.server.deployment.Reconciler.View;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * The host coordinator of one component's tickets: it owns its tickets, reads the device through
 * one readback route, and drives {@link Reconciler#step}. A round observes, records every
 * observation, runs the cohort check, steps, writes and syncs the step's selection and then the
 * stepped ticket, and only then issues the step's crossing. The reply is recorded as an
 * observation; a lost reply records nothing. A coordinator that is lost resumes by observation: a
 * new instance on the same store continues where the records stand, and a crossing whose reply it
 * never recorded counts as lost. Nothing here retries a call.
 *
 * <p>The selection is written before the ticket. A loss between the two writes leaves the choice
 * moved and the ticket one step behind, and the reconciler reads that move as the plan's own. The
 * reconciler also computes an owed move again at APPLIED and in the health window.
 *
 * <p>Host only. The device coordinator is step D7.
 */
public final class Coordinator {
    /** A readback route into the device: its present, what it can read, and its crossings. */
    public interface Device {
        Route route();

        /** The device's present, or null when it cannot be reached. */
        Clock clock();

        /** Everything this route can read now for one ticket's component. */
        List<Observation> observe(Ticket ticket, Plan plan);

        /** Issues one device crossing. Returns the reply as an observation, or null when it is lost. */
        Observation cross(Ticket ticket, Plan plan, Entry entry);
    }

    /** The host signer and artifact store. */
    public interface Host {
        /** Issues one signing request. Returns the signer's reply, or null when it is lost. */
        Observation sign(Ticket ticket, Plan plan, Entry entry, Authorization grant);

        /**
         * Publishes the plan's bundles. Returns the store's read of the plan's publication after the
         * call, naming the entry's attempt, or null when the reply is lost.
         */
        Observation publish(Ticket ticket, Plan plan, Entry entry);

        /**
         * Queries open signing requests by ID, and reads the plan's publication back in a fact that
         * names the ticket's last PUBLISH attempt, whose call has ended by then.
         */
        List<Observation> query(Ticket ticket, Plan plan);
    }

    /** Thrown when a write the protocol requires does not complete. Nothing was issued after it. */
    public static final class StoreRefused extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        StoreRefused(String what) { super(what); }
    }

    /** Named points of a round, for host fault injection. Production passes none. */
    interface Points {
        void at(String point);
    }

    /** The point between the selection write and the ticket write of one round. */
    static final String BETWEEN_WRITES = "selection-written";

    private Points points = point -> { };

    private final DeploymentStore store;
    private final Device device;
    private final Host host;
    private final String trustPolicy;
    private final Ids ids;
    private boolean targetHeld;
    private boolean rebootRequested;
    // Observations are append only and this coordinator is their one writer, so what it has read
    // or written stays valid. A new coordinator reads them all once.
    private List<Observation> observations;

    public Coordinator(DeploymentStore store, Device device, Host host, String trustPolicy, Ids ids) {
        this.store = Objects.requireNonNull(store, "store");
        this.device = Objects.requireNonNull(device, "device");
        this.host = Objects.requireNonNull(host, "host");
        this.trustPolicy = Objects.requireNonNull(trustPolicy, "trustPolicy");
        this.ids = Objects.requireNonNull(ids, "ids");
    }

    /** Host fault injection only. */
    void points(Points points) { this.points = Objects.requireNonNull(points, "points"); }

    /** Whether the native store holds the target. Version 1 refuses such targets at every crossing. */
    public void targetHeld(boolean held) { targetHeld = held; }

    /** The owner's request for the activating reboot now, under early commit. */
    public void rebootRequested(boolean requested) { rebootRequested = requested; }

    /** Records an owner cancellation at once. It takes effect once any intent resolves. */
    public boolean cancel(String ticketId) {
        Ticket ticket = load(ticketId);
        if (ticket.state.terminal() || ticket.cause.code >= Cause.CANCELLED.code) return false;
        Ticket next = ticket.toBuilder().cause(Cause.CANCELLED).build();
        return store.updateTicket(ticket, next);
    }

    private Ticket load(String ticketId) {
        Read<Ticket> read = store.ticket(ticketId);
        if (read.found != Found.RECORD) throw new StoreRefused("ticket unreadable");
        return read.value;
    }

    /** One round for one ticket. Returns the step taken. */
    public Step round(String ticketId) {
        Ticket ticket = load(ticketId);
        Read<Plan> planRead = store.plan(ticket.planId);
        if (planRead.found != Found.RECORD) throw new StoreRefused("plan unreadable");
        Plan plan = planRead.value;
        Clock clock = device.clock();
        List<Observation> seen = new ArrayList<>();
        if (clock != null) seen.addAll(device.observe(ticket, plan));
        seen.addAll(host.query(ticket, plan));
        if (observations == null) observations = new ArrayList<>(store.observations().values);
        for (Observation o : seen) {
            if (repeats(o)) continue;
            if (!store.addObservation(o)) throw new StoreRefused("observation not recorded");
            observations.add(o);
        }
        View view = View.of(clock == null ? DeploymentRecords.NO_ID : clock.boot, plan.component, observations);
        Selection selection = selection(plan.component, view, ticket, plan);
        List<Plan> repairs = new ArrayList<>();
        for (Plan other : store.plans().values) {
            if (other.repairs.equals(plan.planId) && !store.authorizationsOf(other.planId).isEmpty()) {
                repairs.add(other);
            }
        }
        Plan repaired = null;
        if (!plan.repairs.equals(DeploymentRecords.NO_ID)) {
            Read<Plan> repairedRead = store.plan(plan.repairs);
            if (repairedRead.found == Found.RECORD) repaired = repairedRead.value;
        }
        Context context = new Context(plan, ticket, store.authorizationsOf(plan.planId),
                store.ticketsOf(plan.planId), selection, trustPolicy, targetHeld, repairs, repaired, view, clock,
                rebootRequested, ids);
        Step step = Reconciler.step(context);
        // The selection first: a loss before the ticket write leaves a move the next step reads.
        boolean selectionWritten = false;
        if (step.selection != null && !step.selection.equals(selection)) {
            if (!store.putSelection(selection, step.selection)) throw new StoreRefused("selection not written");
            selectionWritten = true;
        }
        if (step.ticket != ticket) {
            if (selectionWritten) points.at(BETWEEN_WRITES);
            if (!store.updateTicket(ticket, step.ticket)) throw new StoreRefused("ticket not written");
        }
        // The entry is synced. Only now is its crossing issued.
        if (step.issue != null) {
            Observation reply = cross(step.ticket, plan, step.issue);
            if (reply != null) {
                if (!store.addObservation(reply)) throw new StoreRefused("reply not recorded");
                if (observations != null) observations.add(reply);
            }
        }
        return step;
    }

    // A fact identical to the latest recorded fact about the same thing, in the same boot and
    // framework instance, adds nothing and is not recorded again. The latest is the one with the
    // largest elapsed time in its boot, as the reconciler's view reads it, never a position in
    // this list: a new coordinator lists the store by ID, and IDs need not rise with time. When
    // several facts share that time, the new fact repeats only if it equals each of them. An older
    // identical fact does not count: a fact that returns after another is recorded again, so the
    // latest fact of its kind stays true. Signer and bundle facts are decided by precedence, not by
    // time, so any identical fact about the same request or bundle settles them. Users and health
    // are judged by time within the health window, so they are always recorded.
    private boolean repeats(Observation o) {
        if (o.kind == ObservationKind.USER || o.kind == ObservationKind.HEALTH) return false;
        boolean precedence = o.kind == ObservationKind.SIGNER || o.kind == ObservationKind.BUNDLE;
        long latest = -1;
        boolean repeat = false;
        for (Observation old : observations) {
            if (!sameSubject(old, o)) continue;
            if (precedence) {
                if (identical(old, o)) return true;
            } else if (old.elapsed > latest) {
                latest = old.elapsed;
                repeat = identical(old, o);
            } else if (old.elapsed == latest) {
                repeat &= identical(old, o);
            }
        }
        return repeat;
    }

    // Facts about the same thing: the same kind, boot, framework instance, route, component, user
    // and request, PUBLISH attempt or ledger entry, and for a session its ID.
    private static boolean sameSubject(Observation a, Observation b) {
        return a.kind == b.kind && a.boot.equals(b.boot) && a.instance == b.instance && a.route == b.route
                && a.component.equals(b.component) && a.user == b.user && a.serial == b.serial
                && a.subject.equals(b.subject) && a.sequence == b.sequence && a.crossing == b.crossing
                && (a.kind != ObservationKind.SESSION || a.reference.sessionId == b.reference.sessionId);
    }

    private static boolean identical(Observation a, Observation b) {
        return a.classification == b.classification && a.text.equals(b.text) && a.digest.equals(b.digest)
                && a.version == b.version && a.number == b.number && a.reference.equals(b.reference);
    }

    private Observation cross(Ticket ticket, Plan plan, Entry entry) {
        switch (entry.crossing) {
            case SIGN:
                Authorization grant = null;
                for (Authorization a : store.authorizationsOf(plan.planId)) {
                    if (a.authorizationId.equals(entry.grant)) grant = a;
                }
                return host.sign(ticket, plan, entry, grant);
            case PUBLISH:
                return host.publish(ticket, plan, entry);
            case HANDOVER:
                return null;
            default:
                return device.cross(ticket, plan, entry);
        }
    }

    // The component's selection after this boot's cohort check, written when it changed.
    private Selection selection(String component, View view, Ticket ticket, Plan plan) {
        Read<Selection> read = store.selection(component);
        if (read.found != Found.RECORD) throw new StoreRefused("selection unreadable");
        Selection current = read.value;
        Plan chosen = null;
        if (current.choice == ChoiceKind.PLAN) {
            Read<Plan> chosenRead = store.plan(current.planId);
            if (chosenRead.found == Found.RECORD) chosen = chosenRead.value;
        }
        Plan temporary = null;
        if (!current.temporary.equals(DeploymentRecords.NO_ID)) {
            Read<Plan> temporaryRead = store.plan(current.temporary);
            if (temporaryRead.found == Found.RECORD) temporary = temporaryRead.value;
        }
        Selection checked = Reconciler.cohortCheck(current, chosen, temporary, view, ticket, plan);
        if (checked != current) {
            if (!store.putSelection(current, checked)) throw new StoreRefused("realization not written");
            return checked;
        }
        return current;
    }

    /** Rounds until a round changes nothing and issues nothing, or the bound is reached. */
    public Step settle(String ticketId, int maxRounds) {
        Step step = null;
        for (int i = 0; i < maxRounds; i++) {
            Ticket before = load(ticketId);
            step = round(ticketId);
            if (step.issue == null && step.ticket.equals(before)) return step;
        }
        return step;
    }

}
