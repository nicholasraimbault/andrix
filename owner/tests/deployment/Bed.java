// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import static dev.andrix.server.deployment.DeploymentRecords.NO_ID;
import static dev.andrix.server.deployment.Fixtures.TIME;
import static dev.andrix.server.deployment.Fixtures.id;

import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.ChoiceKind;
import dev.andrix.server.deployment.DeploymentRecords.Classification;
import dev.andrix.server.deployment.DeploymentRecords.Crossing;
import dev.andrix.server.deployment.DeploymentRecords.Effect;
import dev.andrix.server.deployment.DeploymentRecords.GrantScope;
import dev.andrix.server.deployment.DeploymentRecords.Entry;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Realization;
import dev.andrix.server.deployment.DeploymentRecords.Reference;
import dev.andrix.server.deployment.DeploymentRecords.Selection;
import dev.andrix.server.deployment.DeploymentRecords.State;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import dev.andrix.server.deployment.DeploymentRecords.UpdateResponsibility;
import dev.andrix.server.deployment.Reconciler.Clock;
import dev.andrix.server.deployment.Reconciler.Context;
import dev.andrix.server.deployment.Reconciler.Step;
import dev.andrix.server.deployment.Reconciler.View;
import java.util.ArrayList;
import java.util.List;

/**
 * A test bed for single reconciliation steps: a plan, a ticket built to a state with a plausible
 * ledger, grants, a selection and the facts of one boot, all chosen by the test.
 */
final class Bed {
    static final String B1 = id(0xb1), B2 = id(0xb2), B3 = id(0xb3);
    static final String NONCE = id(0x6e6e);
    static final int SESSION = 4242;
    static final long CREATED = TIME + 5;
    static final String STAGE_DIR = "/data/app-staging/session_4242";
    static final Reference SHELL_REF = new Reference(31, SESSION, CREATED, STAGE_DIR, 2000, NONCE);
    static final String STAGE = id(0x2a1), ACTIVATE = id(0x2a2), SIGN = id(0x2a3), SIGN_RESTORATION = id(0x2a4);

    Plan plan;
    Ticket ticket;
    final List<Authorization> auths = new ArrayList<>();
    final List<Observation> obs = new ArrayList<>();
    final List<Ticket> others = new ArrayList<>();
    final List<Plan> repairs = new ArrayList<>();
    /** The stored plan this plan repairs, or null. */
    Plan repaired;
    Selection selection = new Selection(Fixtures.INSTALLATION, Fixtures.COMPONENT, 0, ChoiceKind.FACTORY, NO_ID,
            UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.UNCHECKED, NO_ID, NO_ID, NO_ID, TIME);
    String trust = Fixtures.TRUST;
    boolean held, reboot;
    String boot = B1;
    long instance = 1, elapsed = 10_000, wall = TIME + 10_000;
    private long n;
    private long ids;

    Bed(Plan plan) {
        this.plan = plan;
        this.ticket = Fixtures.ticket(1, plan).build();
        // The plan's publication as an earlier read found it. A plan cannot know its signed APKs,
        // so every rule that compares the active bytes with the bundle reads them from this fact.
        // It names an attempt that no ticket here holds, so it shows no publication of its own.
        if (plan.target != DeploymentRecords.Target.FACTORY) published(plan);
    }

    /** Adds a read of another plan's publication, binding the fixture APKs signed from its inputs. */
    Bed published(Plan other) {
        return add(Fixtures.published(++n, other, Fixtures.READ_ATTEMPT));
    }

    /** Drops every read of a publication, as for a store whose facts cannot be read. */
    Bed unpublished() {
        obs.removeIf(o -> o.kind == DeploymentRecords.ObservationKind.BUNDLE);
        return this;
    }

    static Bed late() { return new Bed(Fixtures.plan(1).build()); }

    static Bed early() {
        return new Bed(Fixtures.plan(1).commitMode(DeploymentRecords.CommitMode.EARLY).build());
    }

    Bed grant(Effect effect, String authId, long at) {
        int inputs = effect == Effect.SIGN ? 3 : 0;
        auths.add(new Authorization(Fixtures.INSTALLATION, authId, plan.component, plan.planId, effect, inputs,
                DeploymentRecords.ActorClass.LAB_OPERATOR, DeploymentRecords.NO_USER, DeploymentRecords.NO_SERIAL,
                NO_ID, GrantScope.NONE, id(0x3a0), at));
        return this;
    }

    /** STAGE and ACTIVATE granted a minute before the bed's time, and SIGN for both inputs. */
    Bed grants() {
        grant(Effect.SIGN, SIGN, wall - 60_000);
        grant(Effect.STAGE, STAGE, wall - 60_000);
        return grant(Effect.ACTIVATE, ACTIVATE, wall - 60_000);
    }

    static Entry entry(Crossing c, String boot, long instance, long elapsed) {
        String grant = c == Crossing.SIGN ? SIGN : c == Crossing.CREATE ? STAGE
                : c == Crossing.COMMIT || c == Crossing.REBOOT || c == Crossing.NOTICE ? ACTIVATE : NO_ID;
        String reference = c == Crossing.SIGN ? id(0x7e57) : c == Crossing.PUBLISH ? Fixtures.PUBLISH_ATTEMPT
                : c == Crossing.CREATE ? NONCE : NO_ID;
        boolean host = c == Crossing.SIGN || c == Crossing.PUBLISH;
        return new Entry(c, host ? NO_ID : boot, host ? -1 : instance, host ? 0 : elapsed, grant, reference, TIME);
    }

    /**
     * Builds the ticket in a state, with the ledger that leads there in boot B1 and instance 1, and
     * the shell reference once the session is bound.
     */
    Bed at(State state, Crossing... ledger) {
        Ticket.Builder b = Fixtures.ticket(1, plan).state(state).boot(B1);
        if (state == State.HEALTH_WINDOW) b.window(B1, 1000);
        boolean created = false;
        long e = 1000;
        for (Crossing c : ledger) {
            b.append(entry(c, B1, 1, e += 100));
            created |= c == Crossing.CREATE;
        }
        if (created) {
            boolean bound = state != State.SESSION_INTENT && state != State.NO_SESSION;
            b.reference(bound ? SHELL_REF : Reference.NONE.withNonce(NONCE));
        }
        ticket = b.build();
        return this;
    }

    Bed moveTo(String bootId, long instanceValue, long elapsedValue) {
        boot = bootId;
        instance = instanceValue;
        elapsed = elapsedValue;
        return this;
    }

    Observation.Builder f(Classification c) {
        return Fixtures.fact(++n, boot, c, elapsed).at(c.kind == DeploymentRecords.ObservationKind.BOOT
                || c.kind == DeploymentRecords.ObservationKind.CHECKPOINT
                || c.kind == DeploymentRecords.ObservationKind.USER ? -1 : instance, elapsed, wall);
    }

    Bed add(Observation.Builder b) {
        obs.add(b.build());
        return this;
    }

    /** The boot's facts: completed, the checkpoint, the owner's running user, the cohort and the active APK. */
    Bed facts(Classification checkpoint, String activeApk) {
        add(f(Classification.BOOT_COMPLETED));
        user(0, 0, Classification.RUNNING_UNLOCKED);
        add(f(checkpoint));
        add(f(Classification.FACTORY_PRESENT));
        long version = activeApk.equals(Fixtures.signed(plan.bundleInput)) ? plan.bundleVersion
                : activeApk.equals(Fixtures.FACTORY_APK) ? Fixtures.FACTORY_VERSION : 45;
        return add(f(activeApk.equals(Fixtures.FACTORY_APK) ? Classification.FACTORY_COPY : Classification.DATA_COPY)
                .digest(activeApk).version(version));
    }

    Bed committed(String activeApk) { return facts(Classification.CHECKPOINT_COMMITTED, activeApk); }

    Bed session(Classification c, Reference r) {
        return add(f(c).reference(r));
    }

    Bed listing(int count) {
        return add(f(count == 0 ? Classification.NONE_FOR_PACKAGE : Classification.SESSIONS_FOR_PACKAGE).number(count));
    }

    Bed reply(int index, Crossing crossing, Classification c, Reference r) {
        return add(f(c).reply(ticket.ticketId, index, crossing).reference(r)
                .at(crossing.framework() ? instance : -1, elapsed, wall));
    }

    Bed user(int user, long serial, Classification c) {
        return add(f(c).user(user, serial));
    }

    Bed health(int user, long serial, Classification c, int criteria) {
        return add(f(c).user(user, serial).number(criteria));
    }

    /**
     * A host fact: a signer fact names its request, a bundle fact the PUBLISH attempt it read after
     * and this bed's plan.
     */
    Bed host(Classification c, String subject) {
        if (c == Classification.BUNDLE_PUBLISHED) return add(Fixtures.published(++n, plan, subject));
        Observation.Builder b = Fixtures.fact(++n, NO_ID, c, 0).subject(subject);
        if (c.kind == DeploymentRecords.ObservationKind.BUNDLE) b.plan(plan.planId);
        return add(b);
    }

    Context context() {
        List<Ticket> tickets = new ArrayList<>(others);
        tickets.add(ticket);
        return new Context(plan, ticket, auths, tickets, selection, trust, held, repairs, repaired,
                View.of(boot, plan.component, obs), new Clock(boot, instance, elapsed, wall), reboot,
                () -> id(0x1d0000 + (++ids)));
    }

    /** One step, which also becomes the bed's ticket. */
    Step step() {
        Step s = Reconciler.step(context());
        ticket = s.ticket;
        return s;
    }

}
