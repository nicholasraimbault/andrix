// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import static dev.andrix.server.deployment.Fixtures.INSTALLATION;
import static dev.andrix.server.deployment.Fixtures.TIME;

import dev.andrix.server.deployment.AndroidFacade.Apk;
import dev.andrix.server.deployment.AndroidFacade.Call;
import dev.andrix.server.deployment.AndroidFacade.Crash;
import dev.andrix.server.deployment.AndroidFacade.Session;
import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.ChoiceKind;
import dev.andrix.server.deployment.DeploymentRecords.Crossing;
import dev.andrix.server.deployment.DeploymentRecords.Effect;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Realization;
import dev.andrix.server.deployment.DeploymentRecords.Route;
import dev.andrix.server.deployment.DeploymentRecords.Selection;
import dev.andrix.server.deployment.DeploymentRecords.State;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import dev.andrix.server.deployment.DeploymentRecords.UpdateResponsibility;
import dev.andrix.server.deployment.DeploymentStore.Found;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * One coordinated transaction against the Android facade: a store, the facade with one readback
 * route, the host signer and artifact store, and a coordinator that a simulated crash replaces
 * with a fresh instance on the same store. After every settle it checks the invariants that hold
 * in every run: no replay, every ledger entry durable before its crossing, nothing irreversible
 * before the checkpoint commit, no closed ticket with a live session, and the choice moving only
 * at APPLIED. It also records whether each ticket reached APPLIED with no recorded cause, which
 * is when the choice must move, and can lose the coordinator between the selection and ticket
 * writes of a round.
 */
final class World {
    static final String SIGNER = Fixtures.SIGNER;
    static final Apk FACTORY = new Apk(Fixtures.FACTORY_APK, Fixtures.FACTORY_VERSION, SIGNER, true);
    static final Apk BUNDLE = new Apk(Fixtures.BUNDLE_APK, Fixtures.BUNDLE_VERSION, SIGNER, true);
    static final Apk RESTORATION = new Apk(Fixtures.RESTORATION_APK, Fixtures.RESTORATION_VERSION, SIGNER, true);

    final DeploymentStore store;
    final AndroidFacade android;
    final AndroidFacade.Host host;
    final AndroidFacade.Link link;
    final Route route;
    final List<String> violations = new ArrayList<>();
    private final Map<String, State> lastState = new HashMap<>();
    private final Map<String, Selection> lastSelection = new HashMap<>();
    Coordinator coordinator;
    int crashes;
    /** The longest wait between two rounds during a health window, as an operator's probes would come. */
    static final long PROBE = 120_000;
    /** How many rounds that write both records pass before the coordinator is lost between them, or -1. */
    int betweenWrites = -1;
    private boolean lostBetweenWrites;
    private final Map<String, Boolean> appliedWithoutCause = new HashMap<>();
    private long ids;
    private final long seed;

    World(Path root, long seed, Route route) throws IOException {
        Files.createDirectories(root);
        this.seed = seed;
        store = DeploymentStore.unsynced(root, INSTALLATION);
        store.initialize();
        android = new AndroidFacade(seed, FACTORY);
        android.store = store;
        android.apks.put(BUNDLE.digest, BUNDLE);
        android.apks.put(RESTORATION.digest, RESTORATION);
        host = android.host();
        this.route = route;
        link = route == Route.SHELL ? android.shell() : android.device();
        coordinator = coordinator();
        Selection initial = new Selection(INSTALLATION, Fixtures.COMPONENT, 0, ChoiceKind.FACTORY,
                DeploymentRecords.NO_ID, UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.UNCHECKED,
                DeploymentRecords.NO_ID, DeploymentRecords.NO_ID, DeploymentRecords.NO_ID, TIME);
        if (!store.putSelection(null, initial)) throw new IllegalStateException("selection");
    }

    Coordinator coordinator() {
        Coordinator c = new Coordinator(store, link, host, Fixtures.TRUST,
                () -> String.format("%016x%016x", 0x1d5000000000000L | seed, ++ids));
        c.points(point -> {
            if (point.equals(Coordinator.BETWEEN_WRITES) && betweenWrites >= 0 && betweenWrites-- == 0) {
                lostBetweenWrites = true;
                throw new Crash();
            }
        });
        return c;
    }

    /** Notes a coordinator lost between the two writes by a hook of its own. */
    void lostBetweenWrites() { lostBetweenWrites = true; }

    /** Whether the ticket was seen to reach APPLIED with no recorded cause. */
    boolean appliedWithoutCause(String ticketId) { return appliedWithoutCause.getOrDefault(ticketId, false); }

    Plan add(Plan plan) {
        if (!store.addPlan(plan)) throw new IllegalStateException("plan");
        return plan;
    }

    void grant(Authorization a) {
        if (!store.addAuthorization(a)) throw new IllegalStateException("authorization");
    }

    /** The grants a plan needs: SIGN as its signing count says, STAGE and ACTIVATE. */
    void grantAll(Plan plan, long base) {
        int n = (int) base;
        if (plan.signing == 1) {
            int inputs = DeploymentRecords.INPUT_VARIANT
                    | (plan.hasRestoration() ? DeploymentRecords.INPUT_RESTORATION : 0);
            grant(Fixtures.lab(n++, plan, Effect.SIGN, inputs, android.wall()));
        } else if (plan.signing == 2) {
            grant(Fixtures.lab(n++, plan, Effect.SIGN, DeploymentRecords.INPUT_VARIANT, android.wall()));
            grant(Fixtures.lab(n++, plan, Effect.SIGN, DeploymentRecords.INPUT_RESTORATION, android.wall()));
        }
        grant(Fixtures.lab(n++, plan, Effect.STAGE, 0, android.wall()));
        grant(Fixtures.lab(n, plan, Effect.ACTIVATE, 0, android.wall()));
    }

    /** Opens the next attempt of a plan. */
    String open(Plan plan, long n) {
        int attempt = store.ticketsOf(plan.planId).size() + 1;
        Ticket t = Fixtures.ticket(n, plan).attempt(attempt).build();
        if (!store.createTicket(t)) return null;
        return t.ticketId;
    }

    Ticket ticket(String id) {
        DeploymentStore.Read<Ticket> read = store.ticket(id);
        if (read.found != Found.RECORD) throw new IllegalStateException("ticket unreadable");
        return read.value;
    }

    Selection selection() { return store.selection(Fixtures.COMPONENT).value; }

    /**
     * Rounds until a round changes nothing and issues nothing, replacing a crashed coordinator.
     * The invariants are checked after every round.
     */
    void settle(String id) {
        for (int round = 0; round < 80; round++) {
            Ticket before = ticket(id);
            Reconciler.Step step = null;
            try {
                step = coordinator.round(id);
            } catch (Crash lost) {
                ++crashes;
                coordinator = coordinator(); // Resumes by observation.
            }
            check(id);
            if (step != null && step.issue == null && ticket(id).equals(before)) return;
        }
    }

    /**
     * Settles and lets time pass until the ticket closes or the steps run out. Each idle step
     * lets more time pass, up to ten minutes, or up to PROBE during a health window. With
     * escalation an idle ticket outside the window sees a framework restart after four idle steps
     * and a reboot after eight, as an operator would provide.
     * Returns the last ticket value.
     */
    Ticket run(String id, int steps, boolean escalate) {
        return run(id, steps, escalate, null);
    }

    /** As {@link #run(String, int, boolean)}, stopping early once the ticket reaches a state. */
    Ticket run(String id, int steps, boolean escalate, State stop) {
        int idle = 0;
        for (int i = 0; i < steps; i++) {
            Ticket before = ticket(id);
            settle(id);
            Ticket after = ticket(id);
            if (after.state.terminal() || after.state == stop) return after;
            idle = after.equals(before) ? idle + 1 : 0;
            long wait = idle == 0 ? 5_000 : Math.min(600_000, 5_000L << Math.min(idle, 7));
            if (after.state == State.HEALTH_WINDOW) {
                // The health window is observed, not stuck: probes come at least every PROBE
                // milliseconds, and the operator forces no restart.
                android.tick(Math.min(wait, PROBE));
                continue;
            }
            android.tick(wait);
            if (escalate && idle == 4) android.frameworkRestart();
            if (escalate && idle == 8) android.kernelBoot(true);
            if (idle > 12) return after;
        }
        return ticket(id);
    }

    // ------------------------------------------------------------------ invariants

    private void check(String id) {
        Ticket t = ticket(id);
        State before = lastState.put(id, t.state);
        boolean changed = before != t.state;
        if (changed && (t.state.terminal() || t.state == State.APPLIED) && t.count(Crossing.CREATE) > 0
                && android.checkpointPending) {
            violations.add(t.state + " in a boot whose checkpoint is not committed");
        }
        if (t.state.terminal() && t.count(Crossing.CREATE) > 0) {
            for (Session s : android.live.values()) {
                if (s.referrer != null && s.referrer.equals(t.reference.nonce) && s.live()) {
                    violations.add(t.state + " closed with its session live");
                }
            }
        }
        violations.addAll(android.violations);
        android.violations.clear();
        replays(t);
        boolean applied = t.state == State.APPLIED || t.state == State.HEALTH_WINDOW
                || t.state == State.CLOSED_APPLIED || t.state == State.SUPERSEDED;
        if (changed && t.state == State.APPLIED) {
            appliedWithoutCause.put(id, t.cause == DeploymentRecords.Cause.NONE);
        }
        Selection s = selection();
        Selection old = lastSelection.put(id, s);
        // The selection is written before the ticket, so a coordinator lost between the two
        // writes leaves the move with its ticket still APPLIED_PROVISIONAL for one round.
        boolean between = lostBetweenWrites && t.state == State.APPLIED_PROVISIONAL;
        lostBetweenWrites = false;
        if (old != null && (old.choice != s.choice || !old.planId.equals(s.planId))) {
            if (!(applied || between) || !s.planId.equals(t.planId) || t.cause != DeploymentRecords.Cause.NONE) {
                violations.add("the choice moved without its ticket reaching APPLIED");
            }
        }
    }

    // A replay is a second create, write or commit, a signing request beyond the plan's count, a
    // second reboot request in one boot before the time limit, or a repeated abandon of a session
    // that no longer lives.
    private void replays(Ticket t) {
        Plan plan = store.plan(t.planId).value;
        Map<Crossing, Integer> counts = new HashMap<>();
        Call lastReboot = null;
        for (Call call : android.calls) {
            if (!call.ticket.equals(t.ticketId)) continue;
            int n = counts.merge(call.crossing, 1, Integer::sum);
            if ((call.crossing == Crossing.CREATE || call.crossing == Crossing.WRITE
                    || call.crossing == Crossing.COMMIT) && n > 1) {
                violations.add("a second " + call.crossing);
            }
            if (call.crossing == Crossing.SIGN && n > plan.signing) violations.add("a signing request replayed");
            if (call.crossing == Crossing.ABANDON && n > 1 && !call.liveAtIssue) {
                violations.add("an abandon repeated for a session that no longer lives");
            }
            if (call.crossing == Crossing.REBOOT) {
                if (lastReboot != null && lastReboot.boot.equals(call.boot)
                        && call.elapsed - lastReboot.elapsed < plan.rebootTimeLimitMillis) {
                    violations.add("a reboot request repeated before its time limit");
                }
                lastReboot = call;
            }
        }
        if (counts.getOrDefault(Crossing.ABANDON, 0) > t.count(Crossing.ABANDON)
                || counts.getOrDefault(Crossing.REBOOT, 0) > t.count(Crossing.REBOOT)) {
            violations.add("a crossing without its ledger entry");
        }
    }

    /** Whether a session of this ticket lives in memory or in the session file. */
    boolean sessionLives(Ticket t) {
        for (Session s : android.live.values()) {
            if (s.referrer != null && s.referrer.equals(t.reference.nonce) && s.live()) return true;
        }
        return false;
    }

    int calls(String ticketId, Crossing crossing) {
        int n = 0;
        for (Call call : android.calls) if (call.ticket.equals(ticketId) && call.crossing == crossing) ++n;
        return n;
    }
}
