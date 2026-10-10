// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import static dev.andrix.server.deployment.Bed.B1;
import static dev.andrix.server.deployment.Bed.B2;
import static dev.andrix.server.deployment.Bed.B3;
import static dev.andrix.server.deployment.Bed.SHELL_REF;
import static dev.andrix.server.deployment.Cases.check;
import static dev.andrix.server.deployment.DeploymentRecords.FLAG_BOOT_LIMIT;
import static dev.andrix.server.deployment.DeploymentRecords.FLAG_REQUEST_LIMIT;
import static dev.andrix.server.deployment.DeploymentRecords.FLAG_UNRESOLVED;
import static dev.andrix.server.deployment.DeploymentRecords.NO_ID;
import static dev.andrix.server.deployment.Fixtures.BUNDLE_APK;
import static dev.andrix.server.deployment.Fixtures.FACTORY_APK;
import static dev.andrix.server.deployment.Fixtures.TIME;
import static dev.andrix.server.deployment.Fixtures.id;

import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.Cause;
import dev.andrix.server.deployment.DeploymentRecords.ChoiceKind;
import dev.andrix.server.deployment.DeploymentRecords.Classification;
import dev.andrix.server.deployment.DeploymentRecords.CoordinatorClass;
import dev.andrix.server.deployment.DeploymentRecords.Crossing;
import dev.andrix.server.deployment.DeploymentRecords.Effect;
import dev.andrix.server.deployment.DeploymentRecords.GrantScope;
import dev.andrix.server.deployment.DeploymentRecords.Entry;
import dev.andrix.server.deployment.DeploymentRecords.Health;
import dev.andrix.server.deployment.DeploymentRecords.HealthResponse;
import dev.andrix.server.deployment.DeploymentRecords.Outcome;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Realization;
import dev.andrix.server.deployment.DeploymentRecords.Reference;
import dev.andrix.server.deployment.DeploymentRecords.Route;
import dev.andrix.server.deployment.DeploymentRecords.Selection;
import dev.andrix.server.deployment.DeploymentRecords.State;
import dev.andrix.server.deployment.DeploymentRecords.Target;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import dev.andrix.server.deployment.DeploymentRecords.UpdateResponsibility;
import dev.andrix.server.deployment.Reconciler.Step;
import dev.andrix.server.deployment.Reconciler.View;
import dev.andrix.server.deployment.TicketMachine.AtLimit;
import dev.andrix.server.deployment.TicketMachine.Edge;
import dev.andrix.server.deployment.TicketMachine.Loop;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Host checks of the ticket state machine and reconciliation: the exit table against the plan's,
 * every loop bounded or held with an alert, the step check, and each rule of the plan's "Ticket
 * states", "Selection and realization" and recovery sections in single steps built by hand.
 * Host JVM only.
 */
public final class TicketMachineTest {
    private static final Cases cases = new Cases();
    private static final Crossing[] TO_PUBLISHED = {Crossing.SIGN, Crossing.PUBLISH};
    private static final Crossing[] TO_CREATE = {Crossing.SIGN, Crossing.PUBLISH, Crossing.CREATE};
    private static final Crossing[] TO_WRITE = {Crossing.SIGN, Crossing.PUBLISH, Crossing.CREATE, Crossing.WRITE};
    private static final Crossing[] TO_COMMIT = {Crossing.SIGN, Crossing.PUBLISH, Crossing.CREATE, Crossing.WRITE,
        Crossing.COMMIT};
    private static final Crossing[] TO_REBOOT = {Crossing.SIGN, Crossing.PUBLISH, Crossing.CREATE, Crossing.WRITE,
        Crossing.COMMIT, Crossing.REBOOT};

    // The plan's table, restated from its "Ticket states" section.
    private static Map<State, Set<State>> planTable() {
        Map<State, Set<State>> t = new EnumMap<>(State.class);
        t.put(State.PLANNED, EnumSet.of(State.AUTHORIZED, State.CANCELLED, State.VOID));
        t.put(State.AUTHORIZED, EnumSet.of(State.SIGNING, State.CANCELLED, State.VOID));
        t.put(State.SIGNING, EnumSet.of(State.SIGNED, State.SIGN_FAILED));
        t.put(State.SIGNED, EnumSet.of(State.PUBLISHED, State.CANCELLED, State.VOID));
        t.put(State.PUBLISHED, EnumSet.of(State.SESSION_INTENT, State.CANCELLED, State.VOID));
        t.put(State.SESSION_INTENT, EnumSet.of(State.SESSION_BOUND, State.NO_SESSION));
        t.put(State.SESSION_BOUND, EnumSet.of(State.WRITTEN, State.ABANDON_INTENT, State.NATIVE_RECORD_LOST));
        t.put(State.WRITTEN, EnumSet.of(State.COMMIT_INTENT, State.ABANDON_INTENT, State.NATIVE_RECORD_LOST));
        t.put(State.COMMIT_INTENT, EnumSet.of(State.READY, State.FAILED_NATIVE, State.NATIVE_RECORD_LOST,
                State.BOOT_OBSERVED, State.ABANDON_INTENT));
        t.put(State.READY, EnumSet.of(State.REBOOT_INTENT, State.ABANDON_INTENT, State.BOOT_OBSERVED,
                State.NATIVE_RECORD_LOST));
        t.put(State.READY_AGAIN, EnumSet.of(State.REBOOT_INTENT, State.ABANDON_INTENT, State.BOOT_OBSERVED,
                State.NATIVE_RECORD_LOST));
        t.put(State.REBOOT_INTENT, EnumSet.of(State.BOOT_OBSERVED, State.READY, State.ABANDON_INTENT));
        t.put(State.ABANDON_INTENT, EnumSet.of(State.ABANDONED, State.BOOT_OBSERVED, State.ABANDON_INTENT));
        t.put(State.BOOT_OBSERVED, EnumSet.of(State.APPLIED_PROVISIONAL, State.FAILED_NATIVE, State.READY_AGAIN,
                State.ABANDONED, State.NATIVE_RECORD_LOST, State.DIVERGED, State.ABANDON_INTENT));
        t.put(State.APPLIED_PROVISIONAL, EnumSet.of(State.APPLIED, State.BOOT_OBSERVED));
        t.put(State.APPLIED, EnumSet.of(State.HEALTH_WINDOW));
        t.put(State.HEALTH_WINDOW, EnumSet.of(State.CLOSED_APPLIED, State.SUPERSEDED, State.DIVERGED,
                State.HEALTH_WINDOW));
        Set<State> byCause = EnumSet.of(State.CANCELLED, State.VOID, State.CLOSED_FAILED);
        t.put(State.SIGN_FAILED, byCause);
        t.put(State.NO_SESSION, byCause);
        t.put(State.ABANDONED, EnumSet.of(State.CANCELLED, State.VOID, State.DIVERGED, State.CLOSED_FAILED));
        t.put(State.FAILED_NATIVE, EnumSet.of(State.VOID, State.CANCELLED, State.DIVERGED, State.CLOSED_FAILED));
        t.put(State.NATIVE_RECORD_LOST, EnumSet.of(State.APPLIED_PROVISIONAL, State.CANCELLED, State.VOID,
                State.DIVERGED, State.CLOSED_FAILED));
        return t;
    }

    // ------------------------------------------------------------------ the table

    private static void tableCases() {
        cases.run("exits / every state has an exit and terminal states have none", problems -> {
            for (State s : State.values()) {
                Set<State> exits = TicketMachine.exits(s);
                check(problems, s.terminal() == exits.isEmpty(), s + " exits " + exits);
            }
            List<State> terminal = new ArrayList<>();
            for (State s : State.values()) if (s.terminal()) terminal.add(s);
            check(problems, terminal.equals(List.of(State.CLOSED_APPLIED, State.CLOSED_FAILED, State.CANCELLED,
                    State.VOID, State.DIVERGED, State.SUPERSEDED)), "terminal states " + terminal);
            List<State> intents = new ArrayList<>();
            for (State s : State.values()) if (s.intent()) intents.add(s);
            check(problems, intents.equals(List.of(State.SIGNING, State.SESSION_INTENT, State.COMMIT_INTENT,
                    State.REBOOT_INTENT, State.ABANDON_INTENT)), "intent states " + intents);
        });
        cases.run("exits / the table is the plan's table", problems -> {
            Map<State, Set<State>> plan = planTable();
            for (State s : State.values()) {
                if (s.terminal()) continue;
                check(problems, TicketMachine.exits(s).equals(plan.get(s)),
                        s + " has " + TicketMachine.exits(s) + ", the plan " + plan.get(s));
            }
        });
        cases.run("loops / every cycle passes a boot or request edge", problems -> {
            // Without BOOT and REQUEST edges the table is acyclic: a topological order exists.
            Map<State, Set<State>> forward = new EnumMap<>(State.class);
            for (State s : State.values()) forward.put(s, EnumSet.noneOf(State.class));
            for (State[] e : TicketMachine.edges(Edge.FORWARD)) forward.get(e[0]).add(e[1]);
            Set<State> done = EnumSet.noneOf(State.class);
            boolean progress = true;
            while (progress) {
                progress = false;
                for (State s : State.values()) {
                    if (done.contains(s)) continue;
                    if (done.containsAll(forward.get(s))) {
                        done.add(s);
                        progress = true;
                    }
                }
            }
            check(problems, done.size() == State.values().length, "a forward cycle among "
                    + EnumSet.complementOf(EnumSet.copyOf(done)));
            int boot = TicketMachine.edges(Edge.BOOT).size(), request = TicketMachine.edges(Edge.REQUEST).size();
            check(problems, boot == 7 && request == 2, boot + " boot edges, " + request + " request edges");
        });
        cases.run("loops / the four loops are declared bounded or held", problems -> {
            check(problems, TicketMachine.LOOPS.size() == 4, "loops " + TicketMachine.LOOPS);
            for (Loop loop : TicketMachine.LOOPS) {
                check(problems, TicketMachine.edge(loop.from, loop.to) == loop.edge, "edge of " + loop);
            }
            int bounded = 0, held = 0;
            for (Loop loop : TicketMachine.LOOPS) {
                if (loop.atLimit == AtLimit.BOUNDED) ++bounded; else ++held;
            }
            check(problems, bounded == 2 && held == 2, bounded + " bounded, " + held + " held");
            for (State[] e : TicketMachine.edges(Edge.REQUEST)) {
                boolean declared = false;
                for (Loop loop : TicketMachine.LOOPS) declared |= loop.from == e[0] && loop.to == e[1];
                check(problems, declared, "an undeclared request edge " + e[0] + " -> " + e[1]);
            }
        });
        cases.run("check / refuses steps outside the table", problems -> {
            Bed bed = Bed.late().at(State.COMMIT_INTENT, TO_COMMIT);
            Ticket t = bed.ticket;
            check(problems, TicketMachine.check(t, t.toBuilder().state(State.WRITTEN).build()) != null, "backwards");
            check(problems, TicketMachine.check(t, t.toBuilder().state(State.APPLIED).build()) != null, "skip");
            List<Entry> shorter = new ArrayList<>(t.ledger.subList(0, 4));
            check(problems, TicketMachine.check(t, t.toBuilder().ledger(shorter).state(State.COMMIT_INTENT).build())
                    != null, "ledger shrunk");
            check(problems, TicketMachine.check(t, t.toBuilder().state(State.BOOT_OBSERVED).build()) != null,
                    "boot edge without a boot");
            Ticket intent = Bed.late().at(State.WRITTEN, TO_WRITE).ticket;
            check(problems, TicketMachine.check(intent, intent.toBuilder().state(State.COMMIT_INTENT).build()) != null,
                    "intent without its crossing");
            Ticket alerted = t.toBuilder().set(FLAG_BOOT_LIMIT).build();
            check(problems, TicketMachine.check(alerted, t) != null, "alert withdrawn");
            Ticket caused = t.toBuilder().cause(Cause.VOID_TRUST).build();
            check(problems, TicketMachine.check(caused, caused.toBuilder().cause(Cause.CANCELLED).build()) != null,
                    "cause lowered");
            Reference other = new Reference(31, Bed.SESSION, Bed.CREATED + 1, Bed.STAGE_DIR, 2000, Bed.NONCE);
            check(problems, TicketMachine.check(t, t.toBuilder().reference(other).build()) != null, "createdMillis");
            check(problems, TicketMachine.check(t, t.toBuilder().coordinator(CoordinatorClass.DEVICE, id(0xd0))
                    .build()) != null, "coordinator without a handover");
            check(problems, TicketMachine.check(t, t.toBuilder().bootCount(2).boot(B2).build()) != null, "two boots");
            Ticket closed = Bed.late().at(State.CLOSED_FAILED, TO_COMMIT).ticket;
            check(problems, TicketMachine.check(closed, closed.toBuilder().set(FLAG_BOOT_LIMIT).build()) != null,
                    "terminal changed");
            Ticket two = t.toBuilder().append(Bed.entry(Crossing.ABANDON, B1, 1, 9))
                    .append(Bed.entry(Crossing.ABANDON, B1, 1, 10)).state(State.ABANDON_INTENT).build();
            check(problems, TicketMachine.check(t, two) != null, "two crossings in one step");
            Ticket window = Bed.late().at(State.HEALTH_WINDOW, TO_REBOOT).ticket.toBuilder().window(B1, 5).build();
            check(problems, TicketMachine.check(window, window.toBuilder().window(B1, 6).build()) != null,
                    "window restarted without a reboot");
            Ticket judged = window.toBuilder().health(List.of(new Health(0, 0, Outcome.UNHEALTHY))).build();
            check(problems, TicketMachine.check(judged, judged.toBuilder().health(List.of(new Health(0, 0,
                    Outcome.HEALTHY))).build()) != null, "a final outcome changed");
            check(problems, TicketMachine.check(t, t.toBuilder().bootCount(1).boot(B2).state(State.BOOT_OBSERVED)
                    .build()) == null, "the legal boot edge refused");
        });
        cases.run("check / ABANDON_INTENT to BOOT_OBSERVED and every DIVERGED exit need a COMMIT in the ledger",
                problems -> {
            Crossing[] open = {Crossing.SIGN, Crossing.PUBLISH, Crossing.CREATE, Crossing.WRITE, Crossing.ABANDON};
            Crossing[] committed = {Crossing.SIGN, Crossing.PUBLISH, Crossing.CREATE, Crossing.WRITE, Crossing.COMMIT,
                Crossing.ABANDON};
            for (Crossing[] ledger : List.of(open, committed)) {
                boolean legal = ledger == committed;
                Ticket abandon = Bed.late().at(State.ABANDON_INTENT, ledger).ticket;
                check(problems, (TicketMachine.check(abandon, abandon.toBuilder().boot(B2).bootCount(1)
                        .state(State.BOOT_OBSERVED).build()) == null) == legal, "ABANDON_INTENT to BOOT_OBSERVED, "
                        + (legal ? "committed" : "uncommitted"));
                for (State from : List.of(State.ABANDONED, State.FAILED_NATIVE, State.NATIVE_RECORD_LOST,
                        State.BOOT_OBSERVED, State.HEALTH_WINDOW)) {
                    Ticket before = Bed.late().at(from, ledger).ticket;
                    Ticket diverged = before.toBuilder().cause(Cause.OTHER_BYTES).window(NO_ID, 0)
                            .state(State.DIVERGED).build();
                    check(problems, (TicketMachine.check(before, diverged) == null) == legal, from + " to DIVERGED, "
                            + (legal ? "committed" : "uncommitted"));
                }
            }
        });
    }

    // ------------------------------------------------------------------ unresolved intents

    private static void unresolvedCases() {
        cases.run("unresolved / every intent state waits without evidence and never replays", problems -> {
            List<Bed> beds = new ArrayList<>();
            Bed signing = Bed.late().grants().at(State.SIGNING, Crossing.SIGN);
            beds.add(signing);
            beds.add(Bed.late().grants().at(State.SESSION_INTENT, TO_CREATE));
            beds.add(Bed.late().grants().at(State.COMMIT_INTENT, TO_COMMIT));
            beds.add(Bed.late().grants().at(State.ABANDON_INTENT, Crossing.SIGN, Crossing.PUBLISH, Crossing.CREATE,
                    Crossing.ABANDON));
            beds.add(Bed.late().grants().at(State.REBOOT_INTENT, TO_REBOOT));
            for (Bed bed : beds) {
                State state = bed.ticket.state;
                bed.committed(FACTORY_APK).listing(1).session(Classification.LIVE_NOT_READY,
                        new Reference(15, 999, TIME, "/data/app-staging/session_999", 2000, NO_ID));
                for (int i = 0; i < 3; i++) {
                    Step s = bed.step();
                    check(problems, s.issue == null, state + " issued " + s.issue);
                    check(problems, s.ticket.state == state && s.ticket.flag(FLAG_UNRESOLVED),
                            state + " became " + s.ticket);
                }
            }
        });
        cases.run("unresolved / an exact native reference clears the flag", problems -> {
            Bed bed = Bed.late().grants().at(State.COMMIT_INTENT, TO_COMMIT).committed(FACTORY_APK);
            bed.ticket = bed.ticket.toBuilder().set(FLAG_UNRESOLVED).build();
            Reference shell = new Reference(15, Bed.SESSION, Bed.CREATED, Bed.STAGE_DIR, 2000, NO_ID);
            bed.session(Classification.VERIFYING, shell);
            Step s = bed.step();
            check(problems, s.ticket.state == State.COMMIT_INTENT && !s.ticket.flag(FLAG_UNRESOLVED), "verifying " + s);
            bed.elapsed += 10;
            bed.session(Classification.SESSION_READY, shell);
            check(problems, bed.step().ticket.state == State.READY, "ready");
            Bed device = Bed.late().grants().at(State.COMMIT_INTENT, TO_COMMIT).committed(FACTORY_APK);
            device.session(Classification.SESSION_FAILED, new Reference(27, Bed.SESSION, Bed.CREATED, "", 2000,
                    Bed.NONCE));
            check(problems, device.step().ticket.state == State.FAILED_NATIVE, "device route failure");
        });
        cases.run("unresolved / a reused session ID is not the exact reference", problems -> {
            Bed bed = Bed.late().grants().at(State.COMMIT_INTENT, TO_COMMIT).moveTo(B1, 2, 20_000)
                    .committed(FACTORY_APK).listing(1);
            bed.session(Classification.SESSION_READY, new Reference(15, Bed.SESSION, Bed.CREATED + 7, Bed.STAGE_DIR,
                    2000, NO_ID));
            Step s = bed.step();
            check(problems, s.ticket.state == State.NATIVE_RECORD_LOST, "the reused ID bound " + s);
            Bed nonce = Bed.late().grants().at(State.READY, TO_COMMIT).moveTo(B1, 2, 20_000).committed(FACTORY_APK)
                    .listing(1);
            nonce.session(Classification.SESSION_READY, new Reference(27, Bed.SESSION, Bed.CREATED, "", 2000,
                    id(0x6e6f)));
            check(problems, nonce.step().ticket.state == State.NATIVE_RECORD_LOST, "another nonce bound");
        });
        cases.run("unresolved / proof of absence clears the flag", problems -> {
            Bed shell = Bed.late().grants().at(State.SESSION_INTENT, TO_CREATE).moveTo(B1, 2, 20_000)
                    .committed(FACTORY_APK).listing(0);
            Step s = shell.step();
            check(problems, s.ticket.state == State.NO_SESSION && !s.ticket.flag(FLAG_UNRESOLVED), "shell " + s);
            Bed device = Bed.late().grants().at(State.SESSION_INTENT, TO_CREATE).moveTo(B1, 2, 20_000)
                    .committed(FACTORY_APK);
            device.add(device.f(Classification.SESSIONS_FOR_PACKAGE).number(1).route(Route.DEVICE));
            device.session(Classification.LIVE_NOT_READY, new Reference(27, 77, TIME, "", 1000, id(0x6e70)));
            check(problems, device.step().ticket.state == State.NO_SESSION, "device listing without the nonce");
            Bed found = Bed.late().grants().at(State.SESSION_INTENT, TO_CREATE).committed(FACTORY_APK);
            found.session(Classification.OPEN, new Reference(27, Bed.SESSION, Bed.CREATED, "", 1000, Bed.NONCE));
            Step bound = found.step();
            check(problems, bound.ticket.state == State.SESSION_BOUND && bound.ticket.reference.sessionId == Bed.SESSION,
                    "found by nonce " + bound);
            Bed signer = Bed.late().grants().at(State.SIGNING, Crossing.SIGN)
                    .host(Classification.SIGN_CANNOT_COMPLETE, id(0x7e57));
            check(problems, signer.step().ticket.state == State.SIGN_FAILED, "signer proof");
            Bed completed = Bed.late().grants().at(State.SIGNING, Crossing.SIGN)
                    .host(Classification.SIGN_COMPLETED, id(0x7e57));
            check(problems, completed.step().ticket.state == State.SIGNED, "signed by request ID");
        });
        cases.run("unresolved / a listing in the same framework instance proves nothing", problems -> {
            Bed bed = Bed.late().grants().at(State.SESSION_INTENT, TO_CREATE).committed(FACTORY_APK).listing(0);
            Step s = bed.step();
            check(problems, s.ticket.state == State.SESSION_INTENT && s.ticket.flag(FLAG_UNRESOLVED), "same " + s);
            Bed abandon = Bed.late().grants().at(State.ABANDON_INTENT, Crossing.SIGN, Crossing.PUBLISH,
                    Crossing.CREATE, Crossing.ABANDON).committed(FACTORY_APK).listing(0);
            check(problems, abandon.step().ticket.state == State.ABANDON_INTENT, "abandon confirmed in its instance");
            abandon.moveTo(B1, 2, 30_000).committed(FACTORY_APK).listing(0);
            check(problems, abandon.step().ticket.state == State.ABANDONED, "later instance");
        });
        cases.run("unresolved / an abandon is repeated only after a later framework instance shows the session live",
                problems -> {
            Bed bed = Bed.late().grants().at(State.ABANDON_INTENT, TO_COMMIT[0], TO_COMMIT[1], TO_COMMIT[2],
                    TO_COMMIT[3], TO_COMMIT[4], Crossing.ABANDON).committed(FACTORY_APK).listing(1)
                    .session(Classification.VERIFYING, SHELL_REF);
            for (int i = 0; i < 2; i++) {
                Step s = bed.step();
                check(problems, s.issue == null && s.ticket.state == State.ABANDON_INTENT,
                        "a deferred abandon repeated in its instance " + s);
            }
            bed.moveTo(B1, 2, 40_000).committed(FACTORY_APK).listing(1).session(Classification.VERIFYING, SHELL_REF);
            Step later = bed.step();
            check(problems, later.issue != null && later.issue.crossing == Crossing.ABANDON, "a later instance " + later);
        });
        cases.run("unresolved / the shell route never sees the nonce", problems -> {
            Bed bed = Bed.late().grants().at(State.SESSION_INTENT, TO_CREATE).moveTo(B1, 2, 20_000)
                    .committed(FACTORY_APK).listing(1);
            bed.session(Classification.OPEN, new Reference(15, 5151, TIME, "/data/app-staging/session_5151", 2000,
                    NO_ID));
            for (int i = 0; i < 2; i++) {
                Step s = bed.step();
                check(problems, s.ticket.state == State.SESSION_INTENT && s.ticket.flag(FLAG_UNRESOLVED) && s.issue == null,
                        "a session for the package left " + s);
            }
            Bed incomplete = Bed.late().grants().at(State.SESSION_INTENT, TO_CREATE).committed(FACTORY_APK)
                    .reply(2, Crossing.CREATE, Classification.REPLY_SUCCESS, new Reference(1, Bed.SESSION, 0, "", 0,
                            NO_ID));
            check(problems, incomplete.step().ticket.state == State.SESSION_INTENT, "an ID without its reference bound");
        });
    }

    // ------------------------------------------------------------------ causes

    private static void causeCases() {
        cases.run("cancel / deferred until the intent resolves", problems -> {
            Bed bed = Bed.late().grants().at(State.SESSION_INTENT, TO_CREATE).committed(FACTORY_APK);
            bed.ticket = bed.ticket.toBuilder().cause(Cause.CANCELLED).build();
            Step s = bed.step();
            check(problems, s.ticket.state == State.SESSION_INTENT && s.issue == null, "cut short " + s);
            bed.reply(2, Crossing.CREATE, Classification.REPLY_SUCCESS, new Reference(15, Bed.SESSION, Bed.CREATED,
                    Bed.STAGE_DIR, 2000, NO_ID));
            check(problems, bed.step().ticket.state == State.SESSION_BOUND, "resolved");
            Step abandon = bed.step();
            check(problems, abandon.ticket.state == State.ABANDON_INTENT && abandon.issue != null
                    && abandon.issue.crossing == Crossing.ABANDON, "the live session abandoned first " + abandon);
            bed.moveTo(B1, 2, 40_000).committed(FACTORY_APK).listing(0);
            check(problems, bed.step().ticket.state == State.ABANDONED, "abandoned");
            check(problems, bed.step().ticket.state == State.CANCELLED, "closed by its cause");
            Bed signing = Bed.late().grants().at(State.SIGNING, Crossing.SIGN);
            signing.ticket = signing.ticket.toBuilder().cause(Cause.CANCELLED).build();
            check(problems, signing.step().ticket.state == State.SIGNING, "signing cut short");
            signing.host(Classification.SIGN_COMPLETED, id(0x7e57));
            check(problems, signing.step().ticket.state == State.SIGNED, "signing resolved");
            check(problems, signing.step().ticket.state == State.CANCELLED, "then cancelled");
        });
        cases.run("cancel / before any session the ticket closes at once", problems -> {
            for (State s : List.of(State.PLANNED, State.AUTHORIZED, State.SIGNED, State.PUBLISHED)) {
                Bed bed = Bed.late().grants().at(s, s == State.SIGNED || s == State.PUBLISHED ? TO_PUBLISHED
                        : new Crossing[0]);
                bed.ticket = bed.ticket.toBuilder().cause(Cause.CANCELLED).build();
                Step step = bed.step();
                check(problems, step.ticket.state == State.CANCELLED && step.issue == null, s + " " + step);
            }
        });
        cases.run("void / selection and trust changes void before commit", problems -> {
            Bed sel = Bed.late().grants().at(State.PUBLISHED, TO_PUBLISHED).committed(FACTORY_APK);
            sel.selection = sel.selection.chosen(ChoiceKind.FACTORY, NO_ID, Realization.CURRENT, B1, TIME);
            Step s = sel.step();
            check(problems, s.ticket.state == State.VOID && s.ticket.cause == Cause.VOID_SELECTION, "selection " + s);
            Bed trust = Bed.late().grants().at(State.PUBLISHED, TO_PUBLISHED).committed(FACTORY_APK);
            trust.trust = Fixtures.digest(0x7b);
            check(problems, trust.step().ticket.state == State.VOID, "trust");
            Bed bound = Bed.late().grants().at(State.WRITTEN, TO_WRITE).committed(FACTORY_APK);
            bound.trust = Fixtures.digest(0x7b);
            Step b = bound.step();
            check(problems, b.ticket.state == State.ABANDON_INTENT && b.ticket.cause == Cause.VOID_TRUST,
                    "a live session is abandoned first " + b);
        });
        cases.run("void / after commit a session not yet activated is abandoned and one activating is observed",
                problems -> {
            Bed ready = Bed.late().grants().at(State.READY, TO_COMMIT).committed(FACTORY_APK);
            ready.trust = Fixtures.digest(0x7b);
            Step r = ready.step();
            check(problems, r.ticket.state == State.ABANDON_INTENT, "ready " + r);
            Bed rebooting = Bed.late().grants().at(State.REBOOT_INTENT, TO_REBOOT).committed(FACTORY_APK);
            rebooting.trust = Fixtures.digest(0x7b);
            Step w = rebooting.step();
            check(problems, w.ticket.state == State.REBOOT_INTENT && w.issue == null, "activating " + w);
            rebooting.moveTo(B2, 1, 5_000).committed(BUNDLE_APK).listing(1)
                    .session(Classification.SESSION_APPLIED, SHELL_REF);
            check(problems, rebooting.step().ticket.state == State.BOOT_OBSERVED, "observed to its end");
            check(problems, rebooting.step().ticket.state == State.APPLIED_PROVISIONAL, "provisional");
            Step applied = rebooting.step();
            check(problems, applied.ticket.state == State.APPLIED && applied.selection == null,
                    "a void plan moved the choice " + applied);
        });
        cases.run("native accounts / a held target voids the plan before any crossing", problems -> {
            Bed bed = Bed.late().grants().at(State.PUBLISHED, TO_PUBLISHED).committed(FACTORY_APK);
            bed.held = true;
            Step s = bed.step();
            check(problems, s.ticket.state == State.VOID && s.ticket.cause == Cause.VOID_TARGET && s.issue == null,
                    "published " + s);
            Bed written = Bed.late().grants().at(State.WRITTEN, TO_WRITE).committed(FACTORY_APK);
            written.held = true;
            Step w = written.step();
            check(problems, w.ticket.state == State.ABANDON_INTENT && w.ticket.cause == Cause.VOID_TARGET,
                    "no commit for a held target " + w);
        });
    }

    // ------------------------------------------------------------------ grants and activation

    private static void activationCases() {
        cases.run("late commit / ACTIVATE is required before SESSION_INTENT", problems -> {
            Bed stage = Bed.late().grant(Effect.STAGE, Bed.STAGE, TIME).at(State.PUBLISHED, TO_PUBLISHED)
                    .committed(FACTORY_APK);
            check(problems, stage.step().issue == null, "created without ACTIVATE");
            Bed expired = Bed.late().grant(Effect.STAGE, Bed.STAGE, TIME)
                    .grant(Effect.ACTIVATE, Bed.ACTIVATE, TIME + 10_000 - 3_600_000).at(State.PUBLISHED, TO_PUBLISHED)
                    .committed(FACTORY_APK);
            check(problems, expired.step().issue == null, "created under an expired ACTIVATE");
            Bed valid = Bed.late().grants().at(State.PUBLISHED, TO_PUBLISHED).committed(FACTORY_APK);
            Step s = valid.step();
            check(problems, s.ticket.state == State.SESSION_INTENT && s.issue.crossing == Crossing.CREATE
                    && s.issue.reference.equals(s.ticket.reference.nonce), "create " + s);
            Bed early = Bed.early().grant(Effect.STAGE, Bed.STAGE, TIME).at(State.PUBLISHED, TO_PUBLISHED)
                    .committed(FACTORY_APK);
            check(problems, early.step().ticket.state == State.SESSION_INTENT, "early commit creates on STAGE");
            Bed used = Bed.late().grants().at(State.PUBLISHED, TO_PUBLISHED).committed(FACTORY_APK);
            used.others.add(Fixtures.ticket(2, used.plan).attempt(2).state(State.CLOSED_FAILED).boot(B2)
                    .reference(Reference.NONE.withNonce(id(0x6e99)))
                    .append(new Entry(Crossing.CREATE, B1, 1, 1, id(0x2b0), id(0x6e99), TIME)).build());
            check(problems, used.step().issue != null, "an unused STAGE refused");
        });
        cases.run("early commit / ACTIVATE before COMMIT_INTENT and any reboot applies", problems -> {
            Bed none = Bed.early().grant(Effect.STAGE, Bed.STAGE, TIME).at(State.WRITTEN, TO_WRITE)
                    .committed(FACTORY_APK);
            Step s = none.step();
            check(problems, s.ticket.state == State.ABANDON_INTENT, "committed without ACTIVATE " + s);
            Bed with = Bed.early().grants().at(State.WRITTEN, TO_WRITE).committed(FACTORY_APK);
            check(problems, with.step().ticket.state == State.COMMIT_INTENT, "commit");
            Bed ready = Bed.early().grants().at(State.READY, TO_COMMIT).committed(FACTORY_APK);
            Step wait = ready.step();
            check(problems, wait.ticket.state == State.READY && wait.issue == null, "early commit rebooted " + wait);
            ready.moveTo(B2, 1, 3_000).committed(BUNDLE_APK);
            check(problems, ready.step().ticket.state == State.BOOT_OBSERVED, "any reboot");
            Bed asked = Bed.early().grants().at(State.READY, TO_COMMIT).committed(FACTORY_APK);
            asked.reboot = true;
            check(problems, asked.step().ticket.state == State.REBOOT_INTENT, "the owner's reboot");
        });
        cases.run("ready again / late commit reboots at once under an unexpired unused ACTIVATE", problems -> {
            Bed bed = readyAgain(Bed.late().grants());
            Step s = bed.step();
            check(problems, s.ticket.state == State.REBOOT_INTENT && s.issue != null
                    && s.issue.crossing == Crossing.REBOOT && s.issue.grant.equals(Bed.ACTIVATE), "waited " + s);
        });
        cases.run("ready again / late commit abandons without one", problems -> {
            Bed none = readyAgain(new Bed(Fixtures.plan(1).build()).grant(Effect.STAGE, Bed.STAGE, TIME));
            check(problems, none.step().ticket.state == State.ABANDON_INTENT, "no ACTIVATE");
            Bed used = readyAgain(Bed.late().grants());
            used.ticket = used.ticket.toBuilder().ledger(withReboot(used.ticket)).build();
            Step s = used.step();
            check(problems, s.ticket.state == State.ABANDON_INTENT, "an ACTIVATE a reboot used " + s);
            Bed lost = readyAgain(Bed.late().grants());
            lost.ticket = lost.ticket.toBuilder().ledger(withRebootIn(lost.ticket, B2)).build();
            check(problems, lost.step().ticket.state == State.REBOOT_INTENT, "a request that never took effect");
        });
        cases.run("ready again / an expired ACTIVATE is never used", problems -> {
            Bed late = Bed.late().grant(Effect.STAGE, Bed.STAGE, TIME)
                    .grant(Effect.ACTIVATE, Bed.ACTIVATE, TIME + 10_000 - 3_600_000).at(State.READY, TO_COMMIT)
                    .committed(FACTORY_APK);
            Step s = late.step();
            check(problems, s.ticket.state == State.ABANDON_INTENT, "expired by the window " + s);
            Bed back = Bed.late().grant(Effect.STAGE, Bed.STAGE, TIME)
                    .grant(Effect.ACTIVATE, Bed.ACTIVATE, TIME + 20_000).at(State.READY, TO_COMMIT)
                    .committed(FACTORY_APK);
            check(problems, back.step().ticket.state == State.ABANDON_INTENT, "a grant time after the clock");
            Bed edge = Bed.late().grant(Effect.STAGE, Bed.STAGE, TIME)
                    .grant(Effect.ACTIVATE, Bed.ACTIVATE, TIME + 10_000 - 3_600_000 + 1).at(State.READY, TO_COMMIT)
                    .committed(FACTORY_APK);
            check(problems, edge.step().ticket.state == State.REBOOT_INTENT, "one millisecond before expiry");
            Bed again = readyAgain(Bed.late().grant(Effect.STAGE, Bed.STAGE, TIME)
                    .grant(Effect.ACTIVATE, Bed.ACTIVATE, TIME + 10_000 - 3_600_000));
            check(problems, again.step().ticket.state == State.ABANDON_INTENT, "READY_AGAIN with an expired ACTIVATE");
        });
        cases.run("ready again / the request limit counts lost requests, not reboots that took effect", problems -> {
            Bed bed = Bed.late().grants();
            String[] used = {id(0x2b1), id(0x2b2), id(0x2b3)};
            for (String grant : used) bed.grant(Effect.ACTIVATE, grant, bed.wall - 60_000);
            bed.at(State.READY_AGAIN, TO_COMMIT);
            Ticket.Builder t = bed.ticket.toBuilder();
            String[] boots = {B1, B2, B3};
            for (int i = 0; i < 3; i++) t.append(new Entry(Crossing.REBOOT, boots[i], 1, 5_000, used[i], NO_ID, TIME));
            String now = id(0xb4);
            bed.ticket = t.boot(now).bootCount(3).build(); // Three reboots took effect: none was lost.
            bed.moveTo(now, 1, 60_000).committed(FACTORY_APK).listing(1)
                    .session(Classification.SESSION_READY, SHELL_REF);
            Step s = bed.step();
            check(problems, s.ticket.state == State.REBOOT_INTENT && s.issue != null
                    && s.issue.grant.equals(Bed.ACTIVATE), "abandoned with an unused ACTIVATE " + s);
        });
        cases.run("ready again / notice and its delay come first", problems -> {
            Bed bed = readyAgain(new Bed(Fixtures.plan(1).notice(60_000, 60_000).build()).grants());
            bed.user(10, 12, Classification.RUNNING_UNLOCKED);
            Step notice = bed.step();
            check(problems, notice.ticket.state == State.READY_AGAIN && notice.issue != null
                    && notice.issue.crossing == Crossing.NOTICE, "notice " + notice);
            int given = bed.ticket.indexOf(notice.issue);
            bed.reply(given, Crossing.NOTICE, Classification.REPLY_SUCCESS, Reference.NONE)
                    .receipt(10, 12, given, Classification.RECEIPT_SYSTEMUI);
            bed.elapsed += 30_000;
            bed.wall += 30_000;
            bed.committed(FACTORY_APK).user(10, 12, Classification.RUNNING_UNLOCKED);
            Step early = bed.step();
            check(problems, early.issue == null && early.ticket.state == State.READY_AGAIN, "before the delay " + early);
            bed.elapsed += 30_000;
            bed.wall += 30_000;
            bed.committed(FACTORY_APK).user(10, 12, Classification.RUNNING_UNLOCKED);
            check(problems, bed.step().ticket.state == State.REBOOT_INTENT, "after the delay");
            Bed stale = readyAgain(new Bed(Fixtures.plan(1).notice(60_000, 60_000).build()).grants());
            stale.user(10, 12, Classification.RUNNING_UNLOCKED);
            List<Entry> ledger = new ArrayList<>(stale.ticket.ledger);
            ledger.add(new Entry(Crossing.NOTICE, B1, -1, 1, Bed.ACTIVATE, NO_ID, TIME));
            stale.ticket = stale.ticket.toBuilder().ledger(ledger).build();
            Step fresh = stale.step();
            check(problems, fresh.issue != null && fresh.issue.crossing == Crossing.NOTICE,
                    "a notice from an earlier boot counted " + fresh);
        });
        cases.run("ready again / other running users get notice and a declared delay", problems -> {
            Plan plan = Fixtures.plan(1).notice(60_000, 60_000).build();
            Bed alone = readyAgain(new Bed(plan).grants());
            alone.user(0, 0, Classification.RUNNING_UNLOCKED);
            check(problems, alone.step().ticket.state == State.REBOOT_INTENT, "the holder alone needs no notice");
            Bed other = readyAgain(new Bed(plan).grants());
            other.user(0, 0, Classification.RUNNING_UNLOCKED).user(10, 12, Classification.RUNNING_LOCKED);
            Step notice = other.step();
            check(problems, notice.issue != null && notice.issue.crossing == Crossing.NOTICE, "notice " + notice);
            other.receipt(10, 12, other.ticket.indexOf(notice.issue), Classification.RECEIPT_SYSTEMUI);
            other.elapsed += 60_000;
            other.wall += 60_000;
            other.committed(FACTORY_APK).user(0, 0, Classification.RUNNING_UNLOCKED)
                    .user(10, 12, Classification.RUNNING_LOCKED);
            check(problems, other.step().ticket.state == State.REBOOT_INTENT, "another user blocked the change");
            Bed stopped = readyAgain(new Bed(plan).grants());
            stopped.user(0, 0, Classification.RUNNING_UNLOCKED).user(10, 12, Classification.NOT_RUNNING);
            check(problems, stopped.step().ticket.state == State.REBOOT_INTENT, "a stopped user got notice");
        });
        cases.run("notice / a restoration shortens notice only under an emergency policy", problems -> {
            Plan original = listing(id(0x105));
            Plan restoration = restorationOf(original, 5).notice(60_000, 5_000).build();
            State[] ends = new State[3];
            for (int i = 0; i < 3; i++) {
                Bed bed = readyAgain(new Bed(restoration).grants());
                bed.repaired = original;
                bed.published(original);
                bed.user(10, 12, Classification.RUNNING_UNLOCKED);
                if (i != 1) bed.grant(Effect.EMERGENCY_NOTICE, id(0x2e0), TIME);
                Step given = bed.step();
                Classification reply = i == 0 ? Classification.REPLY_SUCCESS : Classification.REPLY_REFUSED;
                int index = bed.ticket.indexOf(given.issue);
                bed.reply(index, Crossing.NOTICE, reply, Reference.NONE).receipt(10, 12, index,
                        i == 0 ? Classification.RECEIPT_SYSTEMUI : Classification.RECEIPT_FULL_SCREEN);
                bed.elapsed += 10_000;
                bed.wall += 10_000;
                bed.committed(FACTORY_APK).user(10, 12, Classification.RUNNING_UNLOCKED);
                ends[i] = bed.step().ticket.state;
            }
            check(problems, ends[0] == State.READY_AGAIN, "a delivered notice shortened " + ends[0]);
            check(problems, ends[1] == State.READY_AGAIN, "shortened without the policy " + ends[1]);
            check(problems, ends[2] == State.REBOOT_INTENT, "the emergency delay refused " + ends[2]);
        });
        cases.run("notice / a rebuilt variant, an unlisted repair or a temporary factory plan never shortens notice",
                problems -> {
            Plan original = listing(id(0x105));
            Plan unlisted = Fixtures.plan(1).build();
            Plan rebuilt = Fixtures.plan(5).repairs(original.planId).notice(60_000, 5_000).build();
            Plan other = restorationOf(original, 6).notice(60_000, 5_000).build();
            Plan restoration = restorationOf(original, 5).notice(60_000, 5_000).build();
            Object[][] runs = {
                {rebuilt, original, "a rebuilt variant"},
                {other, original, "a repair with the restoration bundle that the approval does not list"},
                {restoration, unlisted, "the repaired plan lists no restoration"},
                {restoration, null, "the repaired plan is unreadable"}};
            for (Object[] run : runs) {
                Bed bed = readyAgain(new Bed((Plan) run[0]).grants());
                bed.repaired = (Plan) run[1];
                if (bed.repaired != null) bed.published(bed.repaired);
                bed.user(10, 12, Classification.RUNNING_UNLOCKED);
                bed.grant(Effect.EMERGENCY_NOTICE, id(0x2e0), TIME);
                Step given = bed.step();
                int index = bed.ticket.indexOf(given.issue);
                bed.reply(index, Crossing.NOTICE, Classification.REPLY_REFUSED, Reference.NONE)
                        .receipt(10, 12, index, Classification.RECEIPT_FULL_SCREEN);
                bed.elapsed += 10_000;
                bed.wall += 10_000;
                bed.committed(FACTORY_APK).user(10, 12, Classification.RUNNING_UNLOCKED);
                State end = bed.step().ticket.state;
                check(problems, end == State.READY_AGAIN, run[2] + " shortened the notice: " + end);
            }
            boolean refused = false;
            try {
                DeploymentRecordsTest.planTemporary().toBuilder().notice(60_000, 5_000).build();
            } catch (IllegalArgumentException expected) {
                refused = true;
            }
            check(problems, refused, "a temporary factory plan with a shorter emergency notice");
        });
        cases.run("notice / the reboot waits for a receipt from every other running user and the delay from the last",
                problems -> {
            Plan plan = Fixtures.plan(1).notice(60_000, 60_000).build();
            Bed bed = readyAgain(new Bed(plan).grants());
            bed.user(10, 12, Classification.RUNNING_UNLOCKED).user(11, 14, Classification.RUNNING_LOCKED);
            Step notice = bed.step();
            int given = bed.ticket.indexOf(notice.issue);
            bed.reply(given, Crossing.NOTICE, Classification.REPLY_SUCCESS, Reference.NONE)
                    .receipt(10, 12, given, Classification.RECEIPT_SYSTEMUI);
            bed.elapsed += 30_000;
            bed.wall += 30_000;
            bed.committed(FACTORY_APK).user(10, 12, Classification.RUNNING_UNLOCKED)
                    .user(11, 14, Classification.RUNNING_LOCKED);
            Step one = bed.step();
            check(problems, one.issue == null && one.ticket.state == State.READY_AGAIN,
                    "rebooted or noticed again with one receipt missing " + one);
            bed.receipt(11, 14, given, Classification.RECEIPT_SYSTEMUI);
            bed.elapsed += 30_000;
            bed.wall += 30_000;
            bed.committed(FACTORY_APK).user(10, 12, Classification.RUNNING_UNLOCKED)
                    .user(11, 14, Classification.RUNNING_LOCKED);
            Step early = bed.step();
            check(problems, early.issue == null && early.ticket.state == State.READY_AGAIN,
                    "the delay ran from the first receipt " + early);
            bed.elapsed += 30_000;
            bed.wall += 30_000;
            bed.committed(FACTORY_APK).user(10, 12, Classification.RUNNING_UNLOCKED)
                    .user(11, 14, Classification.RUNNING_LOCKED);
            check(problems, bed.step().ticket.state == State.REBOOT_INTENT, "the delay from the last receipt");
            Bed blind = readyAgain(new Bed(plan).grants());
            blind.obs.removeIf(o -> o.kind == DeploymentRecords.ObservationKind.USER);
            Step owed = blind.step();
            int index = blind.ticket.indexOf(owed.issue);
            blind.reply(index, Crossing.NOTICE, Classification.REPLY_SUCCESS, Reference.NONE);
            blind.elapsed += 120_000;
            blind.wall += 120_000;
            blind.committed(FACTORY_APK);
            blind.obs.removeIf(o -> o.kind == DeploymentRecords.ObservationKind.USER);
            Step unknown = blind.step();
            check(problems, owed.issue != null && owed.issue.crossing == Crossing.NOTICE
                    && unknown.ticket.state == State.READY_AGAIN, "rebooted without knowing who runs " + unknown);
        });
        cases.run("notice / a notice that shows no effect is given again, and one that took effect is not",
                problems -> {
            Plan plan = Fixtures.plan(1).notice(60_000, 60_000).build();
            String[] runs = {"lost before its effect", "refused", "lost after its effect", "accepted", "a newcomer"};
            for (int i = 0; i < runs.length; i++) {
                Bed bed = readyAgain(new Bed(plan).grants());
                bed.user(10, 12, Classification.RUNNING_UNLOCKED);
                Step first = bed.step();
                int given = bed.ticket.indexOf(first.issue);
                if (i == 1) bed.reply(given, Crossing.NOTICE, Classification.REPLY_REFUSED, Reference.NONE);
                if (i == 2 || i == 4) bed.receipt(10, 12, given, Classification.RECEIPT_SYSTEMUI);
                if (i == 3 || i == 4) bed.reply(given, Crossing.NOTICE, Classification.REPLY_SUCCESS, Reference.NONE);
                bed.elapsed += 1_000;
                bed.wall += 1_000;
                bed.committed(FACTORY_APK).user(10, 12, Classification.RUNNING_UNLOCKED);
                if (i == 4) bed.user(11, 14, Classification.RUNNING_UNLOCKED);
                Step next = bed.step();
                boolean again = next.issue != null && next.issue.crossing == Crossing.NOTICE;
                check(problems, again == (i < 2 || i == 4), runs[i] + ": " + next);
                if (again) {
                    check(problems, bed.ticket.count(Crossing.NOTICE) == 2 && next.ticket.state == State.READY_AGAIN,
                            runs[i] + " ledger " + bed.ticket.ledger);
                }
            }
        });
        cases.run("notice / a user still without a receipt after one declared delay gets the notice again",
                problems -> {
            Plan plan = Fixtures.plan(1).notice(60_000, 60_000).build();
            Bed bed = readyAgain(new Bed(plan).grants());
            bed.user(10, 12, Classification.RUNNING_UNLOCKED).user(11, 14, Classification.RUNNING_UNLOCKED);
            Step first = bed.step();
            int given = bed.ticket.indexOf(first.issue);
            bed.reply(given, Crossing.NOTICE, Classification.REPLY_SUCCESS, Reference.NONE)
                    .receipt(10, 12, given, Classification.RECEIPT_SYSTEMUI);
            List<Step> steps = new ArrayList<>();
            for (int i = 0; i < 12 && bed.ticket.state == State.READY_AGAIN; i++) {
                bed.elapsed += 30_000;
                bed.wall += 30_000;
                bed.committed(FACTORY_APK).user(10, 12, Classification.RUNNING_UNLOCKED)
                        .user(11, 14, Classification.RUNNING_UNLOCKED);
                Step s = bed.step();
                steps.add(s);
                if (s.issue != null && s.issue.crossing == Crossing.NOTICE) {
                    bed.reply(bed.ticket.indexOf(s.issue), Crossing.NOTICE, Classification.REPLY_SUCCESS,
                            Reference.NONE);
                }
            }
            check(problems, steps.get(0).issue == null, "noticed again before one declared delay " + steps.get(0));
            check(problems, steps.get(1).issue != null && steps.get(1).issue.crossing == Crossing.NOTICE,
                    "user 11 never got the notice again " + steps.get(1));
            Step last = steps.get(steps.size() - 1);
            check(problems, bed.ticket.count(Crossing.NOTICE) == plan.requestLimit + 1
                    && last.ticket.state == State.ABANDON_INTENT, "the budget did not end the wait " + last);
            Bed later = readyAgain(new Bed(plan).grants());
            later.user(10, 12, Classification.RUNNING_UNLOCKED).user(11, 14, Classification.RUNNING_UNLOCKED);
            Step again = later.step();
            int index = later.ticket.indexOf(again.issue);
            later.reply(index, Crossing.NOTICE, Classification.REPLY_SUCCESS, Reference.NONE)
                    .receipt(10, 12, index, Classification.RECEIPT_SYSTEMUI);
            later.elapsed += 60_000;
            later.wall += 60_000;
            later.committed(FACTORY_APK).user(10, 12, Classification.RUNNING_UNLOCKED)
                    .user(11, 14, Classification.RUNNING_UNLOCKED);
            Step repeat = later.step();
            later.receipt(11, 14, later.ticket.indexOf(repeat.issue), Classification.RECEIPT_SYSTEMUI);
            later.elapsed += 60_000;
            later.wall += 60_000;
            later.committed(FACTORY_APK).user(10, 12, Classification.RUNNING_UNLOCKED)
                    .user(11, 14, Classification.RUNNING_UNLOCKED);
            check(problems, later.step().ticket.state == State.REBOOT_INTENT, "the repeated notice's receipt");
        });
        cases.run("notice / each boot has its own notice budget", problems -> {
            Plan plan = Fixtures.plan(1).notice(60_000, 60_000).build();
            int budget = plan.requestLimit + 1;
            Bed fresh = readyAgain(new Bed(plan).grants());
            fresh.user(10, 12, Classification.RUNNING_UNLOCKED);
            List<Entry> ledger = new ArrayList<>(fresh.ticket.ledger);
            for (int i = 0; i < budget; i++) {
                ledger.add(new Entry(Crossing.NOTICE, B1, 1, 2_000 + i, Bed.ACTIVATE, NO_ID, TIME));
            }
            fresh.ticket = fresh.ticket.toBuilder().ledger(ledger).build();
            Step given = fresh.step();
            check(problems, given.issue != null && given.issue.crossing == Crossing.NOTICE,
                    "an earlier boot's notices took this boot's " + given);
            Bed spent = readyAgain(new Bed(plan).grants());
            spent.user(10, 12, Classification.RUNNING_UNLOCKED);
            ledger = new ArrayList<>(spent.ticket.ledger);
            for (int i = 0; i < budget; i++) {
                ledger.add(new Entry(Crossing.NOTICE, B2, 1, 2_000 + i, Bed.ACTIVATE, NO_ID, TIME));
            }
            spent.ticket = spent.ticket.toBuilder().ledger(ledger).build();
            Step limit = spent.step();
            check(problems, limit.ticket.state == State.ABANDON_INTENT, "this boot's budget was not kept " + limit);
        });
        cases.run("checkpoint / no crossing and no close before the commit", problems -> {
            Bed again = Bed.late().grants().at(State.READY_AGAIN, TO_COMMIT)
                    .facts(Classification.CHECKPOINT_PENDING, FACTORY_APK);
            again.ticket = again.ticket.toBuilder().boot(B1).build();
            Step s = again.step();
            check(problems, s.issue == null && s.ticket.state == State.READY_AGAIN, "rebooted in the checkpoint " + s);
            Bed abandoned = Bed.late().grants().at(State.ABANDONED, Crossing.SIGN, Crossing.PUBLISH, Crossing.CREATE,
                    Crossing.ABANDON).facts(Classification.CHECKPOINT_PENDING, FACTORY_APK);
            check(problems, abandoned.step().ticket.state == State.ABANDONED, "closed in the checkpoint");
            Bed none = Bed.late().grants().at(State.READY_AGAIN, TO_COMMIT);
            none.add(none.f(Classification.BOOT_COMPLETED));
            check(problems, none.step().issue == null, "a crossing without any checkpoint fact");
            Bed observed = Bed.late().grants().at(State.BOOT_OBSERVED, TO_REBOOT)
                    .facts(Classification.CHECKPOINT_PENDING, FACTORY_APK).listing(1);
            observed.session(Classification.LIVE_NOT_READY, SHELL_REF);
            observed.elapsed = 900_000;
            check(problems, observed.step().issue == null, "abandoned in the checkpoint");
        });
        cases.run("checkpoint / APPLIED only once the checkpoint is observed committed", problems -> {
            Bed bed = Bed.late().grants().at(State.APPLIED_PROVISIONAL, TO_REBOOT)
                    .facts(Classification.CHECKPOINT_PENDING, BUNDLE_APK).listing(1)
                    .session(Classification.SESSION_APPLIED, SHELL_REF);
            Step s = bed.step();
            check(problems, s.ticket.state == State.APPLIED_PROVISIONAL && s.selection == null, "early " + s);
            bed.elapsed += 1000;
            bed.add(bed.f(Classification.CHECKPOINT_COMMITTED));
            Step a = bed.step();
            check(problems, a.ticket.state == State.APPLIED && a.selection != null, "applied " + a);
        });
        cases.run("applied / the bundle's bytes are the APK that its publication bound", problems -> {
            // Without a read of the plan's publication, the evidence is missing: never other bytes.
            Bed bed = Bed.late().grants().at(State.APPLIED_PROVISIONAL, TO_REBOOT).unpublished().committed(BUNDLE_APK);
            bed.listing(1).session(Classification.SESSION_APPLIED, SHELL_REF);
            Ticket before = bed.ticket;
            Step none = bed.step();
            check(problems, none.issue == null && none.ticket.state == before.state && none.ticket.cause == Cause.NONE
                    && none.ticket.flag(FLAG_REQUEST_LIMIT), "judged without its publication " + none);
            bed.published(Fixtures.plan(2).build());
            Step another = bed.step();
            check(problems, another.ticket.state == before.state && another.ticket.cause == Cause.NONE,
                    "another plan's publication read as its own");
            bed.published(bed.plan);
            Step applied = bed.step();
            check(problems, applied.ticket.state == State.APPLIED && applied.ticket.cause == Cause.NONE,
                    "applied with its publication " + applied);
            // Bytes that the publication did not bind are other bytes.
            Bed other = Bed.late().grants().at(State.APPLIED_PROVISIONAL, TO_REBOOT).unpublished();
            other.add(Fixtures.published(0x77, other.plan, Fixtures.READ_ATTEMPT).apks(Fixtures.digest(0xa7),
                    Fixtures.RESTORATION_APK));
            other.committed(BUNDLE_APK).listing(1).session(Classification.SESSION_APPLIED, SHELL_REF);
            Step o = other.step();
            check(problems, o.ticket.state == State.APPLIED_PROVISIONAL && o.ticket.cause == Cause.OTHER_BYTES,
                    "unbound bytes applied " + o);
            // Two reads that disagree bind nothing.
            Bed split = Bed.late().grants().at(State.APPLIED_PROVISIONAL, TO_REBOOT);
            split.add(Fixtures.published(0x78, split.plan, Fixtures.PUBLISH_ATTEMPT).apks(Fixtures.digest(0xa7),
                    Fixtures.RESTORATION_APK));
            split.committed(BUNDLE_APK).listing(1).session(Classification.SESSION_APPLIED, SHELL_REF);
            Step splitStep = split.step();
            check(problems, splitStep.ticket.state == State.APPLIED_PROVISIONAL && splitStep.ticket.cause == Cause.NONE
                    && splitStep.ticket.flag(FLAG_REQUEST_LIMIT), "disagreeing reads applied " + splitStep);
            // The cohort check reads the chosen bytes the same way.
            Plan plan = Fixtures.plan(1).build();
            Selection chosen = new Selection(Fixtures.INSTALLATION, Fixtures.COMPONENT, 1, ChoiceKind.PLAN,
                    plan.planId, UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.DIVERGED, B1, NO_ID,
                    NO_ID, TIME);
            Bed facts = new Bed(plan).unpublished().moveTo(B2, 1, 1000).committed(BUNDLE_APK);
            check(problems, Reconciler.cohortCheck(chosen, plan, null, View.of(B2, Fixtures.COMPONENT, facts.obs), null,
                    null) == chosen, "a realization judged without the chosen plan's publication");
            facts.published(plan);
            check(problems, Reconciler.cohortCheck(chosen, plan, null, View.of(B2, Fixtures.COMPONENT, facts.obs), null,
                    null).realization == Realization.CURRENT, "the chosen bytes not CURRENT");
        });
        cases.run("publish / a missing publication read holds with the alert, and a cancellation still abandons",
                problems -> {
            Bed bed = Bed.late().grants().at(State.READY, TO_COMMIT).unpublished();
            bed.moveTo(B1, 1, 20_000).committed(FACTORY_APK).listing(1).session(Classification.SESSION_READY, SHELL_REF);
            Step held = bed.step();
            check(problems, held.issue == null && held.ticket.state == State.READY
                    && held.ticket.flag(FLAG_REQUEST_LIMIT), "a missing read waited silently or moved on " + held);
            bed.ticket = bed.ticket.toBuilder().cause(Cause.CANCELLED).build();
            Step cancelled = bed.step();
            check(problems, cancelled.issue != null && cancelled.issue.crossing == Crossing.ABANDON
                    && cancelled.ticket.state == State.ABANDON_INTENT, "a cancellation could not abandon " + cancelled);
            // Two reads that disagree hold the same way.
            Bed split = Bed.late().grants().at(State.READY, TO_COMMIT);
            split.add(Fixtures.published(0x7a, split.plan, Fixtures.PUBLISH_ATTEMPT).apks(Fixtures.digest(0xa7),
                    Fixtures.RESTORATION_APK));
            split.moveTo(B1, 1, 20_000).committed(FACTORY_APK).listing(1).session(Classification.SESSION_READY,
                    SHELL_REF);
            Step splitHeld = split.step();
            check(problems, splitHeld.issue == null && splitHeld.ticket.flag(FLAG_REQUEST_LIMIT)
                    && splitHeld.ticket.cause == Cause.NONE, "disagreeing reads " + splitHeld);
        });
        cases.run("publish / a later read of other bytes, or of none after a published read, holds with the alert",
                problems -> {
            // The bed's earlier read bound the bundle. Without a later read the ticket moves on.
            Bed moving = Bed.late().grants().at(State.READY, TO_COMMIT);
            moving.moveTo(B1, 1, 20_000).committed(FACTORY_APK).listing(1).session(Classification.SESSION_READY,
                    SHELL_REF);
            Step moved = moving.step();
            check(problems, moved.issue != null && !moved.ticket.flag(FLAG_REQUEST_LIMIT), "the bed held " + moved);
            // A later read naming other bytes holds the ticket, and a cancellation still abandons.
            Bed bed = Bed.late().grants().at(State.READY, TO_COMMIT);
            bed.host(Classification.BUNDLE_MISMATCH, Fixtures.PUBLISH_ATTEMPT);
            bed.moveTo(B1, 1, 20_000).committed(FACTORY_APK).listing(1).session(Classification.SESSION_READY,
                    SHELL_REF);
            Step held = bed.step();
            check(problems, held.issue == null && held.ticket.state == State.READY
                    && held.ticket.flag(FLAG_REQUEST_LIMIT), "a later read of other bytes was ignored " + held);
            bed.ticket = bed.ticket.toBuilder().cause(Cause.CANCELLED).build();
            Step cancelled = bed.step();
            check(problems, cancelled.issue != null && cancelled.issue.crossing == Crossing.ABANDON
                    && cancelled.ticket.state == State.ABANDON_INTENT, "a cancellation could not abandon " + cancelled);
            // An attempt that read the publication published and also absent has lost it.
            Bed gone = Bed.late().grants().at(State.READY, TO_COMMIT);
            gone.host(Classification.BUNDLE_PUBLISHED, Fixtures.PUBLISH_ATTEMPT);
            gone.host(Classification.BUNDLE_ABSENT, Fixtures.PUBLISH_ATTEMPT);
            gone.moveTo(B1, 1, 20_000).committed(FACTORY_APK).listing(1).session(Classification.SESSION_READY,
                    SHELL_REF);
            Step goneHeld = gone.step();
            check(problems, goneHeld.issue == null && goneHeld.ticket.state == State.READY
                    && goneHeld.ticket.flag(FLAG_REQUEST_LIMIT), "a lost publication was ignored " + goneHeld);
            // An absent read of an attempt that never read it published only shows that attempt had no
            // effect, as before a second publication.
            Bed retried = Bed.late().grants().at(State.READY, TO_COMMIT);
            retried.host(Classification.BUNDLE_ABSENT, id(0x9b2));
            retried.host(Classification.BUNDLE_PUBLISHED, Fixtures.PUBLISH_ATTEMPT);
            retried.moveTo(B1, 1, 20_000).committed(FACTORY_APK).listing(1).session(Classification.SESSION_READY,
                    SHELL_REF);
            Step on = retried.step();
            check(problems, on.issue != null && !on.ticket.flag(FLAG_REQUEST_LIMIT),
                    "an attempt without effect held the ticket " + on);
        });
        cases.run("publish / an absent read recorded before a published read of the same attempt holds with the alert",
                problems -> {
            // Host facts carry no time that orders them, so the reverse order disagrees the same way.
            Bed gone = Bed.late().grants().at(State.READY, TO_COMMIT);
            gone.host(Classification.BUNDLE_ABSENT, Fixtures.PUBLISH_ATTEMPT);
            gone.host(Classification.BUNDLE_PUBLISHED, Fixtures.PUBLISH_ATTEMPT);
            gone.moveTo(B1, 1, 20_000).committed(FACTORY_APK).listing(1).session(Classification.SESSION_READY,
                    SHELL_REF);
            Step held = gone.step();
            check(problems, held.issue == null && held.ticket.state == State.READY
                    && held.ticket.flag(FLAG_REQUEST_LIMIT), "an absent read before the published one was ignored " + held);
            // The bound read itself, in both orders.
            for (boolean absentFirst : new boolean[] {true, false}) {
                Bed reads = Bed.late().unpublished();
                reads.host(absentFirst ? Classification.BUNDLE_ABSENT : Classification.BUNDLE_PUBLISHED,
                        Fixtures.PUBLISH_ATTEMPT);
                reads.host(absentFirst ? Classification.BUNDLE_PUBLISHED : Classification.BUNDLE_ABSENT,
                        Fixtures.PUBLISH_ATTEMPT);
                check(problems, View.of(B1, Fixtures.COMPONENT, reads.obs).bound(reads.plan.planId) == null,
                        (absentFirst ? "absent first" : "published first") + ": a publication bound");
            }
        });
        cases.run("applied / a changed UID or context is not applied", problems -> {
            Bed bed = Bed.late().grants().at(State.APPLIED_PROVISIONAL, TO_REBOOT);
            bed.add(bed.f(Classification.BOOT_COMPLETED));
            bed.add(bed.f(Classification.CHECKPOINT_COMMITTED));
            bed.add(bed.f(Classification.FACTORY_PRESENT));
            bed.add(bed.f(Classification.DATA_COPY).digest(BUNDLE_APK).version(40).number(Fixtures.UID + 1));
            bed.listing(1).session(Classification.SESSION_APPLIED, SHELL_REF);
            check(problems, bed.step().ticket.state == State.APPLIED_PROVISIONAL, "another UID applied");
        });
    }

    // Plan 0x101 with RESTORE_AUTOMATICALLY, whose approval lists a restoration plan.
    private static Plan listing(String restorationPlan) {
        return Fixtures.plan(1).healthResponse(HealthResponse.RESTORE_AUTOMATICALLY).restorationPlan(restorationPlan)
                .build();
    }

    // A plan that installs another plan's restoration bundle in its place, as its restoration does.
    private static Plan.Builder restorationOf(Plan original, long n) {
        return Fixtures.plan(n).repairs(original.planId).bundle(original.restorationInput, original.restorationVersion)
                .restoration(DeploymentRecords.NO_DIGEST, 0)
                .signing(0);
    }

    private static Bed readyAgain(Bed bed) {
        bed.at(State.READY_AGAIN, TO_REBOOT);
        bed.ticket = bed.ticket.toBuilder().boot(B2).bootCount(1).ledger(withoutReboot(bed.ticket)).build();
        bed.moveTo(B2, 1, 60_000).committed(FACTORY_APK).listing(1).session(Classification.SESSION_READY, SHELL_REF);
        return bed;
    }

    private static List<Entry> withoutReboot(Ticket t) {
        List<Entry> ledger = new ArrayList<>(t.ledger);
        ledger.removeIf(e -> e.crossing == Crossing.REBOOT);
        return ledger;
    }

    // A reboot requested under the ACTIVATE in B1, which took effect: the ticket is now in B2.
    private static List<Entry> withReboot(Ticket t) {
        return withRebootIn(t, B1);
    }

    private static List<Entry> withRebootIn(Ticket t, String boot) {
        List<Entry> ledger = withoutReboot(t);
        ledger.add(new Entry(Crossing.REBOOT, boot, 1, 2000, Bed.ACTIVATE, NO_ID, TIME));
        return ledger;
    }

    // ------------------------------------------------------------------ boots

    private static void bootCases() {
        cases.run("boot / a boot during COMMIT_INTENT is BOOT_OBSERVED", problems -> {
            for (boolean unresolved : new boolean[] {false, true}) {
                Bed bed = Bed.late().grants().at(State.COMMIT_INTENT, TO_COMMIT);
                if (unresolved) bed.ticket = bed.ticket.toBuilder().set(FLAG_UNRESOLVED).build();
                bed.moveTo(B2, 1, 2_000).committed(FACTORY_APK).listing(1)
                        .session(Classification.SESSION_READY, SHELL_REF);
                Step s = bed.step();
                check(problems, s.ticket.state == State.BOOT_OBSERVED && s.ticket.bootCount == 1
                        && s.ticket.boot.equals(B2) && !s.ticket.flag(FLAG_UNRESOLVED), "unresolved " + unresolved + " " + s);
            }
        });
        cases.run("boot / outcomes after the activation boot", problems -> {
            check(problems, observed(BUNDLE_APK, Classification.SESSION_APPLIED) == State.APPLIED_PROVISIONAL, "applied");
            check(problems, observed(FACTORY_APK, Classification.SESSION_FAILED) == State.FAILED_NATIVE, "failed");
            check(problems, observed(FACTORY_APK, Classification.SESSION_READY) == State.READY_AGAIN, "ready again");
            check(problems, observed(FACTORY_APK, Classification.VERIFYING) == State.BOOT_OBSERVED, "verification time");
            Bed slow = Bed.late().grants().at(State.BOOT_OBSERVED, TO_REBOOT).committed(FACTORY_APK).listing(1)
                    .session(Classification.VERIFYING, SHELL_REF);
            slow.elapsed = 10_000 + 300_000;
            check(problems, slow.step().ticket.state == State.ABANDON_INTENT, "still not ready after verification");
            check(problems, gone(BUNDLE_APK, false) == State.NATIVE_RECORD_LOST, "gone, bundle active");
            check(problems, gone(FACTORY_APK, false) == State.NATIVE_RECORD_LOST, "gone, prior active");
            check(problems, gone(FACTORY_APK, true) == State.ABANDONED, "gone after an abandon");
            check(problems, gone(Fixtures.digest(0xee), false) == State.DIVERGED, "gone, other bytes");
        });
        cases.run("record lost / the active bytes decide", problems -> {
            check(problems, lost(BUNDLE_APK, TO_COMMIT, Cause.NONE) == State.APPLIED_PROVISIONAL, "bundle");
            check(problems, lost(FACTORY_APK, TO_COMMIT, Cause.NONE) == State.CLOSED_FAILED, "prior, no cause");
            check(problems, lost(FACTORY_APK, TO_WRITE, Cause.CANCELLED) == State.CANCELLED, "prior, cancelled");
            check(problems, lost(Fixtures.digest(0xee), TO_WRITE, Cause.NONE) == State.VOID, "other, before commit");
            check(problems, lost(Fixtures.digest(0xee), TO_COMMIT, Cause.NONE) == State.DIVERGED, "other, after commit");
        });
        cases.run("record lost / before any commit the bundle's bytes are never applied", problems -> {
            Bed bed = Bed.late().grants().at(State.NATIVE_RECORD_LOST, TO_WRITE).committed(BUNDLE_APK);
            Step s = bed.step();
            check(problems, s.ticket.state == State.VOID && s.ticket.cause == Cause.OTHER_BYTES && s.selection == null,
                    "before commit " + s);
            check(problems, lost(BUNDLE_APK, TO_COMMIT, Cause.NONE) == State.APPLIED_PROVISIONAL, "after commit");
        });
        cases.run("boot / an applied session with other or prior bytes active is DIVERGED", problems -> {
            for (String active : List.of(FACTORY_APK, Fixtures.digest(0xee))) {
                Bed bed = Bed.late().grants().at(State.BOOT_OBSERVED, TO_REBOOT).committed(active).listing(1)
                        .session(Classification.SESSION_APPLIED, SHELL_REF);
                Step s = bed.step();
                check(problems, s.ticket.state == State.DIVERGED && s.ticket.cause == Cause.OTHER_BYTES
                        && s.selection == null, active + " " + s);
            }
        });
        cases.run("diverged / other bytes close a live session only after abandoning it", problems -> {
            Bed bed = Bed.late().grants().at(State.BOOT_OBSERVED, TO_REBOOT).committed(Fixtures.digest(0xee))
                    .listing(1).session(Classification.SESSION_READY, SHELL_REF);
            Step s = bed.step();
            check(problems, s.ticket.state == State.ABANDON_INTENT && s.ticket.cause == Cause.OTHER_BYTES,
                    "closed with a live session " + s);
            bed.moveTo(B1, 2, 50_000).committed(Fixtures.digest(0xee)).listing(0);
            check(problems, bed.step().ticket.state == State.ABANDONED, "abandoned");
            check(problems, bed.step().ticket.state == State.DIVERGED, "diverged");
            Bed before = Bed.late().grants().at(State.WRITTEN, TO_WRITE).committed(Fixtures.digest(0xee));
            Step w = before.step();
            check(problems, w.ticket.state == State.ABANDON_INTENT, "before commit " + w);
            before.moveTo(B1, 2, 50_000).committed(Fixtures.digest(0xee)).listing(0);
            before.step();
            check(problems, before.step().ticket.state == State.VOID, "before commit closes VOID");
        });
        cases.run("failed native / a changed fingerprint voids", problems -> {
            Bed same = Bed.late().grants().at(State.FAILED_NATIVE, TO_REBOOT).committed(FACTORY_APK);
            check(problems, same.step().ticket.state == State.CLOSED_FAILED, "same base");
            Bed changed = Bed.late().grants().at(State.FAILED_NATIVE, TO_REBOOT);
            changed.add(changed.f(Classification.BOOT_COMPLETED).text(Fixtures.NEW_FINGERPRINT));
            changed.add(changed.f(Classification.CHECKPOINT_COMMITTED));
            changed.add(changed.f(Classification.FACTORY_PRESENT).digest(Fixtures.digest(0xf1)).version(38));
            changed.add(changed.f(Classification.FACTORY_COPY).digest(Fixtures.digest(0xf1)).version(38));
            Step s = changed.step();
            check(problems, s.ticket.state == State.VOID && s.ticket.cause == Cause.VOID_BASE, "new base " + s);
        });
        cases.run("write / a lost or refused write reply abandons the session", problems -> {
            Bed lost = Bed.late().grants().at(State.SESSION_BOUND, TO_WRITE).committed(FACTORY_APK);
            check(problems, lost.step().ticket.state == State.ABANDON_INTENT, "lost");
            Bed refused = Bed.late().grants().at(State.SESSION_BOUND, TO_WRITE).committed(FACTORY_APK)
                    .reply(3, Crossing.WRITE, Classification.REPLY_REFUSED, Reference.NONE);
            check(problems, refused.step().ticket.state == State.ABANDON_INTENT, "refused");
            Bed ok = Bed.late().grants().at(State.SESSION_BOUND, TO_WRITE).committed(FACTORY_APK)
                    .reply(3, Crossing.WRITE, Classification.REPLY_SUCCESS, Reference.NONE);
            check(problems, ok.step().ticket.state == State.WRITTEN, "written");
        });
        cases.run("commit / a later framework instance with the session live but not ready abandons", problems -> {
            Bed bed = Bed.late().grants().at(State.COMMIT_INTENT, TO_COMMIT).moveTo(B1, 2, 30_000)
                    .committed(FACTORY_APK).listing(1)
                    .session(Classification.SEALED, new Reference(15, Bed.SESSION, Bed.CREATED, Bed.STAGE_DIR, 2000,
                            NO_ID));
            check(problems, bed.step().ticket.state == State.ABANDON_INTENT, "sealed in a later instance");
            Bed same = Bed.late().grants().at(State.COMMIT_INTENT, TO_COMMIT).committed(FACTORY_APK).listing(1)
                    .session(Classification.SEALED, new Reference(15, Bed.SESSION, Bed.CREATED, Bed.STAGE_DIR, 2000,
                            NO_ID));
            check(problems, same.step().ticket.state == State.COMMIT_INTENT, "the same instance waits");
            Bed refused = Bed.late().grants().at(State.COMMIT_INTENT, TO_COMMIT).committed(FACTORY_APK)
                    .session(Classification.SESSION_REFUSED, new Reference(15, Bed.SESSION, Bed.CREATED, Bed.STAGE_DIR,
                            2000, NO_ID));
            check(problems, refused.step().ticket.state == State.FAILED_NATIVE, "refused into history");
        });
    }

    private static State observed(String active, Classification session) {
        Bed bed = Bed.late().grants().at(State.BOOT_OBSERVED, TO_REBOOT).committed(active).listing(1)
                .session(session, SHELL_REF);
        return bed.step().ticket.state;
    }

    private static State gone(String active, boolean abandoned) {
        Bed bed = Bed.late().grants().at(State.BOOT_OBSERVED, abandoned
                ? new Crossing[] {Crossing.SIGN, Crossing.PUBLISH, Crossing.CREATE, Crossing.WRITE, Crossing.COMMIT,
                    Crossing.ABANDON} : TO_REBOOT).committed(active).listing(0);
        return bed.step().ticket.state;
    }

    private static State lost(String active, Crossing[] ledger, Cause cause) {
        Bed bed = Bed.late().grants().at(State.NATIVE_RECORD_LOST, ledger).committed(active);
        bed.ticket = bed.ticket.toBuilder().cause(cause).build();
        return bed.step().ticket.state;
    }

    // ------------------------------------------------------------------ loops

    private static void loopCases() {
        cases.run("loops / the reboot request loop abandons at the request limit", problems -> {
            Bed bed = Bed.late().grants().at(State.READY, TO_COMMIT).committed(FACTORY_APK);
            int requests = 0;
            for (int i = 0; i < 10 && bed.ticket.state != State.ABANDON_INTENT; i++) {
                Step s = bed.step();
                if (s.issue != null && s.issue.crossing == Crossing.REBOOT) ++requests;
                bed.elapsed += 120_000;
                bed.wall += 120_000;
                bed.committed(FACTORY_APK);
            }
            check(problems, requests == 3 && bed.ticket.state == State.ABANDON_INTENT,
                    requests + " requests, " + bed.ticket);
        });
        cases.run("loops / the health window ends UNHEALTHY at the boot limit", problems -> {
            Bed bed = Bed.late().grants().at(State.HEALTH_WINDOW, TO_REBOOT);
            bed.ticket = bed.ticket.toBuilder().window(B1, 1000).bootCount(1)
                    .health(List.of(new Health(0, 0, Outcome.OBSERVING), new Health(10, 12, Outcome.DEGRADED))).build();
            String[] boots = {B2, B3, id(0xb4)};
            for (String boot : boots) {
                bed.moveTo(boot, 1, 2_000).committed(BUNDLE_APK);
                bed.step();
            }
            Ticket t = bed.ticket;
            check(problems, t.state == State.CLOSED_APPLIED && t.flag(FLAG_BOOT_LIMIT) && t.bootCount == 4, "" + t);
            check(problems, t.health.equals(List.of(new Health(0, 0, Outcome.UNHEALTHY), new Health(10, 12,
                    Outcome.DEGRADED))), "outcomes " + t.health);
        });
        cases.run("restoration / at the boot limit the restoration listed in the approval takes over", problems -> {
            Bed bed = new Bed(listing(id(0x105))).grants().at(State.HEALTH_WINDOW, TO_REBOOT);
            bed.ticket = bed.ticket.toBuilder().window(B1, 1000).bootCount(1)
                    .health(List.of(new Health(0, 0, Outcome.OBSERVING), new Health(10, 12, Outcome.DEGRADED))).build();
            for (String boot : new String[] {B2, B3, id(0xb4)}) {
                bed.moveTo(boot, 1, 2_000).committed(BUNDLE_APK);
                bed.step();
            }
            Ticket t = bed.ticket;
            check(problems, t.state == State.SUPERSEDED && t.successor.equals(id(0x105)) && t.flag(FLAG_BOOT_LIMIT)
                    && t.bootCount == 4, "" + t);
            check(problems, t.health.equals(List.of(new Health(0, 0, Outcome.UNHEALTHY), new Health(10, 12,
                    Outcome.DEGRADED))), "outcomes " + t.health);
        });
        cases.run("loops / the provisional loop holds with the boot limit alert", problems -> {
            Bed bed = Bed.late().grants().at(State.APPLIED_PROVISIONAL, TO_REBOOT);
            bed.ticket = bed.ticket.toBuilder().bootCount(1).build();
            String[] boots = {B2, B3, id(0xb4), id(0xb5)};
            for (String boot : boots) {
                bed.moveTo(boot, 1, 2_000).facts(Classification.CHECKPOINT_PENDING, BUNDLE_APK).listing(1)
                        .session(Classification.SESSION_APPLIED, SHELL_REF);
                bed.step(); // BOOT_OBSERVED
                bed.step(); // APPLIED_PROVISIONAL again
            }
            Ticket t = bed.ticket;
            check(problems, t.state == State.APPLIED_PROVISIONAL && t.flag(FLAG_BOOT_LIMIT) && t.bootCount == 5,
                    "" + t);
            bed.elapsed += 1000;
            bed.add(bed.f(Classification.CHECKPOINT_COMMITTED));
            check(problems, bed.step().ticket.state == State.APPLIED, "Android ends the loop");
        });
        cases.run("loops / the abandon loop holds with the request limit alert", problems -> {
            Bed bed = Bed.late().grants().at(State.ABANDON_INTENT, Crossing.SIGN, Crossing.PUBLISH, Crossing.CREATE,
                    Crossing.ABANDON);
            int abandons = 1;
            for (int i = 2; i < 8; i++) {
                bed.moveTo(B1, i, 10_000L * i).committed(FACTORY_APK).listing(1)
                        .session(Classification.OPEN, SHELL_REF);
                Step s = bed.step();
                if (s.issue != null) ++abandons;
            }
            Ticket t = bed.ticket;
            check(problems, abandons == 3 && t.state == State.ABANDON_INTENT && t.flag(FLAG_REQUEST_LIMIT),
                    abandons + " abandons, " + t);
            bed.moveTo(B1, 9, 99_000).committed(FACTORY_APK).listing(0);
            check(problems, bed.step().ticket.state == State.ABANDONED, "Android ends the loop");
        });
        cases.run("loops / the boot limit alert on every path repeating across boots", problems -> {
            Bed early = Bed.early().grants().at(State.READY_AGAIN, TO_COMMIT);
            String[] boots = {B2, B3, id(0xb4), id(0xb5)};
            for (String boot : boots) {
                early.moveTo(boot, 1, 2_000).committed(FACTORY_APK).listing(1)
                        .session(Classification.SESSION_READY, SHELL_REF);
                early.step();
                early.step();
            }
            check(problems, early.ticket.state == State.READY_AGAIN && early.ticket.flag(FLAG_BOOT_LIMIT),
                    "early commit " + early.ticket);
            Bed abandon = Bed.late().grants().at(State.ABANDON_INTENT, Crossing.SIGN, Crossing.PUBLISH,
                    Crossing.CREATE, Crossing.ABANDON);
            for (String boot : boots) {
                abandon.moveTo(boot, 1, 2_000).committed(FACTORY_APK);
                abandon.step();
            }
            check(problems, abandon.ticket.flag(FLAG_BOOT_LIMIT) && abandon.ticket.state == State.ABANDON_INTENT,
                    "abandon across boots " + abandon.ticket);
            Bed pre = Bed.late().grants().at(State.PUBLISHED, TO_PUBLISHED);
            pre.auths.clear();
            for (String boot : boots) {
                pre.moveTo(boot, 1, 2_000).add(pre.f(Classification.BOOT_COMPLETED));
                pre.step();
            }
            check(problems, pre.ticket.bootCount == 0, "boots counted before SESSION_INTENT");
        });
    }

    // ------------------------------------------------------------------ health

    private static void healthCases() {
        cases.run("health / outcomes by serial, crashes, removals and new users", problems -> {
            Bed bed = Bed.late().grants().at(State.APPLIED, TO_REBOOT).committed(BUNDLE_APK);
            bed.user(0, 0, Classification.RUNNING_UNLOCKED).user(10, 12, Classification.RUNNING_UNLOCKED)
                    .user(11, 14, Classification.RUNNING_LOCKED);
            check(problems, bed.step().ticket.state == State.HEALTH_WINDOW, "window");
            bed.elapsed += 100_000;
            bed.committed(BUNDLE_APK);
            bed.health(0, 0, Classification.HEALTH_HELD, 0x7f).health(10, 12, Classification.HEALTH_CRASH, 0x7f)
                    .user(11, 14, Classification.USER_REMOVED).user(12, 16, Classification.RUNNING_UNLOCKED)
                    .health(12, 16, Classification.HEALTH_DEGRADED, 0x7f).user(11, 15, Classification.USER_REMOVED);
            Step mid = bed.step();
            check(problems, mid.ticket.health.equals(List.of(new Health(0, 0, Outcome.OBSERVING), new Health(10, 12,
                    Outcome.UNHEALTHY), new Health(11, 14, Outcome.REMOVED), new Health(12, 16, Outcome.OBSERVING))),
                    "mid window " + mid.ticket.health);
            for (int i = 0; i < 3; i++) {
                bed.elapsed += 140_000;
                bed.committed(BUNDLE_APK).health(0, 0, Classification.HEALTH_HELD, 0x7f);
                bed.step();
            }
            bed.elapsed += 80_000;
            bed.committed(BUNDLE_APK);
            bed.health(0, 0, Classification.HEALTH_HELD, 0x7f);
            Step end = bed.step();
            check(problems, end.ticket.state == State.CLOSED_APPLIED && end.ticket.health.equals(List.of(
                    new Health(0, 0, Outcome.HEALTHY), new Health(10, 12, Outcome.UNHEALTHY), new Health(11, 14,
                    Outcome.REMOVED), new Health(12, 16, Outcome.DEGRADED))), "end " + end.ticket.health);
        });
        cases.run("health / a stale base is never healthy", problems -> {
            Bed bed = Bed.late().grants().at(State.HEALTH_WINDOW, TO_REBOOT);
            bed.ticket = bed.ticket.toBuilder().window(B1, 1000).bootCount(1)
                    .health(List.of(new Health(0, 0, Outcome.OBSERVING))).build();
            bed.moveTo(B2, 1, 2_000);
            bed.add(bed.f(Classification.BOOT_COMPLETED).text(Fixtures.NEW_FINGERPRINT));
            bed.add(bed.f(Classification.CHECKPOINT_COMMITTED));
            bed.add(bed.f(Classification.FACTORY_PRESENT).digest(Fixtures.digest(0xf1)).version(38));
            bed.add(bed.f(Classification.DATA_COPY).digest(BUNDLE_APK).version(40));
            bed.health(0, 0, Classification.HEALTH_HELD, 0x7f);
            Step s = bed.step();
            check(problems, s.ticket.state == State.CLOSED_APPLIED, "the image change did not end the window " + s);
            for (Health h : s.ticket.health) check(problems, h.outcome != Outcome.HEALTHY, "healthy on a stale base");
            Plan plan = bed.plan;
            Selection chosen = new Selection(Fixtures.INSTALLATION, Fixtures.COMPONENT, 1, ChoiceKind.PLAN, plan.planId,
                    UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.CURRENT, B1, NO_ID, NO_ID, TIME);
            Selection realized = Reconciler.cohortCheck(chosen, plan, null, View.of(B2, plan.component, bed.obs), null, null);
            check(problems, realized.realization == Realization.STALE_BASE, "realization " + realized);
        });
        cases.run("health / an unavailable observation is inconclusive, never unhealthy", problems -> {
            Bed bed = Bed.late().grants().at(State.HEALTH_WINDOW, TO_REBOOT);
            bed.ticket = bed.ticket.toBuilder().health(List.of(new Health(0, 0, Outcome.OBSERVING),
                    new Health(10, 12, Outcome.OBSERVING))).build();
            bed.elapsed = 300_000;
            bed.committed(BUNDLE_APK).health(0, 0, Classification.HEALTH_INCONCLUSIVE, 0x7f);
            Step mid = bed.step();
            check(problems, mid.ticket.health.get(0).outcome == Outcome.OBSERVING, "counted " + mid.ticket.health);
            bed.elapsed = 700_000;
            bed.committed(BUNDLE_APK);
            Step end = bed.step();
            check(problems, end.ticket.state == State.CLOSED_APPLIED && end.ticket.health.equals(List.of(
                    new Health(0, 0, Outcome.INCONCLUSIVE), new Health(10, 12, Outcome.INCONCLUSIVE))),
                    "end " + end.ticket.health);
        });
        cases.run("restoration / automatic restoration runs only when the approval listed it", problems -> {
            Plan listed = Fixtures.plan(1).healthResponse(HealthResponse.RESTORE_AUTOMATICALLY)
                    .restorationPlan(id(0x105)).build();
            Plan restoration = Fixtures.plan(5).repairs(listed.planId).bundle(Fixtures.RESTORATION_INPUT, 41)
                    .restoration(DeploymentRecords.NO_DIGEST, 0)
                    .signing(0).base(BUNDLE_APK, 40, Fixtures.UID, Fixtures.CONTEXT).selectionRevision(1).build();
            Classification[] probes = {Classification.HEALTH_HELD, Classification.HEALTH_CRASH,
                Classification.HEALTH_INCONCLUSIVE};
            State[] ends = new State[3];
            for (int i = 0; i < 3; i++) {
                Bed bed = new Bed(listed).grants().at(State.HEALTH_WINDOW, TO_REBOOT);
                bed.repairs.add(restoration);
                bed.committed(BUNDLE_APK).health(0, 0, probes[i], 0x7f);
                Step s = bed.step();
                ends[i] = s.ticket.state;
                if (i == 1) check(problems, s.ticket.successor.equals(restoration.planId), "successor " + s);
            }
            check(problems, ends[0] == State.HEALTH_WINDOW, "restored while healthy");
            check(problems, ends[1] == State.SUPERSEDED, "not restored on a crash " + ends[1]);
            check(problems, ends[2] == State.HEALTH_WINDOW, "restored on an unavailable observation");
            Bed unlisted = Bed.late().grants().at(State.HEALTH_WINDOW, TO_REBOOT);
            unlisted.committed(BUNDLE_APK).health(0, 0, Classification.HEALTH_CRASH, 0x7f);
            Step u = unlisted.step();
            check(problems, u.ticket.state == State.HEALTH_WINDOW && u.ticket.health.get(0).outcome == Outcome.UNHEALTHY,
                    "unlisted " + u);
        });
        cases.run("health / probes that miss a declared criterion are inconclusive", problems -> {
            Bed bed = Bed.late().grants().at(State.HEALTH_WINDOW, TO_REBOOT);
            bed.ticket = bed.ticket.toBuilder().window(B1, 1000)
                    .health(List.of(new Health(0, 0, Outcome.OBSERVING))).build();
            bed.elapsed = 700_000;
            bed.committed(BUNDLE_APK).health(0, 0, Classification.HEALTH_HELD, 0x3f);
            Step s = bed.step();
            check(problems, s.ticket.health.equals(List.of(new Health(0, 0, Outcome.INCONCLUSIVE))), "" + s.ticket.health);
        });
        cases.run("health / the criteria must hold across the whole window", problems -> {
            // The window runs from 1000 to 601_000, so no gap may exceed 150_000.
            check(problems, covered(100_000, 250_000, 400_000, 550_000, 601_000) == Outcome.HEALTHY, "covered");
            check(problems, covered(601_000) == Outcome.INCONCLUSIVE, "one probe at the end");
            check(problems, covered(100_000, 250_000, 550_000, 601_000) == Outcome.INCONCLUSIVE, "a gap inside");
            check(problems, covered(200_000, 340_000, 480_000, 601_000) == Outcome.INCONCLUSIVE, "the start uncovered");
            check(problems, covered(100_000, 240_000, 380_000) == Outcome.INCONCLUSIVE, "the end uncovered");
            // A user first unlocked during the window, absent from a listing after the window began,
            // is judged from that listing.
            Bed late = Bed.late().grants().at(State.HEALTH_WINDOW, TO_REBOOT);
            late.ticket = late.ticket.toBuilder().health(List.of(new Health(0, 0, Outcome.OBSERVING))).build();
            late.elapsed = 200_000;
            late.committed(BUNDLE_APK);
            late.step();
            for (long t : new long[] {300_000, 440_000, 580_000, 601_000}) {
                late.elapsed = t;
                late.committed(BUNDLE_APK).user(10, 12, Classification.RUNNING_UNLOCKED)
                        .health(10, 12, Classification.HEALTH_HELD, 0x7f);
                late.step();
            }
            Health ten = null;
            for (Health h : late.ticket.health) if (h.user == 10) ten = h;
            check(problems, late.ticket.state == State.CLOSED_APPLIED && ten != null && ten.outcome == Outcome.HEALTHY,
                    "a user unlocked during the window " + late.ticket.health);
        });
        cases.run("health / time before a late first unlock counts only after a listing showed the user not unlocked",
                problems -> {
            // User 0 runs from the window's start, but its reads are unavailable until 300_000.
            check(problems, lateReads(-1, null) == Outcome.INCONCLUSIVE, "unobserved time judged healthy");
            check(problems, lateReads(1_000, Classification.RUNNING_UNLOCKED) == Outcome.INCONCLUSIVE,
                    "an unlock at the start, then nothing until 300_000");
            check(problems, lateReads(500, Classification.RUNNING_LOCKED) == Outcome.INCONCLUSIVE,
                    "a listing before the window began counted");
            check(problems, lateReads(200_000, Classification.RUNNING_LOCKED) == Outcome.HEALTHY,
                    "a locked listing after the window began, then a covered span");
            check(problems, lateReads(200_000, Classification.NOT_RUNNING) == Outcome.HEALTHY,
                    "a stopped listing after the window began, then a covered span");
        });
    }

    // A window from 1000 to 601_000 for user 0, read only from 300_000 on with full HELD probes, and
    // one listing of user 0 earlier when `at` is not negative. Returns user 0's outcome at the close.
    private static Outcome lateReads(long at, Classification listed) {
        Bed bed = Bed.late().grants().at(State.HEALTH_WINDOW, TO_REBOOT);
        bed.ticket = bed.ticket.toBuilder().health(List.of(new Health(0, 0, Outcome.OBSERVING))).build();
        if (at >= 0) {
            bed.elapsed = at;
            bed.user(0, 0, listed);
        }
        for (long t : new long[] {300_000, 440_000, 580_000, 601_000}) {
            bed.elapsed = t;
            bed.committed(BUNDLE_APK).health(0, 0, Classification.HEALTH_HELD, 0x7f);
            Step s = bed.step();
            if (t == 601_000) return s.ticket.state == State.CLOSED_APPLIED ? s.ticket.health.get(0).outcome : null;
        }
        return null;
    }

    // A window from 1000 to 601_000 for user 0, unlocked at its start, with a full HELD probe at each
    // time. Returns user 0's outcome once the window closes, or null when it did not close.
    private static Outcome covered(long... probes) {
        Bed bed = Bed.late().grants().at(State.HEALTH_WINDOW, TO_REBOOT);
        bed.ticket = bed.ticket.toBuilder().health(List.of(new Health(0, 0, Outcome.OBSERVING))).build();
        bed.elapsed = 1000;
        bed.user(0, 0, Classification.RUNNING_UNLOCKED);
        boolean closing = false;
        for (long t : probes) {
            bed.elapsed = t;
            bed.committed(BUNDLE_APK).health(0, 0, Classification.HEALTH_HELD, 0x7f);
            closing = t >= 601_000;
            if (!closing) bed.step();
        }
        if (!closing) {
            bed.elapsed = 601_000;
            bed.committed(BUNDLE_APK);
        }
        Step end = bed.step();
        return end.ticket.state == State.CLOSED_APPLIED ? end.ticket.health.get(0).outcome : null;
    }

    // ------------------------------------------------------------------ selection

    private static void selectionCases() {
        cases.run("selection / the choice moves at APPLIED and only then", problems -> {
            Bed bed = Bed.late().grants().at(State.APPLIED_PROVISIONAL, TO_REBOOT).committed(BUNDLE_APK).listing(1)
                    .session(Classification.SESSION_APPLIED, SHELL_REF);
            Step s = bed.step();
            check(problems, s.ticket.state == State.APPLIED && s.selection != null
                    && s.selection.choice == ChoiceKind.PLAN && s.selection.planId.equals(bed.plan.planId)
                    && s.selection.revision == 1 && s.selection.realization == Realization.CURRENT, "applied " + s);
            for (State state : List.of(State.BOOT_OBSERVED, State.READY, State.HEALTH_WINDOW)) {
                Bed other = Bed.late().grants().at(state, TO_REBOOT).committed(BUNDLE_APK).listing(1)
                        .session(Classification.SESSION_APPLIED, SHELL_REF);
                if (state == State.HEALTH_WINDOW) {
                    other.ticket = other.ticket.toBuilder().window(B1, 1).build();
                    other.selection = other.selection.chosen(ChoiceKind.PLAN, other.plan.planId, Realization.CURRENT,
                            B1, TIME);
                }
                check(problems, other.step().selection == null, "moved in " + state);
            }
        });
        cases.run("selection / a move lost between two writes is made at APPLIED or in the health window",
                problems -> {
            Bed applied = Bed.late().grants().at(State.APPLIED, TO_REBOOT).committed(BUNDLE_APK);
            Step a = applied.step();
            check(problems, a.ticket.state == State.HEALTH_WINDOW && a.selection != null
                    && a.selection.planId.equals(applied.plan.planId) && a.selection.revision == 1
                    && a.selection.realization == Realization.CURRENT, "at APPLIED " + a);
            Bed window = Bed.late().grants().at(State.HEALTH_WINDOW, TO_REBOOT).committed(BUNDLE_APK);
            Step w = window.step();
            check(problems, w.ticket.state == State.HEALTH_WINDOW && w.selection != null
                    && w.selection.planId.equals(window.plan.planId) && w.selection.revision == 1, "in the window " + w);
            Bed cancelled = Bed.late().grants().at(State.HEALTH_WINDOW, TO_REBOOT).committed(BUNDLE_APK);
            cancelled.ticket = cancelled.ticket.toBuilder().cause(Cause.CANCELLED).build();
            check(problems, cancelled.step().selection == null, "a cancelled ticket moved the choice");
            Bed revision = Bed.late().grants().at(State.HEALTH_WINDOW, TO_REBOOT).committed(BUNDLE_APK);
            revision.selection = revision.selection.chosen(ChoiceKind.FACTORY, NO_ID, Realization.CURRENT, B1, TIME);
            check(problems, revision.step().selection == null, "another revision moved the choice");
            // Written before the ticket: the plan's own move is no change of revision.
            Bed provisional = Bed.late().grants().at(State.APPLIED_PROVISIONAL, TO_REBOOT).committed(BUNDLE_APK)
                    .listing(1).session(Classification.SESSION_APPLIED, SHELL_REF);
            provisional.selection = provisional.selection.chosen(ChoiceKind.PLAN, provisional.plan.planId,
                    Realization.CURRENT, B1, TIME);
            Step p = provisional.step();
            check(problems, p.ticket.state == State.APPLIED && p.ticket.cause == Cause.NONE && p.selection == null,
                    "provisional after the move " + p);
            Bed rebooted = Bed.late().grants().at(State.BOOT_OBSERVED, TO_REBOOT).committed(BUNDLE_APK).listing(1)
                    .session(Classification.SESSION_APPLIED, SHELL_REF);
            rebooted.selection = provisional.selection;
            Step r = rebooted.step();
            check(problems, r.ticket.state == State.APPLIED_PROVISIONAL && r.ticket.cause == Cause.NONE,
                    "a boot after the move " + r);
            // Decision 6: a lost temporary factory realization is set again.
            Plan temporary = DeploymentRecordsTest.planTemporary();
            Bed stand = new Bed(temporary).grants().at(State.HEALTH_WINDOW, TO_REBOOT);
            stand.selection = new Selection(Fixtures.INSTALLATION, Fixtures.COMPONENT, 1, ChoiceKind.PLAN, id(0x101),
                    UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.DIVERGED, B1, NO_ID, NO_ID, TIME);
            stand.add(stand.f(Classification.BOOT_COMPLETED).text(Fixtures.NEW_FINGERPRINT));
            stand.add(stand.f(Classification.CHECKPOINT_COMMITTED));
            stand.add(stand.f(Classification.FACTORY_PRESENT).digest(Fixtures.digest(0xf1)).version(38));
            stand.add(stand.f(Classification.DATA_COPY).digest(Fixtures.signed(temporary.bundleInput)).version(42));
            Step t = stand.step();
            check(problems, t.selection != null && t.selection.revision == 1 && t.selection.planId.equals(id(0x101))
                    && t.selection.realization == Realization.TEMPORARY_FACTORY
                    && t.selection.temporary.equals(temporary.planId), "temporary " + t + " " + t.selection);
            stand.selection = t.selection;
            check(problems, stand.step().selection == null, "the temporary factory state set twice");
        });
        cases.run("selection / an owed move in a step that closes DIVERGED takes the realization from its facts",
                problems -> {
            Bed other = Bed.late().grants().at(State.HEALTH_WINDOW, TO_REBOOT).committed(Fixtures.digest(0xee));
            Step o = other.step();
            check(problems, o.ticket.state == State.DIVERGED && o.selection != null
                    && o.selection.planId.equals(other.plan.planId) && o.selection.revision == 1
                    && o.selection.realization == Realization.DIVERGED, "other bytes " + o + " " + o.selection);
            Bed same = Bed.late().grants().at(State.HEALTH_WINDOW, TO_REBOOT).committed(BUNDLE_APK);
            Step c = same.step();
            check(problems, c.selection != null && c.selection.realization == Realization.CURRENT,
                    "the bundle's bytes " + c.selection);
            // Decision 6: the temporary factory state is owed only while the stand in's bytes are active.
            Plan temporary = DeploymentRecordsTest.planTemporary();
            Bed stand = new Bed(temporary).grants().at(State.HEALTH_WINDOW, TO_REBOOT);
            stand.selection = new Selection(Fixtures.INSTALLATION, Fixtures.COMPONENT, 1, ChoiceKind.PLAN, id(0x101),
                    UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.DIVERGED, B1, NO_ID, NO_ID, TIME);
            stand.add(stand.f(Classification.BOOT_COMPLETED).text(Fixtures.NEW_FINGERPRINT));
            stand.add(stand.f(Classification.CHECKPOINT_COMMITTED));
            stand.add(stand.f(Classification.FACTORY_PRESENT).digest(Fixtures.digest(0xf1)).version(38));
            stand.add(stand.f(Classification.DATA_COPY).digest(Fixtures.digest(0xee)).version(45));
            Step t = stand.step();
            check(problems, t.ticket.state == State.DIVERGED && (t.selection == null
                    || t.selection.realization != Realization.TEMPORARY_FACTORY), "temporary " + t + " " + t.selection);
        });
        cases.run("selection / a void or cancelled plan never moves the choice", problems -> {
            for (Cause cause : List.of(Cause.CANCELLED, Cause.VOID_TRUST)) {
                Bed bed = Bed.late().grants().at(State.APPLIED_PROVISIONAL, TO_REBOOT).committed(BUNDLE_APK)
                        .listing(1).session(Classification.SESSION_APPLIED, SHELL_REF);
                bed.ticket = bed.ticket.toBuilder().cause(cause).build();
                Step s = bed.step();
                check(problems, s.ticket.state == State.APPLIED && s.selection == null, cause + " " + s);
            }
            Bed stale = Bed.late().grants().at(State.APPLIED_PROVISIONAL, TO_REBOOT).committed(BUNDLE_APK).listing(1)
                    .session(Classification.SESSION_APPLIED, SHELL_REF);
            stale.selection = stale.selection.chosen(ChoiceKind.FACTORY, NO_ID, Realization.CURRENT, B1, TIME);
            check(problems, stale.step().selection == null, "a stale revision moved the choice");
        });
        cases.run("cohort / CURRENT, STALE_BASE, DISPLACED and DIVERGED", problems -> {
            Plan plan = Fixtures.plan(1).build();
            Selection chosen = new Selection(Fixtures.INSTALLATION, Fixtures.COMPONENT, 1, ChoiceKind.PLAN, plan.planId,
                    UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.UNCHECKED, NO_ID, NO_ID, NO_ID, TIME);
            check(problems, realize(chosen, plan, BUNDLE_APK, false) == Realization.CURRENT, "current");
            check(problems, realize(chosen, plan, BUNDLE_APK, true) == Realization.STALE_BASE, "stale");
            check(problems, realize(chosen, plan, FACTORY_APK, false) == Realization.DISPLACED, "displaced");
            check(problems, realize(chosen, plan, Fixtures.digest(0xee), false) == Realization.DIVERGED, "diverged");
            Selection factory = new Selection(Fixtures.INSTALLATION, Fixtures.COMPONENT, 0, ChoiceKind.FACTORY, NO_ID,
                    UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.UNCHECKED, NO_ID, NO_ID, NO_ID, TIME);
            check(problems, realize(factory, null, FACTORY_APK, false) == Realization.CURRENT, "factory current");
            check(problems, realize(factory, null, Fixtures.digest(0xee), false) == Realization.DIVERGED,
                    "factory diverged");
        });
        cases.run("cohort / an Android deletion keeps the choice", problems -> {
            Plan plan = Fixtures.plan(1).build();
            Selection chosen = new Selection(Fixtures.INSTALLATION, Fixtures.COMPONENT, 4, ChoiceKind.PLAN, plan.planId,
                    UpdateResponsibility.KEEP_STALE, 0, Realization.CURRENT, B1, NO_ID, NO_ID, TIME);
            Bed bed = new Bed(plan).moveTo(B2, 1, 1000).committed(FACTORY_APK);
            Selection after = Reconciler.cohortCheck(chosen, plan, null, View.of(B2, plan.component, bed.obs), null, null);
            check(problems, after.realization == Realization.DISPLACED && after.choice == ChoiceKind.PLAN
                    && after.planId.equals(plan.planId) && after.revision == 4
                    && after.responsibility == UpdateResponsibility.KEEP_STALE, "" + after);
        });
        cases.run("cohort / an open repair plan is linked and the link outlives a status change", problems -> {
            Plan plan = Fixtures.plan(1).build();
            Plan rebuild = Fixtures.plan(6).repairs(plan.planId).bundle(Fixtures.digest(0xb4), 43)
                    .restoration(DeploymentRecords.NO_DIGEST, 0)
                    .cohort(Fixtures.NEW_FINGERPRINT, Fixtures.digest(0xf1), 38)
                    .base(BUNDLE_APK, Fixtures.BUNDLE_VERSION, Fixtures.UID, Fixtures.CONTEXT).selectionRevision(1).build();
            Selection chosen = new Selection(Fixtures.INSTALLATION, Fixtures.COMPONENT, 1, ChoiceKind.PLAN, plan.planId,
                    UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.CURRENT, B1, NO_ID, NO_ID, TIME);
            Bed stale = new Bed(plan).moveTo(B2, 1, 1000);
            stale.add(stale.f(Classification.BOOT_COMPLETED).text(Fixtures.NEW_FINGERPRINT));
            stale.add(stale.f(Classification.FACTORY_PRESENT).digest(Fixtures.digest(0xf1)).version(38));
            stale.add(stale.f(Classification.DATA_COPY).digest(BUNDLE_APK).version(Fixtures.BUNDLE_VERSION));
            View staleView = View.of(B2, Fixtures.COMPONENT, stale.obs);
            Selection linked = Reconciler.cohortCheck(chosen, plan, null, staleView,
                    Fixtures.ticket(6, rebuild).build(), rebuild);
            check(problems, linked.realization == Realization.STALE_BASE && linked.repair.equals(rebuild.planId),
                    "the open rebuild not linked " + linked);
            Bed deleted = new Bed(plan).moveTo(B3, 1, 1000);
            deleted.add(deleted.f(Classification.BOOT_COMPLETED).text(Fixtures.NEW_FINGERPRINT));
            deleted.add(deleted.f(Classification.FACTORY_PRESENT).digest(Fixtures.digest(0xf1)).version(38));
            deleted.add(deleted.f(Classification.FACTORY_COPY).digest(Fixtures.digest(0xf1)).version(38));
            Selection kept = Reconciler.cohortCheck(linked, plan, null, View.of(B3, Fixtures.COMPONENT, deleted.obs),
                    null, null);
            check(problems, kept.realization == Realization.DISPLACED && kept.repair.equals(rebuild.planId),
                    "the link lost at a status change " + kept);
            Bed back = new Bed(plan).moveTo(id(0xb4), 1, 1000).committed(BUNDLE_APK);
            Selection cleared = Reconciler.cohortCheck(kept, plan, null, View.of(id(0xb4), Fixtures.COMPONENT,
                    back.obs), null, null);
            check(problems, cleared.realization == Realization.CURRENT && cleared.repair.equals(NO_ID),
                    "CURRENT kept a link " + cleared);
            Plan temporary = DeploymentRecordsTest.planTemporary();
            Selection standIn = Reconciler.cohortCheck(chosen, plan, null, staleView,
                    Fixtures.ticket(4, temporary).build(), temporary);
            check(problems, standIn.realization == Realization.STALE_BASE && standIn.repair.equals(NO_ID),
                    "a temporary factory plan linked as the repair " + standIn);
        });
        cases.run("cohort / an activation in flight keeps the previous status", problems -> {
            Plan plan = Fixtures.plan(1).build();
            Selection factory = new Selection(Fixtures.INSTALLATION, Fixtures.COMPONENT, 0, ChoiceKind.FACTORY, NO_ID,
                    UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.CURRENT, B1, NO_ID, NO_ID, TIME);
            Bed bed = Bed.late().grants().at(State.BOOT_OBSERVED, TO_REBOOT).moveTo(B2, 1, 1000).committed(BUNDLE_APK);
            View view = View.of(B2, plan.component, bed.obs);
            check(problems, Reconciler.cohortCheck(factory, null, null, view, bed.ticket, plan) == factory, "in flight");
            Ticket closed = bed.ticket.toBuilder().state(State.VOID).cause(Cause.OTHER_BYTES).build();
            check(problems, Reconciler.cohortCheck(factory, null, null, view, closed, plan).realization
                    == Realization.DIVERGED, "after the ticket closed");
        });
        cases.run("cohort / an owner approved temporary factory state keeps the choice", problems -> {
            Plan chosen = Fixtures.plan(1).build();
            Plan temporary = DeploymentRecordsTest.planTemporary();
            Selection standing = new Selection(Fixtures.INSTALLATION, Fixtures.COMPONENT, 1, ChoiceKind.PLAN,
                    chosen.planId, UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.TEMPORARY_FACTORY,
                    B1, NO_ID, temporary.planId, TIME);
            Bed bed = new Bed(temporary).published(chosen).moveTo(B2, 1, 1000);
            bed.add(bed.f(Classification.BOOT_COMPLETED).text(Fixtures.NEW_FINGERPRINT));
            bed.add(bed.f(Classification.FACTORY_PRESENT).digest(Fixtures.digest(0xf1)).version(38));
            bed.add(bed.f(Classification.DATA_COPY).digest(Fixtures.signed(temporary.bundleInput)).version(42));
            Selection after = Reconciler.cohortCheck(standing, chosen, temporary, View.of(B2, Fixtures.COMPONENT,
                    bed.obs), null, null);
            check(problems, after.realization == Realization.TEMPORARY_FACTORY && after.choice == ChoiceKind.PLAN
                    && after.planId.equals(chosen.planId) && after.revision == 1
                    && after.temporary.equals(temporary.planId), "temporary " + after);
            Bed back = new Bed(chosen).published(temporary).moveTo(B3, 1, 1000).committed(BUNDLE_APK);
            Selection current = Reconciler.cohortCheck(standing, chosen, temporary, View.of(B3, Fixtures.COMPONENT,
                    back.obs), null, null);
            check(problems, current.realization == Realization.CURRENT && current.temporary.equals(NO_ID),
                    "current " + current);
            Bed removed = new Bed(chosen).published(temporary).moveTo(B3, 1, 1000).committed(FACTORY_APK);
            check(problems, Reconciler.cohortCheck(standing, chosen, temporary, View.of(B3, Fixtures.COMPONENT,
                    removed.obs), null, null).realization == Realization.DISPLACED, "Android's removal");
        });
        cases.run("selection / a temporary factory plan never moves the choice", problems -> {
            Plan temporary = DeploymentRecordsTest.planTemporary();
            Bed bed = new Bed(temporary).grants().at(State.APPLIED_PROVISIONAL, TO_REBOOT);
            bed.selection = new Selection(Fixtures.INSTALLATION, Fixtures.COMPONENT, 1, ChoiceKind.PLAN, id(0x101),
                    UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.STALE_BASE, B1, NO_ID, NO_ID, TIME);
            bed.add(bed.f(Classification.BOOT_COMPLETED).text(Fixtures.NEW_FINGERPRINT));
            bed.add(bed.f(Classification.CHECKPOINT_COMMITTED));
            bed.add(bed.f(Classification.FACTORY_PRESENT).digest(Fixtures.digest(0xf1)).version(38));
            bed.add(bed.f(Classification.DATA_COPY).digest(Fixtures.signed(temporary.bundleInput)).version(42));
            bed.listing(1).session(Classification.SESSION_APPLIED, SHELL_REF);
            Step s = bed.step();
            Selection next = s.selection;
            check(problems, s.ticket.state == State.APPLIED && next != null && next.choice == ChoiceKind.PLAN
                    && next.planId.equals(id(0x101)) && next.revision == 1
                    && next.realization == Realization.TEMPORARY_FACTORY && next.temporary.equals(temporary.planId),
                    "applied " + s + " " + next);
        });
        cases.run("factory / a factory plan changes the choice by authorization alone", problems -> {
            String none = DeploymentRecords.NO_DIGEST;
            Plan plan = Fixtures.plan(3).target(Target.FACTORY).bundle(none, 0).signer(none)
                    .restoration(none, 0).signing(0).build();
            Selection factory = new Selection(Fixtures.INSTALLATION, Fixtures.COMPONENT, 0, ChoiceKind.FACTORY, NO_ID,
                    UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.CURRENT, B1, NO_ID, NO_ID, TIME);
            Bed bed = new Bed(plan).committed(FACTORY_APK);
            View view = View.of(B1, plan.component, bed.obs);
            check(problems, Reconciler.selectFactory(factory, plan, List.of(), view, TIME) == null, "without SELECT");
            Authorization select = Fixtures.lab(9, plan, Effect.SELECT, 0, TIME);
            Selection next = Reconciler.selectFactory(factory, plan, List.of(select), view, TIME);
            check(problems, next != null && next.revision == 1 && next.choice == ChoiceKind.FACTORY, "select " + next);
            Bed variant = new Bed(plan).committed(BUNDLE_APK);
            check(problems, Reconciler.selectFactory(factory, plan, List.of(select), View.of(B1, plan.component,
                    variant.obs), TIME) == null, "a crossing needed while a variant is active");
        });
    }

    private static Realization realize(Selection s, Plan plan, String active, boolean newBase) {
        Bed bed = new Bed(Fixtures.plan(1).build());
        if (newBase) {
            bed.add(bed.f(Classification.BOOT_COMPLETED).text(Fixtures.NEW_FINGERPRINT));
            bed.add(bed.f(Classification.FACTORY_PRESENT).digest(Fixtures.digest(0xf1)).version(38));
        } else {
            bed.add(bed.f(Classification.BOOT_COMPLETED));
            bed.add(bed.f(Classification.FACTORY_PRESENT));
        }
        bed.add(bed.f(active.equals(FACTORY_APK) ? Classification.FACTORY_COPY : Classification.DATA_COPY)
                .digest(active).version(40));
        return Reconciler.cohortCheck(s, plan, null, View.of(B1, Fixtures.COMPONENT, bed.obs), null, null).realization;
    }

    // ------------------------------------------------------------------ signing, publication, handover

    private static void signingCases() {
        cases.run("signing / one transaction by default and the two that the records still allow", problems -> {
            Bed one = Bed.late().grants().at(State.AUTHORIZED);
            Step s = one.step();
            check(problems, s.ticket.state == State.SIGNING && s.issue.crossing == Crossing.SIGN
                    && s.issue.grant.equals(Bed.SIGN), "one " + s);
            one.host(Classification.SIGN_COMPLETED, s.issue.reference);
            check(problems, one.step().ticket.state == State.SIGNED, "one completed");
            Plan twoPlan = Fixtures.plan(1).signing(2).build();
            Bed two = new Bed(twoPlan).grant(Effect.STAGE, Bed.STAGE, TIME);
            two.auths.add(new Authorization(Fixtures.INSTALLATION, Bed.SIGN, twoPlan.component, twoPlan.planId,
                    Effect.SIGN, DeploymentRecords.INPUT_VARIANT, DeploymentRecords.ActorClass.LAB_OPERATOR,
                    DeploymentRecords.NO_USER, -1, NO_ID, GrantScope.NONE, id(0x3a1), TIME));
            check(problems, two.at(State.PLANNED).step().ticket.state == State.PLANNED, "authorized without the second");
            two.auths.add(new Authorization(Fixtures.INSTALLATION, Bed.SIGN_RESTORATION, twoPlan.component,
                    twoPlan.planId, Effect.SIGN, DeploymentRecords.INPUT_RESTORATION,
                    DeploymentRecords.ActorClass.LAB_OPERATOR, DeploymentRecords.NO_USER, -1, NO_ID, GrantScope.NONE,
                    id(0x3a2), TIME));
            check(problems, two.step().ticket.state == State.AUTHORIZED, "authorized");
            Step first = two.step();
            Step wait = two.step();
            check(problems, wait.issue == null && wait.ticket.flag(FLAG_UNRESOLVED), "second before the first " + wait);
            two.host(Classification.SIGN_COMPLETED, first.issue.reference);
            Step second = two.step();
            check(problems, second.issue != null && second.issue.grant.equals(Bed.SIGN_RESTORATION)
                    && !second.issue.reference.equals(first.issue.reference), "second " + second);
            two.host(Classification.SIGN_COMPLETED, second.issue.reference);
            check(problems, two.step().ticket.state == State.SIGNED, "both");
            Bed refused = Bed.late().grants().at(State.SIGNING, Crossing.SIGN)
                    .host(Classification.SIGN_REFUSED, id(0x7e57));
            check(problems, refused.step().ticket.state == State.SIGN_FAILED, "refused");
        });
        cases.run("signing / a later attempt skips signing only when the bundles read back published", problems -> {
            // An earlier attempt published the bundles and was cancelled before any session.
            Bed later = Bed.late().grants().at(State.AUTHORIZED);
            Ticket.Builder earlier = Fixtures.ticket(2, later.plan).state(State.CANCELLED).cause(Cause.CANCELLED);
            for (Crossing c : TO_PUBLISHED) earlier.append(Bed.entry(c, B1, 1, 1100));
            later.others.add(earlier.build());
            Bed unread = Bed.late().grants().at(State.AUTHORIZED);
            unread.others.add(earlier.build());
            Step u = unread.step();
            check(problems, u.ticket.state == State.AUTHORIZED && u.issue == null,
                    "an unread publication skipped signing " + u);
            later.host(Classification.BUNDLE_PUBLISHED, Fixtures.PUBLISH_ATTEMPT);
            Step p = later.step();
            check(problems, p.ticket.state == State.SIGNING && p.issue == null, "published bundles signed again " + p);
            Bed other = Bed.late().grants().at(State.AUTHORIZED).host(Classification.BUNDLE_PUBLISHED, id(0x9b99));
            Step o = other.step();
            check(problems, o.issue != null && o.issue.crossing == Crossing.SIGN,
                    "another plan's publication skipped signing " + o);
            Bed fresh = Bed.late().grants().at(State.AUTHORIZED);
            Step f = fresh.step();
            check(problems, f.ticket.state == State.SIGNING && f.issue != null && f.issue.crossing == Crossing.SIGN,
                    "unpublished bundles not signed " + f);
        });
        cases.run("publish / a lost acknowledgement is resolved by reading, never by publishing again", problems -> {
            Bed bed = Bed.late().grants().at(State.SIGNED, Crossing.SIGN);
            Step s = bed.step();
            check(problems, s.issue != null && s.issue.crossing == Crossing.PUBLISH
                    && !s.issue.reference.equals(NO_ID), "publish with an attempt ID " + s);
            for (int i = 0; i < 3; i++) {
                Step again = bed.step();
                check(problems, again.issue == null && again.ticket.state == State.SIGNED, "published again " + again);
            }
            // A read that names no attempt of this ticket, or a mismatch, proves nothing.
            bed.host(Classification.BUNDLE_ABSENT, id(0x9b99)).host(Classification.BUNDLE_PUBLISHED, id(0x9b98));
            check(problems, bed.step().issue == null && bed.ticket.state == State.SIGNED, "another attempt's read");
            bed.host(Classification.BUNDLE_PUBLISHED, s.issue.reference);
            check(problems, bed.step().ticket.state == State.PUBLISHED, "read back");
            Bed mismatch = Bed.late().grants().at(State.SIGNED, Crossing.SIGN, Crossing.PUBLISH)
                    .host(Classification.BUNDLE_PUBLISHED, Fixtures.PUBLISH_ATTEMPT)
                    .host(Classification.BUNDLE_MISMATCH, Fixtures.PUBLISH_ATTEMPT);
            Step m = mismatch.step();
            check(problems, m.issue == null && m.ticket.state == State.SIGNED, "a mismatch read as published " + m);
        });
        cases.run("publish / a second publication follows only a read of absence naming the attempt", problems -> {
            Bed bed = Bed.late().grants().at(State.SIGNED, Crossing.SIGN, Crossing.PUBLISH);
            bed.host(Classification.BUNDLE_ABSENT, id(0x9b99));
            check(problems, bed.step().issue == null, "another attempt's absence");
            bed.host(Classification.BUNDLE_ABSENT, Fixtures.PUBLISH_ATTEMPT);
            Step second = bed.step();
            check(problems, second.issue != null && second.issue.crossing == Crossing.PUBLISH
                    && !second.issue.reference.equals(Fixtures.PUBLISH_ATTEMPT)
                    && second.ticket.state == State.SIGNED && second.ticket.count(Crossing.PUBLISH) == 2,
                    "second publication " + second);
            Step wait = bed.step();
            check(problems, wait.issue == null && !wait.ticket.flag(DeploymentRecords.FLAG_REQUEST_LIMIT),
                    "the first attempt's absence used again " + wait);
            bed.host(Classification.BUNDLE_ABSENT, second.issue.reference);
            Step held = bed.step();
            check(problems, held.issue == null && held.ticket.state == State.SIGNED
                    && held.ticket.flag(DeploymentRecords.FLAG_REQUEST_LIMIT), "held with the alert " + held);
            Step still = bed.step();
            check(problems, still.issue == null && still.ticket.equals(held.ticket), "a third publication " + still);
            bed.host(Classification.BUNDLE_PUBLISHED, second.issue.reference);
            check(problems, bed.step().ticket.state == State.PUBLISHED, "published after the hold");
            Bed cancelled = Bed.late().grants().at(State.SIGNED, Crossing.SIGN, Crossing.PUBLISH);
            cancelled.ticket = cancelled.ticket.toBuilder().cause(Cause.CANCELLED).build();
            check(problems, cancelled.step().ticket.state == State.CANCELLED, "the hold has an exit");
        });
        cases.run("publish / a read of other bytes holds with the request limit alert", problems -> {
            Bed bed = Bed.late().grants().at(State.SIGNED, Crossing.SIGN, Crossing.PUBLISH)
                    .host(Classification.BUNDLE_MISMATCH, Fixtures.PUBLISH_ATTEMPT);
            Step held = bed.step();
            check(problems, held.issue == null && held.ticket.state == State.SIGNED
                    && held.ticket.flag(FLAG_REQUEST_LIMIT), "a mismatch waited silently " + held);
            Step still = bed.step();
            check(problems, still.issue == null && still.ticket.equals(held.ticket), "published again " + still);
            // Store damage never heals: a later attempt of the plan holds on the earlier attempt's read.
            Bed later = Bed.late().grants().at(State.SIGNED, Crossing.SIGN, Crossing.PUBLISH);
            Ticket.Builder earlier = Fixtures.ticket(2, later.plan).state(State.CANCELLED).cause(Cause.CANCELLED);
            earlier.append(Bed.entry(Crossing.SIGN, B1, 1, 1100))
                    .append(new Entry(Crossing.PUBLISH, NO_ID, -1, 0, NO_ID, id(0x9b77), TIME));
            later.others.add(earlier.build());
            later.host(Classification.BUNDLE_MISMATCH, id(0x9b77));
            check(problems, later.step().ticket.flag(FLAG_REQUEST_LIMIT), "an earlier attempt's mismatch ignored");
            // An unreadable record gives no fact: the ticket waits without the alert.
            Bed unread = Bed.late().grants().at(State.SIGNED, Crossing.SIGN, Crossing.PUBLISH);
            Step wait = unread.step();
            check(problems, wait.issue == null && wait.ticket.state == State.SIGNED
                    && !wait.ticket.flag(FLAG_REQUEST_LIMIT), "no fact alerted " + wait);
            // Another plan's mismatch is not this plan's.
            Bed other = Bed.late().grants().at(State.SIGNED, Crossing.SIGN, Crossing.PUBLISH);
            other.add(Fixtures.fact(0x79, NO_ID, Classification.BUNDLE_MISMATCH, 0).plan(id(0x199)));
            check(problems, !other.step().ticket.flag(FLAG_REQUEST_LIMIT), "another plan's mismatch");
            // The hold keeps its exits.
            bed.ticket = bed.ticket.toBuilder().cause(Cause.CANCELLED).build();
            check(problems, bed.step().ticket.state == State.CANCELLED, "the hold has no exit");
        });
        cases.run("handover / the coordinator changes only by a recorded handover", problems -> {
            Bed bed = Bed.late().grants().at(State.READY, TO_COMMIT);
            Ticket t = bed.ticket;
            Ticket handed = t.toBuilder().coordinator(CoordinatorClass.DEVICE, id(0xd0))
                    .append(new Entry(Crossing.HANDOVER, B1, -1, 1, NO_ID, id(0xd0), TIME)).build();
            check(problems, TicketMachine.check(t, handed) == null, "a recorded handover refused");
            Ticket silent = t.toBuilder().coordinator(CoordinatorClass.DEVICE, id(0xd0)).build();
            check(problems, TicketMachine.check(t, silent) != null, "a silent handover accepted");
        });
    }

    public static void main(String[] args) {
        Cases.requireAssertions(TicketMachineTest.class);
        tableCases();
        unresolvedCases();
        causeCases();
        activationCases();
        bootCases();
        loopCases();
        healthCases();
        selectionCases();
        signingCases();
        cases.finish("Ticket machine and reconciliation checks passed");
    }
}
