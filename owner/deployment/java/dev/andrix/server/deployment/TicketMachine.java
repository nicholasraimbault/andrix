// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import dev.andrix.server.deployment.DeploymentRecords.Cause;
import dev.andrix.server.deployment.DeploymentRecords.Crossing;
import dev.andrix.server.deployment.DeploymentRecords.Entry;
import dev.andrix.server.deployment.DeploymentRecords.Health;
import dev.andrix.server.deployment.DeploymentRecords.Outcome;
import dev.andrix.server.deployment.DeploymentRecords.Reference;
import dev.andrix.server.deployment.DeploymentRecords.State;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * The ticket state machine of the plan's "Ticket states" table: every exit of every state, the
 * class of each edge, and the check that one ticket value may follow another.
 *
 * <p>Each edge is FORWARD, BOOT or REQUEST. A BOOT edge is taken only when the ticket observes a
 * new kernel boot, which raises its boot count. A REQUEST edge repeats a request, which the
 * ledger counts against the plan's request limit. Every cycle of the table passes through a BOOT
 * or REQUEST edge, so the counters bound or alert every loop: {@link #LOOPS} names the four loops
 * of the rules and what happens at each limit, and the boot limit alert applies to every BOOT
 * edge. {@link #check} refuses a successor value that leaves the table, shrinks the ledger, adds
 * more than one entry, takes a BOOT edge without a new boot, unsets an alert, lowers the cause or
 * the boot count, changes a known reference field or a final health outcome, or changes a
 * terminal ticket. It also refuses ABANDON_INTENT to BOOT_OBSERVED, and every DIVERGED exit,
 * without a COMMIT in the ledger. The store applies it to every ticket update.
 */
public final class TicketMachine {
    /** Why an edge may be taken. */
    public enum Edge { FORWARD, BOOT, REQUEST }

    /** What a loop does at its limit. */
    public enum AtLimit {
        /** The loop ends: the request loop abandons, the health window closes. */
        BOUNDED,
        /** Only Android can end the loop: the ticket holds its state and alerts the owner. */
        HELD
    }

    /** One of the four loops along which a state returns to an earlier one. */
    public static final class Loop {
        public final State from;
        public final State to;
        public final Edge edge;
        public final AtLimit atLimit;
        public final String limit;

        Loop(State from, State to, Edge edge, AtLimit atLimit, String limit) {
            this.from = from;
            this.to = to;
            this.edge = edge;
            this.atLimit = atLimit;
            this.limit = limit;
        }

        @Override
        public String toString() { return from + " -> " + to + " (" + edge + ", " + atLimit + ")"; }
    }

    private static final Map<State, Map<State, Edge>> EXITS = new EnumMap<>(State.class);

    /** The four loops of the rules. */
    public static final List<Loop> LOOPS = List.of(
            new Loop(State.REBOOT_INTENT, State.READY, Edge.REQUEST, AtLimit.BOUNDED, "request limit"),
            new Loop(State.HEALTH_WINDOW, State.HEALTH_WINDOW, Edge.BOOT, AtLimit.BOUNDED, "boot limit"),
            new Loop(State.APPLIED_PROVISIONAL, State.BOOT_OBSERVED, Edge.BOOT, AtLimit.HELD, "boot limit"),
            new Loop(State.ABANDON_INTENT, State.ABANDON_INTENT, Edge.REQUEST, AtLimit.HELD, "request limit"));

    private static void exits(State from, Object... targets) {
        Map<State, Edge> map = new EnumMap<>(State.class);
        for (int i = 0; i < targets.length; i += 2) map.put((State) targets[i], (Edge) targets[i + 1]);
        EXITS.put(from, Collections.unmodifiableMap(map));
    }

    static {
        Edge f = Edge.FORWARD, b = Edge.BOOT, r = Edge.REQUEST;
        exits(State.PLANNED, State.AUTHORIZED, f, State.CANCELLED, f, State.VOID, f);
        exits(State.AUTHORIZED, State.SIGNING, f, State.CANCELLED, f, State.VOID, f);
        exits(State.SIGNING, State.SIGNED, f, State.SIGN_FAILED, f);
        exits(State.SIGNED, State.PUBLISHED, f, State.CANCELLED, f, State.VOID, f);
        exits(State.PUBLISHED, State.SESSION_INTENT, f, State.CANCELLED, f, State.VOID, f);
        exits(State.SESSION_INTENT, State.SESSION_BOUND, f, State.NO_SESSION, f);
        exits(State.SESSION_BOUND, State.WRITTEN, f, State.ABANDON_INTENT, f, State.NATIVE_RECORD_LOST, f);
        exits(State.WRITTEN, State.COMMIT_INTENT, f, State.ABANDON_INTENT, f, State.NATIVE_RECORD_LOST, f);
        exits(State.COMMIT_INTENT, State.READY, f, State.FAILED_NATIVE, f, State.NATIVE_RECORD_LOST, f,
                State.BOOT_OBSERVED, b, State.ABANDON_INTENT, f);
        exits(State.READY, State.REBOOT_INTENT, f, State.ABANDON_INTENT, f, State.BOOT_OBSERVED, b,
                State.NATIVE_RECORD_LOST, f);
        exits(State.READY_AGAIN, State.REBOOT_INTENT, f, State.ABANDON_INTENT, f, State.BOOT_OBSERVED, b,
                State.NATIVE_RECORD_LOST, f);
        exits(State.REBOOT_INTENT, State.BOOT_OBSERVED, b, State.READY, r, State.ABANDON_INTENT, f);
        exits(State.ABANDON_INTENT, State.ABANDONED, f, State.BOOT_OBSERVED, b, State.ABANDON_INTENT, r);
        exits(State.BOOT_OBSERVED, State.APPLIED_PROVISIONAL, f, State.FAILED_NATIVE, f, State.READY_AGAIN, f,
                State.ABANDONED, f, State.NATIVE_RECORD_LOST, f, State.DIVERGED, f, State.ABANDON_INTENT, f);
        exits(State.APPLIED_PROVISIONAL, State.APPLIED, f, State.BOOT_OBSERVED, b);
        exits(State.APPLIED, State.HEALTH_WINDOW, f);
        exits(State.HEALTH_WINDOW, State.CLOSED_APPLIED, f, State.SUPERSEDED, f, State.DIVERGED, f,
                State.HEALTH_WINDOW, b);
        // By the recorded cause. DIVERGED only where COMMIT_INTENT can have been reached.
        exits(State.SIGN_FAILED, State.CANCELLED, f, State.VOID, f, State.CLOSED_FAILED, f);
        exits(State.NO_SESSION, State.CANCELLED, f, State.VOID, f, State.CLOSED_FAILED, f);
        exits(State.ABANDONED, State.CANCELLED, f, State.VOID, f, State.DIVERGED, f, State.CLOSED_FAILED, f);
        exits(State.FAILED_NATIVE, State.VOID, f, State.CANCELLED, f, State.DIVERGED, f, State.CLOSED_FAILED, f);
        exits(State.NATIVE_RECORD_LOST, State.APPLIED_PROVISIONAL, f, State.CANCELLED, f, State.VOID, f,
                State.DIVERGED, f, State.CLOSED_FAILED, f);
        for (State state : State.values()) {
            if (state.terminal()) EXITS.put(state, Collections.emptyMap());
        }
    }

    private TicketMachine() {}

    /** The exits of a state. Empty exactly for the terminal states. */
    public static Set<State> exits(State state) {
        Map<State, Edge> map = EXITS.get(Objects.requireNonNull(state, "state"));
        return map.isEmpty() ? EnumSet.noneOf(State.class) : EnumSet.copyOf(map.keySet());
    }

    /** The class of an edge, or null when the table has no such edge. */
    public static Edge edge(State from, State to) {
        return EXITS.get(from).get(to);
    }

    /** The edges of one class, as from-to pairs. */
    public static List<State[]> edges(Edge kind) {
        List<State[]> result = new ArrayList<>();
        for (Map.Entry<State, Map<State, Edge>> from : EXITS.entrySet()) {
            for (Map.Entry<State, Edge> to : from.getValue().entrySet()) {
                if (to.getValue() == kind) result.add(new State[] {from.getKey(), to.getKey()});
            }
        }
        return result;
    }

    /** The crossing whose entry leads into a state, or null when entering it issues nothing. */
    static Crossing crossingInto(State state) {
        switch (state) {
            case SIGNING: return Crossing.SIGN;
            case SESSION_INTENT: return Crossing.CREATE;
            case COMMIT_INTENT: return Crossing.COMMIT;
            case ABANDON_INTENT: return Crossing.ABANDON;
            case REBOOT_INTENT: return Crossing.REBOOT;
            default: return null;
        }
    }

    /** The states in which an entry of a crossing may be appended without a state change. */
    private static boolean appendsInPlace(Crossing crossing, State state) {
        switch (crossing) {
            case SIGN: return state == State.SIGNING;
            case PUBLISH: return state == State.SIGNED;
            case WRITE: return state == State.SESSION_BOUND;
            case NOTICE: return state == State.PUBLISHED || state == State.READY || state == State.READY_AGAIN;
            case HANDOVER: return !state.terminal();
            default: return false;
        }
    }

    /**
     * Refuses a successor value that is not a legal step from the current one. Returns null when
     * it is legal, otherwise the broken rule. Equal values are legal.
     */
    public static String check(Ticket before, Ticket after) {
        Objects.requireNonNull(before, "before");
        Objects.requireNonNull(after, "after");
        if (before.equals(after)) return null;
        if (!before.installation.equals(after.installation) || !before.ticketId.equals(after.ticketId)
                || !before.component.equals(after.component) || !before.planId.equals(after.planId)
                || before.attempt != after.attempt) {
            return "identity changed";
        }
        if (before.state.terminal()) return "a terminal ticket changed";
        boolean sameState = before.state == after.state;
        Edge edge = sameState ? null : edge(before.state, after.state);
        if (!sameState && edge == null) return "no exit " + before.state + " -> " + after.state;
        // The ledger only grows, by at most one entry per step.
        if (after.ledger.size() < before.ledger.size()
                || !after.ledger.subList(0, before.ledger.size()).equals(before.ledger)) {
            return "ledger rewritten";
        }
        int added = after.ledger.size() - before.ledger.size();
        if (added > 1) return "more than one crossing in one step";
        // A kernel boot during an abandon, and every DIVERGED close, need COMMIT_INTENT reached.
        if (!sameState && after.count(Crossing.COMMIT) == 0 && (after.state == State.DIVERGED
                || (before.state == State.ABANDON_INTENT && after.state == State.BOOT_OBSERVED))) {
            return "no COMMIT in the ledger for " + before.state + " -> " + after.state;
        }
        if (added == 1) {
            Entry entry = after.ledger.get(after.ledger.size() - 1);
            boolean into = !sameState && crossingInto(after.state) == entry.crossing;
            boolean loop = sameState && after.state == State.ABANDON_INTENT && entry.crossing == Crossing.ABANDON;
            boolean signAgain = sameState && after.state == State.SIGNING && entry.crossing == Crossing.SIGN;
            if (!into && !loop && !signAgain && !(sameState && appendsInPlace(entry.crossing, after.state))) {
                return "crossing " + entry.crossing + " does not lead into " + after.state;
            }
        } else {
            // SIGNING is entered without a request when nothing is left to sign.
            Crossing needed = sameState || after.state == State.SIGNING ? null : crossingInto(after.state);
            if (needed != null) return "entering " + after.state + " without its crossing";
        }
        if (sameState && after.state == State.ABANDON_INTENT && added == 0
                && after.count(Crossing.ABANDON) != before.count(Crossing.ABANDON)) {
            return "abandon count changed without an entry";
        }
        // The coordinator changes only by a handover recorded in the ledger.
        boolean handover = added == 1 && after.ledger.get(after.ledger.size() - 1).crossing == Crossing.HANDOVER;
        if (!handover && (before.coordinatorClass != after.coordinatorClass
                || !before.coordinator.equals(after.coordinator))) {
            return "coordinator changed without a handover";
        }
        // Boots: counted once each, never undone.
        boolean newBoot = !before.boot.equals(after.boot);
        if (newBoot && before.boot.equals(DeploymentRecords.NO_ID) && after.bootCount != before.bootCount) {
            return "the first boot is not counted";
        }
        if (after.bootCount < before.bootCount || after.bootCount > before.bootCount + 1) return "boot count jumped";
        if (after.bootCount != before.bootCount && !newBoot) return "a boot counted without a new boot";
        if (edge == Edge.BOOT && (!newBoot || before.boot.equals(DeploymentRecords.NO_ID))) {
            return "a boot edge without a new boot";
        }
        boolean windowRestart = sameState && after.state == State.HEALTH_WINDOW
                && (!before.windowBoot.equals(after.windowBoot) || before.windowStart != after.windowStart);
        if (windowRestart && (before.windowBoot.equals(after.boot) || !after.windowBoot.equals(after.boot))) {
            return "the health window restarted without a reboot";
        }
        // Alerts are never withdrawn. Causes only rise.
        int alerts = DeploymentRecords.FLAG_BOOT_LIMIT | DeploymentRecords.FLAG_REQUEST_LIMIT;
        if ((before.flags & alerts & ~after.flags) != 0) return "an alert withdrawn";
        if (after.cause.code < before.cause.code) return "cause lowered";
        if (before.cause != Cause.NONE && after.cause != before.cause && after.cause.code <= before.cause.code) {
            return "cause replaced by a lower one";
        }
        // A known reference field never changes. A complete reference appears at SESSION_BOUND.
        String reference = referenceRule(before.reference, after.reference);
        if (reference != null) return reference;
        // Final health outcomes never change, and no observed user disappears.
        for (Health old : before.health) {
            Health now = null;
            for (Health h : after.health) if (h.user == old.user && h.serial == old.serial) now = h;
            if (now == null) return "a health outcome dropped";
            if (old.outcome != Outcome.OBSERVING && now.outcome != old.outcome) return "a final outcome changed";
        }
        if (!before.successor.equals(after.successor) && after.state != State.SUPERSEDED) return "successor changed";
        return null;
    }

    private static String referenceRule(Reference before, Reference after) {
        int fields = before.presence;
        if ((after.presence & fields) != fields) return "a reference field forgotten";
        if (before.has(Reference.SESSION) && before.sessionId != after.sessionId) return "session ID changed";
        if (before.has(Reference.CREATED) && before.createdMillis != after.createdMillis) {
            return "createdMillis changed";
        }
        if (before.has(Reference.STAGE_DIR) && !before.stageDir.equals(after.stageDir)) {
            return "stage directory changed";
        }
        if (before.has(Reference.INSTALLER) && before.installerUid != after.installerUid) return "installer changed";
        if (before.has(Reference.NONCE) && !before.nonce.equals(after.nonce)) return "nonce changed";
        return null;
    }
}
