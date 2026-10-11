// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

import dev.andrix.lab.component.BridgeErrors.BridgeRefusal;
import dev.andrix.lab.component.BridgeErrors.GenerationStopped;
import dev.andrix.lab.component.LabProtocol.Message;
import dev.andrix.lab.component.LabProtocol.Status;
import dev.andrix.lab.component.LabProtocol.Type;
import dev.andrix.server.deployment.Coordinator;
import dev.andrix.server.deployment.DeploymentRecords;
import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.Classification;
import dev.andrix.server.deployment.DeploymentRecords.Crossing;
import dev.andrix.server.deployment.DeploymentRecords.Effect;
import dev.andrix.server.deployment.DeploymentRecords.Entry;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.ObservationKind;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Reference;
import dev.andrix.server.deployment.DeploymentRecords.Route;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import dev.andrix.server.deployment.DeploymentStore;
import dev.andrix.server.deployment.DeploymentStore.Found;
import dev.andrix.server.deployment.DeploymentStore.Read;
import dev.andrix.server.deployment.Reconciler.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * The coordinator's device on the lab shell route, through the broker. Its route is SHELL, fixed when
 * it is made, so a coordinator made with it accepts lab points and nothing relabels a shell reading
 * as the device route.
 *
 * <p>The clock and every observation come from the broker on one scale: the boot ID, system_server's
 * start time in clock ticks as the framework instance, and milliseconds of uptime. An unreachable
 * device gives no clock and no fact. A fact is never invented: what the broker cannot read stays
 * unknown, and absence comes only from a complete listing that the reconciler judges.
 *
 * <p>Every frame is decoded strictly by the deployment records' codec and checked here: the admitted
 * installation, the shell route, the round's boot, a kind and component scope the request allows,
 * and for a receipt the round's ticket. Any frame that breaks a rule ends the generation, because the
 * broker never sends one. The ledger entry of each observation's group stays available through
 * {@link #group}.
 *
 * <p>A crossing is sent only for the exact ticket and plan bytes the store holds, the ticket's last
 * ledger entry, a grant of the right effect, and a reference that names the session with its
 * createdMillis, installer and nonce, never its ID alone. The broker builds the command. A dropped,
 * missing or unqualified reply is lost here. An ordered halt ends the generation at once.
 *
 * <p>The reconciler judges an ACTIVATE grant against the round's clock. A COMMIT, REBOOT or NOTICE
 * carries the grant's time and the plan's activation window, so the broker applies the same rule to
 * its own clock reading just before launch. A grant that expired after the round's clock launches
 * nothing. No fact here comes from a clock older than its round's: a fact's framework instance is
 * never below the round clock's in the same boot.
 */
public final class ShellDevice implements Coordinator.Device {
    private static final Set<ObservationKind> COMPONENT_KINDS = Collections.unmodifiableSet(EnumSet.of(
            ObservationKind.BOOT, ObservationKind.CHECKPOINT, ObservationKind.FACTORY, ObservationKind.ACTIVE));
    private static final Set<ObservationKind> TICKET_KINDS = Collections.unmodifiableSet(EnumSet.of(
            ObservationKind.BOOT, ObservationKind.CHECKPOINT, ObservationKind.FACTORY, ObservationKind.ACTIVE,
            ObservationKind.LISTING, ObservationKind.SESSION, ObservationKind.USER, ObservationKind.RECEIPT));
    private static final Set<ObservationKind> DEVICE_SCOPE = Collections.unmodifiableSet(EnumSet.of(
            ObservationKind.BOOT, ObservationKind.CHECKPOINT, ObservationKind.USER));

    private final BrokerChannel channel;
    private final LabConfig config;
    private final DeploymentStore store;
    private final Halter halter;
    private String clockBoot;
    private long clockInstance = -1;
    private final Map<String, Long> groups = new HashMap<>();

    public ShellDevice(BrokerChannel channel, LabConfig config, DeploymentStore store, Halter halter) {
        this.channel = Objects.requireNonNull(channel, "channel");
        this.config = Objects.requireNonNull(config, "config");
        this.store = Objects.requireNonNull(store, "store");
        this.halter = Objects.requireNonNull(halter, "halter");
        if (!store.installation().equals(config.installation)) throw new IllegalArgumentException("another store");
    }

    @Override
    public Route route() { return Route.SHELL; }

    /** The broker's ledger entry of the group an observation of this generation came from, or -1. */
    public long group(String observationId) {
        Long group = groups.get(observationId);
        return group == null ? -1 : group;
    }

    @Override
    public Clock clock() {
        Message reply = channel.call(channel.request(Type.CLOCK).build());
        switch (reply.status()) {
            case OK:
                clockBoot = reply.id("boot");
                clockInstance = reply.number("instance");
                return new Clock(clockBoot, clockInstance, reply.number("elapsed"), reply.number("wall"));
            case UNAVAILABLE:
                clockBoot = null;
                clockInstance = -1;
                return null;
            case STOPPED:
                throw new GenerationStopped(reply.text("reason"));
            default:
                throw new BridgeRefusal("the broker refused CLOCK: " + reply.text("reason"));
        }
    }

    @Override
    public List<Observation> observe(Ticket ticket, Plan plan) {
        if (!ticket.installation.equals(config.installation) || !ticket.component.equals(config.component)
                || !ticket.planId.equals(plan.planId)) {
            throw new BridgeRefusal("a ticket of another installation, component or plan");
        }
        Message reply = channel.call(channel.request(Type.OBSERVE).number("scope", LabProtocol.SCOPE_TICKET)
                .text("component", config.component).id("boot", boot()).id("ticket", ticket.ticketId)
                .id("plan", plan.planId).number("state", RecordCodes.state(ticket.state)).build());
        return facts(reply, TICKET_KINDS, ticket.ticketId);
    }

    @Override
    public List<Observation> observe(String component) {
        if (!component.equals(config.component)) throw new BridgeRefusal("another component");
        Message reply = channel.call(channel.request(Type.OBSERVE).number("scope", LabProtocol.SCOPE_COMPONENT)
                .text("component", component).id("boot", boot()).id("ticket", LabProtocol.ZERO_ID)
                .id("plan", LabProtocol.ZERO_ID).number("state", 0).build());
        return facts(reply, COMPONENT_KINDS, null);
    }

    private String boot() {
        if (clockBoot == null) throw new IllegalStateException("an observation without a reachable clock");
        return clockBoot;
    }

    private List<Observation> facts(Message reply, Set<ObservationKind> kinds, String ticketId) {
        if (reply.status() == Status.STOPPED) throw new GenerationStopped(reply.text("reason"));
        if (reply.status() != Status.OK) throw new BridgeRefusal("the broker refused OBSERVE: " + reply.text("reason"));
        List<Observation> facts = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        Map<String, Long> seen = new HashMap<>();
        for (LabProtocol.Frame frame : reply.frames("frames")) {
            Observation o = decode(frame.record());
            String problem = factProblem(o, kinds, ticketId);
            if (problem != null) throw new BridgeRefusal("a broker frame breaks a rule: " + problem);
            if (!ids.add(o.observationId)) throw new BridgeRefusal("an observation ID twice in one reply");
            seen.put(o.observationId, frame.group);
            facts.add(o);
        }
        groups.putAll(seen);
        return facts;
    }

    private static Observation decode(byte[] record) {
        try {
            return DeploymentRecords.decodeObservation(record);
        } catch (IllegalArgumentException error) {
            throw new BridgeRefusal("an observation record of no valid form: " + error.getMessage(), error);
        }
    }

    // Why an observed fact breaks the bridge's rules, or null.
    private String factProblem(Observation o, Set<ObservationKind> kinds, String ticketId) {
        if (!o.installation.equals(config.installation)) return "another installation";
        if (o.route != Route.SHELL) return "the " + o.route + " route on the shell bridge";
        if (!kinds.contains(o.kind)) return "a " + o.kind + " fact in this observation";
        if (!o.boot.equals(clockBoot)) return "a fact of another boot than the round's clock";
        if (o.instance >= 0 && o.instance < clockInstance) return "a fact of an earlier framework than the round's clock";
        String scope = DEVICE_SCOPE.contains(o.kind) ? "" : config.component;
        if (!o.component.equals(scope)) return "a fact of another component scope";
        if (o.kind == ObservationKind.RECEIPT && !o.subject.equals(ticketId)) return "a receipt of another ticket";
        return null;
    }

    @Override
    public Observation cross(Ticket ticket, Plan plan, Entry entry) {
        Crossing crossing = entry.crossing;
        if (!crossing.device()) throw new BridgeRefusal("not a device crossing: " + crossing);
        String problem = crossingProblem(ticket, plan, entry);
        if (problem != null) throw new BridgeRefusal("the crossing is not issued: " + problem);
        int index = ticket.ledger.size() - 1;
        int occurrence = 0;
        for (Entry e : ticket.ledger) if (e.crossing == crossing) ++occurrence;
        Authorization grant = grant(plan, entry);
        Reference r = ticket.reference;
        LabProtocol.Ref nativeRef = crossing == Crossing.CREATE
                ? new LabProtocol.Ref(LabProtocol.NONCE, 0, 0, "", 0, entry.reference)
                : new LabProtocol.Ref(r.presence, r.sessionId, r.createdMillis, r.stageDir, r.installerUid, r.nonce);
        String bundleApk = crossing == Crossing.WRITE ? boundApk(plan) : LabProtocol.ZERO_DIGEST;
        boolean activated = crossing == Crossing.COMMIT || crossing == Crossing.REBOOT || crossing == Crossing.NOTICE;
        long granted = activated ? grant.grantedAt : 0;
        long window = activated ? plan.activateWindowMillis : 0;
        Message request = channel.request(Type.CROSS).id("ticket", ticket.ticketId)
                .id("ticket_digest", LabProtocol.sha256Hex(DeploymentRecords.encodeTicket(ticket)))
                .id("plan", plan.planId).id("plan_digest", LabProtocol.sha256Hex(DeploymentRecords.encodePlan(plan)))
                .number("attempt", ticket.attempt).text("component", plan.component).number("index", index)
                .number("crossing", RecordCodes.crossing(crossing)).number("occurrence", occurrence)
                .id("entry_boot", entry.boot).number("entry_instance", entry.instance)
                .number("entry_elapsed", entry.elapsed).id("grant", entry.grant).id("reference", entry.reference)
                .ref("native", nativeRef).id("bundle_apk", bundleApk)
                .number("actor", grant == null ? LabProtocol.ACTOR_NONE : RecordCodes.actor(grant.actorClass))
                .number("granted", granted).number("window", window).build();
        Message reply = channel.call(request);
        switch (reply.status()) {
            case OK:
                return replyFact(ticket, entry, index, reply.bytes("frame"), reply.number("record"));
            case NO_REPLY:
            case WITHHELD:
                return null;
            case HALT:
                halter.halt(Halter.STATUS);
                throw new IllegalStateException("the halter returned");
            case STOPPED:
                throw new GenerationStopped(reply.text("reason"));
            default:
                throw new BridgeRefusal("the broker refused CROSS: " + reply.text("reason"));
        }
    }

    // Why a crossing may not be sent, or null. Every rule is an invariant of the coordinator, so a
    // break means damage or a defect, never a reason to guess.
    private String crossingProblem(Ticket ticket, Plan plan, Entry entry) {
        Read<Ticket> storedTicket = store.ticket(ticket.ticketId);
        if (storedTicket.found != Found.RECORD || !Arrays.equals(DeploymentRecords.encodeTicket(storedTicket.value),
                DeploymentRecords.encodeTicket(ticket))) {
            return "the ticket is not the stored ticket";
        }
        Read<Plan> storedPlan = store.plan(plan.planId);
        if (storedPlan.found != Found.RECORD || !Arrays.equals(DeploymentRecords.encodePlan(storedPlan.value),
                DeploymentRecords.encodePlan(plan))) {
            return "the plan is not the stored plan";
        }
        if (ticket.ledger.isEmpty() || !ticket.ledger.get(ticket.ledger.size() - 1).equals(entry)) {
            return "the entry is not the ticket's last ledger entry";
        }
        if (!ticket.planId.equals(plan.planId) || !ticket.component.equals(plan.component)
                || !plan.component.equals(config.component) || !ticket.installation.equals(config.installation)
                || !plan.installation.equals(config.installation) || !ticket.coordinator.equals(config.coordinator)) {
            return "a ticket or plan of another installation, component or coordinator";
        }
        Crossing c = entry.crossing;
        if ((c == Crossing.CREATE || c == Crossing.COMMIT || c == Crossing.REBOOT || c == Crossing.NOTICE)
                && grant(plan, entry) == null) {
            return "no authorization of the right effect for the entry's grant";
        }
        Reference r = ticket.reference;
        if (c == Crossing.CREATE && !r.equals(Reference.NONE.withNonce(entry.reference))) {
            return "CREATE carries exactly the ticket's nonce";
        }
        if ((c == Crossing.WRITE || c == Crossing.COMMIT || c == Crossing.ABANDON)
                && (r.presence & LabProtocol.BOUND_REFERENCE) != LabProtocol.BOUND_REFERENCE) {
            return "a session crossing needs the session with its createdMillis, installer and nonce";
        }
        if (c == Crossing.WRITE && boundApk(plan) == null) return "no single APK that the plan's publication binds";
        return null;
    }

    private Authorization grant(Plan plan, Entry entry) {
        Effect effect = entry.crossing == Crossing.CREATE ? Effect.STAGE : Effect.ACTIVATE;
        for (Authorization a : store.authorizationsOf(plan.planId)) {
            if (a.authorizationId.equals(entry.grant) && a.effect == effect) return a;
        }
        return null;
    }

    // The APK the plan's publication binds to its VARIANT role, read back PUBLISHED, when every such
    // read agrees. Else null.
    private String boundApk(Plan plan) {
        String apk = null;
        for (Observation o : store.observations().values) {
            if (o.classification != Classification.BUNDLE_PUBLISHED || !o.plan.equals(plan.planId)) continue;
            if (apk != null && !apk.equals(o.bundleApk)) return null;
            apk = o.bundleApk;
        }
        return apk;
    }

    private Observation replyFact(Ticket ticket, Entry entry, int index, byte[] frame, long record) {
        Observation o = decode(frame);
        String problem = null;
        if (!o.installation.equals(config.installation) || o.route != Route.SHELL) {
            problem = "a reply of another installation or route";
        } else if (o.kind != ObservationKind.REPLY || !o.subject.equals(ticket.ticketId) || o.sequence != index
                || o.crossing != entry.crossing) {
            problem = "a reply to another crossing";
        } else if (!o.boot.equals(entry.boot) || (entry.crossing.framework() && o.instance != entry.instance)) {
            problem = "a reply of another boot or framework instance than its entry";
        } else if (!o.component.equals(config.component)) {
            problem = "a reply of another component";
        } else if (o.reference.has(LabProtocol.NONCE) && !o.reference.nonce.equals(ticket.reference.nonce)) {
            problem = "a create reply with another nonce";
        }
        if (problem != null) throw new BridgeRefusal("a broker reply breaks a rule: " + problem);
        groups.put(o.observationId, record);
        return o;
    }
}
