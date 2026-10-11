// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

import dev.andrix.lab.component.BridgeErrors.BridgeRefusal;
import dev.andrix.lab.component.LabProtocol.Message;
import dev.andrix.lab.component.LabProtocol.Type;
import dev.andrix.server.deployment.Coordinator;
import dev.andrix.server.deployment.DeploymentRecords;
import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.Crossing;
import dev.andrix.server.deployment.DeploymentRecords.Entry;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import java.util.List;
import java.util.Objects;

/**
 * The host signer and publisher behind the broker's fault cells and completion fence. Signing and
 * publication stay in the host: this wrapper never moves them into the device.
 *
 * <p>Each SIGN or PUBLISH begins with a HOST BEGIN that the broker records before the delegate runs,
 * and ends with a HOST END after it returns or throws. The broker refuses a second BEGIN or END for
 * one ledger entry, so no generation signs or publishes one entry twice. An admitted cell can halt
 * the generation before the effect or after it, or drop the reply, which this wrapper then loses.
 *
 * <p>A query reads the signer's records and the plan's publication by request and attempt. It may
 * run only once every earlier call has ended: the broker answers HELLO only after it reaped every
 * earlier generation and recorded its open host calls as ended with its process, and calls within one
 * generation are sequential. A wrapper made without that HELLO refuses to query.
 */
public final class FaultHost implements Coordinator.Host {
    private final Coordinator.Host delegate;
    private final BrokerChannel channel;
    private final Halter halter;
    private final boolean fenced;

    /**
     * @param fenced whether the broker's HELLO confirmed that every earlier generation and its calls
     *     ended
     */
    public FaultHost(Coordinator.Host delegate, BrokerChannel channel, Halter halter, boolean fenced) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.channel = Objects.requireNonNull(channel, "channel");
        this.halter = Objects.requireNonNull(halter, "halter");
        this.fenced = fenced;
    }

    @Override
    public Observation sign(Ticket ticket, Plan plan, Entry entry, Authorization grant) {
        return call(ticket, plan, entry, LabProtocol.HOST_SIGN, () -> delegate.sign(ticket, plan, entry, grant));
    }

    @Override
    public Observation publish(Ticket ticket, Plan plan, Entry entry) {
        return call(ticket, plan, entry, LabProtocol.HOST_PUBLISH, () -> delegate.publish(ticket, plan, entry));
    }

    @Override
    public List<Observation> query(Ticket ticket, Plan plan, List<Authorization> grants) {
        if (!fenced) throw new BridgeRefusal("no query before the broker confirmed that earlier calls ended");
        return delegate.query(ticket, plan, grants);
    }

    private interface Effect {
        Observation run();
    }

    private Observation call(Ticket ticket, Plan plan, Entry entry, int crossing, Effect effect) {
        if (!fenced) throw new BridgeRefusal("no host call before the broker confirmed that earlier calls ended");
        Crossing expected = crossing == LabProtocol.HOST_SIGN ? Crossing.SIGN : Crossing.PUBLISH;
        int index = ticket.indexOf(entry);
        if (entry.crossing != expected || index != ticket.ledger.size() - 1) {
            throw new BridgeRefusal("a host call for another entry than the ticket's last " + expected);
        }
        int occurrence = 0;
        for (Entry e : ticket.ledger) if (e.crossing == expected) ++occurrence;
        Message begin = request(ticket, plan, entry, crossing, index, occurrence, LabProtocol.PHASE_BEGIN,
                LabProtocol.OUTCOME_NONE, LabProtocol.ZERO_DIGEST);
        decide(channel.call(begin), false);
        Observation reply;
        try {
            reply = effect.run();
        } catch (RuntimeException | Error thrown) {
            Message end = request(ticket, plan, entry, crossing, index, occurrence, LabProtocol.PHASE_END,
                    LabProtocol.OUTCOME_THREW, LabProtocol.ZERO_DIGEST);
            decide(channel.call(end), true);
            throw thrown;
        }
        String digest = reply == null ? LabProtocol.ZERO_DIGEST
                : LabProtocol.sha256Hex(DeploymentRecords.encodeObservation(reply));
        Message end = request(ticket, plan, entry, crossing, index, occurrence, LabProtocol.PHASE_END,
                reply == null ? LabProtocol.OUTCOME_NULL : LabProtocol.OUTCOME_REPLY, digest);
        return decide(channel.call(end), true) ? reply : null;
    }

    private Message request(Ticket ticket, Plan plan, Entry entry, int crossing, int index, int occurrence, int phase,
            int outcome, String reply) {
        return channel.request(Type.HOST).number("phase", phase).number("crossing", crossing)
                .id("ticket", ticket.ticketId).id("plan", plan.planId).number("attempt", ticket.attempt)
                .number("index", index).number("occurrence", occurrence).id("reference", entry.reference)
                .number("outcome", outcome).id("reply", reply).build();
    }

    // True to deliver the reply, false when the broker withheld it. A halt ends the generation.
    private boolean decide(Message reply, boolean end) {
        switch (reply.status()) {
            case OK:
                return true;
            case WITHHELD:
                if (end) return false;
                throw new BridgeRefusal("a reply withheld before the host call ran");
            case HALT:
                halter.halt(Halter.STATUS);
                throw new IllegalStateException("the halter returned");
            default:
                throw new BridgeRefusal("the broker refused the host call: " + reply.text("reason"));
        }
    }
}
