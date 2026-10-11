// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

import dev.andrix.lab.component.LabProtocol.Builder;
import dev.andrix.lab.component.LabProtocol.Frame;
import dev.andrix.lab.component.LabProtocol.Message;
import dev.andrix.lab.component.LabProtocol.Status;
import dev.andrix.lab.component.LabProtocol.Type;
import dev.andrix.server.deployment.DeploymentRecords;
import dev.andrix.server.deployment.DeploymentRecords.Classification;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.Reference;
import dev.andrix.server.deployment.DeploymentRecords.Route;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * An in process stand in for the broker, for the bridge's own checks: it decodes every request,
 * keeps it, and answers from a small world (one boot, its checkpoint committed, the factory copy
 * active, at most one staged session, user 0 running) or from a scripted answer for a request type.
 * Every exchange moves the uptime on. The real broker, with its ledger and fences, is exercised by
 * the Python suites.
 */
final class FakeBroker implements BrokerChannel.Transport {
    final String manifest;
    final List<Message> requests = new ArrayList<>();
    final Map<Type, Function<Message, Builder>> scripts = new EnumMap<>(Type.class);
    String boot = "1f0d016e80904303a3ff9eb193eb403d";
    long instance = 4021;
    long elapsed = 30_000;
    long wall = LabFixtures.TIME + 30_000;
    int target = LabProtocol.TARGET_ESTABLISHED_EMPTY;
    Reference session;
    Classification sessionState = Classification.OPEN;
    String expectedConfig;
    private long ids = 0x5000;
    private long groups;

    FakeBroker(String manifest) { this.manifest = manifest; }

    @Override
    public byte[] exchange(byte[] data) {
        Message request = LabProtocol.decode(data);
        requests.add(request);
        elapsed += 100;
        wall += 100;
        Function<Message, Builder> script = scripts.get(request.type);
        Builder reply = script != null ? script.apply(request) : answer(request);
        return LabProtocol.encode(reply.build());
    }

    Builder reply(Message request) { return Message.of(request.type.reply(), request.request, manifest); }

    Builder status(Message request, Status status, String reason) {
        return reply(request).number("status", status.code).text("reason", reason).zeros();
    }

    long count(Type type) {
        return requests.stream().filter(m -> m.type == type).count();
    }

    Message last(Type type) {
        Message found = null;
        for (Message m : requests) if (m.type == type) found = m;
        return found;
    }

    private Builder answer(Message request) {
        switch (request.type) {
            case HELLO:
                if (expectedConfig != null && !expectedConfig.equals(request.id("config"))) {
                    return status(request, Status.REFUSED, "the configuration differs from the admission");
                }
                return reply(request).number("status", 1).number("generation", 1).number("target", target).text("reason", "");
            case CLOCK:
                return reply(request).number("status", 1).id("boot", boot).number("instance", instance)
                        .number("elapsed", elapsed).number("wall", wall).number("group", ++groups).text("reason", "");
            case OBSERVE: {
                List<Frame> frames = new ArrayList<>();
                for (Observation o : world(request.number("scope") == LabProtocol.SCOPE_TICKET)) {
                    frames.add(new Frame(++groups, DeploymentRecords.encodeObservation(o)));
                }
                return reply(request).number("status", 1).frames("frames", frames).text("reason", "");
            }
            case CROSS:
                return status(request, Status.NO_REPLY, "scripted: no reply").number("record", ++groups);
            case POINT:
                return reply(request).number("status", 1).number("record", 0).text("reason", "");
            default:
                return reply(request).number("status", 1).number("record", ++groups).text("reason", "");
        }
    }

    String nextId() { return String.format("%032x", ++ids); }

    Observation.Builder fact(Classification c) {
        Observation.Builder b = new Observation.Builder().installation(LabFixtures.INSTALLATION)
                .observationId(nextId()).boot(boot).route(Route.SHELL).raw("99".repeat(32)).classification(c)
                .at(-1, elapsed, wall);
        return b;
    }

    /** The world's facts: the boot, its checkpoint, both copies, and for a ticket the listing and user 0. */
    List<Observation> world(boolean ticket) {
        String component = LabFixtures.COMPONENT;
        List<Observation> facts = new ArrayList<>();
        facts.add(fact(Classification.BOOT_COMPLETED).text(LabFixtures.FINGERPRINT).build());
        facts.add(fact(Classification.CHECKPOINT_COMMITTED).build());
        facts.add(fact(Classification.FACTORY_PRESENT).component(component).digest(LabFixtures.FACTORY_APK)
                .version(LabFixtures.FACTORY_VERSION).build());
        facts.add(fact(Classification.FACTORY_COPY).component(component).digest(LabFixtures.FACTORY_APK)
                .version(LabFixtures.FACTORY_VERSION).number(LabFixtures.UID).text(LabFixtures.CONTEXT).build());
        if (!ticket) return facts;
        if (session == null) {
            facts.add(fact(Classification.NONE_FOR_PACKAGE).component(component).at(instance, elapsed, wall).build());
        } else {
            facts.add(fact(Classification.SESSIONS_FOR_PACKAGE).component(component).number(1)
                    .at(instance, elapsed, wall).build());
            facts.add(fact(sessionState).component(component).reference(session).at(instance, elapsed, wall).build());
        }
        facts.add(fact(Classification.RUNNING_UNLOCKED).user(0, 0).at(instance, elapsed, wall).build());
        return facts;
    }

    /** A REPLY record for a CROSS request, as the broker would build it. */
    byte[] replyFrame(Message cross, Classification classification, Reference reference) {
        Observation o = new Observation.Builder().installation(LabFixtures.INSTALLATION).observationId(nextId())
                .component(cross.text("component")).boot(cross.id("entry_boot")).route(Route.SHELL)
                .raw("98".repeat(32)).classification(classification)
                .reply(cross.id("ticket"), (int) cross.number("index"), crossingOf(cross))
                .reference(reference).at(cross.number("entry_instance"), elapsed, wall).build();
        return DeploymentRecords.encodeObservation(o);
    }

    static DeploymentRecords.Crossing crossingOf(Message cross) {
        switch ((int) cross.number("crossing")) {
            case 3: return DeploymentRecords.Crossing.CREATE;
            case 4: return DeploymentRecords.Crossing.WRITE;
            case 5: return DeploymentRecords.Crossing.COMMIT;
            case 6: return DeploymentRecords.Crossing.ABANDON;
            case 7: return DeploymentRecords.Crossing.REBOOT;
            default: return DeploymentRecords.Crossing.NOTICE;
        }
    }
}
