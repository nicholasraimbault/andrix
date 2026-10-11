// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

import dev.andrix.server.deployment.Coordinator;
import dev.andrix.server.deployment.DeploymentRecords;
import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.Classification;
import dev.andrix.server.deployment.DeploymentRecords.Crossing;
import dev.andrix.server.deployment.DeploymentRecords.Entry;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Route;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * A host test stand in for the host signer and artifact store, durable across coordinator
 * generations through marker files. It keeps the host signer's rules that reconciliation relies on: a
 * signing request without a completed record can no longer complete once its call ended, and a
 * publication reads back PUBLISHED or ABSENT for the PUBLISH attempt it names. Nothing is signed: the
 * plan's bound APKs are given. The production host, with apksig, is the lab driver package's.
 */
final class ScriptedHost implements Coordinator.Host {
    private final Path dir;
    private final String bundleApk;
    private final String restorationApk;
    private final SecureRandom random = new SecureRandom();

    ScriptedHost(Path dir, String bundleApk, String restorationApk) throws IOException {
        this.dir = Files.createDirectories(dir);
        this.bundleApk = bundleApk;
        this.restorationApk = restorationApk;
    }

    private String id() {
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        bytes[0] |= 1;
        return LabProtocol.hex(bytes);
    }

    private Observation.Builder fact(Plan plan, Classification classification, String subject) {
        return new Observation.Builder().installation(plan.installation).observationId(id())
                .component(plan.component).boot(DeploymentRecords.NO_ID).route(Route.HOST).at(-1, 0, 0)
                .raw(LabProtocol.sha256Hex((classification + subject).getBytes(StandardCharsets.US_ASCII)))
                .classification(classification).subject(subject);
    }

    private Observation published(Plan plan, String attempt) {
        return fact(plan, Classification.BUNDLE_PUBLISHED, attempt).plan(plan.planId)
                .digest(LabProtocol.sha256Hex(("publication " + plan.planId).getBytes(StandardCharsets.US_ASCII)))
                .apks(bundleApk, restorationApk).build();
    }

    private void mark(String name) {
        try {
            Files.write(dir.resolve(name), new byte[0]);
        } catch (IOException error) {
            throw new UncheckedIOException(error);
        }
    }

    @Override
    public Observation sign(Ticket ticket, Plan plan, Entry entry, Authorization grant) {
        mark("sign-" + entry.reference);
        return fact(plan, Classification.SIGN_COMPLETED, entry.reference).build();
    }

    @Override
    public Observation publish(Ticket ticket, Plan plan, Entry entry) {
        mark("publish-" + entry.reference);
        return published(plan, entry.reference);
    }

    @Override
    public List<Observation> query(Ticket ticket, Plan plan, List<Authorization> grants) {
        List<Observation> facts = new ArrayList<>();
        for (Entry e : ticket.ledger) {
            if (e.crossing != Crossing.SIGN) continue;
            boolean done = Files.exists(dir.resolve("sign-" + e.reference));
            facts.add(fact(plan, done ? Classification.SIGN_COMPLETED : Classification.SIGN_CANNOT_COMPLETE,
                    e.reference).build());
        }
        Entry last = ticket.last(Crossing.PUBLISH);
        if (last != null) {
            if (Files.exists(dir.resolve("publish-" + last.reference))) {
                facts.add(published(plan, last.reference));
            } else {
                facts.add(fact(plan, Classification.BUNDLE_ABSENT, last.reference).plan(plan.planId).build());
            }
        }
        return facts;
    }
}
