// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

import dev.andrix.server.deployment.DeploymentRecords;
import dev.andrix.server.deployment.DeploymentRecords.ActorClass;
import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.ChoiceKind;
import dev.andrix.server.deployment.DeploymentRecords.CoordinatorClass;
import dev.andrix.server.deployment.DeploymentRecords.Effect;
import dev.andrix.server.deployment.DeploymentRecords.GrantScope;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Realization;
import dev.andrix.server.deployment.DeploymentRecords.Selection;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import dev.andrix.server.deployment.DeploymentRecords.UpdateResponsibility;
import dev.andrix.server.deployment.DeploymentStore;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Records for the lab's host tests, made through the deployment package's public API only. The
 * cohort and the active copy match the simulated guest of the Python suites.
 */
final class LabFixtures {
    static final String INSTALLATION = "00112233445566778899aabbccddeeff";
    static final String COMPONENT = "com.android.systemui";
    static final String COORDINATOR = "c0".repeat(16);
    static final String TRUST = "7a".repeat(32);
    static final String FINGERPRINT = "andrix/cf/cf:17/BP4A.260813.001/2026081300:userdebug/test-keys";
    static final String CONTEXT = "u:r:platform_app:s0:c512,c768";
    static final int UID = 10112;
    static final String FACTORY_APK = "f0".repeat(32);
    static final long FACTORY_VERSION = 37, BUNDLE_VERSION = 40, RESTORATION_VERSION = 41;
    static final String BUNDLE_INPUT = "b1".repeat(32), RESTORATION_INPUT = "b2".repeat(32);
    static final String SIGNER = "51".repeat(32);
    static final long TIME = 1_791_504_000_000L;
    static final long DAY = 24L * 3600 * 1000;

    private LabFixtures() {}

    static String id(long n) { return String.format("%032x", n); }

    /** A late commit variant plan on the factory base, signing both inputs in one transaction. */
    static Plan plan(String planId, long healthWindow) {
        return plan(planId, healthWindow, DAY);
    }

    /** The same plan with its own ACTIVATE window. */
    static Plan plan(String planId, long healthWindow, long activateWindow) {
        return new Plan.Builder().installation(INSTALLATION).planId(planId).component(COMPONENT)
                .bundle(BUNDLE_INPUT, BUNDLE_VERSION).signer(SIGNER).restoration(RESTORATION_INPUT, RESTORATION_VERSION)
                .signing(1).cohort(FINGERPRINT, FACTORY_APK, FACTORY_VERSION).base(FACTORY_APK, FACTORY_VERSION, UID, CONTEXT)
                .selectionRevision(0).trustPolicy(TRUST).healthWindow(healthWindow).notice(120_000, 120_000)
                .limits(4, 300_000, 3, activateWindow, 600_000).createdAt(TIME).build();
    }

    static Authorization lab(long n, Plan plan, Effect effect, int inputs, long at) {
        return new Authorization(INSTALLATION, id(0x200 + n), plan.component, plan.planId, effect, inputs,
                ActorClass.LAB_OPERATOR, DeploymentRecords.NO_USER, DeploymentRecords.NO_SERIAL, DeploymentRecords.NO_ID,
                GrantScope.NONE, id(0x300 + n), at);
    }

    static Selection initialSelection() {
        return new Selection(INSTALLATION, COMPONENT, 0, ChoiceKind.FACTORY, DeploymentRecords.NO_ID,
                UpdateResponsibility.REBUILD_WINDOW, 14 * DAY, Realization.UNCHECKED, DeploymentRecords.NO_ID,
                DeploymentRecords.NO_ID, DeploymentRecords.NO_ID, TIME);
    }

    /** A new store with the plan, the lab operator's SIGN, STAGE and ACTIVATE, the selection and one ticket. */
    static Ticket install(DeploymentStore store, Plan plan, String ticketId, long grantedAt) throws IOException {
        store.initialize();
        require(store.addPlan(plan), "plan");
        int inputs = DeploymentRecords.INPUT_VARIANT | DeploymentRecords.INPUT_RESTORATION;
        require(store.addAuthorization(lab(1, plan, Effect.SIGN, inputs, grantedAt)), "sign");
        require(store.addAuthorization(lab(2, plan, Effect.STAGE, 0, grantedAt)), "stage");
        require(store.addAuthorization(lab(3, plan, Effect.ACTIVATE, 0, grantedAt)), "activate");
        if (store.selection(COMPONENT).found == DeploymentStore.Found.ABSENT) {
            require(store.putSelection(null, initialSelection()), "selection");
        }
        Ticket ticket = new Ticket.Builder().installation(INSTALLATION).ticketId(ticketId).component(COMPONENT)
                .planId(plan.planId).attempt(store.ticketsOf(plan.planId).size() + 1)
                .coordinator(CoordinatorClass.HOST, COORDINATOR).build();
        require(store.createTicket(ticket), "ticket");
        return ticket;
    }

    static Path config(Path directory, Path store, String manifest) throws IOException {
        Path path = directory.resolve("bridge.config");
        Files.write(path, LabConfig.encode(INSTALLATION, COMPONENT, COORDINATOR, TRUST, manifest, store));
        return path;
    }

    /** The next campaign profile's version 3 configuration: its generation speaks protocol 2. */
    static Path config3(Path directory, Path store, String manifest) throws IOException {
        Path path = directory.resolve("bridge.config");
        Files.write(path, LabConfig.encode(INSTALLATION, COMPONENT, COORDINATOR, TRUST, manifest, store, HOST,
                LabConfig.PROFILE));
        return path;
    }

    /** A host configuration digest for version 3 configurations; the scripted host checks none. */
    static final String HOST = "5e".repeat(32);

    private static void require(boolean ok, String what) {
        if (!ok) throw new IllegalStateException(what + " not written");
    }
}
