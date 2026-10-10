// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import dev.andrix.server.deployment.DeploymentRecords.ActorClass;
import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.Classification;
import dev.andrix.server.deployment.DeploymentRecords.CommitMode;
import dev.andrix.server.deployment.DeploymentRecords.CoordinatorClass;
import dev.andrix.server.deployment.DeploymentRecords.Effect;
import dev.andrix.server.deployment.DeploymentRecords.GrantScope;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Route;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;

/** Fixed values shared by the deployment tests. */
final class Fixtures {
    static final String INSTALLATION = "00112233445566778899aabbccddeeff";
    static final String COMPONENT = "com.android.systemui";
    static final String FINGERPRINT = "andrix/caiman/caiman:17/BP4A.260813.001/2026081300:userdebug/test-keys";
    static final String NEW_FINGERPRINT = "andrix/caiman/caiman:17/BP4A.261006.001/2026100600:userdebug/test-keys";
    static final String CONTEXT = "u:r:platform_app:s0:c512,c768";
    static final int UID = 10057;
    static final long TIME = 1_791_504_000_000L; // 2026-10-09T00:00:00Z.
    static final String COORDINATOR = id(0xc0);
    static final String TRUST = digest(0x7a);
    static final String FACTORY_APK = digest(0xf0);
    /** The variant's signing input: the digest of its ZIP entries outside the signing block. */
    static final String BUNDLE_INPUT = digest(0xb1);
    /** The variant's signed APK: signed output, which only its publication binds to the plan. */
    static final String BUNDLE_APK = digest(0xa1);
    static final String RESTORATION_INPUT = digest(0xb2);
    static final String RESTORATION_APK = digest(0xa2);
    static final String SIGNER = digest(0x51);
    /** The PUBLISH attempt that host bundle facts name by default. */
    static final String PUBLISH_ATTEMPT = id(0x9b1);
    /** An earlier read of a plan's publication, after an attempt that no test ledger holds. */
    static final String READ_ATTEMPT = id(0x9b0);
    /** The digest of a plan's publication record, read back complete. */
    static final String PUBLICATION = digest(0xd7);
    static final long FACTORY_VERSION = 37, BUNDLE_VERSION = 40, RESTORATION_VERSION = 41;
    /** Decision 6's declared rebuild window, two weeks. */
    static final long WINDOW = 14L * 24 * 3600 * 1000;

    private Fixtures() {}

    /** A nonzero 16 byte ID from a small number. */
    static String id(long n) {
        if (n == 0) throw new IllegalArgumentException("zero ID");
        return String.format("%032x", n);
    }

    /** A nonzero 32 byte digest repeating one byte. */
    static String digest(int b) {
        return String.format("%02x", b & 0xff).repeat(32);
    }

    /**
     * The APK digest that the host signer produces from a fixture input: 0xa1 from 0xb1, 0xa2
     * from 0xb2 and so on. NO_DIGEST for no input.
     */
    static String signed(String input) {
        if (input.equals(DeploymentRecords.NO_DIGEST)) return DeploymentRecords.NO_DIGEST;
        return digest(0xa0 | (Integer.parseInt(input.substring(0, 2), 16) & 0x0f));
    }

    /** A host fact that read the plan's publication back complete, binding the signed fixture APKs. */
    static Observation.Builder published(long n, Plan plan, String attempt) {
        return fact(n, DeploymentRecords.NO_ID, Classification.BUNDLE_PUBLISHED, 0).subject(attempt)
                .plan(plan.planId).apks(signed(plan.bundleInput), signed(plan.restorationInput));
    }

    /** A variant plan on the factory base: late commit, one signing transaction, a restoration. */
    static Plan.Builder plan(long n) {
        return new Plan.Builder().installation(INSTALLATION).planId(id(0x100 + n)).component(COMPONENT)
                .bundle(BUNDLE_INPUT, BUNDLE_VERSION).signer(SIGNER)
                .restoration(RESTORATION_INPUT, RESTORATION_VERSION).signing(1)
                .cohort(FINGERPRINT, FACTORY_APK, FACTORY_VERSION).base(FACTORY_APK, FACTORY_VERSION, UID, CONTEXT)
                .selectionRevision(0).trustPolicy(TRUST).commitMode(CommitMode.LATE).healthWindow(600_000)
                .limits(4, 120_000, 3, 3_600_000, 300_000).createdAt(TIME);
    }

    static Authorization grant(long n, Plan plan, Effect effect, int inputs, long at) {
        return new Authorization(INSTALLATION, id(0x200 + n), plan.component, plan.planId, effect, inputs,
                ActorClass.GRANT_HOLDER, 0, 0, id(0x9a), GrantScope.ALL_COMPONENTS, id(0x300 + n), at);
    }

    static Authorization lab(long n, Plan plan, Effect effect, int inputs, long at) {
        return new Authorization(INSTALLATION, id(0x200 + n), plan.component, plan.planId, effect, inputs,
                ActorClass.LAB_OPERATOR, DeploymentRecords.NO_USER, DeploymentRecords.NO_SERIAL,
                DeploymentRecords.NO_ID, GrantScope.NONE, id(0x300 + n), at);
    }

    static Ticket.Builder ticket(long n, Plan plan) {
        return new Ticket.Builder().installation(INSTALLATION).ticketId(id(0x400 + n)).component(plan.component)
                .planId(plan.planId).attempt(1).coordinator(CoordinatorClass.HOST, COORDINATOR);
    }

    /** A device fact of one boot. */
    static Observation.Builder fact(long n, String boot, Classification c, long elapsed) {
        Observation.Builder b = new Observation.Builder().installation(INSTALLATION).observationId(id(0x500 + n))
                .boot(boot).route(Route.SHELL).raw(digest(0x99)).classification(c).at(-1, elapsed, TIME + elapsed);
        switch (c.kind) {
            case BOOT:
                b.text(FINGERPRINT);
                break;
            case FACTORY:
                b.component(COMPONENT).digest(FACTORY_APK).version(FACTORY_VERSION);
                break;
            case ACTIVE:
                b.component(COMPONENT).digest(FACTORY_APK).version(FACTORY_VERSION).number(UID).text(CONTEXT);
                break;
            case LISTING:
                b.component(COMPONENT).at(1, elapsed, TIME + elapsed);
                break;
            case SESSION:
                b.component(COMPONENT).at(1, elapsed, TIME + elapsed);
                break;
            case REPLY:
                b.component(COMPONENT).at(1, elapsed, TIME + elapsed);
                break;
            case USER:
                b.user(0, 0);
                break;
            case HEALTH:
                b.component(COMPONENT).user(0, 0).number(DeploymentRecords.Criterion.ALL);
                break;
            case RECEIPT:
                b.component(COMPONENT).user(0, 0).receipt(id(0x401), 0);
                break;
            case SIGNER:
                b.component(COMPONENT).route(Route.HOST).boot(DeploymentRecords.NO_ID).at(-1, 0, TIME);
                break;
            case BUNDLE: {
                boolean published = c == Classification.BUNDLE_PUBLISHED;
                b.component(COMPONENT).route(Route.HOST).boot(DeploymentRecords.NO_ID).at(-1, 0, TIME)
                        .subject(PUBLISH_ATTEMPT).plan(id(0x101))
                        .digest(published ? PUBLICATION : DeploymentRecords.NO_DIGEST)
                        .apks(published ? BUNDLE_APK : DeploymentRecords.NO_DIGEST,
                                published ? RESTORATION_APK : DeploymentRecords.NO_DIGEST);
                break;
            }
            default:
                break;
        }
        return b;
    }
}
