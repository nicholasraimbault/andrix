// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import static dev.andrix.server.deployment.Cases.check;
import static dev.andrix.server.deployment.DeploymentRecords.NO_DIGEST;
import static dev.andrix.server.deployment.DeploymentRecords.NO_ID;
import static dev.andrix.server.deployment.Fixtures.BUNDLE_APK;
import static dev.andrix.server.deployment.Fixtures.COMPONENT;
import static dev.andrix.server.deployment.Fixtures.CONTEXT;
import static dev.andrix.server.deployment.Fixtures.FINGERPRINT;
import static dev.andrix.server.deployment.Fixtures.INSTALLATION;
import static dev.andrix.server.deployment.Fixtures.TIME;
import static dev.andrix.server.deployment.Fixtures.UID;
import static dev.andrix.server.deployment.Fixtures.digest;
import static dev.andrix.server.deployment.Fixtures.id;

import dev.andrix.server.deployment.DeploymentRecords.ActorClass;
import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.Cause;
import dev.andrix.server.deployment.DeploymentRecords.ChoiceKind;
import dev.andrix.server.deployment.DeploymentRecords.Classification;
import dev.andrix.server.deployment.DeploymentRecords.CommitMode;
import dev.andrix.server.deployment.DeploymentRecords.CoordinatorClass;
import dev.andrix.server.deployment.DeploymentRecords.Crossing;
import dev.andrix.server.deployment.DeploymentRecords.Effect;
import dev.andrix.server.deployment.DeploymentRecords.GrantScope;
import dev.andrix.server.deployment.DeploymentRecords.Entry;
import dev.andrix.server.deployment.DeploymentRecords.Health;
import dev.andrix.server.deployment.DeploymentRecords.HealthResponse;
import dev.andrix.server.deployment.DeploymentRecords.Kind;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.Outcome;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Prefix;
import dev.andrix.server.deployment.DeploymentRecords.Realization;
import dev.andrix.server.deployment.DeploymentRecords.RecoveryRoute;
import dev.andrix.server.deployment.DeploymentRecords.Reference;
import dev.andrix.server.deployment.DeploymentRecords.Route;
import dev.andrix.server.deployment.DeploymentRecords.Selection;
import dev.andrix.server.deployment.DeploymentRecords.State;
import dev.andrix.server.deployment.DeploymentRecords.Target;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import dev.andrix.server.deployment.DeploymentRecords.UpdateResponsibility;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Function;

/**
 * Host checks of the deployment record codec, version 1 of every kind. Each golden's length and
 * SHA-256 are pinned below, computed by the runner's independent encoder from the layout in
 * owner/deployment/README.md, and the run writes each golden to the directory it is given so the
 * runner compares the bytes. Two layouts are also written here by hand. Every unknown strict
 * code is refused at its byte position, informational fields accept any value, every relation
 * between fields is refused when broken, resealed mutations of every kind are refused or
 * canonical, and the stable prefix of later versions gives evidence only. Host JVM only.
 */
public final class DeploymentRecordsTest {
    private static final Cases cases = new Cases();

    // The goldens: length and SHA-256 of the whole record, from the runner's independent encoder.
    private static final int GOLDEN_PLAN_LATE_ONE_BYTES = 539;
    private static final String GOLDEN_PLAN_LATE_ONE_SHA256 = "d30fa483d138983351bb151cf071865e8e8bbd34ebe62c9d914ab7c5223804e1";
    private static final int GOLDEN_PLAN_EARLY_TWO_BYTES = 539;
    private static final String GOLDEN_PLAN_EARLY_TWO_SHA256 = "0e3390040804cf95ce8708fc61749202077cacc33d78ba6a98ad88acbde7e934";
    private static final int GOLDEN_PLAN_FACTORY_BYTES = 539;
    private static final String GOLDEN_PLAN_FACTORY_SHA256 = "58693ed7bccb962d16d106ce9cd2577f8fdcb556d04ed0642cb96ee4b907c339";
    private static final int GOLDEN_PLAN_TEMPORARY_BYTES = 539;
    private static final String GOLDEN_PLAN_TEMPORARY_SHA256 = "d0561059d255f7c287be1d5dcf3d257528004a682056f7276470732048a73179";
    private static final int GOLDEN_AUTH_SIGN_BYTES = 170;
    private static final String GOLDEN_AUTH_SIGN_SHA256 = "8a1faf2a9901ce724ea0350aaab3c49187aa7adee35ed58de6576574bfd0f46b";
    private static final int GOLDEN_AUTH_ACTIVATE_LAB_BYTES = 170;
    private static final String GOLDEN_AUTH_ACTIVATE_LAB_SHA256 = "b45311311d3c5e5a3754bc0379f2c41babebeb33930bb2c24beb0328775ba447";
    private static final int GOLDEN_AUTH_EMERGENCY_BYTES = 170;
    private static final String GOLDEN_AUTH_EMERGENCY_SHA256 = "3b09bfc57aaa722467c7fd876429501fb22112e856a5bf5960da7efcbed69dbc";
    private static final int GOLDEN_TICKET_PLANNED_BYTES = 235;
    private static final String GOLDEN_TICKET_PLANNED_SHA256 = "52d4647c577d9189cc918b8d91d7158e3d08e666d9e66457bc6520a8ba117bdb";
    private static final int GOLDEN_TICKET_UNRESOLVED_BYTES = 454;
    private static final String GOLDEN_TICKET_UNRESOLVED_SHA256 = "aca94157a626782c8b517b75ec2c351e2edf4b4b5a5c7a4def5d17dbfa4a6ad3";
    private static final int GOLDEN_TICKET_WINDOW_BYTES = 732;
    private static final String GOLDEN_TICKET_WINDOW_SHA256 = "6552b4ced46488f4a4e7edc2c624878b0be761ccacea8fc1744054df8787b10c";
    private static final int GOLDEN_TICKET_SUPERSEDED_BYTES = 712;
    private static final String GOLDEN_TICKET_SUPERSEDED_SHA256 = "aa0668858c6c29ce5c52a313f16befdc9f937e65fdb274ed5b9ec4f0f4691482";
    private static final int GOLDEN_TICKET_MAXIMUM_BYTES = 5937;
    private static final String GOLDEN_TICKET_MAXIMUM_SHA256 = "f28084b61ab3324a23e5aa73ed16607c87f52efb88b659c2368982354e55f960";
    private static final int GOLDEN_OBS_BOOT_BYTES = 237;
    private static final String GOLDEN_OBS_BOOT_SHA256 = "f711d0057e31c19b4b6d4133142a209fb0a5e52ed8fae4c6ae9e5c0532c1f9e9";
    private static final int GOLDEN_OBS_ACTIVE_BYTES = 260;
    private static final String GOLDEN_OBS_ACTIVE_SHA256 = "3e4a7665a1ef607ca5bc1c7e091877457b20f3749370274f5f0c2c59c5ced40e";
    private static final int GOLDEN_OBS_LISTING_BYTES = 187;
    private static final String GOLDEN_OBS_LISTING_SHA256 = "d57cabd34835bf211eda7f545b3aa349fea4a012afff7b56d0e14e64e3db67d5";
    private static final int GOLDEN_OBS_SESSION_SHELL_BYTES = 253;
    private static final String GOLDEN_OBS_SESSION_SHELL_SHA256 = "bee9dd58e1135bc6a3856118add9a05743a8dd5f7c230fcdf321578e1247e17e";
    private static final int GOLDEN_OBS_REPLY_DEVICE_BYTES = 239;
    private static final String GOLDEN_OBS_REPLY_DEVICE_SHA256 = "99df7fa7b6d60fabf7ce9f9058e47ad7528687185da767041520e0f78848c1b3";
    private static final int GOLDEN_OBS_HEALTH_BYTES = 187;
    private static final String GOLDEN_OBS_HEALTH_SHA256 = "fd7aa73d6982b0810a061f4b55f456b65363bc724cc92d5c0f60691fc2373048";
    private static final int GOLDEN_OBS_SIGNER_BYTES = 201;
    private static final String GOLDEN_OBS_SIGNER_SHA256 = "7b6e0563786f4ee0de90009a1c93ab80c625b08ba887c99bcd29a254f7d4e857";
    private static final int GOLDEN_OBS_BUNDLE_BYTES = 313;
    private static final String GOLDEN_OBS_BUNDLE_SHA256 = "e1c772d949efa5177d243daac91836b2e6dec7ec3928cee96339e7b3acaf5ab6";
    private static final int GOLDEN_SELECTION_FACTORY_BYTES = 173;
    private static final String GOLDEN_SELECTION_FACTORY_SHA256 = "4995f27093bbd21aad786b99f73a32db49f0a3f145ea2cbb22aeb5f06f96c13a";
    private static final int GOLDEN_SELECTION_STALE_BYTES = 173;
    private static final String GOLDEN_SELECTION_STALE_SHA256 = "9871db79666bb108589c57ecf0a262b4f557ae3e007a35468e1af0fc975aff4a";
    private static final int GOLDEN_SELECTION_TEMPORARY_BYTES = 173;
    private static final String GOLDEN_SELECTION_TEMPORARY_SHA256 = "b4449fa53d49dcb053bd5561cd3f2072542f9888ee45fa1d3c6a3a8936b80ff4";

    // Two layouts written by hand, field by field, with their SHA-256 left off.
    private static final String AUTH_SIGN_LAYOUT = "41584452 0200 0100 aa000000"
            + " 00112233445566778899aabbccddeeff 00000000000000000000000000000201"
            + " 1400 636f6d2e616e64726f69642e73797374656d7569 00000000000000000000000000000101"
            + " 01 03 01 00000000 0000000000000000"
            + " 0000000000000000000000000000009a 02 00000000000000000000000000000301 0aa4f51da1010000";
    private static final String TICKET_PLANNED_LAYOUT = "41584452 0300 0100 eb000000"
            + " 00112233445566778899aabbccddeeff 00000000000000000000000000000401"
            + " 1400 636f6d2e616e64726f69642e73797374656d7569 00000000000000000000000000000101 01000000"
            + " 01 000000000000000000000000000000c0"
            + " 01 00 00 0000 00000000000000000000000000000000"
            + " 00 00000000 0000000000000000 0000 00000000 00000000000000000000000000000000"
            + " 00000000000000000000000000000000 0000000000000000 00000000000000000000000000000000"
            + " 0000 0000";

    static final List<String> GOLDEN_ORDER = List.of("PLAN_LATE_ONE", "PLAN_EARLY_TWO", "PLAN_FACTORY",
            "PLAN_TEMPORARY", "AUTH_SIGN", "AUTH_ACTIVATE_LAB", "AUTH_EMERGENCY", "TICKET_PLANNED",
            "TICKET_UNRESOLVED", "TICKET_WINDOW", "TICKET_SUPERSEDED", "TICKET_MAXIMUM", "OBS_BOOT", "OBS_ACTIVE",
            "OBS_LISTING", "OBS_SESSION_SHELL", "OBS_REPLY_DEVICE", "OBS_HEALTH", "OBS_SIGNER", "OBS_BUNDLE",
            "SELECTION_FACTORY", "SELECTION_STALE", "SELECTION_TEMPORARY");

    // ------------------------------------------------------------------ golden values

    static Plan planLateOne() { return Fixtures.plan(1).build(); }

    static Plan planEarlyTwo() {
        return Fixtures.plan(2).commitMode(CommitMode.EARLY).signing(2)
                .healthResponse(HealthResponse.RESTORE_AUTOMATICALLY).recoveryRoute(RecoveryRoute.DEVICE_COORDINATOR)
                .notice(300_000, 60_000).repairs(id(0x101)).restorationPlan(id(0x105))
                .base(digest(0xa0), 39, UID, CONTEXT).criteria(0x3f).limits(8, 60_000, 5, 7_200_000, 600_000)
                .selectionRevision(2).createdAt(TIME + 1).build();
    }

    static Plan planFactory() {
        return Fixtures.plan(3).target(Target.FACTORY).bundle(NO_DIGEST, 0).signer(NO_DIGEST)
                .restoration(NO_DIGEST, 0).signing(0).notice(120_000, 120_000)
                .selectionRevision(5).repairs(id(0x102)).build();
    }

    // Decision 6: the new image's own SystemUI from factory source, standing in for plan 0x101.
    static Plan planTemporary() {
        return Fixtures.plan(4).target(Target.TEMPORARY_FACTORY).repairs(id(0x101))
                .bundle(digest(0xb3), 42).restoration(NO_DIGEST, 0)
                .cohort(Fixtures.NEW_FINGERPRINT, digest(0xf1), 38).base(BUNDLE_APK, 40, UID, CONTEXT)
                .selectionRevision(1).createdAt(TIME + 3).build();
    }

    // Decision 1: a grant delegated for this component only.
    static Authorization authSign() {
        Plan p = planLateOne();
        return new Authorization(INSTALLATION, id(0x201), p.component, p.planId, Effect.SIGN, 3,
                ActorClass.GRANT_HOLDER, 0, 0, id(0x9a), GrantScope.ONE_COMPONENT, id(0x301), TIME + 10);
    }

    static Authorization authActivateLab() {
        return Fixtures.lab(2, planLateOne(), Effect.ACTIVATE, 0, TIME + 20);
    }

    // Decision 7: the explicit emergency policy for a restoration approved in advance.
    static Authorization authEmergency() {
        return new Authorization(INSTALLATION, id(0x203), COMPONENT, planEarlyTwo().planId, Effect.EMERGENCY_NOTICE, 0,
                ActorClass.GRANT_HOLDER, 0, 0, id(0x9b), GrantScope.ALL_COMPONENTS, id(0x303), TIME + 30);
    }

    static Ticket ticketPlanned() { return Fixtures.ticket(1, planLateOne()).build(); }

    static Ticket ticketUnresolved() {
        return Fixtures.ticket(2, planLateOne()).state(State.SESSION_INTENT).flags(DeploymentRecords.FLAG_UNRESOLVED)
                .boot(id(0xb0071)).reference(Reference.NONE.withNonce(id(0x6e01)))
                .append(new Entry(Crossing.SIGN, NO_ID, -1, 0, id(0x201), id(0x7001), TIME + 40))
                .append(new Entry(Crossing.PUBLISH, NO_ID, -1, 0, NO_ID, id(0x9b01), TIME + 50))
                .append(new Entry(Crossing.CREATE, id(0xb0071), 7, 5000, id(0x204), id(0x6e01), TIME + 60)).build();
    }

    static Ticket ticketWindow() {
        return Fixtures.ticket(3, planLateOne()).state(State.HEALTH_WINDOW).flags(DeploymentRecords.FLAG_BOOT_LIMIT)
                .bootCount(2).boot(id(0xb0073))
                .reference(new Reference(31, 1234567, TIME + 61, "/data/app-staging/session_1234567", 2000, id(0x6e03)))
                .window(id(0xb0073), 90_000)
                .health(List.of(new Health(0, 0, Outcome.OBSERVING), new Health(10, 12, Outcome.UNHEALTHY)))
                .append(new Entry(Crossing.SIGN, NO_ID, -1, 0, id(0x201), id(0x7003), TIME + 40))
                .append(new Entry(Crossing.PUBLISH, NO_ID, -1, 0, NO_ID, id(0x9b03), TIME + 50))
                .append(new Entry(Crossing.CREATE, id(0xb0072), 7, 5000, id(0x204), id(0x6e03), TIME + 60))
                .append(new Entry(Crossing.WRITE, id(0xb0072), 7, 5100, NO_ID, NO_ID, TIME + 61))
                .append(new Entry(Crossing.COMMIT, id(0xb0072), 7, 5200, id(0x202), NO_ID, TIME + 62))
                .append(new Entry(Crossing.REBOOT, id(0xb0072), 7, 6000, id(0x202), NO_ID, TIME + 63)).build();
    }

    static Ticket ticketSuperseded() {
        return Fixtures.ticket(4, planLateOne()).coordinator(CoordinatorClass.DEVICE, id(0xd0))
                .state(State.SUPERSEDED).cause(Cause.CANCELLED).successor(id(0x105)).bootCount(1).boot(id(0xb0075))
                .reference(new Reference(27, 99, TIME + 70, "", 1000, id(0x6e04)))
                .health(List.of(new Health(0, 0, Outcome.HEALTHY), new Health(10, 12, Outcome.REMOVED),
                        new Health(11, 14, Outcome.DEGRADED)))
                .append(new Entry(Crossing.CREATE, id(0xb0074), 3, 100, id(0x204), id(0x6e04), TIME + 71))
                .append(new Entry(Crossing.WRITE, id(0xb0074), 3, 110, NO_ID, NO_ID, TIME + 72))
                .append(new Entry(Crossing.COMMIT, id(0xb0074), 3, 120, id(0x202), NO_ID, TIME + 73))
                .append(new Entry(Crossing.NOTICE, id(0xb0074), -1, 150, id(0x202), NO_ID, TIME + 74))
                .append(new Entry(Crossing.REBOOT, id(0xb0074), -1, 200, id(0x202), NO_ID, TIME + 75))
                .append(new Entry(Crossing.HANDOVER, id(0xb0075), -1, 50, NO_ID, id(0xd0), TIME + 76)).build();
    }

    static final String LONGEST = "a." + "b".repeat(253);

    // The largest ticket: the longest name and stage directory, 64 users and every crossing at
    // its bound.
    static Ticket ticketMaximum() {
        String boot = "bb".repeat(16), nonce = "aa".repeat(16), coordinator = "cc".repeat(16);
        Ticket.Builder b = new Ticket.Builder().installation("ff".repeat(16)).ticketId("ee".repeat(16))
                .component(LONGEST).planId("dd".repeat(16)).attempt(Integer.MAX_VALUE)
                .coordinator(CoordinatorClass.DEVICE, coordinator).state(State.CLOSED_APPLIED)
                .flags(DeploymentRecords.FLAG_BOOT_LIMIT | DeploymentRecords.FLAG_REQUEST_LIMIT).cause(Cause.CANCELLED)
                .bootCount(0xffff).boot(boot)
                .reference(new Reference(31, Integer.MAX_VALUE, Long.MAX_VALUE, "/" + "s".repeat(254),
                        Integer.MAX_VALUE, nonce));
        List<Health> health = new ArrayList<>();
        Outcome[] finals = {Outcome.HEALTHY, Outcome.DEGRADED, Outcome.UNHEALTHY, Outcome.INCONCLUSIVE, Outcome.REMOVED};
        for (int i = 0; i < 64; i++) health.add(new Health(i, 3L * i, finals[i % finals.length]));
        b.health(health);
        int n = 0;
        for (Crossing c : List.of(Crossing.SIGN, Crossing.SIGN, Crossing.PUBLISH, Crossing.PUBLISH, Crossing.CREATE,
                Crossing.WRITE, Crossing.COMMIT)) {
            b.append(maximumEntry(c, n++, boot, nonce, coordinator));
        }
        for (Crossing c : List.of(Crossing.REBOOT, Crossing.ABANDON, Crossing.NOTICE, Crossing.HANDOVER)) {
            for (int i = 0; i < c.bound; i++) b.append(maximumEntry(c, n++, boot, nonce, coordinator));
        }
        return b.build();
    }

    private static Entry maximumEntry(Crossing c, int n, String boot, String nonce, String coordinator) {
        boolean host = c == Crossing.SIGN || c == Crossing.PUBLISH;
        String grant = c == Crossing.SIGN ? "11".repeat(16) : c == Crossing.CREATE ? "22".repeat(16)
                : c == Crossing.COMMIT || c == Crossing.REBOOT || c == Crossing.NOTICE ? "33".repeat(16) : NO_ID;
        String reference = c == Crossing.SIGN ? "44".repeat(15) + String.format("%02x", n)
                : c == Crossing.PUBLISH ? "55".repeat(15) + String.format("%02x", n)
                : c == Crossing.CREATE ? nonce : c == Crossing.HANDOVER ? coordinator : NO_ID;
        return new Entry(c, host ? NO_ID : boot, host ? -1 : n, host ? 0 : 1000L * n, grant, reference, -n);
    }

    static Observation obsBoot() {
        return Fixtures.fact(1, id(0xb0071), Classification.BOOT_COMPLETED, 4000).build();
    }

    static Observation obsActive() {
        return Fixtures.fact(6, id(0xb0073), Classification.DATA_COPY, 91_000).digest(BUNDLE_APK).version(40).build();
    }

    static Observation obsListing() {
        return Fixtures.fact(7, id(0xb0071), Classification.SESSIONS_FOR_PACKAGE, 5300).number(1).build();
    }

    static Observation obsSessionShell() {
        return Fixtures.fact(2, id(0xb0071), Classification.VERIFYING, 5300)
                .reference(new Reference(15, 1234567, TIME + 61, "/data/app-staging/session_1234567", 2000, NO_ID))
                .build();
    }

    static Observation obsReplyDevice() {
        return Fixtures.fact(3, id(0xb0071), Classification.REPLY_SUCCESS, 5010).route(Route.DEVICE)
                .reply(id(0x402), 2, Crossing.CREATE)
                .reference(new Reference(27, 99, TIME + 70, "", 1000, id(0x6e01))).build();
    }

    static Observation obsHealth() {
        return Fixtures.fact(4, id(0xb0073), Classification.HEALTH_DEGRADED, 95_000).user(10, 12).number(0x7b).build();
    }

    static Observation obsSigner() {
        return Fixtures.fact(5, NO_ID, Classification.SIGN_COMPLETED, 0).subject(id(0x7001)).build();
    }

    // The store's read of plan 0x101's publication after the PUBLISH attempt of ticketUnresolved(),
    // with the APKs of the bundles it binds to the plan's two roles.
    static Observation obsBundle() {
        return Fixtures.fact(8, NO_ID, Classification.BUNDLE_PUBLISHED, 0).subject(id(0x9b01)).plan(id(0x101))
                .digest(digest(0xd7)).apks(digest(0xa1), digest(0xa2)).build();
    }

    static Selection selectionFactory() {
        return new Selection(INSTALLATION, COMPONENT, 0, ChoiceKind.FACTORY, NO_ID, UpdateResponsibility.REBUILD_WINDOW,
                Fixtures.WINDOW, Realization.UNCHECKED, NO_ID, NO_ID, NO_ID, TIME);
    }

    static Selection selectionStale() {
        return new Selection(INSTALLATION, COMPONENT, 3, ChoiceKind.PLAN, id(0x101),
                UpdateResponsibility.KEEP_STALE, 0, Realization.STALE_BASE, id(0xb0076), id(0x106), NO_ID, TIME + 100);
    }

    // Decision 6: the owner approved temporary factory copy, while the choice stays plan 0x101.
    static Selection selectionTemporary() {
        return new Selection(INSTALLATION, COMPONENT, 1, ChoiceKind.PLAN, id(0x101), UpdateResponsibility.REBUILD_WINDOW,
                Fixtures.WINDOW, Realization.TEMPORARY_FACTORY, id(0xb0077), id(0x106), id(0x104), TIME + 200);
    }

    // Every golden's encoding, by name. A value its constructor refuses is left out, so each case
    // that needs it fails by itself and every run completes with every case.
    static Map<String, byte[]> goldens() {
        Map<String, byte[]> result = new LinkedHashMap<>();
        Map<String, java.util.function.Supplier<byte[]>> make = new LinkedHashMap<>();
        make.put("PLAN_LATE_ONE", () -> DeploymentRecords.encodePlan(planLateOne()));
        make.put("PLAN_EARLY_TWO", () -> DeploymentRecords.encodePlan(planEarlyTwo()));
        make.put("PLAN_FACTORY", () -> DeploymentRecords.encodePlan(planFactory()));
        make.put("PLAN_TEMPORARY", () -> DeploymentRecords.encodePlan(planTemporary()));
        make.put("AUTH_SIGN", () -> DeploymentRecords.encodeAuthorization(authSign()));
        make.put("AUTH_ACTIVATE_LAB", () -> DeploymentRecords.encodeAuthorization(authActivateLab()));
        make.put("AUTH_EMERGENCY", () -> DeploymentRecords.encodeAuthorization(authEmergency()));
        make.put("TICKET_PLANNED", () -> DeploymentRecords.encodeTicket(ticketPlanned()));
        make.put("TICKET_UNRESOLVED", () -> DeploymentRecords.encodeTicket(ticketUnresolved()));
        make.put("TICKET_WINDOW", () -> DeploymentRecords.encodeTicket(ticketWindow()));
        make.put("TICKET_SUPERSEDED", () -> DeploymentRecords.encodeTicket(ticketSuperseded()));
        make.put("TICKET_MAXIMUM", () -> DeploymentRecords.encodeTicket(ticketMaximum()));
        make.put("OBS_BOOT", () -> DeploymentRecords.encodeObservation(obsBoot()));
        make.put("OBS_ACTIVE", () -> DeploymentRecords.encodeObservation(obsActive()));
        make.put("OBS_LISTING", () -> DeploymentRecords.encodeObservation(obsListing()));
        make.put("OBS_SESSION_SHELL", () -> DeploymentRecords.encodeObservation(obsSessionShell()));
        make.put("OBS_REPLY_DEVICE", () -> DeploymentRecords.encodeObservation(obsReplyDevice()));
        make.put("OBS_HEALTH", () -> DeploymentRecords.encodeObservation(obsHealth()));
        make.put("OBS_SIGNER", () -> DeploymentRecords.encodeObservation(obsSigner()));
        make.put("OBS_BUNDLE", () -> DeploymentRecords.encodeObservation(obsBundle()));
        make.put("SELECTION_FACTORY", () -> DeploymentRecords.encodeSelection(selectionFactory()));
        make.put("SELECTION_STALE", () -> DeploymentRecords.encodeSelection(selectionStale()));
        make.put("SELECTION_TEMPORARY", () -> DeploymentRecords.encodeSelection(selectionTemporary()));
        for (Map.Entry<String, java.util.function.Supplier<byte[]>> e : make.entrySet()) {
            try {
                result.put(e.getKey(), e.getValue().get());
            } catch (RuntimeException refused) {
                // Left out: the cases that need it fail.
            }
        }
        return result;
    }

    private static final Map<String, Object[]> PINS = new LinkedHashMap<>();

    static {
        PINS.put("PLAN_LATE_ONE", new Object[] {GOLDEN_PLAN_LATE_ONE_BYTES, GOLDEN_PLAN_LATE_ONE_SHA256});
        PINS.put("PLAN_EARLY_TWO", new Object[] {GOLDEN_PLAN_EARLY_TWO_BYTES, GOLDEN_PLAN_EARLY_TWO_SHA256});
        PINS.put("PLAN_FACTORY", new Object[] {GOLDEN_PLAN_FACTORY_BYTES, GOLDEN_PLAN_FACTORY_SHA256});
        PINS.put("PLAN_TEMPORARY", new Object[] {GOLDEN_PLAN_TEMPORARY_BYTES, GOLDEN_PLAN_TEMPORARY_SHA256});
        PINS.put("AUTH_SIGN", new Object[] {GOLDEN_AUTH_SIGN_BYTES, GOLDEN_AUTH_SIGN_SHA256});
        PINS.put("AUTH_ACTIVATE_LAB", new Object[] {GOLDEN_AUTH_ACTIVATE_LAB_BYTES, GOLDEN_AUTH_ACTIVATE_LAB_SHA256});
        PINS.put("AUTH_EMERGENCY", new Object[] {GOLDEN_AUTH_EMERGENCY_BYTES, GOLDEN_AUTH_EMERGENCY_SHA256});
        PINS.put("TICKET_PLANNED", new Object[] {GOLDEN_TICKET_PLANNED_BYTES, GOLDEN_TICKET_PLANNED_SHA256});
        PINS.put("TICKET_UNRESOLVED", new Object[] {GOLDEN_TICKET_UNRESOLVED_BYTES, GOLDEN_TICKET_UNRESOLVED_SHA256});
        PINS.put("TICKET_WINDOW", new Object[] {GOLDEN_TICKET_WINDOW_BYTES, GOLDEN_TICKET_WINDOW_SHA256});
        PINS.put("TICKET_SUPERSEDED", new Object[] {GOLDEN_TICKET_SUPERSEDED_BYTES, GOLDEN_TICKET_SUPERSEDED_SHA256});
        PINS.put("TICKET_MAXIMUM", new Object[] {GOLDEN_TICKET_MAXIMUM_BYTES, GOLDEN_TICKET_MAXIMUM_SHA256});
        PINS.put("OBS_BOOT", new Object[] {GOLDEN_OBS_BOOT_BYTES, GOLDEN_OBS_BOOT_SHA256});
        PINS.put("OBS_ACTIVE", new Object[] {GOLDEN_OBS_ACTIVE_BYTES, GOLDEN_OBS_ACTIVE_SHA256});
        PINS.put("OBS_LISTING", new Object[] {GOLDEN_OBS_LISTING_BYTES, GOLDEN_OBS_LISTING_SHA256});
        PINS.put("OBS_SESSION_SHELL", new Object[] {GOLDEN_OBS_SESSION_SHELL_BYTES, GOLDEN_OBS_SESSION_SHELL_SHA256});
        PINS.put("OBS_REPLY_DEVICE", new Object[] {GOLDEN_OBS_REPLY_DEVICE_BYTES, GOLDEN_OBS_REPLY_DEVICE_SHA256});
        PINS.put("OBS_HEALTH", new Object[] {GOLDEN_OBS_HEALTH_BYTES, GOLDEN_OBS_HEALTH_SHA256});
        PINS.put("OBS_SIGNER", new Object[] {GOLDEN_OBS_SIGNER_BYTES, GOLDEN_OBS_SIGNER_SHA256});
        PINS.put("OBS_BUNDLE", new Object[] {GOLDEN_OBS_BUNDLE_BYTES, GOLDEN_OBS_BUNDLE_SHA256});
        PINS.put("SELECTION_FACTORY", new Object[] {GOLDEN_SELECTION_FACTORY_BYTES, GOLDEN_SELECTION_FACTORY_SHA256});
        PINS.put("SELECTION_STALE", new Object[] {GOLDEN_SELECTION_STALE_BYTES, GOLDEN_SELECTION_STALE_SHA256});
        PINS.put("SELECTION_TEMPORARY", new Object[] {GOLDEN_SELECTION_TEMPORARY_BYTES,
            GOLDEN_SELECTION_TEMPORARY_SHA256});
    }

    // ------------------------------------------------------------------ helpers

    static String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder();
        for (byte b : bytes) text.append(String.format("%02x", b & 0xff));
        return text.toString();
    }

    static byte[] unhex(String text) {
        String digits = text.replace(" ", "");
        byte[] bytes = new byte[digits.length() / 2];
        for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) Integer.parseInt(digits.substring(2 * i, 2 * i + 2), 16);
        return bytes;
    }

    static String sha(byte[] bytes) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    // Sets the length field and the checksum of a record whose bytes were changed.
    static byte[] reseal(byte[] record) throws Exception {
        byte[] r = record.clone();
        int length = r.length;
        for (int i = 0; i < 4; i++) r[8 + i] = (byte) (length >>> (8 * i));
        byte[] sum = MessageDigest.getInstance("SHA-256").digest(Arrays.copyOf(r, length - 32));
        System.arraycopy(sum, 0, r, length - 32, 32);
        return r;
    }

    // A record of a kind and version from a body, framed and sealed.
    static byte[] frame(int type, int version, byte[] body) throws Exception {
        byte[] r = new byte[12 + body.length + 32];
        r[0] = 0x41; r[1] = 0x58; r[2] = 0x44; r[3] = 0x52;
        r[4] = (byte) type; r[6] = (byte) version; r[7] = (byte) (version >>> 8);
        System.arraycopy(body, 0, r, 12, body.length);
        return reseal(r);
    }

    static byte[] body(byte[] record) { return Arrays.copyOfRange(record, 12, record.length - 32); }

    static byte[] relabel(byte[] record, int version) throws Exception {
        byte[] r = record.clone();
        r[6] = (byte) version;
        r[7] = (byte) (version >>> 8);
        return reseal(r);
    }

    static byte[] set(byte[] record, int at, int... values) throws Exception {
        byte[] r = record.clone();
        for (int i = 0; i < values.length; i++) r[at + i] = (byte) values[i];
        return reseal(r);
    }

    static byte[] setLong(byte[] record, int at, long value) throws Exception {
        byte[] r = record.clone();
        for (int i = 0; i < 8; i++) r[at + i] = (byte) (value >>> (8 * i));
        return reseal(r);
    }

    static boolean refused(Function<byte[], ?> decode, byte[] record) {
        try {
            decode.apply(record);
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }

    static boolean refusedValue(Runnable build) {
        try {
            build.run();
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }

    static Function<byte[], ?> decoder(Kind kind) {
        switch (kind) {
            case PLAN: return DeploymentRecords::decodePlan;
            case AUTHORIZATION: return DeploymentRecords::decodeAuthorization;
            case TICKET: return DeploymentRecords::decodeTicket;
            case OBSERVATION: return DeploymentRecords::decodeObservation;
            default: return DeploymentRecords::decodeSelection;
        }
    }

    static Function<Object, byte[]> encoder(Kind kind) {
        switch (kind) {
            case PLAN: return v -> DeploymentRecords.encodePlan((Plan) v);
            case AUTHORIZATION: return v -> DeploymentRecords.encodeAuthorization((Authorization) v);
            case TICKET: return v -> DeploymentRecords.encodeTicket((Ticket) v);
            case OBSERVATION: return v -> DeploymentRecords.encodeObservation((Observation) v);
            default: return v -> DeploymentRecords.encodeSelection((Selection) v);
        }
    }

    static Kind kindOf(String golden) {
        if (golden.startsWith("PLAN")) return Kind.PLAN;
        if (golden.startsWith("AUTH")) return Kind.AUTHORIZATION;
        if (golden.startsWith("TICKET")) return Kind.TICKET;
        if (golden.startsWith("OBS")) return Kind.OBSERVATION;
        return Kind.SELECTION;
    }

    // Body offsets of the plan's fields after the variable length texts, from the layout.
    static final class PlanAt {
        final int base, after, b;

        PlanAt(Plan p) {
            base = 12 + 32 + 2 + p.component.length();
            after = base + 133 + p.fingerprint.length();
            b = after + 86 + p.baseContext.length();
        }
    }

    static int authorizationBase(Authorization a) { return 12 + 32 + 2 + a.component.length() + 16; }

    static int ticketBase(Ticket t) { return 12 + 32 + 2 + t.component.length() + 16 + 4; }

    static int observationBase(Observation o) { return 12 + 32 + 2 + o.component.length() + 16 + 4 + 8; }

    static int selectionBase(Selection s) { return 12 + 16 + 2 + s.component.length() + 8; }

    // Every value of one byte that is not a known code is refused at that byte.
    static void strictByte(List<String> problems, String field, byte[] record, int at, Function<byte[], ?> decode,
            int... known) throws Exception {
        for (int value = 0; value < 256; value++) {
            boolean isKnown = false;
            for (int k : known) isKnown |= k == value;
            if (isKnown) continue;
            if (!refused(decode, set(record, at, value))) problems.add(field + " accepted unknown " + value);
        }
    }

    // ------------------------------------------------------------------ cases

    private static void goldenCases(Path out) throws Exception {
        Map<String, byte[]> goldens = goldens();
        for (String name : GOLDEN_ORDER) {
            cases.run("golden / " + name.toLowerCase().replace('_', ' '), problems -> {
                byte[] bytes = goldens.get(name);
                check(problems, bytes != null, "golden refused by its constructor");
                if (bytes == null) return;
                Files.write(out.resolve(name + ".bin"), bytes);
                Object[] pin = PINS.get(name);
                check(problems, bytes.length == (Integer) pin[0], "length " + bytes.length);
                check(problems, sha(bytes).equals(pin[1]), "SHA-256 differs from the independent encoder");
                Kind kind = kindOf(name);
                Object decoded = decoder(kind).apply(bytes);
                check(problems, Arrays.equals(encoder(kind).apply(decoded), bytes), "decode and encode differ");
                check(problems, bytes.length <= DeploymentRecords.MAX_BYTES, "above MAX_BYTES");
            });
        }
        cases.run("golden / authorization layout written by hand", problems -> {
            byte[] bytes = goldens.get("AUTH_SIGN");
            byte[] layout = unhex(AUTH_SIGN_LAYOUT);
            check(problems, bytes != null && Arrays.equals(Arrays.copyOf(bytes, bytes.length - 32), layout),
                    "the encoder differs from the hand layout");
            check(problems, bytes != null && Arrays.equals(reseal(Arrays.copyOf(layout, layout.length + 32)), bytes),
                    "the hand layout's SHA-256 differs");
        });
        cases.run("golden / ticket layout written by hand", problems -> {
            byte[] bytes = goldens.get("TICKET_PLANNED");
            byte[] layout = unhex(TICKET_PLANNED_LAYOUT);
            check(problems, bytes != null && Arrays.equals(Arrays.copyOf(bytes, bytes.length - 32), layout),
                    "the encoder differs from the hand layout");
        });
    }

    private static void frameCases() throws Exception {
        Map<String, byte[]> goldens = goldens();
        cases.run("frame / magic, type, version, length and checksum are verified first", problems -> {
            for (String name : GOLDEN_ORDER) {
                byte[] r = goldens.get(name);
                Function<byte[], ?> decode = decoder(kindOf(name));
                byte[] badSum = r.clone();
                badSum[r.length - 1] ^= 1;
                check(problems, refused(decode, badSum), name + " checksum");
                check(problems, refused(decode, set(r, 0, 0x41, 0x58, 0x49, 0x44)), name + " native magic");
                check(problems, refused(decode, relabel(r, 0)), name + " version 0");
                check(problems, refused(decode, relabel(r, 2)), name + " version 2");
                int wrongType = kindOf(name).code % 5 + 1;
                check(problems, refused(decode, set(r, 4, wrongType)), name + " wrong type");
                byte[] badLength = r.clone();
                badLength[8] ^= 1;
                check(problems, refused(decode, badLength), name + " length");
                check(problems, refused(decode, Arrays.copyOf(r, 43)), name + " short");
                check(problems, refused(decode, reseal(Arrays.copyOf(r, r.length + 1))), name + " trailing byte");
                check(problems, refused(decode, reseal(Arrays.copyOfRange(r, 0, r.length - 1))), name + " truncated");
                int[] frame = DeploymentRecords.intactFrame(r);
                check(problems, frame != null && frame[0] == kindOf(name).code && frame[1] == 1, name + " intact frame");
                check(problems, DeploymentRecords.intactFrame(badSum) == null, name + " damaged frame intact");
            }
            check(problems, refused(DeploymentRecords::decodePlan, new byte[DeploymentRecords.MAX_BYTES + 1]),
                    "oversized input");
            try {
                DeploymentRecords.decodeTicket(null);
                problems.add("null decoded");
            } catch (NullPointerException expected) {
                // Null throws its own exception.
            }
        });
    }

    private static void strictCases() throws Exception {
        Map<String, byte[]> goldens = goldens();
        cases.run("decoder refuses / unknown strict codes in every kind", problems -> {
            byte[] plan = goldens.get("PLAN_LATE_ONE");
            PlanAt p = new PlanAt(planLateOne());
            Function<byte[], ?> dp = DeploymentRecords::decodePlan;
            strictByte(problems, "class", plan, p.base, dp, 1, 2, 3);
            strictByte(problems, "target", plan, p.base + 1, dp, 1, 2, 3);
            strictByte(problems, "signing", plan, p.base + 130, dp, 0, 1, 2);
            strictByte(problems, "users", plan, p.b, dp, 1);
            strictByte(problems, "data", plan, p.b + 1, dp, 1);
            strictByte(problems, "commit mode", plan, p.b + 42, dp, 1, 2);
            strictByte(problems, "health response", plan, p.b + 53, dp, 1, 2);
            strictByte(problems, "recovery route", plan, p.b + 70, dp, 1, 2);
            check(problems, refused(dp, set(plan, p.b + 43, 0x80, 0)), "criteria bit 7");
            check(problems, refused(dp, set(plan, p.b + 43, 0, 0)), "no criteria");
            byte[] auth = goldens.get("AUTH_SIGN");
            int a = authorizationBase(authSign());
            Function<byte[], ?> da = DeploymentRecords::decodeAuthorization;
            strictByte(problems, "effect", auth, a, da, 1, 2, 3, 4, 5);
            strictByte(problems, "inputs", auth, a + 1, da, 1, 2, 3);
            strictByte(problems, "actor class", auth, a + 2, da, 1, 2);
            strictByte(problems, "grant scope", auth, a + 31, da, 0, 1, 2);
            byte[] ticket = goldens.get("TICKET_WINDOW");
            Ticket window = ticketWindow();
            int t = ticketBase(window);
            Function<byte[], ?> dt = DeploymentRecords::decodeTicket;
            strictByte(problems, "coordinator class", ticket, t, dt, 1, 2);
            int[] states = new int[28];
            for (int i = 0; i < 28; i++) states[i] = i + 1;
            strictByte(problems, "state", ticket, t + 17, dt, states);
            strictByte(problems, "flags", ticket, t + 18, dt, 0, 1, 2, 3, 4, 5, 6, 7);
            strictByte(problems, "cause", ticket, t + 19, dt, 0, 1, 2, 3, 4, 5, 6);
            strictByte(problems, "reference presence", ticket, t + 38, dt, 31);
            int health = t + 73 + window.reference.stageDir.length() + 16 + 8 + 16 + 2;
            strictByte(problems, "outcome", ticket, health + 12, dt, 0, 1, 2, 3, 4, 5);
            int ledger = health + 2 * 13 + 2;
            strictByte(problems, "crossing", ticket, ledger, dt, 1, 2, 3, 4, 5, 6, 7, 8, 9);
            byte[] obs = goldens.get("OBS_HEALTH");
            int o = observationBase(obsHealth());
            Function<byte[], ?> dob = DeploymentRecords::decodeObservation;
            strictByte(problems, "observation kind", obs, o, dob, 9);
            strictByte(problems, "route", obs, o + 1, dob, 1, 2);
            strictByte(problems, "health classification", obs, o + 58, dob, 1, 2, 3, 4);
            byte[] boot = goldens.get("OBS_BOOT");
            strictByte(problems, "boot classification", boot, observationBase(obsBoot()) + 58, dob, 1, 2);
            byte[] reply = goldens.get("OBS_REPLY_DEVICE");
            int r = observationBase(obsReplyDevice());
            strictByte(problems, "reply crossing", reply, r + 59 + 16 + 2, dob, 3);
            strictByte(problems, "reply classification", reply, r + 58, dob, 1);
            byte[] sel = goldens.get("SELECTION_STALE");
            int s = selectionBase(selectionStale());
            Function<byte[], ?> ds = DeploymentRecords::decodeSelection;
            strictByte(problems, "choice", sel, s, ds, 2);
            strictByte(problems, "responsibility", sel, s + 17, ds, 1, 2);
            strictByte(problems, "realization", sel, s + 26, ds, 3, 4, 5);
        });
        cases.run("decoder accepts / informational fields take any value", problems -> {
            for (long value : new long[] {0, -1, Long.MIN_VALUE, Long.MAX_VALUE, 123}) {
                byte[] plan = setLong(goldens.get("PLAN_LATE_ONE"), new PlanAt(planLateOne()).b + 115, value);
                Plan p = DeploymentRecords.decodePlan(plan);
                check(problems, p.createdAt == value && Arrays.equals(DeploymentRecords.encodePlan(p), plan),
                        "plan created " + value);
                Selection stale = selectionStale();
                byte[] sel = setLong(goldens.get("SELECTION_STALE"), selectionBase(stale) + 75, value);
                check(problems, DeploymentRecords.decodeSelection(sel).changedAt == value, "selection time " + value);
                Observation boot = obsBoot();
                byte[] obs = setLong(goldens.get("OBS_BOOT"), observationBase(boot) + 18, value);
                check(problems, DeploymentRecords.decodeObservation(obs).wall == value, "observation wall " + value);
                Ticket window = ticketWindow();
                int ledger = ticketBase(window) + 73 + window.reference.stageDir.length() + 16 + 8 + 16 + 2 + 2 * 13 + 2;
                byte[] ticket = setLong(goldens.get("TICKET_WINDOW"), ledger + 65, value);
                check(problems, DeploymentRecords.decodeTicket(ticket).ledger.get(0).issuedAt == value,
                        "ledger time " + value);
            }
        });
    }

    private static void relationCases() throws Exception {
        cases.run("decoder refuses / zero IDs and digests where a value is required", problems -> {
            check(problems, refusedValue(() -> Fixtures.plan(1).installation(NO_ID).build()), "plan installation");
            check(problems, refusedValue(() -> Fixtures.plan(1).planId(NO_ID).build()), "plan ID");
            check(problems, refusedValue(() -> Fixtures.plan(1).trustPolicy(NO_DIGEST).build()), "trust policy");
            check(problems, refusedValue(() -> Fixtures.plan(1).cohort(FINGERPRINT, NO_DIGEST, 37).build()), "factory");
            check(problems, refusedValue(() -> Fixtures.plan(1).bundle(NO_DIGEST, 40).build()), "bundle");
            check(problems, refusedValue(() -> Fixtures.plan(1).signer(NO_DIGEST).build()), "signer");
            check(problems, refusedValue(() -> new Authorization(INSTALLATION, id(1), COMPONENT, id(2), Effect.STAGE, 0,
                    ActorClass.GRANT_HOLDER, 0, 0, id(3), GrantScope.ALL_COMPONENTS, NO_ID, TIME)), "interaction");
            check(problems, refusedValue(() -> Fixtures.ticket(1, planLateOne()).coordinator(CoordinatorClass.HOST,
                    NO_ID).build()), "coordinator");
            check(problems, refusedValue(() -> Fixtures.fact(1, NO_ID, Classification.BOOT_COMPLETED, 0).build()),
                    "device fact without a boot");
            check(problems, refusedValue(() -> Fixtures.fact(1, id(9), Classification.BOOT_COMPLETED, 0).raw(NO_DIGEST)
                    .build()), "raw digest");
            check(problems, refusedValue(() -> new Selection(INSTALLATION, COMPONENT, 1, ChoiceKind.PLAN, NO_ID,
                    UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.UNCHECKED, NO_ID, NO_ID, NO_ID, TIME)),
                    "chosen plan");
        });
        cases.run("decoder refuses / text that is empty, too long or not printable", problems -> {
            check(problems, refusedValue(() -> Fixtures.plan(1).cohort("", Fixtures.FACTORY_APK, 37).build()), "empty");
            check(problems, refusedValue(() -> Fixtures.plan(1).cohort("x".repeat(256), Fixtures.FACTORY_APK, 37)
                    .build()), "long");
            check(problems, refusedValue(() -> Fixtures.plan(1).cohort("a\nb", Fixtures.FACTORY_APK, 37).build()),
                    "newline");
            check(problems, refusedValue(() -> Fixtures.plan(1).component("android").build()), "one segment");
            check(problems, refusedValue(() -> Fixtures.plan(1).component("com.1x").build()), "segment digit");
            check(problems, refusedValue(() -> Fixtures.plan(1).base(Fixtures.FACTORY_APK, 37, UID, "cé").build()),
                    "non-ASCII context");
            byte[] boot = goldens().get("OBS_BOOT");
            int at = observationBase(obsBoot()) + 59 + 2;
            check(problems, refused(DeploymentRecords::decodeObservation, set(boot, at, 0x7f)), "DEL in text");
            check(problems, refused(DeploymentRecords::decodeObservation, set(boot, at, 0x80)), "high byte in text");
            check(problems, refused(DeploymentRecords::decodeObservation, set(boot, at - 2, 0, 0)), "zero length text");
        });
        cases.run("decoder refuses / plan relations", problems -> {
            check(problems, refusedValue(() -> Fixtures.plan(1).target(Target.FACTORY).build()), "factory with bundle");
            check(problems, refusedValue(() -> planFactory().toBuilder().base(digest(0xa0), 39, UID, CONTEXT).build()),
                    "factory plan with a variant active");
            check(problems, refusedValue(() -> Fixtures.plan(1).bundle(Fixtures.BUNDLE_INPUT, 37).build()),
                    "bundle at the factory version");
            check(problems, refusedValue(() -> Fixtures.plan(1).base(digest(0xa0), 45, UID, CONTEXT).build()),
                    "bundle below the base");
            check(problems, refusedValue(() -> Fixtures.plan(1).base(Fixtures.FACTORY_APK, 38, UID, CONTEXT).build()),
                    "factory bytes at another version");
            check(problems, refusedValue(() -> Fixtures.plan(1).base(digest(0xa0), 36, UID, CONTEXT).build()),
                    "base below the factory");
            check(problems, refusedValue(() -> Fixtures.plan(1).restoration(Fixtures.RESTORATION_INPUT, 40).build()),
                    "restoration not above the bundle");
            check(problems, refusedValue(() -> Fixtures.plan(1).restoration(NO_DIGEST, 41).build()),
                    "a restoration versionCode without its input");
            check(problems, refusedValue(() -> Fixtures.plan(1).restoration(Fixtures.BUNDLE_INPUT, 41).build()),
                    "restoration equal to the bundle");
            check(problems, refusedValue(() -> Fixtures.plan(1).restoration(NO_DIGEST, 0).signing(2)
                    .build()), "two transactions without a restoration");
            check(problems, refusedValue(() -> Fixtures.plan(1).signing(3).build()), "three transactions");
            check(problems, refusedValue(() -> Fixtures.plan(1).restoration(NO_DIGEST, 0)
                    .healthResponse(HealthResponse.RESTORE_AUTOMATICALLY).build()), "restore without a restoration");
            check(problems, refusedValue(() -> Fixtures.plan(1).notice(-1, -1).build()), "negative notice delay");
            check(problems, refusedValue(() -> Fixtures.plan(1).notice(5, 6).build()), "emergency above the delay");
            check(problems, refusedValue(() -> Fixtures.plan(1).notice(10, 5).build()), "emergency outside a restoration");
            check(problems, refusedValue(() -> planTemporary().toBuilder().notice(10, 5).build()),
                    "emergency for a temporary factory plan");
            check(problems, refusedValue(() -> Fixtures.plan(1).healthResponse(HealthResponse.RESTORE_AUTOMATICALLY)
                    .build()), "automatic restoration without its plan");
            check(problems, refusedValue(() -> Fixtures.plan(1).restorationPlan(id(0x105)).build()),
                    "a restoration plan without automatic restoration");
            check(problems, refusedValue(() -> Fixtures.plan(1).healthResponse(HealthResponse.RESTORE_AUTOMATICALLY)
                    .restorationPlan(id(0x101)).build()), "the plan restores itself");
            check(problems, refusedValue(() -> planTemporary().toBuilder().repairs(NO_ID).build()),
                    "a temporary factory plan standing in for nothing");
            check(problems, refusedValue(() -> Fixtures.plan(1).limits(0, 1, 1, 1, 1).build()), "boot limit 0");
            check(problems, refusedValue(() -> Fixtures.plan(1).limits(33, 1, 1, 1, 1).build()), "boot limit 33");
            check(problems, refusedValue(() -> Fixtures.plan(1).limits(1, 1, 17, 1, 1).build()), "request limit 17");
            check(problems, refusedValue(() -> Fixtures.plan(1).limits(1, 0, 1, 1, 1).build()), "reboot time 0");
            check(problems, refusedValue(() -> Fixtures.plan(1).limits(1, 1, 1, -1, 1).build()), "activate window");
            check(problems, refusedValue(() -> Fixtures.plan(1).limits(1, 1, 1, 1, 0).build()), "verification wait");
            check(problems, refusedValue(() -> Fixtures.plan(1).healthWindow(0).build()), "health window");
            check(problems, refusedValue(() -> Fixtures.plan(1).repairs(id(0x101)).build()), "repairs itself");
            check(problems, refusedValue(() -> Fixtures.plan(1).selectionRevision(-1).build()), "negative revision");
            check(problems, refusedValue(() -> Fixtures.plan(1).base(Fixtures.FACTORY_APK, 37, -1, CONTEXT).build()),
                    "negative UID");
        });
        cases.run("decoder refuses / authorization relations", problems -> {
            Plan p = planLateOne();
            check(problems, refusedValue(() -> Fixtures.grant(1, p, Effect.STAGE, 1, TIME)), "inputs outside SIGN");
            check(problems, refusedValue(() -> Fixtures.grant(1, p, Effect.SIGN, 0, TIME)), "SIGN without inputs");
            check(problems, refusedValue(() -> Fixtures.grant(1, p, Effect.SIGN, 4, TIME)), "unknown input");
            check(problems, refusedValue(() -> new Authorization(INSTALLATION, id(1), COMPONENT, p.planId,
                    Effect.STAGE, 0, ActorClass.GRANT_HOLDER, 0, 0, id(3), GrantScope.NONE, id(5), TIME)),
                    "a holder without a scope");
            check(problems, refusedValue(() -> new Authorization(INSTALLATION, id(1), COMPONENT, p.planId,
                    Effect.STAGE, 0, ActorClass.LAB_OPERATOR, DeploymentRecords.NO_USER, -1, NO_ID,
                    GrantScope.ONE_COMPONENT, id(5), TIME)), "an operator with a scope");
            check(problems, refusedValue(() -> new Authorization(INSTALLATION, id(1), COMPONENT, p.planId,
                    Effect.STAGE, 0, ActorClass.GRANT_HOLDER, 0, 0, NO_ID, GrantScope.ALL_COMPONENTS, id(5), TIME)),
                    "holder without a grant");
            check(problems, refusedValue(() -> new Authorization(INSTALLATION, id(1), COMPONENT, p.planId,
                    Effect.STAGE, 0, ActorClass.LAB_OPERATOR, DeploymentRecords.NO_USER, -1, id(3), GrantScope.NONE,
                    id(5), TIME)), "operator with a grant");
            check(problems, refusedValue(() -> new Authorization(INSTALLATION, id(1), COMPONENT, p.planId,
                    Effect.STAGE, 0, ActorClass.LAB_OPERATOR, 0, 0, NO_ID, GrantScope.NONE, id(5), TIME)), "operator as a user");
            check(problems, refusedValue(() -> new Authorization(INSTALLATION, id(1), COMPONENT, p.planId,
                    Effect.STAGE, 0, ActorClass.GRANT_HOLDER, DeploymentRecords.NO_USER, -1, id(3),
                    GrantScope.ALL_COMPONENTS, id(5), TIME)), "holder without a user");
            check(problems, refusedValue(() -> new Authorization(INSTALLATION, id(1), COMPONENT, p.planId,
                    Effect.STAGE, 0, ActorClass.GRANT_HOLDER, 0, -2, id(3), GrantScope.ALL_COMPONENTS, id(5), TIME)),
                    "negative serial");
            check(problems, refusedValue(() -> Fixtures.grant(1, p, Effect.ACTIVATE, 0, 0)), "grant time zero");
        });
        cases.run("decoder refuses / ticket relations", problems -> {
            Plan p = planLateOne();
            check(problems, refusedValue(() -> Fixtures.ticket(1, p).flags(DeploymentRecords.FLAG_UNRESOLVED).build()),
                    "UNRESOLVED outside an intent");
            check(problems, refusedValue(() -> Fixtures.ticket(1, p).flags(8).build()), "unknown flag");
            check(problems, refusedValue(() -> Fixtures.ticket(1, p).window(id(9), 5).build()), "window outside");
            check(problems, refusedValue(() -> ticketWindow().toBuilder().window(NO_ID, 0).build()), "window missing");
            check(problems, refusedValue(() -> Fixtures.ticket(1, p).successor(id(9)).build()), "successor outside");
            check(problems, refusedValue(() -> ticketSuperseded().toBuilder().successor(NO_ID).build()),
                    "SUPERSEDED without a successor");
            check(problems, refusedValue(() -> Fixtures.ticket(1, p).state(State.CANCELLED).build()), "CANCELLED cause");
            check(problems, refusedValue(() -> Fixtures.ticket(1, p).state(State.VOID).cause(Cause.CANCELLED).build()),
                    "VOID cause");
            check(problems, refusedValue(() -> Fixtures.ticket(1, p).state(State.CLOSED_FAILED)
                    .cause(Cause.VOID_TRUST).build()), "CLOSED_FAILED with a cause");
            check(problems, refusedValue(() -> ticketWindow().toBuilder().state(State.DIVERGED).window(NO_ID, 0)
                    .cause(Cause.VOID_BASE).build()), "DIVERGED without other bytes");
            check(problems, refusedValue(() -> ticketWindow().toBuilder().health(List.of(new Health(10, 12,
                    Outcome.UNHEALTHY), new Health(0, 0, Outcome.OBSERVING))).build()), "health order");
            check(problems, refusedValue(() -> ticketWindow().toBuilder().health(List.of(new Health(0, 0,
                    Outcome.HEALTHY), new Health(0, 0, Outcome.HEALTHY))).build()), "health duplicate");
            check(problems, refusedValue(() -> ticketSuperseded().toBuilder().health(List.of(new Health(0, 0,
                    Outcome.OBSERVING))).build()), "OBSERVING after the window");
            check(problems, refusedValue(() -> ticketUnresolved().toBuilder().health(List.of(new Health(0, 0,
                    Outcome.HEALTHY))).build()), "health before APPLIED");
            check(problems, refusedValue(() -> Fixtures.ticket(1, p).attempt(0).build()), "attempt 0");
            check(problems, refusedValue(() -> Fixtures.ticket(1, p).bootCount(1).build()), "boots without a boot");
            check(problems, refusedValue(() -> Fixtures.ticket(1, p).reference(Reference.NONE.withNonce(id(5)))
                    .build()), "nonce without a create");
            check(problems, refusedValue(() -> Fixtures.ticket(1, p).state(State.READY).build()), "READY without create");
            check(problems, refusedValue(() -> new Reference(1, 0, 0, "", 0, NO_ID)), "present session ID zero");
            check(problems, refusedValue(() -> new Reference(0, 5, 0, "", 0, NO_ID)), "absent session ID set");
            check(problems, refusedValue(() -> new Reference(4, 0, 0, "", 0, NO_ID)), "present empty stage dir");
            check(problems, refusedValue(() -> new Reference(32, 0, 0, "", 0, NO_ID)), "unknown presence bit");
        });
        cases.run("decoder refuses / ledger bounds, order and references", problems -> {
            Ticket base = ticketWindow();
            Entry create = base.ledger.get(2), write = base.ledger.get(3), commit = base.ledger.get(4);
            List<Entry> ledger = new ArrayList<>(base.ledger);
            check(problems, refusedValue(() -> with(base, ledger, create)), "a second create");
            List<Entry> created = new ArrayList<>(ledger.subList(0, 3));
            Ticket bound = base.toBuilder().state(State.SESSION_BOUND).window(NO_ID, 0).health(List.of()).build();
            check(problems, refusedValue(() -> with(bound, created, create)), "two creates in a row");
            List<Entry> committed = new ArrayList<>(ledger.subList(0, 5));
            Ticket ready = base.toBuilder().state(State.READY).window(NO_ID, 0).health(List.of()).build();
            check(problems, refusedValue(() -> with(ready, committed, commit)), "two commits in a row");
            check(problems, !refusedValue(() -> with(ready, committed.subList(0, 4), commit)), "the one commit refused");
            check(problems, refusedValue(() -> with(base, ledger, commit)), "a second commit");
            check(problems, refusedValue(() -> with(base, ledger, write)), "a write after commit");
            List<Entry> early = new ArrayList<>(ledger.subList(0, 2));
            Ticket published = Fixtures.ticket(1, planLateOne()).state(State.PUBLISHED).build();
            check(problems, refusedValue(() -> with(published, early, write)), "a write before create");
            List<Entry> noWrite = new ArrayList<>(ledger.subList(0, 3));
            check(problems, refusedValue(() -> with(base, noWrite, commit)), "a commit before write");
            List<Entry> late = new ArrayList<>(ledger.subList(0, 5));
            check(problems, refusedValue(() -> with(base, late, new Entry(Crossing.SIGN, NO_ID, -1, 0, id(0x201),
                    id(0x7099), 0))), "a signing request after commit");
            check(problems, refusedValue(() -> with(base, early, new Entry(Crossing.ABANDON, id(0xb0072), 7, 1, NO_ID,
                    NO_ID, 0))), "an abandon before create");
            List<Entry> beforeCommit = new ArrayList<>(ledger.subList(0, 4));
            check(problems, refusedValue(() -> with(base, beforeCommit, new Entry(Crossing.REBOOT, id(0xb0072), 7, 1,
                    id(0x202), NO_ID, 0))), "a reboot before commit");
            List<Entry> signs = new ArrayList<>();
            for (int i = 0; i < 3; i++) signs.add(new Entry(Crossing.SIGN, NO_ID, -1, 0, id(0x201), id(0x7010 + i), 0));
            check(problems, refusedValue(() -> Fixtures.ticket(1, planLateOne()).state(State.SIGNING).ledger(signs)
                    .build()), "a third signing transaction");
            List<Entry> reboots = new ArrayList<>(ledger.subList(0, 5));
            for (int i = 0; i < 17; i++) reboots.add(new Entry(Crossing.REBOOT, id(0xb0072), 7, i, id(0x202), NO_ID, 0));
            check(problems, refusedValue(() -> base.toBuilder().ledger(reboots).build()), "seventeen reboots");
            check(problems, refusedValue(() -> new Entry(Crossing.CREATE, id(1), 1, 0, NO_ID, id(2), 0)),
                    "create without its STAGE");
            check(problems, refusedValue(() -> new Entry(Crossing.WRITE, id(1), 1, 0, id(3), NO_ID, 0)),
                    "write with a grant");
            check(problems, refusedValue(() -> new Entry(Crossing.SIGN, NO_ID, -1, 0, id(3), NO_ID, 0)),
                    "sign without a request ID");
            check(problems, refusedValue(() -> new Entry(Crossing.COMMIT, id(1), -1, 0, id(3), NO_ID, 0)),
                    "framework crossing without its instance");
            check(problems, refusedValue(() -> new Entry(Crossing.REBOOT, NO_ID, -1, 0, id(3), NO_ID, 0)),
                    "device crossing without its boot");
            check(problems, refusedValue(() -> new Entry(Crossing.HANDOVER, NO_ID, -1, 0, NO_ID, NO_ID, 0)),
                    "handover without its coordinator");
            List<Entry> otherNonce = new ArrayList<>(ledger.subList(0, 2));
            otherNonce.add(new Entry(Crossing.CREATE, id(0xb0072), 7, 5000, id(0x204), id(0x6eff), 0));
            check(problems, refusedValue(() -> base.toBuilder().ledger(otherNonce).build()), "create with another nonce");
            List<Entry> handover = new ArrayList<>(ledger);
            handover.add(new Entry(Crossing.HANDOVER, id(0xb0073), -1, 1, NO_ID, id(0xd1), 0));
            check(problems, refusedValue(() -> base.toBuilder().ledger(handover).build()),
                    "coordinator other than its handover");
            check(problems, refusedValue(() -> new Entry(Crossing.WRITE, id(1), 1, -1, NO_ID, NO_ID, 0)),
                    "negative elapsed");
        });
        cases.run("decoder refuses / observation scope", problems -> {
            check(problems, refusedValue(() -> Fixtures.fact(1, id(9), Classification.BOOT_COMPLETED, 0)
                    .component(COMPONENT).build()), "boot with a component");
            check(problems, refusedValue(() -> Fixtures.fact(1, id(9), Classification.FACTORY_PRESENT, 0).component("")
                    .build()), "factory without a component");
            check(problems, refusedValue(() -> Fixtures.fact(1, id(9), Classification.USER_REMOVED, 0)
                    .user(DeploymentRecords.NO_USER, -1).build()), "user fact without a user");
            check(problems, refusedValue(() -> Fixtures.fact(1, id(9), Classification.CHECKPOINT_COMMITTED, 0)
                    .user(0, 0).build()), "checkpoint with a user");
            check(problems, refusedValue(() -> Fixtures.fact(1, id(9), Classification.BOOT_COMPLETED, 0)
                    .user(DeploymentRecords.NO_USER, 0).build()), "NO_USER with serial 0");
            check(problems, refusedValue(() -> Fixtures.fact(1, id(9), Classification.BOOT_COMPLETED, 0)
                    .route(Route.HOST).build()), "device fact on the host route");
            check(problems, refusedValue(() -> Fixtures.fact(1, id(9), Classification.SESSIONS_FOR_PACKAGE, 0)
                    .number(1).at(-1, 0, 0).build()), "listing without its instance");
            check(problems, refusedValue(() -> Fixtures.fact(1, id(9), Classification.SESSIONS_FOR_PACKAGE, 0)
                    .number(0).build()), "listing count against its classification");
            check(problems, refusedValue(() -> Fixtures.fact(1, id(9), Classification.NONE_FOR_PACKAGE, 0).number(2)
                    .build()), "none for the package with a count");
            check(problems, refusedValue(() -> Fixtures.fact(1, id(9), Classification.BOOT_COMPLETED, 0)
                    .digest(digest(5)).build()), "digest fact of another kind");
            check(problems, refusedValue(() -> Fixtures.fact(1, id(9), Classification.CHECKPOINT_PENDING, 0).version(3)
                    .build()), "version fact of another kind");
            check(problems, refusedValue(() -> Fixtures.fact(1, id(9), Classification.HEALTH_HELD, 0).number(0x80)
                    .build()), "unknown criteria");
            check(problems, refusedValue(() -> Fixtures.fact(1, id(9), Classification.OPEN, 0).build()),
                    "session without its ID");
            check(problems, refusedValue(() -> Fixtures.fact(1, id(9), Classification.REPLY_READY, 0)
                    .reply(id(4), 1, Crossing.WRITE).build()), "commit reply for a write");
            check(problems, refusedValue(() -> Fixtures.fact(1, id(9), Classification.REPLY_SUCCESS, 0)
                    .reply(id(4), 1, Crossing.COMMIT).build()), "commit replied success");
            check(problems, refusedValue(() -> Fixtures.fact(1, id(9), Classification.REPLY_SUCCESS, 0)
                    .reply(id(4), 1, Crossing.SIGN).build()), "a sign reply as REPLY");
            check(problems, refusedValue(() -> Fixtures.fact(1, id(9), Classification.REPLY_SUCCESS, 0)
                    .reply(id(4), 1, Crossing.CREATE).build()), "create reply without its session");
            check(problems, refusedValue(() -> Fixtures.fact(1, id(9), Classification.REPLY_SUCCESS, 0)
                    .reply(id(4), DeploymentRecords.MAX_LEDGER, Crossing.WRITE).build()), "sequence beyond the ledger");
            check(problems, refusedValue(() -> Fixtures.fact(1, NO_ID, Classification.SIGN_COMPLETED, 0).build()),
                    "signer without its request");
            check(problems, refusedValue(() -> Fixtures.fact(1, NO_ID, Classification.SIGN_COMPLETED, 0)
                    .subject(id(4)).at(-1, 5, TIME).build()), "host fact without a boot but with time");
        });
        // A BUNDLE fact's facts: the attempt at +59, the plan at +75, the publication at +91, the
        // bundle APK at +123 and the restoration APK at +155 from the observation's base.
        cases.run("decoder refuses / a bundle fact names its attempt and its plan", problems -> {
            byte[] bundle = goldens().get("OBS_BUNDLE");
            int at = observationBase(obsBundle()) + 59;
            check(problems, refused(DeploymentRecords::decodeObservation, set(bundle, at, new int[16])),
                    "zero attempt");
            check(problems, refused(DeploymentRecords::decodeObservation, set(bundle, at + 16, new int[16])),
                    "zero plan");
            for (Classification c : List.of(Classification.BUNDLE_PUBLISHED, Classification.BUNDLE_ABSENT,
                    Classification.BUNDLE_MISMATCH)) {
                check(problems, refusedValue(() -> Fixtures.fact(1, NO_ID, c, 0).subject(NO_ID).build()),
                        c + " without its attempt");
                check(problems, refusedValue(() -> Fixtures.fact(1, NO_ID, c, 0).plan(NO_ID).build()),
                        c + " without its plan");
                Observation valid = Fixtures.fact(1, NO_ID, c, 0).build();
                check(problems, DeploymentRecords.decodeObservation(DeploymentRecords.encodeObservation(valid))
                        .equals(valid), c + " round trip");
            }
            check(problems, refusedValue(() -> Fixtures.fact(1, NO_ID, Classification.SIGN_COMPLETED, 0)
                    .subject(id(4)).plan(id(0x101)).build()), "a plan on a signer fact");
        });
        cases.run("decoder refuses / bundle fact digests are set exactly when it read the publication", problems -> {
            byte[] bundle = goldens().get("OBS_BUNDLE");
            int base = observationBase(obsBundle());
            int at = base + 59;
            check(problems, refused(DeploymentRecords::decodeObservation, set(bundle, at + 32, new int[32])),
                    "published without the publication's digest");
            check(problems, refused(DeploymentRecords::decodeObservation, set(bundle, at + 64, new int[32])),
                    "published without the bundle APK");
            Observation one = DeploymentRecords.decodeObservation(set(bundle, at + 96, new int[32]));
            check(problems, one.restorationApk.equals(NO_DIGEST) && one.bundleApk.equals(digest(0xa1)),
                    "a publication of one bundle");
            int[] same = new int[32];
            Arrays.fill(same, 0xa1);
            check(problems, refused(DeploymentRecords::decodeObservation, set(bundle, at + 96, same)),
                    "one APK in both roles");
            for (int code : new int[] {2, 3}) {
                check(problems, refused(DeploymentRecords::decodeObservation, set(bundle, base + 58, code)),
                        "classification " + code + " with digests");
                byte[] none = set(set(bundle, base + 58, code), at + 32, new int[96]);
                check(problems, !refused(DeploymentRecords::decodeObservation, none), "classification " + code);
                for (int field = 0; field < 3; field++) {
                    int[] value = new int[32];
                    Arrays.fill(value, 0x5a);
                    check(problems, refused(DeploymentRecords::decodeObservation, set(none, at + 32 + 32 * field,
                            value)), "classification " + code + " with digest " + field);
                }
            }
            check(problems, refusedValue(() -> Fixtures.fact(1, NO_ID, Classification.BUNDLE_ABSENT, 0)
                    .apks(digest(0xa1), NO_DIGEST).build()), "absent with an APK");
            check(problems, refusedValue(() -> Fixtures.fact(1, NO_ID, Classification.BUNDLE_PUBLISHED, 0)
                    .apks(NO_DIGEST, digest(0xa2)).build()), "published without its bundle APK");
            check(problems, refusedValue(() -> Fixtures.fact(1, id(9), Classification.FACTORY_PRESENT, 0)
                    .apks(digest(0xa1), NO_DIGEST).build()), "APKs on another kind");
        });
        cases.run("decoder refuses / selection relations", problems -> {
            check(problems, refusedValue(() -> new Selection(INSTALLATION, COMPONENT, 0, ChoiceKind.FACTORY, id(5),
                    UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.UNCHECKED, NO_ID, NO_ID, NO_ID, TIME)),
                    "factory with a plan");
            check(problems, refusedValue(() -> new Selection(INSTALLATION, COMPONENT, 0, ChoiceKind.FACTORY, NO_ID,
                    UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.CURRENT, NO_ID, NO_ID, NO_ID, TIME)),
                    "checked without a boot");
            check(problems, refusedValue(() -> new Selection(INSTALLATION, COMPONENT, 0, ChoiceKind.FACTORY, NO_ID,
                    UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.UNCHECKED, id(7), NO_ID, NO_ID, TIME)),
                    "unchecked with a boot");
            check(problems, refusedValue(() -> new Selection(INSTALLATION, COMPONENT, 0, ChoiceKind.FACTORY, NO_ID,
                    UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.STALE_BASE, id(7), NO_ID, NO_ID, TIME)),
                    "factory stale");
            check(problems, refusedValue(() -> new Selection(INSTALLATION, COMPONENT, 0, ChoiceKind.FACTORY, NO_ID,
                    UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.DISPLACED, id(7), NO_ID, NO_ID, TIME)),
                    "factory displaced");
            check(problems, refusedValue(() -> new Selection(INSTALLATION, COMPONENT, 0, ChoiceKind.PLAN, id(5),
                    UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.CURRENT, id(7), id(6), NO_ID, TIME)),
                    "repair while current");
            Selection t = selectionTemporary();
            check(problems, refusedValue(() -> new Selection(INSTALLATION, COMPONENT, 1, ChoiceKind.PLAN, id(5),
                    UpdateResponsibility.REBUILD_WINDOW, 0, Realization.CURRENT, id(7), NO_ID, NO_ID, TIME)),
                    "a rebuild window of zero");
            check(problems, refusedValue(() -> new Selection(INSTALLATION, COMPONENT, 1, ChoiceKind.PLAN, id(5),
                    UpdateResponsibility.KEEP_STALE, Fixtures.WINDOW, Realization.CURRENT, id(7), NO_ID, NO_ID, TIME)),
                    "a window while keeping a stale base");
            check(problems, refusedValue(() -> new Selection(t.installation, t.component, t.revision, t.choice, t.planId,
                    t.responsibility, t.rebuildWindowMillis, t.realization, t.checkedBoot, t.repair, NO_ID, t.changedAt)),
                    "TEMPORARY_FACTORY without its plan");
            check(problems, refusedValue(() -> new Selection(t.installation, t.component, t.revision, t.choice, t.planId,
                    t.responsibility, t.rebuildWindowMillis, Realization.CURRENT, t.checkedBoot, NO_ID, t.temporary,
                    t.changedAt)), "a temporary plan outside TEMPORARY_FACTORY");
            check(problems, refusedValue(() -> new Selection(t.installation, t.component, t.revision, t.choice, t.planId,
                    t.responsibility, t.rebuildWindowMillis, t.realization, t.checkedBoot, t.repair, t.planId,
                    t.changedAt)), "the chosen plan as its own temporary plan");
            check(problems, refusedValue(() -> new Selection(INSTALLATION, COMPONENT, 0, ChoiceKind.FACTORY, NO_ID,
                    UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.TEMPORARY_FACTORY, id(7), NO_ID,
                    id(8), TIME)), "the factory copy temporarily replaced");
            check(problems, refusedValue(() -> new Selection(INSTALLATION, COMPONENT, -1, ChoiceKind.FACTORY, NO_ID,
                    UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.UNCHECKED, NO_ID, NO_ID, NO_ID, TIME)),
                    "negative revision");
        });
    }

    private static Ticket with(Ticket base, List<Entry> ledger, Entry extra) {
        List<Entry> next = new ArrayList<>(ledger);
        next.add(extra);
        return base.toBuilder().ledger(next).build();
    }

    private static void decisionCases() throws Exception {
        cases.run("decision 8 / one or two signing transactions fit the layout", problems -> {
            Plan one = planLateOne(), two = planEarlyTwo();
            check(problems, one.signing == 1 && two.signing == 2, "signing counts");
            Authorization both = authSign();
            Authorization variant = Fixtures.grant(5, two, Effect.SIGN, DeploymentRecords.INPUT_VARIANT, TIME);
            Authorization restoration = Fixtures.grant(6, two, Effect.SIGN, DeploymentRecords.INPUT_RESTORATION, TIME);
            for (Authorization a : List.of(both, variant, restoration)) {
                check(problems, DeploymentRecords.decodeAuthorization(DeploymentRecords.encodeAuthorization(a))
                        .equals(a), "round trip " + a.inputs);
            }
            Ticket twice = Fixtures.ticket(9, two).state(State.SIGNED)
                    .append(new Entry(Crossing.SIGN, NO_ID, -1, 0, variant.authorizationId, id(0x7101), TIME))
                    .append(new Entry(Crossing.SIGN, NO_ID, -1, 0, restoration.authorizationId, id(0x7102), TIME))
                    .build();
            check(problems, DeploymentRecords.decodeTicket(DeploymentRecords.encodeTicket(twice)).equals(twice),
                    "two transactions in one ledger");
            check(problems, DeploymentRecords.encodePlan(one).length == DeploymentRecords.encodePlan(
                    one.toBuilder().signing(2).build()).length, "the layout does not depend on the count");
            check(problems, refusedValue(() -> Fixtures.plan(1).restoration(NO_DIGEST, 0).signing(2)
                    .build()), "two without a restoration");
        });
        cases.run("decision 2 / both commit modes fit the layout", problems -> {
            for (CommitMode mode : CommitMode.values()) {
                Plan p = Fixtures.plan(1).commitMode(mode).build();
                check(problems, DeploymentRecords.decodePlan(DeploymentRecords.encodePlan(p)).commitMode == mode,
                        mode.toString());
            }
            for (UpdateResponsibility r : UpdateResponsibility.values()) {
                Selection s = selectionStale();
                long window = r == UpdateResponsibility.REBUILD_WINDOW ? Fixtures.WINDOW : 0;
                Selection t = new Selection(s.installation, s.component, s.revision, s.choice, s.planId, r, window,
                        s.realization, s.checkedBoot, s.repair, s.temporary, s.changedAt);
                check(problems, DeploymentRecords.decodeSelection(DeploymentRecords.encodeSelection(t)).equals(t),
                        "decision 6 " + r);
            }
            Plan noticed = planEarlyTwo();
            Plan decoded = DeploymentRecords.decodePlan(DeploymentRecords.encodePlan(noticed));
            check(problems, decoded.noticeDelayMillis == 300_000 && decoded.emergencyNoticeMillis == 60_000,
                    "decision 7 delays");
            for (HealthResponse h : HealthResponse.values()) {
                Plan p = Fixtures.plan(1).healthResponse(h)
                        .restorationPlan(h == HealthResponse.RESTORE_AUTOMATICALLY ? id(0x105) : NO_ID).build();
                check(problems, DeploymentRecords.decodePlan(DeploymentRecords.encodePlan(p)).healthResponse == h,
                        "decision 3 " + h);
            }
        });
        cases.run("observation / no user is USER_NULL with serial -1", problems -> {
            Observation boot = obsBoot();
            check(problems, boot.user == -10000 && boot.serial == -1, "boot observation user");
            check(problems, DeploymentRecords.NO_USER == -10000 && DeploymentRecords.NO_SERIAL == -1, "constants");
            Observation health = obsHealth();
            check(problems, health.user == 10 && health.serial == 12, "user observation");
        });
        cases.run("size / the largest ticket fits MAX_BYTES", problems -> {
            byte[] largest = goldens().get("TICKET_MAXIMUM");
            check(problems, largest != null && largest.length <= DeploymentRecords.MAX_BYTES, "largest ticket");
            check(problems, DeploymentRecords.MAX_LEDGER == 60, "ledger bound " + DeploymentRecords.MAX_LEDGER);
            Ticket max = ticketMaximum();
            check(problems, max.ledger.size() == DeploymentRecords.MAX_LEDGER && max.health.size() == 64,
                    "every bound reached");
        });
    }

    // ------------------------------------------------------------------ mutation

    private static byte[] mutate(byte[] bytes, Random random) {
        int changes = 1 + random.nextInt(3);
        for (int i = 0; i < changes; i++) {
            int at = random.nextInt(bytes.length);
            switch (random.nextInt(4)) {
                case 0:
                    bytes[at] ^= (byte) (1 << random.nextInt(8));
                    break;
                case 1:
                    bytes[at] = (byte) random.nextInt(256);
                    break;
                case 2: {
                    byte[] longer = new byte[bytes.length + 1];
                    System.arraycopy(bytes, 0, longer, 0, at);
                    longer[at] = (byte) random.nextInt(256);
                    System.arraycopy(bytes, at, longer, at + 1, bytes.length - at);
                    bytes = longer;
                    break;
                }
                default: {
                    if (bytes.length < 2) break;
                    byte[] shorter = new byte[bytes.length - 1];
                    System.arraycopy(bytes, 0, shorter, 0, at);
                    System.arraycopy(bytes, at + 1, shorter, at, bytes.length - at - 1);
                    bytes = shorter;
                    break;
                }
            }
        }
        return bytes;
    }

    // Random changes of each golden body, resealed. Each result is refused or is exactly the one
    // encoding of the value it decodes to. A fixed seed repeats the inputs.
    private static void mutationCases() throws Exception {
        Map<String, byte[]> goldens = goldens();
        for (Kind kind : Kind.values()) {
            String label = kind.toString().toLowerCase();
            cases.run("mutation / resealed " + label + " mutations are refused or canonical", problems -> {
                List<byte[]> bodies = new ArrayList<>();
                for (String name : GOLDEN_ORDER) {
                    if (kindOf(name) == kind && !name.equals("TICKET_MAXIMUM")) bodies.add(body(goldens.get(name)));
                }
                Random random = new Random(20261009L + kind.code);
                int accepted = 0, refused = 0;
                Function<byte[], ?> decode = decoder(kind);
                Function<Object, byte[]> encode = encoder(kind);
                for (int round = 0; round < 20_000; round++) {
                    byte[] candidate = frame(kind.code, 1, mutate(bodies.get(round % bodies.size()).clone(), random));
                    try {
                        Object value = decode.apply(candidate);
                        if (!Arrays.equals(encode.apply(value), candidate)) {
                            problems.add("second encoding in round " + round);
                        }
                        ++accepted;
                    } catch (IllegalArgumentException expected) {
                        ++refused;
                    }
                }
                check(problems, accepted > 100 && refused > 1_000, accepted + " accepted, " + refused + " refused");
                System.out.println("Resealed " + label + " mutations: " + accepted + " canonical, " + refused
                        + " refused");
            });
        }
    }

    // ------------------------------------------------------------------ prefix

    private static void prefixCases() throws Exception {
        Map<String, byte[]> goldens = goldens();
        cases.run("prefix / later versions give what each record concerns", problems -> {
            for (String name : List.of("PLAN_EARLY_TWO", "AUTH_EMERGENCY", "TICKET_WINDOW", "OBS_HEALTH",
                    "SELECTION_STALE")) {
                for (int version : new int[] {2, 3, 0xffff}) {
                    byte[] later = relabel(goldens.get(name), version);
                    Prefix p = DeploymentRecords.decodePrefix(later);
                    check(problems, p.kind == kindOf(name) && p.version == version
                            && p.installation.equals(INSTALLATION) && p.component.equals(COMPONENT),
                            name + " " + version + " " + p);
                    check(problems, refused(decoder(kindOf(name)), later), name + " decoded in full at " + version);
                }
            }
            Prefix ticket = DeploymentRecords.decodePrefix(relabel(goldens.get("TICKET_WINDOW"), 2));
            check(problems, ticket.recordId.equals(id(0x403)) && ticket.planId.equals(id(0x101)), "ticket IDs");
            Prefix boot = DeploymentRecords.decodePrefix(relabel(goldens.get("OBS_BOOT"), 2));
            check(problems, boot.component.isEmpty() && boot.recordId.equals(id(0x501)), "device observation");
            Prefix sel = DeploymentRecords.decodePrefix(relabel(goldens.get("SELECTION_STALE"), 2));
            check(problems, sel.recordId.equals(NO_ID) && sel.planId.equals(NO_ID), "selection has no record ID");
        });
        cases.run("prefix / version 1 and damaged frames give no prefix", problems -> {
            for (String name : GOLDEN_ORDER) {
                byte[] r = goldens.get(name);
                check(problems, refused(DeploymentRecords::decodePrefix, r), name + " version 1");
                byte[] damaged = relabel(r, 2);
                damaged[damaged.length - 1] ^= 1;
                check(problems, refused(DeploymentRecords::decodePrefix, damaged), name + " damaged");
                check(problems, refused(DeploymentRecords::decodePrefix, set(relabel(r, 2), 4, 9)), name + " type 9");
            }
        });
        cases.run("prefix / nothing after the prefix is read", problems -> {
            byte[] ticket = goldens.get("TICKET_WINDOW");
            int prefixEnd = ticketBase(ticketWindow());
            byte[] cut = frame(3, 7, Arrays.copyOfRange(ticket, 12, prefixEnd));
            check(problems, DeploymentRecords.decodePrefix(cut).recordId.equals(id(0x403)), "prefix alone");
            byte[] noisy = Arrays.copyOf(Arrays.copyOfRange(ticket, 12, prefixEnd), prefixEnd - 12 + 40);
            Arrays.fill(noisy, prefixEnd - 12, noisy.length, (byte) 0xee);
            check(problems, DeploymentRecords.decodePrefix(frame(3, 7, noisy)).planId.equals(id(0x101)),
                    "a changed remainder");
        });
        cases.run("prefix / each frozen rule refuses", problems -> {
            byte[] ticket = relabel(goldens.get("TICKET_WINDOW"), 2);
            check(problems, refused(DeploymentRecords::decodePrefix, set(ticket, 12, new int[16])), "zero installation");
            check(problems, refused(DeploymentRecords::decodePrefix, set(ticket, 28, new int[16])), "zero ticket ID");
            check(problems, refused(DeploymentRecords::decodePrefix, set(ticket, 46, 0x31)), "component grammar");
            int plan = 12 + 32 + 2 + COMPONENT.length();
            check(problems, refused(DeploymentRecords::decodePrefix, set(ticket, plan, new int[16])), "zero plan");
            check(problems, refused(DeploymentRecords::decodePrefix, set(ticket, plan + 16, 0, 0, 0, 0)), "attempt 0");
            byte[] obs = relabel(goldens.get("OBS_HEALTH"), 2);
            int user = observationBase(obsHealth()) - 12;
            check(problems, refused(DeploymentRecords::decodePrefix, set(obs, user, 0xf0, 0xd8, 0xff, 0xff)),
                    "NO_USER with a serial");
            byte[] sel = relabel(goldens.get("SELECTION_STALE"), 2);
            check(problems, refused(DeploymentRecords::decodePrefix, set(sel, selectionBase(selectionStale()) - 1,
                    0x80)), "negative revision");
        });
    }

    private static void surfaceCases() {
        cases.run("surface / values are closed and print no references", problems -> {
            for (Class<?> type : DeploymentRecords.class.getDeclaredClasses()) {
                if (type.isEnum() || type.isInterface() || !Modifier.isPublic(type.getModifiers())) continue;
                check(problems, Modifier.isFinal(type.getModifiers()), "open class " + type.getSimpleName());
                for (Field field : type.getDeclaredFields()) {
                    int m = field.getModifiers();
                    if (!Modifier.isStatic(m) && !type.getSimpleName().equals("Builder")) {
                        check(problems, Modifier.isFinal(m), "mutable field " + type.getSimpleName() + "." + field.getName());
                    }
                }
            }
            StringBuilder text = new StringBuilder();
            text.append(planEarlyTwo()).append(authSign()).append(ticketWindow()).append(obsReplyDevice())
                    .append(selectionStale()).append(ticketWindow().reference);
            for (String secret : List.of(INSTALLATION, id(0x101), id(0x6e03), BUNDLE_APK, Fixtures.SIGNER,
                    Fixtures.TRUST, FINGERPRINT, "session_1234567", id(0x9a))) {
                check(problems, !text.toString().contains(secret), "printed " + secret.substring(0, 8));
            }
            check(problems, text.toString().contains("HEALTH_WINDOW") && text.toString().contains("GRANT_HOLDER"),
                    "states and classes print");
            check(problems, ticketWindow().health.getClass().getName().contains("Unmodifiable"), "health list mutable");
        });
    }

    public static void main(String[] args) throws Exception {
        Cases.requireAssertions(DeploymentRecordsTest.class);
        if (args.length != 1) throw new IllegalArgumentException("a fresh golden directory is required");
        Path out = Path.of(args[0]);
        if (!Files.isDirectory(out, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("golden directory");
        try (var listing = Files.list(out)) {
            if (listing.findAny().isPresent()) throw new IllegalArgumentException("golden directory not fresh");
        }
        goldenCases(out);
        frameCases();
        strictCases();
        relationCases();
        decisionCases();
        mutationCases();
        prefixCases();
        surfaceCases();
        cases.finish("Deployment record codec checks passed");
    }
}
