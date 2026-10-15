// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.notice.join;

import dev.andrix.server.deployment.DeploymentRecords;
import dev.andrix.server.deployment.DeploymentRecords.ActorClass;
import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.ChoiceKind;
import dev.andrix.server.deployment.DeploymentRecords.Classification;
import dev.andrix.server.deployment.DeploymentRecords.CommitMode;
import dev.andrix.server.deployment.DeploymentRecords.CoordinatorClass;
import dev.andrix.server.deployment.DeploymentRecords.Crossing;
import dev.andrix.server.deployment.DeploymentRecords.Effect;
import dev.andrix.server.deployment.DeploymentRecords.Entry;
import dev.andrix.server.deployment.DeploymentRecords.GrantScope;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Realization;
import dev.andrix.server.deployment.DeploymentRecords.Reference;
import dev.andrix.server.deployment.DeploymentRecords.Route;
import dev.andrix.server.deployment.DeploymentRecords.Selection;
import dev.andrix.server.deployment.DeploymentRecords.State;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import dev.andrix.server.deployment.DeploymentRecords.UpdateResponsibility;
import dev.andrix.server.deployment.Reconciler;
import dev.andrix.server.deployment.Reconciler.Clock;
import dev.andrix.server.deployment.Reconciler.Context;
import dev.andrix.server.deployment.Reconciler.Step;
import dev.andrix.server.deployment.Reconciler.View;
import java.util.ArrayList;
import java.util.List;

/**
 * The fixture's receipts against the accepted Java reconciler, through its public API only: the
 * notice delay boundary from the first proven delivery, what a substituted or stepped event time
 * would do instead, the last required user's first receipt, the per boot notice budget and the
 * ledger's notice bound, and receipts of a prior boot, another serial or another entry. The plan
 * carries the lab's starting values: 2 minute ordinary and emergency notice delays, request limit
 * 3, late commit, report and wait. Receipts are RECEIPT_FULL_SCREEN facts whose elapsed time is
 * the proven delivery a RECEIPT_EVENT carries. Host evidence only.
 */
public final class ReceiptReconcilerTests {
    static final String INSTALLATION = "00112233445566778899aabbccddeeff";
    static final String COMPONENT = "com.android.systemui";
    static final String FINGERPRINT = "andrix/cf/cf:17/BP4A.260813.001/2026081300:userdebug/test-keys";
    static final String CONTEXT = "u:r:platform_app:s0:c512,c768";
    static final int UID = 10112;
    static final long TIME = 1_791_504_000_000L;
    static final long DAY = 24L * 3600 * 1000;
    static final long DELAY = 120_000;
    static final String FACTORY_APK = digest(0xf0);
    static final String BUNDLE_INPUT = digest(0xb1);
    static final String RESTORATION_INPUT = digest(0xb2);
    static final String BUNDLE_APK = digest(0xa1);
    static final String RESTORATION_APK = digest(0xa2);
    static final String B1 = id(0xb1), B2 = id(0xb2);
    static final String NONCE = id(0x6e6e);
    static final Reference SHELL_REF = new Reference(31, 4242, TIME + 5, "/data/app-staging/session_4242", 2000,
            NONCE);
    static final String SIGN = id(0x2a3), STAGE = id(0x2a1), ACTIVATE = id(0x2a2);

    static String id(long n) {
        return String.format("%032x", n);
    }

    static String digest(int b) {
        return String.format("%02x", b).repeat(32);
    }

    /** A READY_AGAIN ticket in boot B2 after its activation reboot in B1, with its facts. */
    static final class Bed {
        final Plan plan;
        Ticket ticket;
        final List<Authorization> auths = new ArrayList<>();
        final List<Observation> obs = new ArrayList<>();
        long instance = 1, elapsed = 60_000, wall = TIME + 60_000;
        private long n;
        private long ids;

        Bed() {
            plan = new Plan.Builder().installation(INSTALLATION).planId(id(0x101)).component(COMPONENT)
                    .bundle(BUNDLE_INPUT, 40).signer(digest(0x51)).restoration(RESTORATION_INPUT, 41).signing(1)
                    .cohort(FINGERPRINT, FACTORY_APK, 37).base(FACTORY_APK, 37, UID, CONTEXT).selectionRevision(0)
                    .trustPolicy(digest(0x7a)).commitMode(CommitMode.LATE).healthWindow(900_000)
                    .notice(DELAY, DELAY).limits(4, 300_000, 3, DAY, 600_000).createdAt(TIME).build();
            for (Object[] g : new Object[][] {{SIGN, Effect.SIGN, 3}, {STAGE, Effect.STAGE, 0},
                {ACTIVATE, Effect.ACTIVATE, 0}}) {
                auths.add(new Authorization(INSTALLATION, (String) g[0], COMPONENT, plan.planId, (Effect) g[1],
                        (Integer) g[2], ActorClass.LAB_OPERATOR, DeploymentRecords.NO_USER,
                        DeploymentRecords.NO_SERIAL, DeploymentRecords.NO_ID, GrantScope.NONE, id(0x3a0),
                        TIME - 60_000));
            }
            Ticket.Builder b = new Ticket.Builder().installation(INSTALLATION).ticketId(id(0x401)).component(COMPONENT)
                    .planId(plan.planId).attempt(1).coordinator(CoordinatorClass.HOST, id(0xc0))
                    .state(State.READY_AGAIN).boot(B2).bootCount(1).reference(SHELL_REF);
            b.append(new Entry(Crossing.SIGN, DeploymentRecords.NO_ID, -1, 0, SIGN, id(0x7e57), TIME));
            b.append(new Entry(Crossing.PUBLISH, DeploymentRecords.NO_ID, -1, 0, DeploymentRecords.NO_ID, id(0x9b1),
                    TIME));
            b.append(new Entry(Crossing.CREATE, B1, 1, 1100, STAGE, NONCE, TIME));
            b.append(new Entry(Crossing.WRITE, B1, 1, 1200, DeploymentRecords.NO_ID, DeploymentRecords.NO_ID, TIME));
            b.append(new Entry(Crossing.COMMIT, B1, 1, 1300, ACTIVATE, DeploymentRecords.NO_ID, TIME));
            ticket = b.build();
            facts();
        }

        Observation.Builder fact(Classification c) {
            Observation.Builder b = new Observation.Builder().installation(INSTALLATION).observationId(id(0x500 + ++n))
                    .boot(B2).route(Route.SHELL).raw(digest(0x99)).classification(c);
            boolean device = c == Classification.BOOT_COMPLETED || c == Classification.CHECKPOINT_COMMITTED
                    || c == Classification.RUNNING_UNLOCKED;
            return b.component(device ? "" : COMPONENT).at(device ? -1 : instance, elapsed, wall);
        }

        /** This boot's facts: completed, the checkpoint committed, the system user, the cohort, the
         * factory copy active, the ready session and the plan's publication read back. */
        void facts() {
            obs.add(fact(Classification.BOOT_COMPLETED).text(FINGERPRINT).build());
            obs.add(fact(Classification.CHECKPOINT_COMMITTED).build());
            user(0, 0);
            obs.add(fact(Classification.FACTORY_PRESENT).digest(FACTORY_APK).version(37).build());
            obs.add(fact(Classification.FACTORY_COPY).digest(FACTORY_APK).version(37).number(UID).text(CONTEXT)
                    .build());
            obs.add(fact(Classification.SESSIONS_FOR_PACKAGE).number(1).build());
            obs.add(fact(Classification.SESSION_READY).reference(SHELL_REF).build());
            obs.add(new Observation.Builder().installation(INSTALLATION).observationId(id(0x500 + ++n))
                    .boot(DeploymentRecords.NO_ID).route(Route.HOST).raw(digest(0x99))
                    .classification(Classification.BUNDLE_PUBLISHED).component(COMPONENT).at(-1, 0, TIME)
                    .subject(id(0x9b0)).plan(plan.planId).digest(digest(0xd7)).apks(BUNDLE_APK, RESTORATION_APK)
                    .build());
        }

        Bed user(int user, long serial) {
            obs.add(fact(Classification.RUNNING_UNLOCKED).user(user, serial).build());
            return this;
        }

        void reply(int index) {
            obs.add(fact(Classification.REPLY_SUCCESS).reply(ticket.ticketId, index, Crossing.NOTICE)
                    .reference(Reference.NONE).build());
        }

        /** A receipt of a ledger entry with its proven delivery time, read in this framework. */
        void receipt(int user, long serial, int index, long proven) {
            obs.add(fact(Classification.RECEIPT_FULL_SCREEN).user(user, serial).receipt(ticket.ticketId, index)
                    .at(instance, proven, TIME + proven).build());
        }

        /** Moves the clock and reads this boot's facts again, with the given running users. */
        void at(long when, int... users) {
            elapsed = when;
            wall = TIME + when;
            facts();
            for (int i = 0; i + 1 < users.length; i += 2) user(users[i], users[i + 1]);
        }

        Step step() {
            Selection selection = new Selection(INSTALLATION, COMPONENT, 0, ChoiceKind.FACTORY,
                    DeploymentRecords.NO_ID, UpdateResponsibility.REBUILD_WINDOW, 14 * DAY, Realization.UNCHECKED,
                    DeploymentRecords.NO_ID, DeploymentRecords.NO_ID, DeploymentRecords.NO_ID, TIME);
            List<Ticket> tickets = new ArrayList<>();
            tickets.add(ticket);
            Context context = new Context(plan, ticket, auths, tickets, selection, digest(0x7a), false,
                    new ArrayList<>(), null, View.of(B2, COMPONENT, obs), new Clock(B2, instance, elapsed, wall),
                    false, () -> id(0x1d0000 + (++ids)));
            Step s = Reconciler.step(context);
            ticket = s.ticket;
            return s;
        }

        int notices() {
            int count = 0;
            for (Entry e : ticket.ledger) if (e.crossing == Crossing.NOTICE && e.boot.equals(B2)) count++;
            return count;
        }
    }

    static boolean noticed(Step s) {
        return s.issue != null && s.issue.crossing == Crossing.NOTICE;
    }

    /** A bed whose first step issued the NOTICE to user 10, serial 5. Returns its ledger index. */
    static int issued(Bed bed, List<String> problems) {
        bed.user(10, 5);
        Step first = bed.step();
        check(problems, noticed(first) && first.ticket.state == State.READY_AGAIN, "the notice " + first);
        int index = bed.ticket.ledger.indexOf(first.issue);
        bed.reply(index);
        return index;
    }

    static void check(List<String> problems, boolean ok, String what) {
        if (!ok) problems.add(what);
    }

    interface Body {
        void run(List<String> problems);
    }

    static int failed;

    static void run(String name, Body body) {
        List<String> problems = new ArrayList<>();
        try {
            body.run(problems);
        } catch (RuntimeException | AssertionError e) {
            problems.add("threw " + e);
        }
        if (problems.isEmpty()) {
            System.out.println("PASS " + name);
        } else {
            failed++;
            System.out.println("FAIL " + name + ": " + String.join("; ", problems));
        }
    }

    public static void main(String[] args) {
        run("delay / the reboot waits the declared delay from the proven delivery, to the millisecond", p -> {
            Bed bed = new Bed();
            int index = issued(bed, p);
            long proven = 61_500;
            bed.receipt(10, 5, index, proven);
            bed.at(proven + DELAY - 1, 10, 5);
            Step early = bed.step();
            check(p, early.issue == null && early.ticket.state == State.READY_AGAIN, "one millisecond early " + early);
            bed.at(proven + DELAY, 10, 5);
            check(p, bed.step().ticket.state == State.REBOOT_INTENT, "at the delay");
        });
        run("delay / a read time substituted for the delivery would wait longer, so only the event counts", p -> {
            Bed bed = new Bed();
            int index = issued(bed, p);
            long proven = 61_500;
            long read = proven + 40_000;
            bed.receipt(10, 5, index, read);
            bed.at(proven + DELAY, 10, 5);
            Step s = bed.step();
            check(p, s.issue == null && s.ticket.state == State.READY_AGAIN, "the read time would still wait " + s);
            bed.at(read + DELAY, 10, 5);
            check(p, bed.step().ticket.state == State.REBOOT_INTENT, "the read time's own boundary");
        });
        run("delay / an event stepped before its notice entry would shorten the wait, which the broker refuses", p -> {
            Bed bed = new Bed();
            int index = issued(bed, p);
            long entry = bed.ticket.ledger.get(index).elapsed;
            bed.receipt(10, 5, index, entry - 1_000);
            bed.at(entry + DELAY - 1_000, 10, 5);
            check(p, bed.step().ticket.state == State.REBOOT_INTENT,
                    "the reconciler takes the receipt's elapsed as given: the event check is the broker's");
        });
        run("delay / the last required user's first receipt starts the delay; a later receipt never moves it", p -> {
            Bed bed = new Bed();
            bed.user(11, 7);
            int index = issued(bed, p);
            bed.receipt(10, 5, index, 61_000);
            bed.receipt(11, 7, index, 70_000);
            bed.receipt(10, 5, index, 75_000);
            bed.at(70_000 + DELAY - 1, 10, 5, 11, 7);
            check(p, bed.step().issue == null && bed.ticket.state == State.READY_AGAIN, "before the last first");
            bed.at(70_000 + DELAY, 10, 5, 11, 7);
            check(p, bed.step().ticket.state == State.REBOOT_INTENT, "from the last first receipt");
        });
        run("budget / without receipts, request limit plus one notices in a boot, then the session is abandoned",
                p -> {
            Bed bed = new Bed();
            bed.user(10, 5);
            long when = bed.elapsed;
            int given = 0;
            Step last = null;
            for (int round = 0; round < 12 && (last == null || last.ticket.state == State.READY_AGAIN); round++) {
                last = bed.step();
                if (noticed(last)) {
                    given++;
                    bed.reply(bed.ticket.ledger.indexOf(last.issue));
                }
                when += DELAY;
                bed.at(when, 10, 5);
            }
            check(p, given == bed.plan.requestLimit + 1 && bed.notices() == 4, "notices " + given);
            check(p, last != null && last.ticket.state == State.ABANDON_INTENT, "abandoned at the limit " + last);
        });
        run("budget / the ledger's notice bound holds across boots", p -> {
            Bed bed = new Bed();
            Ticket.Builder b = bed.ticket.toBuilder();
            for (int i = 0; i < 17; i++) b.append(new Entry(Crossing.NOTICE, B1, 1, 2_000 + i, ACTIVATE,
                    DeploymentRecords.NO_ID, TIME));
            bed.ticket = b.build();
            bed.user(10, 5);
            Step s = bed.step();
            check(p, !noticed(s) && s.ticket.state == State.ABANDON_INTENT, "the seventeenth earlier notice " + s);
        });
        run("scope / a prior boot's notice and receipt, another serial and another entry give nothing", p -> {
            Bed prior = new Bed();
            Ticket.Builder b = prior.ticket.toBuilder();
            b.append(new Entry(Crossing.NOTICE, B1, 1, 1_400, ACTIVATE, DeploymentRecords.NO_ID, TIME));
            prior.ticket = b.build();
            int old = prior.ticket.ledger.size() - 1;
            prior.obs.add(prior.fact(Classification.RECEIPT_FULL_SCREEN).boot(B1).user(10, 5)
                    .receipt(prior.ticket.ticketId, old).at(1, 1_500, TIME + 1_500).build());
            prior.user(10, 5);
            check(p, noticed(prior.step()), "a new notice in this boot");
            Bed serial = new Bed();
            int index = issued(serial, p);
            serial.receipt(10, 6, index, 61_500);
            serial.at(61_500 + DELAY, 10, 5);
            Step s = serial.step();
            check(p, s.ticket.state == State.READY_AGAIN && !(s.ticket.state == State.REBOOT_INTENT),
                    "another serial's receipt " + s);
            Bed entry = new Bed();
            issued(entry, p);
            entry.receipt(10, 5, 4, 61_500);
            entry.at(61_500 + DELAY, 10, 5);
            Step e = entry.step();
            check(p, e.ticket.state == State.READY_AGAIN, "a receipt of the COMMIT entry " + e);
        });
        System.out.println("RESULT failed=" + failed);
        System.exit(failed == 0 ? 0 : 1);
    }
}
