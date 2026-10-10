// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import static dev.andrix.server.deployment.Cases.check;

import dev.andrix.server.deployment.AndroidFacade.Apk;
import dev.andrix.server.deployment.AndroidFacade.Fault;
import dev.andrix.server.deployment.DeploymentRecords.Cause;
import dev.andrix.server.deployment.DeploymentRecords.ChoiceKind;
import dev.andrix.server.deployment.DeploymentRecords.Classification;
import dev.andrix.server.deployment.DeploymentRecords.CommitMode;
import dev.andrix.server.deployment.DeploymentRecords.Crossing;
import dev.andrix.server.deployment.DeploymentRecords.Effect;
import dev.andrix.server.deployment.DeploymentRecords.Entry;
import dev.andrix.server.deployment.DeploymentRecords.Health;
import dev.andrix.server.deployment.DeploymentRecords.HealthResponse;
import dev.andrix.server.deployment.DeploymentRecords.Outcome;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Realization;
import dev.andrix.server.deployment.DeploymentRecords.Route;
import dev.andrix.server.deployment.DeploymentRecords.Selection;
import dev.andrix.server.deployment.DeploymentRecords.State;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * End to end transactions against the Android facade on both readback routes: each row of the
 * plan's recovery table, fault sweeps at every crossing, world events at every round, and the
 * invariants that every run keeps. The coordinator never replays, every entry is synced before
 * its crossing, nothing irreversible happens before the checkpoint commit, no ticket closes with
 * its session live, an applied change is reported as applied, and the choice moves only with an
 * APPLIED ticket. Host JVM only: the facade models the plan's description of Android.
 */
public final class TransactionTest {
    private static final Cases cases = new Cases();
    private static Path root;
    private static int worlds;
    private static int runs, calls, violations;

    static World world(Route route, long seed) throws Exception {
        World w = new World(root.resolve("world-" + (++worlds)), seed, route);
        return w;
    }

    private static void account(World w, List<String> problems) {
        ++runs;
        calls += w.android.calls.size();
        violations += w.violations.size();
        if (!w.violations.isEmpty()) problems.add("violations " + w.violations);
    }

    static Plan plan(World w, Plan.Builder b) {
        Plan plan = w.add(b.build());
        w.grantAll(plan, 16L * w.store.plans().values.size() + 1); // Each plan's grants get their own IDs.
        return plan;
    }

    // Drives a ticket to an end: escalation, then storage freeing, then the owner's cancellation.
    static Ticket finish(World w, String id) {
        Ticket t = w.run(id, 150, true);
        if (t.state.terminal()) return t;
        w.android.advance(9L * 3600 * 1000);
        w.android.storageFreeing();
        w.android.flush();
        w.android.frameworkRestart();
        t = w.run(id, 150, true);
        if (t.state.terminal()) return t;
        w.coordinator.cancel(id);
        return w.run(id, 150, true);
    }

    // The end state agrees with the facade: an applied change is reported as applied, and a
    // closed ticket leaves no live session. The choice names the plan exactly when the ticket
    // reached APPLIED with no recorded cause: each run's plan expects the selection's first
    // revision, and nothing else changes the choice.
    static void consistent(World w, Plan plan, Ticket t, List<String> problems) {
        check(problems, t.state.terminal(), "not closed: " + t);
        boolean bundle = w.android.active().digest.equals(Fixtures.signed(plan.bundleInput));
        boolean sameBase = w.android.fingerprint.equals(Fixtures.FINGERPRINT);
        if (sameBase) {
            check(problems, bundle == (t.state == State.CLOSED_APPLIED || t.state == State.SUPERSEDED),
                    "bundle active " + bundle + " but " + t);
        }
        check(problems, !w.sessionLives(t), "closed with its session live: " + t);
        Selection s = w.selection();
        boolean moved = s.choice == ChoiceKind.PLAN && s.planId.equals(plan.planId)
                && s.revision == plan.selectionRevision + 1;
        boolean owed = plan.target != DeploymentRecords.Target.TEMPORARY_FACTORY
                && w.appliedWithoutCause(t.ticketId);
        check(problems, moved == owed, "choice " + s + (owed ? " owed a move by " : " owed nothing by ") + t);
        if (owed && sameBase && bundle) {
            check(problems, s.realization == Realization.CURRENT, "realization " + s + " for " + t);
        }
    }

    // ------------------------------------------------------------------ flows

    private static void flowCases() {
        for (Route route : List.of(Route.SHELL, Route.DEVICE)) {
            for (CommitMode mode : CommitMode.values()) {
                for (int signing : new int[] {1, 2}) {
                    String name = "flow / " + route.toString().toLowerCase() + " route, " + mode.toString().toLowerCase()
                            + " commit, " + (signing == 1 ? "one signing transaction" : "two signing transactions");
                    cases.run(name, problems -> {
                        World w = world(route, 7 + signing);
                        Plan plan = plan(w, Fixtures.plan(1).commitMode(mode).signing(signing));
                        String id = w.open(plan, 1);
                        Ticket t = w.run(id, 80, false, mode == CommitMode.EARLY ? State.READY : null);
                        if (mode == CommitMode.EARLY && t.state == State.READY) {
                            check(problems, w.calls(id, Crossing.REBOOT) == 0, "early commit requested a reboot");
                            w.android.kernelBoot(true); // Any reboot applies the change.
                            t = w.run(id, 80, false);
                        }
                        check(problems, t.state == State.CLOSED_APPLIED, "ended " + t);
                        check(problems, t.health.equals(List.of(new Health(0, 0, Outcome.HEALTHY))), "health " + t.health);
                        check(problems, w.android.active().digest.equals(Fixtures.BUNDLE_APK), "bundle not active");
                        check(problems, t.count(Crossing.SIGN) == signing && w.host.signatures == signing,
                                "signing requests " + t.count(Crossing.SIGN));
                        Selection s = w.selection();
                        check(problems, s.planId.equals(plan.planId) && s.revision == 1
                                && s.realization == Realization.CURRENT, "choice " + s);
                        check(problems, t.bootCount == 1, "boots " + t.bootCount);
                        // An identical fact is recorded once in each framework instance.
                        java.util.Set<String> instances = new java.util.HashSet<>();
                        int factory = 0;
                        for (DeploymentRecords.Observation o : w.store.observations().values) {
                            if (o.kind != DeploymentRecords.ObservationKind.FACTORY) continue;
                            ++factory;
                            instances.add(o.boot + "/" + o.instance);
                        }
                        check(problems, factory == instances.size(), factory + " factory facts in "
                                + instances.size() + " instances");
                        account(w, problems);
                    });
                }
            }
        }
    }

    // ------------------------------------------------------------------ the recovery table

    private static void recoveryCases() {
        cases.run("recovery / create reply lost on the shell route stays unresolved until a listing shows none",
                problems -> {
            World w = world(Route.SHELL, 21);
            Plan plan = plan(w, Fixtures.plan(1));
            w.android.faults.put(2, Fault.LOST);
            w.android.holdWrites = true;
            String id = w.open(plan, 1);
            w.settle(id);
            Ticket t = w.ticket(id);
            check(problems, t.state == State.SESSION_INTENT && t.flag(DeploymentRecords.FLAG_UNRESOLVED), "lost " + t);
            w.android.frameworkRestart(); // The creation never reached the session file.
            w.android.holdWrites = false;
            w.settle(id);
            t = w.run(id, 40, false);
            check(problems, t.state == State.CLOSED_FAILED && w.calls(id, Crossing.CREATE) == 1, "ended " + t);
            World kept = world(Route.SHELL, 22);
            Plan plan2 = plan(kept, Fixtures.plan(1));
            kept.android.faults.put(2, Fault.LOST);
            String id2 = kept.open(plan2, 1);
            Ticket held = kept.run(id2, 30, true);
            check(problems, held.state == State.SESSION_INTENT && held.flag(DeploymentRecords.FLAG_UNRESOLVED),
                    "a session for the package must hold the ticket " + held);
            Ticket closed = finish(kept, id2);
            check(problems, closed.state == State.CLOSED_FAILED && kept.calls(id2, Crossing.CREATE) == 1,
                    "after storage freeing " + closed);
            account(w, problems);
            account(kept, problems);
        });
        cases.run("recovery / create reply lost on the device route is found by nonce", problems -> {
            World w = world(Route.DEVICE, 23);
            Plan plan = plan(w, Fixtures.plan(1));
            w.android.faults.put(2, Fault.LOST);
            String id = w.open(plan, 1);
            Ticket t = w.run(id, 80, false);
            check(problems, t.state == State.CLOSED_APPLIED && w.calls(id, Crossing.CREATE) == 1, "ended " + t);
            account(w, problems);
        });
        cases.run("recovery / framework restart before commit loses the record and a new attempt follows",
                problems -> {
            World w = world(Route.SHELL, 24);
            Plan plan = plan(w, Fixtures.plan(1));
            w.android.holdWrites = true;
            w.android.faults.put(3, Fault.RESTART_AFTER); // After the write: the creation never reached the file.
            String id = w.open(plan, 1);
            Ticket t = w.run(id, 60, true);
            check(problems, t.state == State.CLOSED_FAILED, "first attempt " + t);
            w.android.holdWrites = false;
            w.grant(Fixtures.lab(20, plan, Effect.STAGE, 0, w.android.wall()));
            String retry = w.open(plan, 2);
            check(problems, retry != null, "the retry was refused");
            Ticket second = w.run(retry, 80, false);
            check(problems, second.state == State.CLOSED_APPLIED && second.attempt == 2
                    && second.count(Crossing.SIGN) == 0, "retry " + second);
            account(w, problems);
        });
        cases.run("recovery / write fails or its reply is lost", problems -> {
            for (Fault fault : List.of(Fault.REFUSED, Fault.LOST, Fault.NO_EFFECT)) {
                World w = world(Route.SHELL, 25);
                Plan plan = plan(w, Fixtures.plan(1));
                w.android.faults.put(3, fault);
                String id = w.open(plan, 1);
                Ticket t = finish(w, id);
                check(problems, t.state == State.CLOSED_FAILED && w.calls(id, Crossing.WRITE) == 1
                        && t.count(Crossing.ABANDON) >= 1, fault + " " + t);
                consistent(w, plan, t, problems);
                account(w, problems);
            }
        });
        cases.run("recovery / commit reply lost, ready or failed", problems -> {
            World ready = world(Route.SHELL, 26);
            Plan plan = plan(ready, Fixtures.plan(1));
            ready.android.faults.put(4, Fault.LOST);
            String id = ready.open(plan, 1);
            Ticket t = ready.run(id, 80, false);
            check(problems, t.state == State.CLOSED_APPLIED && ready.calls(id, Crossing.COMMIT) == 1, "ready " + t);
            World failed = world(Route.DEVICE, 27);
            Plan plan2 = plan(failed, Fixtures.plan(1));
            failed.android.faults.put(4, Fault.LOST);
            failed.android.failVerification = true;
            String id2 = failed.open(plan2, 1);
            Ticket f = failed.run(id2, 80, false);
            check(problems, f.state == State.CLOSED_FAILED && failed.calls(id2, Crossing.COMMIT) == 1, "failed " + f);
            account(ready, problems);
            account(failed, problems);
        });
        cases.run("recovery / framework restart during commit", problems -> {
            World w = world(Route.SHELL, 28);
            Plan plan = plan(w, Fixtures.plan(1));
            w.android.holdVerification = true;
            w.android.faults.put(4, Fault.RESTART_AFTER);
            String id = w.open(plan, 1);
            Ticket t = finish(w, id);
            check(problems, t.state == State.CLOSED_FAILED && t.count(Crossing.ABANDON) >= 1
                    && w.calls(id, Crossing.COMMIT) == 1, "ended " + t);
            consistent(w, plan, t, problems);
            World boot = world(Route.SHELL, 29);
            Plan plan2 = plan(boot, Fixtures.plan(1));
            boot.android.holdVerification = true;
            boot.android.holdWrites = true;
            boot.android.faults.put(4, Fault.STOP_AFTER); // A kernel boot first.
            String id2 = boot.open(plan2, 1);
            boot.settle(id2);
            check(problems, boot.ticket(id2).state == State.BOOT_OBSERVED, "a boot during commit " + boot.ticket(id2));
            boot.android.holdVerification = false;
            boot.android.holdWrites = false;
            Ticket b = finish(boot, id2);
            consistent(boot, plan2, b, problems);
            account(w, problems);
            account(boot, problems);
        });
        cases.run("recovery / framework restart while READY", problems -> {
            World w = world(Route.SHELL, 30);
            Plan plan = plan(w, Fixtures.plan(1).commitMode(CommitMode.EARLY));
            String id = w.open(plan, 1);
            Ticket ready = w.run(id, 40, false, State.READY);
            w.android.tick(1000);
            w.android.frameworkRestart();
            w.settle(id);
            check(problems, ready.state == State.READY && w.ticket(id).state == State.READY, "left READY " + w.ticket(id));
            w.android.kernelBoot(true);
            Ticket t = w.run(id, 80, false);
            check(problems, t.state == State.CLOSED_APPLIED, "ended " + t);
            account(w, problems);
        });
        cases.run("recovery / unclean stop after READY, applied, ready again or abandoned", problems -> {
            World applied = world(Route.SHELL, 31);
            Plan plan = plan(applied, Fixtures.plan(1).commitMode(CommitMode.EARLY));
            String id = applied.open(plan, 1);
            applied.run(id, 40, false, State.READY);
            applied.android.tick(1000);
            applied.android.kernelBoot(false);
            Ticket a = applied.run(id, 80, false);
            check(problems, a.state == State.CLOSED_APPLIED, "applied " + a);
            World again = world(Route.SHELL, 32);
            Plan plan2 = plan(again, Fixtures.plan(1));
            again.android.holdVerification = true;
            String id2 = again.open(plan2, 1);
            again.settle(id2); // COMMIT_INTENT, verifying.
            again.android.flush(); // The committed flag reaches the file, the ready flag never does.
            again.android.kernelBoot(false);
            again.android.holdVerification = false;
            Ticket g = again.run(id2, 80, false);
            check(problems, g.state == State.CLOSED_APPLIED && g.count(Crossing.REBOOT) == 1, "ready again " + g);
            World expired = world(Route.SHELL, 33);
            Plan plan3 = plan(expired, Fixtures.plan(1));
            expired.android.holdVerification = true;
            String id3 = expired.open(plan3, 1);
            expired.settle(id3);
            expired.android.flush();
            expired.android.advance(2L * 3600 * 1000); // The ACTIVATE expires.
            expired.android.kernelBoot(false);
            expired.android.holdVerification = false;
            Ticket e = finish(expired, id3);
            check(problems, e.state == State.CLOSED_FAILED && e.count(Crossing.REBOOT) == 0, "expired " + e);
            consistent(expired, plan3, e, problems);
            account(applied, problems);
            account(again, problems);
            account(expired, problems);
        });
        cases.run("recovery / reboot request lost up to the request limit", problems -> {
            World w = world(Route.SHELL, 34);
            Plan plan = plan(w, Fixtures.plan(1));
            for (int k = 5; k < 9; k++) w.android.faults.put(k, Fault.NO_EFFECT);
            String id = w.open(plan, 1);
            Ticket t = finish(w, id);
            check(problems, w.calls(id, Crossing.REBOOT) == 3 && t.count(Crossing.REBOOT) == 3, "requests "
                    + w.calls(id, Crossing.REBOOT));
            check(problems, t.state == State.CLOSED_FAILED && t.count(Crossing.ABANDON) >= 1, "ended " + t);
            consistent(w, plan, t, problems);
            account(w, problems);
        });
        cases.run("recovery / abandon reply lost, gone or still live in a later instance", problems -> {
            for (Fault fault : List.of(Fault.LOST, Fault.NO_EFFECT)) {
                World w = world(Route.SHELL, 35);
                Plan plan = plan(w, Fixtures.plan(1).commitMode(CommitMode.EARLY));
                String id = w.open(plan, 1);
                w.run(id, 40, false, State.READY);
                w.android.faults.put(w.android.ordinal, fault);
                w.coordinator.cancel(id);
                Ticket t = finish(w, id);
                int expected = fault == Fault.LOST ? 1 : 2;
                check(problems, t.state == State.CANCELLED && w.calls(id, Crossing.ABANDON) == expected,
                        fault + " " + t + " abandons " + w.calls(id, Crossing.ABANDON));
                consistent(w, plan, t, problems);
                account(w, problems);
            }
            World resurrected = world(Route.SHELL, 36);
            Plan plan = plan(resurrected, Fixtures.plan(1).commitMode(CommitMode.EARLY));
            String id = resurrected.open(plan, 1);
            resurrected.run(id, 40, false, State.READY);
            resurrected.android.tick(1000);
            resurrected.android.holdWrites = true; // Hidden as destroyed, never written.
            resurrected.coordinator.cancel(id);
            resurrected.settle(id);
            resurrected.android.frameworkRestart();
            resurrected.android.holdWrites = false;
            Ticket t = finish(resurrected, id);
            check(problems, t.state == State.CANCELLED && resurrected.calls(id, Crossing.ABANDON) == 2,
                    "resurrected " + t);
            consistent(resurrected, plan, t, problems);
            account(resurrected, problems);
        });
        cases.run("recovery / install fails at boot", problems -> {
            World w = world(Route.SHELL, 37);
            w.android.apks.put(Fixtures.BUNDLE_APK, new Apk(Fixtures.BUNDLE_APK, 40, World.SIGNER, false));
            Plan plan = plan(w, Fixtures.plan(1));
            String id = w.open(plan, 1);
            Ticket t = w.run(id, 80, false);
            // The failed boot and Android's extra reboot happen before the coordinator sees a boot.
            check(problems, t.state == State.CLOSED_FAILED && t.bootCount == 1 && w.calls(id, Crossing.CREATE) == 1
                    && t.cause == Cause.NONE, "ended " + t);
            check(problems, !w.android.active().digest.equals(Fixtures.BUNDLE_APK), "the bundle stayed");
            account(w, problems);
        });
        cases.run("recovery / stop before the checkpoint commits repeats the install", problems -> {
            World once = world(Route.SHELL, 38);
            Plan plan = plan(once, Fixtures.plan(1));
            once.android.holdCheckpoint = true;
            String id = once.open(plan, 1);
            once.run(id, 10, false, State.APPLIED_PROVISIONAL);
            once.android.kernelBoot(false);
            once.android.holdCheckpoint = false;
            Ticket t = once.run(id, 80, false);
            check(problems, t.state == State.CLOSED_APPLIED && t.bootCount == 2, "repeated " + t);
            World twice = world(Route.SHELL, 39);
            Plan plan2 = plan(twice, Fixtures.plan(1));
            twice.android.holdCheckpoint = true;
            String id2 = twice.open(plan2, 1);
            twice.run(id2, 10, false, State.APPLIED_PROVISIONAL);
            twice.android.kernelBoot(false);
            twice.run(id2, 10, false, State.APPLIED_PROVISIONAL);
            twice.android.kernelBoot(false);
            twice.android.holdCheckpoint = false;
            Ticket f = twice.run(id2, 80, false);
            check(problems, f.state == State.CLOSED_FAILED && f.bootCount == 3, "reverted " + f);
            check(problems, !twice.android.active().digest.equals(Fixtures.BUNDLE_APK), "the bundle stayed");
            account(once, problems);
            account(twice, problems);
        });
        cases.run("recovery / a session made ready again waits for the checkpoint and activates nothing on a crash",
                problems -> {
            World w = world(Route.SHELL, 40);
            Plan plan = plan(w, Fixtures.plan(1));
            w.android.holdVerification = true;
            String id = w.open(plan, 1);
            w.settle(id); // COMMIT_INTENT while verification runs.
            w.android.flush(); // The committed flag reaches the file.
            w.android.holdWrites = true;
            w.android.holdVerification = false;
            w.android.verifyPending(); // Ready in memory and the checkpoint armed; the ready flag never written.
            w.android.kernelBoot(false); // A crash after READY.
            w.android.holdWrites = false;
            w.android.holdCheckpoint = true; // This boot runs under the armed checkpoint, which stays pending.
            Ticket waiting = w.run(id, 20, false, State.READY_AGAIN);
            w.settle(id);
            Ticket t0 = w.ticket(id);
            check(problems, t0.state == State.READY_AGAIN && w.android.checkpointPending && t0.count(Crossing.REBOOT) == 0,
                    "not waiting " + waiting + " / " + t0);
            w.android.kernelBoot(false); // A crash before the checkpoint commits.
            check(problems, !w.android.active().digest.equals(Fixtures.BUNDLE_APK), "activated on the crash");
            w.android.holdCheckpoint = false;
            Ticket t = w.run(id, 80, false);
            check(problems, t.state == State.CLOSED_APPLIED && t.count(Crossing.REBOOT) == 1, "ended " + t);
            consistent(w, plan, t, problems);
            account(w, problems);
        });
        cases.run("recovery / cancellation at each step", problems -> {
            int closings = 0;
            for (int rounds = 0; rounds < 12; rounds++) {
                World w = world(Route.SHELL, 41 + rounds);
                Plan plan = plan(w, Fixtures.plan(1));
                String id = w.open(plan, 1);
                for (int i = 0; i < rounds; i++) w.coordinator.round(id);
                boolean recorded = w.coordinator.cancel(id);
                Ticket t = finish(w, id);
                consistent(w, plan, t, problems);
                check(problems, !recorded || t.state == State.CANCELLED || t.state == State.CLOSED_APPLIED,
                        "after " + rounds + " rounds " + t);
                if (t.state == State.CANCELLED) ++closings;
                account(w, problems);
            }
            check(problems, closings >= 8, closings + " cancellations closed as CANCELLED");
        });
        cases.run("recovery / image change with a pending session, committed and uncommitted", problems -> {
            World committed = world(Route.SHELL, 60);
            Plan plan = plan(committed, Fixtures.plan(1).commitMode(CommitMode.EARLY));
            String id = committed.open(plan, 1);
            committed.run(id, 40, false, State.READY);
            committed.android.tick(1000);
            committed.android.imageChange(Fixtures.NEW_FINGERPRINT, new Apk(Fixtures.digest(0xf1), 38, World.SIGNER,
                    true));
            committed.android.kernelBoot(true);
            Ticket c = committed.run(id, 60, true);
            check(problems, c.state == State.VOID && c.cause == Cause.VOID_BASE, "committed " + c);
            World open = world(Route.SHELL, 61);
            Plan plan2 = plan(open, Fixtures.plan(1));
            String id2 = open.open(plan2, 1);
            open.android.faults.put(4, Fault.CRASH_BEFORE); // Stops before the commit.
            open.settle(id2);
            open.android.faults.clear();
            open.android.ordinal = 100;
            Ticket before = open.ticket(id2);
            open.android.tick(1000);
            open.android.imageChange(Fixtures.NEW_FINGERPRINT, new Apk(Fixtures.digest(0xf1), 38, World.SIGNER, true));
            open.android.kernelBoot(true);
            Ticket u = finish(open, id2);
            check(problems, u.state == State.VOID && u.cause == Cause.VOID_BASE, "uncommitted from " + before + ": " + u);
            consistent(open, plan2, u, problems);
            account(committed, problems);
            account(open, problems);
        });
        cases.run("recovery / image change deletes the variant and DISPLACED keeps the choice", problems -> {
            World w = world(Route.SHELL, 62);
            Plan plan = plan(w, Fixtures.plan(1));
            String id = w.open(plan, 1);
            check(problems, w.run(id, 80, false).state == State.CLOSED_APPLIED, "applied");
            Selection before = w.selection();
            w.android.imageChange(Fixtures.NEW_FINGERPRINT, new Apk(Fixtures.digest(0xf1), 45, World.SIGNER, true));
            w.android.kernelBoot(true);
            w.android.tick(1000);
            w.settle(id);
            Selection after = w.selection();
            check(problems, after.realization == Realization.DISPLACED && after.choice == before.choice
                    && after.planId.equals(before.planId) && after.revision == before.revision, "after " + after);
            account(w, problems);
        });
        cases.run("recovery / image change keeps the variant as STALE_BASE, never healthy", problems -> {
            World w = world(Route.SHELL, 63);
            Plan plan = plan(w, Fixtures.plan(1));
            String id = w.open(plan, 1);
            w.run(id, 10, false, State.HEALTH_WINDOW);
            w.android.imageChange(Fixtures.NEW_FINGERPRINT, new Apk(Fixtures.digest(0xf1), 38, World.SIGNER, true));
            w.android.kernelBoot(true);
            Ticket t = w.run(id, 40, false);
            check(problems, t.state == State.CLOSED_APPLIED, "ended " + t);
            for (Health h : t.health) check(problems, h.outcome != Outcome.HEALTHY, "healthy on a stale base");
            Selection s = w.selection();
            check(problems, s.realization == Realization.STALE_BASE && s.planId.equals(plan.planId), "selection " + s);
            check(problems, w.android.active().digest.equals(Fixtures.BUNDLE_APK), "the variant stays");
            account(w, problems);
        });
        cases.run("recovery / session file damaged", problems -> {
            World w = world(Route.SHELL, 64);
            Plan plan = plan(w, Fixtures.plan(1));
            w.android.faults.put(4, Fault.CRASH_BEFORE);
            String id = w.open(plan, 1);
            w.settle(id);
            w.android.fileDamaged = true;
            w.android.frameworkRestart();
            Ticket t = finish(w, id);
            check(problems, t.state == State.CLOSED_FAILED, "ended " + t);
            consistent(w, plan, t, problems);
            account(w, problems);
        });
        cases.run("recovery / storage freeing while a session waits", problems -> {
            World w = world(Route.SHELL, 65);
            Plan plan = plan(w, Fixtures.plan(1).commitMode(CommitMode.EARLY)
                    .limits(4, 120_000, 3, 48L * 3600 * 1000, 300_000));
            String id = w.open(plan, 1);
            w.run(id, 40, false, State.READY);
            w.android.advance(9L * 3600 * 1000);
            w.android.storageFreeing();
            w.android.flush();
            w.settle(id);
            check(problems, w.ticket(id).state == State.READY, "a destroyed session concluded in its instance");
            w.android.frameworkRestart();
            Ticket t = w.run(id, 40, false);
            check(problems, t.state == State.CLOSED_FAILED && t.count(Crossing.ABANDON) == 0, "ended " + t);
            consistent(w, plan, t, problems);
            account(w, problems);
        });
        cases.run("recovery / another installer or a downgrade through root", problems -> {
            World before = world(Route.SHELL, 66);
            Plan plan = plan(before, Fixtures.plan(1));
            String id = before.open(plan, 1);
            for (int i = 0; i < 20 && before.ticket(id).state != State.WRITTEN; i++) before.coordinator.round(id);
            before.android.otherInstaller(new Apk(Fixtures.digest(0xee), 45, World.SIGNER, true));
            Ticket v = finish(before, id);
            check(problems, v.state == State.VOID && v.cause == Cause.OTHER_BYTES && v.count(Crossing.ABANDON) >= 1,
                    "before commit " + v);
            consistent(before, plan, v, problems);
            World after = world(Route.SHELL, 67);
            Plan plan2 = plan(after, Fixtures.plan(1));
            String id2 = after.open(plan2, 1);
            after.run(id2, 10, false, State.HEALTH_WINDOW);
            after.android.otherInstaller(new Apk(Fixtures.digest(0xee), 45, World.SIGNER, true));
            Ticket d = after.run(id2, 20, false);
            check(problems, d.state == State.DIVERGED && d.cause == Cause.OTHER_BYTES, "after commit " + d);
            check(problems, after.selection().realization == Realization.DIVERGED, "realization " + after.selection());
            World booted = world(Route.SHELL, 69);
            Plan plan3 = plan(booted, Fixtures.plan(1));
            booted.android.holdVerification = true;
            String id3 = booted.open(plan3, 1);
            booted.settle(id3); // COMMIT_INTENT while verification runs.
            booted.android.flush();
            booted.android.kernelBoot(false); // BOOT_OBSERVED with the session live and not ready.
            booted.android.otherInstaller(new Apk(Fixtures.digest(0xee), 45, World.SIGNER, true));
            booted.android.holdVerification = false;
            Ticket o = finish(booted, id3);
            check(problems, o.state == State.DIVERGED && o.count(Crossing.ABANDON) >= 1, "while live " + o);
            consistent(booted, plan3, o, problems);
            account(before, problems);
            account(after, problems);
            account(booted, problems);
        });
        cases.run("recovery / users added, removed and switched during activation", problems -> {
            World w = world(Route.SHELL, 68);
            w.android.users.add(new AndroidFacade.User(10, 12));
            Plan plan = plan(w, Fixtures.plan(1));
            String id = w.open(plan, 1);
            w.run(id, 10, false, State.HEALTH_WINDOW);
            w.android.users.get(1).removed = true;
            w.android.users.add(new AndroidFacade.User(11, 13));
            w.android.users.get(0).unlocked = false; // Switched away: locked, still running.
            w.settle(id);
            w.android.users.get(0).unlocked = true;
            Ticket t = w.run(id, 80, false);
            check(problems, t.state == State.CLOSED_APPLIED && t.health.equals(List.of(new Health(0, 0,
                    Outcome.HEALTHY), new Health(10, 12, Outcome.REMOVED), new Health(11, 13, Outcome.HEALTHY))),
                    "outcomes " + t.health);
            account(w, problems);
        });
        cases.run("recovery / coordinator lost at every step resumes by observation", problems -> {
            for (Route route : List.of(Route.SHELL, Route.DEVICE)) {
                for (int k = 0; k < 6; k++) {
                    for (Fault fault : List.of(Fault.CRASH_BEFORE, Fault.CRASH_AFTER)) {
                        World w = world(route, 70 + k);
                        Plan plan = plan(w, Fixtures.plan(1));
                        w.android.faults.put(k, fault);
                        String id = w.open(plan, 1);
                        Ticket t = finish(w, id);
                        consistent(w, plan, t, problems);
                        check(problems, w.crashes == 1, route + " " + k + " " + fault + " crashes " + w.crashes);
                        account(w, problems);
                    }
                }
            }
        });
        cases.run("recovery / coordinator lost between the selection and ticket writes keeps the choice", problems -> {
            for (Route route : List.of(Route.SHELL, Route.DEVICE)) {
                World w = world(route, 78);
                Plan plan = plan(w, Fixtures.plan(1));
                w.betweenWrites = 0; // The first round that writes both records is lost between them.
                String id = w.open(plan, 1);
                Ticket t = finish(w, id);
                Selection s = w.selection();
                check(problems, w.crashes == 1 && w.betweenWrites == -1, route + " crashes " + w.crashes);
                check(problems, t.state == State.CLOSED_APPLIED && t.cause == Cause.NONE, route + " ended " + t);
                check(problems, s.choice == ChoiceKind.PLAN && s.planId.equals(plan.planId) && s.revision == 1
                        && s.realization == Realization.CURRENT, route + " choice " + s);
                consistent(w, plan, t, problems);
                account(w, problems);
            }
            // Decision 6: the temporary factory realization is kept the same way.
            World w = world(Route.SHELL, 79);
            Plan variant = plan(w, Fixtures.plan(1));
            String id = w.open(variant, 1);
            check(problems, w.run(id, 80, false).state == State.CLOSED_APPLIED, "variant applied");
            Apk newFactory = new Apk(Fixtures.digest(0xf1), 38, World.SIGNER, true);
            w.android.imageChange(Fixtures.NEW_FINGERPRINT, newFactory);
            w.android.kernelBoot(true);
            w.android.tick(1000);
            w.settle(id);
            Apk factorySource = new Apk(Fixtures.digest(0xa3), 42, World.SIGNER, true);
            w.android.apks.put(factorySource.digest, factorySource);
            Plan temporary = plan(w, Fixtures.plan(4).target(DeploymentRecords.Target.TEMPORARY_FACTORY)
                    .repairs(variant.planId).bundle(Fixtures.digest(0xb3), 42)
                    .restoration(DeploymentRecords.NO_DIGEST, 0)
                    .cohort(Fixtures.NEW_FINGERPRINT, newFactory.digest, 38)
                    .base(Fixtures.BUNDLE_APK, 40, Fixtures.UID, Fixtures.CONTEXT).selectionRevision(1));
            w.betweenWrites = 0;
            String tid = w.open(temporary, 2);
            Ticket t = w.run(tid, 80, false);
            Selection standing = w.selection();
            check(problems, w.crashes == 1, "temporary crashes " + w.crashes);
            check(problems, t.state == State.CLOSED_APPLIED && standing.choice == ChoiceKind.PLAN
                    && standing.planId.equals(variant.planId) && standing.revision == 1
                    && standing.realization == Realization.TEMPORARY_FACTORY
                    && standing.temporary.equals(temporary.planId), "temporary " + t + " " + standing);
            account(w, problems);
        });
        cases.run("recovery / chosen bytes that return after other bytes are CURRENT again", problems -> {
            // Observation IDs that rise and that fall with time. A new coordinator lists the store
            // by ID, so with falling IDs the listing runs against time.
            for (boolean falling : List.of(false, true)) {
                for (boolean restart : List.of(false, true)) {
                    String label = (falling ? "falling" : "rising") + (restart ? " after a restart" : "");
                    World w = world(Route.SHELL, 77);
                    w.android.fallingIds = falling;
                    Plan plan = plan(w, Fixtures.plan(1));
                    String id = w.open(plan, 1);
                    check(problems, w.run(id, 80, false).state == State.CLOSED_APPLIED, label + " applied");
                    w.android.otherInstaller(new Apk(Fixtures.digest(0xee), 45, World.SIGNER, true));
                    w.android.tick(1000);
                    w.settle(id);
                    check(problems, w.selection().realization == Realization.DIVERGED,
                            label + " other bytes " + w.selection());
                    if (restart) w.coordinator = w.coordinator();
                    w.android.otherInstaller(World.BUNDLE); // The same framework instance throughout.
                    w.android.tick(1000);
                    w.settle(id);
                    check(problems, w.selection().realization == Realization.CURRENT,
                            label + " the chosen bytes back " + w.selection());
                    account(w, problems);
                }
            }
        });
        cases.run("recovery / crash during the health window", problems -> {
            World crash = world(Route.SHELL, 80);
            crash.android.users.add(new AndroidFacade.User(10, 12));
            Plan plan = plan(crash, Fixtures.plan(1));
            String id = crash.open(plan, 1);
            crash.run(id, 10, false, State.HEALTH_WINDOW);
            crash.android.users.get(1).probe = Classification.HEALTH_CRASH;
            crash.settle(id);
            crash.android.users.get(1).probe = Classification.HEALTH_HELD;
            Ticket c = crash.run(id, 80, false);
            check(problems, c.health.equals(List.of(new Health(0, 0, Outcome.HEALTHY), new Health(10, 12,
                    Outcome.UNHEALTHY))), "crash " + c.health);
            World reboots = world(Route.SHELL, 81);
            Plan plan2 = plan(reboots, Fixtures.plan(1));
            String id2 = reboots.open(plan2, 1);
            reboots.run(id2, 10, false, State.HEALTH_WINDOW);
            for (int i = 0; i < 3; i++) {
                reboots.android.kernelBoot(true);
                reboots.android.tick(1000);
                reboots.settle(id2);
            }
            Ticket r = reboots.ticket(id2);
            check(problems, r.state == State.CLOSED_APPLIED && r.flag(DeploymentRecords.FLAG_BOOT_LIMIT)
                    && r.health.equals(List.of(new Health(0, 0, Outcome.UNHEALTHY))), "boot limit " + r);
            account(crash, problems);
            account(reboots, problems);
        });
        cases.run("repair / a linked repair plan supersedes the window and restores", problems -> {
            World w = world(Route.SHELL, 82);
            Plan plan = plan(w, Fixtures.plan(1));
            String id = w.open(plan, 1);
            w.run(id, 10, false, State.HEALTH_WINDOW);
            check(problems, w.open(plan, 9) == null, "a second open ticket for the component");
            Plan repair = w.add(Fixtures.plan(5).repairs(plan.planId).bundle(Fixtures.RESTORATION_INPUT,
                    Fixtures.RESTORATION_VERSION).restoration(DeploymentRecords.NO_DIGEST, 0).signing(0)
                    .base(Fixtures.BUNDLE_APK, Fixtures.BUNDLE_VERSION,
                    Fixtures.UID, Fixtures.CONTEXT).selectionRevision(1).build());
            w.grant(Fixtures.lab(30, repair, Effect.STAGE, 0, w.android.wall()));
            w.grant(Fixtures.lab(31, repair, Effect.ACTIVATE, 0, w.android.wall()));
            w.settle(id);
            Ticket superseded = w.ticket(id);
            check(problems, superseded.state == State.SUPERSEDED && superseded.successor.equals(repair.planId),
                    "superseded " + superseded);
            String rid = w.open(repair, 2);
            Ticket r = w.run(rid, 80, false);
            check(problems, r.state == State.CLOSED_APPLIED && w.android.active().digest.equals(Fixtures.RESTORATION_APK)
                    && w.selection().planId.equals(repair.planId) && w.selection().revision == 2, "repair " + r);
            account(w, problems);
        });
    }

    private static void decisionCases() {
        cases.run("decision 3 / automatic restoration takes over only on an observed failure", problems -> {
            World w = world(Route.SHELL, 90);
            Plan plan = plan(w, Fixtures.plan(1).healthResponse(HealthResponse.RESTORE_AUTOMATICALLY)
                    .restorationPlan(Fixtures.id(0x105)));
            // The approval lists the restoration reboot and grants its STAGE and ACTIVATE up front.
            Plan restoration = w.add(Fixtures.plan(5).repairs(plan.planId).bundle(Fixtures.RESTORATION_INPUT,
                    Fixtures.RESTORATION_VERSION).restoration(DeploymentRecords.NO_DIGEST, 0).signing(0)
                    .base(Fixtures.BUNDLE_APK, Fixtures.BUNDLE_VERSION,
                    Fixtures.UID, Fixtures.CONTEXT).selectionRevision(1).build());
            w.grant(Fixtures.lab(40, restoration, Effect.STAGE, 0, w.android.wall()));
            w.grant(Fixtures.lab(41, restoration, Effect.ACTIVATE, 0, w.android.wall()));
            String id = w.open(plan, 1);
            w.run(id, 10, false, State.HEALTH_WINDOW);
            w.android.users.get(0).probe = Classification.HEALTH_INCONCLUSIVE;
            w.settle(id);
            check(problems, w.ticket(id).state == State.HEALTH_WINDOW, "restored on an unavailable observation");
            w.android.users.get(0).probe = Classification.HEALTH_CRASH;
            w.settle(id);
            Ticket superseded = w.ticket(id);
            check(problems, superseded.state == State.SUPERSEDED && superseded.successor.equals(restoration.planId),
                    "not restored on a crash " + superseded);
            w.android.users.get(0).probe = Classification.HEALTH_HELD;
            String rid = w.open(restoration, 2);
            Ticket r = w.run(rid, 80, false);
            check(problems, r.state == State.CLOSED_APPLIED
                    && w.android.active().digest.equals(Fixtures.RESTORATION_APK)
                    && w.selection().planId.equals(restoration.planId) && w.selection().revision == 2, "restoration " + r);
            account(w, problems);
        });
        cases.run("decision 3 / automatic restoration takes over at the boot limit", problems -> {
            World w = world(Route.SHELL, 93);
            Plan plan = plan(w, Fixtures.plan(1).healthResponse(HealthResponse.RESTORE_AUTOMATICALLY)
                    .restorationPlan(Fixtures.id(0x105)));
            Plan restoration = w.add(Fixtures.plan(5).repairs(plan.planId).bundle(Fixtures.RESTORATION_INPUT,
                    Fixtures.RESTORATION_VERSION).restoration(DeploymentRecords.NO_DIGEST, 0).signing(0)
                    .base(Fixtures.BUNDLE_APK, Fixtures.BUNDLE_VERSION,
                    Fixtures.UID, Fixtures.CONTEXT).selectionRevision(1).build());
            w.grant(Fixtures.lab(40, restoration, Effect.STAGE, 0, w.android.wall()));
            w.grant(Fixtures.lab(41, restoration, Effect.ACTIVATE, 0, w.android.wall()));
            String id = w.open(plan, 1);
            w.run(id, 10, false, State.HEALTH_WINDOW);
            for (int i = 0; i < 3; i++) {
                w.android.kernelBoot(true); // SystemUI keeps the device rebooting.
                w.android.tick(1000);
                w.settle(id);
            }
            Ticket superseded = w.ticket(id);
            check(problems, superseded.state == State.SUPERSEDED && superseded.successor.equals(restoration.planId)
                    && superseded.flag(DeploymentRecords.FLAG_BOOT_LIMIT)
                    && superseded.health.equals(List.of(new Health(0, 0, Outcome.UNHEALTHY))),
                    "not restored at the boot limit " + superseded);
            String rid = w.open(restoration, 2);
            Ticket r = w.run(rid, 80, false);
            check(problems, r.state == State.CLOSED_APPLIED
                    && w.android.active().digest.equals(Fixtures.RESTORATION_APK)
                    && w.selection().planId.equals(restoration.planId) && w.selection().revision == 2, "restoration " + r);
            account(w, problems);
        });
        cases.run("decision 6 / a temporary factory copy keeps the choice until the rebuild lands", problems -> {
            World w = world(Route.SHELL, 91);
            Plan variant = plan(w, Fixtures.plan(1));
            String id = w.open(variant, 1);
            check(problems, w.run(id, 80, false).state == State.CLOSED_APPLIED, "variant applied");
            Apk newFactory = new Apk(Fixtures.digest(0xf1), 38, World.SIGNER, true);
            w.android.imageChange(Fixtures.NEW_FINGERPRINT, newFactory);
            w.android.kernelBoot(true);
            w.android.tick(1000);
            w.settle(id);
            check(problems, w.selection().realization == Realization.STALE_BASE, "stale " + w.selection());
            Apk factorySource = new Apk(Fixtures.digest(0xa3), 42, World.SIGNER, true);
            w.android.apks.put(factorySource.digest, factorySource);
            Plan temporary = plan(w, Fixtures.plan(4).target(DeploymentRecords.Target.TEMPORARY_FACTORY)
                    .repairs(variant.planId).bundle(Fixtures.digest(0xb3), 42)
                    .restoration(DeploymentRecords.NO_DIGEST, 0)
                    .cohort(Fixtures.NEW_FINGERPRINT, newFactory.digest, 38)
                    .base(Fixtures.BUNDLE_APK, 40, Fixtures.UID, Fixtures.CONTEXT).selectionRevision(1));
            String tid = w.open(temporary, 2);
            Ticket t = w.run(tid, 80, false);
            Selection standing = w.selection();
            check(problems, t.state == State.CLOSED_APPLIED && standing.choice == ChoiceKind.PLAN
                    && standing.planId.equals(variant.planId) && standing.revision == 1
                    && standing.realization == Realization.TEMPORARY_FACTORY
                    && standing.temporary.equals(temporary.planId), "temporary " + t + " " + standing);
            Apk rebuilt = new Apk(Fixtures.digest(0xa4), 43, World.SIGNER, true);
            w.android.apks.put(rebuilt.digest, rebuilt);
            Plan rebuild = plan(w, Fixtures.plan(6).repairs(variant.planId).bundle(Fixtures.digest(0xb4), 43)
                    .restoration(DeploymentRecords.NO_DIGEST, 0)
                    .cohort(Fixtures.NEW_FINGERPRINT, newFactory.digest, 38)
                    .base(factorySource.digest, 42, Fixtures.UID, Fixtures.CONTEXT).selectionRevision(1));
            String rid = w.open(rebuild, 3);
            Ticket r = w.run(rid, 80, false);
            Selection landed = w.selection();
            check(problems, r.state == State.CLOSED_APPLIED && landed.planId.equals(rebuild.planId) && landed.revision == 2
                    && landed.realization == Realization.CURRENT && landed.temporary.equals(DeploymentRecords.NO_ID),
                    "rebuild " + r + " " + landed);
            account(w, problems);
        });
        cases.run("decision 7 / other running users get notice and a declared delay before the reboot", problems -> {
            World w = world(Route.DEVICE, 92);
            w.android.users.add(new AndroidFacade.User(10, 12));
            Plan plan = plan(w, Fixtures.plan(1).notice(60_000, 60_000));
            String id = w.open(plan, 1);
            Ticket t = w.run(id, 80, false);
            Entry notice = t.last(Crossing.NOTICE), create = t.last(Crossing.CREATE);
            check(problems, t.state == State.CLOSED_APPLIED && notice != null && create != null
                    && notice.boot.equals(create.boot) && create.elapsed - notice.elapsed >= 60_000,
                    "ended " + t + " notice " + notice);
            check(problems, t.health.size() == 2, "both users observed " + t.health);
            account(w, problems);
        });
        cases.run("decision 7 / a notice lost before its effect is given again, and the reboot waits for its receipts",
                problems -> {
            for (Fault fault : List.of(Fault.NO_EFFECT, Fault.CRASH_BEFORE, Fault.LOST, Fault.CRASH_AFTER)) {
                World w = world(Route.SHELL, 93);
                w.android.users.add(new AndroidFacade.User(10, 12));
                Plan plan = plan(w, Fixtures.plan(1).notice(60_000, 60_000));
                String id = w.open(plan, 1);
                // The calls run SIGN, PUBLISH, then the notice before the session.
                w.android.faults.put(2, fault);
                Ticket t = w.run(id, 80, false);
                boolean effect = fault == Fault.LOST || fault == Fault.CRASH_AFTER;
                List<AndroidFacade.Call> notices = new java.util.ArrayList<>();
                for (AndroidFacade.Call call : w.android.calls) if (call.crossing == Crossing.NOTICE) notices.add(call);
                Entry create = t.last(Crossing.CREATE);
                AndroidFacade.Call delivered = notices.isEmpty() ? null : notices.get(notices.size() - 1);
                check(problems, t.state == State.CLOSED_APPLIED && notices.size() == (effect ? 1 : 2)
                        && delivered != null && delivered.fault == Fault.NONE == !effect && create != null
                        && create.boot.equals(delivered.boot) && create.elapsed - delivered.elapsed >= 60_000,
                        fault + ": ended " + t + " notices " + notices.size());
                account(w, problems);
            }
        });
    }

    private static void cohortCases() {
        cases.run("cohort / a check with no ticket open realizes each new boot", problems -> {
            World w = world(Route.SHELL, 96);
            Plan plan = plan(w, Fixtures.plan(1));
            Ticket t = w.run(w.open(plan, 1), 80, false);
            w.android.kernelBoot(true);
            w.android.tick(5_000);
            String boot = w.android.boot;
            Selection s = w.coordinator.check(Fixtures.COMPONENT);
            check(problems, t.state == State.CLOSED_APPLIED && s.realization == Realization.CURRENT
                    && s.checkedBoot.equals(boot) && s.planId.equals(plan.planId) && s.equals(w.selection()),
                    "current " + s);
            w.android.otherInstaller(new Apk(Fixtures.digest(0xee), 45, World.SIGNER, true));
            Selection other = w.coordinator.check(Fixtures.COMPONENT);
            check(problems, other.realization == Realization.DIVERGED && other.choice == ChoiceKind.PLAN
                    && other.planId.equals(plan.planId) && other.revision == s.revision, "other bytes " + other);
            int calls = w.android.calls.size();
            check(problems, w.coordinator.check(Fixtures.COMPONENT).equals(other) && w.android.calls.size() == calls,
                    "a check crossed into the device or changed again");
            account(w, problems);
        });
        cases.run("cohort / a closed ticket's round sets no DIVERGED while another bundle is active before APPLIED",
                problems -> {
            World w = world(Route.SHELL, 97);
            Plan plan = plan(w, Fixtures.plan(1));
            String id = w.open(plan, 1);
            w.run(id, 10, false, State.HEALTH_WINDOW);
            Plan repair = w.add(Fixtures.plan(5).repairs(plan.planId).bundle(Fixtures.RESTORATION_INPUT,
                    Fixtures.RESTORATION_VERSION).restoration(DeploymentRecords.NO_DIGEST, 0).signing(0)
                    .base(Fixtures.BUNDLE_APK, Fixtures.BUNDLE_VERSION, Fixtures.UID, Fixtures.CONTEXT)
                    .selectionRevision(1).build());
            w.grant(Fixtures.lab(30, repair, Effect.STAGE, 0, w.android.wall()));
            w.grant(Fixtures.lab(31, repair, Effect.ACTIVATE, 0, w.android.wall()));
            w.settle(id);
            String rid = w.open(repair, 2);
            // The repair's activation boot keeps its checkpoint pending, so it waits before APPLIED.
            w.android.holdCheckpoint = true;
            Ticket r = w.run(rid, 40, false, State.APPLIED_PROVISIONAL);
            Selection before = w.selection();
            w.coordinator.round(id);
            Selection closed = w.selection();
            Selection checked = w.coordinator.check(Fixtures.COMPONENT);
            check(problems, w.ticket(id).state == State.SUPERSEDED && r.state == State.APPLIED_PROVISIONAL
                    && w.android.active().digest.equals(Fixtures.RESTORATION_APK)
                    && closed.realization != Realization.DIVERGED && closed.equals(before) && checked.equals(before),
                    "repair " + r + " before " + before + " after the closed round " + closed + " check " + checked);
            w.android.holdCheckpoint = false;
            Ticket done = w.run(rid, 80, false);
            Selection landed = w.selection();
            check(problems, done.state == State.CLOSED_APPLIED && landed.planId.equals(repair.planId)
                    && landed.realization == Realization.CURRENT, "repair " + done + " " + landed);
            account(w, problems);
        });
        cases.run("lab / a driver's points act between the two writes, on the shell route only", problems -> {
            int[] fired = {0};
            World w = world(Route.SHELL, 99);
            // A lab driver outside the package sees only the public hook and the public point.
            Coordinator.Points lose = point -> {
                if (point.equals(Coordinator.BETWEEN_WRITES) && fired[0]++ == 0) {
                    w.lostBetweenWrites();
                    throw new AndroidFacade.Crash();
                }
            };
            World device = world(Route.DEVICE, 98);
            Coordinator refused = new Coordinator(device.store, device.link, device.host, Fixtures.TRUST,
                    () -> Fixtures.id(0x1d6000));
            check(problems, !refused.labPoints(lose), "the device route accepted a lab hook");
            // The route is fixed when the coordinator is made: one that reads DEVICE then, and SHELL
            // later, still refuses.
            int[] asked = {0};
            Coordinator.Device turning = new Coordinator.Device() {
                @Override
                public Route route() { return asked[0]++ == 0 ? Route.DEVICE : Route.SHELL; }

                @Override
                public Reconciler.Clock clock() { return device.link.clock(); }

                @Override
                public List<DeploymentRecords.Observation> observe(Ticket ticket, Plan plan) {
                    return device.link.observe(ticket, plan);
                }

                @Override
                public List<DeploymentRecords.Observation> observe(String component) {
                    return device.link.observe(component);
                }

                @Override
                public DeploymentRecords.Observation cross(Ticket ticket, Plan plan, Entry entry) {
                    return device.link.cross(ticket, plan, entry);
                }
            };
            Coordinator fixed = new Coordinator(device.store, turning, device.host, Fixtures.TRUST,
                    () -> Fixtures.id(0x1d6001));
            check(problems, asked[0] == 1 && !fixed.labPoints(lose) && turning.route() == Route.SHELL,
                    "a route read when the hook is installed, not when the coordinator is made");
            long[] n = {0};
            w.coordinator = new Coordinator(w.store, w.link, w.host, Fixtures.TRUST,
                    () -> String.format("%016x%016x", 0x1d7000000000000L, ++n[0]));
            check(problems, w.coordinator.labPoints(lose), "the shell route refused a lab hook");
            Plan plan = plan(w, Fixtures.plan(1));
            Ticket t = w.run(w.open(plan, 1), 80, false);
            Selection s = w.selection();
            check(problems, fired[0] == 1 && w.crashes == 1 && t.state == State.CLOSED_APPLIED
                    && s.planId.equals(plan.planId) && s.realization == Realization.CURRENT,
                    "fired " + fired[0] + " crashes " + w.crashes + " " + t + " " + s);
            account(w, problems);
        });
    }

    // ------------------------------------------------------------------ sweeps

    private static final List<Fault> FAULTS = List.of(Fault.LOST, Fault.REFUSED, Fault.CRASH_BEFORE,
            Fault.CRASH_AFTER, Fault.RESTART_AFTER, Fault.STOP_AFTER, Fault.UNRECOGNIZED, Fault.NO_EFFECT);

    private static void sweepCases() {
        for (Route route : List.of(Route.SHELL, Route.DEVICE)) {
            for (CommitMode mode : CommitMode.values()) {
                String name = "faults / sweep at every crossing on the " + route.toString().toLowerCase() + " route, "
                        + mode.toString().toLowerCase() + " commit";
                cases.run(name, problems -> {
                    Map<String, Integer> outcomes = new TreeMap<>();
                    int crossings = mode == CommitMode.LATE ? 6 : 5;
                    for (int k = 0; k < crossings + 2; k++) {
                        for (Fault fault : FAULTS) {
                            World w = world(route, 1000 + 31 * k + fault.ordinal());
                            Plan plan = plan(w, Fixtures.plan(1).commitMode(mode).signing(1 + k % 2));
                            w.android.faults.put(k, fault);
                            String id = w.open(plan, 1);
                            Ticket t = w.run(id, 60, true, mode == CommitMode.EARLY ? State.READY : null);
                            if (t.state == State.READY) {
                                w.android.kernelBoot(true);
                            }
                            t = finish(w, id);
                            consistent(w, plan, t, problems);
                            if (!problems.isEmpty()) {
                                problems.add("at crossing " + k + " with " + fault);
                                return;
                            }
                            outcomes.merge(t.state.toString(), 1, Integer::sum);
                            account(w, problems);
                        }
                    }
                    System.out.println("Sweep " + route + " " + mode + ": " + outcomes);
                });
            }
        }
        cases.run("faults / world events at every round", problems -> {
            Map<String, Integer> outcomes = new TreeMap<>();
            for (Route route : List.of(Route.SHELL, Route.DEVICE)) {
                for (int event = 0; event < 3; event++) {
                    for (int round = 0; round < 14; round++) {
                        World w = world(route, 2000 + 97 * event + round);
                        Plan plan = plan(w, Fixtures.plan(1));
                        String id = w.open(plan, 1);
                        for (int i = 0; i < round; i++) {
                            try {
                                w.coordinator.round(id);
                            } catch (AndroidFacade.Crash lost) {
                                w.coordinator = w.coordinator();
                            }
                            if (i % 3 == 2) w.android.tick(2000);
                        }
                        if (event == 0) w.android.frameworkRestart();
                        else if (event == 1) w.android.kernelBoot(false);
                        else {
                            w.android.holdCheckpoint = true;
                            w.android.kernelBoot(false);
                        }
                        Ticket t = w.run(id, 20, true);
                        w.android.holdCheckpoint = false;
                        t = finish(w, id);
                        consistent(w, plan, t, problems);
                        if (!problems.isEmpty()) {
                            problems.add(route + " event " + event + " at round " + round);
                            return;
                        }
                        outcomes.merge(t.state.toString(), 1, Integer::sum);
                        account(w, problems);
                    }
                }
            }
            System.out.println("World events: " + outcomes);
        });
    }

    private static void invariantCases() {
        cases.run("invariants / every run kept every invariant", problems -> {
            check(problems, violations == 0, violations + " violations");
            check(problems, runs > 300 && calls > 2000, runs + " runs, " + calls + " crossings checked");
            System.out.println("Invariants held in " + runs + " runs over " + calls + " crossings");
        });
    }

    public static void main(String[] args) throws Exception {
        Cases.requireAssertions(TransactionTest.class);
        if (args.length != 1) throw new IllegalArgumentException("a fresh state directory is required");
        root = Path.of(args[0]);
        Files.createDirectories(root);
        try (var listing = Files.list(root)) {
            if (listing.findAny().isPresent()) throw new IllegalArgumentException("state directory not fresh");
        }
        flowCases();
        recoveryCases();
        decisionCases();
        cohortCases();
        sweepCases();
        invariantCases();
        cases.finish("Deployment transaction checks passed");
    }
}
