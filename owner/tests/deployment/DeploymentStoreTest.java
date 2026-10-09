// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import static dev.andrix.server.deployment.Cases.check;
import static dev.andrix.server.deployment.DeploymentRecords.NO_ID;
import static dev.andrix.server.deployment.Fixtures.INSTALLATION;
import static dev.andrix.server.deployment.Fixtures.TIME;
import static dev.andrix.server.deployment.Fixtures.id;

import dev.andrix.server.deployment.DeploymentRecords.Authorization;
import dev.andrix.server.deployment.DeploymentRecords.Cause;
import dev.andrix.server.deployment.DeploymentRecords.ChoiceKind;
import dev.andrix.server.deployment.DeploymentRecords.Effect;
import dev.andrix.server.deployment.DeploymentRecords.Observation;
import dev.andrix.server.deployment.DeploymentRecords.Plan;
import dev.andrix.server.deployment.DeploymentRecords.Realization;
import dev.andrix.server.deployment.DeploymentRecords.Selection;
import dev.andrix.server.deployment.DeploymentRecords.State;
import dev.andrix.server.deployment.DeploymentRecords.Target;
import dev.andrix.server.deployment.DeploymentRecords.Ticket;
import dev.andrix.server.deployment.DeploymentRecords.UpdateResponsibility;
import dev.andrix.server.deployment.DeploymentStore.Found;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;

/**
 * Host checks of durable deployment storage with every sync: write once records, compare and set
 * updates, a crash at each step of the write protocol, presence and footprints, the one open
 * ticket rule and the selection's revision rules. Host JVM only: a process crash, not power loss.
 */
public final class DeploymentStoreTest {
    private static final Cases cases = new Cases();
    private static Path root;
    private static int stores;

    /** A crash at one write step. */
    private static final class Stop extends IOException {
        private static final long serialVersionUID = 1L;

        Stop(String step) { super(step); }
    }

    private static Path fresh() throws IOException {
        Path dir = root.resolve("store-" + (++stores));
        Files.createDirectories(dir);
        return dir;
    }

    private static DeploymentStore store(Path dir) throws IOException {
        DeploymentStore store = new DeploymentStore(dir, INSTALLATION);
        store.initialize();
        return store;
    }

    private static Selection initial() {
        return new Selection(INSTALLATION, Fixtures.COMPONENT, 0, ChoiceKind.FACTORY, NO_ID,
                UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.UNCHECKED, NO_ID, NO_ID, NO_ID, TIME);
    }

    private static void cases() {
        cases.run("store / round trip of every kind", problems -> {
            DeploymentStore store = store(fresh());
            Plan plan = DeploymentRecordsTest.planLateOne();
            check(problems, store.addPlan(plan) && store.plan(plan.planId).value.equals(plan), "plan");
            Authorization sign = DeploymentRecordsTest.authSign();
            check(problems, store.addAuthorization(sign) && store.authorizationsOf(plan.planId).equals(List.of(sign)),
                    "authorization");
            Observation boot = DeploymentRecordsTest.obsBoot();
            check(problems, store.addObservation(boot) && store.observations().values.equals(List.of(boot)),
                    "observation");
            Ticket ticket = DeploymentRecordsTest.ticketPlanned();
            check(problems, store.createTicket(ticket) && store.ticket(ticket.ticketId).value.equals(ticket), "ticket");
            check(problems, store.putSelection(null, initial()) && store.selection(Fixtures.COMPONENT).value
                    .equals(initial()), "selection");
            for (DeploymentStore.Listing<?> listing : List.of(store.plans(), store.authorizations(), store.tickets(),
                    store.observations(), store.selections())) {
                check(problems, listing.footprints.isEmpty() && listing.values.size() == 1, "listing " + listing.values);
            }
        });
        cases.run("store / records are written once and read back as exact bytes", problems -> {
            DeploymentStore store = store(fresh());
            Plan plan = DeploymentRecordsTest.planLateOne();
            check(problems, store.addPlan(plan) && store.addPlan(plan), "the same bytes again");
            check(problems, !store.addPlan(plan.toBuilder().createdAt(TIME + 1).build()), "other bytes under the ID");
            Ticket ticket = DeploymentRecordsTest.ticketPlanned();
            check(problems, store.createTicket(ticket) && !store.createTicket(ticket), "a ticket created twice");
            check(problems, !store.addObservation(Fixtures.fact(1, id(5), DeploymentRecords.Classification
                    .BOOT_COMPLETED, 1).installation(id(0x77)).build()), "another installation");
        });
        cases.run("store / a crash at each write step leaves the old record or the new one", problems -> {
            Plan plan = DeploymentRecordsTest.planLateOne();
            Ticket planned = DeploymentRecordsTest.ticketPlanned();
            Ticket next = planned.toBuilder().state(State.AUTHORIZED).build();
            for (String at : DeploymentStore.STEPS) {
                Path dir = fresh();
                store(dir).addPlan(plan);
                DeploymentStore crashing = new DeploymentStore(dir, INSTALLATION, step -> {
                    if (step.equals(at)) throw new Stop(step);
                }, true);
                check(problems, !crashing.createTicket(planned), "create survived a crash at " + at);
                DeploymentStore reopened = store(dir);
                DeploymentStore.Read<Ticket> read = reopened.ticket(planned.ticketId);
                boolean renamed = DeploymentStore.STEPS.indexOf(at) >= DeploymentStore.STEPS.indexOf("renamed");
                check(problems, renamed ? read.found == Found.RECORD && read.value.equals(planned)
                        : read.found == Found.ABSENT, "create crashed at " + at + ": " + read.found);
                check(problems, reopened.tickets().footprints.isEmpty(), "a staging file listed at " + at);
                if (!renamed) check(problems, reopened.createTicket(planned), "create after a crash at " + at);
                DeploymentStore crashingUpdate = new DeploymentStore(dir, INSTALLATION, step -> {
                    if (step.equals(at)) throw new Stop(step);
                }, true);
                check(problems, !crashingUpdate.updateTicket(planned, next), "update survived a crash at " + at);
                DeploymentStore.Read<Ticket> after = store(dir).ticket(planned.ticketId);
                check(problems, after.found == Found.RECORD && after.value.equals(renamed ? next : planned),
                        "update crashed at " + at);
                Ticket current = after.value;
                check(problems, current.equals(next) || store(dir).updateTicket(planned, next), "update retried at " + at);
            }
        });
        cases.run("store / staging leftovers are never records", problems -> {
            Path dir = fresh();
            DeploymentStore store = store(dir);
            Files.write(dir.resolve("tickets/." + id(9) + ".rec.staging"), new byte[] {1, 2, 3});
            check(problems, store.tickets().values.isEmpty() && store.tickets().footprints.isEmpty(), "listed");
            Ticket ticket = DeploymentRecordsTest.ticketPlanned();
            store.addPlan(DeploymentRecordsTest.planLateOne());
            Files.write(dir.resolve("tickets/." + ticket.ticketId + ".rec.staging"), new byte[] {9});
            check(problems, store.createTicket(ticket), "a leftover blocked the writer");
        });
        cases.run("store / presence as absent, damaged, newer or unavailable", problems -> {
            Path dir = fresh();
            DeploymentStore store = store(dir);
            check(problems, store.ticket(id(1)).found == Found.ABSENT, "absent");
            Files.createSymbolicLink(dir.resolve("tickets/" + id(2) + ".rec"), dir.resolve("plans"));
            check(problems, store.ticket(id(2)).found == Found.DAMAGED, "a link");
            Files.createDirectory(dir.resolve("tickets/" + id(3) + ".rec"));
            check(problems, store.ticket(id(3)).found == Found.DAMAGED, "a directory");
            byte[] ticket = DeploymentRecords.encodeTicket(DeploymentRecordsTest.ticketWindow());
            Files.write(dir.resolve("tickets/" + id(0x403) + ".rec"), DeploymentRecordsTest.relabel(ticket, 2));
            DeploymentStore.Read<Ticket> newer = store.ticket(id(0x403));
            check(problems, newer.found == Found.NEWER && newer.prefix != null
                    && newer.prefix.component.equals(Fixtures.COMPONENT), "newer " + newer.found);
            Files.write(dir.resolve("tickets/" + id(4) + ".rec"), new byte[] {1});
            check(problems, store.ticket(id(4)).found == Found.DAMAGED, "short bytes");
            Path locked = dir.resolve("tickets/" + id(5) + ".rec");
            Files.write(locked, ticket);
            Files.setPosixFilePermissions(locked, PosixFilePermissions.fromString("---------"));
            boolean enforced = !Files.isReadable(locked);
            check(problems, enforced, "DAC not enforced: run unprivileged");
            check(problems, store.ticket(id(5)).found == Found.UNAVAILABLE, "unreadable " + store.ticket(id(5)).found);
            Path hidden = dir.resolve("selections");
            Files.setPosixFilePermissions(hidden, PosixFilePermissions.fromString("---------"));
            check(problems, store.selection(Fixtures.COMPONENT).found == Found.UNAVAILABLE, "unsearchable directory");
            Files.setPosixFilePermissions(hidden, PosixFilePermissions.fromString("rwx------"));
            if (enforced) System.out.println("Unprivileged DAC refused both probes");
            Files.setPosixFilePermissions(locked, PosixFilePermissions.fromString("rw-------"));
        });
        cases.run("store / newer, damaged and unknown ticket files block every new ticket", problems -> {
            for (int kind = 0; kind < 3; kind++) {
                Path dir = fresh();
                DeploymentStore store = store(dir);
                Plan plan = Fixtures.plan(7).component("dev.andrix.other").build();
                store.addPlan(plan);
                byte[] ticket = DeploymentRecords.encodeTicket(DeploymentRecordsTest.ticketWindow());
                Path file = dir.resolve("tickets/" + id(0x403) + ".rec");
                if (kind == 0) Files.write(file, DeploymentRecordsTest.relabel(ticket, 2));
                if (kind == 1) Files.write(file, new byte[] {7});
                if (kind == 2) Files.write(dir.resolve("tickets/unknown"), new byte[0]);
                check(problems, !store.createTicket(Fixtures.ticket(1, plan).build()), "kind " + kind + " ignored");
                check(problems, !store.tickets().footprints.isEmpty(), "kind " + kind + " left no footprint");
            }
        });
        cases.run("store / one open ticket per component and attempts in order", problems -> {
            DeploymentStore store = store(fresh());
            Plan a = Fixtures.plan(1).build(), b = Fixtures.plan(2).build();
            Plan other = Fixtures.plan(3).component("dev.andrix.other").build();
            store.addPlan(a);
            store.addPlan(b);
            store.addPlan(other);
            Ticket first = Fixtures.ticket(1, a).build();
            check(problems, store.createTicket(first), "first");
            check(problems, !store.createTicket(Fixtures.ticket(2, b).build()), "a second open ticket");
            check(problems, store.createTicket(Fixtures.ticket(3, other).build()), "another component");
            Ticket cancelled = first.toBuilder().cause(Cause.CANCELLED).state(State.CANCELLED).build();
            check(problems, store.updateTicket(first, first.toBuilder().cause(Cause.CANCELLED).build())
                    && store.updateTicket(first.toBuilder().cause(Cause.CANCELLED).build(), cancelled), "closed");
            check(problems, !store.createTicket(Fixtures.ticket(4, a).attempt(1).build()), "attempt 1 again");
            check(problems, !store.createTicket(Fixtures.ticket(4, a).attempt(3).build()), "attempt 3 early");
            check(problems, store.createTicket(Fixtures.ticket(4, a).attempt(2).build()), "attempt 2");
            check(problems, !store.createTicket(Fixtures.ticket(5, Fixtures.plan(9).build()).build()), "unknown plan");
        });
        cases.run("store / ticket updates must be legal steps from the exact stored bytes", problems -> {
            DeploymentStore store = store(fresh());
            Plan plan = Fixtures.plan(1).build();
            store.addPlan(plan);
            Ticket t = Fixtures.ticket(1, plan).build();
            store.createTicket(t);
            Ticket authorized = t.toBuilder().state(State.AUTHORIZED).build();
            check(problems, !store.updateTicket(authorized, authorized.toBuilder().state(State.SIGNING).build()),
                    "a stale expected value");
            check(problems, !store.updateTicket(t, t.toBuilder().state(State.SIGNED).build()), "an illegal step");
            check(problems, store.updateTicket(t, authorized), "a legal step");
            check(problems, store.ticket(t.ticketId).value.equals(authorized), "read back");
        });
        cases.run("store / a selection's choice changes only with the next revision", problems -> {
            DeploymentStore store = store(fresh());
            Plan plan = Fixtures.plan(1).build();
            Selection first = initial();
            check(problems, !store.putSelection(null, first.realized(Realization.CURRENT, id(1), NO_ID, NO_ID)),
                    "a first selection already checked");
            check(problems, store.putSelection(null, first), "first");
            check(problems, !store.putSelection(null, first), "first twice");
            Selection same = new Selection(INSTALLATION, Fixtures.COMPONENT, 0, ChoiceKind.PLAN, plan.planId,
                    UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.UNCHECKED, NO_ID, NO_ID, NO_ID, TIME);
            check(problems, !store.putSelection(first, same), "the choice moved at the same revision");
            Selection unknown = first.chosen(ChoiceKind.PLAN, plan.planId, Realization.CURRENT, id(1), TIME);
            check(problems, !store.putSelection(first, unknown), "a choice of an unknown plan");
            store.addPlan(plan);
            Selection skip = new Selection(INSTALLATION, Fixtures.COMPONENT, 2, ChoiceKind.PLAN, plan.planId,
                    UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.CURRENT, id(1), NO_ID, NO_ID, TIME);
            check(problems, !store.putSelection(first, skip), "a revision skipped");
            check(problems, store.putSelection(first, unknown), "the next revision");
            Selection responsibility = new Selection(INSTALLATION, Fixtures.COMPONENT, 1, ChoiceKind.PLAN, plan.planId,
                    UpdateResponsibility.KEEP_STALE, 0, Realization.CURRENT, id(1), NO_ID, NO_ID, TIME);
            check(problems, !store.putSelection(unknown, responsibility), "the responsibility at the same revision");
        });
        cases.run("store / the realization changes only at the same revision", problems -> {
            DeploymentStore store = store(fresh());
            Selection first = initial();
            store.putSelection(null, first);
            Selection checked = first.realized(Realization.DIVERGED, id(1), NO_ID, NO_ID);
            check(problems, store.putSelection(first, checked), "realized");
            Selection bumped = new Selection(INSTALLATION, Fixtures.COMPONENT, 1, ChoiceKind.FACTORY, NO_ID,
                    UpdateResponsibility.REBUILD_WINDOW, Fixtures.WINDOW, Realization.CURRENT, id(2), NO_ID, NO_ID, TIME);
            check(problems, !store.putSelection(checked, bumped), "a revision without a choice change");
            check(problems, !store.putSelection(first, checked.realized(Realization.CURRENT, id(2), NO_ID, NO_ID)),
                    "a stale expected selection");
        });
        cases.run("store / a temporary factory state names its stored stand-in and keeps the choice", problems -> {
            DeploymentStore store = store(fresh());
            Plan chosen = Fixtures.plan(1).build();
            Plan temporary = DeploymentRecordsTest.planTemporary();
            store.addPlan(chosen);
            Selection first = initial();
            store.putSelection(null, first);
            Selection moved = first.chosen(ChoiceKind.PLAN, chosen.planId, Realization.CURRENT, id(1), TIME);
            check(problems, store.putSelection(first, moved), "the choice moved");
            Selection standIn = moved.realized(Realization.TEMPORARY_FACTORY, id(2), NO_ID, temporary.planId);
            check(problems, !store.putSelection(moved, standIn), "an unstored temporary plan");
            store.addPlan(temporary);
            check(problems, store.putSelection(moved, standIn), "the temporary factory state");
            Selection read = store.selection(Fixtures.COMPONENT).value;
            check(problems, read.choice == ChoiceKind.PLAN && read.planId.equals(chosen.planId) && read.revision == 1,
                    "the choice changed " + read);
            Plan stranger = Fixtures.plan(6).target(Target.TEMPORARY_FACTORY).repairs(id(0x1ff)).build();
            store.addPlan(stranger);
            check(problems, !store.putSelection(standIn, standIn.realized(Realization.TEMPORARY_FACTORY, id(3), NO_ID,
                    stranger.planId)), "a stand-in for another plan");
        });
        cases.run("store / file names repeat the record's ID", problems -> {
            Path dir = fresh();
            DeploymentStore store = store(dir);
            Plan plan = DeploymentRecordsTest.planLateOne();
            store.addPlan(plan);
            Files.copy(dir.resolve("plans/" + plan.planId + ".rec"), dir.resolve("plans/" + id(0x999) + ".rec"));
            check(problems, store.plan(id(0x999)).found == Found.DAMAGED, "a renamed record read");
            check(problems, store.plans().values.size() == 1 && store.plans().footprints.size() == 1, "listing");
        });
        cases.run("store / authorizations need their stored plan of the same component", problems -> {
            DeploymentStore store = store(fresh());
            Plan plan = DeploymentRecordsTest.planLateOne();
            Authorization sign = DeploymentRecordsTest.authSign();
            check(problems, !store.addAuthorization(sign), "without its plan");
            store.addPlan(plan.toBuilder().component("dev.andrix.other").build());
            check(problems, !store.addAuthorization(sign), "a plan of another component");
            DeploymentStore second = store(fresh());
            second.addPlan(plan);
            check(problems, second.addAuthorization(sign), "with its plan");
            check(problems, !second.addAuthorization(Fixtures.grant(1, plan, Effect.STAGE, 0, TIME)), "another grant "
                    + "under the same ID");
        });
        cases.run("store / every write follows the protocol's steps in order", problems -> {
            Path dir = fresh();
            store(dir);
            List<String> seen = new ArrayList<>();
            DeploymentStore traced = new DeploymentStore(dir, INSTALLATION, seen::add, true);
            traced.addPlan(DeploymentRecordsTest.planLateOne());
            traced.putSelection(null, initial());
            check(problems, seen.equals(List.of("staged", "synced", "renamed", "parent-synced", "staged", "synced",
                    "renamed", "parent-synced")), "steps " + seen);
        });
    }

    public static void main(String[] args) throws Exception {
        Cases.requireAssertions(DeploymentStoreTest.class);
        if (args.length != 1) throw new IllegalArgumentException("a fresh state directory is required");
        root = Path.of(args[0]);
        Files.createDirectories(root);
        try (var listing = Files.list(root)) {
            if (listing.findAny().isPresent()) throw new IllegalArgumentException("state directory not fresh");
        }
        cases();
        cases.finish("Deployment store checks passed");
    }
}
