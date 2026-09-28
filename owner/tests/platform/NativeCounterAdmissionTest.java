// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeBindingTestSupport.*;
import static com.android.server.pm.NativeHeaderTestSupport.*;

import android.system.Os;
import com.android.server.LocalServices;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.HeaderEntry;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.UserEntry;
import com.android.server.pm.NativeIdentityStore.Status;
import com.android.server.pm.NativePrincipalPins.Phase;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Counter admission over the actual records, store, persistence, manager and host PMS facade.
 * When the selected header is valid, a principal ID above its counter in any decoded slot copy
 * of its lineage, or in any decoded copy of a record that is already negative evidence, blocks
 * new issuance. It changes no status, binding, hold, evidence, header byte or footprint flag,
 * and no counter is raised or derived. Existing eligible bindings still confirm, mark and
 * retire. The same source also runs against the pinned 0018a1d and 89491b9 sources, through
 * only the surface they share and each side's own NativeHistoryHarness, as baseline controls.
 * OBSERVE lines report each layout's facts and readiness for the runner's comparison across the
 * three sides. Quiescence here is synthetic. Host facades only: not Android boot, crash,
 * storage, SELinux, native Stop or UID authority qualification, and no data or key disposal.
 */
public final class NativeCounterAdmissionTest {
    private static final List<NativeIdentityStore.Format> FORMATS = List.of(V1, V2);
    private static final String REFUSED = "Native identity issuance requires recovery";
    // A creation binding's signers and a body's other signers.
    private static final Set<String> S0 = Set.of("a0".repeat(32)), S1 = Set.of("b1".repeat(32));

    private static Header hdr(NativeIdentityStore.Format format, long lastId, HeaderEntry... entries) {
        return format == V1 ? header(lastId, entries) : v2(lastId, entries);
    }

    // A store whose main and reserve header copies are this header, with no slot.
    private static Path paired(Header selected) throws Exception {
        return layout(null, bytes(selected), bytes(selected));
    }

    private static byte[] encoded(Slot slot) {
        return NativeIdentityRecords.encodeSlot(slot);
    }

    // A body of one principal of this user, in the store's lineage, with the facade's signer.
    private static Slot user(int appId, String name, long id, int userId) {
        return new Slot(LINEAGE, appId, name, 1, SIGNERS, List.of(new UserEntry(id, userId, SERIAL, false)));
    }

    private static Slot users(int appId, String name, long first, long second) {
        return new Slot(LINEAGE, appId, name, 1, SIGNERS, List.of(new UserEntry(first, 0, SERIAL, false),
                new UserEntry(second, 1, SERIAL, false)));
    }

    // A slot directory with exactly these copies. A null copy is absent.
    private static void slotCopies(Path root, int appId, byte[] main, byte[] reserve, byte[] backup)
            throws Exception {
        Path directory = Files.createDirectory(root.resolve("slots/" + appId));
        if (main != null) Files.write(directory.resolve("record.bin"), main);
        if (reserve != null) Files.write(directory.resolve("record.bin.reservecopy"), reserve);
        if (backup != null) Files.write(directory.resolve("record.bin-backup"), backup);
    }

    private static String inputs(NativeHistoryHarness.Inputs inputs) {
        StringBuilder text = new StringBuilder();
        for (NativePrincipalPins.Record record : inputs.records) {
            text.append(record.id).append('/').append(record.packageName).append('/')
                    .append(record.appId).append('/').append(record.userId).append('/')
                    .append(record.userSerial).append(',');
        }
        return text.append(" retiring=").append(new TreeSet<>(inputs.retiring)).toString();
    }

    // What the correction must not change: header, statuses, eligible bindings, holds, footprint
    // flags and the published bodies that restoration takes, through this side's own adapter.
    private static String facts(NativeIdentityStore.Loaded view) {
        StringBuilder text = new StringBuilder("header=").append(view.header.status);
        if (view.header.value != null) {
            text.append(':').append(view.header.value.version).append(':')
                    .append(view.header.value.lastId).append(':').append(view.header.value.entries.size());
        }
        text.append(" slots=");
        for (Map.Entry<Integer, NativeIdentityStore.ReadResult<Slot>> entry
                : new TreeMap<>(view.slots).entrySet()) {
            text.append(entry.getKey()).append(':').append(entry.getValue().status)
                    .append(entry.getValue().unavailable ? ":unavailable" : "")
                    .append(view.bindingUsable(entry.getKey()) ? ":usable" : "")
                    .append(':').append(entry.getValue().decodedCopies.size()).append(',');
        }
        text.append(" holds=").append(new TreeSet<>(view.occupiedAppIds))
                .append(" flags=").append(view.enumerationComplete ? 'C' : '-')
                .append(view.unsupportedFootprint ? 'U' : '-')
                .append(view.unavailableFootprint ? 'A' : '-')
                .append(view.unselectedFootprint ? 'S' : '-')
                .append(" body=").append(inputs(NativeHistoryHarness.bodyInputs(view)));
        return text.toString();
    }

    // One read of a counter layout, reported for the runner before any check can stop the case.
    private static NativeIdentityStore.Loaded observed(String label, Path root,
            NativeIdentityStore.Format format) {
        NativeIdentityStore.Loaded view = loadedOf(root, format);
        System.out.println("OBSERVE\t" + label + "\t" + format + "\t" + facts(view) + "\tready="
                + view.creationReady() + "\trestorable=" + view.counterRestorable());
        return view;
    }

    // A view the correction blocks: no creation and no counter, and a reopened registry with no
    // counter. No footprint flag stands in for the block.
    private static void blocked(List<String> problems, String what, Path root,
            NativeIdentityStore.Format format, NativeIdentityStore.Loaded view) {
        check(problems, view.header.status == Status.VALID && view.enumerationComplete
                && !view.creationReady() && !view.counterRestorable()
                && !view.unsupportedFootprint && !view.unavailableFootprint,
                what + " not blocked: ready " + view.creationReady() + " " + facts(view));
        bootCounterOf(problems, root, format, -1);
    }

    // A view that stays creation ready, whose reopened registry restores exactly this counter.
    private static void admits(List<String> problems, String what, Path root,
            NativeIdentityStore.Format format, NativeIdentityStore.Loaded view, long counter) {
        check(problems, view.header.status == Status.VALID && view.creationReady()
                && view.counterRestorable() && view.header.value.lastId == counter,
                what + " blocked: " + facts(view));
        bootCounterOf(problems, root, format, counter);
    }

    // The message of the IllegalStateException that refuses a call, or what happened instead.
    private static String refusal(Call<?> call) {
        try {
            Object value = call.run();
            return "returned " + (value == null ? "null" : value.getClass().getSimpleName());
        } catch (IllegalStateException refused) {
            return refused.getMessage();
        } catch (Exception other) {
            return "threw " + other.getClass().getSimpleName() + ": " + other.getMessage();
        }
    }

    // The same bytes of one decoded slot copy restored as the pin of its eligible body only.
    private static void restoredBody(List<String> problems, String what, Path root,
            NativeIdentityStore.Format format, String name, int appId, long id) {
        PackageManagerService pm = reopenOf(root, format, Map.of());
        NativePrincipalPins.Pin pin = pm.mSettings.pins.find(name, 0);
        check(problems, pin != null && pin.phase() == Phase.PENDING
                && pin.record().equals(record(id, name, appId)) && !pm.mSettings.pins.hasKnownCounter()
                && pm.mSettings.isNativePrincipalAppIdLPr(appId), what + " restored " + pin);
    }

    // Unsupported users, selected and unselected copies, conflicts, damage and aliases.
    private static void gates() {
        run("gate / a nonzero user above the counter", problems -> {
            for (NativeIdentityStore.Format format : FORMATS) {
                Path root = paired(hdr(format, 1, live(B)));
                slot(root, B, user(B, PKG_B, 2, 1));
                NativeIdentityStore.Loaded view = observed("nonzero-user-above", root, format);
                check(problems, view.slots.get(B).status == Status.UNSUPPORTED && !view.bindingUsable(B)
                        && !view.unselectedFootprint && view.occupiedAppIds.equals(Set.of(B)),
                        format + " facts " + facts(view));
                blocked(problems, format + " N", root, format, view);
            }
        });
        run("control / a nonzero user within the counter", problems -> {
            for (NativeIdentityStore.Format format : FORMATS) {
                Path root = paired(hdr(format, 1, live(B)));
                slot(root, B, user(B, PKG_B, 1, 1));
                NativeIdentityStore.Loaded view = observed("nonzero-user-within", root, format);
                check(problems, view.slots.get(B).status == Status.UNSUPPORTED && !view.bindingUsable(B),
                        format + " facts " + facts(view));
                admits(problems, format + " N", root, format, view, 1);
            }
        });
        run("control / a selected body above the counter blocks as before", problems -> {
            for (NativeIdentityStore.Format format : FORMATS) {
                Path root = paired(hdr(format, 1, live(B)));
                slot(root, B, bound(B, PKG_B, 2, false, 1));
                NativeIdentityStore.Loaded view = observed("selected-body-above", root, format);
                check(problems, view.slots.get(B).status == Status.CONFLICT && !view.bindingUsable(B),
                        format + " facts " + facts(view));
                blocked(problems, format + " N", root, format, view);
            }
        });
        run("gate / a stale copy beside a selected backup", problems -> {
            for (NativeIdentityStore.Format format : FORMATS) {
                Path root = paired(hdr(format, 1, live(B)));
                Slot selected = bound(B, PKG_B, 1, false, 1), stale = bound(B, PKG_B, 2, false, 1);
                slotCopies(root, B, encoded(stale), encoded(stale), encoded(selected));
                NativeIdentityStore.Loaded view = observed("stale-copies-beside-backup", root, format);
                check(problems, view.slots.get(B).status == Status.VALID && view.bindingUsable(B)
                        && selected.equals(view.slots.get(B).value), format + " facts " + facts(view));
                blocked(problems, format + " N", root, format, view);
                restoredBody(problems, format + " N", root, format, PKG_B, B, 1);
            }
        });
        run("control / an unselected copy of another package keeps ordinary bindings", problems -> {
            for (NativeIdentityStore.Format format : FORMATS) {
                Path root = paired(hdr(format, 2, live(B), live(D)));
                Slot other = user(B, PKG_X, 1, 0);
                slotCopies(root, B, encoded(other), encoded(other), encoded(bound(B, PKG_B, 1, false, 1)));
                slot(root, D, bound(D, PKG_X, 2, false, 1));
                NativeIdentityStore.Loaded view = observed("unselected-other-package", root, format);
                check(problems, view.slots.get(B).status == Status.VALID && view.bindingUsable(B)
                        && view.slots.get(D).status == Status.VALID && view.bindingUsable(D),
                        format + " facts " + facts(view));
                admits(problems, format + " N", root, format, view, 2);
            }
        });
        run("gate / conflicting copies without a backup", problems -> {
            for (NativeIdentityStore.Format format : FORMATS) {
                Path root = paired(hdr(format, 1, live(B)));
                slotCopies(root, B, encoded(bound(B, PKG_B, 1, false, 1)),
                        encoded(bound(B, PKG_B, 2, false, 1)), null);
                NativeIdentityStore.Loaded view = observed("conflicting-copies", root, format);
                check(problems, view.slots.get(B).status == Status.CONFLICT && !view.bindingUsable(B),
                        format + " facts " + facts(view));
                blocked(problems, format + " N", root, format, view);
            }
        });
        run("gate / a damaged preferred backup beside decoded copies", problems -> {
            for (NativeIdentityStore.Format format : FORMATS) {
                Header selected = hdr(format, 1, live(B));
                Path root = paired(selected);
                Slot higher = bound(B, PKG_B, 2, false, 1);
                slotCopies(root, B, encoded(higher), encoded(higher), GARBAGE);
                NativeIdentityStore.Loaded view = observed("damaged-backup", root, format);
                // No header or body fallback: the selection and the damage stay as they were.
                check(problems, view.slots.get(B).status == Status.DAMAGED && !view.bindingUsable(B)
                        && view.slots.get(B).decodedCopies.size() == 2 && selected.equals(view.header.value),
                        format + " facts " + facts(view));
                blocked(problems, format + " N", root, format, view);
                check(problems, reopenOf(root, format, Map.of()).mSettings.pins.find(PKG_B, 0) == null,
                        format + " a damaged body was restored");
            }
        });
        run("gate / a body naming another app ID", problems -> {
            for (NativeIdentityStore.Format format : FORMATS) {
                Path root = paired(hdr(format, 1, live(B)));
                slot(root, B, user(C, PKG_C, 2, 0));
                NativeIdentityStore.Loaded view = observed("body-names-other-app", root, format);
                check(problems, view.slots.get(B).status == Status.CONFLICT && !view.bindingUsable(B)
                        && view.slots.get(C) == null && view.occupiedAppIds.equals(Set.of(B)),
                        format + " facts " + facts(view));
                blocked(problems, format + " N", root, format, view);
                // Nothing is owned at the app ID the body names.
                PackageManagerService pm = reopenOf(root, format, Map.of(PKG_C, C));
                check(problems, pm.mSettings.pins.find(PKG_C, 0) == null
                        && !pm.mSettings.isNativePrincipalAppIdLPr(C), format + " ownership invented");
            }
        });
        run("control / an ordinary conflict of another lineage", problems -> {
            for (NativeIdentityStore.Format format : FORMATS) {
                Path root = paired(hdr(format, 1, live(B)));
                slot(root, B, new Slot(FOREIGN, B, PKG_B, 1, SIGNERS,
                        List.of(new UserEntry(2, 0, SERIAL, false))));
                NativeIdentityStore.Loaded view = observed("ordinary-other-lineage", root, format);
                check(problems, view.slots.get(B).status == Status.CONFLICT && !view.bindingUsable(B),
                        format + " facts " + facts(view));
                admits(problems, format + " N", root, format, view, 1);
            }
        });
        run("gate / an unsupported record of another lineage", problems -> {
            for (NativeIdentityStore.Format format : FORMATS) {
                Path root = paired(hdr(format, 1, live(B)));
                slot(root, B, new Slot(FOREIGN, B, PKG_B, 1, SIGNERS,
                        List.of(new UserEntry(2, 1, SERIAL, false))));
                NativeIdentityStore.Loaded view = observed("unsupported-other-lineage", root, format);
                check(problems, view.slots.get(B).status == Status.UNSUPPORTED && !view.bindingUsable(B),
                        format + " facts " + facts(view));
                blocked(problems, format + " N", root, format, view);
            }
        });
    }

    // The documented residual: an ordinary conflict of another lineage is no evidence and blocks
    // nothing, so an issued ID can meet its decoded copy, and the conservative release check then
    // strands that ID. Release authority is deliberately unchanged here.
    private static void residual() {
        run("residual / another lineage above the counter strands a later release", problems -> {
            Path root = paired(header(1, live(B)));
            slot(root, B, new Slot(FOREIGN, B, PKG_B, 1, SIGNERS, List.of(new UserEntry(2, 0, SERIAL, false))));
            PackageManagerService pm = reopenOf(root, V1, Map.of(PKG_B, B, PKG_C, C));
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle q = manager.prepare(manager.select(PKG_C, 0));
            check(problems, manager.identity(q).id == 2 && manager.commit(q), "Q beside the foreign copy");
            check(problems, manager.beginRetirement(q) && !manager.finishRetirementAfterQuiescence(q)
                    && manager.phase(q) == Phase.RETIRING && pm.mSettings.isNativePrincipalAppIdLPr(C),
                    "the documented residual changed");
        });
    }

    // A failed complete creation binding is already negative evidence: all of its decoded copies
    // count, in every position and lineage, beside an ordinary conflict too. Evidence, statuses
    // and holds are as before.
    private static void evidence() {
        Header held = v2(1, boundCreating(R, 1, PKG_R, S0));
        Slot mismatched = new Slot(LINEAGE, R, PKG_R, 1, S1, List.of(new UserEntry(1, 0, SERIAL, false)));
        Slot higher = new Slot(LINEAGE, R, PKG_R, 1, S1, List.of(new UserEntry(3, 0, SERIAL, false)));
        run("evidence / a failed binding keeps every higher copy", problems -> {
            // Main and reserve, main alone, then reserve alone name ID 3 beside the selected backup.
            String[] labels = {"failed-binding-higher-both", "failed-binding-higher-main",
                    "failed-binding-higher-reserve"};
            for (int position = 0; position < 3; position++) {
                Path root = paired(held);
                slotCopies(root, R, encoded(position == 2 ? mismatched : higher),
                        encoded(position == 1 ? mismatched : higher), encoded(mismatched));
                NativeIdentityStore.Loaded view = observed(labels[position], root, V2);
                check(problems, view.slots.get(R).status == Status.CONFLICT && !view.bindingUsable(R)
                        && view.occupiedAppIds.equals(Set.of(R)), position + " facts " + facts(view));
                blocked(problems, "position " + position, root, V2, view);
            }
        });
        run("evidence / a failed binding beside an ordinary conflict", problems -> {
            Path root = paired(held);
            Slot mixed = new Slot(LINEAGE, R, PKG_X, 1, S1, List.of(new UserEntry(1, 0, SERIAL, false)));
            Slot mixedHigher = new Slot(LINEAGE, R, PKG_X, 1, S1, List.of(new UserEntry(3, 0, SERIAL, false)));
            slotCopies(root, R, encoded(mixedHigher), encoded(mixedHigher), encoded(mixed));
            NativeIdentityStore.Loaded view = observed("failed-binding-mixed", root, V2);
            check(problems, view.slots.get(R).status == Status.CONFLICT && !view.bindingUsable(R),
                    "facts " + facts(view));
            blocked(problems, "R", root, V2, view);
        });
        run("evidence / a failed binding of another lineage", problems -> {
            // The selected backup header has this lineage. Main and reserve are another lineage's
            // copies, whose binding R's body of that lineage fails. They are incompatible, so no
            // counter was ever restorable; creation readiness is what the correction withdraws.
            Header foreignCopy = Header.newV2(FOREIGN, 1, List.of(boundCreating(R, 1, PKG_R, S0)));
            Path root = layout(bytes(held), bytes(foreignCopy), bytes(foreignCopy));
            Slot foreignR = new Slot(FOREIGN, R, PKG_R, 1, S1, List.of(new UserEntry(1, 0, SERIAL, false)));
            Slot foreignHigher = new Slot(FOREIGN, R, PKG_R, 1, S1, List.of(new UserEntry(3, 0, SERIAL, false)));
            slotCopies(root, R, encoded(foreignHigher), encoded(foreignHigher), encoded(foreignR));
            NativeIdentityStore.Loaded view = observed("failed-binding-other-lineage", root, V2);
            check(problems, held.equals(view.header.value) && view.unselectedFootprint
                    && view.slots.get(R).status == Status.CONFLICT && !view.bindingUsable(R),
                    "facts " + facts(view));
            blocked(problems, "R", root, V2, view);
        });
        run("evidence / a failed binding keeps a foreign slot copy under a known counter", problems -> {
            // No foreign header or unselected header addition can withhold this counter.
            // Only the binding-conflict evidence clause covers the foreign higher slot copy.
            Path root = paired(held);
            Slot foreignHigher = new Slot(FOREIGN, R, PKG_R, 1, S1,
                    List.of(new UserEntry(2, 0, SERIAL, false)));
            slotCopies(root, R, encoded(foreignHigher), encoded(foreignHigher), encoded(mismatched));
            NativeIdentityStore.Loaded view = observed("failed-binding-foreign-slot-copy", root, V2);
            check(problems, held.equals(view.header.value) && !view.unselectedFootprint
                    && !view.unsupportedFootprint && !view.unavailableFootprint
                    && view.slots.get(R).status == Status.CONFLICT && !view.bindingUsable(R),
                    "facts " + facts(view));
            blocked(problems, "foreign slot copy", root, V2, view);
            // Matching the selected binding makes the same foreign copy an ordinary residual.
            Header matching = v2(1, boundCreating(R, 1, PKG_R, S1));
            Path twin = paired(matching);
            slotCopies(twin, R, encoded(foreignHigher), encoded(foreignHigher), encoded(mismatched));
            NativeIdentityStore.Loaded matched = observed("matching-binding-foreign-slot-copy", twin, V2);
            check(problems, matched.slots.get(R).status == Status.VALID && matched.bindingUsable(R),
                    "matching binding " + facts(matched));
            admits(problems, "matching binding", twin, V2, matched, 1);
        });
        run("evidence / a failed binding keeps its sibling evidence", problems -> {
            Header beside = v2(2, boundCreating(R, 1, PKG_R, S0), live(C));
            for (boolean colliding : List.of(true, false)) {
                Path root = paired(beside);
                slotCopies(root, R, encoded(higher), encoded(higher), encoded(mismatched));
                slot(root, C, new Slot(LINEAGE, C, colliding ? PKG_R : PKG_X, 1, S1,
                        List.of(new UserEntry(2, 0, SERIAL, false))));
                NativeIdentityStore.Loaded view = observed(colliding ? "failed-binding-sibling-colliding"
                        : "failed-binding-sibling-unrelated", root, V2);
                check(problems, view.slots.get(R).status == Status.CONFLICT
                        && view.slots.get(C).status == (colliding ? Status.CONFLICT : Status.VALID)
                        && view.bindingUsable(C) == !colliding && view.occupiedAppIds.equals(Set.of(R, C)),
                        colliding + " facts " + facts(view));
                blocked(problems, "sibling " + colliding, root, V2, view);
            }
        });
    }

    // Staging, copy positions, user order, app ID order, healthy controls and the boundary.
    private static void placements() {
        run("selection / a higher unselected header counter is not the bound", problems -> {
            for (NativeIdentityStore.Format format : FORMATS) {
                Header selected = hdr(format, 1, live(B));
                Header ahead = hdr(format, 2, live(B), creating(D, 2, PKG_D));
                Path root = layout(bytes(selected), bytes(ahead), bytes(ahead));
                slotCopies(root, B, encoded(bound(B, PKG_B, 2, false, 1)),
                        encoded(bound(B, PKG_B, 2, false, 1)), encoded(bound(B, PKG_B, 1, false, 1)));
                NativeIdentityStore.Loaded view = observed("selected-below-unselected-header", root, format);
                check(problems, selected.equals(view.header.value) && view.unselectedFootprint
                        && view.slots.get(B).status == Status.VALID && view.bindingUsable(B),
                        "selection " + facts(view));
                blocked(problems, "selected counter", root, format, view);
            }
        });
        run("selection / a predecessor counter is not the bound", problems -> {
            Header selected = v2(3, live(B), boundCreating(D, 3, PKG_D));
            Header predecessor = header(1, live(B));
            Path root = layout(bytes(selected), bytes(predecessor), bytes(predecessor));
            slotCopies(root, B, encoded(bound(B, PKG_B, 3, false, 1)),
                    encoded(bound(B, PKG_B, 3, false, 1)), encoded(bound(B, PKG_B, 1, false, 1)));
            NativeIdentityStore.Loaded view = observed("selected-above-predecessor-header", root, V2);
            check(problems, selected.equals(view.header.value) && !view.unselectedFootprint
                    && view.slots.get(B).status == Status.VALID && view.bindingUsable(B),
                    "predecessor " + facts(view));
            admits(problems, "selected counter covers the copies", root, V2, view, 3);
        });
        run("control / a decodable staging seed is never counted", problems -> {
            for (NativeIdentityStore.Format format : FORMATS) {
                Path root = paired(hdr(format, 1, live(B)));
                slot(root, B, bound(B, PKG_B, 1, false, 1));
                Files.write(root.resolve("slots/" + B + "/record.bin-seed"), encoded(bound(B, PKG_B, 2, false, 2)));
                NativeIdentityStore.Loaded view = observed("decodable-seed", root, format);
                check(problems, view.slots.get(B).status == Status.VALID && view.bindingUsable(B),
                        format + " facts " + facts(view));
                admits(problems, format + " N", root, format, view, 1);
                NativePrincipalPins.Pin pin = reopenOf(root, format, Map.of()).mSettings.pins.find(PKG_B, 0);
                check(problems, pin != null && pin.record().equals(record(1, PKG_B, B)),
                        format + " the seed became history " + pin);
            }
        });
        Slot selected = bound(B, PKG_B, 1, false, 1), stale = bound(B, PKG_B, 2, false, 1);
        String[] labels = {"middle-copy", "main-copy", "reserve-copy"};
        String[] names = {"copies / a higher ID only in the middle copy", "copies / a higher ID only in main",
                "copies / a higher ID only in reserve without main"};
        for (int i = 0; i < labels.length; i++) {
            int position = i;
            run(names[position], problems -> {
                for (NativeIdentityStore.Format format : FORMATS) {
                    Path root = paired(hdr(format, 1, live(B)));
                    // Decoded copies are main, reserve, then the selected backup.
                    byte[] main = position == 0 ? encoded(selected) : position == 1 ? encoded(stale) : null;
                    byte[] reserve = position == 1 ? encoded(selected) : encoded(stale);
                    slotCopies(root, B, main, reserve, encoded(selected));
                    NativeIdentityStore.Loaded view = observed(labels[position], root, format);
                    check(problems, view.slots.get(B).status == Status.VALID && view.bindingUsable(B)
                            && selected.equals(view.slots.get(B).value), format + " facts " + facts(view));
                    blocked(problems, format + " N", root, format, view);
                    restoredBody(problems, format + " N", root, format, PKG_B, B, 1);
                }
            });
        }
        run("copies / a higher ID in either user order", problems -> {
            for (NativeIdentityStore.Format format : FORMATS) {
                for (boolean ascending : List.of(true, false)) {
                    Path root = paired(hdr(format, 1, live(B)));
                    slot(root, B, ascending ? users(B, PKG_B, 1, 2) : users(B, PKG_B, 2, 1));
                    NativeIdentityStore.Loaded view = observed(ascending ? "users-ascending-ids"
                            : "users-descending-ids", root, format);
                    check(problems, view.slots.get(B).status == Status.UNSUPPORTED,
                            format + " " + ascending + " facts " + facts(view));
                    blocked(problems, format + " " + ascending, root, format, view);
                }
            }
        });
        run("copies / a higher claim at either app ID order", problems -> {
            for (NativeIdentityStore.Format format : FORMATS) {
                for (int claimer : List.of(B, E)) {
                    Path root = paired(hdr(format, 1, live(A), live(claimer)));
                    slot(root, A, bound(A, PKG_A, 1, false, 1));
                    slot(root, claimer, user(claimer, PKG_X, 2, 1));
                    NativeIdentityStore.Loaded view = observed(claimer < A ? "claimer-below-sibling"
                            : "claimer-above-sibling", root, format);
                    check(problems, view.slots.get(claimer).status == Status.UNSUPPORTED && view.bindingUsable(A),
                            format + " " + claimer + " facts " + facts(view));
                    blocked(problems, format + " " + claimer, root, format, view);
                    restoredBody(problems, format + " A", root, format, PKG_A, A, 1);
                }
            }
        });
        run("control / healthy copies at or below the counter", problems -> {
            for (NativeIdentityStore.Format format : FORMATS) {
                Path root = paired(hdr(format, 2, live(A), live(B)));
                slot(root, A, bound(A, PKG_A, 1, false, 1));
                Slot lower = bound(B, PKG_B, 1, false, 1);
                slotCopies(root, B, encoded(lower), encoded(lower), encoded(bound(B, PKG_B, 2, false, 1)));
                NativeIdentityStore.Loaded view = observed("healthy-at-or-below", root, format);
                check(problems, view.bindingUsable(A) && view.bindingUsable(B), format + " facts " + facts(view));
                admits(problems, format + " A and N", root, format, view, 2);
            }
        });
        run("boundary / a Long.MAX_VALUE claim never becomes the counter", problems -> {
            for (NativeIdentityStore.Format format : FORMATS) {
                for (boolean unsupported : List.of(false, true)) {
                    Path root = paired(hdr(format, 1, live(B)));
                    if (unsupported) {
                        slot(root, B, user(B, PKG_B, Long.MAX_VALUE, 1));
                    } else {
                        Slot claim = bound(B, PKG_B, Long.MAX_VALUE, false, 1);
                        slotCopies(root, B, encoded(claim), encoded(claim), encoded(selected));
                    }
                    NativeIdentityStore.Loaded view = observed(unsupported ? "max-claim-unsupported"
                            : "max-claim-stale-copy", root, format);
                    check(problems, view.header.value.lastId == 1 && view.bindingUsable(B) == !unsupported,
                            format + " " + unsupported + " facts " + facts(view));
                    blocked(problems, format + " " + unsupported, root, format, view);
                    PackageManagerService pm = reopenOf(root, format, Map.of(PKG_B, B, PKG_C, C));
                    NativePrincipalManager manager = new NativePrincipalManager(pm);
                    check(problems, !pm.mSettings.pins.hasKnownCounter()
                            && REFUSED.equals(refusal(() -> manager.prepare(manager.select(PKG_C, 0))))
                            && storedOf(root, format).lastId == 1, format + " " + unsupported + " counter");
                }
            }
        });
        run("boundary / an ID equal to the counter passes without a counter change", problems -> {
            for (NativeIdentityStore.Format format : FORMATS) {
                for (boolean unsupported : List.of(true, false)) {
                    Path root = paired(hdr(format, 2, live(B)));
                    if (unsupported) {
                        slot(root, B, user(B, PKG_B, 2, 1));
                    } else {
                        slotCopies(root, B, encoded(stale), encoded(stale), encoded(selected));
                    }
                    NativeIdentityStore.Loaded view = observed(unsupported ? "equal-unsupported"
                            : "equal-stale-copy", root, format);
                    admits(problems, format + " " + unsupported, root, format, view, 2);
                    PackageManagerService pm = reopenOf(root, format, Map.of(PKG_B, B, PKG_C, C));
                    NativePrincipalManager manager = new NativePrincipalManager(pm);
                    NativePrincipalManager.Handle q = manager.prepare(manager.select(PKG_C, 0));
                    check(problems, manager.identity(q).id == 3 && manager.commit(q)
                            && hdr(format, 3, live(B), live(C)).equals(storedOf(root, format)),
                            format + " " + unsupported + " next issuance " + storedOf(root, format));
                }
            }
        });
        run("control / an ordinary conflict gives no sibling evidence", problems -> {
            for (NativeIdentityStore.Format format : FORMATS) {
                Path root = paired(hdr(format, 2, live(B), live(D)));
                slotCopies(root, B, encoded(bound(B, PKG_B, 1, false, 1)), encoded(user(B, PKG_X, 1, 0)), null);
                slot(root, D, bound(D, PKG_X, 2, false, 1));
                NativeIdentityStore.Loaded view = observed("ordinary-conflict-sibling", root, format);
                check(problems, view.slots.get(B).status == Status.CONFLICT
                        && view.slots.get(D).status == Status.VALID && view.bindingUsable(D),
                        format + " facts " + facts(view));
                admits(problems, format + " D", root, format, view, 2);
            }
        });
    }

    // The history view's strict creation gate composes: a counter block withdraws a complete
    // header reservation, as every other creation block does, and keeps each eligible body.
    private static void composition() {
        run("composition / a counter block withdraws a reservation and keeps bodies", problems -> {
            Path root = paired(v2(2, live(A), live(B), boundCreating(R, 2, PKG_R)));
            slot(root, A, bound(A, PKG_A, 1, false, 1));
            slot(root, B, user(B, PKG_B, 3, 1));
            NativeIdentityStore.Loaded view = observed("counter-blocked-reservation", root, V2);
            NativeHistoryHarness.Inputs restore = NativeHistoryHarness.restoreInputs(view);
            NativeHistoryHarness.Inputs bodies = NativeHistoryHarness.bodyInputs(view);
            check(problems, !view.creationReady() && restore.records.equals(bodies.records)
                    && bodies.records.equals(List.of(record(1, PKG_A, A))),
                    "restore " + inputs(restore) + " bodies " + inputs(bodies));
            NativeHistoryHarness harness = new NativeHistoryHarness();
            harness.apply(view);
            check(problems, !harness.nativePrincipalPinsLPr().hasKnownCounter()
                    && harness.nativePrincipalPinsLPr().reservedAppIds().equals(Set.of(A))
                    && harness.mAppIds.nativePrincipalAppIds().containsAll(Set.of(A, B, R)),
                    "harness boot " + harness.nativePrincipalPinsLPr().reservedAppIds());
            PackageManagerService pm = reopenOf(root, V2, Map.of());
            check(problems, pm.mSettings.pins.find(PKG_R, 0) == null && pm.mSettings.pins.find(PKG_A, 0) != null
                    && pm.mSettings.isNativePrincipalAppIdLPr(R) && !pm.mSettings.pins.hasKnownCounter(),
                    "facade boot " + pm.mSettings.pins.reservedAppIds());
        });
    }

    // What a reopened registry of the M5 layout restores: A's body and every hold, no counter.
    private static void reopened(List<String> problems, String what, PackageManagerService pm) {
        NativePrincipalPins.Pin a = pm.mSettings.pins.find(PKG_A, 0);
        check(problems, !pm.mSettings.pins.hasKnownCounter() && !pm.mSettings.nativePrincipalCreationReadyLPr()
                && a != null && a.phase() == Phase.PENDING && a.record().equals(record(1, PKG_A, A))
                && pm.mSettings.pins.reservedAppIds().equals(Set.of(A))
                && pm.mSettings.isNativePrincipalAppIdLPr(A) && pm.mSettings.isNativePrincipalAppIdLPr(B)
                && !pm.mSettings.isNativePrincipalAppIdLPr(C), what + " registry");
    }

    // The actual manager over reopened and live host PMS facades.
    private static void manager() {
        run("manager / an unsupported higher principal refuses issuance before any effect", problems -> {
            for (NativeIdentityStore.Format format : FORMATS) {
                Path root = paired(hdr(format, 1, live(B)));
                slot(root, B, user(B, PKG_B, 2, 1));
                NativeIdentityStore.Loaded view = loadedOf(root, format);
                // The actual mappings of N and Q and their boot data owners do not defer Q
                // before the counter gate: only that gate refuses its issuance.
                NativeHistoryHarness harness = new NativeHistoryHarness();
                harness.map(B, new NativeHistoryHarness.PackageSetting(PKG_B, B, false));
                harness.map(C, new NativeHistoryHarness.PackageSetting(PKG_C, C, false));
                harness.mNativeDeOwnersAtBoot = Map.of(PKG_B, B, PKG_C, C);
                harness.apply(view);
                check(problems, !harness.mNativeRecoveryView.defersName(PKG_C), format + " seeding deferred Q");
                check(problems, view.slots.get(B).status == Status.UNSUPPORTED && !view.unsupportedFootprint
                        && !view.creationReady() && !view.counterRestorable(), format + " view " + facts(view));
                PackageManagerService pm = reopenOf(root, format, Map.of(PKG_B, B, PKG_C, C));
                NativePrincipalManager manager = new NativePrincipalManager(pm);
                NativePrincipalManager.Selection q = manager.select(PKG_C, 0);
                age(root);
                Map<String, String> before = footprint(root);
                String refused = refusal(() -> manager.prepare(q));
                check(problems, REFUSED.equals(refused), format + " Q preparation " + refused);
                check(problems, footprint(root).equals(before), format + " the refused preparation wrote");
                check(problems, pm.mSettings.pins.find(PKG_C, 0) == null && pm.mSettings.pins.findId(1) == null
                        && pm.mSettings.pins.findId(2) == null && !pm.mSettings.isNativePrincipalAppIdLPr(C)
                        && pm.mSettings.pins.reservedAppIds().isEmpty(), format + " Q issued, pinned or held");
                // The counter is unknown: neither N's decoded 2 nor any maximum became one.
                check(problems, !pm.mSettings.pins.hasKnownCounter()
                        && throwsType(() -> pm.mSettings.pins.snapshotForWrite(), IllegalStateException.class),
                        format + " a counter was restored");
                NativeIdentityStore.Loaded after = loadedOf(root, format);
                check(problems, pm.mSettings.isNativePrincipalAppIdLPr(B)
                        && hdr(format, 1, live(B)).equals(after.header.value)
                        && after.occupiedAppIds.equals(Set.of(B))
                        && after.slots.get(B).status == Status.UNSUPPORTED, format + " store " + facts(after));
            }
        });
        run("manager / a stale higher copy refuses issuance until its own confirmation", problems -> {
            for (NativeIdentityStore.Format format : FORMATS) {
                Path root = paired(hdr(format, 1, live(B)));
                Slot original = bound(B, PKG_B, 1, false, 1), stale = bound(B, PKG_B, 2, false, 1);
                slot(root, B, stale);
                Files.write(root.resolve("slots/" + B + "/record.bin-backup"), encoded(original));
                NativeIdentityStore.Loaded view = loadedOf(root, format);
                check(problems, view.slots.get(B).status == Status.VALID && view.bindingUsable(B)
                        && original.equals(view.slots.get(B).value) && !view.creationReady()
                        && !view.counterRestorable(), format + " view " + facts(view));
                PackageManagerService pm = reopenOf(root, format, Map.of(PKG_B, B, PKG_C, C));
                NativePrincipalPins.Pin restored = pm.mSettings.pins.find(PKG_B, 0);
                check(problems, restored != null && restored.phase() == Phase.PENDING
                        && restored.record().equals(record(1, PKG_B, B)) && !pm.mSettings.pins.hasKnownCounter(),
                        format + " N restored " + restored);
                NativePrincipalManager manager = new NativePrincipalManager(pm);
                age(root);
                Map<String, String> before = footprint(root);
                check(problems, REFUSED.equals(refusal(() -> manager.prepare(manager.select(PKG_C, 0))))
                        && footprint(root).equals(before) && pm.mSettings.pins.find(PKG_C, 0) == null,
                        format + " Q issued beside the stale copy");
                // N's own explicit rebind confirms its original body over every copy.
                NativePrincipalManager.Handle n = manager.prepare(manager.select(PKG_B, 0));
                check(problems, manager.identity(n).equals(record(1, PKG_B, B)) && manager.commit(n)
                        && manager.phase(n) == Phase.ACTIVE, format + " N's own confirmation refused");
                Path directory = root.resolve("slots/" + B);
                check(problems, sameBytes(directory.resolve("record.bin"), encoded(original))
                        && sameBytes(directory.resolve("record.bin.reservecopy"), encoded(original))
                        && !Files.exists(directory.resolve("record.bin-backup"), LinkOption.NOFOLLOW_LINKS)
                        && hdr(format, 1, live(B)).equals(storedOf(root, format)),
                        format + " N's original body was not confirmed over every copy");
                NativeIdentityStore.Loaded resolved = loadedOf(root, format);
                check(problems, resolved.creationReady() && resolved.counterRestorable(),
                        format + " resolved view " + facts(resolved));
                // This registry keeps its unknown counter: no reset or inference in one instance.
                check(problems, !pm.mSettings.pins.hasKnownCounter() && !pm.mSettings.nativePrincipalCreationReadyLPr()
                        && REFUSED.equals(refusal(() -> manager.prepare(manager.select(PKG_C, 0)))),
                        format + " the live registry reset its counter");
                // Only a new registry restores the now coherent selected counter 1, then issues 2.
                PackageManagerService again = reopenOf(root, format, Map.of(PKG_B, B, PKG_C, C));
                check(problems, again.mSettings.pins.hasKnownCounter()
                        && again.mSettings.pins.snapshotForWrite().lastId == 1, format + " reopened counter");
                NativePrincipalManager later = new NativePrincipalManager(again);
                NativePrincipalManager.Handle q = later.prepare(later.select(PKG_C, 0));
                check(problems, later.identity(q).id == 2 && later.commit(q)
                        && hdr(format, 2, live(B), live(C)).equals(storedOf(root, format)),
                        format + " Q after N's confirmation " + storedOf(root, format));
            }
        });
        run("manager / a healthy body retires beside a blocked store", problems -> {
            Path root = paired(header(1, live(A), live(B)));
            slot(root, A, bound(A, PKG_A, 1, false, 1));
            slot(root, B, user(B, PKG_B, 2, 1));
            PackageManagerService pm = reopenOf(root, V1, Map.of(PKG_A, A, PKG_B, B, PKG_C, C));
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            age(root);
            Map<String, String> held = footprint(root.resolve("slots/" + B));
            check(problems, REFUSED.equals(refusal(() -> manager.prepare(manager.select(PKG_C, 0)))),
                    "Q issued before A's retirement");
            NativePrincipalManager.Handle a = manager.prepare(manager.select(PKG_A, 0));
            check(problems, manager.identity(a).equals(record(1, PKG_A, A)) && manager.commit(a)
                    && manager.phase(a) == Phase.ACTIVE, "A's rebind refused");
            // Synthetic quiescence: the host has no native work to stop.
            check(problems, manager.beginRetirement(a) && manager.finishRetirementAfterQuiescence(a),
                    "A's retirement refused");
            check(problems, header(1, live(B)).equals(stored(root))
                    && !Files.exists(root.resolve("slots/" + A), LinkOption.NOFOLLOW_LINKS),
                    "A's release " + stored(root));
            check(problems, footprint(root.resolve("slots/" + B)).equals(held)
                    && pm.mSettings.isNativePrincipalAppIdLPr(B)
                    && loaded(root).slots.get(B).status == Status.UNSUPPORTED, "N's hold or data changed");
            check(problems, REFUSED.equals(refusal(() -> manager.prepare(manager.select(PKG_C, 0))))
                    && pm.mSettings.pins.find(PKG_C, 0) == null, "Q issued after A's retirement");
        });
        run("manager / a lost BODY cannot be republished while the counter is blocked", problems -> {
            for (NativeIdentityStore.Format format : FORMATS) {
                Header held = hdr(format, 1, format == V1 ? creating(A, 1, PKG_A)
                        : boundCreating(A, 1, PKG_A), live(B));
                Path root = paired(held);
                slot(root, A, bound(A, PKG_A, 1, false, 1));
                slot(root, B, user(B, PKG_B, 2, 1));
                PackageManagerService pm = reopenOf(root, format, Map.of(PKG_A, A, PKG_B, B));
                NativePrincipalManager manager = new NativePrincipalManager(pm);
                NativePrincipalManager.Handle a = manager.find(PKG_A, 0);
                Path directory = root.resolve("slots/" + A);
                Files.delete(directory.resolve("record.bin"));
                Files.delete(directory.resolve("record.bin.reservecopy"));
                Files.delete(directory);
                observe(pm);
                age(root);
                Map<String, String> before = footprint(root);
                check(problems, !manager.beginRetirement(a) && manager.phase(a) == Phase.RETIRING,
                        format + " lost BODY was republished");
                check(problems, footprint(root).equals(before) && !Files.exists(directory)
                        && held.equals(storedOf(root, format)), format + " a store write occurred");
                check(problems, "Retirement marker is not durably confirmed".equals(refusal(
                        () -> manager.finishRetirementAfterQuiescence(a))), format + " removal authorized");
            }
        });
        run("manager / a live registry refuses after observing a higher copy", problems -> {
            for (boolean unsupported : List.of(false, true)) {
                String what = unsupported ? "unsupported copy" : "stale copy";
                Path root = paired(header(1, live(B)));
                slot(root, B, bound(B, PKG_B, 1, false, 1));
                PackageManagerService pm = reopenOf(root, V1, Map.of(PKG_A, A, PKG_B, B, PKG_C, C));
                NativePrincipalManager manager = new NativePrincipalManager(pm);
                NativePrincipalManager.Selection selectedP = manager.select(PKG_A, 0);
                NativePrincipalManager.Handle p = manager.prepare(selectedP);
                check(problems, manager.identity(p).equals(record(2, PKG_A, A)), what + " P was not issued 2");
                // Crafted state the live registry then observes: a stale copy of this lineage naming
                // P's own unpublished ID, or an unsupported record naming a higher one.
                Path directory = root.resolve("slots/" + B);
                if (unsupported) {
                    Files.write(directory.resolve("record.bin"), encoded(user(B, PKG_B, 3, 1)));
                    Files.write(directory.resolve("record.bin.reservecopy"), encoded(user(B, PKG_B, 3, 1)));
                } else {
                    Files.write(directory.resolve("record.bin.reservecopy"), encoded(bound(B, PKG_B, 2, false, 1)));
                }
                observe(pm);
                check(problems, !pm.mSettings.mNativeIdentityLoaded.creationReady()
                        && !pm.mSettings.nativePrincipalCreationReadyLPr() && pm.mSettings.pins.hasKnownCounter(),
                        what + " live view");
                age(root);
                Map<String, String> before = footprint(root);
                check(problems, REFUSED.equals(refusal(() -> manager.prepare(manager.select(PKG_C, 0)))),
                        what + " Q issued");
                check(problems, !manager.commit(p) && footprint(root).equals(before), what + " P committed or wrote");
                // The original handle and request are kept, and no other ID was issued.
                check(problems, manager.phase(p) == Phase.PENDING && manager.prepare(selectedP) == p
                        && manager.find(PKG_A, 0) == p && pm.mSettings.pins.snapshotForWrite().lastId == 2
                        && pm.mSettings.pins.find(PKG_C, 0) == null && pm.mSettings.pins.findId(3) == null,
                        what + " P's handle, request or counter changed");
                check(problems, pm.mSettings.isNativePrincipalAppIdLPr(A) && pm.mSettings.isNativePrincipalAppIdLPr(B)
                        && !pm.mSettings.isNativePrincipalAppIdLPr(C) && footprint(root).equals(before),
                        what + " holds");
            }
        });
        run("manager / holds and refusals survive reopening and lost replies", problems -> {
            Path root = paired(header(1, live(A), live(B)));
            slot(root, A, bound(A, PKG_A, 1, false, 1));
            slot(root, B, user(B, PKG_B, 2, 1));
            Map<String, Integer> packages = Map.of(PKG_A, A, PKG_B, B, PKG_C, C);
            PackageManagerService pm = reopenOf(root, V1, packages);
            reopened(problems, "first boot", pm);
            // The cached view keeps the block and every hold.
            check(problems, !pm.mSettings.mNativeIdentityLoaded.creationReady()
                    && pm.mSettings.mNativeIdentityLoaded.occupiedAppIds.equals(Set.of(A, B)), "cached view");
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            age(root);
            Map<String, String> before = footprint(root);
            // A refusal returns no handle: the same selection refuses again and nothing is found.
            NativePrincipalManager.Selection q = manager.select(PKG_C, 0);
            check(problems, REFUSED.equals(refusal(() -> manager.prepare(q)))
                    && REFUSED.equals(refusal(() -> manager.prepare(q)))
                    && manager.find(PKG_C, 0) == null && footprint(root).equals(before), "Q refusals");
            // A's confirmation is durable, but its reply is lost after the write.
            NativePrincipalManager.Handle a = manager.prepare(manager.select(PKG_A, 0));
            pm.mSettings.failRefresh = true;
            check(problems, "injected refresh failure".equals(refusal(() -> manager.commit(a))),
                    "no lost reply");
            check(problems, manager.phase(a) == Phase.PENDING && pm.mSettings.isNativePrincipalAppIdLPr(A)
                    && pm.mSettings.isNativePrincipalAppIdLPr(B), "a lost reply dropped a hold or committed A");
            check(problems, manager.commit(a) && manager.phase(a) == Phase.ACTIVE, "A's retry refused");
            // No snapshot or pin overlaps N's decoded claim, and the refusal is unchanged.
            check(problems, !pm.mSettings.pins.hasKnownCounter()
                    && throwsType(() -> pm.mSettings.pins.snapshotForWrite(), IllegalStateException.class)
                    && pm.mSettings.pins.findId(2) == null && pm.mSettings.pins.reservedAppIds().equals(Set.of(A))
                    && REFUSED.equals(refusal(() -> manager.prepare(q))), "registry after A's confirmation");
            reopened(problems, "second boot", reopenOf(root, V1, packages));
        });
    }

    public static void main(String[] args) throws Exception {
        if (!NativeCounterAdmissionTest.class.desiredAssertionStatus()) {
            throw new AssertionError("run with java -ea");
        }
        if (!LINEAGE.equals(Settings.LINEAGE)) throw new AssertionError("facade lineage");
        start(Path.of(args[0]).resolve("counter-admission"));
        LocalServices.addService(UserManagerInternal.class, new UserManagerInternal());
        gates();
        residual();
        evidence();
        placements();
        composition();
        manager();
        finish(Os.allClosed());
        System.out.println("Decoded principal IDs above the selected counter withhold new issuance and"
                + " change nothing else; Android boot, crash recovery and activation unqualified");
    }
}
