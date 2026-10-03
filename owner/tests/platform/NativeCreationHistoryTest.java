// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeBindingTestSupport.*;
import static com.android.server.pm.NativeHeaderTestSupport.*;
import static com.android.server.pm.NativeHistoryTestSupport.*;

import android.content.pm.Signature;
import android.content.pm.SigningDetails;
import android.system.Os;
import com.android.server.LocalServices;
import com.android.server.pm.NativeIdentityRecords.CreationBinding;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.HeaderEntry;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.SlotPhase;
import com.android.server.pm.NativeIdentityRecords.UserEntry;
import com.android.server.pm.NativeIdentityStore.History;
import com.android.server.pm.NativeIdentityStore.Source;
import com.android.server.pm.NativeIdentityStore.Status;
import com.android.server.pm.NativePrincipalPins.Phase;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * B2 historical identities over the actual records, store, persistence, manager and host PMS
 * facade. A published eligible body is BODY history, exactly as restoration always took it. A
 * selected complete header creation whose slot this view reads as missing is RESERVATION
 * history only when the store is creation ready, its copies agree and no other app ID claims
 * its package or principal. That says what this view holds, not that no body ever existed. It
 * restores PENDING, and only an explicit designation rebinds and publishes it with its original
 * ID and signers. Published bindings and current identities stay body only. A reservation never
 * rebound cannot create its first body in retirement. Each case isolates one store, and every
 * booted facade restores exactly what the adapted Settings text restores. Host facades only:
 * not Android boot, crash, storage, SELinux or UID authority qualification, and not activation
 * of the version 2 format.
 */
public final class NativeCreationHistoryTest {
    private interface Layer { void write(Path root) throws Exception; }

    private static final UserManagerInternal USERS = new UserManagerInternal();
    private static final SigningDetails OWN = new SigningDetails(new Signature(new byte[] {1, 2, 3}));
    // A device encrypted data directory owner UID that no fixture maps, and a directory name
    // that no package setting owns.
    private static final int FOREIGN_OWNER_UID = 10099;
    private static final String PKG_ORPHAN = "dev.andrix.orphan";
    private static final File CODE_R = new File("/data/app/~~host/" + PKG_R + "-1");
    private static final Header BESIDE_A = v2(2, live(A), boundCreating(R, 2, PKG_R));
    private static final Header TARGET = v2(3, creating(A, 1, PKG_A), creating(B, 2, PKG_B),
            boundCreating(C, 3, PKG_C));

    private static Path pairLayout(Header header) throws Exception {
        return layout(null, bytes(header), bytes(header));
    }
    private static Path protectedTarget() throws Exception {
        return layout(bytes(TARGET), bytes(header(1, creating(A, 1, PKG_A))),
                bytes(header(2, creating(A, 1, PKG_A), creating(B, 2, PKG_B))));
    }
    private static void removeDirectory(Path directory) throws Exception {
        List<Path> files;
        try (var entries = Files.list(directory)) {
            files = entries.toList();
        }
        for (Path file : files) Files.delete(file);
        Files.delete(directory);
    }
    private static com.android.server.pm.pkg.PackageStateInternal state(String name) {
        return new com.android.server.pm.pkg.PackageStateInternal() {
            @Override public String getPackageName() { return name; }
            @Override public File getPath() { return new File("/data/app/~~host/" + name + "-1"); }
        };
    }
    private static Slot userBody(int appId, String name, long id, int userId, Set<String> signers) {
        return new Slot(LINEAGE, appId, name, 1, signers,
                List.of(new UserEntry(id, userId, SERIAL, false)));
    }
    // A body at A with users 0 and 1, which the codec allows in ascending order, and one with
    // only user 1. Load reads both as UNSUPPORTED slots, as 0018a1d does.
    private static final Slot TWO_USERS = new Slot(LINEAGE, A, PKG_A, 1, SIGNERS,
            List.of(new UserEntry(1, 0, SERIAL, false), new UserEntry(2, 1, 9, false)));
    private static final Slot NONZERO_USER = new Slot(LINEAGE, A, PKG_A, 1, SIGNERS,
            List.of(new UserEntry(2, 1, 9, false)));

    // Every UID data and key dependency of this app ID stays fenced.
    private static boolean fenced(NativePrincipalRecovery recovery, int appId) {
        return recovery.holdsAppId(appId) && recovery.protectsKeystore(appId)
                && recovery.protectsObservedUid(appId);
    }

    // What a recovery view defers, protects, keeps and holds, over the fixture names and IDs.
    private static String recoveryFacts(NativePrincipalRecovery recovery) {
        StringBuilder text = new StringBuilder();
        for (String name : List.of(PKG_A, PKG_R, PKG_X, PKG_ORPHAN)) {
            text.append(name).append(recovery.defersName(name) ? " deferred" : "")
                    .append(recovery.protectsName(name) ? " protected" : "")
                    .append(recovery.keepsCodePath(new File("/data/app/~~host/" + name + "-1"))
                            ? " kept" : "").append("; ");
        }
        for (int appId : List.of(A, R)) {
            text.append(appId).append(fenced(recovery, appId) ? " fenced; " : "; ");
        }
        return text.append("unidentified ").append(recovery.hasUnidentifiedCode()).toString();
    }

    // BODY and RESERVATION sources, and the view a reopened registry restores from them.
    private static void sources() {
        run("history / an eligible body is BODY with its one user", problems -> {
            for (NativeIdentityStore.Format format : List.of(V1, V2)) {
                Path root = pairLayout(format == V1 ? header(1, live(A)) : v2(1, live(A)));
                slot(root, A, BODY_A);
                NativeIdentityStore.Loaded view = loadedOf(root, format);
                History history = view.history(A);
                check(problems, history != null && history.source == Source.BODY && history.id == 1
                        && history.appId == A && history.packageName.equals(PKG_A) && history.userId == 0
                        && history.userSerial == SERIAL && history.signerSha256.equals(SIGNERS)
                        && !history.retiring && history.lineage.equals(LINEAGE)
                        && view.histories().keySet().equals(Set.of(A)) && bodiesExact(view),
                        format + " history " + history);
                NativePrincipalPins.Pin pin = reopenOf(root, format, Map.of()).mSettings.pins.find(PKG_A, 0);
                check(problems, pin != null && pin.phase() == Phase.PENDING
                        && pin.record().equals(record(1, PKG_A, A)), format + " restored " + pin);
            }
        });
        run("history / a retiring body keeps its marker", problems -> {
            Path root = pairLayout(v2(1, live(A)));
            slot(root, A, bound(A, PKG_A, 1, true, 2));
            NativeIdentityStore.Loaded view = loadedOf(root, V2);
            History history = view.history(A);
            check(problems, history != null && history.source == Source.BODY && history.retiring
                    && bodiesExact(view), "history " + history);
            check(problems, NativeIdentityPersistence.restoration(view.histories()).retiringIds
                    .equals(Set.of(1L)), "retiring IDs");
            check(problems, reopenedPhase(root, V2, PKG_A) == Phase.RETIRING, "restored phase");
        });
        run("history / a body under its creation entry is BODY", problems -> {
            Path root = pairLayout(v2(1, boundCreating(A, 1, PKG_A)));
            slot(root, A, BODY_A);
            NativeIdentityStore.Loaded view = loadedOf(root, V2);
            check(problems, view.history(A) != null && view.history(A).source == Source.BODY
                    && bodiesExact(view), "history " + view.history(A));
        });
        run("history / a complete creation without a body is a reservation", problems -> {
            Path root = reserved();
            NativeIdentityStore.Loaded view = loadedOf(root, V2);
            reservedR(problems, view, "view");
            check(problems, view.slots.get(R).status == Status.MISSING && view.creationReady()
                    && view.counterRestorable()
                    && !Files.exists(root.resolve("slots/" + R), LinkOption.NOFOLLOW_LINKS),
                    "view " + view.slots.get(R).status);
            NativeIdentityPersistence.Restoration restoration =
                    NativeIdentityPersistence.restoration(view.histories());
            check(problems, restoration.records.equals(List.of(recordR()))
                    && restoration.retiringIds.isEmpty() && restoration.withdrawnReservations.isEmpty(),
                    "restoration " + restoration.records);
        });
        run("history / an empty slot directory keeps the reservation", problems -> {
            Path root = reserved();
            slotDirectory(root, R);
            reservedR(problems, loadedOf(root, V2), "empty directory");
        });
        run("history / a torn seed keeps the reservation and is no history", problems -> {
            Path root = reserved();
            byte[] torn = Arrays.copyOf(NativeIdentityRecords.encodeSlot(BODY_R), 40);
            Path seed = slotDirectory(root, R).resolve("record.bin-seed");
            Files.write(seed, torn);
            reservedR(problems, loadedOf(root, V2), "torn seed");
            check(problems, sameBytes(seed, torn), "a read changed the seed");
        });
        run("history / an intact seed is never history", problems -> {
            for (Set<String> signers : List.of(SIGNERS, OTHER_SIGNERS)) {
                Path root = reserved();
                Files.write(slotDirectory(root, R).resolve("record.bin-seed"),
                        NativeIdentityRecords.encodeSlot(userBody(R, PKG_R, 1, 0, signers)));
                NativeIdentityStore.Loaded view = loadedOf(root, V2);
                reservedR(problems, view, "seed with " + signers.size() + " signer");
                check(problems, view.slots.get(R).status == Status.MISSING,
                        "a seed was read as a copy " + view.slots.get(R).status);
            }
        });
        run("history / a damaged header keeps an eligible body", problems -> {
            Path root = layout(null, GARBAGE, GARBAGE);
            slot(root, A, BODY_A);
            NativeIdentityStore.Loaded view = loadedOf(root, V2);
            check(problems, view.header.status == Status.DAMAGED && !view.creationReady()
                    && view.history(A) != null && view.history(A).source == Source.BODY
                    && bodiesExact(view), "view " + view.header.status + " " + view.history(A));
            PackageManagerService pm = reopenOf(root, V2, Map.of());
            check(problems, !pm.mSettings.pins.hasKnownCounter()
                    && pm.mSettings.pins.find(PKG_A, 0) != null, "restoration beside a damaged header");
        });
        run("history / the version 1 rollback reader reads no reservation", problems -> {
            Path root = reserved();
            NativeIdentityStore.Loaded view = loadedOf(root, V1);
            check(problems, view.header.status == Status.UNSUPPORTED && view.histories().isEmpty()
                    && view.occupiedAppIds.equals(Set.of(R)), "view " + view.header.status);
            PackageManagerService pm = reopen(root, Map.of());
            check(problems, pm.mSettings.pins.reservedAppIds().isEmpty()
                    && pm.mSettings.isNativePrincipalAppIdLPr(R) && !pm.mSettings.pins.hasKnownCounter(),
                    "version 1 registry");
        });
        run("history / a protected V2 target beside V1 predecessors is a reservation", problems -> {
            Path root = protectedTarget();
            NativeIdentityStore.Loaded view = loadedOf(root, V2);
            reservation(problems, view.history(C), C, 3, PKG_C, SIGNERS, "target");
            check(problems, view.history(A) == null && view.history(B) == null
                    && view.histories().size() == 1 && view.counterRestorable(), "legacy entries became history");
            PackageManagerService pm = reopenOf(root, V2, Map.of());
            NativePrincipalPins.Pin pin = pm.mSettings.pins.find(PKG_C, 0);
            check(problems, pin != null && pin.phase() == Phase.PENDING
                    && pin.record().equals(record(3, PKG_C, C))
                    && pm.mSettings.pins.snapshotForWrite().lastId == 3, "restored " + pin);
        });
        run("history / bodies with a nonzero user give none and claim their principals", problems -> {
            for (Slot body : List.of(TWO_USERS, NONZERO_USER)) {
                Path root = pairLayout(v2(2, live(A)));
                slot(root, A, body);
                NativeIdentityStore.Loaded view = loadedOf(root, V2);
                // A user 0 limit, not a format footprint: the store stays creation ready.
                check(problems, view.slots.get(A).status == Status.UNSUPPORTED && !view.unsupportedFootprint
                        && view.creationReady() && view.histories().isEmpty()
                        && view.occupiedAppIds.equals(Set.of(A)) && bodiesExact(view),
                        body.users.size() + " users: " + view.slots.get(A).status);
                PackageManagerService pm = reopenOf(root, V2, Map.of());
                check(problems, pm.mSettings.pins.reservedAppIds().isEmpty()
                        && pm.mSettings.isNativePrincipalAppIdLPr(A), "registry beside " + body.users.size());
            }
            Path beside = pairLayout(v2(3, live(A), boundCreating(R, 3, PKG_R)));
            slot(beside, A, TWO_USERS);
            reservation(problems, loadedOf(beside, V2).history(R), R, 3, PKG_R, SIGNERS,
                    "an unclaimed reservation beside it");
            Path claimed = pairLayout(v2(3, live(A), boundCreating(R, 2, PKG_R)));
            slot(claimed, A, TWO_USERS);
            noHistory(problems, claimed, V2, R, "a reservation of its user 1 principal");
        });
        run("history / tombstones give none and keep their holds", problems -> {
            Path root = pairLayout(v2(2, live(A), releasing(B)));
            slot(root, A, tombstone(A, PKG_A, 2));
            slot(root, B, tombstone(B, PKG_B, 3));
            NativeIdentityStore.Loaded view = loadedOf(root, V2);
            check(problems, view.histories().isEmpty() && view.occupiedAppIds.equals(Set.of(A, B))
                    && bodiesExact(view), "view " + view.histories());
            PackageManagerService pm = reopenOf(root, V2, Map.of());
            check(problems, pm.mSettings.pins.reservedAppIds().isEmpty()
                    && pm.mSettings.isNativePrincipalAppIdLPr(A) && pm.mSettings.isNativePrincipalAppIdLPr(B),
                    "reopened");
        });
    }

    // A body that exists but is not eligible leaves no history. Nothing falls back to the header.
    private static void fallbacks() {
        Map<String, Layer> bodies = new TreeMap<>();
        bodies.put("damaged copies", root -> {
            Path directory = slotDirectory(root, R);
            Files.write(directory.resolve("record.bin"), GARBAGE);
            Files.write(directory.resolve("record.bin.reservecopy"), GARBAGE);
        });
        bodies.put("conflicting copies", root -> {
            Path directory = slotDirectory(root, R);
            Files.write(directory.resolve("record.bin"), NativeIdentityRecords.encodeSlot(BODY_R));
            Files.write(directory.resolve("record.bin.reservecopy"),
                    NativeIdentityRecords.encodeSlot(bound(R, PKG_R, 1, false, 2)));
        });
        bodies.put("a binding mismatch", root -> slot(root, R, userBody(R, PKG_R, 1, 0, OTHER_SIGNERS)));
        bodies.put("a tombstone", root -> slot(root, R, tombstone(R, PKG_R, 1)));
        bodies.put("a future body", root -> Files.write(slotDirectory(root, R).resolve("record.bin"),
                relabeled(NativeIdentityRecords.encodeSlot(BODY_R), 2)));
        bodies.put("a link entry", root -> Files.createSymbolicLink(root.resolve("slots/" + R),
                Path.of("absent-target")));
        bodies.put("a file entry", root -> Files.write(root.resolve("slots/" + R), GARBAGE));
        bodies.put("a directory record", root ->
                Files.createDirectories(root.resolve("slots/" + R + "/record.bin")));
        for (Map.Entry<String, Layer> kind : bodies.entrySet()) {
            run("no fallback / " + kind.getKey(), problems -> {
                Path root = reserved();
                kind.getValue().write(root);
                noHistory(problems, root, V2, R, kind.getKey());
            });
        }
        run("no fallback / an unavailable body", problems -> {
            Path root = reserved();
            slot(root, R, BODY_R);
            NativeIdentityStore.Loaded view = restricted(root.resolve("slots/" + R + "/record.bin"),
                    "-w-------", () -> loadedOf(root, V2));
            check(problems, view.slots.get(R).unavailable && view.unavailableFootprint
                    && view.histories().isEmpty() && view.occupiedAppIds.contains(R),
                    "view " + view.slots.get(R).status + " " + view.histories());
        });
    }

    // Store and header gates withdraw every reservation they apply to, and nothing else.
    private static void gates() {
        Map<String, Layer> global = new TreeMap<>();
        global.put("an unindexed slot directory", root -> slotDirectory(root, 10050));
        global.put("a slot entry that is no app ID", root ->
                Files.createDirectory(root.resolve("slots/notes")));
        global.put("an unsupported header seed", root -> Files.write(root.resolve("store.bin-seed"),
                frame(1, 3, body(bytes(RESERVED_R)))));
        for (Map.Entry<String, Layer> gate : global.entrySet()) {
            run("gate / " + gate.getKey(), problems -> {
                Path root = reserved();
                gate.getValue().write(root);
                NativeIdentityStore.Loaded view = loadedOf(root, V2);
                check(problems, !view.creationReady() && view.header.status == Status.VALID,
                        "the store stayed creation ready");
                noHistory(problems, root, V2, R, gate.getKey());
            });
        }
        run("gate / an unsupported slot seed", problems -> {
            Path root = pairLayout(BESIDE_A);
            slot(root, A, BODY_A);
            Files.write(root.resolve("slots/" + A + "/record.bin-seed"),
                    relabeled(NativeIdentityRecords.encodeSlot(BODY_A), 2));
            NativeIdentityStore.Loaded view = loadedOf(root, V2);
            check(problems, view.unsupportedFootprint && !view.creationReady() && view.history(A) != null
                    && view.history(A).source == Source.BODY, "the body was gated " + view.history(A));
            noHistory(problems, root, V2, R, "unsupported slot seed");
        });
        run("gate / an unavailable header copy", problems -> {
            Path root = reserved();
            NativeIdentityStore.Loaded view = restricted(root.resolve("store.bin.reservecopy"),
                    "-w-------", () -> loadedOf(root, V2));
            check(problems, view.header.unavailable && view.histories().isEmpty()
                    && view.occupiedAppIds.contains(R), "view " + view.header.status);
        });
        // The selected entry and every decoded copy: backup, main and reserve.
        Map<String, Header[]> selections = new TreeMap<>();
        Header unbound = v2(1, creating(R, 1, PKG_R));
        selections.put("a version 2 entry without a binding", new Header[] {null, unbound, unbound});
        selections.put("a version 1 entry", new Header[] {null, header(1, creating(R, 1, PKG_R)),
                header(1, creating(R, 1, PKG_R))});
        selections.put("an unselected addition", new Header[] {v2(0), RESERVED_R, RESERVED_R});
        selections.put("a LIVE entry without a body", new Header[] {null, v2(1, live(R)), v2(1, live(R))});
        selections.put("a RELEASING entry without a body", new Header[] {null, v2(1, releasing(R)),
                v2(1, releasing(R))});
        selections.put("a LIVE copy of the creation", new Header[] {RESERVED_R, v2(1, live(R)),
                v2(1, live(R))});
        Header otherBinding = v2(1, boundCreating(R, 1, PKG_R, OTHER_SIGNERS));
        selections.put("a copy with another binding", new Header[] {RESERVED_R, otherBinding, otherBinding});
        selections.put("a copy without the binding", new Header[] {RESERVED_R, unbound, unbound});
        Header foreign = Header.newV2(FOREIGN, 1, List.of(boundCreating(R, 1, PKG_R)));
        selections.put("a copy of another lineage", new Header[] {RESERVED_R, foreign, foreign});
        Header counterOnly = v2(2, boundCreating(R, 1, PKG_R));
        selections.put("a copy with a counter only difference", new Header[] {RESERVED_R, counterOnly,
                counterOnly});
        Header otherUser = v2(1, new HeaderEntry(R, SlotPhase.CREATING, 1, PKG_R,
                new CreationBinding(10, SERIAL, SIGNERS)));
        selections.put("another user's binding", new Header[] {null, otherUser, otherUser});
        for (Map.Entry<String, Header[]> selection : selections.entrySet()) {
            run("gate / " + selection.getKey(), problems -> {
                Header[] copies = selection.getValue();
                Path root = layout(copies[0] == null ? null : bytes(copies[0]), bytes(copies[1]),
                        bytes(copies[2]));
                noHistory(problems, root, V2, R, selection.getKey());
                noHistory(problems, root, V1, R, selection.getKey() + " under V1");
            });
        }
        run("gate / a compatible LIVE copy is withdrawn by corroboration alone", problems -> {
            Path root = layout(bytes(RESERVED_R), bytes(v2(1, live(R))), bytes(v2(1, live(R))));
            NativeIdentityStore.Loaded view = loadedOf(root, V2);
            check(problems, view.header.status == Status.VALID && RESERVED_R.equals(view.header.value)
                    && NativeIdentityStore.HeaderCopies.of(view.header) != null && view.creationReady()
                    && view.history(R) == null, "view " + view.history(R));
        });
        run("gate / incompatible copies are withdrawn by the copy rule alone", problems -> {
            for (Header copy : List.of(foreign, counterOnly)) {
                Path root = layout(bytes(RESERVED_R), bytes(copy), bytes(copy));
                NativeIdentityStore.Loaded view = loadedOf(root, V2);
                boolean listed = true;
                for (Header decoded : view.header.decodedCopies) {
                    listed &= decoded.entries.contains(RESERVED_R.entries.get(0));
                }
                check(problems, listed && NativeIdentityStore.HeaderCopies.of(view.header) == null
                        && view.history(R) == null, "view " + view.history(R));
            }
        });
    }

    // Any claim at another app ID withdraws only the reservation, never a body.
    private static void uniqueness() {
        Map<String, Layer> claims = new TreeMap<>();
        claims.put("the package of a valid body", root -> {
            copies(root, null, bytes(v2(2, live(A), boundCreating(R, 2, PKG_A))),
                    bytes(v2(2, live(A), boundCreating(R, 2, PKG_A))));
            slot(root, A, BODY_A);
        });
        claims.put("the principal of a valid body", root -> {
            copies(root, null, bytes(v2(2, live(A), boundCreating(R, 1, PKG_R))),
                    bytes(v2(2, live(A), boundCreating(R, 1, PKG_R))));
            slot(root, A, BODY_A);
        });
        claims.put("a damaged copy", root -> {
            copies(root, null, bytes(BESIDE_A), bytes(BESIDE_A));
            Path directory = slotDirectory(root, A);
            Files.write(directory.resolve("record.bin"),
                    NativeIdentityRecords.encodeSlot(bound(A, PKG_R, 1, false, 1)));
            Files.write(directory.resolve("record.bin-backup"), GARBAGE);
        });
        claims.put("a conflicting copy", root -> {
            copies(root, null, bytes(BESIDE_A), bytes(BESIDE_A));
            Path directory = slotDirectory(root, A);
            Files.write(directory.resolve("record.bin"), NativeIdentityRecords.encodeSlot(BODY_A));
            Files.write(directory.resolve("record.bin.reservecopy"),
                    NativeIdentityRecords.encodeSlot(bound(A, PKG_R, 1, false, 1)));
        });
        claims.put("an unsupported copy", root -> {
            copies(root, null, bytes(BESIDE_A), bytes(BESIDE_A));
            slot(root, A, userBody(A, PKG_R, 1, 10, SIGNERS));
        });
        claims.put("a tombstone package", root -> {
            copies(root, null, bytes(BESIDE_A), bytes(BESIDE_A));
            slot(root, A, tombstone(A, PKG_R, 2));
        });
        claims.put("a legacy creation entry", root -> {
            Header legacyA = v2(2, creating(A, 1, PKG_R), boundCreating(R, 2, PKG_R));
            copies(root, null, bytes(legacyA), bytes(legacyA));
        });
        claims.put("an unselected addition", root -> {
            Header addition = v2(2, boundCreating(R, 1, PKG_R), creating(D, 2, PKG_R));
            copies(root, bytes(RESERVED_R), bytes(addition), bytes(addition));
        });
        claims.put("a body elsewhere naming this app ID", root -> {
            Header liveC = v2(2, live(C), boundCreating(R, 2, PKG_R));
            copies(root, null, bytes(liveC), bytes(liveC));
            byte[] misplaced = NativeIdentityRecords.encodeSlot(bound(R, PKG_R, 1, false, 1));
            Path directory = slotDirectory(root, C);
            Files.write(directory.resolve("record.bin"), misplaced);
            Files.write(directory.resolve("record.bin.reservecopy"), misplaced);
        });
        for (Map.Entry<String, Layer> claim : claims.entrySet()) {
            run("uniqueness / " + claim.getKey(), problems -> {
                Path root = layout(null, null, null);
                claim.getValue().write(root);
                NativeIdentityStore.Loaded view = loadedOf(root, V2);
                check(problems, view.creationReady(), "not a creation ready claim");
                noHistory(problems, root, V2, R, claim.getKey());
            });
        }
        run("uniqueness / valid bodies stay usable beside a withdrawn reservation", problems -> {
            for (Header held : List.of(v2(2, live(A), boundCreating(R, 2, PKG_A)),
                    v2(2, live(A), boundCreating(R, 1, PKG_R)))) {
                Path root = pairLayout(held);
                slot(root, A, BODY_A);
                NativeIdentityStore.Loaded view = loadedOf(root, V2);
                check(problems, view.history(R) == null && view.history(A) != null
                        && view.history(A).source == Source.BODY && view.bindingUsable(A),
                        "body withdrawn " + view.slots.get(A).status);
                PackageManagerService pm = reopenOf(root, V2, Map.of());
                check(problems, pm.mSettings.pins.reservedAppIds().equals(Set.of(A))
                        && pm.mSettings.isNativePrincipalAppIdLPr(R), "pins " + pm.mSettings.pins.reservedAppIds());
            }
        });
        run("uniqueness / two reservations of one package both withdraw", problems -> {
            Path root = pairLayout(v2(2, boundCreating(R, 1, PKG_R), boundCreating(D, 2, PKG_R)));
            noHistory(problems, root, V2, R, "first");
            noHistory(problems, root, V2, D, "second");
        });
        run("uniqueness / an unavailable copy withdraws through the store gate", problems -> {
            Path root = pairLayout(BESIDE_A);
            slot(root, A, bound(A, PKG_R, 1, false, 1));
            NativeIdentityStore.Loaded view = restricted(root.resolve("slots/" + A + "/record.bin.reservecopy"),
                    "-w-------", () -> loadedOf(root, V2));
            check(problems, view.unavailableFootprint && view.history(R) == null
                    && view.occupiedAppIds.contains(R), "view " + view.history(R));
        });
        run("uniqueness / an unrelated sibling keeps the reservation", problems -> {
            Path root = pairLayout(BESIDE_A);
            slot(root, A, BODY_A);
            NativeIdentityStore.Loaded view = loadedOf(root, V2);
            reservation(problems, view.history(R), R, 2, PKG_R, SIGNERS, "control");
            check(problems, view.history(A) != null && view.history(A).source == Source.BODY
                    && bodiesExact(view), "sibling " + view.history(A));
            PackageManagerService pm = reopenOf(root, V2, Map.of());
            check(problems, pm.mSettings.pins.reservedAppIds().equals(Set.of(A, R)),
                    "pins " + pm.mSettings.pins.reservedAppIds());
        });
    }

    // The one shared restoration, its backstop, and the histories a live registry remembers.
    private static void restoration() {
        run("restoration / a store view needs no backstop", problems -> {
            List<Path> roots = new ArrayList<>();
            roots.add(reserved());
            Path beside = pairLayout(BESIDE_A);
            slot(beside, A, BODY_A);
            roots.add(beside);
            roots.add(protectedTarget());
            roots.add(pairLayout(v2(3, boundCreating(A, 1, PKG_A), boundCreating(B, 2, PKG_B),
                    boundCreating(C, 3, PKG_C))));
            for (Path root : roots) {
                NativeIdentityStore.Loaded view = loadedOf(root, V2);
                NativeIdentityPersistence.Restoration restored =
                        NativeIdentityPersistence.restoration(view.histories());
                List<NativePrincipalPins.Record> expected = new ArrayList<>();
                for (History history : view.histories().values()) {
                    expected.add(NativeIdentityPersistence.record(history));
                }
                expected.sort(Comparator.comparingLong(value -> value.id));
                check(problems, !expected.isEmpty() && restored.withdrawnReservations.isEmpty()
                        && restored.records.equals(expected), root + " restoration " + restored.records);
            }
        });
        run("restoration / the backstop withdraws only merged reservations", problems -> {
            Path published = pairLayout(v2(1, live(A)));
            slot(published, A, BODY_A);
            Map<Integer, History> bodies = loadedOf(published, V2).histories();
            Map<Integer, History> packageOfA = loadedOf(pairLayout(v2(2, boundCreating(R, 2, PKG_A))),
                    V2).histories();
            Map<Integer, History> principalOne = loadedOf(reserved(), V2).histories();
            Map<Integer, History> packageOfR = loadedOf(pairLayout(v2(2, boundCreating(D, 2, PKG_R))),
                    V2).histories();
            check(problems, bodies.size() == 1 && packageOfA.size() == 1 && principalOne.size() == 1
                    && packageOfR.size() == 1, "fixture histories");
            List<Map<Integer, History>> seconds = List.of(packageOfA, principalOne);
            for (Map<Integer, History> second : seconds) {
                Map<Integer, History> merged = new TreeMap<>(bodies);
                merged.putAll(second);
                NativeIdentityPersistence.Restoration restoration =
                        NativeIdentityPersistence.restoration(merged);
                check(problems, restoration.withdrawnReservations.equals(Set.of(R))
                        && restoration.records.equals(List.of(record(1, PKG_A, A))),
                        "merged " + restoration.records);
                new NativePrincipalPins(64).restore(new NativePrincipalPins.Snapshot(2,
                        restoration.records, restoration.retiringIds));
            }
            Map<Integer, History> twice = new TreeMap<>(principalOne);
            twice.putAll(packageOfR);
            NativeIdentityPersistence.Restoration both = NativeIdentityPersistence.restoration(twice);
            check(problems, both.withdrawnReservations.equals(Set.of(R, D)) && both.records.isEmpty(),
                    "one package twice " + both.records);
            Map<Integer, History> misplaced = new TreeMap<>();
            misplaced.put(D, principalOne.get(R));
            check(problems, NativeIdentityPersistence.restoration(misplaced).withdrawnReservations
                    .equals(Set.of(D)), "a history under another app ID was restored");
        });
        run("restoration / reservations restore PENDING under the selected counter", problems -> {
            Path root = reserved();
            PackageManagerService pm = reopenOf(root, V2, Map.of());
            NativePrincipalPins.Pin pin = pm.mSettings.pins.find(PKG_R, 0);
            check(problems, pin != null && pin.phase() == Phase.PENDING && pin.issuance() == null
                    && pin.record().equals(recordR()) && pm.mSettings.pins.hasKnownCounter()
                    && pm.mSettings.pins.snapshotForWrite().lastId == 1
                    && pm.mSettings.nativePrincipalCreationReadyLPr(), "restored " + pin);
            History stored = pm.mSettings.nativePrincipalStoredHistoryLPr(recordR());
            check(problems, stored != null && stored.source == Source.RESERVATION
                    && stored.equals(loadedOf(root, V2).history(R)), "stored " + stored);
        });
        run("restoration / an unknown counter restores R beside unselected X", problems -> {
            Header addition = v2(2, boundCreating(R, 1, PKG_R), boundCreating(D, 2, PKG_D));
            Path root = layout(bytes(RESERVED_R), bytes(addition), bytes(addition));
            NativeIdentityStore.Loaded view = loadedOf(root, V2);
            reservedR(problems, view, "beside an addition");
            check(problems, view.history(D) == null && view.unselectedFootprint && view.creationReady()
                    && !view.counterRestorable(), "view " + view.history(D));
            PackageManagerService pm = reopenOf(root, V2, Map.of());
            check(problems, !pm.mSettings.pins.hasKnownCounter() && pm.mSettings.pins.find(PKG_R, 0) != null
                    && pm.mSettings.pins.find(PKG_D, 0) == null && pm.mSettings.isNativePrincipalAppIdLPr(D)
                    && !pm.mSettings.nativePrincipalCreationReadyLPr(), "registry");
        });
        run("stored history / only the exact record is returned", problems -> {
            PackageManagerService pm = reopenOf(reserved(), V2, Map.of());
            check(problems, pm.mSettings.nativePrincipalStoredHistoryLPr(recordR()) != null
                    && pm.mSettings.nativePrincipalStoredHistoryLPr(
                            new NativePrincipalPins.Record(1, PKG_R, R, 0, SERIAL + 1)) == null
                    && pm.mSettings.nativePrincipalStoredHistoryLPr(
                            new NativePrincipalPins.Record(1, PKG_A, R, 0, SERIAL)) == null
                    && pm.mSettings.nativePrincipalStoredHistoryLPr(
                            new NativePrincipalPins.Record(1, PKG_R, A, 0, SERIAL)) == null,
                    "a partial match was returned");
        });
        run("stored history / only an exact core pin is remembered", problems -> {
            PackageManagerService pm = livePmOf(V2);
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            manager.prepare(manager.select(PKG_B, 0));
            Path other = pairLayout(v2(1, live(C)));
            slot(other, C, bound(C, PKG_C, 1, false, 1));
            pm.mSettings.observeNativeIdentityStoreLPw(loadedOf(other, V2));
            check(problems, !pm.mSettings.mNativeRememberedBindings.containsKey(1L)
                    && pm.mSettings.nativePrincipalStoredHistoryLPr(record(1, PKG_B, B)) == null,
                    "another record's history was remembered for pin 1");
        });
    }

    // Explicit designation rebinds a restored creation with its original ID and signers.
    private static void rebind() {
        run("rebind / an explicit designation publishes the original ID", problems -> {
            Path root = reserved();
            PackageManagerService pm = boot(root, V2, Map.of(PKG_R, R));
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle restored = manager.find(PKG_R, 0);
            check(problems, restored != null && manager.phase(restored) == Phase.PENDING
                    && manager.identity(restored).equals(recordR()), "restored handle");
            check(problems, throwsType(() -> manager.commit(restored), IllegalStateException.class),
                    "committed without a designation");
            NativePrincipalManager.Handle rebound = manager.prepare(manager.select(PKG_R, 0));
            check(problems, rebound == restored && pm.mSettings.pins.find(PKG_R, 0).issuance() == null,
                    "the rebind replaced the handle or invented issuance");
            check(problems, manager.commit(rebound) && manager.phase(rebound) == Phase.ACTIVE, "commit refused");
            NativeIdentityStore.Loaded after = loadedOf(root, V2);
            check(problems, v2(1, live(R)).equals(after.header.value) && BODY_R.equals(after.slots.get(R).value)
                    && after.history(R) != null && after.history(R).source == Source.BODY
                    && pm.mSettings.pins.snapshotForWrite().lastId == 1, "published " + after.header.value);
            check(problems, manager.currentIdentity(rebound).equals(recordR()), "current identity");
            check(problems, reopenedPhase(root, V2, PKG_R) == Phase.PENDING, "reopened phase");
        });
        run("rebind / the next issuance advances the selected counter", problems -> {
            Path root = reserved();
            PackageManagerService pm = boot(root, V2, Map.of(PKG_R, R, PKG_B, B));
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            check(problems, manager.commit(manager.prepare(manager.select(PKG_R, 0))), "rebind refused");
            NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
            check(problems, manager.identity(b).id == 2 && manager.commit(b)
                    && v2(2, live(B), live(R)).equals(storedOf(root, V2))
                    && pm.mSettings.pins.snapshotForWrite().lastId == 2, "issuance " + storedOf(root, V2));
        });
        run("rebind / a new package reserves beside an unrebound reservation", problems -> {
            Path root = reserved();
            PackageManagerService pm = boot(root, V2, Map.of(PKG_R, R, PKG_B, B));
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle restored = manager.find(PKG_R, 0);
            NativePrincipalManager.Handle b = manager.prepare(manager.select(PKG_B, 0));
            check(problems, manager.identity(b).id == 2 && manager.commit(b)
                    && v2(2, live(B), boundCreating(R, 1, PKG_R)).equals(storedOf(root, V2)),
                    "beside " + storedOf(root, V2));
            check(problems, manager.phase(restored) == Phase.PENDING && manager.find(PKG_R, 0) == restored
                    && pm.mSettings.pins.find(PKG_R, 0).issuance() == null, "the reservation changed");
        });
        run("rebind / missing directory, empty directory and torn seed publish", problems -> {
            for (String kind : List.of("missing", "empty", "torn")) {
                Path root = reserved();
                if (!kind.equals("missing")) {
                    Path directory = slotDirectory(root, R);
                    if (kind.equals("torn")) {
                        Files.write(directory.resolve("record.bin-seed"),
                                Arrays.copyOf(NativeIdentityRecords.encodeSlot(BODY_R), 40));
                    }
                }
                PackageManagerService pm = boot(root, V2, Map.of(PKG_R, R));
                NativePrincipalManager manager = new NativePrincipalManager(pm);
                NativePrincipalManager.Handle r = manager.prepare(manager.select(PKG_R, 0));
                boolean committed = manager.commit(r);
                NativeIdentityStore.Loaded after = loadedOf(root, V2);
                check(problems, committed && v2(1, live(R)).equals(after.header.value)
                        && BODY_R.equals(after.slots.get(R).value) && manager.identity(r).equals(recordR()),
                        kind + " " + after.header.value);
            }
        });
        run("rebind / a mismatched intact seed refuses and keeps the reservation", problems -> {
            Path root = reserved();
            Path seed = slotDirectory(root, R).resolve("record.bin-seed");
            byte[] foreign = NativeIdentityRecords.encodeSlot(userBody(R, PKG_R, 1, 0, OTHER_SIGNERS));
            Files.write(seed, foreign);
            PackageManagerService pm = boot(root, V2, Map.of(PKG_R, R));
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle r = manager.prepare(manager.select(PKG_R, 0));
            check(problems, !manager.commit(r) && manager.phase(r) == Phase.PENDING,
                    "published beside a foreign seed");
            check(problems, sameBytes(seed, foreign)
                    && !Files.exists(root.resolve("slots/" + R + "/record.bin"), LinkOption.NOFOLLOW_LINKS)
                    && sameBytes(root.resolve("store.bin"), bytes(RESERVED_R))
                    && sameBytes(root.resolve("store.bin.reservecopy"), bytes(RESERVED_R)), "footprint");
            reservedR(problems, loadedOf(root, V2), "after the refusal");
            check(problems, reopenedPhase(root, V2, PKG_R) == Phase.PENDING, "reopened phase");
        });
        run("rebind / changed APK signers refuse without taking APK history", problems -> {
            Path root = reserved();
            PackageManagerService pm = boot(root, V2, Map.of(PKG_R, R));
            SigningDetails replaced = signing(5, 2);
            PackageSetting installed = pm.mSettings.packages.get(PKG_R);
            installed.signing = replaced;
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            age(root);
            Map<String, String> before = footprint(root);
            check(problems, throwsType(() -> manager.prepare(manager.select(PKG_R, 0)),
                    IllegalStateException.class), "rebound to the current APK signers");
            History stored = pm.mSettings.nativePrincipalStoredHistoryLPr(recordR());
            check(problems, footprint(root).equals(before) && stored != null
                    && stored.signerSha256.equals(SIGNERS)
                    && loadedOf(root, V2).history(R).signerSha256.equals(SIGNERS),
                    "history took the APK signers");
            check(problems, !pm.mSettings.nativeScanBindingAllowedLPr(installed, replaced)
                    && pm.mSettings.nativeScanBindingAllowedLPr(installed, OWN), "scan took the APK signers");
        });
        run("rebind / a changed serial, UID, mapping or shared user refuses", problems -> {
            Path root = reserved();
            PackageManagerService serial = boot(root, V2, Map.of(PKG_R, R));
            NativePrincipalManager first = new NativePrincipalManager(serial);
            USERS.info.serialNumber = 8;
            try {
                check(problems, throwsType(() -> first.prepare(first.select(PKG_R, 0)),
                        IllegalStateException.class), "another serial rebound");
            } finally {
                USERS.info.serialNumber = 7;
            }
            PackageManagerService moved = boot(root, V2, Map.of(PKG_R, 10020));
            NativePrincipalManager second = new NativePrincipalManager(moved);
            check(problems, moved.mSettings.nativePrincipalDesignationDeferredLPr(PKG_R)
                    && throwsType(() -> second.prepare(second.select(PKG_R, 0)), IllegalStateException.class),
                    "another UID rebound");
            PackageManagerService unmapped = boot(root, V2, Map.of());
            NativePrincipalManager third = new NativePrincipalManager(unmapped);
            check(problems, third.find(PKG_R, 0) != null
                    && throwsType(() -> third.select(PKG_R, 0), IllegalStateException.class), "unmapped");
            PackageManagerService shared = boot(root, V2, Map.of(PKG_R, R));
            shared.mSettings.packages.get(PKG_R).shared = true;
            NativePrincipalManager fourth = new NativePrincipalManager(shared);
            check(problems, throwsType(() -> fourth.select(PKG_R, 0), IllegalStateException.class),
                    "a shared user rebound");
            reservedR(problems, loadedOf(root, V2), "after every refusal");
        });
        run("rebind / an unknown counter rebinds but neither commits nor issues", problems -> {
            Header addition = v2(2, boundCreating(R, 1, PKG_R), boundCreating(D, 2, PKG_D));
            Path root = layout(bytes(RESERVED_R), bytes(addition), bytes(addition));
            PackageManagerService pm = boot(root, V2, Map.of(PKG_R, R, PKG_C, C));
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle r = manager.prepare(manager.select(PKG_R, 0));
            check(problems, manager.identity(r).equals(recordR()) && !pm.mSettings.pins.hasKnownCounter(),
                    "rebind");
            age(root);
            Map<String, String> before = footprint(root);
            check(problems, !manager.commit(r) && manager.phase(r) == Phase.PENDING
                    && footprint(root).equals(before), "committed without a counter");
            check(problems, throwsType(() -> manager.prepare(manager.select(PKG_C, 0)),
                    IllegalStateException.class) && pm.mSettings.pins.find(PKG_C, 0) == null
                    && footprint(root).equals(before), "issued without a counter");
        });
        run("rebind / a protected target confirms beside its predecessors", problems -> {
            Path root = protectedTarget();
            PackageManagerService pm = boot(root, V2, Map.of(PKG_C, C));
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle c = manager.prepare(manager.select(PKG_C, 0));
            check(problems, manager.identity(c).equals(record(3, PKG_C, C)) && manager.commit(c),
                    "rebind refused");
            NativeIdentityStore.Loaded after = loadedOf(root, V2);
            check(problems, v2(3, creating(A, 1, PKG_A), creating(B, 2, PKG_B), live(C))
                    .equals(after.header.value) && after.header.decodedCopies.size() == 2
                    && after.slots.get(C).status == Status.VALID
                    && pm.mSettings.pins.snapshotForWrite().lastId == 3, "result " + after.header.value);
        });
        run("rebind / a body first creation completes its lost LIVE entry", problems -> {
            Path root = pairLayout(v2(1, boundCreating(A, 1, PKG_A)));
            slot(root, A, BODY_A);
            PackageManagerService pm = boot(root, V2, Map.of(PKG_A, A));
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle a = manager.prepare(manager.select(PKG_A, 0));
            check(problems, manager.commit(a) && v2(1, live(A)).equals(storedOf(root, V2))
                    && BODY_A.equals(loadedOf(root, V2).slots.get(A).value), "completion " + storedOf(root, V2));
        });
    }

    // Published bindings and current identities come only from bodies.
    private static void bodyOnly() {
        run("body only / no header only binding, current identity or ACTIVE exposure", problems -> {
            Path root = reserved();
            PackageManagerService pm = boot(root, V2, Map.of(PKG_R, R));
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle r = manager.find(PKG_R, 0);
            check(problems, pm.mSettings.nativePrincipalBindingLPr(recordR()) == null
                    && pm.mSettings.persistence.binding(recordR()) == null
                    && throwsType(() -> manager.currentIdentity(r), IllegalStateException.class),
                    "a header only reservation was a published binding");
            manager.prepare(manager.select(PKG_R, 0));
            check(problems, !restricted(root.resolve("slots"), READ_ONLY, () -> manager.commit(r)),
                    "published through a read only namespace");
            pm.mSettings.pins.commit(pm.mSettings.pins.find(PKG_R, 0));
            check(problems, manager.phase(r) == Phase.ACTIVE
                    && throwsType(() -> manager.currentIdentity(r), IllegalStateException.class),
                    "a header only reservation became a current identity");
        });
    }

    // Retirement keeps B1 behavior for owned, rebound and body restored handles. A reservation
    // never rebound refuses before any effect; a cached body missing from the store writes nothing.
    private static void retirement() {
        run("retirement / a never rebound reservation refuses before any effect", problems -> {
            Path root = reserved();
            PackageManagerService pm = boot(root, V2, Map.of(PKG_R, R));
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle r = manager.find(PKG_R, 0);
            age(root);
            Map<String, String> before = footprint(root);
            check(problems, throwsType(() -> manager.beginRetirement(r), IllegalStateException.class)
                    && manager.phase(r) == Phase.PENDING && footprint(root).equals(before),
                    "retirement created a first body");
            check(problems, throwsType(() -> manager.finishRetirementAfterQuiescence(r),
                    IllegalStateException.class) && footprint(root).equals(before)
                    && pm.mSettings.isNativePrincipalAppIdLPr(R), "finish");
            check(problems, reopenedPhase(root, V2, PKG_R) == Phase.PENDING, "reopened phase");
        });
        run("retirement / a cached body missing from the store returns false without a write", problems -> {
            Path root = reserved();
            PackageManagerService pm = boot(root, V2, Map.of(PKG_R, R));
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle r = manager.find(PKG_R, 0);
            NativeIdentityStore store = storeOf(root, V2);
            check(problems, store.resumeCreatingDirectory(RESERVED_R, R)
                    && store.publishCreatingSlot(RESERVED_R, BODY_R), "fixture body");
            observe(pm);
            History stored = pm.mSettings.nativePrincipalStoredHistoryLPr(recordR());
            check(problems, pm.mSettings.nativePrincipalBindingLPr(recordR()) != null && stored != null
                    && stored.source == Source.RESERVATION, "cached view " + stored);
            removeDirectory(root.resolve("slots/" + R));
            age(root);
            Map<String, String> before = footprint(root);
            check(problems, !manager.beginRetirement(r) && manager.phase(r) == Phase.RETIRING
                    && footprint(root).equals(before), "a missing body was recreated");
            // That call observed the fresh store, so the cached view no longer holds the body. A
            // second call takes the early origin guard before any pin or store effect.
            check(problems, pm.mSettings.nativePrincipalBindingLPr(recordR()) == null
                    && pm.mSettings.nativePrincipalStoredHistoryLPr(recordR()) == stored, "observed view");
            String guard = thrown(() -> manager.beginRetirement(r));
            check(problems, guard.equals("IllegalStateException: Restored native reservation needs its"
                    + " designation before retirement") && manager.phase(r) == Phase.RETIRING
                    && footprint(root).equals(before), "second retirement: " + guard);
            String finish = thrown(() -> manager.finishRetirementAfterQuiescence(r));
            check(problems, finish.equals("IllegalStateException: Retirement marker is not durably"
                    + " confirmed") && footprint(root).equals(before), "finish: " + finish);
            String commit = thrown(() -> manager.commit(r));
            check(problems, commit.equals("IllegalStateException: Restored pin needs an explicit"
                    + " designation binding") && footprint(root).equals(before), "commit: " + commit);
            String prepare = thrown(() -> manager.prepare(manager.select(PKG_R, 0)));
            check(problems, prepare.equals("IllegalStateException: retiring pin must finish first: "
                    + recordR()) && manager.phase(r) == Phase.RETIRING && manager.find(PKG_R, 0) == r
                    && footprint(root).equals(before), "prepare: " + prepare);
            check(problems, reopenedPhase(root, V2, PKG_R) == Phase.PENDING
                    && loadedOf(root, V2).history(R).source == Source.RESERVATION, "reopened");
        });
        run("retirement / an explicitly rebound reservation publishes and retires", problems -> {
            Path root = reserved();
            PackageManagerService pm = boot(root, V2, Map.of(PKG_R, R));
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle r = manager.prepare(manager.select(PKG_R, 0));
            check(problems, manager.beginRetirement(r) && manager.phase(r) == Phase.RETIRING, "marker refused");
            NativeIdentityStore.Loaded marked = loadedOf(root, V2);
            Slot marker = marked.slots.get(R).value;
            check(problems, marker != null && marker.generation == 2 && marker.signerSha256.equals(SIGNERS)
                    && marker.users.get(0).retiring && v2(1, live(R)).equals(marked.header.value),
                    "marked " + marked.header.value);
            check(problems, reopenedPhase(root, V2, PKG_R) == Phase.RETIRING, "reopened phase");
            check(problems, manager.finishRetirementAfterQuiescence(r) && v2(1).equals(storedOf(root, V2))
                    && !pm.mSettings.isNativePrincipalAppIdLPr(R), "release " + storedOf(root, V2));
        });
        run("retirement / BODY origin republishes after its body was observed missing", problems -> {
            Path root = pairLayout(v2(1, boundCreating(A, 1, PKG_A)));
            slot(root, A, BODY_A);
            PackageManagerService pm = boot(root, V2, Map.of(PKG_A, A));
            removeDirectory(root.resolve("slots/" + A));
            observe(pm);
            History current = loadedOf(root, V2).history(A);
            check(problems, current != null && current.source == Source.RESERVATION
                    && pm.mSettings.nativePrincipalBindingLPr(record(1, PKG_A, A)) == null, "fixture view");
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            // Made after the missing body was observed: the origin is the stored BODY history.
            NativePrincipalManager.Handle a = manager.find(PKG_A, 0);
            check(problems, manager.beginRetirement(a), "BODY origin refused");
            NativeIdentityStore.Loaded marked = loadedOf(root, V2);
            Slot marker = marked.slots.get(A).value;
            check(problems, v2(1, live(A)).equals(marked.header.value) && marker != null
                    && marker.generation == 2 && marker.users.get(0).retiring
                    && marker.signerSha256.equals(SIGNERS), "marked " + marked.header.value);
            check(problems, manager.finishRetirementAfterQuiescence(a) && v2(1).equals(storedOf(root, V2)),
                    "finish " + storedOf(root, V2));
        });
        run("retirement / no durable marker restores PENDING after restart", problems -> {
            Path root = reserved();
            PackageManagerService pm = boot(root, V2, Map.of(PKG_R, R));
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle r = manager.prepare(manager.select(PKG_R, 0));
            check(problems, !restricted(root.resolve("slots"), READ_ONLY, () -> manager.beginRetirement(r))
                    && manager.phase(r) == Phase.RETIRING, "a marker without a body");
            reservedR(problems, loadedOf(root, V2), "after the refusal");
            check(problems, reopenedPhase(root, V2, PKG_R) == Phase.PENDING, "restored phase");
            check(problems, throwsType(() -> manager.finishRetirementAfterQuiescence(r),
                    IllegalStateException.class), "finish");
        });
        run("retirement / a restored retiring body finishes", problems -> {
            Path root = pairLayout(v2(1, live(A)));
            slot(root, A, bound(A, PKG_A, 1, true, 2));
            PackageManagerService pm = boot(root, V2, Map.of(PKG_A, A));
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle a = manager.find(PKG_A, 0);
            check(problems, manager.phase(a) == Phase.RETIRING && manager.beginRetirement(a)
                    && manager.finishRetirementAfterQuiescence(a) && v2(1).equals(storedOf(root, V2)),
                    "retirement " + storedOf(root, V2));
        });
    }

    // The facade runs the exact scan fragment of the adapted Settings.
    private static void scan() {
        run("scan / a mapped reservation is scanned with its recorded signers", problems -> {
            PackageManagerService pm = boot(reserved(), V2, Map.of(PKG_R, R));
            PackageSetting candidate = pm.mSettings.packages.get(PKG_R);
            check(problems, pm.mSettings.nativeScanSubjectAllowedLPr(candidate)
                    && pm.mSettings.nativeScanBindingAllowedLPr(candidate, OWN)
                    && !pm.mSettings.nativeScanBindingAllowedLPr(candidate, signing(6, 1)), "scan");
        });
        run("scan / signer, serial, retiring, mapping and shared negatives", problems -> {
            PackageManagerService pm = boot(reserved(), V2, Map.of(PKG_R, R));
            PackageSetting mapped = pm.mSettings.packages.get(PKG_R);
            USERS.info.serialNumber = 8;
            try {
                check(problems, !pm.mSettings.nativeScanSubjectAllowedLPr(mapped), "another serial");
            } finally {
                USERS.info.serialNumber = 7;
            }
            USERS.info.partial = true;
            try {
                check(problems, !pm.mSettings.nativeScanSubjectAllowedLPr(mapped), "a partial user");
            } finally {
                USERS.info.partial = false;
            }
            PackageSetting sharedCandidate = new PackageSetting(PKG_R);
            sharedCandidate.appId = R;
            sharedCandidate.shared = true;
            check(problems, !pm.mSettings.nativeScanSubjectAllowedLPr(sharedCandidate), "a shared candidate");
            PackageSetting candidate = new PackageSetting(PKG_R);
            candidate.appId = R;
            mapped.shared = true;
            check(problems, !pm.mSettings.nativeScanSubjectAllowedLPr(candidate), "a shared mapping");
            mapped.shared = false;
            check(problems, pm.mSettings.nativeScanSubjectAllowedLPr(candidate), "the control");
            pm.mSettings.mNativeRecoveryView = pm.mSettings.mNativeRecoveryView.defer(PKG_R, null);
            check(problems, !pm.mSettings.nativeScanSubjectAllowedLPr(candidate), "a deferred name");
            // Without seeding, so the mapping rule alone refuses these.
            PackageManagerService foreignMapping = reopenOf(reserved(), V2, Map.of(PKG_X, R));
            check(problems, !foreignMapping.mSettings.nativePrincipalDesignationDeferredLPr(PKG_R)
                    && !foreignMapping.mSettings.nativeScanSubjectAllowedLPr(candidate),
                    "another mapped package");
            PackageManagerService noMapping = reopenOf(reserved(), V2, Map.of());
            check(problems, !noMapping.mSettings.nativePrincipalDesignationDeferredLPr(PKG_R)
                    && !noMapping.mSettings.nativeScanSubjectAllowedLPr(candidate), "no mapping");
            Path retiring = pairLayout(v2(1, live(A)));
            slot(retiring, A, bound(A, PKG_A, 1, true, 2));
            PackageManagerService retiringPm = boot(retiring, V2, Map.of(PKG_A, A));
            check(problems, !retiringPm.mSettings.nativeScanSubjectAllowedLPr(
                    retiringPm.mSettings.packages.get(PKG_A)), "a retiring history");
        });
        run("scan / a withdrawn reservation defers its package", problems -> {
            Path root = pairLayout(v2(2, boundCreating(R, 1, PKG_R), boundCreating(D, 2, PKG_R)));
            PackageManagerService pm = boot(root, V2, Map.of(PKG_R, R));
            check(problems, pm.mSettings.nativePrincipalDesignationDeferredLPr(PKG_R)
                    && !pm.mSettings.nativeScanSubjectAllowedLPr(pm.mSettings.packages.get(PKG_R)),
                    "a withdrawn reservation was scanned");
        });
    }

    // The harness runs the exact recovery seeding fragment over the same history view.
    private static void seeding() {
        File code = new File("/data/app/~~host/" + PKG_R + "-1");
        run("seeding / a mapped reservation stays recoverable", problems -> {
            NativeIdentityStore.Loaded view = loadedOf(reserved(), V2);
            NativeHistoryHarness mapped = seeded(view, R,
                    new NativeHistoryHarness.PackageSetting(PKG_R, R, false));
            NativePrincipalRecovery recovery = mapped.mNativeRecoveryView;
            check(problems, !recovery.defersName(PKG_R) && recovery.protectsName(PKG_R)
                    && recovery.keepsCodePath(code) && recovery.protectsKeystore(R)
                    && !recovery.hasUnidentifiedCode()
                    && mapped.nativePrincipalPinsLPr().find(PKG_R, 0) != null, "view");
        });
        run("seeding / an unmapped reservation keeps its hold and unidentified code", problems -> {
            NativeIdentityStore.Loaded view = loadedOf(reserved(), V2);
            NativePrincipalRecovery recovery = seeded(view, R, null).mNativeRecoveryView;
            check(problems, recovery.defersName(PKG_R) && recovery.protectsName(PKG_R)
                    && recovery.hasUnidentifiedCode() && recovery.protectsKeystore(R)
                    && recovery.preservesUnidentifiedCode(new File("/data/app/~~opaque/base.apk"),
                            new File("/data/app")), "view");
        });
        run("seeding / shared and foreign mappings are deferred", problems -> {
            NativeIdentityStore.Loaded view = loadedOf(reserved(), V2);
            NativeHistoryHarness.SharedUserSetting sharedUser = new NativeHistoryHarness.SharedUserSetting();
            sharedUser.add(state("dev.andrix.shared"));
            NativePrincipalRecovery shared = seeded(view, R, sharedUser).mNativeRecoveryView;
            check(problems, shared.defersName("dev.andrix.shared") && shared.defersName(PKG_R)
                    && shared.hasUnidentifiedCode() && shared.protectsKeystore(R), "a shared user mapping");
            NativePrincipalRecovery other = seeded(view, R,
                    new NativeHistoryHarness.PackageSetting(PKG_X, R, false)).mNativeRecoveryView;
            check(problems, other.defersName(PKG_X) && other.defersName(PKG_R) && other.protectsKeystore(R),
                    "another package mapping");
            NativePrincipalRecovery sharedSetting = seeded(view, R,
                    new NativeHistoryHarness.PackageSetting(PKG_R, R, true)).mNativeRecoveryView;
            check(problems, sharedSetting.defersName(PKG_R), "a shared setting of the package");
        });
        NativeHistoryHarness.PackageSetting mappedR = new NativeHistoryHarness.PackageSetting(PKG_R, R, false);
        run("seeding / a matching data owner keeps a mapped reservation recoverable", problems -> {
            NativeIdentityStore.Loaded view = loadedOf(reserved(), V2);
            NativeHistoryHarness booted = seeded(view, R, mappedR, Map.of(PKG_R, R), true);
            NativePrincipalRecovery recovery = booted.mNativeRecoveryView;
            check(problems, !recovery.defersName(PKG_R) && recovery.protectsName(PKG_R)
                    && recovery.keepsCodePath(CODE_R) && !recovery.hasUnidentifiedCode()
                    && fenced(recovery, R) && booted.nativePrincipalPinsLPr().find(PKG_R, 0) != null,
                    recoveryFacts(recovery));
        });
        run("seeding / foreign, unreadable and unowned data owners are deferred", problems -> {
            NativeIdentityStore.Loaded view = loadedOf(reserved(), V2);
            Map<String, Map<String, Integer>> owners = new TreeMap<>();
            owners.put("a foreign owner", Map.of(PKG_R, FOREIGN_OWNER_UID));
            owners.put("an unreadable owner", Map.of(PKG_R, -1));
            for (Map.Entry<String, Map<String, Integer>> owner : owners.entrySet()) {
                NativePrincipalRecovery recovery = seeded(view, R, mappedR, owner.getValue(), true)
                        .mNativeRecoveryView;
                check(problems, recovery.defersName(PKG_R) && recovery.protectsName(PKG_R)
                        && recovery.keepsCodePath(CODE_R) && fenced(recovery, R),
                        owner.getKey() + ": " + recoveryFacts(recovery));
            }
            NativePrincipalRecovery unowned = seeded(view, R, mappedR, Map.of(PKG_ORPHAN, R), true)
                    .mNativeRecoveryView;
            check(problems, unowned.defersName(PKG_ORPHAN) && unowned.protectsName(PKG_ORPHAN)
                    && !unowned.defersName(PKG_R) && unowned.keepsCodePath(CODE_R) && fenced(unowned, R),
                    "an unowned name: " + recoveryFacts(unowned));
        });
        run("seeding / an incomplete data owner enumeration keeps unidentified code", problems -> {
            NativeIdentityStore.Loaded view = loadedOf(reserved(), V2);
            NativePrincipalRecovery recovery = seeded(view, R, mappedR, Map.of(), false).mNativeRecoveryView;
            check(problems, recovery.hasUnidentifiedCode() && !recovery.defersName(PKG_R)
                    && recovery.keepsCodePath(CODE_R) && fenced(recovery, R)
                    && recovery.preservesUnidentifiedCode(new File("/data/app/~~opaque/base.apk"),
                            new File("/data/app")), recoveryFacts(recovery));
        });
        run("seeding / a reservation seeds as its published body under every data owner", problems -> {
            Path published = reserved();
            slot(published, R, BODY_R);
            NativeIdentityStore.Loaded reservation = loadedOf(reserved(), V2);
            NativeIdentityStore.Loaded body = loadedOf(published, V2);
            check(problems, reservation.history(R).source == Source.RESERVATION
                    && body.history(R).source == Source.BODY, "fixture histories");
            Map<String, Map<String, Integer>> owners = new TreeMap<>();
            owners.put("none", Map.of());
            owners.put("matching", Map.of(PKG_R, R));
            owners.put("foreign", Map.of(PKG_R, FOREIGN_OWNER_UID));
            owners.put("unreadable", Map.of(PKG_R, -1));
            owners.put("unowned", Map.of(PKG_ORPHAN, R));
            for (Map.Entry<String, Map<String, Integer>> owner : owners.entrySet()) {
                for (boolean enumerated : List.of(true, false)) {
                    NativeHistoryHarness.SettingBase mapping = mappedR;
                    String held = recoveryFacts(seeded(reservation, R, mapping, owner.getValue(),
                            enumerated).mNativeRecoveryView);
                    String twin = recoveryFacts(seeded(body, R, mapping, owner.getValue(),
                            enumerated).mNativeRecoveryView);
                    check(problems, held.equals(twin), owner.getKey() + " " + enumerated + ": " + held
                            + " and " + twin);
                }
            }
        });
    }

    // Every UID hold, package fence and keystore protection remains beside the histories.
    private static void holds() {
        run("holds / every hold and fence remains", problems -> {
            Header selected = v2(2, live(A), releasing(B), boundCreating(R, 2, PKG_R));
            Header addition = v2(3, live(A), releasing(B), boundCreating(R, 2, PKG_R),
                    boundCreating(D, 3, PKG_D));
            Path root = layout(bytes(selected), bytes(addition), bytes(addition));
            slot(root, A, BODY_A);
            slot(root, B, tombstone(B, PKG_B, 3));
            PackageManagerService pm = boot(root, V2, Map.of(PKG_A, A, PKG_R, R));
            Set<Integer> held = Set.of(A, B, R, D);
            for (int appId : held) {
                check(problems, pm.mSettings.isNativePrincipalAppIdLPr(appId)
                        && pm.mSettings.mNativeRecoveryView.protectsKeystore(appId), "hold " + appId);
            }
            check(problems, pm.mSettings.pins.reservedAppIds().equals(Set.of(A, R))
                    && !pm.mSettings.pins.hasKnownCounter(), "pins " + pm.mSettings.pins.reservedAppIds());
            for (String name : List.of(PKG_A, PKG_B, PKG_R, PKG_D)) {
                check(problems, pm.mSettings.isNativePrincipalPackageLPr(name), "package " + name);
            }
            int fresh = pm.mSettings.ids.acquireAndRegisterNewAppId(new PackageSetting("dev.andrix.fresh"));
            check(problems, fresh >= 10000 && !held.contains(fresh), "allocated a held ID " + fresh);
        });
        run("holds / an exact release lifts only its own UID hold and keystore fence", problems -> {
            Path root = pairLayout(BESIDE_A);
            slot(root, A, BODY_A);
            PackageManagerService pm = boot(root, V2, Map.of(PKG_A, A, PKG_R, R));
            NativePrincipalManager manager = new NativePrincipalManager(pm);
            NativePrincipalManager.Handle r = manager.prepare(manager.select(PKG_R, 0));
            check(problems, manager.commit(r) && manager.beginRetirement(r)
                    && fenced(pm.mSettings.mNativeRecoveryView, R) && pm.mSettings.isNativePrincipalAppIdLPr(R),
                    "before the release");
            check(problems, manager.finishRetirementAfterQuiescence(r)
                    && v2(2, live(A)).equals(storedOf(root, V2)), "release " + storedOf(root, V2));
            // The refresh after the exact release publishes the smaller hold set to the recovery
            // view, as the adapted Settings refresh does.
            NativePrincipalRecovery view = pm.mSettings.mNativeRecoveryView;
            check(problems, !pm.mSettings.isNativePrincipalAppIdLPr(R) && !view.holdsAppId(R)
                    && !view.protectsKeystore(R), "the released hold or keystore fence remains");
            check(problems, pm.mSettings.isNativePrincipalAppIdLPr(A) && fenced(view, A)
                    && pm.mSettings.pins.reservedAppIds().equals(Set.of(A)), "another hold was lifted");
            // Only the native identity is released. This claims nothing about the package's APK
            // or data: it stays installed at its app ID, and the names and code paths the view
            // protects stay until a separately owned maintenance rebuilds the view.
            PackageSetting installed = pm.mSettings.getPackageLPr(PKG_R);
            check(problems, installed != null && installed.getAppId() == R
                    && pm.mSettings.getSettingLPr(R) == installed && view.protectsName(PKG_R)
                    && view.keepsCodePath(CODE_R), "installed or protected state changed");
        });
    }

    public static void main(String[] args) throws Exception {
        if (!NativeCreationHistoryTest.class.desiredAssertionStatus()) {
            throw new AssertionError("run with java -ea");
        }
        if (!LINEAGE.equals(Settings.LINEAGE)) throw new AssertionError("facade lineage");
        start(Path.of(args[0]).resolve("creation-history"));
        requireDac(Path.of(args[0]).resolve("creation-history-dac"));
        LocalServices.addService(UserManagerInternal.class, USERS);
        sources();
        fallbacks();
        gates();
        uniqueness();
        restoration();
        rebind();
        bodyOnly();
        retirement();
        scan();
        seeding();
        holds();
        finish(Os.allClosed());
        System.out.println("Historical native identities and exact restored creation rebinding; Android"
                + " boot, crash recovery and version 2 activation unqualified");
    }
}
