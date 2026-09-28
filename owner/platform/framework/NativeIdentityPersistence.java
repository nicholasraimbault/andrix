// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import com.android.server.pm.NativeIdentityRecords.CreationBinding;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.HeaderEntry;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.SlotPhase;
import com.android.server.pm.NativeIdentityRecords.UserEntry;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

/**
 * Package Manager's per target transactions over its {@link NativeIdentityStore}, for the
 * trusted native principal caller only. Each call carries one exact core pin record through
 * the store's checked steps: reservation, publication, retirement marker or final release.
 * Nothing is kept between calls. Every call starts from a fresh load and continues exactly
 * the durable state that the same transaction left behind.
 *
 * <p>This is not a UID allocator, a grant, a caller check or a public API. It takes no Binder
 * input, creates no PackageSetting or other installed state, never initializes a store and
 * deletes nothing except the exact confirmed release of one retiring slot. App IDs are
 * Package Manager's existing assignments. Store records and IDs are metadata, not
 * credentials. The first adapter supports Android user 0 with one user per slot. Stored signer
 * sets are immutable, and no call adds a user to an existing slot.
 *
 * <p>A reservation takes a {@link CreationPlan}: the core snapshot plus the original signer set
 * of each record whose issuance the caller owns. A truly new entry needs that row. Under the
 * store's version 2 format it becomes a complete creation binding; under version 1 the row is
 * provenance the caller must have, and the entry stays as version 1 always wrote it. Durable
 * entries are never refilled from a row, and nothing is taken from the current APK.
 *
 * <p>Caller obligations, which this class cannot check:
 * <ol>
 * <li>One writer. Serialize every call under Package Manager's install lock. Calls block on
 *     file I/O: never hold the PMS state lock or any AMS, WM, work control or admission lock,
 *     and never call from the native Stop lane.
 * <li>Own the exact core handle of the transaction. Validate the actual Package Manager
 *     selection, including the signer set passed here, outside this class.
 * <li>Treat false as refused or uncertain, never as no effect. Durable partial progress may
 *     exist. Keep the original handle, pin, hold and every obligation, and continue with the
 *     same operation and inputs. Never retry as a new operation or present the current APK
 *     as the prior identity.
 * </ol>
 * True means the store's checked writers acknowledged the call's final state. It never
 * authorizes execution, CE access or foreground presentation.
 *
 * <p>Null arguments throw {@link NullPointerException}. Malformed signer sets, lineages and
 * snapshots throw {@link IllegalArgumentException}. Both happen before any effect.
 */
final class NativeIdentityPersistence {
    private static final int USER_SYSTEM = 0;
    private static final int LINEAGE_DIGITS = 32;
    private static final int SIGNER_DIGITS = 64;
    private static final int VERSION_1 = 1;
    private static final int VERSION_2 = 2;

    private final NativeIdentityStore store;

    /**
     * One validated reservation proposal: a complete core snapshot and the original signer set
     * of each of its records whose issuance the caller owns. Immutable and memory only. A row
     * is provenance for a truly new entry and a negative check against a durable binding. It
     * never fills in or replaces a durable entry, and it is no grant or current identity.
     * Records without a row keep their durable entries unchanged; a new one refuses.
     */
    static final class CreationPlan {
        final NativePrincipalPins.Snapshot snapshot;
        private final Map<Long, Set<String>> signers;

        /**
         * Copies the rows. Each key must be a record ID of the snapshot, and each set must hold
         * 1 to MAX_SIGNERS lowercase SHA-256 digests.
         *
         * @throws IllegalArgumentException for a malformed snapshot, a foreign row ID or an
         *     invalid signer set
         * @throws NullPointerException for a null snapshot, map, key, set or digest
         */
        CreationPlan(NativePrincipalPins.Snapshot snapshot, Map<Long, Set<String>> signers) {
            Objects.requireNonNull(snapshot, "snapshot");
            Map<Long, Set<String>> rows = Map.copyOf(Objects.requireNonNull(signers, "signers"));
            checkSnapshot(snapshot);
            Set<Long> ids = new HashSet<>();
            for (NativePrincipalPins.Record record : snapshot.records) ids.add(record.id);
            Map<Long, Set<String>> copy = new HashMap<>();
            for (Map.Entry<Long, Set<String>> row : rows.entrySet()) {
                if (!ids.contains(row.getKey())) {
                    throw new IllegalArgumentException("signer row for an ID outside the snapshot");
                }
                copy.put(row.getKey(), signers(row.getValue()));
            }
            this.snapshot = snapshot;
            this.signers = Map.copyOf(copy);
        }

        /** The owned original signer set of this record ID, or null without one. */
        Set<String> row(long id) {
            return signers.get(id);
        }
    }

    NativeIdentityPersistence(NativeIdentityStore store) {
        this.store = Objects.requireNonNull(store, "store");
    }

    /** Read only discovery of every hold and eligible record. Creates and repairs nothing. */
    NativeIdentityStore.Loaded load() {
        return store.load();
    }

    /**
     * The store's chosen eligible slot bound exactly to this user 0 record, or null. Data
     * only: its retiring flag and signer set feed the caller's own checks, never permission.
     */
    Slot binding(NativePrincipalPins.Record record) {
        Objects.requireNonNull(record, "record");
        return bound(store.load(), record);
    }

    /**
     * Durably reserves every pending core pin that the store's counter has not yet passed,
     * before any of them is published. Pass a plan of the core's complete
     * {@code snapshotForWrite()}. Memory prepares can issue IDs 1 and 2 and then publish 2
     * first. A counter advanced to 2 without an entry for 1 would leave 1 permanently
     * unreservable.
     *
     * <p>Needs a creation ready store. Every existing index entry is kept exactly, including
     * damaged, unknown and core absent slots: core absence never omits anything. A record
     * with an index entry must match a CREATING entry exactly, and LIVE or RELEASING slots are
     * never reallocated here. A record without one gets a new CREATING entry only if its ID is
     * above the durable counter and the plan has its owned signer row. A pending creation whose
     * core handle is already RETIRING still gets its negative reservation, so its original
     * retirement can publish a marker and complete. That is not activation. The counter becomes
     * the larger of the store's and the snapshot's lastId, never a maximum of observed IDs. No
     * slot directory or body is created.
     *
     * <p>An entry listed only by an unselected header copy is retained as a negative footprint;
     * it can reflect an earlier unacknowledged write. Only this snapshot's own exact record
     * restates it, with its exact original entry, and the snapshot counter must cover every
     * copy's. Otherwise the call refuses before any effect, as does every other header write.
     * The counter never advances without a new reservation.
     */
    boolean reservePending(CreationPlan plan) {
        Objects.requireNonNull(plan, "plan");
        for (NativePrincipalPins.Record record : plan.snapshot.records) {
            if (record.userId != USER_SYSTEM) return false;
        }
        NativeIdentityStore.Loaded loaded = store.load();
        Header next = projectReservation(loaded, plan);
        if (next == null) return false;
        // Also the exact retry: an unchanged header is rewritten through checked writers.
        return store.writeHeader(loaded.header.value, next);
    }

    /**
     * Pure projection shared by admission, on the cached view, and by the writer, on a fresh
     * load: the one place a reservation header is built. It needs no I/O and grants nothing. A
     * cached view is not a durability acknowledgement or a live lease.
     *
     * <p>It keeps every durable index entry and adds each unreserved record of the plan,
     * including RETIRING ones, in one of three ways. A selected entry is kept unchanged; its
     * CREATING tuple must be this record's, and a complete binding must name its user and
     * serial and, where the plan has a row, that signer set. A missing row never strands it.
     * An unselected addition keeps its exact original entry, an absent binding included, under
     * the same checks; nothing refills it. Any other record is truly new: it needs its owned
     * row, and under the store's version 2 format it carries its original user, serial and
     * signer set as a complete creation binding. Only a truly new bound entry raises a version
     * 1 header to version 2; restatements alone keep the version. Nothing is inferred from an
     * APK or reconstructed after a restart.
     *
     * <p>The exact chosen version and entries are measured by the encoder before any Header is
     * built. A proposal over MAX_SLOTS or MAX_BYTES is refused here, so admission refuses it
     * before an ID is issued and the writer before any effect. The store's header copy rule
     * then applies: it refuses to lose or rebind an unselected addition, to reuse its creation
     * ID, to fall below any copy's counter, to advance the counter without a new reservation
     * or to change the version without a truly new bound entry.
     *
     * @return the header to write, or null to refuse
     */
    Header projectReservation(NativeIdentityStore.Loaded loaded, CreationPlan plan) {
        Objects.requireNonNull(loaded, "loaded");
        Objects.requireNonNull(plan, "plan");
        NativeIdentityStore.Format format = store.format();
        for (NativePrincipalPins.Record record : plan.snapshot.records) {
            if (record.userId != USER_SYSTEM) return null;
        }
        if (!loaded.creationReady()) return null;
        Header current = loaded.header.value;
        NativeIdentityStore.HeaderCopies copies = NativeIdentityStore.HeaderCopies.of(loaded.header);
        if (copies == null || current.version > format.headerCeiling) return null;
        TreeMap<Integer, HeaderEntry> entries = new TreeMap<>();
        for (HeaderEntry entry : current.entries) entries.put(entry.appId, entry);
        boolean bound = false;
        for (NativePrincipalPins.Record record : plan.snapshot.records) {
            Set<String> row = plan.row(record.id);
            HeaderEntry held = entry(current, record.appId);
            if (held != null) {
                if (held.phase == SlotPhase.CREATING && !reservedFor(held, record, row)) return null;
                continue; // Its own reservation, or an existing slot that publish must match.
            }
            HeaderEntry known = copies.additions.get(record.appId);
            if (known != null) {
                // Its exact original entry: an absent binding stays absent.
                if (!reservedFor(known, record, row)) return null;
                entries.put(record.appId, known);
                continue;
            }
            if (record.id <= current.lastId) return null; // Passed without a reservation.
            if (row == null) return null; // A new entry needs owned signer provenance.
            CreationBinding binding = format.reservationVersion == VERSION_1 ? null
                    : new CreationBinding(record.userId, record.userSerial, row);
            entries.put(record.appId, new HeaderEntry(record.appId, SlotPhase.CREATING,
                    record.id, record.packageName, binding));
            if (binding != null) bound = true;
        }
        int version = bound ? format.reservationVersion : current.version;
        long lastId = Math.max(current.lastId, plan.snapshot.lastId);
        List<HeaderEntry> list = new ArrayList<>(entries.values());
        if (list.size() > NativeIdentityRecords.MAX_SLOTS || NativeIdentityRecords.encodedHeaderLength(
                version, current.lineage, lastId, list) > NativeIdentityRecords.MAX_BYTES) return null;
        Header next = version == VERSION_1 ? new Header(current.lineage, lastId, list)
                : Header.newV2(current.lineage, lastId, list);
        return NativeIdentityStore.keepsHeaderCopies(loaded.header, next, format) ? next : null;
    }

    /**
     * Publishes or confirms this record's exact durable binding. The caller owns the exact
     * core creation or rebinding handle and has validated the actual PMS selection outside
     * this class, including the stored signer set it expects here.
     *
     * <p>An eligible existing binding must match every record field and the expected signer
     * set, and must not be retiring. A valid header's CREATING entry for it completes to LIVE
     * first. With a bad header an intact binding is still confirmed, without the counter.
     * Otherwise the target needs this record's reservePending entry in a creation ready store
     * and no body yet: its private directory is resumed, generation 1 is published and the
     * entry becomes LIVE. Retries confirm the same binding and never issue another ID. Every
     * true result ends with a checked confirmation of the exact slot. A complete creation
     * binding on the entry must name this record's user and serial and the expected signer
     * set, or nothing is published; an entry without one, from an older writer, is published
     * as before.
     */
    boolean publish(NativePrincipalPins.Record record, Set<String> expectedSigners) {
        Objects.requireNonNull(record, "record");
        Set<String> signers = signers(expectedSigners);
        if (record.userId != USER_SYSTEM) return false;
        NativeIdentityStore.Loaded loaded = store.load();
        Slot slot = eligible(loaded, record.appId);
        if (slot == null) {
            if (!loaded.creationReady()) return false;
            Header header = loaded.header.value;
            NativeIdentityStore.ReadResult<Slot> read = loaded.slots.get(record.appId);
            if (!reservedFor(entry(header, record.appId), record, signers) || read == null
                    || read.status != NativeIdentityStore.Status.MISSING) return false;
            Slot created = new Slot(header.lineage, record.appId, record.packageName, 1, signers,
                    List.of(new UserEntry(record.id, record.userId, record.userSerial, false)));
            if (!store.resumeCreatingDirectory(header, record.appId)
                    || !store.publishCreatingSlot(header, created)) return false;
            loaded = store.load();
            slot = eligible(loaded, record.appId);
            if (slot == null || !slot.equals(created)) return false;
        }
        if (!boundTo(slot, record) || !slot.signerSha256.equals(signers)
                || slot.users.get(0).retiring) return false;
        if (loaded.header.status == NativeIdentityStore.Status.VALID) {
            Header header = loaded.header.value;
            HeaderEntry entry = entry(header, record.appId);
            if (entry == null || entry.phase == SlotPhase.RELEASING) return false;
            if (entry.phase == SlotPhase.CREATING && (!reservedFor(entry, record, signers)
                    || !store.writeHeader(header, withPhase(header, record.appId,
                    SlotPhase.LIVE)))) return false;
        }
        return store.confirmExistingSlot(slot);
    }

    /**
     * Durably marks this exact existing binding retiring, before account removal or
     * quiescence begins. Needs only an intact eligible binding, so it works with a bad header.
     * A missing target returns false: the caller publishes its own pending creation first if
     * that creation must enter retirement. An existing marker is confirmed, never cleared.
     */
    boolean markRetiring(NativePrincipalPins.Record record, Set<String> expectedSigners) {
        Objects.requireNonNull(record, "record");
        Set<String> signers = signers(expectedSigners);
        Slot slot = bound(store.load(), record);
        if (slot == null || !slot.signerSha256.equals(signers)) return false;
        UserEntry user = slot.users.get(0);
        if (user.retiring) return store.confirmExistingSlot(slot);
        if (slot.generation == Long.MAX_VALUE) return false;
        return store.updateExistingSlot(slot, new Slot(slot.lineage, slot.appId,
                slot.packageName, slot.generation + 1, slot.signerSha256,
                List.of(new UserEntry(user.id, user.userId, user.userSerial, true))));
    }

    /**
     * Releases this exact retiring binding's slot and index entry, one checked step per
     * durable state. Call only from the trusted PMS handle that owns this record's durably
     * confirmed retirement marker, after the account authority completed producer, work,
     * API, key and data disposition. This class cannot infer that from process death, file
     * paths or a caller boolean. It is never a query of whether an ID is free: absent state
     * is accepted only as this same retirement's continuation after a lost reply.
     *
     * <p>Needs a valid header of the expected lineage whose counter covers the record. A bad
     * header returns false and keeps the directory, index and core hold, and no header is
     * invented. The target, while present, must be exactly this retiring user with the
     * expected signers. A CREATING entry completes to LIVE before the user is omitted, or the
     * tombstone would strand. The tombstone keeps the app ID held. The entry then becomes
     * RELEASING, the directory is removed and only this entry is dropped, with the same
     * counter and every other entry. Each step continues after a lost reply. Every remaining
     * copy must be this binding or its tombstone, and a live binding of this package or ID
     * in another slot refuses. True means the final omission is durable. Only then may the
     * core pin finish.
     */
    boolean finishRetirement(NativePrincipalPins.Record record, String expectedLineage,
            Set<String> expectedSigners) {
        Objects.requireNonNull(record, "record");
        checkLineage(expectedLineage);
        Set<String> signers = signers(expectedSigners);
        if (record.userId != USER_SYSTEM) return false;
        NativeIdentityStore.Loaded loaded = store.load();
        if (!loaded.enumerationComplete
                || loaded.header.status != NativeIdentityStore.Status.VALID) return false;
        Header header = loaded.header.value;
        int appId = record.appId;
        if (!header.lineage.equals(expectedLineage) || header.lastId < record.id
                || liveElsewhere(loaded, record)) return false;
        HeaderEntry entry = entry(header, appId);
        NativeIdentityStore.ReadResult<Slot> read = loaded.slots.get(appId);
        if (entry == null) {
            // Index and directory are both gone. Any remaining hold of this app ID, from a
            // directory or any header copy, refuses.
            return read == null && store.confirmReleasedSlot(header, appId);
        }
        if (read == null) return false;
        for (Slot copy : read.decodedCopies) {
            if (!retirementCopy(copy, record, expectedLineage, signers)) return false;
        }
        Header releasing = withPhase(header, appId, SlotPhase.RELEASING);
        if (entry.phase == SlotPhase.RELEASING) {
            for (Slot copy : read.decodedCopies) if (!copy.users.isEmpty()) return false;
        } else {
            if (read.status != NativeIdentityStore.Status.VALID) return false;
            Slot slot = read.value;
            if (slot.users.isEmpty()) {
                // This retirement's own durable tombstone. A CREATING entry cannot complete
                // to LIVE without its user, so that state is never advanced here.
                if (entry.phase != SlotPhase.LIVE || !store.writeHeader(header, releasing)) {
                    return false;
                }
            } else {
                if (!loaded.bindingUsable(appId) || !boundTo(slot, record)
                        || !slot.users.get(0).retiring || slot.generation == Long.MAX_VALUE) {
                    return false;
                }
                Header live = withPhase(header, appId, SlotPhase.LIVE);
                Slot tombstone = new Slot(slot.lineage, appId, slot.packageName,
                        slot.generation + 1, slot.signerSha256, List.of());
                if ((entry.phase == SlotPhase.CREATING && !store.writeHeader(header, live))
                        || !store.updateExistingSlot(slot, tombstone)
                        || !store.writeHeader(live, releasing)) return false;
            }
        }
        return store.removeReleasingSlot(releasing, appId)
                && store.writeHeader(releasing, without(releasing, appId));
    }

    private static Slot eligible(NativeIdentityStore.Loaded loaded, int appId) {
        return loaded.bindingUsable(appId) ? loaded.slots.get(appId).value : null;
    }

    private static Slot bound(NativeIdentityStore.Loaded loaded,
            NativePrincipalPins.Record record) {
        Slot slot = record.userId == USER_SYSTEM ? eligible(loaded, record.appId) : null;
        return slot != null && boundTo(slot, record) ? slot : null;
    }

    // Every record field. Signers are compared separately with the caller's expectation.
    private static boolean boundTo(Slot slot, NativePrincipalPins.Record record) {
        if (slot.appId != record.appId || !slot.packageName.equals(record.packageName)
                || slot.users.size() != 1) return false;
        UserEntry user = slot.users.get(0);
        return user.id == record.id && user.userId == record.userId
                && user.userSerial == record.userSerial;
    }

    // A copy of this record's slot during its retirement: the retiring binding or its
    // tombstone, never another principal, package, lineage or signer set.
    private static boolean retirementCopy(Slot copy, NativePrincipalPins.Record record,
            String lineage, Set<String> signers) {
        return copy.appId == record.appId && copy.lineage.equals(lineage)
                && copy.packageName.equals(record.packageName)
                && copy.signerSha256.equals(signers) && (copy.users.isEmpty()
                || (boundTo(copy, record) && copy.users.get(0).retiring));
    }

    // Any other slot copy binding this package or principal ID, or another reservation of
    // this ID. A tombstone of an earlier identity binds no user and does not count.
    private static boolean liveElsewhere(NativeIdentityStore.Loaded loaded,
            NativePrincipalPins.Record record) {
        for (Header copy : loaded.header.decodedCopies) {
            for (HeaderEntry entry : copy.entries) {
                if (entry.appId != record.appId && entry.phase == SlotPhase.CREATING
                        && entry.creationId == record.id) return true;
            }
        }
        for (Map.Entry<Integer, NativeIdentityStore.ReadResult<Slot>> held
                : loaded.slots.entrySet()) {
            if (held.getKey().intValue() == record.appId) continue;
            for (Slot copy : held.getValue().decodedCopies) {
                if (copy.users.isEmpty()) continue;
                if (copy.packageName.equals(record.packageName)) return true;
                for (UserEntry user : copy.users) if (user.id == record.id) return true;
            }
        }
        return false;
    }

    // This record's CREATING entry: its creation ID and package, and with a complete creation
    // binding, the record's user and serial and, when known, the signer set. Negative only: an
    // entry without a binding keeps the checks it always had, and a null set skips only the
    // signer comparison. Nothing compares against or copies current package signers.
    private static boolean reservedFor(HeaderEntry entry, NativePrincipalPins.Record record,
            Set<String> signers) {
        if (entry == null || entry.phase != SlotPhase.CREATING || entry.creationId != record.id
                || !entry.creationPackage.equals(record.packageName)) return false;
        CreationBinding binding = entry.creationBinding;
        return binding == null || (binding.userId == record.userId
                && binding.userSerial == record.userSerial
                && (signers == null || binding.signerSha256.equals(signers)));
    }

    private static HeaderEntry entry(Header header, int appId) {
        for (HeaderEntry entry : header.entries) if (entry.appId == appId) return entry;
        return null;
    }

    // LIVE or RELEASING for one entry, with the same version, counter and every other entry.
    private static Header withPhase(Header header, int appId, SlotPhase phase) {
        List<HeaderEntry> entries = new ArrayList<>(header.entries.size());
        for (HeaderEntry entry : header.entries) {
            entries.add(entry.appId == appId ? new HeaderEntry(appId, phase, 0, "") : entry);
        }
        return sameVersion(header, entries);
    }

    private static Header without(Header header, int appId) {
        List<HeaderEntry> entries = new ArrayList<>(header.entries.size());
        for (HeaderEntry entry : header.entries) if (entry.appId != appId) entries.add(entry);
        return sameVersion(header, entries);
    }

    // The header's own version, lineage and counter with other entries. Phase changes and
    // omissions never convert a version: only a reservation with a truly new bound entry does.
    private static Header sameVersion(Header header, List<HeaderEntry> entries) {
        if (header.version == VERSION_1) return new Header(header.lineage, header.lastId, entries);
        if (header.version == VERSION_2) return Header.newV2(header.lineage, header.lastId, entries);
        throw new IllegalStateException("header version without a writer");
    }

    // One validated immutable copy of the caller's set. It is only compared, never stored
    // over an existing slot's signers.
    private static Set<String> signers(Set<String> expected) {
        Set<String> copy = Set.copyOf(Objects.requireNonNull(expected, "expectedSigners"));
        if (copy.isEmpty() || copy.size() > NativeIdentityRecords.MAX_SIGNERS) {
            throw new IllegalArgumentException("signer count outside 1..MAX_SIGNERS");
        }
        for (String digest : copy) {
            if (!lowerHex(digest, SIGNER_DIGITS)) {
                throw new IllegalArgumentException("signer digest is not 64 lowercase hex digits");
            }
        }
        return copy;
    }

    private static void checkLineage(String lineage) {
        Objects.requireNonNull(lineage, "expectedLineage");
        if (!lowerHex(lineage, LINEAGE_DIGITS)) {
            throw new IllegalArgumentException("lineage is not 32 lowercase hex digits");
        }
    }

    private static boolean lowerHex(String value, int digits) {
        if (value.length() != digits) return false;
        for (int i = 0; i < digits; ++i) {
            char c = value.charAt(i);
            if ((c < '0' || c > '9') && (c < 'a' || c > 'f')) return false;
        }
        return true;
    }

    // The structural rules of NativePrincipalPins.restore, checked again at this boundary.
    private static void checkSnapshot(NativePrincipalPins.Snapshot snapshot) {
        if (snapshot.lastId < 0) throw new IllegalArgumentException("negative lastId");
        Set<Long> ids = new HashSet<>();
        Set<String> subjects = new HashSet<>();
        Map<String, Integer> appIds = new HashMap<>();
        Map<Integer, String> packages = new HashMap<>();
        for (NativePrincipalPins.Record record : snapshot.records) {
            if (record.id <= 0 || record.id > snapshot.lastId) {
                throw new IllegalArgumentException("record ID outside 1..lastId");
            }
            if (!ids.add(record.id)) throw new IllegalArgumentException("duplicate record ID");
            if (!subjects.add(record.packageName + '/' + record.userId)) {
                throw new IllegalArgumentException("duplicate package and user");
            }
            Integer appId = appIds.putIfAbsent(record.packageName, record.appId);
            String packageName = packages.putIfAbsent(record.appId, record.packageName);
            if ((appId != null && appId.intValue() != record.appId)
                    || (packageName != null && !packageName.equals(record.packageName))) {
                throw new IllegalArgumentException("package and app ID do not correspond");
            }
        }
        for (long id : snapshot.retiringIds) {
            if (!ids.contains(id)) throw new IllegalArgumentException("unknown retiring ID");
        }
    }
}
