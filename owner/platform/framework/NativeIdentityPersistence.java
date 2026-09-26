// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

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

    private final NativeIdentityStore store;

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
     * before any of them is published. Pass the core's complete {@code snapshotForWrite()}.
     * Memory prepares can issue IDs 1 and 2 and then publish 2 first. A counter advanced to 2
     * without an entry for 1 would leave 1 permanently unreservable.
     *
     * <p>Needs a creation ready store. Every existing index entry is kept exactly, including
     * damaged, unknown and core absent slots: core absence never omits anything. A record
     * with an index entry must match a CREATING entry exactly, and LIVE or RELEASING slots are
     * never reallocated here. A record without one gets a new CREATING entry only if its ID is
     * above the durable counter. A pending creation whose core handle is already RETIRING
     * still gets its negative reservation, so its original retirement can publish a marker
     * and complete. That is not activation. The counter becomes the larger of the store's and the snapshot's lastId, never a maximum of
     * observed IDs. No slot directory or body is created.
     */
    boolean reservePending(NativePrincipalPins.Snapshot snapshot) {
        Objects.requireNonNull(snapshot, "snapshot");
        checkSnapshot(snapshot);
        for (NativePrincipalPins.Record record : snapshot.records) {
            if (record.userId != USER_SYSTEM) return false;
        }
        NativeIdentityStore.Loaded loaded = store.load();
        if (!loaded.creationReady()) return false;
        Header current = loaded.header.value;
        TreeMap<Integer, HeaderEntry> entries = new TreeMap<>();
        for (HeaderEntry entry : current.entries) entries.put(entry.appId, entry);
        for (NativePrincipalPins.Record record : snapshot.records) {
            HeaderEntry held = entry(current, record.appId);
            if (held != null) {
                if (held.phase == SlotPhase.CREATING && !reservedFor(held, record)) return false;
                continue; // Its own reservation, or an existing slot that publish must match.
            }
            if (record.id <= current.lastId) return false; // Passed without a reservation.
            entries.put(record.appId, new HeaderEntry(record.appId, SlotPhase.CREATING,
                    record.id, record.packageName));
        }
        if (entries.size() > NativeIdentityRecords.MAX_SLOTS) return false;
        Header next = new Header(current.lineage, Math.max(current.lastId, snapshot.lastId),
                new ArrayList<>(entries.values()));
        // Also the exact retry: an unchanged header is rewritten through checked writers.
        return store.writeHeader(current, next);
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
     * true result ends with a checked confirmation of the exact slot.
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
            if (!reservedFor(entry(header, record.appId), record) || read == null
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
            if (entry.phase == SlotPhase.CREATING && (!reservedFor(entry, record)
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

    private static boolean reservedFor(HeaderEntry entry, NativePrincipalPins.Record record) {
        return entry != null && entry.phase == SlotPhase.CREATING
                && entry.creationId == record.id
                && entry.creationPackage.equals(record.packageName);
    }

    private static HeaderEntry entry(Header header, int appId) {
        for (HeaderEntry entry : header.entries) if (entry.appId == appId) return entry;
        return null;
    }

    // LIVE or RELEASING for one entry, with the same counter and every other entry.
    private static Header withPhase(Header header, int appId, SlotPhase phase) {
        List<HeaderEntry> entries = new ArrayList<>(header.entries.size());
        for (HeaderEntry entry : header.entries) {
            entries.add(entry.appId == appId ? new HeaderEntry(appId, phase, 0, "") : entry);
        }
        return new Header(header.lineage, header.lastId, entries);
    }

    private static Header without(Header header, int appId) {
        List<HeaderEntry> entries = new ArrayList<>(header.entries.size());
        for (HeaderEntry entry : header.entries) if (entry.appId != appId) entries.add(entry);
        return new Header(header.lineage, header.lastId, entries);
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
