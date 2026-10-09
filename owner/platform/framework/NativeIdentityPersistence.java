// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import com.android.server.pm.NativeIdentityRecords.ActorClass;
import com.android.server.pm.NativeIdentityRecords.CreationBinding;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.HeaderEntry;
import com.android.server.pm.NativeIdentityRecords.Lifecycle;
import com.android.server.pm.NativeIdentityRecords.LifecycleState;
import com.android.server.pm.NativeIdentityRecords.Obligation;
import com.android.server.pm.NativeIdentityRecords.ObligationState;
import com.android.server.pm.NativeIdentityRecords.ReleaseTicket;
import com.android.server.pm.NativeIdentityRecords.Retirement;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.SlotPhase;
import com.android.server.pm.NativeIdentityRecords.Suspension;
import com.android.server.pm.NativeIdentityRecords.UserEntry;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Package Manager's per target transactions over its {@link NativeIdentityStore}, for the
 * trusted native principal caller only. Each call carries one exact core pin record through
 * the store's checked steps: reservation, publication, retirement marker or final release, and
 * under the lifecycle format suspension, lift, retirement and confirmed retirement. Nothing is
 * kept between calls. Every call starts from a fresh load and continues exactly the durable
 * state that the same transaction left behind.
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
 * snapshots throw {@link IllegalArgumentException}, and so does a lifecycle request that no
 * writer of this stage writes. Both happen before any effect.
 *
 * <p>The lifecycle transactions, suspend, lift, markRetiring with a {@link Retirement},
 * markRetired, beginDisposition, confirmDisposition, restore and release, write version 2 slots.
 * Each refuses under a format whose slot ceiling is 1 before any effect, and the store's named
 * transitions, Restore writer and release primitives apply the lifecycle record's store rules
 * again. Disposition and release run only in a retired boot, which the caller's {@link BootFacts}
 * show, and an interrupted release continues only in a boot that began with its ticketed tombstone
 * or with its RELEASING entry and no directory. Restore is the recovery route's writer, and only it
 * writes a recovery hold. Release is the gated release engine: it needs a {@link
 * ReleaseCapability}, which only its tests construct, and it is off, so no production text calls
 * it. Under the lifecycle format the version 1 retirement marker and the final release refuse
 * before any effect: the marker would drop suspension entries and create a legacy marker, and a
 * user leaves a slot only through the release engine.
 *
 * <p>Pure static helpers shared by real Settings and its host facade interpret the store's
 * historical identities: the pins a view restores, the exact record a history names, the rule
 * that decides whether actual Package Manager state may own a scanned history and one boot's
 * {@link BootFacts}. They do no I/O, create no PackageSetting, mapping or UID and take nothing
 * from a current APK.
 */
final class NativeIdentityPersistence {
    private static final int USER_SYSTEM = 0;
    private static final int PER_USER_RANGE = 100_000;
    private static final int LINEAGE_DIGITS = 32;
    private static final int SIGNER_DIGITS = 64;
    private static final int VERSION_1 = 1;
    private static final int VERSION_2 = 2;

    private final NativeIdentityStore store;

    /**
     * The result of a suspension. An actor's differing repeat and an explicit refusal for want of
     * a place are distinguished from every other refusal or uncertainty.
     */
    enum SuspensionResult {
        /**
         * This entry is durable: written now, or the actor's equal entry confirmed through the
         * checked writers.
         */
        SUSPENDED,
        /**
         * The actor's entry exists and stays unchanged, confirmed through the checked writers:
         * the request differed from it, and the entry keeps its stored reason, scope, time, note
         * and actor fields. The account is suspended by this actor. To change the reason or
         * scope, the actor lifts its entry and suspends again.
         */
        HELD_UNCHANGED,
        /**
         * Refused before any effect: no place is free for the actor's class. Writers allot one
         * place to the account's user, one to a recovery hold and four to grant references, and a
         * record holds six entries at most. The account stays suspended by the others. The caller
         * keeps this suspension as a pending durable intent, designates nothing for the account
         * meanwhile and applies it as soon as a place is free.
         */
        FULL,
        /**
         * Refused, as a request that cannot be written over the durable state, or uncertain, as
         * false is for every other transaction.
         */
        REFUSED
    }

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

    /**
     * Pin inputs restored from one view's historical identities: core records in principal ID
     * order and the IDs of retiring bodies. Memory only. It carries no counter and grants
     * nothing; the caller's restore keeps its own capacity and counter rules.
     */
    static final class Restoration {
        /** Unmodifiable, in principal ID order. */
        final List<NativePrincipalPins.Record> records;
        /** Unmodifiable: the principal IDs of retiring bodies, ascending. */
        final Set<Long> retiringIds;
        /**
         * Unmodifiable: app IDs of reservations withdrawn because they could not be restored
         * beside every other history. A store view leaves none. Their holds remain.
         */
        final Set<Integer> withdrawnReservations;

        private Restoration(List<NativePrincipalPins.Record> records, TreeSet<Long> retiringIds,
                TreeSet<Integer> withdrawnReservations) {
            this.records = List.copyOf(records);
            this.retiringIds = Collections.unmodifiableSet(retiringIds);
            this.withdrawnReservations = Collections.unmodifiableSet(withdrawnReservations);
        }
    }

    /**
     * What one boot's durable read showed at its start, for the rules that need a boot after an
     * earlier one: the accounts that were RETIRED, the ticketed tombstones and the RELEASING entries
     * without a directory. Disposition and release need this evidence. The cached store view, the
     * recovery view and the remembered histories are not evidence, because each changes after the
     * boot read: every store read replaces the view, and histories grow as accounts appear and do
     * not exist for tombstones. Immutable and memory only. Only {@link #bootFacts} builds it, from a
     * read. Real Settings assigns it once, at construction, from its boot read and never again, and
     * defers each named package. It grants nothing by itself.
     */
    static final class BootFacts {
        /** Unmodifiable, by app ID: the record of each account that the boot read showed RETIRED. */
        final Map<Integer, NativePrincipalPins.Record> retired;
        /**
         * Unmodifiable, by app ID: the selected tombstone that carries a release ticket, as the boot
         * read showed it. Its ticket names the last principal, user and serial.
         */
        final Map<Integer, Slot> ticketedTombstones;
        /**
         * Unmodifiable: the app IDs of RELEASING header entries whose slot held no record copy, so
         * the directory was gone or emptied by release, as the boot read showed them.
         */
        final Set<Integer> releasingWithoutDirectory;

        private BootFacts(Map<Integer, NativePrincipalPins.Record> retired,
                Map<Integer, Slot> ticketedTombstones, Set<Integer> releasingWithoutDirectory) {
            this.retired = Collections.unmodifiableMap(new TreeMap<>(retired));
            this.ticketedTombstones = Collections.unmodifiableMap(new TreeMap<>(ticketedTombstones));
            this.releasingWithoutDirectory = Collections.unmodifiableSet(
                    new TreeSet<>(releasingWithoutDirectory));
        }

        /**
         * Whether this boot began with exactly this account RETIRED: a retired boot for it. Its
         * package was then deferred at seeding and at the scan, and nothing under its UID started.
         */
        boolean retiredBoot(NativePrincipalPins.Record record) {
            return record.equals(retired.get(record.appId));
        }
    }

    /**
     * The release engine's capability. Release is off: nobody chooses it, and only the release
     * engine's tests construct this. Every class lives in one Java package, so access rules cannot
     * stop its construction; a source rule refuses its construction, constructor references, class
     * literals and name strings in every production text and allows construction only in the
     * engine's named test classes. It has no factory. It carries the hook that clears the key
     * namespace, so release cannot skip that step. It grants nothing by itself: release still needs
     * the durable record and the boot facts.
     */
    static final class ReleaseCapability {
        /** Clears the key namespace of one UID once more, which also removes grants it received. */
        interface KeyNamespace {
            /** True only once the namespace of this UID is clear. False keeps every hold. */
            boolean clear(int uid);
        }

        private final KeyNamespace keys;

        ReleaseCapability(KeyNamespace keys) {
            this.keys = Objects.requireNonNull(keys, "keys");
        }
    }

    NativeIdentityPersistence(NativeIdentityStore store) {
        this.store = Objects.requireNonNull(store, "store");
    }

    /**
     * The shared boot facts helper of real Settings and its host facade: the boot facts of this
     * durable read. Pure: no I/O, and nothing is taken from an APK, a PackageSetting or a remembered
     * history. An account is RETIRED only in an eligible binding's selected value, a ticketed
     * tombstone only as a selected valid tombstone, and a RELEASING entry lacks its directory only
     * when the selected valid header lists it and its slot reads as missing, with no copy, decoded
     * or not. Damaged, conflicting or unsupported records give no fact. Under a format whose slot
     * ceiling is 1, no version 2 slot is valid, so the facts hold no RETIRED account and no ticketed
     * tombstone.
     */
    static BootFacts bootFacts(NativeIdentityStore.Loaded loaded) {
        Objects.requireNonNull(loaded, "loaded");
        Map<Integer, NativePrincipalPins.Record> retired = new TreeMap<>();
        Map<Integer, Slot> tombstones = new TreeMap<>();
        Set<Integer> releasing = new TreeSet<>();
        for (Map.Entry<Integer, NativeIdentityStore.ReadResult<Slot>> held : loaded.slots.entrySet()) {
            int appId = held.getKey();
            NativeIdentityStore.ReadResult<Slot> read = held.getValue();
            if (loaded.bindingUsable(appId) && read.value.users.size() == 1) {
                UserEntry user = read.value.users.get(0);
                if (user.lifecycle.state == LifecycleState.RETIRED) {
                    retired.put(appId, new NativePrincipalPins.Record(user.id,
                            read.value.packageName, appId, user.userId, user.userSerial));
                }
            } else if (read.status == NativeIdentityStore.Status.VALID && loaded.enumerationComplete
                    && loaded.header.status != NativeIdentityStore.Status.UNSUPPORTED
                    && !loaded.header.unavailable && read.value.users.isEmpty()
                    && read.value.ticket != null) {
                tombstones.put(appId, read.value);
            }
        }
        if (loaded.enumerationComplete && loaded.header.status == NativeIdentityStore.Status.VALID) {
            for (HeaderEntry entry : loaded.header.value.entries) {
                NativeIdentityStore.ReadResult<Slot> read = loaded.slots.get(entry.appId);
                if (entry.phase == SlotPhase.RELEASING && read != null
                        && read.status == NativeIdentityStore.Status.MISSING) releasing.add(entry.appId);
            }
        }
        return new BootFacts(retired, tombstones, releasing);
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
     * The shared restoration of real Settings and its host facade. A BODY history gives its
     * record, and its ID when retiring, exactly as eligible bodies were always restored. Retiring
     * means RETIRING or RETIRED: both restore a RETIRING pin, so a retired account never becomes
     * PENDING again. A suspended ELIGIBLE body restores PENDING, because suspension is no pin
     * phase; every activation point refuses it instead. A RESERVATION history gives its record,
     * never retiring, only when it is in the policy's Eligible state and relates to every other
     * history as NativePrincipalPins.restore requires: its own app ID key, user 0, and an ID,
     * package and app ID that no other history has. Otherwise it is withdrawn here, never
     * repaired or merged, and its app ID stays held by the store footprint. This backstop never
     * fabricates a record and never adds, withdraws or changes a body. The store's claim rules
     * already withdraw every such reservation, so a store view never needs it.
     */
    static Restoration restoration(Map<Integer, NativeIdentityStore.History> histories) {
        Objects.requireNonNull(histories, "histories");
        List<NativePrincipalPins.Record> records = new ArrayList<>();
        TreeSet<Long> retiring = new TreeSet<>();
        TreeSet<Integer> withdrawn = new TreeSet<>();
        for (NativeIdentityStore.History history : histories.values()) {
            if (history.source != NativeIdentityStore.Source.BODY) continue;
            records.add(record(history));
            if (history.retiring) retiring.add(history.id);
        }
        for (Map.Entry<Integer, NativeIdentityStore.History> entry : histories.entrySet()) {
            if (entry.getValue().source != NativeIdentityStore.Source.RESERVATION) continue;
            NativePrincipalPins.Record restored = restorable(entry.getKey(), entry.getValue(),
                    histories);
            if (restored == null) withdrawn.add(entry.getKey());
            else records.add(restored);
        }
        records.sort(Comparator.comparingLong(record -> record.id));
        return new Restoration(records, retiring, withdrawn);
    }

    // A reservation's own record, or null unless it can be restored beside every other history.
    private static NativePrincipalPins.Record restorable(int key,
            NativeIdentityStore.History reservation,
            Map<Integer, NativeIdentityStore.History> histories) {
        if (reservation.appId != key || !reservation.eligible()
                || reservation.userId != USER_SYSTEM) return null;
        for (Map.Entry<Integer, NativeIdentityStore.History> other : histories.entrySet()) {
            if (other.getKey().intValue() == key) continue;
            NativeIdentityStore.History history = other.getValue();
            if (history.id == reservation.id || history.appId == reservation.appId
                    || history.packageName.equals(reservation.packageName)) return null;
        }
        try {
            return record(reservation);
        } catch (IllegalArgumentException invalid) {
            return null;
        }
    }

    /** The core record a history names: its principal ID, package, app ID, user and serial. */
    static NativePrincipalPins.Record record(NativeIdentityStore.History history) {
        return new NativePrincipalPins.Record(history.id, history.packageName, history.appId,
                history.userId, history.userSerial);
    }

    /** Whether this history names exactly this record, every record field included. */
    static boolean identifies(NativeIdentityStore.History history,
            NativePrincipalPins.Record record) {
        return history.id == record.id && history.appId == record.appId
                && history.userId == record.userId && history.userSerial == record.userSerial
                && history.packageName.equals(record.packageName);
    }

    /**
     * The one scan rule of real Settings and its host facade: the history of the candidate's
     * app ID when actual Package Manager state matches it, or null. The candidate and the app
     * ID's existing mapping must both be the history's package, neither of them a shared user,
     * and the current user 0 serial must equal the history's. Only a history in the policy's
     * Eligible state, ELIGIBLE with no suspension entry, owns a scan: a suspended, retiring or
     * retired one never does. A null mapping package means no PackageSetting maps the app ID. A
     * negative serial means the user is unavailable. The same rule holds for a body and a
     * reservation. The caller then compares the APK's signers with the history's recorded set.
     * Pure: it creates no mapping or PackageSetting, allocates no UID and reconstructs no history
     * from the APK.
     */
    static NativeIdentityStore.History scanOwner(NativeIdentityStore.History history,
            String candidatePackage, int candidateAppId, boolean candidateShared,
            String mappingPackage, boolean mappingShared, long currentSerial) {
        if (history == null || candidateShared || mappingPackage == null || mappingShared
                || currentSerial < 0 || history.appId != candidateAppId || !history.eligible()
                || history.userId != USER_SYSTEM || history.userSerial != currentSerial
                || !history.packageName.equals(candidatePackage)
                || !mappingPackage.equals(candidatePackage)) return null;
        return history;
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
     * set, and must be in the policy's Eligible state: not retiring or retired, and with no
     * suspension entry. That refusal is this transaction's own, before the header changes. The
     * shared slot confirmation, which retirement and header phase changes also use, admits every
     * lifecycle. A valid header's CREATING entry for it completes to LIVE first. With a bad
     * header an intact binding is still confirmed, without the counter. Otherwise the target
     * needs this record's reservePending entry in a creation ready store and no body yet: its
     * private directory is resumed, generation 1 is published and the entry becomes LIVE.
     * Retries confirm the same binding and never issue another ID. Every true result ends with
     * a checked confirmation of the exact slot. A complete creation binding on the entry must
     * name this record's user and serial and the expected signer set, or nothing is published;
     * an entry without one, from an older writer, is published as before.
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
                || slot.users.get(0).retiring
                || !slot.users.get(0).lifecycle.suspensions.isEmpty()) return false;
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
     * that creation must enter retirement. An existing marker is confirmed, never cleared. Under
     * the lifecycle format it refuses before any effect: the marker would create a legacy marker
     * and drop suspension entries, and markRetiring with a Retirement writes the retirement
     * block there.
     */
    boolean markRetiring(NativePrincipalPins.Record record, Set<String> expectedSigners) {
        Objects.requireNonNull(record, "record");
        Set<String> signers = signers(expectedSigners);
        if (lifecycleFormat()) return false;
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
     * core pin finish. Under the lifecycle format it refuses before any effect: a user leaves a
     * slot only through the release engine there.
     */
    boolean finishRetirement(NativePrincipalPins.Record record, String expectedLineage,
            Set<String> expectedSigners) {
        Objects.requireNonNull(record, "record");
        checkLineage(expectedLineage);
        Set<String> signers = signers(expectedSigners);
        if (record.userId != USER_SYSTEM) return false;
        if (lifecycleFormat()) return false;
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

    /**
     * The suspend transaction: durably adds this entry to the exact binding of this user 0
     * record, or confirms its actor's existing entry. The caller closes admission in memory
     * first, keeps that closure through an uncertain result and retries from its own durable
     * intent until the entry is confirmed.
     *
     * <p>Needs the lifecycle format and only an intact binding with the expected signers, so it
     * works with a bad header, in any lifecycle state. A repeated suspension by the same actor,
     * the account's user or a grant reference whatever its actor fields, confirms the existing
     * entry unchanged through the checked writers: {@link SuspensionResult#SUSPENDED} when the
     * request equals it, and {@link SuspensionResult#HELD_UNCHANGED} when it differs. To change a
     * reason or scope, the actor lifts and suspends again. Without a free place for the actor's
     * class, as for a fifth grant or a seventh actor, it is {@link SuspensionResult#FULL}.
     *
     * @throws IllegalArgumentException for a request no writer of this stage writes: see
     *     {@link NativeIdentityStore#writableSuspension}; and for malformed signers
     */
    SuspensionResult suspend(NativePrincipalPins.Record record, Set<String> expectedSigners,
            Suspension entry) {
        Objects.requireNonNull(record, "record");
        Set<String> signers = signers(expectedSigners);
        Objects.requireNonNull(entry, "entry");
        if (!NativeIdentityStore.writableSuspension(record.userId, record.userSerial, entry)) {
            throw new IllegalArgumentException("suspension entry outside the writer rules");
        }
        if (!lifecycleFormat()) return SuspensionResult.REFUSED;
        Slot slot = bound(store.load(), record);
        if (slot == null || !slot.signerSha256.equals(signers)) return SuspensionResult.REFUSED;
        Lifecycle lifecycle = slot.users.get(0).lifecycle;
        for (Suspension held : lifecycle.suspensions) {
            if (!NativeIdentityStore.sameActor(held, entry)) continue;
            if (!store.confirmExistingSlot(slot)) return SuspensionResult.REFUSED;
            return held.equals(entry) ? SuspensionResult.SUSPENDED : SuspensionResult.HELD_UNCHANGED;
        }
        if (!NativeIdentityStore.placeFree(lifecycle, entry.actorClass)) return SuspensionResult.FULL;
        return store.addSuspension(slot, record.id, entry)
                ? SuspensionResult.SUSPENDED : SuspensionResult.REFUSED;
    }

    /**
     * The lift transaction: durably removes exactly this entry from the exact binding of this
     * user 0 record. In this stage only the actor that placed an entry lifts it. The caller has
     * established that it is this entry's actor and passes the entry as the record holds it.
     * Another entry of the same actor refuses, such as a grant entry that another Android user
     * placed under the same grant. With no entry of this actor the lift is durable already, as
     * after an uncertain earlier result, and the binding is confirmed through checked writers.
     *
     * <p>Needs the lifecycle format and only an intact binding with the expected signers. A lift
     * takes effect when it is durable, and eligibility returns only through a fresh designation.
     * Lifting the last entry of an eligible account writes version 1 again, so older images
     * admit the account again.
     *
     * @throws IllegalArgumentException for a recovery hold, which has no lift path in this
     *     stage, an account user entry of another user or serial, and malformed signers
     */
    boolean lift(NativePrincipalPins.Record record, Set<String> expectedSigners, Suspension entry) {
        Objects.requireNonNull(record, "record");
        Set<String> signers = signers(expectedSigners);
        Objects.requireNonNull(entry, "entry");
        if (entry.actorClass == ActorClass.RECOVERY_HOLD) {
            throw new IllegalArgumentException("a recovery hold has no lift path in this stage");
        }
        if (entry.actorClass == ActorClass.ACCOUNT_USER && (entry.actorUserId != record.userId
                || entry.actorSerial != record.userSerial)) {
            throw new IllegalArgumentException("an account user entry of another user");
        }
        if (!lifecycleFormat()) return false;
        Slot slot = bound(store.load(), record);
        if (slot == null || !slot.signerSha256.equals(signers)) return false;
        for (Suspension held : slot.users.get(0).lifecycle.suspensions) {
            if (NativeIdentityStore.sameActor(held, entry)) {
                return held.equals(entry) && store.liftSuspension(slot, record.id, entry);
            }
        }
        return store.confirmExistingSlot(slot);
    }

    /**
     * The retire transaction: durably makes the exact eligible binding of this user 0 record
     * RETIRING with this retirement block, with every suspension entry kept, before quiescence
     * starts. The block names its actor, the account's user with that user's own serial or a
     * grant, and lists every kind outstanding. Its exact retry confirms it. A RETIRING legacy
     * marker with an unknown inventory takes only its continuation, a legacy marker block that
     * lists every kind outstanding; no writer creates a legacy marker. Any other durable state or
     * block refuses: the state only moves forward and a written block never changes.
     *
     * <p>Needs the lifecycle format and only an intact binding with the expected signers, so it
     * works with a bad header. A missing target returns false.
     *
     * @throws IllegalArgumentException for a block no writer of this stage writes: see
     *     {@link NativeIdentityStore#writableRetirement}; and for malformed signers
     */
    boolean markRetiring(NativePrincipalPins.Record record, Set<String> expectedSigners,
            Retirement retirement) {
        Objects.requireNonNull(record, "record");
        Set<String> signers = signers(expectedSigners);
        Objects.requireNonNull(retirement, "retirement");
        if (!NativeIdentityStore.writableRetirement(record.userId, record.userSerial, retirement)) {
            throw new IllegalArgumentException("retirement outside the writer rules");
        }
        if (!lifecycleFormat()) return false;
        Slot slot = bound(store.load(), record);
        if (slot == null || !slot.signerSha256.equals(signers)) return false;
        Lifecycle lifecycle = slot.users.get(0).lifecycle;
        if (lifecycle.state == LifecycleState.RETIRING && retirement.equals(lifecycle.retirement)) {
            return store.confirmExistingSlot(slot);
        }
        return store.markSlotRetiring(slot, record.id, retirement);
    }

    /**
     * Confirms retired: the exact RETIRING binding of this user 0 record, with a known
     * inventory, durably becomes RETIRED with each retirement kind discharged by its receipt. The
     * account authority calls it once every retirement kind's owner gave its receipt. It releases
     * nothing, and every disposition kind and suspension entry stays. Its exact retry, RETIRED
     * with every retirement kind equal to its receipt, confirms it.
     *
     * <p>Needs the lifecycle format and only an intact binding with the expected signers. A
     * legacy marker continues through markRetiring first. A kind orphaned with its Android user,
     * a discharged kind with another receipt and a receipt that would bind a bound reference
     * again refuse.
     *
     * @throws IllegalArgumentException for receipts that are not one DISCHARGED obligation of
     *     each retirement kind in kind order, and for malformed signers
     */
    boolean markRetired(NativePrincipalPins.Record record, Set<String> expectedSigners,
            List<Obligation> receipts) {
        Objects.requireNonNull(record, "record");
        Set<String> signers = signers(expectedSigners);
        List<Obligation> copy = List.copyOf(Objects.requireNonNull(receipts, "receipts"));
        if (!NativeIdentityStore.writableReceipts(copy)) {
            throw new IllegalArgumentException("not one receipt of each retirement kind");
        }
        if (!lifecycleFormat()) return false;
        Slot slot = bound(store.load(), record);
        if (slot == null || !slot.signerSha256.equals(signers)) return false;
        Lifecycle lifecycle = slot.users.get(0).lifecycle;
        if (lifecycle.state == LifecycleState.RETIRED) {
            return lifecycle.retirement.obligations.containsAll(copy)
                    && store.confirmExistingSlot(slot);
        }
        return store.markSlotRetired(slot, record.id, copy);
    }

    /**
     * Begin deletion or migration: the exact RETIRED binding of this user 0 record durably has
     * every disposition kind DISPOSING at once, before anything is deleted. The caller has
     * established that the account's own user, or the grant holder with destructive confirmation,
     * asked for it. It is never automatic. Once it is durable, the DISPOSING kinds complete, because
     * a partial deletion cannot be safely paused. Its retry, once every disposition kind is
     * DISPOSING or DISCHARGED, confirms it.
     *
     * <p>Allowed only in a retired boot: facts, the boot facts of this boot, must show exactly this
     * account RETIRED. Refused while any suspension entry with scope bit 0 exists, which no writer
     * of this stage sets, and beside a kind orphaned with its Android user, which stage C owns.
     * Needs the lifecycle format, a known inventory and only an intact binding with the expected
     * signers. Every refusal comes before any effect.
     *
     * @throws IllegalArgumentException for malformed signers
     */
    boolean beginDisposition(NativePrincipalPins.Record record, Set<String> expectedSigners,
            BootFacts facts) {
        Objects.requireNonNull(record, "record");
        Set<String> signers = signers(expectedSigners);
        Objects.requireNonNull(facts, "facts");
        if (!lifecycleFormat() || !facts.retiredBoot(record)) return false;
        Slot slot = bound(store.load(), record);
        if (slot == null || !slot.signerSha256.equals(signers)) return false;
        Lifecycle lifecycle = slot.users.get(0).lifecycle;
        if (lifecycle.state == LifecycleState.RETIRED && dispositionBegun(lifecycle.retirement)) {
            return store.confirmExistingSlot(slot);
        }
        return store.beginSlotDisposition(slot, record.id);
    }

    /**
     * Confirm disposal: in the exact RETIRED binding of this user 0 record, each disposition kind
     * a receipt names durably moves from DISPOSING to DISCHARGED. The storage, key and policy owners
     * give their receipts on observed evidence. A receipt may discharge a kind with no bound
     * reference, and a bound reference never changes or becomes zero. Its exact retry, every
     * receipt already as the record holds it, confirms it.
     *
     * <p>Allowed only in a retired boot, as for {@link #beginDisposition}. An outstanding kind
     * refuses until deletion or migration began, and a kind orphaned with its Android user refuses:
     * stage C defines its discharge. Needs the lifecycle format and only an intact binding with the
     * expected signers. Every refusal comes before any effect.
     *
     * @throws IllegalArgumentException for receipts that are not DISCHARGED obligations of
     *     disposition kinds in strictly ascending kind order, and for malformed signers
     */
    boolean confirmDisposition(NativePrincipalPins.Record record, Set<String> expectedSigners,
            List<Obligation> receipts, BootFacts facts) {
        Objects.requireNonNull(record, "record");
        Set<String> signers = signers(expectedSigners);
        List<Obligation> copy = List.copyOf(Objects.requireNonNull(receipts, "receipts"));
        Objects.requireNonNull(facts, "facts");
        if (!NativeIdentityStore.writableDispositionReceipts(copy)) {
            throw new IllegalArgumentException("not receipts of disposition kinds");
        }
        if (!lifecycleFormat() || !facts.retiredBoot(record)) return false;
        Slot slot = bound(store.load(), record);
        if (slot == null || !slot.signerSha256.equals(signers)) return false;
        Lifecycle lifecycle = slot.users.get(0).lifecycle;
        if (lifecycle.state == LifecycleState.RETIRED
                && lifecycle.retirement.obligations.containsAll(copy)) {
            return store.confirmExistingSlot(slot);
        }
        return store.dischargeSlotDisposition(slot, record.id, copy);
    }

    /**
     * Restore, for the independent recovery route only: durably writes the last known state of
     * this user 0 record's account, with this recovery hold, into its existing slot. The last known
     * state is the intact copy with the highest generation among the slot's main, reserve and
     * backup, never an earlier one. If no copy is intact, the state cannot be established, and the
     * account is written ELIGIBLE with the hold and scope bit 1, which tells whoever lifts the hold
     * that the account may have been retired. The hold keeps the restored account from becoming
     * active directly: every activation point refuses a suspended account, and a recovery hold has
     * no lift path in this stage. A restored RETIRING or RETIRED account restores a RETIRING pin.
     * If the account already holds a recovery hold, that hold stays as it is. The header entry
     * stays as found. The caller closes admission in memory first, as for a suspension, and keeps
     * that closure through an uncertain result: false may follow a durable restore.
     *
     * <p>The caller names the account by its record, the store lineage and its original signer
     * set, from the recovery route's own evidence. The record's own CREATING entry must match it,
     * and no other app ID may claim its package or principal ID: no decoded slot copy there,
     * tombstones and their tickets included, and no CREATING entry there in any decoded header
     * copy, because a load reads such a sibling and the restored record as conflicting. Restore
     * needs a
     * valid header of the expected lineage that holds the app ID, and the slot directory with at
     * least one copy, intact or not. It needs no valid read of the slot: it is the one writer for
     * a damaged or conflicting record. A missing body, an unsupported footprint, a RELEASING entry
     * in any decoded header copy,
     * a copy of another account, lineage or package, a tombstone, two different intact copies of
     * the highest generation and an account without a free place for the hold refuse before any
     * effect. No production caller exists.
     *
     * @throws IllegalArgumentException for a hold no writer writes: see
     *     {@link NativeIdentityStore#writableRecoveryHold}; and for a malformed lineage or signers
     */
    boolean restore(NativePrincipalPins.Record record, String expectedLineage,
            Set<String> expectedSigners, Suspension hold) {
        Objects.requireNonNull(record, "record");
        checkLineage(expectedLineage);
        Set<String> signers = signers(expectedSigners);
        Objects.requireNonNull(hold, "hold");
        if (!NativeIdentityStore.writableRecoveryHold(hold)) {
            throw new IllegalArgumentException("recovery hold outside the writer rules");
        }
        if (!lifecycleFormat() || record.userId != USER_SYSTEM) return false;
        NativeIdentityStore.Loaded loaded = store.load();
        if (!loaded.enumerationComplete
                || loaded.header.status != NativeIdentityStore.Status.VALID) return false;
        // The store checks the header's lineage, entry and counter against the account itself.
        if (claimedElsewhere(loaded, record)) return false;
        Slot account = new Slot(expectedLineage, record.appId, record.packageName, 1, signers,
                List.of(new UserEntry(record.id, record.userId, record.userSerial, false)));
        return store.restoreSlot(loaded.header.value, account, hold);
    }

    /**
     * The gated release engine, which is off: nothing in production calls it. It releases this
     * user 0 record's slot and index entry under the lifecycle format, one checked step per durable
     * state, in this order: a CREATING entry completes to LIVE before the user is omitted, the
     * capability's hook clears the key namespace once more, the account becomes its tombstone with
     * this release ticket, the entry becomes RELEASING, the directory is removed and the entry is
     * omitted. The app ID stays held in memory until the next boot, which is the caller's.
     *
     * <p>It starts only when the durable record is RETIRED with a known inventory, every obligation
     * discharged and no suspension entry, the exact binding with the expected signers, and only in
     * a retired boot: facts, this boot's facts, show exactly this account RETIRED. An interrupted
     * release continues from durable state only, in a boot that began with this account's ticketed
     * tombstone, the caller's ticket, or with its RELEASING entry and no directory. In the boot that
     * wrote the tombstone the release waits for the next boot, since nothing remembered in memory
     * is evidence. A durable omission is confirmed in a boot whose facts show any of the three.
     * Continuation passes only the store's checked steps: removal refuses unknown files and any
     * copy but the tombstone, and omission needs the directory's genuine absence.
     *
     * <p>Needs a valid header of the expected lineage whose counter covers the record, and no live
     * binding of this package or ID elsewhere. During a continuation those two are the only checks
     * of the counter and of siblings, because a tombstone binds no user. Every remaining copy must
     * be this account's binding while retiring, or its tombstone with this ticket. A tombstone
     * without a ticket, which only the version 1 release writes, has no owner here and stays held.
     *
     * <p>Every check of the durable state comes before any effect. A step the store refuses later
     * keeps the steps already acknowledged durable, and a refusal after the key namespace was
     * cleared leaves it cleared. That is harmless: the record's KEYSTORE obligation is already
     * discharged, and the app ID stays held. True means the final omission is durable.
     *
     * @throws IllegalArgumentException for a ticket that does not name this record's principal ID,
     *     user and serial, including a user whose UID with the app ID would not fit in an int; and
     *     for a malformed lineage or signers
     */
    boolean release(NativePrincipalPins.Record record, String expectedLineage,
            Set<String> expectedSigners, ReleaseTicket ticket, ReleaseCapability capability,
            BootFacts facts) {
        Objects.requireNonNull(record, "record");
        checkLineage(expectedLineage);
        Set<String> signers = signers(expectedSigners);
        Objects.requireNonNull(ticket, "ticket");
        Objects.requireNonNull(capability, "capability");
        Objects.requireNonNull(facts, "facts");
        // The UID comes from the ticket's user only after that user is checked against the app ID.
        int uid = ticketUid(ticket, record.appId);
        if (uid < 0 || uid != record.userId * PER_USER_RANGE + record.appId
                || ticket.lastId != record.id || ticket.userSerial != record.userSerial) {
            throw new IllegalArgumentException("ticket of another principal, user or serial");
        }
        if (record.userId != USER_SYSTEM || !lifecycleFormat()) return false;
        int appId = record.appId;
        Slot began = facts.ticketedTombstones.get(appId);
        boolean tombstoneBoot = began != null
                && releaseCopy(began, record, expectedLineage, signers, ticket) && began.users.isEmpty();
        boolean emptiedBoot = facts.releasingWithoutDirectory.contains(appId);
        boolean retiredBoot = facts.retiredBoot(record);
        if (!retiredBoot && !tombstoneBoot && !emptiedBoot) return false;
        NativeIdentityStore.Loaded loaded = store.load();
        if (!loaded.enumerationComplete
                || loaded.header.status != NativeIdentityStore.Status.VALID) return false;
        Header header = loaded.header.value;
        if (!header.lineage.equals(expectedLineage)) return false;
        // At the start a conflict already makes the binding unusable. During a continuation these
        // two are the only guards: a tombstone binds no user.
        if (header.lastId < record.id) return false;
        if (liveElsewhere(loaded, record)) return false;
        HeaderEntry entry = entry(header, appId);
        NativeIdentityStore.ReadResult<Slot> read = loaded.slots.get(appId);
        // A durable omission: index and directory are both gone. Any remaining hold refuses.
        if (entry == null) return read == null && store.confirmReleasedSlot(header, appId);
        if (read == null) return false;
        for (Slot copy : read.decodedCopies) {
            if (!releaseCopy(copy, record, expectedLineage, signers, ticket)) return false;
        }
        Header releasing = withPhase(header, appId, SlotPhase.RELEASING);
        if (entry.phase == SlotPhase.RELEASING) {
            // Continuation only: the tombstone's boot, or an emptied or removed directory's.
            if (!tombstoneBoot && !emptiedBoot) return false;
            for (Slot copy : read.decodedCopies) if (!copy.users.isEmpty()) return false;
            return store.removeReleasingSlot(releasing, appId)
                    && store.omitReleasedSlot(releasing, appId);
        }
        if (read.status != NativeIdentityStore.Status.VALID) return false;
        Slot slot = read.value;
        if (slot.users.isEmpty()) {
            // This release's ticketed tombstone under LIVE, continued in a boot that began with it.
            if (!tombstoneBoot || entry.phase != SlotPhase.LIVE) return false;
            return store.markSlotReleasing(header, appId)
                    && store.removeReleasingSlot(releasing, appId)
                    && store.omitReleasedSlot(releasing, appId);
        }
        // The start: this boot began with the account RETIRED, and it still is, releasable.
        if (!retiredBoot || !loaded.bindingUsable(appId) || !boundTo(slot, record)
                || !slot.signerSha256.equals(signers)
                || !NativeIdentityStore.releasable(slot.users.get(0).lifecycle)) return false;
        Header live = withPhase(header, appId, SlotPhase.LIVE);
        // A CREATING entry completes to LIVE before the user is omitted, or the tombstone would
        // strand. Then the key namespace is cleared once more, before the tombstone.
        if (entry.phase == SlotPhase.CREATING && !store.writeHeader(header, live)) return false;
        if (!capability.keys.clear(uid)) return false;
        return store.dropReleasedUser(slot, record.id, ticket)
                && store.markSlotReleasing(live, appId)
                && store.removeReleasingSlot(releasing, appId)
                && store.omitReleasedSlot(releasing, appId);
    }

    // The UID of this ticket's user under this app ID, or -1 when it would not fit in an int: a
    // decoded ticket bounds its user only as not negative, so no UID comes from it unchecked.
    static int ticketUid(ReleaseTicket ticket, int appId) {
        long uid = (long) ticket.userId * PER_USER_RANGE + appId;
        return uid > Integer.MAX_VALUE ? -1 : (int) uid;
    }

    // A copy of this record's slot during its release: its binding while retiring, or its
    // tombstone with this ticket, never another principal, package, lineage, signer set or ticket.
    private static boolean releaseCopy(Slot copy, NativePrincipalPins.Record record, String lineage,
            Set<String> signers, ReleaseTicket ticket) {
        return copy.appId == record.appId && copy.lineage.equals(lineage)
                && copy.packageName.equals(record.packageName) && copy.signerSha256.equals(signers)
                && (copy.users.isEmpty() ? ticket.equals(copy.ticket)
                : boundTo(copy, record) && copy.users.get(0).retiring);
    }

    // Whether the deletion or migration step already began: no disposition kind is OUTSTANDING or
    // orphaned with its Android user. Only that step moves a disposition kind out of OUTSTANDING.
    private static boolean dispositionBegun(Retirement retirement) {
        if (retirement.obligations.isEmpty()) return false;
        for (Obligation duty : retirement.obligations) {
            if (duty.kind.disposition() && duty.state != ObligationState.DISPOSING
                    && duty.state != ObligationState.DISCHARGED) return false;
        }
        return true;
    }

    // Whether this store's format reads and writes version 2 slots, which carry lifecycle
    // records. Every lifecycle transaction refuses under an earlier format before any effect, and
    // the version 1 retirement marker and release refuse under this one. The manager asks it
    // first, so its lifecycle operations refuse before their in memory closure and pin changes.
    boolean lifecycleFormat() {
        return store.format().slotCeiling >= VERSION_2;
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

    // Restore's claim rule, the store's rule for a reservation: another app ID claims this record's
    // package or principal ID through any decoded slot copy there, whatever its status, tombstones
    // and their tickets included, or through a CREATING entry there in any decoded header copy. A
    // claim is located by the slot's physical app ID or the entry's own. The release keeps
    // liveElsewhere.
    private static boolean claimedElsewhere(NativeIdentityStore.Loaded loaded,
            NativePrincipalPins.Record record) {
        for (Map.Entry<Integer, NativeIdentityStore.ReadResult<Slot>> other : loaded.slots.entrySet()) {
            if (other.getKey().intValue() == record.appId) continue;
            for (Slot claim : other.getValue().decodedCopies) {
                if (claim.packageName.equals(record.packageName)
                        || (claim.ticket != null && claim.ticket.lastId == record.id)) return true;
                for (UserEntry user : claim.users) if (user.id == record.id) return true;
            }
        }
        for (Header seen : loaded.header.decodedCopies) {
            for (HeaderEntry entry : seen.entries) {
                if (entry.appId != record.appId && entry.phase == SlotPhase.CREATING
                        && (entry.creationId == record.id
                        || entry.creationPackage.equals(record.packageName))) return true;
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
