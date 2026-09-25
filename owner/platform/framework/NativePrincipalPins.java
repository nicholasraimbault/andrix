// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Package Manager state that pins native principal bindings of package, app ID and user.
 *
 * <p>A pin reserves a package and its app ID for one incarnation of an Android user. PMS resolves
 * every input from its own authoritative state. This class allocates no app IDs and keeps no
 * installation, grant, signing or execution state. It is not a public API. Queries return
 * ordinary metadata, not grant decisions, and a handle is not a credential.
 *
 * <p>Invariants over all pins in every phase:
 * <ul>
 * <li>At most one pin exists for each package and user.
 * <li>A pinned app ID belongs to exactly one package, and a pinned package has exactly one app
 *     ID. The same package and app ID may be pinned for several users.
 * <li>Pin IDs are positive and follow {@code lastId}; committed lineage counters
 *     survive restore. Undurable prepares are not cross-instance authority. A
 *     refused call consumes no ID.
 * <li>Every pin counts toward the capacity.
 * </ul>
 *
 * <p>{@link #prepare} pins immediately in {@link Phase#PENDING}. ACTIVE only means a
 * durably reserved identity that may be considered by the real admission authority.
 * RETIRING closes that possibility and is persisted, never silently restored as
 * PENDING. Every held pin remains in {@link #snapshotForWrite}. Only an exact
 * {@link #snapshotWithout} candidate can omit one retiring pin after quiescence.
 * This is reservation metadata, not installed state or a live execution grant.
 *
 * <p>Caller obligations, which this class cannot check:
 * <ol>
 * <li>Restore before prepare or write. Nonretiring records restore PENDING.
 * <li>Commit only after a containing snapshot is durably written and actual
 *     Package Manager/user identity has been revalidated.
 * <li>Begin retirement, durably publish its marker, and only then begin account
 *     removal/quiescence. An uncertain marker write has not authorized removal.
 * <li>After work, manager, API and data obligations are authoritatively retired,
 *     durably write the target-specific omission and call finishRetire.
 * </ol>
 * Lost writes/replies retain the exact pin. No GC, death, timeout or label releases
 * a reservation. This class does no I/O and checks no caller or live authority.
 *
 * <p>This object's monitor guards all state. Methods hold it only for memory operations, never
 * for I/O, callbacks or waits. Malformed input throws {@link IllegalArgumentException}, or
 * {@link NullPointerException} for null. Conflicts, phase errors, capacity, ID exhaustion and
 * foreign or stale handles throw {@link IllegalStateException}. A call that throws changes
 * nothing.
 */
public final class NativePrincipalPins {
    /** Lifecycle of one pin handle. Phases only move forward. */
    public enum Phase {
        /** Held before commitment or after restore. Not eligible for launch. */
        PENDING,
        /**
         * Committed after a durable write and revalidation. The only phase a launch path may
         * consider.
         */
        ACTIVE,
        /** Irrevocably leaving, still held and persisted until confirmed removal. */
        RETIRING,
        /** Terminal metadata on a stale handle; no longer indexed or reserved. */
        RETIRED
    }

    /** Immutable binding as persisted. The constructor validates every field. */
    public static final class Record {
        /** Positive pin ID, never reused within one lineage of state. */
        public final long id;
        /** ASCII Android package name with two or more segments and at most 255 characters. */
        public final String packageName;
        /** App ID resolved by PMS, from 10000 to 19999. */
        public final int appId;
        /** Android user ID. The UID {@code userId * 100000 + appId} fits in an int. */
        public final int userId;
        /** Serial number that identifies this incarnation of the user ID. Not negative. */
        public final long userSerial;

        /**
         * @throws IllegalArgumentException for any invalid field
         * @throws NullPointerException for a null package name
         */
        public Record(long id, String packageName, int appId, int userId, long userSerial) {
            if (id <= 0) throw new IllegalArgumentException("pin ID must be positive: " + id);
            checkBinding(packageName, appId, userId, userSerial);
            this.id = id;
            this.packageName = packageName;
            this.appId = appId;
            this.userId = userId;
            this.userSerial = userSerial;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) return true;
            if (!(other instanceof Record)) return false;
            Record record = (Record) other;
            return id == record.id && appId == record.appId && userId == record.userId
                    && userSerial == record.userSerial && packageName.equals(record.packageName);
        }

        @Override
        public int hashCode() {
            return Objects.hash(id, packageName, appId, userId, userSerial);
        }

        @Override
        public String toString() {
            return "Record{id=" + id + ", package=" + packageName + ", appId=" + appId
                    + ", user=" + userId + ", serial=" + userSerial + "}";
        }
    }

    /**
     * Immutable persistence image: counter, all held records, and retiring markers. The
     * public constructor lets PMS rebuild a parsed file and lets host tests build input. It only
     * copies. {@link NativePrincipalPins#restore} is the validation boundary.
     */
    public static final class Snapshot {
        /** Highest pin ID ever issued in this lineage, including released IDs. */
        public final long lastId;
        /** Unmodifiable copy of the records. */
        public final List<Record> records;
        public final Set<Long> retiringIds;

        public Snapshot(long lastId, List<Record> records) {
            this(lastId, records, Set.of());
        }

        /** Copies input. restore validates marker membership and the whole image. */
        public Snapshot(long lastId, List<Record> records, Set<Long> retiringIds) {
            this.lastId = lastId;
            this.records = List.copyOf(Objects.requireNonNull(records, "records"));
            this.retiringIds = Set.copyOf(Objects.requireNonNull(retiringIds, "retiringIds"));
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) return true;
            if (!(other instanceof Snapshot)) return false;
            Snapshot snapshot = (Snapshot) other;
            return lastId == snapshot.lastId && records.equals(snapshot.records)
                    && retiringIds.equals(snapshot.retiringIds);
        }

        @Override
        public int hashCode() {
            return Objects.hash(lastId, records, retiringIds);
        }

        @Override
        public String toString() {
            return "Snapshot{lastId=" + lastId + ", records=" + records + ", retiring=" + retiringIds + "}";
        }
    }

    /**
     * Opaque handle owned by one instance. Phase changes accept only this exact current object,
     * never an ID, an equal record or a handle from another instance. After finishRetire the
     * handle is stale and reports RETIRED; findId no longer returns it.
     */
    public static final class Pin {
        private final NativePrincipalPins owner;
        private final Record record;
        private Phase phase = Phase.PENDING; // Guarded by owner.

        private Pin(NativePrincipalPins owner, Record record) {
            this.owner = owner;
            this.record = record;
        }

        public Record record() {
            return record;
        }

        /** Reads the phase under the owner's monitor. */
        public Phase phase() {
            synchronized (owner) {
                return phase;
            }
        }

        @Override
        public String toString() {
            return "Pin{" + record + ", " + phase() + "}";
        }
    }

    // Live pins of one package. They all share its single app ID.
    private static final class PinnedPackage {
        final String packageName;
        final int appId;
        final Map<Integer, Pin> users = new HashMap<>();

        PinnedPackage(String packageName, int appId) {
            this.packageName = packageName;
            this.appId = appId;
        }
    }

    // Every live pin appears once in each map. Packages and app IDs correspond one to one.
    private static final class Index {
        final Map<String, PinnedPackage> packages = new HashMap<>();
        final Map<Integer, PinnedPackage> appIds = new HashMap<>();
        final TreeMap<Long, Pin> ids = new TreeMap<>();

        Pin find(String packageName, int userId) {
            PinnedPackage entry = packages.get(packageName);
            return entry == null ? null : entry.users.get(userId);
        }

        // Why a new pin of this package and app ID would break the correspondence, or null.
        String conflict(String packageName, int appId) {
            PinnedPackage entry = packages.get(packageName);
            if (entry != null && entry.appId != appId) {
                return packageName + " is pinned to app ID " + entry.appId;
            }
            PinnedPackage holder = appIds.get(appId);
            if (holder != null && holder != entry) {
                return "app ID " + appId + " is pinned to " + holder.packageName;
            }
            return null;
        }

        void add(Pin pin) {
            Record record = pin.record;
            PinnedPackage entry = packages.get(record.packageName);
            if (entry == null) {
                entry = new PinnedPackage(record.packageName, record.appId);
                packages.put(record.packageName, entry);
                appIds.put(record.appId, entry);
            }
            entry.users.put(record.userId, pin);
            ids.put(record.id, pin);
        }

        void remove(Pin pin) {
            Record record = pin.record;
            PinnedPackage entry = packages.get(record.packageName);
            entry.users.remove(record.userId);
            if (entry.users.isEmpty()) {
                packages.remove(record.packageName);
                appIds.remove(record.appId);
            }
            ids.remove(record.id);
        }
    }

    private static final int FIRST_APP_ID = 10_000;
    private static final int LAST_APP_ID = 19_999;
    private static final int PER_USER_RANGE = 100_000;
    private static final int MAX_PACKAGE_NAME_LENGTH = 255;

    private final int capacity;
    // The three fields below are guarded by this. Restore replaces the whole index at once.
    private Index index = new Index();
    private long lastId;
    private boolean fresh = true; // No successful prepare or restore yet.

    /** @param capacity maximum number of pins in any phase, at least 1 */
    public NativePrincipalPins(int capacity) {
        if (capacity < 1) {
            throw new IllegalArgumentException("capacity must be positive: " + capacity);
        }
        this.capacity = capacity;
    }

    /**
     * Pins a binding resolved by PMS. Returns the existing handle when the exact binding is
     * already pinned and not RETIRING. A new pin is PENDING and takes the next ID.
     *
     * @throws IllegalArgumentException for a malformed binding
     * @throws IllegalStateException if the package and user are RETIRING or pinned to another
     *     binding, the package or app ID is pinned with a different counterpart, the capacity is
     *     reached or the IDs are exhausted
     */
    public synchronized Pin prepare(String packageName, int appId, int userId, long userSerial) {
        checkBinding(packageName, appId, userId, userSerial);
        Pin existing = index.find(packageName, userId);
        if (existing != null) {
            if (existing.phase == Phase.RETIRING) {
                throw new IllegalStateException(
                        "retiring pin must finish first: " + existing.record);
            }
            if (existing.record.appId != appId || existing.record.userSerial != userSerial) {
                throw new IllegalStateException("conflicting binding: " + existing.record);
            }
            return existing; // Exact retry of a PENDING or ACTIVE pin.
        }
        String reason = index.conflict(packageName, appId);
        if (reason != null) throw new IllegalStateException(reason);
        if (index.ids.size() >= capacity) {
            throw new IllegalStateException("capacity reached: " + capacity);
        }
        if (lastId == Long.MAX_VALUE) throw new IllegalStateException("pin IDs exhausted");
        Pin pin = new Pin(this, new Record(lastId + 1, packageName, appId, userId, userSerial));
        index.add(pin);
        lastId = pin.record.id;
        fresh = false;
        return pin;
    }

    /** Returns the live pin of a package and user in any phase, or null. Not a grant check. */
    public synchronized Pin find(String packageName, int userId) {
        return index.find(Objects.requireNonNull(packageName, "packageName"), userId);
    }

    /** Returns the live pin with this ID in any phase, or null. */
    public synchronized Pin findId(long id) {
        return index.ids.get(id);
    }

    /** Whether a live pin in any phase, RETIRING included, holds this package. */
    public synchronized boolean isPackagePinned(String packageName) {
        return index.packages.containsKey(Objects.requireNonNull(packageName, "packageName"));
    }

    /** Whether a live pin in any phase, RETIRING included, holds this app ID. */
    public synchronized boolean isAppIdPinned(int appId) {
        return index.appIds.containsKey(appId);
    }

    /**
     * Returns every app ID held by a live pin in any phase, RETIRING included, once each and in
     * ascending order. PMS refreshes its allocator barrier from this under its own lock. An app
     * ID leaves only when the last pin holding it is finished. The result is an
     * unmodifiable copy, not a live view.
     */
    public synchronized Set<Integer> reservedAppIds() {
        return Collections.unmodifiableSet(new TreeSet<>(index.appIds.keySet()));
    }

    /** All held records in ID order, including persisted retirement markers. */
    public synchronized Snapshot snapshotForWrite() {
        return snapshotExcept(null);
    }

    /**
     * Candidate final publication after this exact pin's quiescence. It omits
     * only that pin, never other RETIRING pins which may still own live work.
     * Nothing changes in memory until the caller confirms durability and finishes.
     */
    public synchronized Snapshot snapshotWithout(Pin pin) {
        requireCurrent(pin);
        if (pin.phase != Phase.RETIRING) throw new IllegalStateException("Pin is not retiring");
        return snapshotExcept(pin);
    }

    private Snapshot snapshotExcept(Pin omitted) {
        List<Record> records = new ArrayList<>(index.ids.size());
        Set<Long> retiring = new TreeSet<>();
        for (Pin pin : index.ids.values()) {
            if (pin == omitted) continue;
            records.add(pin.record);
            if (pin.phase == Phase.RETIRING) retiring.add(pin.record.id);
        }
        return new Snapshot(lastId, records, retiring);
    }

    /**
     * Makes a PENDING pin ACTIVE. Repeating it for the same ACTIVE handle changes nothing. Call
     * only after a snapshot containing the record is durable and the subject is revalidated.
     *
     * @throws IllegalStateException for a RETIRING, stale or foreign handle
     */
    public synchronized void commit(Pin pin) {
        requireCurrent(pin);
        if (pin.phase == Phase.RETIRING) {
            throw new IllegalStateException("cannot commit a retiring pin: " + pin.record);
        }
        pin.phase = Phase.ACTIVE;
    }

    /**
     * Moves a PENDING or ACTIVE pin to RETIRING, irrevocably. Repeating it for the same handle
     * changes nothing. Durably publish the marked snapshot before account removal
     * or quiescence starts. The pin stays held in every ordinary snapshot.
     *
     * @throws IllegalStateException for a stale or foreign handle
     */
    public synchronized void beginRetire(Pin pin) {
        requireCurrent(pin);
        pin.phase = Phase.RETIRING;
    }

    /**
     * Removes a RETIRING pin. Its handle becomes stale and its ID stays consumed. The app ID is
     * released only when no other pin holds it. Call only after authoritative
     * quiescence and durable publication of snapshotWithout for this exact pin.
     *
     * @throws IllegalStateException unless the handle is current, owned here and RETIRING
     */
    public synchronized void finishRetire(Pin pin) {
        requireCurrent(pin);
        if (pin.phase != Phase.RETIRING) {
            throw new IllegalStateException("finishRetire needs RETIRING, not " + pin.phase);
        }
        index.remove(pin);
        pin.phase = Phase.RETIRED;
    }

    /**
     * Loads durable state into a fresh instance, before any prepare. Checks every field, the
     * uniqueness rules, that lastId covers every ID and the capacity before changing anything.
     * Retiring markers restore RETIRING. All other pins restore PENDING, never ACTIVE.
     *
     * @return the new handles, in snapshot order
     * @throws IllegalArgumentException for an invalid snapshot
     * @throws IllegalStateException if this instance is not fresh or the records exceed capacity
     */
    public synchronized List<Pin> restore(Snapshot snapshot) {
        Objects.requireNonNull(snapshot, "snapshot");
        if (!fresh) throw new IllegalStateException("restore needs a fresh instance");
        if (snapshot.lastId < 0) {
            throw new IllegalArgumentException("negative lastId: " + snapshot.lastId);
        }
        if (snapshot.records.size() > capacity) {
            throw new IllegalStateException(
                    snapshot.records.size() + " records exceed capacity " + capacity);
        }
        Index restored = new Index();
        List<Pin> pins = new ArrayList<>(snapshot.records.size());
        for (Record record : snapshot.records) {
            // Records validate on construction. Durable input is checked again at this boundary.
            checkBinding(record.packageName, record.appId, record.userId, record.userSerial);
            if (record.id <= 0 || record.id > snapshot.lastId) {
                throw new IllegalArgumentException("ID outside 1..lastId: " + record);
            }
            if (restored.ids.containsKey(record.id)) {
                throw new IllegalArgumentException("duplicate ID: " + record);
            }
            if (restored.find(record.packageName, record.userId) != null) {
                throw new IllegalArgumentException("duplicate package and user: " + record);
            }
            String reason = restored.conflict(record.packageName, record.appId);
            if (reason != null) throw new IllegalArgumentException(reason + ": " + record);
            Pin pin = new Pin(this, record);
            if (snapshot.retiringIds.contains(record.id)) pin.phase = Phase.RETIRING;
            restored.add(pin);
            pins.add(pin);
        }
        for (long id : snapshot.retiringIds) {
            if (id <= 0 || !restored.ids.containsKey(id)) {
                throw new IllegalArgumentException("Unknown retiring pin ID: " + id);
            }
        }
        index = restored; // First change. Every check above has passed.
        lastId = snapshot.lastId;
        fresh = false;
        return Collections.unmodifiableList(pins);
    }

    // Only the exact live handle of this instance. A finished handle is no longer indexed.
    private void requireCurrent(Pin pin) {
        Objects.requireNonNull(pin, "pin");
        if (pin.owner != this) throw new IllegalStateException("foreign pin: " + pin.record);
        if (index.ids.get(pin.record.id) != pin) {
            throw new IllegalStateException("stale pin: " + pin.record);
        }
    }

    private static void checkBinding(String packageName, int appId, int userId, long userSerial) {
        Objects.requireNonNull(packageName, "packageName");
        if (!isPackageName(packageName)) {
            throw new IllegalArgumentException(
                    "malformed package name of length " + packageName.length());
        }
        if (appId < FIRST_APP_ID || appId > LAST_APP_ID) {
            throw new IllegalArgumentException(
                    "app ID outside " + FIRST_APP_ID + ".." + LAST_APP_ID + ": " + appId);
        }
        if (userId < 0) throw new IllegalArgumentException("negative user ID: " + userId);
        if ((long) userId * PER_USER_RANGE + appId > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("UID above Integer.MAX_VALUE for user " + userId);
        }
        if (userSerial < 0) {
            throw new IllegalArgumentException("negative user serial: " + userSerial);
        }
    }

    // Dot separated ASCII segments. Each starts with a letter, then letters, digits or '_'.
    private static boolean isPackageName(String name) {
        int length = name.length();
        if (length > MAX_PACKAGE_NAME_LENGTH) return false;
        int segments = 1;
        boolean segmentStart = true;
        for (int i = 0; i < length; i++) {
            char c = name.charAt(i);
            boolean letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
            boolean trailing = (c >= '0' && c <= '9') || c == '_';
            if (letter || (trailing && !segmentStart)) {
                segmentStart = false;
            } else if (c == '.' && !segmentStart) {
                ++segments;
                segmentStart = true;
            } else {
                return false;
            }
        }
        return !segmentStart && segments >= 2;
    }
}
