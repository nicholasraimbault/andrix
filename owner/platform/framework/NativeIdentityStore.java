// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import android.os.FileUtils;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import com.android.server.pm.NativeIdentityRecords.ActorClass;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.HeaderEntry;
import com.android.server.pm.NativeIdentityRecords.Lifecycle;
import com.android.server.pm.NativeIdentityRecords.LifecycleState;
import com.android.server.pm.NativeIdentityRecords.Obligation;
import com.android.server.pm.NativeIdentityRecords.ObligationKind;
import com.android.server.pm.NativeIdentityRecords.ObligationState;
import com.android.server.pm.NativeIdentityRecords.ReleaseTicket;
import com.android.server.pm.NativeIdentityRecords.Retirement;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.SlotPhase;
import com.android.server.pm.NativeIdentityRecords.Suspension;
import com.android.server.pm.NativeIdentityRecords.SuspensionReason;
import com.android.server.pm.NativeIdentityRecords.UserEntry;

/**
 * Package Manager owned persistence of native UID reservations. Stable slot
 * directory names and header entries impose negative allocation holds only.
 * Valid record bytes do not authenticate a caller or establish a live lease.
 *
 * All access is serialized by the caller's install/mutation operation. No work
 * control, admission, AMS or WM lock may be held during this I/O. In particular,
 * the PMS state lock is not held: the caller publishes a conservative in-memory
 * hold before a write, and revalidates under that lock before activating/releasing.
 *
 * Reads never create, repair or delete anything. This deliberately does not call
 * ResilientAtomicFile.openRead/failRead, which may delete recovery copies. The
 * existing strict writer is reused to check the original writing descriptors.
 *
 * Each store has one Format, fixed at construction: the highest header version it
 * reads as supported, the version a new bound reservation writes, and the highest
 * slot version it reads as supported and writes. Production constructs Format.V2
 * once, at the Settings boot read. Format.V1 reads and writes version 1 headers
 * only, as the earlier images did. Format.V1 and Format.V2 read and write version 1
 * slots only. Format.V3 also reads and writes version 2 slots, which carry the
 * account lifecycle record; no production text constructs it. Initialization
 * writes an empty version 1 header in every format.
 * An intact record frame (bounded size, magic, expected type, length and SHA-256)
 * that declares a version above the format's ceiling is an unsupported footprint,
 * not damage. Under Format.V1 a decoded version 2 header copy still contributes
 * its holds, and only holds. Under a slot ceiling of 1, a decoded version 2 slot
 * copy is negative evidence only, and so is the stable prefix of a slot frame above
 * version 2 in every format: package names, principal IDs and sibling conflicts.
 * Nothing is restored from either. The frame alone classifies a record: a body or
 * prefix that fails to decode never turns an intact newer frame into damage, and a
 * broken prefix only gives no evidence. A frame the codec cannot decode is no
 * value: no app ID, binding or counter is invented from it. Such a main, reserve or
 * backup copy makes its record UNSUPPORTED even when an older valid copy exists. A staging
 * seed is never a copy or positive history, but it is preserved too. While any
 * such footprint is recognized, every writer refuses before its first effect:
 * the whole native store stays read only. That is an availability choice,
 * separate from per-slot binding eligibility. It releases
 * nothing, and damaged bytes, including a bad checksum, remain ordinary damage.
 * It protects only records within the codec's size bound, and it does not
 * recover holds that exist only in an unreadable index.
 *
 * Presence comes from one stat that does not follow links. Only a genuine
 * ENOENT is absence. A symbolic link or special node is never followed or
 * opened. Any other stat failure, such as EACCES, ENOTDIR or EIO, leaves
 * presence unknown. A copy or seed whose presence or bytes are unknown is
 * unavailable: not absence, and not ordinary damage, because it may be a newer
 * record. No value is selected around such a copy, and the whole native store
 * stays read only as for a recognized footprint. An unavailable header copy
 * withdraws every binding, as a newer one does. Every acknowledgement that
 * depends on absence needs the genuine ENOENT. This is an availability choice
 * too; it releases nothing.
 *
 * A preferred backup outranks a newer main or reserve, so a decodable copy can
 * differ from the selected header. Only relations a writer leaves are compatible:
 * an interrupted phase change or omission, a copy that predates a protected
 * reservation, or an unselected addition an older writer left behind. Additions
 * are negative holds, never positive history. Every header write must restate
 * each one exactly and cover every copy's counter, or refuse before its first
 * effect, and incompatible copies refuse every header write. A pure reservation
 * publishes its own target as the preferred backup before main and reserve are
 * rewritten; every other write keeps its prior there until its final step. A new
 * registry restores the selected counter only when it covers every copy. See
 * keepsHeaderCopies and writeStrict.
 *
 * A complete creation binding in a version 2 CREATING entry is checked only
 * negatively: its body must have exactly that one user, serial and signer set,
 * or the slot is a CONFLICT and no transition uses it. Its decoded copies remain
 * negative package and principal evidence for siblings. An entry without a binding
 * keeps the version 1 checks. Nothing fills in or relaxes a binding.
 *
 * The selected valid header's counter also bounds new issuance, never binding. A
 * decoded slot copy that names a principal ID above it blocks creation when it has the
 * selected lineage, in any record whatever its status, selection, app ID or tuple, or
 * when its record is already negative evidence (unsupported, unavailable or a failed
 * complete binding), whatever its lineage. Nothing raises, reconstructs or derives a
 * counter from such an ID. Statuses, eligible bindings, evidence, holds and footprint
 * flags are unchanged, so existing eligible bindings still confirm, mark and retire.
 * Staging seeds never count. A copy from another lineage outside that existing evidence
 * blocks nothing here; the conservative release check remains separate.
 *
 * Each view also names the historical identity of an app ID, if any: see History.
 * A published eligible body is one. So is a selected complete header creation whose
 * slot this view reads as genuinely missing, when every copy and every other app ID
 * agree. A missing slot now is no proof that no body ever existed: one may have been
 * lost before a restart. Either is data for restoring a pending pin and matching an
 * explicit designation, never a grant.
 *
 * Under a format that writes version 2 slots, an account's lifecycle record changes only
 * through the named transitions: addSuspension and liftSuspension change suspension
 * entries, markSlotRetiring writes the retirement block, markSlotRetired confirms
 * retired, beginSlotDisposition moves every disposition kind to DISPOSING at once and
 * dischargeSlotDisposition confirms disposal per kind. The state only moves forward, ELIGIBLE
 * to RETIRING to RETIRED. A written retirement block never changes, except that a legacy
 * marker's unknown inventory continues once to every kind outstanding, and its obligations
 * move only forward as the record's obligation transitions list them. A user leaves a slot only
 * through the release engine's named primitives: dropReleasedUser writes the ticketed tombstone of
 * an account RETIRED with every obligation discharged and no suspension entry, markSlotReleasing
 * turns its LIVE entry RELEASING, removeReleasingSlot removes the directory, omitReleasedSlot omits
 * the entry and confirmReleasedSlot confirms that omission. The generic update keeps every lifecycle
 * there and drops no user, and the generic header write turns no entry RELEASING and omits none. A
 * tombstone's release ticket is likewise the release engine's alone, and LIVE becomes RELEASING
 * only over a ticketed tombstone. No production text calls a release primitive outside the release
 * bodies of NativeIdentityPersistence. Each transition
 * also applies the writer rules of the lifecycle record, which are narrower than what its
 * decoder accepts: see writableSuspension, placeFree, writableRetirement, writableReceipts
 * and writableDispositionReceipts. Restore, the recovery route's writer, is separate: it
 * writes an account's last known state with a recovery hold over a record that needs no valid
 * read, and it is the only writer of a recovery hold. Under the earlier formats every
 * transition and Restore refuse before their first effect, and version 1's retiring rule
 * stays.
 */
final class NativeIdentityStore {
    enum Status { MISSING, VALID, DAMAGED, CONFLICT, UNSUPPORTED }

    /**
     * The header and slot versions one store instance reads and writes. Closed and fixed
     * at construction; nothing selects it from configuration, properties, settings or
     * stored bytes. Production constructs V2 at its one boot read. V1, the earlier
     * images' format, remains for host rollback models. V3 is the lifecycle format, which
     * no production text constructs yet.
     */
    enum Format {
        /**
         * Reads and writes version 1 headers and slots. Every newer intact frame is an
         * unsupported footprint.
         */
        V1(1, 1, 1),
        /**
         * Also reads version 2 headers. A reservation with a truly new entry writes version 2
         * with that entry's complete creation binding. Version 3 headers and above, and slots
         * above version 1, are unsupported footprints.
         */
        V2(2, 2, 1),
        /**
         * Also reads and writes version 2 slots, with their lifecycle records. Version 3
         * headers and slots and above are unsupported footprints.
         */
        V3(2, 2, 2);

        /** Highest header version read as supported. A newer intact frame is a footprint. */
        final int headerCeiling;
        /** Header version of a reservation that adds a truly new entry. */
        final int reservationVersion;
        /**
         * Highest slot version read as supported and written. A newer intact frame is a
         * footprint, and every slot writer refuses a newer value before its first effect.
         */
        final int slotCeiling;

        Format(int headerCeiling, int reservationVersion, int slotCeiling) {
            this.headerCeiling = headerCeiling;
            this.reservationVersion = reservationVersion;
            this.slotCeiling = slotCeiling;
        }
    }

    static final class ReadResult<T> {
        final Status status;
        final T value; // Positive metadata only when VALID.
        final List<T> decodedCopies; // Negative holds only; never merged into a grant.
        // The stable prefixes of slot copies above every version the codec decodes. Only an
        // unsupported record has them. Negative package and principal evidence only: never a
        // value, binding, history, counter or hold. A copy whose prefix is broken gives none.
        final List<NativeIdentityRecords.SlotPrefix> prefixes;
        // Some copy's presence or bytes could not be observed. It may be newer, so
        // the record is never VALID or MISSING. This is I/O, not parser damage.
        final boolean unavailable;
        ReadResult(Status status, T value, List<T> decodedCopies) {
            this(status, value, decodedCopies, false);
        }
        ReadResult(Status status, T value, List<T> decodedCopies, boolean unavailable) {
            this(status, value, decodedCopies, List.of(), unavailable);
        }
        ReadResult(Status status, T value, List<T> decodedCopies,
                List<NativeIdentityRecords.SlotPrefix> prefixes, boolean unavailable) {
            this.status = status;
            this.value = value;
            this.decodedCopies = List.copyOf(decodedCopies);
            this.prefixes = List.copyOf(prefixes);
            this.unavailable = unavailable;
        }
    }

    /** Where a historical identity comes from. Neither source is live authority. */
    enum Source {
        /** A published slot body that is eligible for binding: exactly bindingUsable. */
        BODY,
        /**
         * The selected complete creation binding of a CREATING entry, where this view has no
         * eligible published body because the slot is genuinely missing. That is no proof that
         * a body never existed; one may have been lost before a restart. It restores the
         * original creation after its handle was lost. Never retiring.
         */
        RESERVATION
    }

    /**
     * The historical native identity of one app ID in one view: its original lineage, package,
     * principal ID, user, serial and signer set, and a body's lifecycle state and suspension
     * entries. It is metadata for restoring a PENDING or RETIRING pin and for matching an
     * explicit designation against actual Package Manager state. It is never execution, CE,
     * designation or allocation authority, and never a current identity. Only the store builds
     * it, from a view's own immutable data, without I/O. Nothing fills it from an APK, a
     * PackageSetting, a directory, a staging seed, an unselected header copy, a stable prefix or
     * a counter.
     */
    static final class History {
        final String lineage;
        final int appId;
        final String packageName;
        /** The principal ID: the body's one user, or the entry's creation ID. */
        final long id;
        final int userId;
        final long userSerial;
        /** Unmodifiable: the body's stored signers, or the selected creation binding's. */
        final Set<String> signerSha256;
        /** The body's lifecycle state. A reservation is ELIGIBLE. */
        final NativeIdentityRecords.LifecycleState state;
        /** Unmodifiable: the body's suspension entries, in record order. A reservation has none. */
        final List<NativeIdentityRecords.Suspension> suspensions;
        /**
         * The body's durable retirement: its state is RETIRING or RETIRED, and either restores a
         * RETIRING pin. A reservation is never retiring.
         */
        final boolean retiring;
        final Source source;

        private History(String lineage, int appId, String packageName, long id, int userId,
                long userSerial, Set<String> signerSha256, NativeIdentityRecords.Lifecycle lifecycle,
                Source source) {
            this.lineage = Objects.requireNonNull(lineage);
            this.appId = appId;
            this.packageName = Objects.requireNonNull(packageName);
            this.id = id;
            this.userId = userId;
            this.userSerial = userSerial;
            // Already an unmodifiable ascending set of the record it came from.
            this.signerSha256 = Objects.requireNonNull(signerSha256);
            this.state = lifecycle.state;
            // Already an unmodifiable list of the record it came from.
            this.suspensions = lifecycle.suspensions;
            this.retiring = lifecycle.state != NativeIdentityRecords.LifecycleState.ELIGIBLE;
            this.source = Objects.requireNonNull(source);
        }

        /**
         * The policy's Eligible state: ELIGIBLE with no suspension entry. Only such a history
         * may own a scan or restore as a reservation. A suspended or retiring one never does.
         */
        boolean eligible() {
            return state == NativeIdentityRecords.LifecycleState.ELIGIBLE && suspensions.isEmpty();
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) return true;
            if (!(other instanceof History)) return false;
            History history = (History) other;
            return appId == history.appId && id == history.id && userId == history.userId
                    && userSerial == history.userSerial && state == history.state
                    && suspensions.equals(history.suspensions)
                    && source == history.source && lineage.equals(history.lineage)
                    && packageName.equals(history.packageName)
                    && signerSha256.equals(history.signerSha256);
        }

        @Override
        public int hashCode() {
            return Objects.hash(lineage, appId, packageName, id, userId, userSerial, signerSha256,
                    state.ordinal(), suspensions, source.ordinal());
        }

        @Override
        public String toString() {
            return "History{" + source + ", appId=" + appId + ", package=" + packageName + ", id="
                    + id + ", user=" + userId + ", serial=" + userSerial + ", signers="
                    + signerSha256.size() + (state == NativeIdentityRecords.LifecycleState.ELIGIBLE
                    ? "" : ", " + state) + (suspensions.isEmpty() ? "}" : ", suspended}");
        }
    }

    static final class Loaded {
        final ReadResult<Header> header;
        final Map<Integer, ReadResult<Slot>> slots;
        final Set<Integer> occupiedAppIds;
        final boolean creationBlocked;
        final boolean enumerationComplete;
        // Store availability, NOT binding eligibility: some header or slot copy
        // or staging seed is a recognized unsupported footprint. Every writer
        // then refuses and creation is blocked. bindingUsable still judges
        // each slot by its own copies and the header.
        final boolean unsupportedFootprint;
        // Store availability too: some header or slot copy or staging seed, or a
        // listed slot entry, could not be stat'ed or read. It may be a newer
        // footprint. Every writer then refuses and creation is blocked.
        // Namespace observation failures can instead appear only through
        // enumerationComplete=false; callers must check both conditions.
        final boolean unavailableFootprint;
        // NOT a creation block: some decodable header copy is incompatible with the
        // selected valid header, or holds an unselected addition or counter the
        // selection does not cover. A copy that predates a protected reservation is
        // neither. The owner of an unacknowledged reservation can still restate it
        // exactly, and every other header write refuses. A new registry has no such
        // owner: see counterRestorable. This is the pure coverage test of
        // selectionCovers; it takes no writer format from the records.
        final boolean unselectedFootprint;
        // Historical identities by app ID, computed once from this view by historiesOf.
        private final Map<Integer, History> histories;
        Loaded(ReadResult<Header> header, Map<Integer, ReadResult<Slot>> slots,
                Set<Integer> occupied, boolean blocked, boolean complete) {
            this(header, slots, occupied, blocked, complete, false, false);
        }
        Loaded(ReadResult<Header> header, Map<Integer, ReadResult<Slot>> slots,
                Set<Integer> occupied, boolean blocked, boolean complete, boolean unsupported) {
            this(header, slots, occupied, blocked, complete, unsupported, false);
        }
        Loaded(ReadResult<Header> header, Map<Integer, ReadResult<Slot>> slots,
                Set<Integer> occupied, boolean blocked, boolean complete, boolean unsupported,
                boolean unavailable) {
            this.header = header;
            this.slots = Map.copyOf(slots);
            occupiedAppIds = Set.copyOf(occupied);
            creationBlocked = blocked || unsupported || unavailable;
            enumerationComplete = complete;
            unsupportedFootprint = unsupported;
            unavailableFootprint = unavailable;
            unselectedFootprint = header.status == Status.VALID && !selectionCovers(header);
            histories = historiesOf(this);
        }
        /** This app ID's historical identity in this view, or null. Metadata, never authority. */
        History history(int appId) {
            return histories.get(appId);
        }
        /** Every historical identity of this view, by app ID. Unmodifiable. */
        Map<Integer, History> histories() {
            return histories;
        }
        // Metadata eligibility for fresh designation/PMS rebinding, NOT live
        // execution authority. Retiring users must still restore as RETIRING.
        // A header copy that could not be read may be newer. Like a newer
        // header, it withdraws every binding.
        boolean bindingUsable(int appId) {
            ReadResult<Slot> slot = slots.get(appId);
            return enumerationComplete && header.status != Status.UNSUPPORTED && !header.unavailable
                    && slot != null && slot.status == Status.VALID && !slot.value.users.isEmpty();
        }
        // Also false beside a decoded principal ID above the selected counter; see load().
        boolean creationReady() {
            return enumerationComplete && !creationBlocked && header.status == Status.VALID;
        }
        // Whether a new registry may restore the selected counter: only when the
        // selection is compatible with and covers every copy. It is never taken
        // from another copy. Holds and eligible bindings are restored either way,
        // and a live registry keeps its own counter for its exact retries.
        boolean counterRestorable() {
            return creationReady() && !unselectedFootprint;
        }
    }

    private interface Decoder<T> { T decode(byte[] bytes); }

    // The codec can preserve future header data, but this store's transition and
    // admission protocols implement only its format's header and slot versions. A
    // decoded newer footprint is a hold, or for a slot negative evidence, not
    // permission to reinterpret or mutate that state. An intact frame of a newer
    // version that does not decode keeps no hold of its own.
    // The one cross-version relation between copies: a version 1 predecessor of a
    // version 2 protected reservation. Not a rule for any other or future version.
    private static final int HEADER_V1 = 1;
    private static final int HEADER_V2 = 2;
    // The only user of a reservation history: this adapter supports user 0.
    private static final int USER_SYSTEM = 0;
    // The first slot version that carries an account lifecycle record. A format whose slot
    // ceiling reaches it changes lifecycles only through the named transitions.
    private static final int LIFECYCLE_SLOT_VERSION = 2;
    // The grant references' places among a version 2 record's six suspension entries, as writers
    // allot them beside one for the account's user and one for a recovery hold.
    private static final int GRANT_PLACES = 4;

    private final File root;
    private final File slotRoot;
    private final Format format;

    NativeIdentityStore(File root, Format format) {
        this.root = Objects.requireNonNull(root).getAbsoluteFile();
        this.format = Objects.requireNonNull(format, "format");
        slotRoot = new File(this.root, "slots");
    }

    /** This store's fixed format. Metadata for its own persistence, never read from bytes. */
    Format format() { return format; }

    // The filename is deliberately stable while its record body is replaced.
    private File slotDirectory(int appId) {
        checkAppId(appId);
        return new File(slotRoot, Integer.toString(appId));
    }
    private File headerFile() { return new File(root, "store.bin"); }
    private File slotFile(int appId) { return new File(slotDirectory(appId), "record.bin"); }
    private static File backup(File main) { return new File(main.getPath() + "-backup"); }
    private static File reserve(File main) { return new File(main.getPath() + ".reservecopy"); }
    // Staging for the preferred backup. Never a copy or positive history.
    private static File seed(File main) { return new File(main.getPath() + "-seed"); }
    // What one stat that does not follow links proves. Only a genuine ENOENT is
    // ABSENT. A symbolic link or special node is OTHER: never followed or opened.
    // Any other failure, including EACCES, ENOTDIR and EIO, is UNKNOWN. That is
    // never absence.
    private enum Node { ABSENT, FILE, DIRECTORY, OTHER, UNKNOWN }

    private static Node node(File file) {
        try {
            BasicFileAttributes attributes = Files.readAttributes(file.toPath(),
                    BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (attributes.isRegularFile()) return Node.FILE;
            return attributes.isDirectory() ? Node.DIRECTORY : Node.OTHER;
        } catch (NoSuchFileException absent) {
            return Node.ABSENT;
        } catch (IOException | RuntimeException unknown) {
            return Node.UNKNOWN;
        }
    }
    // Evidence for the caller's exact transaction only, never a free app ID.
    private static boolean absent(File file) { return node(file) == Node.ABSENT; }
    private static boolean directory(File file) { return node(file) == Node.DIRECTORY; }

    // One record path. Bytes come only from a readable regular file within the
    // format bound. DAMAGED is known not to be an intact record: a link, special
    // node or directory, or more bytes than the bound. UNAVAILABLE means the stat
    // or read failed. That is neither absence nor damage: it may be a newer
    // record, so it is never overwritten, removed or selected around.
    private enum Found { ABSENT, BYTES, DAMAGED, UNAVAILABLE }

    private static final class Copy {
        final Found found;
        final byte[] bytes; // Only for BYTES.
        Copy(Found found, byte[] bytes) {
            this.found = found;
            this.bytes = bytes;
        }
    }

    // Opened only right after that stat found a regular file. The store is
    // private to its one serialized writer; nothing else replaces the node.
    private static Copy observe(File file) {
        Node node = node(file);
        if (node == Node.ABSENT) return new Copy(Found.ABSENT, null);
        if (node == Node.UNKNOWN) return new Copy(Found.UNAVAILABLE, null);
        if (node != Node.FILE) return new Copy(Found.DAMAGED, null);
        try (FileInputStream in = new FileInputStream(file)) {
            byte[] bytes = in.readNBytes(NativeIdentityRecords.MAX_BYTES + 1);
            return bytes.length > NativeIdentityRecords.MAX_BYTES ? new Copy(Found.DAMAGED, null)
                    : new Copy(Found.BYTES, bytes);
        } catch (IOException | RuntimeException unavailable) {
            return new Copy(Found.UNAVAILABLE, null);
        }
    }

    private static byte[] readBytes(File file) throws IOException {
        Copy copy = observe(file);
        if (copy.found != Found.BYTES) throw new IOException("Native record bytes unavailable");
        return copy.bytes;
    }

    // An intact frame of the expected type which declares a version above what this
    // store's format reads: its header or slot ceiling. The frame alone decides,
    // whatever the body holds. Torn, foreign, wrongly typed, oversized, version 0 and
    // bad checksum bytes are not recognized. They remain ordinary damage.
    private boolean unsupportedBytes(byte[] bytes, boolean header) {
        return header ? NativeIdentityRecords.intactHeaderVersion(bytes) > format.headerCeiling
                : NativeIdentityRecords.intactSlotVersion(bytes) > format.slotCeiling;
    }
    // The stable prefix of a slot copy that the codec cannot decode, as negative evidence,
    // or none when the prefix breaks its rules. It never decides the record's status.
    private static List<NativeIdentityRecords.SlotPrefix> stablePrefix(byte[] bytes) {
        try {
            return List.of(NativeIdentityRecords.decodeSlotPrefix(bytes));
        } catch (IllegalArgumentException broken) {
            return List.of();
        }
    }
    private boolean newer(Copy copy, boolean header) {
        return copy.found == Found.BYTES && unsupportedBytes(copy.bytes, header);
    }
    // Every file a writer of this record can replace, truncate, rename over or
    // unlink. A recognized newer frame blocks. So does a path whose presence or
    // bytes are unavailable: it cannot be assumed not to be newer.
    private boolean recordBlocked(File main, boolean header) {
        for (File file : List.of(main, reserve(main), backup(main), seed(main))) {
            Copy copy = observe(file);
            if (copy.found == Found.UNAVAILABLE || newer(copy, header)) return true;
        }
        return false;
    }

    /**
     * The store wide availability gate. Every writer passes it before its first
     * effect. A recognized unsupported footprint in any header or slot record
     * refuses them all, because a newer protocol can relate records in ways
     * this writer cannot see. Incomplete namespace inspection also refuses:
     * a target check cannot prove unrelated slots have no newer footprint.
     * So does any slot entry or record path whose presence or bytes are
     * unavailable. A link, special node or file slot entry stays ordinary
     * damage with its hold; the target writers refuse such an entry.
     * Refusal only keeps state; it is no hold, release or binding decision.
     */
    private boolean writeInspectionBlocked(int... targets) {
        if (!directory(root) || !directory(slotRoot)) return true;
        if (recordBlocked(headerFile(), true)) return true;
        File[] entries = slotRoot.listFiles();
        if (entries == null) return true;
        TreeSet<Integer> appIds = new TreeSet<>();
        for (int target : targets) appIds.add(target);
        for (File entry : entries) {
            Integer appId = parseSlotName(entry.getName());
            if (appId != null) appIds.add(appId);
        }
        for (int appId : appIds) {
            Node node = node(slotDirectory(appId));
            if (node == Node.UNKNOWN
                    || (node == Node.DIRECTORY && recordBlocked(slotFile(appId), false))) return true;
        }
        return false;
    }

    private <T> ReadResult<T> readCopies(File main, Decoder<T> decoder, boolean header) {
        File[] paths = {main, reserve(main), backup(main)};
        ArrayList<T> valid = new ArrayList<>();
        ArrayList<T> values = new ArrayList<>();
        ArrayList<NativeIdentityRecords.SlotPrefix> prefixes = new ArrayList<>();
        boolean[] present = new boolean[3];
        boolean bad = false, unsupported = false, unavailable = false;
        for (int i = 0; i < paths.length; ++i) {
            T value = null;
            Copy copy = observe(paths[i]);
            present[i] = copy.found != Found.ABSENT;
            if (copy.found == Found.UNAVAILABLE) unavailable = true;
            if (copy.found == Found.DAMAGED) bad = true;
            if (copy.bytes != null) {
                try {
                    value = decoder.decode(copy.bytes);
                    valid.add(value);
                } catch (RuntimeException error) { bad = true; }
                if (unsupportedBytes(copy.bytes, header)) {
                    unsupported = true;
                    // A slot frame above every version the codec decodes still names its
                    // package and principals in its stable prefix: evidence, never a value.
                    if (!header && value == null) prefixes.addAll(stablePrefix(copy.bytes));
                }
            }
            values.add(value);
        }
        // A newer copy, selected or not, is never hidden by an older valid one.
        // Decoded copies and stable prefixes still contribute their negative evidence.
        if (unsupported) {
            return new ReadResult<>(Status.UNSUPPORTED, null, valid, prefixes, unavailable);
        }
        // Nor is a copy that could not be observed. It may be newer, or the
        // authoritative backup. It is not absence, so the record is never
        // MISSING, and no value is selected around it. Decoded copies stay holds.
        if (unavailable) return new ReadResult<>(Status.DAMAGED, null, valid, true);
        // Backup existence is authoritative for interrupted publication. Never
        // fall through an invalid backup to a possibly unconfirmed omission.
        if (present[2]) {
            T value = values.get(2);
            return new ReadResult<>(value == null ? Status.DAMAGED : Status.VALID, value, valid);
        }
        T first = values.get(0), second = values.get(1);
        if (first != null && second != null && !first.equals(second)) {
            return new ReadResult<>(Status.CONFLICT, null, valid);
        }
        if (first != null || second != null) {
            return new ReadResult<>(Status.VALID, first != null ? first : second, valid);
        }
        return new ReadResult<>(bad || present[0] || present[1] ? Status.DAMAGED : Status.MISSING,
                null, valid);
    }

    // Never read through a slot entry that is not a real directory: a link can
    // lead to foreign records. Such an entry is damage, or unavailable.
    private ReadResult<Slot> readSlotCopies(int appId) {
        Node node = node(slotDirectory(appId));
        if (node == Node.DIRECTORY || node == Node.ABSENT) {
            return readCopies(slotFile(appId), NativeIdentityRecords::decodeSlot, false);
        }
        return new ReadResult<>(Status.DAMAGED, null, List.of(), node == Node.UNKNOWN);
    }

    private ReadResult<Header> readHeaderCopies() {
        ReadResult<Header> read = readCopies(headerFile(), NativeIdentityRecords::decodeHeader, true);
        for (Header copy : read.decodedCopies) {
            if (copy.version > format.headerCeiling) {
                // Even an unselected copy can contain a reservation whose new
                // transition semantics this writer has not qualified. Preserve
                // all decoded UID holds and do not fall through to an older copy.
                return new ReadResult<>(Status.UNSUPPORTED, null, read.decodedCopies,
                        read.unavailable);
            }
        }
        return read;
    }

    Loaded load() {
        TreeMap<Integer, ReadResult<Slot>> loaded = new TreeMap<>();
        TreeSet<Integer> occupied = new TreeSet<>();
        ReadResult<Header> header = new ReadResult<>(Status.MISSING, null, List.of());
        boolean complete = false, blocked = true, unsupported = false, unavailable = false;
        try {
            Node rootNode = node(root);
            if (rootNode != Node.DIRECTORY || !directory(slotRoot)) {
                // A missing root is NOT automatically permission to initialize a
                // new lineage. The trusted creation operation decides that case.
                // Only a genuinely absent root reads as a missing header.
                if (rootNode == Node.DIRECTORY) {
                    header = readHeaderCopies();
                    Copy seed = observe(seed(headerFile()));
                    unsupported = header.status == Status.UNSUPPORTED || newer(seed, true);
                    unavailable = header.unavailable || seed.found == Found.UNAVAILABLE;
                } else if (rootNode != Node.ABSENT) {
                    unavailable = rootNode == Node.UNKNOWN;
                    header = new ReadResult<>(Status.DAMAGED, null, List.of(), unavailable);
                }
                for (Header copy : header.decodedCopies) {
                    for (HeaderEntry entry : copy.entries) occupied.add(entry.appId);
                }
                return new Loaded(header, loaded, occupied, true, false, unsupported, unavailable);
            }
            header = readHeaderCopies();
            Copy headerSeed = observe(seed(headerFile()));
            unsupported = header.status == Status.UNSUPPORTED || newer(headerSeed, true);
            unavailable = header.unavailable || headerSeed.found == Found.UNAVAILABLE;
            for (Header copy : header.decodedCopies) {
                for (HeaderEntry entry : copy.entries) occupied.add(entry.appId);
            }
            File[] entries = slotRoot.listFiles();
            if (entries == null) {
                return new Loaded(header, loaded, occupied, true, false, unsupported, unavailable);
            }
            complete = true;
            blocked = header.status != Status.VALID;
            // Discover every negative hold BEFORE record decoding can fail.
            for (File entry : entries) {
                Integer appId = parseSlotName(entry.getName());
                if (appId == null) blocked = true;
                else occupied.add(appId);
            }
            for (File entry : entries) {
                Integer appId = parseSlotName(entry.getName());
                if (appId == null) continue;
                if (header.status == Status.VALID && headerEntry(header.value, appId) == null) {
                    blocked = true; // Unknown creation lineage/counter, but only a negative hold.
                }
                Node node = node(entry);
                ReadResult<Slot> record;
                if (node == Node.DIRECTORY) {
                    record = readSlotCopies(appId);
                    Copy seed = observe(seed(slotFile(appId)));
                    // Only a format footprint here; a user 0 limit below is not one.
                    if (record.status == Status.UNSUPPORTED || newer(seed, false)) unsupported = true;
                    if (record.unavailable || seed.found == Found.UNAVAILABLE) unavailable = true;
                } else {
                    // A link, special node or file keeps its hold as damage. An
                    // entry whose type cannot be observed is unavailable too.
                    record = new ReadResult<>(Status.DAMAGED, null, List.of(), node == Node.UNKNOWN);
                    if (node == Node.UNKNOWN) unavailable = true;
                }
                if (record.status == Status.VALID) {
                    if (record.value.appId != appId) {
                        record = new ReadResult<>(Status.CONFLICT, null, record.decodedCopies);
                    } else {
                        for (UserEntry user : record.value.users) {
                            if (user.userId != 0) {
                                record = new ReadResult<>(Status.UNSUPPORTED, null, record.decodedCopies);
                                break;
                            }
                        }
                    }
                }
                loaded.put(appId, record);
            }
            Set<String> lineages = new HashSet<>();
            for (Header copy : header.decodedCopies) lineages.add(copy.lineage);
            // A known header lineage identifies foreign slots locally. With no
            // header source, intact slots must agree; never invent a new lineage
            // or reconstruct a counter from their maximum issued ID.
            if (lineages.isEmpty()) {
                for (ReadResult<Slot> record : loaded.values()) {
                    if (record.status == Status.VALID) lineages.add(record.value.lineage);
                }
            }
            // Records whose complete creation binding fails. They stay negative package and
            // principal evidence for their siblings below, whatever else conflicts.
            HashSet<Integer> bindingConflicts = new HashSet<>();
            for (Map.Entry<Integer, ReadResult<Slot>> entry : loaded.entrySet()) {
                ReadResult<Slot> record = entry.getValue();
                if (record.status != Status.VALID) continue;
                Slot slot = record.value;
                boolean conflict = lineages.size() != 1 || !lineages.contains(slot.lineage);
                boolean bindingMismatch = false;
                for (Header copy : header.decodedCopies) {
                    if (!copy.lineage.equals(slot.lineage)) { conflict = true; continue; }
                    HeaderEntry index = headerEntry(copy, slot.appId);
                    if (index == null) { conflict = true; continue; }
                    for (UserEntry user : slot.users) {
                        if (user.id > copy.lastId) { conflict = true; blocked = true; }
                    }
                    if (index.phase == SlotPhase.CREATING
                            && (!slot.packageName.equals(index.creationPackage)
                            || (!slot.users.isEmpty() && (slot.users.size() != 1
                            || slot.users.get(0).id != index.creationId)))) conflict = true;
                    // A complete creation binding also needs exactly its one user, serial
                    // and signer set, in every decoded copy that lists the entry. It is
                    // its own check, never skipped for another reason. Only negative: a
                    // mismatch is a CONFLICT with its holds, never usable history.
                    if (index.phase == SlotPhase.CREATING && !bindingHolds(index, slot)) {
                        bindingMismatch = true;
                    }
                    if (index.phase == SlotPhase.RELEASING && !slot.users.isEmpty()) conflict = true;
                }
                if (conflict || bindingMismatch) entry.setValue(new ReadResult<>(Status.CONFLICT,
                        null, record.decodedCopies));
                // A failed binding keeps the record's copies as evidence below, also beside
                // an ordinary conflict: that only restricts a bound state further. An
                // ordinary conflict alone still gives none, as before.
                if (bindingMismatch) bindingConflicts.add(entry.getKey());
            }
            // An index entry with no directory still holds its ID.
            for (int appId : occupied) {
                loaded.putIfAbsent(appId, new ReadResult<>(Status.MISSING, null, List.of()));
            }
            HashMap<String, Integer> packages = new HashMap<>();
            HashMap<Long, Integer> incarnations = new HashMap<>();
            HashSet<Integer> conflicts = new HashSet<>();
            // A newly unsupported or unavailable record must not make an otherwise
            // conflicting sibling usable, and neither may a record whose complete creation
            // binding fails: that check is negative only. Their decodable copies are
            // negative evidence, never an identity or counter source for them.
            // The same pass bounds new issuance by the selected header's counter. A decoded
            // copy that names a principal ID above it blocks creation when it has this
            // lineage, whatever its record's status, selection, app ID or tuple, or when its
            // record is such evidence, whatever its lineage. That is only a refusal: no
            // counter is raised or derived from the copy, and no status, binding, hold or
            // evidence changes. A staging seed is never a copy. A tombstone's release ticket
            // names a principal ID too, as sibling evidence and for this bound. A stable prefix
            // need not feed the bound: only an unsupported record has one, and that footprint
            // already blocks creation.
            Header selected = header.status == Status.VALID ? header.value : null;
            for (Map.Entry<Integer, ReadResult<Slot>> entry : loaded.entrySet()) {
                boolean evidence = entry.getValue().status == Status.UNSUPPORTED
                        || entry.getValue().unavailable
                        || bindingConflicts.contains(entry.getKey());
                for (Slot copy : entry.getValue().decodedCopies) {
                    if (selected != null && (evidence || copy.lineage.equals(selected.lineage))
                            && claimsAbove(copy, selected.lastId)) blocked = true;
                    if (!evidence) continue;
                    packages.putIfAbsent(copy.packageName, entry.getKey());
                    for (UserEntry user : copy.users) incarnations.putIfAbsent(user.id, entry.getKey());
                    // A tombstone's release ticket names its last principal: evidence too.
                    if (copy.ticket != null) incarnations.putIfAbsent(copy.ticket.lastId, entry.getKey());
                }
                // A later slot version's stable prefix. Only an unsupported record has one, so it
                // is always negative evidence, and that footprint already blocks creation.
                for (NativeIdentityRecords.SlotPrefix prefix : entry.getValue().prefixes) {
                    packages.putIfAbsent(prefix.packageName, entry.getKey());
                    for (long id : prefix.principalIds) incarnations.putIfAbsent(id, entry.getKey());
                }
            }
            for (Map.Entry<Integer, ReadResult<Slot>> entry : loaded.entrySet()) {
                if (entry.getValue().status != Status.VALID) continue;
                Slot slot = entry.getValue().value;
                Integer previous = packages.putIfAbsent(slot.packageName, entry.getKey());
                if (previous != null) { conflicts.add(previous); conflicts.add(entry.getKey()); }
                for (UserEntry user : slot.users) {
                    previous = incarnations.putIfAbsent(user.id, entry.getKey());
                    if (previous != null) { conflicts.add(previous); conflicts.add(entry.getKey()); }
                }
                // A valid tombstone's ticket names its last principal, which no sibling may name.
                if (slot.ticket != null) {
                    previous = incarnations.putIfAbsent(slot.ticket.lastId, entry.getKey());
                    if (previous != null) { conflicts.add(previous); conflicts.add(entry.getKey()); }
                }
            }
            for (int appId : conflicts) {
                ReadResult<Slot> prior = loaded.get(appId);
                if (prior.status == Status.VALID) {
                    loaded.put(appId, new ReadResult<>(Status.CONFLICT, null, prior.decodedCopies));
                }
            }
        } catch (RuntimeException error) {
            // Namespace/read failures are not permission to delete package data
            // or to present incomplete discovery as a fresh, empty store.
            complete = false;
            blocked = true;
        }
        return new Loaded(header, loaded, occupied, blocked, complete, unsupported, unavailable);
    }

    // Whether this decoded slot copy names a principal ID above the counter: a user's, or a
    // tombstone ticket's last principal. A refusal bound for new issuance only: the ID is never taken
    // as a counter or an allocation floor. A later slot version's stable prefix need not feed this
    // rule: a prefix exists only in an unsupported record, which already blocks creation.
    private static boolean claimsAbove(Slot copy, long counter) {
        for (UserEntry user : copy.users) {
            if (user.id > counter) return true;
        }
        return copy.ticket != null && copy.ticket.lastId > counter;
    }

    /** Explicit fresh creation or its exact empty-result retry, never called by load(). */
    boolean initializeNew(String lineage) {
        Header empty = new Header(lineage, 0, List.of());
        try {
            File parent = root.getParentFile();
            if (!directory(parent)) return false;
            Node existing = node(root);
            if (existing == Node.DIRECTORY) {
                if (writeInspectionBlocked()) return false;
                File[] children = slotRoot.listFiles();
                File[] contents = root.listFiles();
                Set<String> allowed = Set.of("slots", "store.bin", "store.bin-backup",
                        "store.bin.reservecopy", "store.bin-seed");
                if (!directory(root) || !directory(slotRoot) || children == null
                        || children.length != 0 || contents == null || !sameHeader(empty)) return false;
                for (File child : contents) if (!allowed.contains(child.getName())) return false;
                if (!confirmHeader(empty)) return false;
                syncDirectory(slotRoot); syncDirectory(root); syncDirectory(parent);
                return true;
            }
            // Only a genuinely absent root is created. A link, special node, file
            // or root whose presence is unknown is never replaced or assumed empty.
            if (existing != Node.ABSENT) return false;
            // The canonical root is absent or has a complete empty layout. A
            // crash before rename leaves only an unpublished staging sibling,
            // never a torn canonical store that looks like lost identity data.
            File staging = Files.createTempDirectory(parent.toPath(), "." + root.getName()
                    + "-creating-" + lineage + "-").toFile();
            protectDirectory(staging);
            File stagedSlots = new File(staging, "slots");
            if (!stagedSlots.mkdir()) return false;
            protectDirectory(stagedSlots); syncDirectory(stagedSlots);
            byte[] bytes = NativeIdentityRecords.encodeHeader(empty);
            if (!writeStrict(new File(staging, "store.bin"), bytes, null, false, true)) return false;
            syncDirectory(staging);
            // Same private parent and one writer. No REPLACE_EXISTING and no
            // ATOMIC_MOVE option which could replace an existing empty target.
            if (!absent(root)) return false;
            Files.move(staging.toPath(), root.toPath());
            syncDirectory(parent);
            return true;
        } catch (IOException | RuntimeException error) { return false; }
    }

    /** Diagnostic maintenance references, never proof that a directory can be adopted/deleted. */
    List<String> pendingInitializationNames() throws IOException {
        File parent = root.getParentFile();
        if (!directory(parent)) throw new IOException("Native store parent unavailable");
        File[] files = parent.listFiles();
        if (files == null) throw new IOException("Native store parent enumeration failed");
        TreeSet<String> names = new TreeSet<>();
        String prefix = "." + root.getName() + "-creating-";
        for (File file : files) if (file.getName().startsWith(prefix)) names.add(file.getName());
        return List.copyOf(names);
    }

    /**
     * Whether a decodable header copy relates to the selected valid header as this store's own
     * writers can leave it. This structural relation is the only one between copies the store
     * recognizes: nothing is ordered by time, and the selection stays the preferred backup
     * rule's. The copy has the same lineage, and the same version except for one supported
     * reader shape: a version 1 copy below the counter of a version 2 selection, which must
     * then be a predecessor of that protected reservation. Only a reservation that adds a truly
     * new bound entry raises the version, and it always advances the counter. A newer copy, an
     * older one at or above the selected counter, or any other version is incompatible. An app
     * ID both list is equal, or one phase ahead in the copy (CREATING to LIVE, or LIVE to
     * RELEASING). An entry only the selection lists is RELEASING, omitted by the copy, or
     * CREATING above the copy's counter, when the copy predates a protected reservation. An
     * entry only the copy lists is CREATING above the selected counter: an unselected addition.
     * A higher copy counter comes only with such an addition, a lower one only with such a
     * newer selected reservation, and otherwise the counters are equal.
     */
    private static boolean compatible(Header selected, Header copy) {
        if (copy.version != selected.version && (copy.version != HEADER_V1
                || selected.version != HEADER_V2 || copy.lastId >= selected.lastId)) return false;
        return related(selected, copy);
    }

    // The structural part of compatible, whatever the versions: lineage, entries and counters.
    // A header written over the selection must relate to it the same way.
    private static boolean related(Header selected, Header copy) {
        if (!copy.lineage.equals(selected.lineage)) return false;
        boolean behind = false, ahead = false;
        for (HeaderEntry kept : selected.entries) {
            HeaderEntry seen = headerEntry(copy, kept.appId);
            if (seen == null) {
                if (kept.phase == SlotPhase.CREATING && kept.creationId > copy.lastId) behind = true;
                else if (kept.phase != SlotPhase.RELEASING) return false;
            } else if (!seen.equals(kept)
                    && !(kept.phase == SlotPhase.CREATING && seen.phase == SlotPhase.LIVE)
                    && !(kept.phase == SlotPhase.LIVE && seen.phase == SlotPhase.RELEASING)) {
                return false;
            }
        }
        for (HeaderEntry entry : copy.entries) {
            if (headerEntry(selected, entry.appId) != null) continue;
            if (entry.phase != SlotPhase.CREATING || entry.creationId <= selected.lastId) return false;
            ahead = true;
        }
        return copy.lastId > selected.lastId ? ahead
                : copy.lastId < selected.lastId ? behind : true;
    }

    /**
     * A pure reservation: every selected entry unchanged and at least one new CREATING entry
     * above the selected counter. Only this shape advances the counter, and only it publishes
     * its own target as the preferred backup before main and reserve are removed. An exact
     * retry or confirmation adds nothing, and phase changes and omissions are never staged
     * early: they keep their prior as the backup until their final step. It keeps the selected
     * version, except that a format reserving a newer version may raise a version 1 selection
     * to it. keepsHeaderCopies requires a truly new bound entry for that.
     */
    private static boolean addsOnly(Header selected, Header next, Format format) {
        if ((next.version != selected.version && (selected.version >= format.reservationVersion
                || next.version != format.reservationVersion))
                || !next.lineage.equals(selected.lineage)
                || next.entries.size() <= selected.entries.size()) return false;
        for (HeaderEntry kept : selected.entries) {
            if (!kept.equals(headerEntry(next, kept.appId))) return false;
        }
        for (HeaderEntry entry : next.entries) {
            if (headerEntry(selected, entry.appId) == null && (entry.phase != SlotPhase.CREATING
                    || entry.creationId <= selected.lastId)) return false;
        }
        return true;
    }

    /**
     * Negative facts of every decodable header copy beside the selected valid header, shared by
     * the boot coverage test, reservation projection and every header writer. Pure: no I/O and
     * no writer format. Every copy must be compatible with the selection. An entry some copy
     * lists and the selection lacks is an unselected addition: a hold its exact owner must
     * restate, never positive history. Additions must be identical wherever they appear, and
     * no two may share a creation ID. Otherwise there are no facts, and every header write
     * refuses. The observed counter is the largest of the selection and every copy: only a
     * refusal bound, never restored, issued or derived as allocator state.
     */
    static final class HeaderCopies {
        /** Unselected additions by app ID, each the exact entry its copies list. */
        final Map<Integer, HeaderEntry> additions;
        /** Largest counter of the selection and every copy. A refusal bound only. */
        final long observedCounter;

        private HeaderCopies(Map<Integer, HeaderEntry> additions, long observedCounter) {
            this.additions = Map.copyOf(additions);
            this.observedCounter = observedCounter;
        }

        /** The facts of a valid read, or null when it is not valid or its copies disagree. */
        static HeaderCopies of(ReadResult<Header> read) {
            if (read.status != Status.VALID) return null;
            Header selected = read.value;
            HashMap<Integer, HeaderEntry> additions = new HashMap<>();
            HashMap<Long, Integer> additionIds = new HashMap<>();
            long observed = selected.lastId;
            for (Header copy : read.decodedCopies) {
                if (!compatible(selected, copy)) return null;
                observed = Math.max(observed, copy.lastId);
                for (HeaderEntry entry : copy.entries) {
                    if (headerEntry(selected, entry.appId) != null) continue;
                    HeaderEntry known = additions.putIfAbsent(entry.appId, entry);
                    Integer holder = additionIds.putIfAbsent(entry.creationId, entry.appId);
                    if ((known != null && !known.equals(entry))
                            || (holder != null && holder.intValue() != entry.appId)) return null;
                }
            }
            return new HeaderCopies(additions, observed);
        }
    }

    /**
     * The pure coverage test of a valid read: every copy is compatible, and the selection lists
     * every addition and counter. A copy that predates a protected reservation is covered, so
     * the selected counter, and only it, may be restored beside it. Takes no writer format.
     */
    static boolean selectionCovers(ReadResult<Header> read) {
        HeaderCopies copies = HeaderCopies.of(read);
        return copies != null && copies.additions.isEmpty()
                && copies.observedCounter == read.value.lastId;
    }

    /**
     * The historical identities of one view, by app ID. Pure: no I/O, no writer format and
     * nothing from any source but the view itself.
     *
     * A BODY exists exactly where bindingUsable holds, for the slot's one user, whatever its
     * lifecycle. That is the eligibility restoration has always used, and nothing stricter is
     * added: the history carries the lifecycle state and suspension entries for its readers.
     *
     * A RESERVATION exists only in a creation ready view whose header copies have
     * {@link HeaderCopies} facts, for a SELECTED CREATING entry with a complete creation binding
     * of user 0 whose slot is genuinely MISSING in this view. That says only that the selected
     * header alone supplies history here, not that no body ever existed. Every decoded header
     * copy must list exactly that
     * entry, or omit it as a predecessor whose counter is below the creation ID. A LIVE or
     * RELEASING copy withdraws it, even where that copy is compatible. No other app ID may claim
     * its package or principal ID: see claimed. A claim withdraws only the reservation; no body is
     * withdrawn or changed here. There is no fallback around a damaged, conflicting, unsupported,
     * unavailable, tombstone, alias or special body. Nothing comes from staging seeds, unselected
     * additions, entries without a binding, LIVE or RELEASING entries or a counter. The history
     * is the entry's own app ID, creation ID, package, user and serial, with the selected
     * binding's signer set.
     */
    private static Map<Integer, History> historiesOf(Loaded view) {
        TreeMap<Integer, History> result = new TreeMap<>();
        for (Map.Entry<Integer, ReadResult<Slot>> held : view.slots.entrySet()) {
            int appId = held.getKey();
            if (!view.bindingUsable(appId) || held.getValue().value.users.size() != 1) continue;
            Slot body = held.getValue().value;
            UserEntry user = body.users.get(0);
            result.put(appId, new History(body.lineage, appId, body.packageName, user.id,
                    user.userId, user.userSerial, body.signerSha256, user.lifecycle, Source.BODY));
        }
        if (!view.creationReady() || HeaderCopies.of(view.header) == null) {
            return Collections.unmodifiableMap(result);
        }
        Header selected = view.header.value;
        for (HeaderEntry creation : selected.entries) {
            NativeIdentityRecords.CreationBinding binding = creation.creationBinding;
            ReadResult<Slot> read = view.slots.get(creation.appId);
            if (creation.phase != SlotPhase.CREATING || binding == null
                    || binding.userId != USER_SYSTEM || result.containsKey(creation.appId)
                    || read == null || read.status != Status.MISSING || read.unavailable
                    || !corroborated(view.header, creation) || claimed(view, creation)) continue;
            result.put(creation.appId, new History(selected.lineage, creation.appId,
                    creation.creationPackage, creation.creationId, binding.userId,
                    binding.userSerial, binding.signerSha256,
                    NativeIdentityRecords.Lifecycle.version1(false), Source.RESERVATION));
        }
        return Collections.unmodifiableMap(result);
    }

    // Every decoded header copy lists exactly this selected creation, or omits it as a copy
    // written before its creation ID was issued. Any other copy, LIVE or RELEASING included,
    // withdraws it.
    private static boolean corroborated(ReadResult<Header> read, HeaderEntry creation) {
        for (Header seen : read.decodedCopies) {
            HeaderEntry listed = headerEntry(seen, creation.appId);
            if (listed == null ? seen.lastId >= creation.creationId : !listed.equals(creation)) {
                return false;
            }
        }
        return true;
    }

    // Whether another app ID claims this creation's package or principal ID: any decoded slot
    // copy there, whatever its status, a tombstone's ticket included, or a CREATING entry there in
    // any decoded header copy. A
    // claim is located by the slot's physical app ID or the entry's own, never by a body's own
    // app ID field. Claims are only negative: they withdraw a reservation and supply nothing.
    private static boolean claimed(Loaded view, HeaderEntry creation) {
        for (Map.Entry<Integer, ReadResult<Slot>> other : view.slots.entrySet()) {
            if (other.getKey().intValue() == creation.appId) continue;
            for (Slot claim : other.getValue().decodedCopies) {
                if (claim.packageName.equals(creation.creationPackage)) return true;
                if (claim.ticket != null && claim.ticket.lastId == creation.creationId) return true;
                for (UserEntry user : claim.users) {
                    if (user.id == creation.creationId) return true;
                }
            }
        }
        for (Header seen : view.header.decodedCopies) {
            for (HeaderEntry entry : seen.entries) {
                if (entry.appId != creation.appId && entry.phase == SlotPhase.CREATING
                        && (entry.creationId == creation.creationId
                        || entry.creationPackage.equals(creation.creationPackage))) return true;
            }
        }
        return false;
    }

    /**
     * Pure rule shared by every header writer, on a fresh read before its first effect, and by
     * reservation admission, on the cached view before an ID is issued. The read must have
     * {@link HeaderCopies} facts. Otherwise every header write refuses and nothing is merged.
     *
     * next must relate to the selection as a compatible copy would. It keeps the selected
     * counter, unless it is a pure reservation. It must restate each unselected addition
     * exactly (app ID, phase, creation ID, package and binding), and its counter must cover
     * every copy's. A new CREATING entry at or below that largest observed counter must be a
     * known addition, not a new identity in that range. The observed counter is only a refusal
     * constraint: nothing restores, issues or derives state from it. Only the exact original
     * reservation, whose own counter and full pin snapshot already cover its writes, meets this
     * beside an addition.
     *
     * The writer format adds version rules. next never exceeds the format's readable ceiling
     * or falls below the selected version. A new entry that restates no known addition is
     * truly new. Under a format that reserves version 2 it needs a complete creation binding
     * in a version 2 header; an incomplete version 2 entry is only ever an exact restatement.
     * A version 1 selection becomes version 2 only through a pure reservation with a truly new
     * bound entry, never through restatements alone.
     */
    static boolean keepsHeaderCopies(ReadResult<Header> read, Header next, Format format) {
        Objects.requireNonNull(format, "format");
        HeaderCopies copies = HeaderCopies.of(read);
        if (copies == null) return false;
        Header selected = read.value;
        if (next.version > format.headerCeiling || next.version < selected.version
                || !related(selected, next) || next.lastId < copies.observedCounter
                || (next.lastId != selected.lastId && !addsOnly(selected, next, format))) return false;
        for (HeaderEntry addition : copies.additions.values()) {
            if (!addition.equals(headerEntry(next, addition.appId))) return false;
        }
        boolean newlyBound = false;
        for (HeaderEntry entry : next.entries) {
            if (headerEntry(selected, entry.appId) != null
                    || entry.equals(copies.additions.get(entry.appId))) continue;
            if (entry.creationId <= copies.observedCounter) return false;
            if (format.reservationVersion > HEADER_V1 && (next.version != format.reservationVersion
                    || entry.creationBinding == null)) return false;
            if (entry.creationBinding != null) newlyBound = true;
        }
        return next.version == selected.version || newlyBound;
    }

    /**
     * The checked header writer. Under a format that writes version 2 slots it turns no entry
     * RELEASING and omits none: those are the release engine's header writes, which only
     * markSlotReleasing and omitReleasedSlot make. Under the earlier formats the version 1 release
     * still makes them here.
     */
    boolean writeHeader(Header expected, Header next) {
        Objects.requireNonNull(expected); Objects.requireNonNull(next);
        if (format.slotCeiling >= LIFECYCLE_SLOT_VERSION && releases(expected, next)) return false;
        return writeAnyHeader(expected, next);
    }

    // Every header write, the release engine's RELEASING and omission writes included. Their phase
    // and omission rules are validHeaderTransition's.
    private boolean writeAnyHeader(Header expected, Header next) {
        if (expected.version > format.headerCeiling || next.version > format.headerCeiling
                || next.version < expected.version
                || !expected.lineage.equals(next.lineage) || next.lastId < expected.lastId
                || writeInspectionBlocked()) return false;
        ReadResult<Header> read = safeReadHeader();
        // Before the transition checks, which can confirm slots and sync. This also
        // refuses a counter advance without a pure reservation, and a version change
        // without a truly new bound entry.
        if (read.status != Status.VALID || !(read.value.equals(expected) || read.value.equals(next))
                || !keepsHeaderCopies(read, next, format)) {
            return false;
        }
        if (!read.value.equals(next) && !validHeaderTransition(expected, next)) return false;
        // An exact uncertain retry is rewritten through real checked writers;
        // matching readback alone never turns it into a durable acknowledgement.
        // Only a validated pure reservation against the fresh selection protects
        // its own target; see writeStrict.
        return writeStrict(headerFile(), NativeIdentityRecords.encodeHeader(next),
                NativeIdentityRecords.encodeHeader(read.value), addsOnly(read.value, next, format), true);
    }

    boolean ensureFreshSlot(Header expected, int appId) {
        HeaderEntry entry = headerEntry(expected, appId);
        if (entry == null || entry.phase != SlotPhase.CREATING || writeInspectionBlocked(appId)
                || !confirmHeader(expected)) return false;
        File directory = slotDirectory(appId);
        // A retry reconciles, never adopts an unknown mkdir. Unknown presence is not absence.
        if (!absent(directory)) return false;
        try {
            if (!directory.mkdir()) return false;
            protectDirectory(directory);
            syncDirectory(directory);
            syncDirectory(slotRoot);
            return true;
        } catch (IOException | RuntimeException error) { return false; }
    }

    /**
     * Continue the caller's exact owned creation transaction. This confirms only
     * a private storage layout; it grants no identity and is not a process or
     * directory-inode lease. Unknown files/aliases and conflicting bodies refuse.
     */
    boolean resumeCreatingDirectory(Header expected, int appId) {
        HeaderEntry entry = headerEntry(expected, appId);
        if (entry == null || entry.phase != SlotPhase.CREATING || writeInspectionBlocked(appId)
                || !confirmHeader(expected)) return false;
        File dir = slotDirectory(appId);
        Node node = node(dir);
        if (node == Node.ABSENT) return ensureFreshSlot(expected, appId);
        if (node != Node.DIRECTORY) return false;
        File[] files = dir.listFiles();
        if (files == null) return false;
        Set<String> allowed = Set.of("record.bin", "record.bin-backup", "record.bin.reservecopy",
                "record.bin-seed");
        for (File file : files) {
            if (!allowed.contains(file.getName()) || node(file) != Node.FILE) return false;
        }
        ReadResult<Slot> read = readSlotCopies(appId);
        if (read.status != Status.MISSING && read.status != Status.VALID) return false;
        for (Slot copy : read.decodedCopies) {
            if (!matchesCreation(copy, expected, entry)) return false;
        }
        Copy seed = observe(seed(slotFile(appId)));
        // Only parser damage is owned staging. Unreadable bytes may be newer.
        if (seed.found == Found.UNAVAILABLE) return false;
        if (seed.bytes != null) {
            try {
                if (!matchesCreation(NativeIdentityRecords.decodeSlot(seed.bytes), expected,
                        entry)) return false;
            } catch (IllegalArgumentException error) {
                // A torn unpublished seed may be overwritten by this same
                // owned creation, not adopted as positive binding metadata.
                // An intact unsupported seed never reaches here: the gate refused.
            }
        }
        try { syncDirectory(dir); syncDirectory(slotRoot); return true; }
        catch (IOException error) { return false; }
    }

    private static boolean matchesCreation(Slot slot, Header header, HeaderEntry entry) {
        return slot.appId == entry.appId && slot.lineage.equals(header.lineage)
                && slot.packageName.equals(entry.creationPackage) && slot.users.size() == 1
                && slot.users.get(0).id == entry.creationId && bindingHolds(entry, slot);
    }

    /**
     * Negative only. A CREATING entry with a complete creation binding admits a body with
     * exactly one user, of the entry's creation ID, the binding's user and serial, and exactly
     * its signer set. The retiring flag may be either. An entry without a binding admits any
     * body here, and keeps the checks it always had. Nothing is filled in or relaxed.
     */
    private static boolean bindingHolds(HeaderEntry entry, Slot slot) {
        NativeIdentityRecords.CreationBinding binding = entry.creationBinding;
        if (binding == null) return true;
        if (slot.users.size() != 1 || !slot.signerSha256.equals(binding.signerSha256)) return false;
        UserEntry user = slot.users.get(0);
        return user.id == entry.creationId && user.userId == binding.userId
                && user.userSerial == binding.userSerial;
    }

    /**
     * The release engine's RELEASING write: this LIVE entry becomes RELEASING, with the same
     * version, counter and every other entry. Its slot must already be the engine's ticketed
     * tombstone, which validHeaderTransition requires under this format. It refuses before any
     * effect under a format whose slot ceiling is 1, where the version 1 release writes the phase
     * through the generic header writer.
     */
    boolean markSlotReleasing(Header expected, int appId) {
        Objects.requireNonNull(expected);
        HeaderEntry entry = headerEntry(expected, appId);
        if (format.slotCeiling < LIFECYCLE_SLOT_VERSION || entry == null
                || entry.phase != SlotPhase.LIVE) return false;
        return writeAnyHeader(expected, phased(expected, appId, SlotPhase.RELEASING));
    }

    /**
     * The release engine's omission: this RELEASING entry is dropped, with the same version,
     * counter and every other entry, once its directory is genuinely absent. It refuses before any
     * effect under a format whose slot ceiling is 1, where the version 1 release omits the entry
     * through the generic header writer.
     */
    boolean omitReleasedSlot(Header expected, int appId) {
        Objects.requireNonNull(expected);
        HeaderEntry entry = headerEntry(expected, appId);
        if (format.slotCeiling < LIFECYCLE_SLOT_VERSION || entry == null
                || entry.phase != SlotPhase.RELEASING) return false;
        return writeAnyHeader(expected, omitted(expected, appId));
    }

    // Whether next turns an entry of previous RELEASING or omits one: the release engine's header
    // writes.
    private static boolean releases(Header previous, Header next) {
        for (HeaderEntry old : previous.entries) {
            HeaderEntry changed = headerEntry(next, old.appId);
            if (changed == null || (changed.phase == SlotPhase.RELEASING
                    && old.phase != SlotPhase.RELEASING)) return true;
        }
        return false;
    }

    // This entry in another phase, with the header's own version, lineage, counter and every other
    // entry. A phase change never converts a version.
    private static Header phased(Header header, int appId, SlotPhase phase) {
        List<HeaderEntry> entries = new ArrayList<>(header.entries.size());
        for (HeaderEntry entry : header.entries) {
            entries.add(entry.appId == appId ? new HeaderEntry(appId, phase, 0, "") : entry);
        }
        return sameVersion(header, entries);
    }

    // The header without this entry, with its own version, lineage and counter.
    private static Header omitted(Header header, int appId) {
        List<HeaderEntry> entries = new ArrayList<>(header.entries.size());
        for (HeaderEntry entry : header.entries) if (entry.appId != appId) entries.add(entry);
        return sameVersion(header, entries);
    }

    private static Header sameVersion(Header header, List<HeaderEntry> entries) {
        if (header.version == HEADER_V1) return new Header(header.lineage, header.lastId, entries);
        if (header.version == HEADER_V2) return Header.newV2(header.lineage, header.lastId, entries);
        throw new IllegalStateException("header version without a writer");
    }

    /** Exact retirement reconciliation only, never a general absence-is-free test. */
    boolean confirmReleasedSlot(Header expected, int appId) {
        if (headerEntry(expected, appId) != null || !absent(slotDirectory(appId))
                || writeInspectionBlocked(appId) || !confirmHeader(expected)) return false;
        try { syncDirectory(slotRoot); return true; }
        catch (IOException error) { return false; }
    }

    boolean publishCreatingSlot(Header expectedHeader, Slot next) {
        Objects.requireNonNull(next);
        Objects.requireNonNull(expectedHeader);
        // Before the header confirmation, which writes: no slot above the ceiling is written.
        if (next.version > format.slotCeiling) return false;
        HeaderEntry index = headerEntry(expectedHeader, next.appId);
        if (writeInspectionBlocked(next.appId) || !confirmHeader(expectedHeader) || index == null
                || !directory(slotDirectory(next.appId))
                || !expectedHeader.lineage.equals(next.lineage)) return false;
        for (UserEntry user : next.users) if (user.id > expectedHeader.lastId) return false;
        if (index.phase == SlotPhase.RELEASING && !next.users.isEmpty()) return false;
        File main = slotFile(next.appId);
        ReadResult<Slot> read = readSlotCopies(next.appId);
        if (index.phase != SlotPhase.CREATING || next.users.size() != 1
                || next.users.get(0).id != index.creationId
                || !next.packageName.equals(index.creationPackage)
                || next.generation != 1 || !bindingHolds(index, next)) return false;
        if (read.status != Status.MISSING && !(read.status == Status.VALID
                && read.value.equals(next))) return false;
        try {
            syncDirectory(slotDirectory(next.appId));
            syncDirectory(slotRoot);
        } catch (IOException error) { return false; }
        return writeStrict(main, NativeIdentityRecords.encodeSlot(next),
                read.value == null ? null : NativeIdentityRecords.encodeSlot(read.value), false, false);
    }

    /**
     * Existing binding mutation only: no counter reconstruction or new identity issuance. A slot
     * of a version above this format's ceiling is refused before anything else. Under a format
     * that writes version 2 slots it changes no lifecycle and drops no user: only the named
     * transitions change a lifecycle, and only the release engine will drop a user. Under the
     * earlier formats version 1's rule stays: retirement is irreversible for every user that
     * remains, and only a retiring user may be dropped.
     */
    boolean updateExistingSlot(Slot expected, Slot next) {
        Objects.requireNonNull(expected); Objects.requireNonNull(next);
        return writeExistingSlot(expected, next, false, false);
    }

    /**
     * The release engine's user drop, its only one: the expected slot's one account, of principal
     * ID id, leaves the slot, which becomes its tombstone at the next generation with this release
     * ticket. The account must be RETIRED with a known inventory, every obligation discharged and
     * no suspension entry, the ticket must name its principal ID, user and serial, and the selected
     * valid header must list the app ID LIVE: a CREATING entry completes to LIVE first, or the
     * tombstone would strand. Otherwise it refuses before any effect, and so it does beside any
     * store footprint, when expected is not the fresh durable value and under a format whose slot
     * ceiling is 1.
     */
    boolean dropReleasedUser(Slot expected, long id, ReleaseTicket ticket) {
        Objects.requireNonNull(expected); Objects.requireNonNull(ticket);
        UserEntry user = user(expected, id);
        if (format.slotCeiling < LIFECYCLE_SLOT_VERSION || user == null || expected.users.size() != 1
                || !releasable(user.lifecycle) || ticket.lastId != user.id
                || ticket.userId != user.userId || ticket.userSerial != user.userSerial
                || expected.generation == Long.MAX_VALUE) return false;
        return writeExistingSlot(expected, new Slot(expected.lineage, expected.appId,
                expected.packageName, expected.generation + 1, expected.signerSha256, List.of(),
                ticket), false, true);
    }

    /**
     * Whether release may drop this account: RETIRED with a known inventory, every obligation
     * DISCHARGED and no suspension entry. A kind orphaned with its Android user blocks it until
     * stage C defines its discharge.
     */
    static boolean releasable(Lifecycle lifecycle) {
        if (lifecycle.state != LifecycleState.RETIRED || !lifecycle.suspensions.isEmpty()
                || lifecycle.retirement == null || lifecycle.retirement.obligations.isEmpty()) return false;
        for (Obligation duty : lifecycle.retirement.obligations) {
            if (duty.state != ObligationState.DISCHARGED) return false;
        }
        return true;
    }

    // The checked writer of an existing slot, shared by the generic update, the named transitions
    // and the release engine's drop. A transition passes true for the one lifecycle its own rule
    // computed; the generic update passes false. Only dropReleasedUser passes drop.
    private boolean writeExistingSlot(Slot expected, Slot next, boolean transition, boolean drop) {
        if (expected.version > format.slotCeiling || next.version > format.slotCeiling) return false;
        if (writeInspectionBlocked(next.appId)) return false;
        Loaded loaded = load();
        ReadResult<Slot> read = loaded.slots.get(next.appId);
        if (!loaded.enumerationComplete || loaded.unsupportedFootprint || loaded.unavailableFootprint
                || loaded.header.status == Status.UNSUPPORTED
                || read == null || read.status != Status.VALID) return false;
        HeaderEntry index = loaded.header.value == null ? null : headerEntry(loaded.header.value, next.appId);
        if (index != null && index.phase == SlotPhase.RELEASING && !next.users.isEmpty()) return false;
        if (drop && (loaded.header.status != Status.VALID || index == null
                || index.phase != SlotPhase.LIVE)) return false;
        for (Header copy : loaded.header.decodedCopies) {
            HeaderEntry known = headerEntry(copy, next.appId);
            if (known != null && known.phase == SlotPhase.CREATING
                    && next.users.size() < expected.users.size()) return false;
        }
        if (expected.users.isEmpty() && !next.users.isEmpty()) return false;
        if (expected.appId != next.appId || !expected.lineage.equals(next.lineage)
                || !expected.packageName.equals(next.packageName)
                || !expected.signerSha256.equals(next.signerSha256)
                || expected.generation == Long.MAX_VALUE
                || next.generation != expected.generation + 1
                || read.status != Status.VALID
                || !(read.value.equals(expected) || read.value.equals(next))) return false;
        if (format.slotCeiling < LIFECYCLE_SLOT_VERSION) {
            // Retirement is irreversible for every entry that remains present.
            for (UserEntry prior : expected.users) {
                boolean retained = false;
                for (UserEntry current : next.users) {
                    if (prior.userId != current.userId) continue;
                    retained = true;
                    if (prior.id != current.id || prior.userSerial != current.userSerial
                            || (prior.retiring && !current.retiring)) return false;
                }
                if (!retained && !prior.retiring) return false;
            }
        } else if (!lifecyclesKept(expected, next, transition, drop)) {
            return false;
        }
        // User additions need their own durable issuance proof. The first
        // platform adapter supports only the original user 0 binding.
        for (UserEntry added : next.users) {
            boolean found = false;
            for (UserEntry old : expected.users) {
                if (old.id == added.id && old.userId == added.userId) found = true;
            }
            if (!found) return false;
        }
        return writeStrict(slotFile(next.appId), NativeIdentityRecords.encodeSlot(next),
                NativeIdentityRecords.encodeSlot(read.value), false, false);
    }

    // The store transitions between two values of one slot under a format that writes lifecycle
    // records. Every user keeps its identity: its principal ID, Android user and serial. A
    // tombstone keeps its release ticket, which only the release engine writes. The generic update
    // keeps every lifecycle, and a named transition changes at most the one lifecycle its rule
    // computed. Only the release engine's drop turns the one releasable account into its ticketed
    // tombstone.
    private static boolean lifecyclesKept(Slot expected, Slot next, boolean transition, boolean drop) {
        if (drop) {
            return expected.users.size() == 1 && expected.ticket == null && next.users.isEmpty()
                    && next.ticket != null && releasable(expected.users.get(0).lifecycle);
        }
        if (!Objects.equals(expected.ticket, next.ticket)) return false;
        int changed = 0;
        for (UserEntry prior : expected.users) {
            UserEntry current = user(next, prior.id);
            // No user leaves: only the release engine's drop does, RETIRED with every
            // obligation discharged and no suspension entry.
            if (current == null) return false;
            if (current.userId != prior.userId
                    || current.userSerial != prior.userSerial) return false;
            if (!current.lifecycle.equals(prior.lifecycle)) ++changed;
        }
        return changed <= (transition ? 1 : 0);
    }

    /**
     * The suspend transition: adds this entry to the account of principal ID id in the expected
     * slot and changes nothing else. It is the only transition that adds an entry of the account's
     * user or of a grant, and any lifecycle state may hold entries. A recovery hold comes only
     * from {@link #restoreSlot}, the recovery route's writer. The entry must pass {@link #writableSuspension} for
     * that account, whose record holds no entry of the same actor and has a free place for the
     * entry's actor class: see {@link #placeFree}.
     * Otherwise it refuses before any effect, and so it does beside any store footprint, when
     * expected is not the fresh durable value, and under a format whose slot ceiling is 1.
     */
    boolean addSuspension(Slot expected, long id, Suspension entry) {
        Objects.requireNonNull(expected); Objects.requireNonNull(entry);
        UserEntry user = user(expected, id);
        return user != null && writeLifecycle(expected, user, suspended(user, entry));
    }

    /**
     * The lift transition: removes exactly this entry, equal in every field, from the account of
     * principal ID id and changes nothing else. It is the only primitive that removes a
     * suspension entry. A recovery hold has no lift path in this stage. Lifting the last entry of
     * an eligible account leaves a value that version 1 expresses, which is written as version 1.
     * Refuses as {@link #addSuspension} does.
     */
    boolean liftSuspension(Slot expected, long id, Suspension entry) {
        Objects.requireNonNull(expected); Objects.requireNonNull(entry);
        UserEntry user = user(expected, id);
        return user != null && writeLifecycle(expected, user, lifted(user, entry));
    }

    /**
     * The retire transition: an ELIGIBLE account of principal ID id becomes RETIRING with this
     * retirement block, which must pass {@link #writableRetirement}, and keeps every suspension
     * entry. A legacy marker's block is never written over an eligible account: it passes only as
     * the inventory rule, over a RETIRING legacy marker whose inventory is unknown, which then
     * continues to every kind outstanding with its class, actor, grant and time unchanged. Every
     * other block, state or account refuses as {@link #addSuspension} does.
     */
    boolean markSlotRetiring(Slot expected, long id, Retirement retirement) {
        Objects.requireNonNull(expected); Objects.requireNonNull(retirement);
        UserEntry user = user(expected, id);
        return user != null && writeLifecycle(expected, user, retiring(user, retirement));
    }

    /**
     * Confirms retired: a RETIRING account of principal ID id with a known inventory becomes
     * RETIRED, each retirement kind discharged by its receipt, which must pass
     * {@link #writableReceipts}. Only OUTSTANDING becomes DISCHARGED here. A discharged kind stays
     * exactly as it is, and a bound reference is never bound again. The retirement block's class,
     * actor, grant and time, every disposition kind and every suspension entry stay. It releases
     * nothing. Every other account refuses as {@link #addSuspension} does.
     */
    boolean markSlotRetired(Slot expected, long id, List<Obligation> receipts) {
        Objects.requireNonNull(expected);
        List<Obligation> copy = List.copyOf(Objects.requireNonNull(receipts));
        UserEntry user = user(expected, id);
        return user != null && writeLifecycle(expected, user, retired(user, copy));
    }

    /**
     * The deletion or migration step: a RETIRED account of principal ID id, with a known inventory,
     * has every disposition kind moved from OUTSTANDING to DISPOSING at once, before anything is
     * deleted. Each kind keeps its reference, code and time, and every retirement kind, the block's
     * class, actor, grant and time and every suspension entry stay. It refuses while any suspension
     * entry with scope bit 0 exists, and beside any disposition kind that is not OUTSTANDING: a kind
     * orphaned with its Android user belongs to stage C, and a deletion that began never begins
     * again. Every other account refuses as {@link #addSuspension} does. The retired boot rule is
     * the caller's, because the store holds no boot facts.
     */
    boolean beginSlotDisposition(Slot expected, long id) {
        Objects.requireNonNull(expected);
        UserEntry user = user(expected, id);
        return user != null && writeLifecycle(expected, user, disposing(user));
    }

    /**
     * Confirms disposal: in a RETIRED account of principal ID id, each disposition kind that a
     * receipt names moves from DISPOSING to DISCHARGED, on its owner's observed evidence. The
     * receipts must pass {@link #writableDispositionReceipts}. A discharged kind stays exactly as it
     * is, and a bound reference is never bound again. An OUTSTANDING kind waits for the deletion or
     * migration step, and a kind orphaned with its Android user for stage C. Everything else stays.
     * Every other account refuses as {@link #addSuspension} does.
     */
    boolean dischargeSlotDisposition(Slot expected, long id, List<Obligation> receipts) {
        Objects.requireNonNull(expected);
        List<Obligation> copy = List.copyOf(Objects.requireNonNull(receipts));
        UserEntry user = user(expected, id);
        return user != null && writeLifecycle(expected, user, dispositionDischarged(user, copy));
    }

    /**
     * Restore, the independent recovery route's writer and the only writer of a recovery hold. It
     * writes the last known state of one account, held, into the account's existing slot directory
     * and changes nothing else. The header entry stays as found.
     *
     * <p>account names the account: it is the value publication creates for it, generation 1 and
     * ELIGIBLE with no entry, with the lineage, app ID, package, signers and one user's principal
     * ID, Android user and serial. hold is the recovery hold to place, with scope 0. The last
     * known state is the intact copy with the highest generation among the slot's main, reserve
     * and backup, never an earlier one: see {@link #restoration}. The value written is that copy
     * at the next generation with the hold added, every other field and entry kept. If no copy is
     * intact, the state cannot be established, and the value written is the account at ELIGIBLE,
     * generation 1, with the hold and scope bit 1, which tells whoever lifts the hold that the
     * account may have been retired. A staging seed is never a copy. When the selected value is
     * already that last known state and holds a recovery hold, the restore is durable and is
     * confirmed through checked writers instead.
     *
     * <p>It needs the selected valid header of the account's lineage, whose counter covers the
     * principal ID, with a LIVE entry for the app ID or the account's own CREATING entry, the slot
     * directory and at least one present copy. It refuses before any effect beside any store
     * footprint, under a RELEASING entry or beside a header copy that lists the app ID RELEASING,
     * beside a copy of another lineage, account or package or a tombstone, beside two different
     * intact copies of the highest generation, when the account has no free place for a recovery
     * hold, at the last generation and under a format whose slot ceiling is 1, because a recovery
     * hold needs version 2. Unlike every other slot writer it
     * replaces a damaged or older preferred backup, after the last known state was chosen from
     * every intact copy, so it also restores a record that no checked writer can write.
     */
    boolean restoreSlot(Header expected, Slot account, Suspension hold) {
        Objects.requireNonNull(expected); Objects.requireNonNull(account); Objects.requireNonNull(hold);
        if (format.slotCeiling < LIFECYCLE_SLOT_VERSION) return false;
        if (writeInspectionBlocked(account.appId)) return false;
        Loaded loaded = load();
        ReadResult<Slot> read = loaded.slots.get(account.appId);
        if (!loaded.enumerationComplete || loaded.unsupportedFootprint || loaded.unavailableFootprint
                || loaded.header.status != Status.VALID || !loaded.header.value.equals(expected)
                || read == null || read.status == Status.MISSING || read.unavailable
                || !directory(slotDirectory(account.appId))) return false;
        HeaderEntry index = headerEntry(expected, account.appId);
        // Nor beside any decoded header copy that lists it RELEASING, as an interrupted release's
        // phase change leaves one: the record would read as a conflict.
        for (Header copy : loaded.header.decodedCopies) {
            HeaderEntry listed = headerEntry(copy, account.appId);
            if (listed != null && listed.phase == SlotPhase.RELEASING) return false;
        }
        // The header stays as found, and a releasing entry never regains a user.
        if (index == null || index.phase == SlotPhase.RELEASING
                || (index.phase == SlotPhase.CREATING && !matchesCreation(account, expected, index))
                || !expected.lineage.equals(account.lineage) || account.users.size() != 1
                || account.users.get(0).id > expected.lastId) return false;
        Slot next = restoration(read.decodedCopies, account, hold);
        if (next == null || next.version > format.slotCeiling) return false;
        // Its exact retry: the last known state is selected and already held.
        if (read.status == Status.VALID && read.value.generation + 1 == next.generation
                && recoveryHeld(read.value) && next.equals(advanced(read.value))) {
            return confirmExistingSlot(read.value);
        }
        return writeStrict(slotFile(account.appId), NativeIdentityRecords.encodeSlot(next), null, true,
                false, true);
    }

    /**
     * The value Restore writes over these decoded copies of one slot, or null when Restore refuses.
     * Pure. Every copy must be the account's: its lineage, app ID, package, signers and one user's
     * principal ID, Android user and serial, so Restore never writes over another account, a
     * foreign lineage or a tombstone. The copy with the highest generation is the last known state,
     * and two different copies of that generation leave it unestablished, which refuses, rather
     * than choose between them. With no copy, the state cannot be established: the account at
     * ELIGIBLE, generation 1, held with scope bit 1. Otherwise the last known state at the next
     * generation, its state, block and entries kept, with the hold added unless a recovery hold is
     * already there, as writers allot it a place: see {@link #placeFree}. The hold must pass
     * {@link #writableRecoveryHold}, and bit 1 is the writer's own, set exactly when the state
     * cannot be established.
     */
    static Slot restoration(List<Slot> copies, Slot account, Suspension hold) {
        if (!writableRecoveryHold(hold) || account.generation != 1 || account.users.size() != 1
                || !account.users.get(0).lifecycle.equals(Lifecycle.version1(false))) return null;
        UserEntry identity = account.users.get(0);
        Slot last = null;
        for (Slot copy : copies) {
            if (!sameAccount(copy, account)) return null;
            if (last == null || copy.generation > last.generation) last = copy;
        }
        if (last == null) {
            Suspension unknown = new Suspension(ActorClass.RECOVERY_HOLD,
                    NativeIdentityRecords.SCOPE_PRIOR_UNKNOWN, hold.actorUserId, hold.actorSerial,
                    hold.grant, hold.reason, hold.time, hold.noteDigest);
            return new Slot(account.lineage, account.appId, account.packageName, 1,
                    account.signerSha256, List.of(new UserEntry(identity.id, identity.userId,
                    identity.userSerial, new Lifecycle(LifecycleState.ELIGIBLE, List.of(unknown), null))));
        }
        for (Slot copy : copies) {
            if (copy.generation == last.generation && !copy.equals(last)) return null;
        }
        if (last.generation == Long.MAX_VALUE) return null;
        if (recoveryHeld(last)) return advanced(last);
        Lifecycle prior = last.users.get(0).lifecycle;
        if (!placeFree(prior, ActorClass.RECOVERY_HOLD)) return null;
        List<Suspension> entries = new ArrayList<>(prior.suspensions);
        entries.add(hold);
        entries.sort(NativeIdentityRecords::order);
        UserEntry user = last.users.get(0);
        return new Slot(last.lineage, last.appId, last.packageName, last.generation + 1,
                last.signerSha256, List.of(new UserEntry(user.id, user.userId, user.userSerial,
                new Lifecycle(prior.state, entries, prior.retirement))));
    }

    // Whether this copy is the named account's: every identity field, whatever its generation,
    // lifecycle or entries. A tombstone or a slot of two users never is.
    private static boolean sameAccount(Slot copy, Slot account) {
        if (!copy.lineage.equals(account.lineage) || copy.appId != account.appId
                || !copy.packageName.equals(account.packageName)
                || !copy.signerSha256.equals(account.signerSha256) || copy.users.size() != 1) return false;
        UserEntry user = copy.users.get(0), identity = account.users.get(0);
        return user.id == identity.id && user.userId == identity.userId
                && user.userSerial == identity.userSerial;
    }

    // Whether the one account of this slot holds a recovery hold.
    private static boolean recoveryHeld(Slot slot) {
        for (Suspension entry : slot.users.get(0).lifecycle.suspensions) {
            if (entry.actorClass == ActorClass.RECOVERY_HOLD) return true;
        }
        return false;
    }

    // The same value at the next generation.
    private static Slot advanced(Slot slot) {
        return new Slot(slot.lineage, slot.appId, slot.packageName, slot.generation + 1,
                slot.signerSha256, slot.users, slot.ticket);
    }

    // One account's lifecycle becomes next in its slot's next generation, through the checked
    // writer of an existing slot. The lineage, app ID, package, signers, every other user and
    // every identity stay.
    private boolean writeLifecycle(Slot expected, UserEntry user, Lifecycle next) {
        if (next == null || expected.generation == Long.MAX_VALUE) return false;
        List<UserEntry> users = new ArrayList<>(expected.users.size());
        for (UserEntry each : expected.users) {
            users.add(each != user ? each
                    : new UserEntry(each.id, each.userId, each.userSerial, next));
        }
        return writeExistingSlot(expected, new Slot(expected.lineage, expected.appId,
                expected.packageName, expected.generation + 1, expected.signerSha256, users), true, false);
    }

    private static UserEntry user(Slot slot, long id) {
        for (UserEntry user : slot.users) if (user.id == id) return user;
        return null;
    }

    // The pure rules of the named transitions. Each returns the lifecycle its transition makes of
    // this user's, or null when the store's rules refuse it. None touches another user.

    private static Lifecycle suspended(UserEntry user, Suspension entry) {
        Lifecycle prior = user.lifecycle;
        if (!writableSuspension(user.userId, user.userSerial, entry)) return null;
        // A fifth grant, or a seventh actor, waits for a free place.
        if (!placeFree(prior, entry.actorClass)) return null;
        // One entry per actor. Its repeated suspension is a confirmation, never a second entry.
        for (Suspension held : prior.suspensions) {
            if (sameActor(held, entry)) return null;
        }
        List<Suspension> entries = new ArrayList<>(prior.suspensions);
        entries.add(entry);
        entries.sort(NativeIdentityRecords::order);
        return new Lifecycle(prior.state, entries, prior.retirement);
    }

    private static Lifecycle lifted(UserEntry user, Suspension entry) {
        Lifecycle prior = user.lifecycle;
        // In this stage a recovery hold has no lift path.
        if (entry.actorClass == ActorClass.RECOVERY_HOLD) return null;
        // Only the exact entry its actor placed.
        if (!prior.suspensions.contains(entry)) return null;
        List<Suspension> entries = new ArrayList<>(prior.suspensions);
        entries.remove(entry);
        return new Lifecycle(prior.state, entries, prior.retirement);
    }

    private static Lifecycle retiring(UserEntry user, Retirement retirement) {
        Lifecycle prior = user.lifecycle;
        if (!writableRetirement(user.userId, user.userSerial, retirement)) return null;
        if (retirement.actorClass == ActorClass.LEGACY_MARKER) {
            // The inventory rule, the one change of a written block: a RETIRING legacy marker's
            // unknown inventory, which only a legacy marker has, continues to every kind
            // outstanding, once. Its class, actor, grant and time stay, all zero. No writer
            // creates a legacy marker.
            if (prior.state != LifecycleState.RETIRING) return null;
            if (!prior.retirement.obligations.isEmpty()) return null;
        } else if (prior.state != LifecycleState.ELIGIBLE) {
            // The state only moves forward, and a written block never changes.
            return null;
        }
        return new Lifecycle(LifecycleState.RETIRING, prior.suspensions, retirement);
    }

    private static Lifecycle retired(UserEntry user, List<Obligation> receipts) {
        Lifecycle prior = user.lifecycle;
        if (!writableReceipts(receipts) || prior.state != LifecycleState.RETIRING) return null;
        Retirement held = prior.retirement;
        // RETIRED needs a known inventory: a legacy marker continues first.
        if (held.obligations.isEmpty()) return null;
        List<Obligation> obligations = new ArrayList<>(held.obligations);
        for (Obligation receipt : receipts) {
            // A known inventory lists every kind once, in kind order.
            int index = receipt.kind.code - 1;
            Obligation duty = obligations.get(index);
            // A discharged kind stays exactly as it is.
            if (duty.state == ObligationState.DISCHARGED) {
                if (!duty.equals(receipt)) return null;
                continue;
            }
            // Only OUTSTANDING becomes DISCHARGED here. A kind orphaned with its Android user
            // waits for stage C.
            if (duty.state != ObligationState.OUTSTANDING) return null;
            // A reference is bound once: an unbound one may be bound now, a bound one never
            // changes, to zero or to another reference.
            if (!duty.reference.equals(NativeIdentityRecords.NO_REFERENCE)
                    && !duty.reference.equals(receipt.reference)) return null;
            obligations.set(index, receipt);
        }
        return new Lifecycle(LifecycleState.RETIRED, prior.suspensions, new Retirement(
                held.actorClass, held.actorUserId, held.actorSerial, held.grant, held.time,
                obligations));
    }

    private static Lifecycle disposing(UserEntry user) {
        Lifecycle prior = user.lifecycle;
        if (prior.state != LifecycleState.RETIRED) return null;
        // No writer sets scope bit 0 yet, but a later writer's entry blocks deletion and migration.
        if (dispositionBlocked(prior)) return null;
        Retirement held = prior.retirement;
        // Disposition needs a known inventory. The decoder already refuses RETIRED without one.
        if (held.obligations.size() != ObligationKind.values().length) return null;
        List<Obligation> obligations = new ArrayList<>(held.obligations);
        for (int index = 0; index < obligations.size(); ++index) {
            Obligation duty = obligations.get(index);
            if (!duty.kind.disposition()) continue;
            // Every disposition kind at once, and only from OUTSTANDING.
            boolean outstanding = duty.state == ObligationState.OUTSTANDING;
            if (!outstanding) return null;
            obligations.set(index, new Obligation(duty.kind, ObligationState.DISPOSING,
                    duty.reference, duty.code, duty.time));
        }
        return obligationsMoved(prior, obligations);
    }

    private static Lifecycle dispositionDischarged(UserEntry user, List<Obligation> receipts) {
        Lifecycle prior = user.lifecycle;
        if (!writableDispositionReceipts(receipts) || prior.state != LifecycleState.RETIRED) {
            return null;
        }
        Retirement held = prior.retirement;
        if (held.obligations.size() != ObligationKind.values().length) return null;
        List<Obligation> obligations = new ArrayList<>(held.obligations);
        for (Obligation receipt : receipts) {
            int index = receipt.kind.code - 1;
            Obligation duty = obligations.get(index);
            // A discharged kind stays exactly as it is.
            if (duty.state == ObligationState.DISCHARGED) {
                if (duty.equals(receipt)) continue;
                return null;
            }
            // Only DISPOSING becomes DISCHARGED here. An outstanding kind waits for the deletion or
            // migration step, and a kind orphaned with its Android user for stage C.
            if (duty.state != ObligationState.DISPOSING) return null;
            // A reference is bound once: an unbound one may be bound now, a bound one never
            // changes, to zero or to another reference.
            boolean bound = !duty.reference.equals(NativeIdentityRecords.NO_REFERENCE);
            if (bound && !duty.reference.equals(receipt.reference)) return null;
            obligations.set(index, receipt);
        }
        return obligationsMoved(prior, obligations);
    }

    // The same RETIRED lifecycle with these obligations. The block's class, actor, grant and time
    // and every suspension entry stay.
    private static Lifecycle obligationsMoved(Lifecycle prior, List<Obligation> obligations) {
        Retirement block = prior.retirement;
        return new Lifecycle(LifecycleState.RETIRED, prior.suspensions, new Retirement(block.actorClass,
                block.actorUserId, block.actorSerial, block.grant, block.time, obligations));
    }

    /**
     * Whether a suspension entry with scope bit 0, which blocks deletion and migration, holds this
     * lifecycle. No writer of this stage sets the bit, and the decoder accepts it, so only a later
     * writer's record can hold one. Pure.
     */
    static boolean dispositionBlocked(Lifecycle lifecycle) {
        for (Suspension entry : lifecycle.suspensions) {
            if ((entry.scope & NativeIdentityRecords.SCOPE_BLOCKS_DISPOSITION) != 0) return true;
        }
        return false;
    }

    /**
     * Whether this lifecycle has a free place for an entry of this actor class, as writers allot
     * a version 2 record's six suspension entries: one to the account's user, one to a recovery
     * hold and four to grant references. So a fifth grant waits while the account's user keeps
     * its place. The decoder accepts any six entries, one per actor, so a later writer's records
     * stay readable, and beside six entries of any classes no place is free. Pure.
     */
    static boolean placeFree(Lifecycle lifecycle, ActorClass actorClass) {
        if (lifecycle.suspensions.size() >= NativeIdentityRecords.MAX_SUSPENSIONS) return false;
        int held = 0;
        for (Suspension entry : lifecycle.suspensions) {
            if (entry.actorClass == actorClass) ++held;
        }
        return held < (actorClass == ActorClass.ADMIN_GRANT ? GRANT_PLACES : 1);
    }

    /**
     * Whether two suspension entries come from one actor, of whom a record holds at most one
     * entry: the account's user, one grant reference whatever its actor fields, or the recovery
     * hold. Pure.
     */
    static boolean sameActor(Suspension first, Suspension second) {
        return first.actorClass == second.actorClass
                && (first.actorClass != ActorClass.ADMIN_GRANT || first.grant.equals(second.grant));
    }

    /**
     * The writer rules of a suspension entry for the account of this Android user and serial,
     * narrower than what the decoder accepts. Pure. The suspend transition writes only the
     * account user's own entry and grant entries: a recovery hold comes only from Restore, under
     * {@link #writableRecoveryHold}. It never sets scope bit 0, which blocks deletion and migration,
     * until the owner accepts a design that grants that power. Bit 1 belongs to a recovery hold
     * alone, which the entry itself requires. The reason is in the registry and allowed for the
     * entry's actor class. An account user entry's actor is the account's own user and serial.
     */
    static boolean writableSuspension(int userId, long userSerial, Suspension entry) {
        if (entry.actorClass != ActorClass.ACCOUNT_USER
                && entry.actorClass != ActorClass.ADMIN_GRANT) return false;
        if ((entry.scope & NativeIdentityRecords.SCOPE_BLOCKS_DISPOSITION) != 0) return false;
        SuspensionReason reason = SuspensionReason.registered(entry.reason);
        if (reason == null) return false;
        if (!reason.actors.contains(entry.actorClass)) return false;
        return entry.actorClass != ActorClass.ACCOUNT_USER
                || (entry.actorUserId == userId && entry.actorSerial == userSerial);
    }

    /**
     * The writer rules of a retirement block for the account of this Android user and serial.
     * Pure. A retirement starts with this design's inventory, every kind outstanding and
     * unbound, with no code or time. Its actor is the account's own user and serial, or a grant.
     * USER_REMOVAL belongs to the Android user removal path alone, which is stage C's. A legacy
     * marker's block, all zero, passes only in that form: the retire transition takes it as a
     * legacy marker's continuation, never over an eligible account.
     */
    static boolean writableRetirement(int userId, long userSerial, Retirement retirement) {
        if (retirement.actorClass == ActorClass.USER_REMOVAL) return false;
        if (retirement.actorClass == ActorClass.ACCOUNT_USER && (retirement.actorUserId != userId
                || retirement.actorSerial != userSerial)) return false;
        if (retirement.obligations.isEmpty()) return false;
        for (Obligation duty : retirement.obligations) {
            if (!duty.equals(new Obligation(duty.kind, ObligationState.OUTSTANDING,
                    NativeIdentityRecords.NO_REFERENCE, 0, 0))) return false;
        }
        return true;
    }

    /**
     * The writer rules of the receipts that confirm retired: one DISCHARGED obligation for each
     * retirement kind, in kind order, each its owner's explicit receipt. Nothing to do is a
     * receipt too. A receipt binds its reference, or none when it keeps zero. No disposition kind
     * is discharged here. Pure.
     */
    static boolean writableReceipts(List<Obligation> receipts) {
        int index = 0;
        for (ObligationKind kind : ObligationKind.values()) {
            if (kind.disposition()) continue;
            if (index >= receipts.size()) return false;
            Obligation receipt = receipts.get(index++);
            if (receipt.kind != kind || receipt.state != ObligationState.DISCHARGED) return false;
        }
        return index == receipts.size();
    }

    /**
     * The writer rules of the receipts that confirm disposal: one or more DISCHARGED obligations of
     * disposition kinds, in strictly ascending kind order, each its owner's receipt on observed
     * evidence. A receipt binds its reference, or none when it keeps zero. No retirement kind is
     * discharged here, and no receipt orphans a kind. Pure.
     */
    static boolean writableDispositionReceipts(List<Obligation> receipts) {
        if (receipts.isEmpty()) return false;
        int last = 0;
        for (Obligation receipt : receipts) {
            if (!receipt.kind.disposition() || receipt.state != ObligationState.DISCHARGED
                    || receipt.kind.code <= last) return false;
            last = receipt.kind.code;
        }
        return true;
    }

    /**
     * The writer rules of a recovery hold as the recovery route requests it. Pure. Its class is
     * RECOVERY_HOLD, its reason is registered for recovery holds, and its scope is 0: the writer
     * never sets bit 0, and sets bit 1 itself exactly when the last known state cannot be
     * established. Its actor is the Android user that ran recovery, and its note is optional.
     */
    static boolean writableRecoveryHold(Suspension hold) {
        if (hold.actorClass != ActorClass.RECOVERY_HOLD || hold.scope != 0) return false;
        SuspensionReason reason = SuspensionReason.registered(hold.reason);
        return reason != null && reason.actors.contains(ActorClass.RECOVERY_HOLD);
    }

    /**
     * Confirm exact observed bytes through new checked writing FDs, not reader sync. A slot of a
     * version above this format's ceiling is refused before anything else, as it is never VALID.
     */
    boolean confirmExistingSlot(Slot expected) {
        if (expected.version > format.slotCeiling) return false;
        if (writeInspectionBlocked(expected.appId)) return false;
        Loaded loaded = load();
        ReadResult<Slot> read = loaded.slots.get(expected.appId);
        if (!loaded.enumerationComplete || loaded.unsupportedFootprint || loaded.unavailableFootprint
                || loaded.header.status == Status.UNSUPPORTED
                || read == null || read.status != Status.VALID || !expected.equals(read.value)) return false;
        byte[] bytes = NativeIdentityRecords.encodeSlot(expected);
        return writeStrict(slotFile(expected.appId), bytes, bytes, false, false);
    }

    // Rewrites the selected header over every copy, keeping it as the backup, so
    // it refuses beside an unselected addition or counter the rewrite would
    // erase, and beside any incompatible copy. Each caller uses it as its first
    // effect.
    private boolean confirmHeader(Header expected) {
        ReadResult<Header> read = safeReadHeader();
        if (read.status != Status.VALID || !read.value.equals(expected)
                || !keepsHeaderCopies(read, expected, format)) return false;
        byte[] bytes = NativeIdentityRecords.encodeHeader(expected);
        return writeStrict(headerFile(), bytes, bytes, false, true);
    }

    /**
     * Filesystem continuation ONLY after a confirmed RELEASING header. The
     * account authority must have completed all producer/API/key/data duties
     * before authorizing that header. This is not a public quiescence boolean.
     * Damaged creation records are deliberately NOT auto-deleted by this slice.
     */
    boolean removeReleasingSlot(Header expected, int appId) {
        HeaderEntry index = headerEntry(expected, appId);
        if (index == null || index.phase != SlotPhase.RELEASING || writeInspectionBlocked(appId)
                || !confirmHeader(expected)) return false;
        File dir = slotDirectory(appId);
        Node node = node(dir);
        // Only a genuine ENOENT continues as removed. A directory whose presence
        // cannot be observed, or a link or special node, acknowledges nothing.
        if (node == Node.ABSENT) {
            try { syncDirectory(slotRoot); return true; }
            catch (IOException error) { return false; }
        }
        if (node != Node.DIRECTORY) return false;
        ReadResult<Slot> read = readSlotCopies(appId);
        // Even a transaction marker cannot erase a parseable foreign/live body.
        for (Slot copy : read.decodedCopies) {
            if (copy.appId != appId || !copy.lineage.equals(expected.lineage)
                    || !copy.users.isEmpty()) return false;
        }
        Copy seed = observe(seed(slotFile(appId)));
        if (seed.bytes != null) {
            try {
                Slot copy = NativeIdentityRecords.decodeSlot(seed.bytes);
                if (copy.appId != appId || !copy.lineage.equals(expected.lineage)
                        || !copy.users.isEmpty()) return false;
            } catch (IllegalArgumentException error) {
                // A torn staging body is not positive metadata. The durable
                // RELEASING transaction, not this parse failure, owns removal.
                // An intact unsupported or unreadable seed never reaches removal:
                // the gate and the check below refuse it.
            }
        }
        Set<String> allowed = Set.of("record.bin", "record.bin.reservecopy", "record.bin-backup",
                "record.bin-seed");
        File[] files = dir.listFiles();
        if (files == null) return false;
        try {
            for (File file : files) {
                if (!allowed.contains(file.getName()) || node(file) != Node.FILE) return false;
            }
            // At the point of effect too: a tombstone copy is no permission to
            // unlink an intact newer record or seed beside it, or unreadable bytes.
            if (recordBlocked(slotFile(appId), false)) return false;
            for (File file : files) if (!file.delete()) return false;
            syncDirectory(dir);
            if (!dir.delete()) return false;
            syncDirectory(slotRoot);
            return true;
        } catch (IOException | RuntimeException error) { return false; }
    }

    private boolean validHeaderTransition(Header previous, Header next) {
        if (next.lastId > previous.lastId && !load().creationReady()) return false;
        for (HeaderEntry old : previous.entries) {
            HeaderEntry changed = headerEntry(next, old.appId);
            if (changed == null) {
                // Omission needs the directory's genuine absence. A directory that
                // cannot be observed is not absence, even for a RELEASING entry.
                if (old.phase != SlotPhase.RELEASING || !absent(slotDirectory(old.appId))) return false;
                try { syncDirectory(slotRoot); }
                catch (IOException error) { return false; }
                continue;
            }
            if (old.phase == changed.phase) {
                // The whole entry, creation binding included: nothing fills one in.
                if (!old.equals(changed)) return false;
                continue;
            }
            ReadResult<Slot> slot = readSlotCopies(old.appId);
            if (slot.status != Status.VALID || slot.value.appId != old.appId
                    || !slot.value.lineage.equals(previous.lineage)) return false;
            if (old.phase == SlotPhase.CREATING && changed.phase == SlotPhase.LIVE) {
                if (slot.value.users.size() != 1 || slot.value.users.get(0).id != old.creationId
                        || !slot.value.packageName.equals(old.creationPackage)
                        || !bindingHolds(old, slot.value)) return false;
            } else if (old.phase == SlotPhase.LIVE && changed.phase == SlotPhase.RELEASING) {
                if (!slot.value.users.isEmpty()) return false;
                // Under a format that writes lifecycle records, only the release engine's ticketed
                // tombstone becomes RELEASING.
                if (format.slotCeiling >= LIFECYCLE_SLOT_VERSION && slot.value.ticket == null) return false;
                // The caller's exact account retirement owns the work/API/key/
                // data evidence. A tombstone is not independently that proof.
            } else return false;
            // Observation is not an acknowledgement of the write whose result
            // was lost. Reconfirm this exact precondition through checked FDs.
            if (!confirmExistingSlot(slot.value)) return false;
        }
        for (HeaderEntry added : next.entries) {
            if (headerEntry(previous, added.appId) != null) continue;
            if (!load().creationReady()) return false;
            if (added.phase != SlotPhase.CREATING || added.creationId <= previous.lastId
                    || !absent(slotDirectory(added.appId))) return false;
            try { syncDirectory(slotRoot); }
            catch (IOException error) { return false; }
        }
        return true;
    }

    private ReadResult<Header> safeReadHeader() {
        if (!directory(root) || !directory(slotRoot)) {
            return new ReadResult<>(Status.DAMAGED, null, List.of());
        }
        return readHeaderCopies();
    }
    private boolean sameHeader(Header expected) {
        ReadResult<Header> read = safeReadHeader();
        return read.status == Status.VALID && read.value.equals(expected);
    }

    // kept is what the preferred backup must durably hold before startWrite may
    // remove main and reserve. An existing backup must already be kept or the
    // selected prior; anything else is refused unchanged. Only Restore replaces
    // any regular backup, after it chose the last known state from every intact copy.
    private static void preserveChosenBase(File main, byte[] prior, byte[] kept, boolean restore)
            throws IOException {
        Node preferred = node(backup(main));
        if (preferred != Node.ABSENT && !(restore && preferred == Node.FILE)) {
            byte[] current = preferred == Node.FILE ? readBytes(backup(main)) : null;
            if (current == null || !(java.util.Arrays.equals(kept, current)
                    || (prior != null && java.util.Arrays.equals(prior, current)))) {
                throw new IOException("Native preferred backup changed");
            }
        }
        // startWrite could rename a bad main into the preferred backup and
        // delete the only good reserve. Persist the kept base using a checked
        // writer first, including when its earlier publication was uncertain.
        // Replacing a same-value backup does not change its meaning.
        File staging = seed(main);
        Node staged = node(staging);
        if (staged != Node.ABSENT && staged != Node.FILE) {
            throw new IOException("Native backup staging alias");
        }
        try (FileOutputStream out = new FileOutputStream(staging)) {
            out.write(kept);
            out.flush();
            if (FileUtils.setPermissions(out.getFD(), 0600, -1, -1) != 0) {
                throw new IOException("Native backup permissions");
            }
            out.getFD().sync();
        }
        if (!java.util.Arrays.equals(kept, readBytes(staging))) {
            throw new IOException("Native backup staging changed");
        }
        Files.move(staging.toPath(), backup(main).toPath(), StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING);
        syncDirectory(main.getParentFile());
    }

    private boolean writeStrict(File main, byte[] bytes, byte[] prior, boolean protectTarget,
            boolean header) {
        return writeStrict(main, bytes, prior, protectTarget, header, false);
    }

    private boolean writeStrict(File main, byte[] bytes, byte[] prior, boolean protectTarget,
            boolean header, boolean restore) {
        if (!directory(main.getParentFile())) return false;
        // Every caller passed the store gate first. This is the point of effect:
        // startWrite and the seed staging can unlink or replace each of these.
        if (recordBlocked(main, header)) return false;
        // The root is private to PMS. Still refuse filesystem aliases, special
        // nodes and unknown paths rather than allowing a corrupt slot to
        // redirect a trusted writer.
        for (File file : List.of(main, reserve(main), backup(main))) {
            Node node = node(file);
            if (node != Node.ABSENT && node != Node.FILE) return false;
        }
        try (ResilientAtomicFile atomic = new ResilientAtomicFile(main, backup(main), reserve(main),
                0600, "native-identity", null)) {
            // A first write publishes complete, checked creation bytes as the
            // preferred backup before the canonical writer can expose a torn
            // main. Such a creation remains PENDING until explicit rebinding.
            // A pure header reservation publishes its own target the same way,
            // so every hold, including an unselected addition it restates,
            // stays in the backup while main and reserve are rewritten. Every
            // other write keeps its prior until the final step removes it.
            preserveChosenBase(main, prior, prior == null || protectTarget ? bytes : prior, restore);
            FileOutputStream out = atomic.startWrite();
            out.write(bytes);
            atomic.finishWriteStrict(out);
            // Supplemental exact readback, after the actual writing FDs sync.
            // The preferred backup must be genuinely gone, not unobservable.
            return absent(backup(main)) && java.util.Arrays.equals(bytes, readBytes(main))
                    && java.util.Arrays.equals(bytes, readBytes(reserve(main)));
        } catch (IOException | RuntimeException error) {
            // Do not call failWrite: retain uncertain copies and every hold.
            return false;
        }
    }

    private static void protectDirectory(File directory) throws IOException {
        try { Os.chmod(directory.getPath(), 0700); }
        catch (ErrnoException error) { throw new IOException("Native directory mode", error); }
    }
    private static void syncDirectory(File directory) throws IOException {
        if (!directory(directory)) throw new IOException("Native parent is not a directory");
        FileDescriptor fd = null;
        try {
            fd = Os.open(directory.getPath(), OsConstants.O_RDONLY | OsConstants.O_CLOEXEC, 0);
            if (!OsConstants.S_ISDIR(Os.fstat(fd).st_mode)) {
                throw new IOException("Native parent changed type");
            }
            Os.fsync(fd);
        } catch (ErrnoException error) { throw new IOException("Native directory sync", error); }
        finally {
            if (fd != null) try { Os.close(fd); }
            catch (ErrnoException error) { throw new IOException("Native directory close", error); }
        }
    }

    private static HeaderEntry headerEntry(Header header, int appId) {
        for (HeaderEntry entry : header.entries) if (entry.appId == appId) return entry;
        return null;
    }
    private static void checkAppId(int appId) {
        if (appId < 10000 || appId > 19999) throw new IllegalArgumentException("Native app ID");
    }
    private static Integer parseSlotName(String name) {
        if (name.length() != 5) return null;
        int result = 0;
        for (int i = 0; i < name.length(); ++i) {
            char value = name.charAt(i);
            if (value < '0' || value > '9') return null;
            result = result * 10 + value - '0';
        }
        return result >= 10000 && result <= 19999 ? result : null;
    }
}
