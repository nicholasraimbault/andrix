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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.HeaderEntry;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.SlotPhase;
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
 * This protocol writes version 1 headers and slots only. An intact record frame
 * (bounded size, magic, expected type, length and SHA-256) that declares a newer
 * version is an unsupported footprint, not damage. A decoded version 2 header
 * copy still contributes its holds, and only holds. A frame the codec cannot
 * decode is no value: no app ID, binding or counter is invented from it. Such a
 * main, reserve or backup copy makes its record UNSUPPORTED even when an older
 * valid copy exists. A staging seed is never a copy or positive history, but it
 * is preserved too. While any such footprint is recognized, every writer refuses
 * before its first effect: the whole native store stays read only. That is an
 * availability choice, separate from per-slot binding eligibility. It releases
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
 */
final class NativeIdentityStore {
    enum Status { MISSING, VALID, DAMAGED, CONFLICT, UNSUPPORTED }

    static final class ReadResult<T> {
        final Status status;
        final T value; // Positive metadata only when VALID.
        final List<T> decodedCopies; // Negative holds only; never merged into a grant.
        // Some copy's presence or bytes could not be observed. It may be newer, so
        // the record is never VALID or MISSING. This is I/O, not parser damage.
        final boolean unavailable;
        ReadResult(Status status, T value, List<T> decodedCopies) {
            this(status, value, decodedCopies, false);
        }
        ReadResult(Status status, T value, List<T> decodedCopies, boolean unavailable) {
            this.status = status;
            this.value = value;
            this.decodedCopies = List.copyOf(decodedCopies);
            this.unavailable = unavailable;
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
        boolean creationReady() {
            return enumerationComplete && !creationBlocked && header.status == Status.VALID;
        }
    }

    private interface Decoder<T> { T decode(byte[] bytes); }

    // The codec can preserve future header data, but this store's transition and
    // admission protocols still implement version 1. A decoded newer footprint
    // is a hold, not permission to reinterpret or mutate that state. An intact
    // frame of a newer version that does not decode keeps no hold of its own.
    private static final int SUPPORTED_HEADER_VERSION = 1;
    private static final int SUPPORTED_SLOT_VERSION = 1;

    private final File root;
    private final File slotRoot;

    NativeIdentityStore(File root) {
        this.root = Objects.requireNonNull(root).getAbsoluteFile();
        slotRoot = new File(this.root, "slots");
    }

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

    // An intact frame of the expected type which declares a version this protocol
    // does not write. Torn, foreign, wrongly typed, oversized, version 0 and bad
    // checksum bytes are not recognized. They remain ordinary damage.
    private static boolean unsupportedBytes(byte[] bytes, boolean header) {
        return header ? NativeIdentityRecords.intactHeaderVersion(bytes) > SUPPORTED_HEADER_VERSION
                : NativeIdentityRecords.intactSlotVersion(bytes) > SUPPORTED_SLOT_VERSION;
    }
    private static boolean newer(Copy copy, boolean header) {
        return copy.found == Found.BYTES && unsupportedBytes(copy.bytes, header);
    }
    // Every file a writer of this record can replace, truncate, rename over or
    // unlink. A recognized newer frame blocks. So does a path whose presence or
    // bytes are unavailable: it cannot be assumed not to be newer.
    private static boolean recordBlocked(File main, boolean header) {
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

    private static <T> ReadResult<T> readCopies(File main, Decoder<T> decoder, boolean header) {
        File[] paths = {main, reserve(main), backup(main)};
        ArrayList<T> valid = new ArrayList<>();
        ArrayList<T> values = new ArrayList<>();
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
                if (unsupportedBytes(copy.bytes, header)) unsupported = true;
            }
            values.add(value);
        }
        // A newer copy, selected or not, is never hidden by an older valid one.
        // Decoded copies still contribute their negative holds.
        if (unsupported) return new ReadResult<>(Status.UNSUPPORTED, null, valid, unavailable);
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
            if (copy.version != SUPPORTED_HEADER_VERSION) {
                // Even an unselected copy can contain a reservation whose new
                // transition semantics this writer has not qualified. Preserve
                // all decoded UID holds and do not fall through to a v1 copy.
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
            for (Map.Entry<Integer, ReadResult<Slot>> entry : loaded.entrySet()) {
                ReadResult<Slot> record = entry.getValue();
                if (record.status != Status.VALID) continue;
                Slot slot = record.value;
                boolean conflict = lineages.size() != 1 || !lineages.contains(slot.lineage);
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
                    if (index.phase == SlotPhase.RELEASING && !slot.users.isEmpty()) conflict = true;
                }
                if (conflict) entry.setValue(new ReadResult<>(Status.CONFLICT, null,
                        record.decodedCopies));
            }
            // An index entry with no directory still holds its ID.
            for (int appId : occupied) {
                loaded.putIfAbsent(appId, new ReadResult<>(Status.MISSING, null, List.of()));
            }
            HashMap<String, Integer> packages = new HashMap<>();
            HashMap<Long, Integer> incarnations = new HashMap<>();
            HashSet<Integer> conflicts = new HashSet<>();
            // A newly unsupported or unavailable record must not make an otherwise
            // conflicting sibling usable. Its decodable older copies are negative
            // evidence, never an identity or counter source for that record.
            for (Map.Entry<Integer, ReadResult<Slot>> entry : loaded.entrySet()) {
                if (entry.getValue().status != Status.UNSUPPORTED
                        && !entry.getValue().unavailable) continue;
                for (Slot copy : entry.getValue().decodedCopies) {
                    packages.putIfAbsent(copy.packageName, entry.getKey());
                    for (UserEntry user : copy.users) incarnations.putIfAbsent(user.id, entry.getKey());
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
            if (!writeStrict(new File(staging, "store.bin"), bytes, null, true)) return false;
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

    boolean writeHeader(Header expected, Header next) {
        Objects.requireNonNull(expected); Objects.requireNonNull(next);
        if (expected.version != SUPPORTED_HEADER_VERSION || next.version != SUPPORTED_HEADER_VERSION
                || !expected.lineage.equals(next.lineage) || next.lastId < expected.lastId
                || writeInspectionBlocked()) return false;
        ReadResult<Header> read = safeReadHeader();
        if (read.status != Status.VALID || !(read.value.equals(expected) || read.value.equals(next))) {
            return false;
        }
        if (!read.value.equals(next) && !validHeaderTransition(expected, next)) return false;
        // An exact uncertain retry is rewritten through real checked writers;
        // matching readback alone never turns it into a durable acknowledgement.
        return writeStrict(headerFile(), NativeIdentityRecords.encodeHeader(next),
                NativeIdentityRecords.encodeHeader(read.value), true);
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
                && slot.users.get(0).id == entry.creationId;
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
                || next.generation != 1) return false;
        if (read.status != Status.MISSING && !(read.status == Status.VALID
                && read.value.equals(next))) return false;
        try {
            syncDirectory(slotDirectory(next.appId));
            syncDirectory(slotRoot);
        } catch (IOException error) { return false; }
        return writeStrict(main, NativeIdentityRecords.encodeSlot(next),
                read.value == null ? null : NativeIdentityRecords.encodeSlot(read.value), false);
    }

    /** Existing binding mutation only: no counter reconstruction or new identity issuance. */
    boolean updateExistingSlot(Slot expected, Slot next) {
        Objects.requireNonNull(expected); Objects.requireNonNull(next);
        if (writeInspectionBlocked(next.appId)) return false;
        Loaded loaded = load();
        ReadResult<Slot> read = loaded.slots.get(next.appId);
        if (!loaded.enumerationComplete || loaded.unsupportedFootprint || loaded.unavailableFootprint
                || loaded.header.status == Status.UNSUPPORTED
                || read == null || read.status != Status.VALID) return false;
        HeaderEntry index = loaded.header.value == null ? null : headerEntry(loaded.header.value, next.appId);
        if (index != null && index.phase == SlotPhase.RELEASING && !next.users.isEmpty()) return false;
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
                NativeIdentityRecords.encodeSlot(read.value), false);
    }

    /** Confirm exact observed bytes through new checked writing FDs, not reader sync. */
    boolean confirmExistingSlot(Slot expected) {
        if (writeInspectionBlocked(expected.appId)) return false;
        Loaded loaded = load();
        ReadResult<Slot> read = loaded.slots.get(expected.appId);
        if (!loaded.enumerationComplete || loaded.unsupportedFootprint || loaded.unavailableFootprint
                || loaded.header.status == Status.UNSUPPORTED
                || read == null || read.status != Status.VALID || !expected.equals(read.value)) return false;
        byte[] bytes = NativeIdentityRecords.encodeSlot(expected);
        return writeStrict(slotFile(expected.appId), bytes, bytes, false);
    }

    private boolean confirmHeader(Header expected) {
        if (!sameHeader(expected)) return false;
        byte[] bytes = NativeIdentityRecords.encodeHeader(expected);
        return writeStrict(headerFile(), bytes, bytes, true);
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
                if (old.creationId != changed.creationId
                        || !old.creationPackage.equals(changed.creationPackage)) return false;
                continue;
            }
            ReadResult<Slot> slot = readSlotCopies(old.appId);
            if (slot.status != Status.VALID || slot.value.appId != old.appId
                    || !slot.value.lineage.equals(previous.lineage)) return false;
            if (old.phase == SlotPhase.CREATING && changed.phase == SlotPhase.LIVE) {
                if (slot.value.users.size() != 1 || slot.value.users.get(0).id != old.creationId
                        || !slot.value.packageName.equals(old.creationPackage)) return false;
            } else if (old.phase == SlotPhase.LIVE && changed.phase == SlotPhase.RELEASING) {
                if (!slot.value.users.isEmpty()) return false;
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

    private static void preserveChosenBase(File main, byte[] prior) throws IOException {
        if (prior == null) return;
        Node preferred = node(backup(main));
        if (preferred != Node.ABSENT && (preferred != Node.FILE
                || !java.util.Arrays.equals(prior, readBytes(backup(main))))) {
            throw new IOException("Native preferred backup changed");
        }
        // startWrite could rename a bad main into the preferred backup and
        // delete the only good reserve. Persist the selected valid base using
        // a checked writer first, including when its earlier publication was
        // uncertain. Replacing a same-value backup does not change its meaning.
        File staging = seed(main);
        Node staged = node(staging);
        if (staged != Node.ABSENT && staged != Node.FILE) {
            throw new IOException("Native backup staging alias");
        }
        try (FileOutputStream out = new FileOutputStream(staging)) {
            out.write(prior);
            out.flush();
            if (FileUtils.setPermissions(out.getFD(), 0600, -1, -1) != 0) {
                throw new IOException("Native backup permissions");
            }
            out.getFD().sync();
        }
        if (!java.util.Arrays.equals(prior, readBytes(staging))) {
            throw new IOException("Native backup staging changed");
        }
        Files.move(staging.toPath(), backup(main).toPath(), StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING);
        syncDirectory(main.getParentFile());
    }

    private static boolean writeStrict(File main, byte[] bytes, byte[] prior, boolean header) {
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
            preserveChosenBase(main, prior == null ? bytes : prior);
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
