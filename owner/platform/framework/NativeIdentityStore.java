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
import java.nio.file.StandardCopyOption;
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
 */
final class NativeIdentityStore {
    enum Status { MISSING, VALID, DAMAGED, CONFLICT, UNSUPPORTED }

    static final class ReadResult<T> {
        final Status status;
        final T value; // Positive metadata only when VALID.
        final List<T> decodedCopies; // Negative holds only; never merged into a grant.
        ReadResult(Status status, T value, List<T> decodedCopies) {
            this.status = status;
            this.value = value;
            this.decodedCopies = List.copyOf(decodedCopies);
        }
    }

    static final class Loaded {
        final ReadResult<Header> header;
        final Map<Integer, ReadResult<Slot>> slots;
        final Set<Integer> occupiedAppIds;
        final boolean creationBlocked;
        final boolean enumerationComplete;
        Loaded(ReadResult<Header> header, Map<Integer, ReadResult<Slot>> slots,
                Set<Integer> occupied, boolean blocked, boolean complete) {
            this.header = header;
            this.slots = Map.copyOf(slots);
            occupiedAppIds = Set.copyOf(occupied);
            creationBlocked = blocked;
            enumerationComplete = complete;
        }
        // Metadata eligibility for fresh designation/PMS rebinding, NOT live
        // execution authority. Retiring users must still restore as RETIRING.
        boolean bindingUsable(int appId) {
            ReadResult<Slot> slot = slots.get(appId);
            return enumerationComplete && slot != null && slot.status == Status.VALID
                    && !slot.value.users.isEmpty();
        }
        boolean creationReady() {
            return enumerationComplete && !creationBlocked && header.status == Status.VALID;
        }
    }

    private interface Decoder<T> { T decode(byte[] bytes); }

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
    private static boolean exists(File file) {
        return Files.exists(file.toPath(), LinkOption.NOFOLLOW_LINKS);
    }
    private static boolean directory(File file) {
        return Files.isDirectory(file.toPath(), LinkOption.NOFOLLOW_LINKS)
                && !Files.isSymbolicLink(file.toPath());
    }

    private static byte[] readBytes(File file) throws IOException {
        if (!Files.isRegularFile(file.toPath(), LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(file.toPath())) {
            throw new IOException("Native record is not a regular file");
        }
        try (FileInputStream in = new FileInputStream(file)) {
            byte[] bytes = in.readNBytes(NativeIdentityRecords.MAX_BYTES + 1);
            if (bytes.length > NativeIdentityRecords.MAX_BYTES) {
                throw new IOException("Native record exceeds its format bound");
            }
            return bytes;
        }
    }

    private static <T> ReadResult<T> readCopies(File main, Decoder<T> decoder) {
        File[] paths = {main, reserve(main), backup(main)};
        ArrayList<T> valid = new ArrayList<>();
        ArrayList<T> values = new ArrayList<>();
        boolean[] present = new boolean[3];
        boolean bad = false;
        for (int i = 0; i < paths.length; ++i) {
            T value = null;
            present[i] = exists(paths[i]);
            if (present[i]) {
                try {
                    value = decoder.decode(readBytes(paths[i]));
                    valid.add(value);
                } catch (IOException | RuntimeException error) { bad = true; }
            }
            values.add(value);
        }
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

    Loaded load() {
        TreeMap<Integer, ReadResult<Slot>> loaded = new TreeMap<>();
        TreeSet<Integer> occupied = new TreeSet<>();
        ReadResult<Header> header = new ReadResult<>(Status.MISSING, null, List.of());
        boolean complete = false, blocked = true;
        try {
            if (!directory(root) || !directory(slotRoot)) {
                // A missing root is NOT automatically permission to initialize a
                // new lineage. The trusted creation operation decides that case.
                if (directory(root)) header = readCopies(headerFile(), NativeIdentityRecords::decodeHeader);
                for (Header copy : header.decodedCopies) {
                    for (HeaderEntry entry : copy.entries) occupied.add(entry.appId);
                }
                return new Loaded(header, loaded, occupied, true, false);
            }
            header = readCopies(headerFile(), NativeIdentityRecords::decodeHeader);
            for (Header copy : header.decodedCopies) {
                for (HeaderEntry entry : copy.entries) occupied.add(entry.appId);
            }
            File[] entries = slotRoot.listFiles();
            if (entries == null) return new Loaded(header, loaded, occupied, true, false);
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
                ReadResult<Slot> record = directory(entry)
                        ? readCopies(slotFile(appId), NativeIdentityRecords::decodeSlot)
                        : new ReadResult<>(Status.DAMAGED, null, List.of());
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
                loaded.put(appId, new ReadResult<>(Status.CONFLICT, null,
                        loaded.get(appId).decodedCopies));
            }
        } catch (RuntimeException error) {
            // Namespace/read failures are not permission to delete package data
            // or to present incomplete discovery as a fresh, empty store.
            complete = false;
            blocked = true;
        }
        return new Loaded(header, loaded, occupied, blocked, complete);
    }

    /** Explicit fresh creation or its exact empty-result retry, never called by load(). */
    boolean initializeNew(String lineage) {
        Header empty = new Header(lineage, 0, List.of());
        try {
            File parent = root.getParentFile();
            if (!directory(parent)) return false;
            if (exists(root)) {
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
            if (!writeStrict(new File(staging, "store.bin"), bytes, null)) return false;
            syncDirectory(staging);
            // Same private parent and one writer. No REPLACE_EXISTING and no
            // ATOMIC_MOVE option which could replace an existing empty target.
            if (exists(root)) return false;
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
        if (!expected.lineage.equals(next.lineage) || next.lastId < expected.lastId) return false;
        ReadResult<Header> read = safeReadHeader();
        if (read.status != Status.VALID || !(read.value.equals(expected) || read.value.equals(next))) {
            return false;
        }
        if (!read.value.equals(next) && !validHeaderTransition(expected, next)) return false;
        // An exact uncertain retry is rewritten through real checked writers;
        // matching readback alone never turns it into a durable acknowledgement.
        return writeStrict(headerFile(), NativeIdentityRecords.encodeHeader(next),
                NativeIdentityRecords.encodeHeader(read.value));
    }

    boolean ensureFreshSlot(Header expected, int appId) {
        HeaderEntry entry = headerEntry(expected, appId);
        if (entry == null || entry.phase != SlotPhase.CREATING || !confirmHeader(expected)) return false;
        File directory = slotDirectory(appId);
        if (exists(directory)) return false; // A retry reconciles, never adopts an unknown mkdir.
        try {
            if (!directory.mkdir()) return false;
            protectDirectory(directory);
            syncDirectory(directory);
            syncDirectory(slotRoot);
            return true;
        } catch (IOException | RuntimeException error) { return false; }
    }

    boolean publishCreatingSlot(Header expectedHeader, Slot next) {
        Objects.requireNonNull(next);
        Objects.requireNonNull(expectedHeader);
        HeaderEntry index = headerEntry(expectedHeader, next.appId);
        if (!confirmHeader(expectedHeader) || index == null || !directory(slotDirectory(next.appId))
                || !expectedHeader.lineage.equals(next.lineage)) return false;
        for (UserEntry user : next.users) if (user.id > expectedHeader.lastId) return false;
        if (index.phase == SlotPhase.RELEASING && !next.users.isEmpty()) return false;
        File main = slotFile(next.appId);
        ReadResult<Slot> read = readCopies(main, NativeIdentityRecords::decodeSlot);
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
                read.value == null ? null : NativeIdentityRecords.encodeSlot(read.value));
    }

    /** Existing binding mutation only: no counter reconstruction or new identity issuance. */
    boolean updateExistingSlot(Slot expected, Slot next) {
        Objects.requireNonNull(expected); Objects.requireNonNull(next);
        Loaded loaded = load();
        ReadResult<Slot> read = loaded.slots.get(next.appId);
        if (!loaded.enumerationComplete || read == null || read.status != Status.VALID) return false;
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
                NativeIdentityRecords.encodeSlot(read.value));
    }

    /** Confirm exact observed bytes through new checked writing FDs, not reader sync. */
    boolean confirmExistingSlot(Slot expected) {
        Loaded loaded = load();
        ReadResult<Slot> read = loaded.slots.get(expected.appId);
        if (!loaded.enumerationComplete || read == null || read.status != Status.VALID
                || !expected.equals(read.value)) return false;
        byte[] bytes = NativeIdentityRecords.encodeSlot(expected);
        return writeStrict(slotFile(expected.appId), bytes, bytes);
    }

    private boolean confirmHeader(Header expected) {
        if (!sameHeader(expected)) return false;
        byte[] bytes = NativeIdentityRecords.encodeHeader(expected);
        return writeStrict(headerFile(), bytes, bytes);
    }

    /**
     * Filesystem continuation ONLY after a confirmed RELEASING header. The
     * account authority must have completed all producer/API/key/data duties
     * before authorizing that header. This is not a public quiescence boolean.
     * Damaged creation records are deliberately NOT auto-deleted by this slice.
     */
    boolean removeReleasingSlot(Header expected, int appId) {
        HeaderEntry index = headerEntry(expected, appId);
        if (index == null || index.phase != SlotPhase.RELEASING || !confirmHeader(expected)) return false;
        File dir = slotDirectory(appId);
        if (!exists(dir)) {
            try { syncDirectory(slotRoot); return true; }
            catch (IOException error) { return false; }
        }
        if (!directory(dir)) return false;
        ReadResult<Slot> read = readCopies(slotFile(appId), NativeIdentityRecords::decodeSlot);
        // Even a transaction marker cannot erase a parseable foreign/live body.
        for (Slot copy : read.decodedCopies) {
            if (copy.appId != appId || !copy.lineage.equals(expected.lineage)
                    || !copy.users.isEmpty()) return false;
        }
        File seed = new File(slotFile(appId).getPath() + "-seed");
        if (exists(seed)) {
            try {
                Slot copy = NativeIdentityRecords.decodeSlot(readBytes(seed));
                if (copy.appId != appId || !copy.lineage.equals(expected.lineage)
                        || !copy.users.isEmpty()) return false;
            } catch (IOException | IllegalArgumentException error) {
                // A torn staging body is not positive metadata. The durable
                // RELEASING transaction, not this parse failure, owns removal.
            }
        }
        Set<String> allowed = Set.of("record.bin", "record.bin.reservecopy", "record.bin-backup",
                "record.bin-seed");
        File[] files = dir.listFiles();
        if (files == null) return false;
        try {
            for (File file : files) {
                if (!allowed.contains(file.getName()) || Files.isSymbolicLink(file.toPath())
                        || !Files.isRegularFile(file.toPath(), LinkOption.NOFOLLOW_LINKS)) return false;
            }
            for (File file : files) if (!file.delete()) return false;
            syncDirectory(dir);
            if (!dir.delete()) return false;
            syncDirectory(slotRoot);
            return true;
        } catch (IOException | RuntimeException error) { return false; }
    }

    private boolean validHeaderTransition(Header previous, Header next) {
        for (HeaderEntry old : previous.entries) {
            HeaderEntry changed = headerEntry(next, old.appId);
            if (changed == null) {
                if (old.phase != SlotPhase.RELEASING || exists(slotDirectory(old.appId))) return false;
                try { syncDirectory(slotRoot); }
                catch (IOException error) { return false; }
                continue;
            }
            if (old.phase == changed.phase) {
                if (old.creationId != changed.creationId
                        || !old.creationPackage.equals(changed.creationPackage)) return false;
                continue;
            }
            ReadResult<Slot> slot = readCopies(slotFile(old.appId), NativeIdentityRecords::decodeSlot);
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
            if (added.phase != SlotPhase.CREATING || added.creationId <= previous.lastId
                    || exists(slotDirectory(added.appId))) return false;
            try { syncDirectory(slotRoot); }
            catch (IOException error) { return false; }
        }
        return true;
    }

    private ReadResult<Header> safeReadHeader() {
        if (!directory(root) || !directory(slotRoot)) {
            return new ReadResult<>(Status.DAMAGED, null, List.of());
        }
        return readCopies(headerFile(), NativeIdentityRecords::decodeHeader);
    }
    private boolean sameHeader(Header expected) {
        ReadResult<Header> read = safeReadHeader();
        return read.status == Status.VALID && read.value.equals(expected);
    }

    private static void preserveChosenBase(File main, byte[] prior) throws IOException {
        if (prior == null) return;
        if (exists(backup(main)) && !java.util.Arrays.equals(prior, readBytes(backup(main)))) {
            throw new IOException("Native preferred backup changed");
        }
        // startWrite could rename a bad main into the preferred backup and
        // delete the only good reserve. Persist the selected valid base using
        // a checked writer first, including when its earlier publication was
        // uncertain. Replacing a same-value backup does not change its meaning.
        File staging = new File(main.getPath() + "-seed");
        if (exists(staging) && (!Files.isRegularFile(staging.toPath(), LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(staging.toPath()))) {
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

    private static boolean writeStrict(File main, byte[] bytes, byte[] prior) {
        if (!directory(main.getParentFile())) return false;
        // The root is private to PMS. Still refuse filesystem aliases rather
        // than allowing a corrupt slot to redirect a trusted writer.
        for (File file : List.of(main, reserve(main), backup(main))) {
            if (exists(file) && (!Files.isRegularFile(file.toPath(), LinkOption.NOFOLLOW_LINKS)
                    || Files.isSymbolicLink(file.toPath()))) return false;
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
            return !exists(backup(main)) && java.util.Arrays.equals(bytes, readBytes(main))
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
