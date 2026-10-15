// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeHeaderTestSupport.*;

import android.content.pm.Signature;
import android.content.pm.SigningDetails;
import android.system.Os;
import com.android.server.LocalServices;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * The readings of the guest inputs of the reader step of the normal image: the store layouts that
 * the guest generator wrote, each booted as its guest would boot it, with the subject mapped at its
 * app ID unless the input's mapping is lost, the boot's device encrypted data owners and the
 * guest's user 0 serial. The host facade restores the store, the candidate's exact Settings text in
 * the history harness restores the same view, and the two must agree on every pin, hold, deferral,
 * boot fact and diagnostic line but the allocator's search start, which only the guest reports.
 *
 * <p>For each input it prints one line of facts: each held app ID's slot as the store selected it,
 * with the copies it was selected from, or its status and the evidence its decoded copies and
 * stable prefixes name; the restored pins and their phases; the deferred names; the scan outcome of
 * each mapped package, its subject check and its signer check with the subject's certificate;
 * whether each named package is protected in a boot of the same store that maps nothing; the boot
 * facts; and the candidate text's raw diagnostic. The runner compares them with its exact
 * predictions. Nothing here predicts: it reads and reports. No byte, file or time of an input
 * changes.
 *
 * <p>The same source compiles with the current sources, read under Format.V3, the production
 * format, and with B1's sources pinned from their Git objects, read under Format.V2, B1's boot
 * format: the API it uses is equal in both. Host files only, not an Android boot.
 */
public final class NativeLifecycleGuestCheck {
    private static final List<String> COPIES = List.of("record.bin", "record.bin.reservecopy", "record.bin-backup");
    private static final List<String> COPY_NAMES = List.of("main", "reserve", "backup");
    private static final UserManagerInternal USERS = new UserManagerInternal();
    private static NativeIdentityStore.Format format;
    private static SigningDetails signer;
    // The packages the readings name, by package: the label each reading uses for it.
    private static Map<String, String> labels;

    /** Each line "name number" of a file, by name. */
    private static Map<String, Integer> pairs(Path file) throws Exception {
        Map<String, Integer> pairs = new TreeMap<>();
        for (String line : Files.readAllLines(file)) {
            String[] words = line.split(" ");
            if (words.length != 2 || pairs.put(words[0], Integer.parseInt(words[1])) != null) {
                throw new AssertionError("pair line " + line);
            }
        }
        return pairs;
    }

    private static String obligations(NativeIdentityRecords.Retirement retirement) {
        if (retirement.obligations.isEmpty()) return "-";
        StringBuilder letters = new StringBuilder();
        for (NativeIdentityRecords.Obligation duty : retirement.obligations) {
            letters.append(switch (duty.state) {
                case OUTSTANDING -> 'O';
                case DISPOSING -> 'P';
                case DISCHARGED -> 'D';
                case ORPHANED_WITH_USER -> 'U';
            });
        }
        return letters.toString();
    }

    /**
     * STATE:entries:retirement, each entry CLASS/scope with +note, the retirement
     * CLASS/inventory/states.
     */
    private static String lifecycle(NativeIdentityRecords.Lifecycle lifecycle) {
        List<String> entries = new ArrayList<>();
        for (NativeIdentityRecords.Suspension entry : lifecycle.suspensions) {
            entries.add(entry.actorClass + "/" + entry.scope + (entry.noteDigest == null ? "" : "+note"));
        }
        NativeIdentityRecords.Retirement retirement = lifecycle.retirement;
        return lifecycle.state + ":" + (entries.isEmpty() ? "-" : String.join(",", entries)) + ":"
                + (retirement == null ? "-" : retirement.actorClass + "/" + retirement.inventory + "/"
                + obligations(retirement));
    }

    /** A package by the label the names file gives it, or itself. */
    private static String label(String packageName) {
        return labels.getOrDefault(packageName, packageName);
    }

    /** Principal IDs ascending, each run of consecutive IDs as first-last, or "-" for none. */
    private static String ids(TreeSet<Long> ids) {
        List<String> runs = new ArrayList<>();
        Long first = null, last = null;
        for (long id : ids) {
            if (last != null && id == last + 1) {
                last = id;
                continue;
            }
            if (first != null) runs.add(first.equals(last) ? String.valueOf(first) : first + "-" + last);
            first = id;
            last = id;
        }
        if (first != null) runs.add(first.equals(last) ? String.valueOf(first) : first + "-" + last);
        return runs.isEmpty() ? "-" : String.join(",", runs);
    }

    /**
     * A selected value: its version, generation, package by its label, and users or tombstone
     * ticket, and the copies whose own value it is. Otherwise the status, and what the decoded
     * copies and prefixes name, packages by their labels and principal IDs in runs.
     */
    private static String slot(NativeIdentityStore.ReadResult<NativeIdentityRecords.Slot> read, Path directory)
            throws Exception {
        StringBuilder text = new StringBuilder(read.status.name());
        if (read.status == NativeIdentityStore.Status.VALID) {
            NativeIdentityRecords.Slot value = read.value;
            text.append(" v").append(value.version).append(" g").append(value.generation).append(' ')
                    .append(label(value.packageName));
            if (value.users.isEmpty()) {
                text.append(" TOMBSTONE");
                if (value.ticket != null) {
                    text.append(" ticket=").append(value.ticket.lastId).append('/').append(value.ticket.userId)
                            .append('/').append(value.ticket.userSerial);
                }
            }
            for (NativeIdentityRecords.UserEntry user : value.users) {
                text.append(" user=").append(user.id).append('/').append(user.userId).append('/')
                        .append(user.userSerial).append(':').append(lifecycle(user.lifecycle));
            }
            List<String> selected = new ArrayList<>();
            for (int i = 0; i < COPIES.size(); i++) {
                Path file = directory.resolve(COPIES.get(i));
                if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) continue;
                try {
                    if (NativeIdentityRecords.decodeSlot(Files.readAllBytes(file)).equals(value)) {
                        selected.add(COPY_NAMES.get(i));
                    }
                } catch (IllegalArgumentException undecodable) {
                    // Not this value: a damaged copy or a frame of another version.
                }
            }
            return text.append(" selected=").append(selected.isEmpty() ? "none" : String.join(",", selected))
                    .toString();
        }
        TreeSet<String> packages = new TreeSet<>();
        TreeSet<Long> principals = new TreeSet<>();
        for (NativeIdentityRecords.Slot copy : read.decodedCopies) {
            packages.add(label(copy.packageName));
            for (NativeIdentityRecords.UserEntry user : copy.users) principals.add(user.id);
            if (copy.ticket != null) principals.add(copy.ticket.lastId);
        }
        for (NativeIdentityRecords.SlotPrefix prefix : read.prefixes) {
            packages.add(label(prefix.packageName));
            principals.addAll(prefix.principalIds);
        }
        text.append(" copies=").append(read.decodedCopies.size()).append(" prefixes=").append(read.prefixes.size())
                .append(" names=").append(packages.isEmpty() ? "-" : String.join(",", packages))
                .append(" ids=").append(ids(principals));
        return text.append(read.unavailable ? " unavailable" : "").toString();
    }

    /**
     * The selected header: version, counter and each entry, a creation's package by its label, or
     * the status; and a format footprint.
     */
    private static String header(NativeIdentityStore.Loaded loaded) {
        NativeIdentityStore.ReadResult<NativeIdentityRecords.Header> read = loaded.header;
        StringBuilder text = new StringBuilder(read.status.name());
        if (read.status == NativeIdentityStore.Status.VALID) {
            text.append(" v").append(read.value.version).append(" last=").append(read.value.lastId);
            for (NativeIdentityRecords.HeaderEntry entry : read.value.entries) {
                text.append(' ').append(entry.appId).append(':').append(entry.phase);
                if (entry.phase != NativeIdentityRecords.SlotPhase.CREATING) continue;
                NativeIdentityRecords.CreationBinding binding = entry.creationBinding;
                text.append(':').append(entry.creationId).append(':').append(label(entry.creationPackage))
                        .append(binding == null ? ":unbound" : ":bound/" + binding.userId + "/" + binding.userSerial);
            }
        } else {
            text.append(" copies=").append(read.decodedCopies.size());
        }
        return text.append(loaded.unsupportedFootprint ? " unsupported-footprint" : "").toString();
    }

    private static String withoutSearchStart(String dump) {
        return dump.replaceAll("(?m)^allocator_search_start=[0-9]*\n", "");
    }

    private static boolean sameFacts(NativeIdentityPersistence.BootFacts one, NativeIdentityPersistence.BootFacts two) {
        return one.retired.equals(two.retired) && one.ticketedTombstones.equals(two.ticketedTombstones)
                && one.releasingWithoutDirectory.equals(two.releasingWithoutDirectory);
    }

    private static String quote(String value) {
        StringBuilder text = new StringBuilder("\"");
        for (char c : value.toCharArray()) {
            if (c == '"' || c == '\\') text.append('\\').append(c);
            else if (c < 0x20 || c > 0x7e) text.append(String.format("\\u%04x", (int) c));
            else text.append(c);
        }
        return text.append('"').toString();
    }

    private static String json(Object value) {
        if (value instanceof String text) return quote(text);
        if (value instanceof List<?> list) {
            List<String> items = new ArrayList<>();
            for (Object item : list) items.add(json(item));
            return "[" + String.join(",", items) + "]";
        }
        if (value instanceof Map<?, ?> map) {
            List<String> items = new ArrayList<>();
            for (Map.Entry<?, ?> entry : new TreeMap<>(map).entrySet()) {
                items.add(quote((String) entry.getKey()) + ":" + json(entry.getValue()));
            }
            return "{" + String.join(",", items) + "}";
        }
        throw new AssertionError("no JSON form for " + value);
    }

    private static void read(Path input, List<String> problems) throws Exception {
        Path root = input.resolve("store");
        Map<String, Integer> packages = pairs(input.resolve("packages"));
        Map<String, Integer> owners = pairs(input.resolve("owners"));
        long serial = Long.parseLong(Files.readString(input.resolve("serial")).trim());
        if (serial > Integer.MAX_VALUE) throw new AssertionError("a serial beyond the host user facade");
        USERS.info.serialNumber = (int) serial;
        age(root);
        Map<String, String> before = footprint(root);

        // The facade's boot: package settings first, then the store, with the boot's data owners.
        PackageManagerService pm = new PackageManagerService(root, false, format);
        pm.mSettings.mNativeDeOwnersAtBoot = Map.copyOf(owners);
        for (Map.Entry<String, Integer> entry : packages.entrySet()) pm.mSettings.add(entry.getKey(), entry.getValue());
        pm.mSettings.restoreAfterPackageSettings();
        NativeIdentityStore.Loaded loaded = pm.mSettings.mNativeIdentityLoaded;
        // The image enumerates data owners only for app IDs its store holds.
        for (int uid : owners.values()) {
            check(problems, loaded.occupiedAppIds.contains(uid % 100000),
                    "a data owner the store does not hold " + uid);
        }
        // The candidate's exact boot text over the same view, mappings and owners.
        NativeHistoryHarness harness = new NativeHistoryHarness();
        harness.slotCeiling = format.slotCeiling;
        harness.mNativeDeOwnersAtBoot = Map.copyOf(owners);
        for (Map.Entry<String, Integer> entry : packages.entrySet()) {
            harness.map(entry.getValue(), new NativeHistoryHarness.PackageSetting(entry.getKey(), entry.getValue(),
                    false));
        }
        harness.apply(loaded);
        String difference = NativeHistoryTestSupport.pinDifference(pm.mSettings.pins, harness.nativePrincipalPinsLPr(),
                loaded);
        check(problems, difference == null, "the facade and the candidate text restored differently: " + difference);
        Set<Integer> holds = new TreeSet<>(pm.mSettings.storeHolds);
        holds.addAll(pm.mSettings.pins.reservedAppIds());
        check(problems, holds.equals(harness.mAppIds.nativePrincipalAppIds()), "allocator holds " + holds + " and "
                + harness.mAppIds.nativePrincipalAppIds());
        NativePrincipalRecovery view = harness.mNativeRecoveryView;
        check(problems, view.deferredPackageNames().equals(pm.mSettings.mNativeRecoveryView.deferredPackageNames())
                && view.hasUnidentifiedCode() == pm.mSettings.mNativeRecoveryView.hasUnidentifiedCode(),
                "the facade and the candidate text seeded differently");
        check(problems, sameFacts(harness.mNativeBootFacts, pm.mSettings.nativeBootFactsLPr()),
                "the facade and the candidate text recorded different boot facts");
        // The scan runs over the candidate text's recovery view.
        pm.mSettings.mNativeRecoveryView = view;

        Map<String, Object> reading = new TreeMap<>();
        Map<String, Object> slots = new TreeMap<>();
        slots.put("header", header(loaded));
        for (Map.Entry<Integer, NativeIdentityStore.ReadResult<NativeIdentityRecords.Slot>> held
                : new TreeMap<>(loaded.slots).entrySet()) {
            slots.put(String.valueOf(held.getKey()), slot(held.getValue(), root.resolve("slots/" + held.getKey())));
        }
        reading.put("lifecycle", slots);
        List<Object> pins = new ArrayList<>();
        Set<Integer> pinned = new TreeSet<>();
        for (NativePrincipalPins.Record record : NativeIdentityPersistence.restoration(loaded.histories()).records) {
            NativePrincipalPins.Pin pin = pm.mSettings.pins.findId(record.id);
            if (pin == null) continue;
            pins.add(record.appId + " " + record.id + " " + record.packageName + " " + pin.phase());
            pinned.add(record.appId);
        }
        check(problems, pinned.equals(pm.mSettings.pins.reservedAppIds()), "pins beside the restored records");
        reading.put("pins", pins);
        reading.put("deferred", new ArrayList<Object>(new TreeSet<>(view.deferredPackageNames())));
        Map<String, Object> scan = new TreeMap<>();
        for (String name : packages.keySet()) {
            PackageSetting setting = pm.mSettings.getPackageLPr(name);
            boolean subject = pm.mSettings.nativeScanSubjectAllowedLPr(setting);
            boolean binding = pm.mSettings.nativeScanBindingAllowedLPr(setting, signer);
            if (!labels.containsKey(name)) throw new AssertionError("an unnamed mapped package " + name);
            scan.put(labels.get(name), subject && binding ? "admitted" : !subject && !binding ? "refused"
                    : subject ? "signer refused" : "subject refused");
        }
        // The identity predicate, the first check of a fresh registration, in a boot that maps
        // nothing: what the bytes alone protect.
        PackageManagerService bare = new PackageManagerService(root, false, format);
        bare.mSettings.restoreAfterPackageSettings();
        for (Map.Entry<String, String> name : labels.entrySet()) {
            scan.put(name.getValue() + " unmapped", bare.mSettings.isNativePrincipalPackageLPr(name.getKey())
                    ? "protected" : "unprotected");
        }
        reading.put("scan", scan);
        List<Object> facts = new ArrayList<>();
        NativeIdentityPersistence.BootFacts boot = harness.mNativeBootFacts;
        for (Map.Entry<Integer, NativePrincipalPins.Record> retired : boot.retired.entrySet()) {
            facts.add("retired " + retired.getKey() + " " + retired.getValue().id + " "
                    + retired.getValue().packageName);
        }
        for (Map.Entry<Integer, NativeIdentityRecords.Slot> tombstone : boot.ticketedTombstones.entrySet()) {
            facts.add("tombstone " + tombstone.getKey() + " " + tombstone.getValue().ticket.lastId);
        }
        for (int appId : boot.releasingWithoutDirectory) facts.add("releasing " + appId);
        reading.put("boot_facts", facts);
        String dump = harness.nativeIdentityDumpLPr();
        check(problems, withoutSearchStart(dump).equals(withoutSearchStart(pm.mSettings.nativeIdentityDumpLPr())),
                "the facade's diagnostic differs from the candidate text's");
        reading.put("dump", dump);
        check(problems, footprint(root).equals(before), "the reads changed the store");
        System.out.println("GUEST " + input.getFileName() + " " + json(reading));
    }

    /**
     * Arguments: the inputs, one directory each with its store, packages, owners and serial files;
     * a state directory; the format, V2 or V3; the subject's certificate; and the file of the
     * packages the readings name, one "label package" line each, whose protection the boot that
     * maps nothing reports.
     */
    public static void main(String[] args) throws Exception {
        if (!NativeLifecycleGuestCheck.class.desiredAssertionStatus()) throw new AssertionError("run with java -ea");
        if (args.length != 5) throw new AssertionError("inputs, state, format, certificate and names required");
        format = NativeIdentityStore.Format.valueOf(args[2]);
        if (format == NativeIdentityStore.Format.V1) throw new AssertionError("Format.V2 or V3 required");
        start(Path.of(args[1]).resolve("guest-inputs"));
        LocalServices.addService(UserManagerInternal.class, USERS);
        signer = new SigningDetails(new Signature(Files.readAllBytes(Path.of(args[3]))));
        labels = new TreeMap<>();
        for (String line : Files.readAllLines(Path.of(args[4]))) {
            String[] words = line.split(" ");
            if (words.length != 2 || labels.containsValue(words[0]) || labels.put(words[1], words[0]) != null) {
                throw new AssertionError("name line " + line);
            }
        }
        List<Path> inputs = new ArrayList<>();
        try (var entries = Files.list(Path.of(args[0]))) {
            entries.sorted().forEach(inputs::add);
        }
        if (inputs.isEmpty() || labels.isEmpty()) throw new AssertionError("inputs and names required");
        for (Path input : inputs) run(input.getFileName().toString(), problems -> read(input, problems));
        finish(Os.allClosed());
        System.out.println(inputs.size() + " guest inputs read under Format." + format + "; Android boot unqualified");
    }
}
