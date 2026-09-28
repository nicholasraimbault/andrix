// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import android.content.pm.Signature;
import android.content.pm.SigningDetails;
import android.os.Binder;
import android.system.Os;
import com.android.server.LocalServices;
import dev.andrix.proof.nativelab.LabHistoryStore;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Host rehearsal of the lab version 2 header only arm through the unchanged writer fixture, the
 * actual manager and store and the host PMS facades. Format.V2 is constructed by this host test
 * only. A slot root that the real unprivileged writer can read and search but not change makes
 * the first commit return false after a complete CREATING header, without a body. A modeled cold
 * restart restores that creation PENDING, and an explicit rebind publishes the original ID.
 * Transcript lines carry the actual fixture replies to the Python observers. No PackageSetting,
 * UID, pin, history or issuance is injected. Not Android, SELinux, crash or storage evidence.
 */
public final class NativeWriterLabRehearsal {
    static final String SUBJECT = "dev.andrix.proof.principalclosed";
    static final int APP_ID = 10148;
    static final long SERIAL = 7;
    // The existing fixture tests' synthetic host certificate: SHA-256 of the bytes 1, 2 and 3. It is
    // no Android signer; the lab command line predicts only the fixture's development signer.
    static final Set<String> SIGNERS =
            Set.of("039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81");
    static final NativePrincipalPins.Record RECORD =
            new NativePrincipalPins.Record(1, SUBJECT, APP_ID, 0, SERIAL);
    // Server instances, one per modeled system server or arm, and original caller nonces.
    static final String FIRST = "a".repeat(32), SECOND = "b".repeat(32), LOST = "c".repeat(32);
    static final String ERROR = "d".repeat(32), EXCEPTION = "e".repeat(32), OBSERVATION = "f".repeat(32);
    static final String FALLBACK = "0".repeat(31) + "1", CHANGED = "0".repeat(31) + "2";
    static final String ORIGINAL = "1".repeat(32), OTHER = "2".repeat(32), REBIND = "3".repeat(32);
    static final String LOST_NONCE = "4".repeat(32), ERROR_NONCE = "5".repeat(32);
    static final String EXCEPTION_NONCE = "6".repeat(32), OBSERVATION_NONCE = "7".repeat(32);
    static final String FALLBACK_NONCE = "8".repeat(32), CHANGED_NONCE = "9".repeat(32);
    private static final Set<String> LABELS = new HashSet<>();

    private static final class InjectedError extends Error {
        private static final long serialVersionUID = 1L;

        InjectedError(String message) {
            super(message);
        }
    }

    // Wrapper faults after the actual manager returned. The real writer always runs first.
    private static final class Fault implements NativePrincipalWriterFixture.Calls {
        private final NativePrincipalWriterFixture.Calls actual;
        private final String kind;
        private boolean committed;
        private int commits;

        Fault(NativePrincipalManager manager, String kind) {
            actual = new NativePrincipalWriterFixture.ManagerCalls(manager);
            this.kind = kind;
        }

        public NativePrincipalManager.Selection select() {
            return actual.select();
        }

        public NativePrincipalManager.Handle find() {
            return actual.find();
        }

        public NativePrincipalManager.Handle prepare(NativePrincipalManager.Selection selection) {
            return actual.prepare(selection);
        }

        public boolean commit(NativePrincipalManager.Handle handle) {
            boolean result = actual.commit(handle);
            committed = true;
            commits++;
            if (kind.equals("error")) throw new InjectedError("reply lost after the writer returned");
            if (kind.equals("exception")) throw new IllegalStateException("wrapper failure after the writer returned");
            return result;
        }

        public NativePrincipalPins.Record identity(NativePrincipalManager.Handle handle) {
            if (committed && kind.equals("observation")) throw new IllegalStateException("observation unavailable");
            return actual.identity(handle);
        }

        public NativePrincipalPins.Phase phase(NativePrincipalManager.Handle handle) {
            return actual.phase(handle);
        }
    }

    private static void check(boolean ok, String problem) {
        if (!ok) throw new AssertionError(problem);
    }

    private static NativePrincipalWriterFixture install(NativePrincipalWriterFixture fixture) throws Exception {
        // Host only, as in the existing transcript bridge: the new system server's fixture. The
        // helper itself forbids reflection and is not changed.
        var field = NativePrincipalWriterFixture.class.getDeclaredField("service");
        field.setAccessible(true);
        field.set(null, fixture);
        return fixture;
    }

    private static String encode(String text) {
        return Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8));
    }

    // One actual fixture command, printed once under its label with the issued operation,
    // instance and nonce, as the controller's ledger records them.
    private static void reply(String label, String... args) {
        if (!LABELS.add(label)) throw new AssertionError("replayed operation label " + label);
        StringWriter output = new StringWriter(), errors = new StringWriter();
        int code = NativePrincipalWriterFixture.command(new PrintWriter(output), new PrintWriter(errors), args);
        System.out.println(String.join("\t", "REPLY", label, args[0], args.length == 3 ? args[1] : "-",
                args.length == 3 ? args[2] : "-", Integer.toString(code), encode(output.toString()),
                encode(errors.toString())));
    }

    // A command whose reply the controller never receives. Its issued ledger record is printed
    // before it is sent; the reply itself is never printed or assessed.
    private static void lost(String label, String... args) {
        if (!LABELS.add(label)) throw new AssertionError("replayed operation label " + label);
        System.out.println(String.join("\t", "ISSUED", label, args[0], args[1], args[2]));
        NativePrincipalWriterFixture.command(new PrintWriter(new StringWriter()), new PrintWriter(new StringWriter()), args);
    }

    // Observed modes of the live store, kept apart from the byte copies, which carry no modes.
    private static String json(Map<String, String> values) {
        StringBuilder out = new StringBuilder("{");
        for (Map.Entry<String, String> entry : values.entrySet()) {
            if (out.length() > 1) out.append(',');
            out.append('"').append(entry.getKey()).append("\":\"").append(entry.getValue()).append('"');
        }
        return out.append('}').toString();
    }

    private static String cli(String... args) throws Exception {
        PrintStream saved = System.out;
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        try (PrintStream redirected = new PrintStream(captured, true, StandardCharsets.UTF_8)) {
            System.setOut(redirected);
            LabHistoryStore.main(args);
        } finally {
            System.setOut(saved);
        }
        return captured.toString(StandardCharsets.UTF_8).trim();
    }

    // One fresh owned empty version 1 store through the lab generator; returns its lineage.
    private static String generate(Path store, boolean print) throws Exception {
        String manifest = cli("empty-v1", store.toString());
        Matcher matcher = Pattern.compile("\"lineage\":\"([0-9a-f]{32})\"").matcher(manifest);
        check(matcher.find(), "generator manifest");
        if (print) System.out.println("CONTEXT\tgeneration\t" + manifest);
        return matcher.group(1);
    }

    // The facade's cold boot of this store: packages read first at their existing app IDs.
    private static PackageManagerService boot(Path store) {
        PackageManagerService pm = new PackageManagerService(store, false, NativeIdentityStore.Format.V2);
        pm.mSettings.add(SUBJECT, APP_ID);
        pm.mSettings.restoreAfterPackageSettings();
        return pm;
    }

    private static String mode(Path path) throws IOException {
        return PosixFilePermissions.toString(Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS));
    }

    private static void chmod(Path path, String mode) throws IOException {
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(mode));
        check(mode(path).equals(mode), "mode of " + path);
    }

    // Real read and search of this directory: listing works and a missing child is a genuine
    // absence, not an access refusal. Creates nothing.
    private static boolean readAndSearch(Path directory) throws IOException {
        try (Stream<Path> entries = Files.list(directory)) {
            entries.count();
        }
        try {
            Files.readAttributes(directory.resolve(Integer.toString(APP_ID)), BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS);
            return false;
        } catch (NoSuchFileException absent) {
            return true;
        }
    }

    // Unprivileged discretionary access control, with no override or read search capability.
    private static void requireUnprivilegedDac(Path work) throws Exception {
        Matcher capabilities = Pattern.compile("(?m)^CapEff:\\s*([0-9a-f]+)$")
                .matcher(Files.readString(Path.of("/proc/self/status")));
        check(capabilities.find() && (Long.parseUnsignedLong(capabilities.group(1), 16) & 6L) == 0,
                "DAC override or read search capability present");
        Path probe = Files.createDirectory(work.resolve("dac-probe"));
        chmod(probe, "r-x------");
        boolean refused = false;
        try {
            check(readAndSearch(probe), "read and search of a read only directory");
            try {
                Files.createDirectory(probe.resolve("created"));
            } catch (AccessDeniedException expected) {
                refused = true;
            }
        } finally {
            chmod(probe, "rwx------");
        }
        check(refused, "unprivileged DAC did not refuse creation; a root or capability bypass is no coverage");
        System.out.println("PASS unprivileged DAC refuses creation and keeps read and search");
    }

    // The whole store tree: exactly these regular files with these bytes, these directories and
    // nothing else. No link, hard link alias, special node, backup, seed or extra slot directory.
    private static void exactTree(Path root, Map<String, byte[]> files, Set<String> directories) throws IOException {
        Map<String, byte[]> found = new TreeMap<>();
        Set<String> folders = new TreeSet<>();
        Set<Object> keys = new HashSet<>();
        try (Stream<Path> paths = Files.walk(root)) {
            Iterator<Path> iterator = paths.iterator();
            while (iterator.hasNext()) {
                Path path = iterator.next();
                BasicFileAttributes attributes = Files.readAttributes(path, BasicFileAttributes.class,
                        LinkOption.NOFOLLOW_LINKS);
                String name = root.relativize(path).toString();
                if (attributes.isDirectory()) {
                    folders.add(name);
                } else if (attributes.isRegularFile() && attributes.fileKey() != null && keys.add(attributes.fileKey())) {
                    found.put(name, Files.readAllBytes(path));
                } else {
                    throw new AssertionError("link, alias or special node in the store: " + name);
                }
            }
        }
        check(folders.equals(new TreeSet<>(directories)), "store directories " + folders);
        check(found.keySet().equals(new TreeSet<>(files.keySet())), "store files " + found.keySet());
        for (Map.Entry<String, byte[]> entry : files.entrySet()) {
            check(Arrays.equals(entry.getValue(), found.get(entry.getKey())), "store bytes of " + entry.getKey());
        }
    }

    private static void headerOnly(Path store, byte[] header) throws IOException {
        exactTree(store, Map.of("store.bin", header, "store.bin.reservecopy", header), Set.of("", "slots"));
    }

    // A byte copy of the store tree for the observers and the restart controls. It is a byte
    // oracle only: modes, owners and labels are not copied, and the copy proves no durability.
    private static void snapshot(Path store, Path copy) throws IOException {
        try (Stream<Path> paths = Files.walk(store)) {
            for (Path path : paths.toList()) {
                Path target = copy.resolve(store.relativize(path).toString());
                if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) Files.createDirectory(target);
                else Files.copy(path, target, LinkOption.NOFOLLOW_LINKS);
            }
        }
    }

    private static boolean empty(Path directory) throws IOException {
        try (Stream<Path> entries = Files.list(directory)) {
            return entries.findAny().isEmpty();
        }
    }

    public static void main(String[] args) throws Exception {
        if (!NativeWriterLabRehearsal.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        if (args.length != 1) throw new IllegalArgumentException("fresh work directory required");
        Path work = Path.of(args[0]);
        check(work.isAbsolute() && Files.isDirectory(work, LinkOption.NOFOLLOW_LINKS)
                && work.toRealPath().equals(work) && empty(work), "fresh real work directory");
        requireUnprivilegedDac(work);
        LocalServices.addService(UserManagerInternal.class, new UserManagerInternal());
        Binder.callerUid = 0;
        System.out.println("CONTEXT\tselected\t{\"app_id\":" + APP_ID + ",\"user_id\":0,\"user_serial\":" + SERIAL
                + ",\"version_code\":1,\"signer_sha256\":\"" + SIGNERS.iterator().next() + "\"}");
        byte[] creating = mainArm(work);
        lostReply(work);
        for (String[] fault : new String[][]{{"error", ERROR, ERROR_NONCE}, {"exception", EXCEPTION, EXCEPTION_NONCE},
                {"observation", OBSERVATION, OBSERVATION_NONCE}}) {
            faultArm(work, fault[0], fault[1], fault[2]);
        }
        fallbackControl(work, creating);
        changedSignerControl(work, creating);
        System.out.println("DONE\tLab V2 header only host rehearsal passed; Android route unqualified");
    }

    private static byte[] mainArm(Path work) throws Exception {
        // P2: one fresh owned empty version 1 store with a known lineage.
        Path store = work.resolve("store");
        Path slots = store.resolve("slots");
        Path snapshots = Files.createDirectory(work.resolve("snapshots"));
        Map<String, String> modes = new TreeMap<>();
        String lineage = generate(store, true);
        byte[] empty = LabHistoryStore.emptyHeader(lineage);
        headerOnly(store, empty);
        modes.put("p2-root", mode(store));
        modes.put("p2-slots", mode(slots));
        snapshot(store, snapshots.resolve("empty"));
        PackageManagerService pm = boot(store);
        NativePrincipalManager manager = new NativePrincipalManager(pm);
        check(pm.mSettings.pins.reservedAppIds().isEmpty() && pm.mSettings.pins.hasKnownCounter()
                && pm.mSettings.pins.snapshotForWrite().lastId == 0 && pm.mSettings.nativePrincipalCreationReadyLPr(),
                "fresh store boot");
        install(new NativePrincipalWriterFixture(manager, FIRST, SIGNERS));
        reply("info", "info");
        reply("select", "select-new", FIRST, ORIGINAL);
        reply("prepare", "prepare", FIRST, ORIGINAL);
        NativePrincipalManager.Handle original = manager.find(SUBJECT, 0);
        check(original != null && manager.identity(original).equals(RECORD)
                && manager.phase(original) == NativePrincipalPins.Phase.PENDING, "prepared original record");
        headerOnly(store, empty);

        // P3: the slot root keeps real unprivileged read and search but refuses creation.
        check(mode(slots).equals("rwx------"), "original slot root mode");
        chmod(slots, "r-x------");
        check(readAndSearch(slots), "read and search of the slot root");
        modes.put("p3-slots", mode(slots));
        Os.forbiddenMonitor = pm.mLock;
        reply("commit", "commit", FIRST, ORIGINAL);
        Os.forbiddenMonitor = null;
        check(manager.find(SUBJECT, 0) == original && manager.phase(original) == NativePrincipalPins.Phase.PENDING,
                "the original handle left pending");
        // Header and filesystem bytes, observed apart from the reply.
        byte[] creating = LabHistoryStore.creatingHeader(lineage, APP_ID, SERIAL, SIGNERS);
        headerOnly(store, creating);
        snapshot(store, snapshots.resolve("creating"));
        System.out.println("PASS the first commit returns false after a complete CREATING header without a body");

        // Reconciliation and retained ownership. No retry before the cold restart.
        reply("status", "status", FIRST, ORIGINAL);
        reply("other-nonce", "status", FIRST, OTHER);
        reply("select-again", "select-new", FIRST, ORIGINAL);
        reply("prepare-after-commit", "prepare", FIRST, ORIGINAL);
        headerOnly(store, creating);
        snapshot(store, work.resolve("fallback-store"));
        snapshot(store, work.resolve("changed-store"));

        // P5: modeled cold restart. A new facade, manager and fixture instance.
        PackageManagerService rebooted = boot(store);
        NativePrincipalManager restored = new NativePrincipalManager(rebooted);
        NativeIdentityStore.History history = rebooted.mSettings.mNativeIdentityLoaded.history(APP_ID);
        check(history != null && history.source == NativeIdentityStore.Source.RESERVATION
                && NativeIdentityPersistence.identifies(history, RECORD) && history.lineage.equals(lineage)
                && history.signerSha256.equals(SIGNERS) && !history.retiring, "restored reservation history");
        NativePrincipalManager.Handle stored = restored.find(SUBJECT, 0);
        check(stored != null && restored.identity(stored).equals(RECORD)
                && restored.phase(stored) == NativePrincipalPins.Phase.PENDING
                && rebooted.mSettings.pins.snapshotForWrite().lastId == 1
                && rebooted.mSettings.pins.reservedAppIds().equals(Set.of(APP_ID)), "restored PENDING under counter 1");
        NativePrincipalWriterFixture second = install(new NativePrincipalWriterFixture(restored, SECOND, SIGNERS));
        reply("rebind-info", "info");
        reply("stale-status", "status", FIRST, ORIGINAL);
        reply("stale-commit", "commit", FIRST, ORIGINAL);
        headerOnly(store, creating);
        // The owned fault protocol: capture the persisted slot root mode, then restore exactly the
        // original mode while the new fixture is idle, before select-rebind, and capture it.
        String persisted = mode(slots);
        check(persisted.equals("r-x------"), "persisted slot root mode");
        modes.put("p5-slots-persisted", persisted);
        String idle = second.snapshot("status");
        check(idle.contains("\"busy\":false") && idle.contains("\"attempt\":0"), "idle fixture");
        chmod(slots, "rwx------");
        modes.put("p5-slots-restored", mode(slots));
        reply("rebind-select", "select-rebind", SECOND, REBIND);
        reply("rebind-prepare", "prepare", SECOND, REBIND);
        check(restored.find(SUBJECT, 0) == stored && restored.phase(stored) == NativePrincipalPins.Phase.PENDING,
                "the same restored handle");
        Os.forbiddenMonitor = rebooted.mLock;
        reply("rebind-commit", "commit", SECOND, REBIND);
        Os.forbiddenMonitor = null;
        reply("rebind-status", "status", SECOND, REBIND);
        check(restored.phase(stored) == NativePrincipalPins.Phase.ACTIVE && restored.currentIdentity(stored).equals(RECORD),
                "the rebound original ID");

        // P6: generation 1 body and LIVE header under counter 1, with the original signers.
        byte[] live = LabHistoryStore.liveHeader(lineage, APP_ID);
        byte[] body = LabHistoryStore.body(lineage, APP_ID, SERIAL, SIGNERS);
        String slot = "slots/" + APP_ID;
        Map<String, byte[]> published = Map.of("store.bin", live, "store.bin.reservecopy", live,
                slot + "/record.bin", body, slot + "/record.bin.reservecopy", body);
        exactTree(store, published, Set.of("", "slots", slot));
        modes.put("p6-slot", mode(store.resolve(slot)));
        snapshot(store, snapshots.resolve("live"));
        System.out.println("PASS an explicit rebind after the cold restart publishes the original ID");

        // P7: a cold reopening reads the body and restores the same original ID PENDING.
        PackageManagerService reopened = boot(store);
        NativeIdentityStore.History body1 = reopened.mSettings.mNativeIdentityLoaded.history(APP_ID);
        NativePrincipalPins.Pin pin = reopened.mSettings.pins.find(SUBJECT, 0);
        check(body1 != null && body1.source == NativeIdentityStore.Source.BODY
                && NativeIdentityPersistence.identifies(body1, RECORD) && body1.signerSha256.equals(SIGNERS)
                && pin != null && pin.record().equals(RECORD) && pin.phase() == NativePrincipalPins.Phase.PENDING
                && reopened.mSettings.pins.snapshotForWrite().lastId == 1, "reopened body restores PENDING");
        exactTree(store, published, Set.of("", "slots", slot));
        System.out.println("PASS a cold reopening restores the body PENDING with the original ID");
        System.out.println("CONTEXT\tmodes\t" + json(modes));
        System.out.println("CONTEXT\tprediction\t" + LabHistoryStore.predict(work.resolve("host-prediction"), lineage,
                APP_ID, SERIAL, 1, SIGNERS));
        return creating;
    }

    // The commit reply is lost. Explicit status reconciliation with the original request remains.
    private static void lostReply(Path work) throws Exception {
        Path store = work.resolve("lost-store");
        String lineage = generate(store, false);
        PackageManagerService pm = boot(store);
        install(new NativePrincipalWriterFixture(new NativePrincipalManager(pm), LOST, SIGNERS));
        reply("lost-info", "info");
        reply("lost-select", "select-new", LOST, LOST_NONCE);
        reply("lost-prepare", "prepare", LOST, LOST_NONCE);
        Path slots = store.resolve("slots");
        chmod(slots, "r-x------");
        lost("lost-commit", "commit", LOST, LOST_NONCE);
        reply("lost-status", "status", LOST, LOST_NONCE);
        headerOnly(store, LabHistoryStore.creatingHeader(lineage, APP_ID, SERIAL, SIGNERS));
        chmod(slots, "rwx------");
        System.out.println("PASS a lost commit reply keeps its original request for status reconciliation");
    }

    // A wrapper failure after the actual writer returned false: the reply is unknown, effects exist.
    private static void faultArm(Path work, String kind, String instance, String nonce) throws Exception {
        Path store = work.resolve(kind + "-store");
        String lineage = generate(store, false);
        PackageManagerService pm = boot(store);
        NativePrincipalManager manager = new NativePrincipalManager(pm);
        Fault calls = new Fault(manager, kind);
        install(new NativePrincipalWriterFixture(calls, instance, SIGNERS));
        reply(kind + "-info", "info");
        reply(kind + "-select", "select-new", instance, nonce);
        reply(kind + "-prepare", "prepare", instance, nonce);
        Path slots = store.resolve("slots");
        chmod(slots, "r-x------");
        reply(kind + "-commit", "commit", instance, nonce);
        reply(kind + "-status", "status", instance, nonce);
        check(calls.commits == 1, "the writer ran once");
        NativePrincipalManager.Handle handle = manager.find(SUBJECT, 0);
        check(handle != null && manager.identity(handle).equals(RECORD)
                && manager.phase(handle) == NativePrincipalPins.Phase.PENDING, kind + " kept the original pending pin");
        headerOnly(store, LabHistoryStore.creatingHeader(lineage, APP_ID, SERIAL, SIGNERS));
        chmod(slots, "rwx------");
        System.out.println("PASS the " + kind + " wrapper fault keeps the reservation and an unknown reply");
    }

    // After the restart a new selection is refused, and nothing issues or initializes.
    private static void fallbackControl(Path work, byte[] creating) throws Exception {
        Path store = work.resolve("fallback-store");
        PackageManagerService pm = boot(store);
        NativePrincipalManager manager = new NativePrincipalManager(pm);
        install(new NativePrincipalWriterFixture(manager, FALLBACK, SIGNERS));
        reply("fallback-info", "info");
        reply("fallback-select", "select-new", FALLBACK, FALLBACK_NONCE);
        reply("fallback-prepare", "prepare", FALLBACK, FALLBACK_NONCE);
        NativePrincipalManager.Handle handle = manager.find(SUBJECT, 0);
        check(handle != null && manager.identity(handle).equals(RECORD)
                && manager.phase(handle) == NativePrincipalPins.Phase.PENDING
                && pm.mSettings.pins.snapshotForWrite().lastId == 1
                && pm.mSettings.store.pendingInitializationNames().isEmpty(), "no new issuance or initialization");
        headerOnly(store, creating);
        System.out.println("PASS no select-new fallback or initializer after the restart");
    }

    // A changed APK signer cannot rebind: the history keeps its original signers.
    private static void changedSignerControl(Path work, byte[] creating) throws Exception {
        Path store = work.resolve("changed-store");
        PackageManagerService pm = new PackageManagerService(store, false, NativeIdentityStore.Format.V2);
        PackageSetting setting = pm.mSettings.add(SUBJECT, APP_ID);
        setting.signing = new SigningDetails(new Signature(new byte[]{9}));
        pm.mSettings.restoreAfterPackageSettings();
        NativePrincipalManager manager = new NativePrincipalManager(pm);
        // The fixture's own signer check admits the changed APK, so the manager's history decides.
        Set<String> changed = NativePrincipalManager.signerDigests(setting.getSigningDetails());
        check(!changed.equals(SIGNERS), "changed signer");
        install(new NativePrincipalWriterFixture(manager, CHANGED, changed));
        reply("changed-info", "info");
        reply("changed-select", "select-rebind", CHANGED, CHANGED_NONCE);
        reply("changed-prepare", "prepare", CHANGED, CHANGED_NONCE);
        reply("changed-commit", "commit", CHANGED, CHANGED_NONCE);
        NativePrincipalManager.Handle handle = manager.find(SUBJECT, 0);
        check(handle != null && manager.identity(handle).equals(RECORD)
                && manager.phase(handle) == NativePrincipalPins.Phase.PENDING
                && pm.mSettings.pins.snapshotForWrite().lastId == 1, "the changed signer changed the pin");
        headerOnly(store, creating);
        System.out.println("PASS a changed APK signer refuses the rebind without taking APK history");
    }
}
