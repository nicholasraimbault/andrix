// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeHeaderTestSupport.*;

import android.content.pm.Signature;
import android.content.pm.SigningDetails;
import com.android.server.pm.NativeIdentityRecords.CreationBinding;
import com.android.server.pm.NativeIdentityRecords.Header;
import com.android.server.pm.NativeIdentityRecords.HeaderEntry;
import com.android.server.pm.NativeIdentityRecords.SlotPhase;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Host fixtures of the creation binding tests, which run only against the creation plan
 * sources: explicit store formats, version 2 values, owned plans, facades of either format,
 * independently computed golden encodings and real unprivileged permission refusals. The
 * shared header footprint fixtures come from NativeHeaderTestSupport. Host files only, not
 * Android persistence, SELinux or crash qualification.
 */
final class NativeBindingTestSupport {
    static final NativeIdentityStore.Format V1 = NativeIdentityStore.Format.V1;
    static final NativeIdentityStore.Format V2 = NativeIdentityStore.Format.V2;
    static final Header OLD = header(0);
    static final Header PENDING_B = header(1, creating(B, 1, PKG_B));
    // Computed from the documented layout by a separate Python encoder, not by this codec:
    // lineage LINEAGE, the facade's user 0 serial 7 and its one installed signer digest.
    static final byte[] GOLDEN_EMPTY_V1 = hex("4158494401000100460000000123456789abcdef0123456789abcdef"
            + "00000000000000000000ec471413e123122c80585ce4f8dcd7c9550a69af7372693e0c0f7888b210fc8d");
    static final byte[] GOLDEN_PENDING_B_V1 = hex("4158494401000100610000000123456789abcdef0123456789abcdef"
            + "01000000000000000100102700000101000000000000000c006465762e616e647269782e622b59610b"
            + "ef6d16305905e05e936f79131c49682513705a61235788c0f89e3207");
    static final byte[] GOLDEN_LIVE_B_V1 = hex("4158494401000100550000000123456789abcdef0123456789abcdef"
            + "01000000000000000100102700000200000000000000000000ee62893b4103728e4715d37869c15296"
            + "8066f4266b40b8175debbce1919f1076");
    static final byte[] GOLDEN_PENDING_B_V2 = hex("4158494401000200900000000123456789abcdef0123456789abcdef"
            + "01000000000000000100102700000101000000000000000c006465762e616e647269782e6201000000"
            + "0007000000000000000100039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011c"
            + "fb81a37e4e24dc3aa39a886ee562f3cbfb230f93fefb43c789b8d41d05d64e115dfc");
    static final byte[] GOLDEN_LEGACY_B_BOUND_C_V2 = hex("4158494401000200ac0000000123456789abcdef"
            + "0123456789abcdef02000000000000000200102700000101000000000000000c006465762e616e6472"
            + "69782e6200112700000102000000000000000c006465762e616e647269782e63010000000007000000"
            + "000000000100039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81acc0d7"
            + "0b7e088bdda9058f1aa5a477c15dc25ed2327b871a9228647d4b337c16");
    // A directory whose entries can be read but not added or removed.
    static final String READ_ONLY = "r-x------";

    interface Call<T> { T run() throws Exception; }

    static byte[] hex(String text) {
        return HexFormat.of().parseHex(text);
    }

    static CreationBinding binding(Set<String> signers) {
        return new CreationBinding(0, SERIAL, signers);
    }
    static HeaderEntry boundCreating(int appId, long id, String name) {
        return boundCreating(appId, id, name, SIGNERS);
    }
    static HeaderEntry boundCreating(int appId, long id, String name, Set<String> signers) {
        return new HeaderEntry(appId, SlotPhase.CREATING, id, name, binding(signers));
    }
    // A version 2 header, entries in app ID order whatever order a case lists them in.
    static Header v2(long lastId, HeaderEntry... entries) {
        List<HeaderEntry> sorted = new ArrayList<>(List.of(entries));
        sorted.sort(Comparator.comparingInt(entry -> entry.appId));
        return Header.newV2(LINEAGE, lastId, sorted);
    }

    static NativeIdentityStore storeOf(Path root, NativeIdentityStore.Format format) {
        return new NativeIdentityStore(root.toFile(), format);
    }
    static NativeIdentityPersistence persistenceOf(Path root, NativeIdentityStore.Format format) {
        return new NativeIdentityPersistence(storeOf(root, format));
    }
    static NativeIdentityStore.Loaded loadedOf(Path root, NativeIdentityStore.Format format) {
        return storeOf(root, format).load();
    }
    static Header storedOf(Path root, NativeIdentityStore.Format format) {
        return loadedOf(root, format).header.value;
    }
    static NativeIdentityPersistence.CreationPlan plan(NativePrincipalPins.Snapshot snapshot,
            Map<Long, Set<String>> rows) {
        return new NativeIdentityPersistence.CreationPlan(snapshot, rows);
    }
    static boolean sameBytes(Path file, byte[] expected) throws Exception {
        return Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)
                && Arrays.equals(Files.readAllBytes(file), expected);
    }

    // A live PMS facade of this format over a new store, with the subject packages installed.
    static PackageManagerService livePmOf(NativeIdentityStore.Format format) throws Exception {
        PackageManagerService pm = new PackageManagerService(fresh(), true, format);
        pm.mSettings.add(PKG_B, B);
        pm.mSettings.add(PKG_C, C);
        pm.mSettings.add(PKG_A, A);
        return pm;
    }
    // A new PMS facade of this format over the same files: package settings, then the store.
    static PackageManagerService reopenOf(Path root, NativeIdentityStore.Format format,
            Map<String, Integer> packages) {
        PackageManagerService pm = new PackageManagerService(root, false, format);
        for (Map.Entry<String, Integer> entry : new TreeMap<>(packages).entrySet()) {
            pm.mSettings.add(entry.getKey(), entry.getValue());
        }
        pm.mSettings.restoreAfterPackageSettings();
        return pm;
    }
    // A reopened registry of this format restores exactly this counter, or none when negative.
    static void bootCounterOf(List<String> problems, Path root, NativeIdentityStore.Format format,
            long counter) {
        PackageManagerService pm = reopenOf(root, format, Map.of());
        boolean known = pm.mSettings.pins.hasKnownCounter();
        if (counter < 0) {
            check(problems, !known, format + " reopened registry restored a counter");
        } else {
            check(problems, known && pm.mSettings.pins.snapshotForWrite().lastId == counter,
                    format + " reopened registry did not restore counter " + counter);
        }
        check(problems, pm.mSettings.nativePrincipalCreationReadyLPr() == (counter >= 0),
                format + " reopened creation readiness " + (counter < 0));
    }
    // What an older writer leaves under a live facade: its preferred backup still holds prior.
    static void legacyReservation(PackageManagerService pm, Header prior, Header next)
            throws Exception {
        copies(pm.mSettings.root, bytes(prior), bytes(next), bytes(next));
        observe(pm);
    }

    // Signing details of count distinct signatures, and the digests the manager derives.
    static SigningDetails signing(int seed, int count) {
        Signature[] signatures = new Signature[count];
        for (int i = 0; i < count; i++) {
            signatures[i] = new Signature(new byte[] {(byte) seed, (byte) i, 42});
        }
        return new SigningDetails(signatures);
    }
    static Set<String> digests(SigningDetails details) {
        return NativePrincipalManager.signerDigests(details);
    }
    // A valid package name of exactly this length: two segments of ASCII letters.
    static String packageName(int length, char fill) {
        if (length < 5 || length > 255) throw new IllegalArgumentException("package name length");
        return "dev." + String.valueOf(fill).repeat(length - 4);
    }

    // Only this path's own mode changes, only for the call, restored even when the call fails.
    static <T> T restricted(Path path, String mode, Call<T> call) throws Exception {
        Set<PosixFilePermission> original = Files.getPosixFilePermissions(path,
                LinkOption.NOFOLLOW_LINKS);
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(mode));
        try {
            return call.run();
        } finally {
            Files.setPosixFilePermissions(path, original);
        }
    }
    // Slot directory creation must be refused by real unprivileged permissions. A root or
    // capability bypass would make every refused publication vacuous.
    static void requireDac(Path directory) throws Exception {
        Path probe = Files.createDirectories(directory.resolve("dac-probe"));
        boolean refused = restricted(probe, READ_ONLY, () -> {
            try {
                Files.createDirectory(probe.resolve("child"));
                return false;
            } catch (AccessDeniedException expected) {
                return true;
            }
        });
        if (!refused) {
            throw new AssertionError("creation binding controls need unprivileged DAC; a root or"
                    + " capability bypass is not coverage");
        }
        System.out.println("Unprivileged DAC refused the read only namespace probe");
    }

    // The same bytes under another declared version, still an intact frame.
    static byte[] relabeled(byte[] record, int version) throws Exception {
        byte[] bytes = record.clone();
        bytes[6] = (byte) version;
        bytes[7] = (byte) (version >>> 8);
        return resealed(bytes);
    }
    // The checksum of changed bytes recomputed, so they remain an intact frame.
    static byte[] resealed(byte[] record) throws Exception {
        byte[] bytes = record.clone();
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(
                Arrays.copyOf(bytes, bytes.length - 32));
        System.arraycopy(digest, 0, bytes, bytes.length - 32, 32);
        return bytes;
    }
    // An intact frame of any declared type and version around this body.
    static byte[] frame(int type, int version, byte[] body) throws Exception {
        int length = 12 + body.length + 32;
        byte[] bytes = new byte[length];
        int magic = 0x44495841;
        for (int i = 0; i < 4; i++) bytes[i] = (byte) (magic >>> (8 * i));
        bytes[4] = (byte) type;
        bytes[5] = (byte) (type >>> 8);
        bytes[6] = (byte) version;
        bytes[7] = (byte) (version >>> 8);
        for (int i = 0; i < 4; i++) bytes[8 + i] = (byte) (length >>> (8 * i));
        System.arraycopy(body, 0, bytes, 12, body.length);
        return resealed(bytes);
    }
    static byte[] body(byte[] record) {
        return Arrays.copyOfRange(record, 12, record.length - 32);
    }

    // True when the call throws this type, false when it returns or throws another.
    static boolean throwsType(Call<?> call, Class<? extends Throwable> type) {
        try {
            call.run();
            return false;
        } catch (Throwable thrown) {
            return type.isInstance(thrown);
        }
    }

    private NativeBindingTestSupport() {}
}
