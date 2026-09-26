// SPDX-License-Identifier: Apache-2.0
import com.android.server.pm.NativeIdentityRecords;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

public final class FixtureVariantTest {
    private static final String LINEAGE = "0123456789abcdef0123456789abcdef";
    private static NativeIdentityRecords.Slot original(long serial, String signer) {
        return new NativeIdentityRecords.Slot(LINEAGE, 10123, "dev.andrix.proof.uidstore", 7,
                Set.of(signer), List.of(new NativeIdentityRecords.UserEntry(5, 0, serial, false)));
    }
    private static void sameIdentity(NativeIdentityRecords.Slot a, NativeIdentityRecords.Slot b) {
        assert a.lineage.equals(b.lineage) && a.appId == b.appId && a.packageName.equals(b.packageName);
        assert a.generation == b.generation && a.users.size() == b.users.size();
        assert a.users.get(0).id == b.users.get(0).id && a.users.get(0).userId == b.users.get(0).userId;
        assert a.users.get(0).retiring == b.users.get(0).retiring;
        assert b.equals(NativeIdentityRecords.decodeSlot(NativeIdentityRecords.encodeSlot(b)));
    }
    private static void reject(Runnable action) {
        try { action.run(); }
        catch (IllegalArgumentException | ArithmeticException expected) { return; }
        throw new AssertionError("invalid variant accepted");
    }
    public static void main(String[] args) throws Exception {
        if (!FixtureVariantTest.class.desiredAssertionStatus()) throw new AssertionError("-ea required");
        NativeIdentityRecords.Slot a = original(12, "a".repeat(64));
        NativeIdentityRecords.Slot signer = FixtureVariant.variant(a, "signer");
        sameIdentity(a, signer);
        assert signer.users.equals(a.users) && !signer.signerSha256.equals(a.signerSha256);
        NativeIdentityRecords.Slot serial = FixtureVariant.variant(a, "serial");
        sameIdentity(a, serial);
        assert serial.signerSha256.equals(a.signerSha256) && serial.users.get(0).userSerial == 13;
        assert FixtureVariant.variant(original(12, "0".repeat(64)), "signer").signerSha256.equals(Set.of("f".repeat(64)));
        reject(() -> FixtureVariant.variant(a, "other"));
        reject(() -> FixtureVariant.variant(original(Long.MAX_VALUE, "a".repeat(64)), "serial"));
        Path root = Files.createTempDirectory("identity-variants-");
        try {
            Path input = Files.createDirectory(root.resolve("original"));
            Path slot = Files.createDirectories(input.resolve("slots/10123"));
            byte[] header = NativeIdentityRecords.encodeHeader(new NativeIdentityRecords.Header(LINEAGE, 5,
                    List.of(new NativeIdentityRecords.HeaderEntry(10123, NativeIdentityRecords.SlotPhase.LIVE, 0, ""))));
            byte[] record = NativeIdentityRecords.encodeSlot(a);
            Files.write(input.resolve("store.bin"), header); Files.write(input.resolve("store.bin.reservecopy"), header);
            Files.write(slot.resolve("record.bin"), record); Files.write(slot.resolve("record.bin.reservecopy"), record);
            for (String mode : List.of("signer", "serial")) {
                Path output = root.resolve(mode);
                FixtureVariant.main(new String[]{input.toString(), output.toString(), mode});
                assert Arrays.equals(header, Files.readAllBytes(output.resolve("store.bin")));
                assert Arrays.equals(header, Files.readAllBytes(output.resolve("store.bin.reservecopy")));
                byte[] changed = Files.readAllBytes(output.resolve("slots/10123/record.bin"));
                assert Arrays.equals(changed, Files.readAllBytes(output.resolve("slots/10123/record.bin.reservecopy")));
                assert NativeIdentityRecords.decodeSlot(changed).equals(FixtureVariant.variant(a, mode));
                try { FixtureVariant.main(new String[]{input.toString(), output.toString(), mode}); throw new AssertionError("overwrite"); }
                catch (java.nio.file.FileAlreadyExistsException expected) { }
            }
            Path forbidden = input.resolve("derived");
            try { FixtureVariant.main(new String[]{input.toString(), forbidden.toString(), "serial"}); throw new AssertionError("input mutation"); }
            catch (IllegalArgumentException expected) { }
            assert !Files.exists(forbidden);
            assert Arrays.equals(header, Files.readAllBytes(input.resolve("store.bin")));
            assert Arrays.equals(record, Files.readAllBytes(slot.resolve("record.bin")));
        } finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
        System.out.println("Canonical signer/serial fixture variants passed; Android behavior unqualified");
    }
}
