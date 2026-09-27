// SPDX-License-Identifier: Apache-2.0
import com.android.server.pm.NativeIdentityRecords;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Set;

public final class FutureHeaderFixtureTest {
    public static void main(String[] ignored) throws Exception {
        if (!FutureHeaderFixtureTest.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        Path parent = Files.createTempDirectory("future-header-");
        String lineage = "a".repeat(32), signer = "b".repeat(64), pkg = "dev.andrix.proof.uidstore";
        for (String mode : Set.of("header-only", "with-body", "mixed-backup")) {
            Path root = parent.resolve(mode);
            String[] args = {root.toString(), "10123", "7", pkg, signer, lineage, mode};
            FutureHeaderFixture.main(args);
            byte[] bytes = Files.readAllBytes(root.resolve("store.bin"));
            NativeIdentityRecords.Header header = NativeIdentityRecords.decodeHeader(bytes);
            assert header.version == 2 && header.lastId == 1 && header.entries.size() == 1;
            assert header.entries.get(0).appId == 10123;
            assert header.entries.get(0).creationBinding.userSerial == 7;
            assert header.entries.get(0).creationBinding.signerSha256.equals(Set.of(signer));
            assert Arrays.equals(bytes, Files.readAllBytes(root.resolve("store.bin.reservecopy")));
            if (mode.equals("mixed-backup")) {
                var old = NativeIdentityRecords.decodeHeader(Files.readAllBytes(root.resolve("store.bin-backup")));
                assert old.version == 1 && old.lastId == 0 && old.entries.isEmpty();
            } else assert !Files.exists(root.resolve("store.bin-backup"));
            if (mode.equals("with-body")) {
                var slot = NativeIdentityRecords.decodeSlot(Files.readAllBytes(root.resolve("slots/10123/record.bin")));
                assert slot.appId == 10123 && slot.users.get(0).id == 1 && slot.users.get(0).userSerial == 7;
            } else try (var files = Files.list(root.resolve("slots"))) { assert files.findAny().isEmpty(); }
            try { FutureHeaderFixture.main(args); throw new AssertionError("existing output overwritten"); }
            catch (java.nio.file.FileAlreadyExistsException expected) { }
            assert Arrays.equals(bytes, Files.readAllBytes(root.resolve("store.bin")));
        }
        Path denied = parent.resolve("denied");
        try { FutureHeaderFixture.main(new String[]{denied.toString(), "10123", "7", "dev.other", signer, lineage, "header-only"}); throw new AssertionError("foreign package accepted"); }
        catch (IllegalArgumentException expected) { }
        assert !Files.exists(denied);
    }
}
