// SPDX-License-Identifier: Apache-2.0
import com.android.server.pm.NativeIdentityRecords;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/** Actual codec and finite host layouts, not Android state or native authority. */
public final class HeaderFootprintFixtureTest {
    private interface Operation { void run() throws Exception; }

    private static void refused(Operation operation) throws Exception {
        try {
            operation.run();
        } catch (IllegalArgumentException | java.io.IOException expected) {
            return;
        }
        throw new AssertionError("fixture unexpectedly accepted");
    }

    private static NativeIdentityRecords.Header read(Path root, String name) throws Exception {
        return NativeIdentityRecords.decodeHeader(Files.readAllBytes(root.resolve(name)));
    }

    public static void main(String[] args) throws Exception {
        if (!HeaderFootprintFixtureTest.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        Path parent = Files.createTempDirectory("header-reader-fixture-").toRealPath();
        for (int id : new int[]{10000, 10123, 19999}) {
            NativeIdentityRecords.Header empty = new NativeIdentityRecords.Header(
                    HeaderFootprintFixture.LINEAGE, 0, List.of());
            NativeIdentityRecords.Header expected = new NativeIdentityRecords.Header(
                    HeaderFootprintFixture.LINEAGE, 1,
                    List.of(new NativeIdentityRecords.HeaderEntry(id,
                            NativeIdentityRecords.SlotPhase.CREATING, 1,
                            HeaderFootprintFixture.PACKAGE)));
            for (String mode : HeaderFootprintFixture.MODES) {
                Path output = parent.resolve(mode + "-" + id);
                HeaderFootprintFixture.main(new String[]{output.toString(), Integer.toString(id), mode});
                try (var paths = Files.list(output)) {
                    assert paths.map(p -> p.getFileName().toString()).collect(Collectors.toSet())
                            .equals(Set.of("slots", "store.bin", "store.bin.reservecopy", "store.bin-backup"));
                }
                try (var paths = Files.list(output.resolve("slots"))) { assert paths.findAny().isEmpty(); }
                NativeIdentityRecords.Header main = read(output, "store.bin");
                NativeIdentityRecords.Header reserve = read(output, "store.bin.reservecopy");
                NativeIdentityRecords.Header backup = read(output, "store.bin-backup");
                assert main.version == 1 && reserve.version == 1 && backup.version == 1;
                assert main.equals(reserve);
                assert main.equals(mode.equals("protected-predecessors") ? empty : expected);
                assert backup.equals(mode.equals("legacy-addition") ? empty : expected);
                assert expected.entries.get(0).creationBinding == null;
                byte[] before = Files.readAllBytes(output.resolve("store.bin"));
                refused(() -> HeaderFootprintFixture.main(new String[]{output.toString(), "10123", mode}));
                assert java.util.Arrays.equals(before, Files.readAllBytes(output.resolve("store.bin")));
            }
        }
        for (String id : List.of("9999", "20000", "-1", "+10000", "010000", "1", "abc", " 10000")) {
            Path output = parent.resolve("bad-id-" + Math.abs(id.hashCode()));
            refused(() -> HeaderFootprintFixture.main(new String[]{output.toString(), id, "legacy-addition"}));
            assert !Files.exists(output);
        }
        Path wrongMode = parent.resolve("wrong-mode");
        refused(() -> HeaderFootprintFixture.main(new String[]{wrongMode.toString(), "10123", "with-body"}));
        assert !Files.exists(wrongMode);
        refused(() -> HeaderFootprintFixture.main(new String[]{"relative-output", "10123", "legacy-addition"}));
        refused(() -> HeaderFootprintFixture.main(new String[]{parent.resolve("a/../bad").toString(), "10123", "legacy-addition"}));
        refused(() -> HeaderFootprintFixture.main(new String[]{parent.resolve("missing/out").toString(), "10123", "legacy-addition"}));
        refused(() -> HeaderFootprintFixture.main(new String[]{parent.toString(), "10123"}));
        Path alias = parent.resolve("alias");
        Files.createSymbolicLink(alias, parent);
        refused(() -> HeaderFootprintFixture.main(new String[]{alias.resolve("out").toString(), "10123", "legacy-addition"}));
        assert !Files.exists(parent.resolve("out"));
        Path existing = parent.resolve("existing-file");
        Files.writeString(existing, "original");
        refused(() -> HeaderFootprintFixture.main(new String[]{existing.toString(), "10123", "legacy-addition"}));
        assert Files.readString(existing).equals("original");
        Path finalLink = parent.resolve("final-link");
        Files.createSymbolicLink(finalLink, parent.resolve("missing-target"));
        refused(() -> HeaderFootprintFixture.main(new String[]{finalLink.toString(), "10123", "legacy-addition"}));
        assert Files.isSymbolicLink(finalLink) && !Files.exists(parent.resolve("missing-target"));
        System.out.println("Header reader fixture host controls passed; Android and authority unqualified");
    }
}
