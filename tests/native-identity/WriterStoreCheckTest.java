// SPDX-License-Identifier: Apache-2.0
import com.android.server.pm.NativeIdentityRecords;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

public final class WriterStoreCheckTest {
    private static void refused(String[] args) throws Exception {
        try { WriterStoreCheck.main(args); }
        catch (IllegalStateException | IllegalArgumentException | java.io.IOException expected) { return; }
        throw new AssertionError("damaged or out of scope snapshot accepted");
    }
    public static void main(String[] ignored) throws Exception {
        if (!WriterStoreCheckTest.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        Path root = Files.createTempDirectory("writer-codec-");
        String lineage = "a".repeat(32), signerA = "b".repeat(64), signerC = "c".repeat(64);
        String[] args = {root.toString(), "10123", "7", signerA, "10125", signerC, lineage, "2"};
        NativeIdentityRecords.Header header = new NativeIdentityRecords.Header(lineage, 2, List.of(
                new NativeIdentityRecords.HeaderEntry(10123, NativeIdentityRecords.SlotPhase.LIVE, 0, ""),
                new NativeIdentityRecords.HeaderEntry(10125, NativeIdentityRecords.SlotPhase.LIVE, 0, "")));
        byte[] index = NativeIdentityRecords.encodeHeader(header);
        pair(root.resolve("store.bin"), index);
        NativeIdentityRecords.Slot a = new NativeIdentityRecords.Slot(lineage, 10123,
                "dev.andrix.proof.uidstore", 1, Set.of(signerA),
                List.of(new NativeIdentityRecords.UserEntry(1, 0, 7, false)));
        NativeIdentityRecords.Slot c = new NativeIdentityRecords.Slot(lineage, 10125,
                "dev.andrix.proof.principalclosed", 1, Set.of(signerC),
                List.of(new NativeIdentityRecords.UserEntry(2, 0, 7, false)));
        byte[] aBytes = NativeIdentityRecords.encodeSlot(a), cBytes = NativeIdentityRecords.encodeSlot(c);
        pair(root.resolve("slots/10123/record.bin"), aBytes);
        pair(root.resolve("slots/10125/record.bin"), cBytes);
        WriterStoreCheck.main(args);
        for (String file : List.of("store.bin", "store.bin.reservecopy", "slots/10123/record.bin", "slots/10125/record.bin.reservecopy")) {
            Path p = root.resolve(file); byte[] bytes = Files.readAllBytes(p);
            Files.write(p, new byte[]{1, 2}); refused(args); Files.write(p, bytes);
            Files.delete(p); refused(args); Files.write(p, bytes);
        }
        for (String file : List.of("store.bin-backup", "store.bin-seed", "slots/10125/record.bin-backup")) {
            Path p = root.resolve(file); Files.write(p, index); refused(args); Files.delete(p);
        }
        Path extra = Files.createDirectory(root.resolve("slots/10126")); refused(args); Files.delete(extra);
        String[] wrong = args.clone(); wrong[6] = "d".repeat(32); refused(wrong);
        wrong = args.clone(); wrong[3] = signerC; wrong[5] = signerA; refused(wrong);
        wrong = args.clone(); wrong[7] = "3"; refused(wrong);
        wrong = args.clone(); wrong[1] = "10127"; refused(wrong);
        Path reserve = root.resolve("slots/10125/record.bin.reservecopy");
        Files.write(reserve, NativeIdentityRecords.encodeSlot(new NativeIdentityRecords.Slot(lineage, 10125,
                c.packageName, 1, Set.of(signerC), List.of(new NativeIdentityRecords.UserEntry(2, 0, 8, false)))));
        refused(args); Files.write(reserve, cBytes);
        Files.delete(reserve); Files.createSymbolicLink(reserve, root.resolve("slots/10125/record.bin"));
        refused(args); Files.delete(reserve); Files.write(reserve, cBytes);
        Path outside = root.resolveSibling(root.getFileName() + "-slots");
        Files.move(root.resolve("slots"), outside); Files.createSymbolicLink(root.resolve("slots"), outside);
        refused(args); Files.delete(root.resolve("slots")); Files.move(outside, root.resolve("slots"));
        Path alias = root.resolveSibling(root.getFileName() + "-alias"); Files.createSymbolicLink(alias, root);
        wrong = args.clone(); wrong[0] = alias.toString(); refused(wrong); Files.delete(alias);
        WriterStoreCheck.main(args);
    }
    private static void pair(Path main, byte[] data) throws Exception {
        Files.createDirectories(main.getParent());
        Files.write(main, data); Files.write(Path.of(main + ".reservecopy"), data);
    }
}
