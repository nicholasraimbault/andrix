// SPDX-License-Identifier: Apache-2.0
import com.android.server.pm.NativeIdentityRecords;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Set;

/** Host generated reader inputs, not a native identity, allocator, repair or durability proof. */
public final class HeaderFootprintFixture {
    static final String LINEAGE = "0123456789abcdef0123456789abcdef";
    static final String PACKAGE = "dev.andrix.proof.headerpending";
    static final Set<String> MODES = Set.of("legacy-addition", "protected-predecessors", "equal-control");

    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("output appId mode");
        Path output = Path.of(args[0]);
        Path parent = output.getParent();
        if (!output.isAbsolute() || !output.normalize().equals(output) || parent == null
                || !parent.toRealPath().equals(parent) || !MODES.contains(args[2])
                || !args[1].matches("1[0-9]{4}")) {
            throw new IllegalArgumentException("fresh host fixture scope required");
        }
        int appId = Integer.parseInt(args[1]);
        byte[] empty = NativeIdentityRecords.encodeHeader(new NativeIdentityRecords.Header(
                LINEAGE, 0, List.of()));
        byte[] reserved = NativeIdentityRecords.encodeHeader(new NativeIdentityRecords.Header(
                LINEAGE, 1, List.of(new NativeIdentityRecords.HeaderEntry(appId,
                        NativeIdentityRecords.SlotPhase.CREATING, 1, PACKAGE))));
        byte[] main = args[2].equals("protected-predecessors") ? empty : reserved;
        byte[] backup = args[2].equals("legacy-addition") ? empty : reserved;
        Files.createDirectory(output); // Existing files, directories and final links refuse.
        Files.createDirectory(output.resolve("slots"));
        // Failure leaves any partial fixture for inspection. No overwrite, cleanup or replay.
        Files.write(output.resolve("store.bin"), main, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        Files.write(output.resolve("store.bin.reservecopy"), main,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        Files.write(output.resolve("store.bin-backup"), backup,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        System.out.println("Controlled V1 header inputs only; no binding, execution or durability authority");
    }
}
