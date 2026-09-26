// SPDX-License-Identifier: Apache-2.0
import com.android.server.pm.NativeIdentityRecords;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.LinkOption;
import java.nio.file.StandardOpenOption;
import java.nio.ByteBuffer;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/** Exact bounded lab record comparison through the production codec. Not authority or durability proof. */
public final class WriterStoreCheck {
    public static void main(String[] args) throws Exception {
        if (args.length != 8) throw new IllegalArgumentException("root Auid serial Asigner Cuid Csigner lineage Cid");
        Path root = Path.of(args[0]);
        if (!root.isAbsolute() || !root.equals(root.normalize())) throw new IllegalArgumentException("canonical snapshot root");
        for (Path component = root; component != null; component = component.getParent()) {
            if (!Files.readAttributes(component, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS).isDirectory()) {
                throw new IllegalStateException("snapshot ancestor is not a real directory");
            }
        }
        int a = Integer.parseInt(args[1]), c = Integer.parseInt(args[4]);
        long serial = Long.parseLong(args[2]), id = Long.parseLong(args[7]);
        if (a >= c || id != 2) throw new IllegalArgumentException("controlled initial allocator and counter observations required");
        NativeIdentityRecords.Header header = new NativeIdentityRecords.Header(args[6], id, List.of(
                new NativeIdentityRecords.HeaderEntry(a, NativeIdentityRecords.SlotPhase.LIVE, 0, ""),
                new NativeIdentityRecords.HeaderEntry(c, NativeIdentityRecords.SlotPhase.LIVE, 0, "")));
        NativeIdentityRecords.Slot first = new NativeIdentityRecords.Slot(args[6], a,
                "dev.andrix.proof.uidstore", 1, Set.of(args[3]),
                List.of(new NativeIdentityRecords.UserEntry(1, 0, serial, false)));
        NativeIdentityRecords.Slot created = new NativeIdentityRecords.Slot(args[6], c,
                "dev.andrix.proof.principalclosed", 1, Set.of(args[5]),
                List.of(new NativeIdentityRecords.UserEntry(id, 0, serial, false)));
        Set<String> files = Set.of("store.bin", "store.bin.reservecopy", "slots/" + a + "/record.bin",
                "slots/" + a + "/record.bin.reservecopy", "slots/" + c + "/record.bin", "slots/" + c + "/record.bin.reservecopy");
        Set<String> directories = Set.of("", "slots", "slots/" + a, "slots/" + c);
        Set<String> observedFiles = new HashSet<>(), observedDirectories = new HashSet<>();
        Set<Object> fileKeys = new HashSet<>();
        Map<Path, BasicFileAttributes> captured = new HashMap<>();
        try (var paths = Files.walk(root)) { // Does not follow symbolic directories.
            var iterator = paths.iterator();
            while (iterator.hasNext()) {
                Path path = iterator.next();
                var attrs = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                String relative = root.relativize(path).toString();
                if (attrs.isDirectory()) observedDirectories.add(relative);
                else if (attrs.isRegularFile()) {
                    if (attrs.fileKey() == null || !fileKeys.add(attrs.fileKey())) {
                        throw new IllegalStateException("snapshot file identity unavailable or aliased");
                    }
                    observedFiles.add(relative); captured.put(path, attrs);
                }
                else throw new IllegalStateException("snapshot special or symbolic node");
                if (observedFiles.size() > files.size() || observedDirectories.size() > directories.size()) {
                    throw new IllegalStateException("snapshot footprint exceeds controlled case");
                }
            }
        }
        if (!files.equals(observedFiles) || !directories.equals(observedDirectories)) {
            throw new IllegalStateException("unexpected snapshot footprint, backup or missing copy");
        }
        pair(root.resolve("store.bin"), NativeIdentityRecords.encodeHeader(header), captured);
        pair(root.resolve("slots/" + a + "/record.bin"), NativeIdentityRecords.encodeSlot(first), captured);
        pair(root.resolve("slots/" + c + "/record.bin"), NativeIdentityRecords.encodeSlot(created), captured);
        System.out.println("Exact original A and writer C records, lineage, counter and paired copies matched");
    }
    private static void pair(Path main, byte[] expected, Map<Path, BasicFileAttributes> captured) throws Exception {
        for (Path file : List.of(main, Path.of(main + ".reservecopy"))) {
            var before = Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            BasicFileAttributes original = captured.get(file);
            if (!before.isRegularFile() || before.size() != expected.length || original == null
                    || !Objects.equals(before.fileKey(), original.fileKey())
                    || !before.lastModifiedTime().equals(original.lastModifiedTime())) {
                throw new IllegalStateException("controlled writer record type or size differs");
            }
            ByteBuffer bytes = ByteBuffer.allocate(expected.length);
            try (var channel = Files.newByteChannel(file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
                while (bytes.hasRemaining()) {
                    if (channel.read(bytes) <= 0) throw new IllegalStateException("short snapshot read");
                }
                if (channel.size() != expected.length || !Arrays.equals(bytes.array(), expected)) {
                    throw new IllegalStateException("controlled writer record differs");
                }
            }
            var after = Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!after.isRegularFile() || before.size() != after.size()
                    || !Objects.equals(before.fileKey(), after.fileKey())
                    || !before.lastModifiedTime().equals(after.lastModifiedTime())) {
                throw new IllegalStateException("snapshot changed during read");
            }
        }
    }
}
