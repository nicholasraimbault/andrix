// SPDX-License-Identifier: Apache-2.0
import com.android.server.pm.NativeIdentityRecords;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/** Canonical negative fixtures only. Never repair, designation or a live authority grant. */
public final class FixtureVariant {
    public static NativeIdentityRecords.Slot variant(NativeIdentityRecords.Slot original, String mode) {
        if (!original.packageName.equals("dev.andrix.proof.uidstore") || original.users.size() != 1
                || original.users.get(0).userId != 0 || original.users.get(0).retiring
                || original.signerSha256.size() != 1) {
            throw new IllegalArgumentException("one ordinary fixture binding required");
        }
        NativeIdentityRecords.UserEntry user = original.users.get(0);
        Set<String> signers = original.signerSha256;
        if (mode.equals("signer")) {
            String different = "0".repeat(64);
            if (signers.contains(different)) different = "f".repeat(64);
            signers = Set.of(different);
        } else if (mode.equals("serial")) {
            user = new NativeIdentityRecords.UserEntry(user.id, user.userId,
                    Math.addExact(user.userSerial, 1), user.retiring);
        } else {
            throw new IllegalArgumentException("unsupported fixture variant");
        }
        return new NativeIdentityRecords.Slot(original.lineage, original.appId, original.packageName,
                original.generation, signers, List.of(user));
    }

    private static byte[] regular(Path path) throws Exception {
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                || Files.size(path) > NativeIdentityRecords.MAX_BYTES) {
            throw new IllegalArgumentException("bounded regular input required");
        }
        return Files.readAllBytes(path);
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("original-root fresh-output signer-or-serial");
        Path input = Path.of(args[0]), output = Path.of(args[1]);
        if (!input.isAbsolute() || !output.isAbsolute() || !input.toRealPath().equals(input.normalize())) {
            throw new IllegalArgumentException("canonical fixture paths required");
        }
        Path resolvedOutput = output.getParent().toRealPath().resolve(output.getFileName()).normalize();
        if (!resolvedOutput.equals(output.normalize()) || resolvedOutput.startsWith(input.toRealPath())) {
            throw new IllegalArgumentException("output must be outside the original fixture");
        }
        byte[] headerBytes = regular(input.resolve("store.bin"));
        if (!Arrays.equals(headerBytes, regular(input.resolve("store.bin.reservecopy")))) {
            throw new IllegalArgumentException("original header copies differ");
        }
        NativeIdentityRecords.Header header = NativeIdentityRecords.decodeHeader(headerBytes);
        if (header.entries.size() != 1 || header.entries.get(0).phase != NativeIdentityRecords.SlotPhase.LIVE) {
            throw new IllegalArgumentException("one established fixture slot required");
        }
        int appId = header.entries.get(0).appId;
        Path directory = input.resolve("slots").resolve(Integer.toString(appId));
        if (!directory.toRealPath().equals(directory.normalize())) {
            throw new IllegalArgumentException("slot path alias");
        }
        byte[] before = regular(directory.resolve("record.bin"));
        if (!Arrays.equals(before, regular(directory.resolve("record.bin.reservecopy")))) {
            throw new IllegalArgumentException("original slot copies differ");
        }
        NativeIdentityRecords.Slot original = NativeIdentityRecords.decodeSlot(before);
        if (original.appId != appId || !original.lineage.equals(header.lineage)
                || original.users.size() != 1 || original.users.get(0).id > header.lastId) {
            throw new IllegalArgumentException("original cross-file binding mismatch");
        }
        NativeIdentityRecords.Slot changed = variant(original, args[2]);
        byte[] after = NativeIdentityRecords.encodeSlot(changed);
        if (!changed.equals(NativeIdentityRecords.decodeSlot(after))) throw new AssertionError("codec round trip");
        // Validate all inputs before writing, and never overwrite an earlier operation.
        Files.createDirectory(output);
        Path slots = Files.createDirectory(output.resolve("slots"));
        Path target = Files.createDirectory(slots.resolve(Integer.toString(appId)));
        Files.write(output.resolve("store.bin"), headerBytes);
        Files.write(output.resolve("store.bin.reservecopy"), headerBytes);
        Files.write(target.resolve("record.bin"), after);
        Files.write(target.resolve("record.bin.reservecopy"), after);
        System.out.println("Canonical single-field negative fixture only; no designation or runtime qualification");
    }
}
