// SPDX-License-Identifier: Apache-2.0
import com.android.server.pm.NativeIdentityRecords;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/** Controlled future header inputs, not a supported writer, migration or designation. */
public final class FutureHeaderFixture {
    public static void main(String[] args) throws Exception {
        if (args.length != 7) throw new IllegalArgumentException("output uid serial package signer lineage mode");
        Path root = Path.of(args[0]);
        if (!root.isAbsolute() || !root.normalize().equals(root)
                || !root.getParent().toRealPath().equals(root.getParent())
                || !args[3].equals("dev.andrix.proof.uidstore")
                || !Set.of("header-only", "with-body", "mixed-backup").contains(args[6])) {
            throw new IllegalArgumentException("controlled fixture scope required");
        }
        int appId = Integer.parseInt(args[1]);
        long serial = Long.parseLong(args[2]);
        NativeIdentityRecords.CreationBinding binding = new NativeIdentityRecords.CreationBinding(0, serial, Set.of(args[4]));
        NativeIdentityRecords.Header header = NativeIdentityRecords.Header.newV2(args[5], 1, List.of(
                new NativeIdentityRecords.HeaderEntry(appId, NativeIdentityRecords.SlotPhase.CREATING, 1, args[3], binding)));
        NativeIdentityRecords.Slot slot = new NativeIdentityRecords.Slot(args[5], appId, args[3], 1,
                Set.of(args[4]), List.of(new NativeIdentityRecords.UserEntry(1, 0, serial, false)));
        byte[] headerBytes = NativeIdentityRecords.encodeHeader(header);
        byte[] slotBytes = NativeIdentityRecords.encodeSlot(slot);
        byte[] older = NativeIdentityRecords.encodeHeader(new NativeIdentityRecords.Header(args[5], 0, List.of()));
        Files.createDirectory(root); // Refuse any existing or unknown prior output.
        Path slots = Files.createDirectory(root.resolve("slots"));
        Files.write(root.resolve("store.bin"), headerBytes);
        Files.write(root.resolve("store.bin.reservecopy"), headerBytes);
        if (args[6].equals("mixed-backup")) Files.write(root.resolve("store.bin-backup"), older);
        if (args[6].equals("with-body")) {
            Path directory = Files.createDirectory(slots.resolve(Integer.toString(appId)));
            Files.write(directory.resolve("record.bin"), slotBytes);
            Files.write(directory.resolve("record.bin.reservecopy"), slotBytes);
        }
        System.out.println("Controlled unsupported header fixture only; no writer, binding or execution authority");
    }
}
