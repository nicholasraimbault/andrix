// SPDX-License-Identifier: Apache-2.0
import com.android.server.pm.NativeIdentityRecords;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/**
 * Fresh disposable test metadata only. Inputs must come from actual PMS and APK observations.
 * These bytes are not production designation, a live lease, or a durability test of the writer.
 */
public final class FixtureStore {
    public static void main(String[] args) throws Exception {
        if (args.length != 6) throw new IllegalArgumentException("output uid serial package signer lineage");
        Path output = Path.of(args[0]);
        int uid = Integer.parseInt(args[1]);
        long serial = Long.parseLong(args[2]);
        NativeIdentityRecords.Slot slot = new NativeIdentityRecords.Slot(args[5], uid, args[3], 1,
                Set.of(args[4]), List.of(new NativeIdentityRecords.UserEntry(1, 0, serial, false)));
        NativeIdentityRecords.Header header = new NativeIdentityRecords.Header(args[5], 1,
                List.of(new NativeIdentityRecords.HeaderEntry(uid, NativeIdentityRecords.SlotPhase.LIVE, 0, "")));
        Files.createDirectory(output); // Refuse an existing output, including a prior unknown attempt.
        Path slots = Files.createDirectory(output.resolve("slots"));
        Path directory = Files.createDirectory(slots.resolve(Integer.toString(uid)));
        byte[] record = NativeIdentityRecords.encodeSlot(slot), index = NativeIdentityRecords.encodeHeader(header);
        Files.write(output.resolve("store.bin"), index);
        Files.write(output.resolve("store.bin.reservecopy"), index);
        Files.write(directory.resolve("record.bin"), record);
        Files.write(directory.resolve("record.bin.reservecopy"), record);
        System.out.println("Controlled fixture metadata only; no designation, live authority or runtime qualification");
    }
}
