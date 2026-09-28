// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import dev.andrix.proof.nativelab.LabHistoryStore;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Host controls of the lab store generator and predictor over the actual record codec and the
 * actual store initialization. Not Android state, designation or authority.
 */
public final class LabHistoryStoreTest {
    // Independent goldens, computed from the documented record layout without this codec.
    private static final String LINEAGE = "00112233445566778899aabbccddeeff";
    private static final int APP_ID = 10148;
    private static final long SERIAL = 7;
    private static final String EMPTY_SHA256 = "7ce97c1c6c3a54b91001c260292ea594c7af3d638d5bf83f4aef3c098c0926ad";
    private static final int EMPTY_BYTES = 70;
    private static final String CREATING_SHA256 = "e22c3933a1aac12acec7227646e8fb1f4727bbe6d1c44084b60f8addef501106";
    private static final int CREATING_BYTES = 164;
    private static final String LIVE_SHA256 = "e8aad44f5ce866b017532810bef045f07ba96dec6db5453e12e75a36d1f6d9a0";
    private static final int LIVE_BYTES = 85;
    private static final String BODY_SHA256 = "fd36d085d7d7acf46425eda8852ab3a783748e0a95a76eea0e31b62d1e9f2121";
    private static final int BODY_BYTES = 163;
    private static final Set<String> STORE = Set.of("slots", "store.bin", "store.bin.reservecopy");
    private static final Set<String> PREDICTION = Set.of("prediction.json", "v2-creating-header.bin",
            "v2-live-header.bin", "v2-slot-body.bin");

    private interface Operation {
        void run() throws Exception;
    }

    private static void check(boolean ok, String problem) {
        if (!ok) throw new AssertionError(problem);
    }

    private static void refused(Operation operation, String what) throws Exception {
        try {
            operation.run();
        } catch (IllegalArgumentException | IOException expected) {
            return;
        }
        throw new AssertionError("accepted " + what);
    }

    // The command line's own output, captured without changing its behavior.
    private static String cli(String... args) throws Exception {
        PrintStream saved = System.out;
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        try (PrintStream redirected = new PrintStream(captured, true, StandardCharsets.UTF_8)) {
            System.setOut(redirected);
            LabHistoryStore.main(args);
        } finally {
            System.setOut(saved);
        }
        return captured.toString(StandardCharsets.UTF_8).trim();
    }

    private static String field(String json, String name) {
        Matcher matcher = Pattern.compile("\"" + name + "\":\"([^\"]*)\"").matcher(json);
        check(matcher.find(), "missing field " + name);
        return matcher.group(1);
    }

    private static Set<String> entries(Path directory) throws IOException {
        Set<String> names = new TreeSet<>();
        try (Stream<Path> paths = Files.list(directory)) {
            for (Path path : paths.toList()) names.add(path.getFileName().toString());
        }
        return names;
    }

    private static String mode(Path path) throws IOException {
        return PosixFilePermissions.toString(Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS));
    }

    private static Path store(Path root, byte[] header, byte[] body) throws IOException {
        Files.createDirectories(root.resolve("slots"));
        Files.write(root.resolve("store.bin"), header);
        Files.write(root.resolve("store.bin.reservecopy"), header);
        if (body != null) {
            Path slot = Files.createDirectory(root.resolve("slots/" + APP_ID));
            Files.write(slot.resolve("record.bin"), body);
            Files.write(slot.resolve("record.bin.reservecopy"), body);
        }
        return root;
    }

    public static void main(String[] args) throws Exception {
        if (!LabHistoryStoreTest.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        if (args.length != 1) throw new IllegalArgumentException("fresh work directory required");
        Path work = Path.of(args[0]);
        check(work.isAbsolute() && Files.isDirectory(work, LinkOption.NOFOLLOW_LINKS)
                && work.toRealPath().equals(work) && entries(work).isEmpty(), "fresh real work directory");
        Set<String> signers = Set.of(LabHistoryStore.FIXTURE_SIGNER);

        // Goldens and exact sizes.
        byte[] empty = LabHistoryStore.emptyHeader(LINEAGE);
        byte[] creating = LabHistoryStore.creatingHeader(LINEAGE, APP_ID, SERIAL, signers);
        byte[] live = LabHistoryStore.liveHeader(LINEAGE, APP_ID);
        byte[] body = LabHistoryStore.body(LINEAGE, APP_ID, SERIAL, signers);
        check(empty.length == EMPTY_BYTES && LabHistoryStore.sha256(empty).equals(EMPTY_SHA256), "empty golden");
        check(creating.length == CREATING_BYTES && LabHistoryStore.sha256(creating).equals(CREATING_SHA256),
                "creating golden");
        check(live.length == LIVE_BYTES && LabHistoryStore.sha256(live).equals(LIVE_SHA256), "live golden");
        check(body.length == BODY_BYTES && LabHistoryStore.sha256(body).equals(BODY_SHA256), "body golden");
        System.out.println("PASS golden bytes and sizes");

        // Round trips through the actual decoder, with every field.
        NativeIdentityRecords.Header emptyValue = NativeIdentityRecords.decodeHeader(empty);
        check(emptyValue.version == 1 && emptyValue.equals(new NativeIdentityRecords.Header(LINEAGE, 0, List.of()))
                && Arrays.equals(NativeIdentityRecords.encodeHeader(emptyValue), empty), "empty round trip");
        NativeIdentityRecords.Header creatingValue = NativeIdentityRecords.decodeHeader(creating);
        NativeIdentityRecords.HeaderEntry entry = creatingValue.entries.get(0);
        check(creatingValue.version == 2 && creatingValue.lastId == 1 && creatingValue.entries.size() == 1
                && creatingValue.lineage.equals(LINEAGE) && entry.appId == APP_ID
                && entry.phase == NativeIdentityRecords.SlotPhase.CREATING && entry.creationId == 1
                && entry.creationPackage.equals(LabHistoryStore.SUBJECT) && entry.creationBinding != null
                && entry.creationBinding.userId == 0 && entry.creationBinding.userSerial == SERIAL
                && entry.creationBinding.signerSha256.equals(signers)
                && Arrays.equals(NativeIdentityRecords.encodeHeader(creatingValue), creating), "creating round trip");
        NativeIdentityRecords.Header liveValue = NativeIdentityRecords.decodeHeader(live);
        check(liveValue.version == 2 && liveValue.lastId == 1 && liveValue.lineage.equals(LINEAGE)
                && liveValue.entries.equals(List.of(new NativeIdentityRecords.HeaderEntry(APP_ID,
                        NativeIdentityRecords.SlotPhase.LIVE, 0, "")))
                && Arrays.equals(NativeIdentityRecords.encodeHeader(liveValue), live), "live round trip");
        NativeIdentityRecords.Slot bodyValue = NativeIdentityRecords.decodeSlot(body);
        check(bodyValue.equals(new NativeIdentityRecords.Slot(LINEAGE, APP_ID, LabHistoryStore.SUBJECT, 1, signers,
                List.of(new NativeIdentityRecords.UserEntry(1, 0, SERIAL, false))))
                && Arrays.equals(NativeIdentityRecords.encodeSlot(bodyValue), body), "body round trip");
        System.out.println("PASS actual codec round trips");

        // The generator's bytes equal the store's own initialization of the same fresh lineage.
        Path generated = work.resolve("generated");
        String manifest = cli("empty-v1", generated.toString());
        String lineage = field(manifest, "lineage");
        byte[] expected = LabHistoryStore.emptyHeader(lineage);
        check(manifest.equals("{\"version\":1,\"mode\":\"empty-v1\",\"format\":\"V1\",\"lab_input_only\":true,"
                + "\"authority\":false,\"lineage\":\"" + lineage + "\",\"header_sha256\":\""
                + LabHistoryStore.sha256(expected) + "\",\"header_bytes\":70,\"entries\":[\"slots\","
                + "\"store.bin\",\"store.bin.reservecopy\"]}"), "generator manifest " + manifest);
        Path initialized = work.resolve("initialized");
        check(new NativeIdentityStore(initialized.toFile(), NativeIdentityStore.Format.V1).initializeNew(lineage),
                "store initialization");
        for (String name : List.of("store.bin", "store.bin.reservecopy")) {
            check(Arrays.equals(Files.readAllBytes(generated.resolve(name)), expected)
                    && Arrays.equals(Files.readAllBytes(initialized.resolve(name)), expected),
                    "generated " + name + " differs from initialization");
        }
        check(entries(generated).equals(STORE) && entries(initialized).equals(STORE)
                && entries(generated.resolve("slots")).isEmpty() && entries(initialized.resolve("slots")).isEmpty(),
                "generated entries differ from initialization");
        check(mode(generated).equals("rwx------") && mode(generated.resolve("slots")).equals("rwx------")
                && mode(generated.resolve("store.bin")).equals("rw-------")
                && mode(generated.resolve("store.bin.reservecopy")).equals("rw-------"), "generated modes");
        for (NativeIdentityStore.Format format : List.of(NativeIdentityStore.Format.V1, NativeIdentityStore.Format.V2)) {
            NativeIdentityStore.Loaded loaded = new NativeIdentityStore(generated.toFile(), format).load();
            check(loaded.creationReady() && loaded.counterRestorable()
                    && loaded.header.value.equals(new NativeIdentityRecords.Header(lineage, 0, List.of()))
                    && loaded.occupiedAppIds.isEmpty() && loaded.histories().isEmpty(),
                    format + " reading of the generated store");
        }
        check(!field(cli("empty-v1", work.resolve("second").toString()), "lineage").equals(lineage),
                "lineage is not fresh");
        System.out.println("PASS empty version 1 input equals store initialization");

        // Predictions through the command line, in files that are no store layout.
        Path prediction = work.resolve("prediction");
        String predicted = cli("predict-v2", prediction.toString(), LINEAGE, Integer.toString(APP_ID),
                Long.toString(SERIAL), "1");
        check(entries(prediction).equals(PREDICTION)
                && Arrays.equals(Files.readAllBytes(prediction.resolve("v2-creating-header.bin")), creating)
                && Arrays.equals(Files.readAllBytes(prediction.resolve("v2-live-header.bin")), live)
                && Arrays.equals(Files.readAllBytes(prediction.resolve("v2-slot-body.bin")), body)
                && Files.readString(prediction.resolve("prediction.json")).equals(predicted + "\n")
                && predicted.contains("\"signer_sha256\":\"" + LabHistoryStore.FIXTURE_SIGNER + "\"")
                && predicted.contains("\"principal_id\":1,") && predicted.contains("\"prediction_only\":true")
                && predicted.contains("\"v2-creating-header.bin\":{\"sha256\":\"" + CREATING_SHA256 + "\""),
                "predicted files " + predicted);
        System.out.println("PASS predictions equal the goldens");

        // The readers treat the predictions as a header reservation and then a published body.
        Path reservation = store(work.resolve("reservation"), creating, null);
        NativeIdentityStore.Loaded v2 = new NativeIdentityStore(reservation.toFile(), NativeIdentityStore.Format.V2).load();
        NativeIdentityStore.History history = v2.history(APP_ID);
        check(v2.creationReady() && v2.counterRestorable() && history != null
                && history.source == NativeIdentityStore.Source.RESERVATION && history.id == 1
                && history.userId == 0 && history.userSerial == SERIAL && history.signerSha256.equals(signers)
                && history.lineage.equals(LINEAGE) && history.packageName.equals(LabHistoryStore.SUBJECT)
                && !v2.bindingUsable(APP_ID), "V2 reservation history");
        NativeIdentityStore.Loaded v1 = new NativeIdentityStore(reservation.toFile(), NativeIdentityStore.Format.V1).load();
        check(v1.header.status == NativeIdentityStore.Status.UNSUPPORTED && v1.creationBlocked
                && v1.histories().isEmpty() && v1.occupiedAppIds.contains(APP_ID), "V1 keeps the reservation read only");
        Path published = store(work.resolve("published"), live, body);
        NativeIdentityStore.Loaded after = new NativeIdentityStore(published.toFile(), NativeIdentityStore.Format.V2).load();
        check(after.bindingUsable(APP_ID) && after.history(APP_ID) != null
                && after.history(APP_ID).source == NativeIdentityStore.Source.BODY && after.history(APP_ID).id == 1
                && after.counterRestorable(), "V2 published body history");
        System.out.println("PASS readers classify the predictions");

        // Fresh output only: no alias, reuse, overwrite or partial output.
        byte[] before = Files.readAllBytes(generated.resolve("store.bin"));
        refused(() -> LabHistoryStore.main(new String[]{"empty-v1", generated.toString()}), "an existing store");
        check(Arrays.equals(before, Files.readAllBytes(generated.resolve("store.bin")))
                && entries(generated).equals(STORE), "an existing store changed");
        refused(() -> cli("predict-v2", prediction.toString(), LINEAGE, "10148", "7", "1"), "an existing prediction");
        Path partial = Files.createDirectory(work.resolve("partial"));
        refused(() -> LabHistoryStore.main(new String[]{"empty-v1", partial.toString()}), "a partial output");
        check(entries(partial).isEmpty(), "a partial output was reused");
        Path file = Files.writeString(work.resolve("file"), "original");
        refused(() -> LabHistoryStore.main(new String[]{"empty-v1", file.toString()}), "an existing file");
        check(Files.readString(file).equals("original"), "an existing file changed");
        Path dangling = work.resolve("dangling");
        Files.createSymbolicLink(dangling, work.resolve("dangling-target"));
        refused(() -> LabHistoryStore.main(new String[]{"empty-v1", dangling.toString()}), "a final link");
        check(!Files.exists(work.resolve("dangling-target"), LinkOption.NOFOLLOW_LINKS), "a link was followed");
        Path alias = work.resolve("alias");
        Files.createSymbolicLink(alias, work);
        refused(() -> LabHistoryStore.main(new String[]{"empty-v1", alias.resolve("out").toString()}), "an aliased parent");
        check(!Files.exists(work.resolve("out"), LinkOption.NOFOLLOW_LINKS), "output created through an alias");
        for (String value : List.of("relative-output", work + "/a/../b", work + "/missing/out", "")) {
            refused(() -> LabHistoryStore.main(new String[]{"empty-v1", value}), "path " + value);
        }
        check(!Files.exists(work.resolve("b"), LinkOption.NOFOLLOW_LINKS)
                && !Files.exists(work.resolve("missing"), LinkOption.NOFOLLOW_LINKS), "output created for a bad path");
        System.out.println("PASS fresh output paths only");

        // Identifier and mode controls refuse before any output exists.
        Path unused = work.resolve("unused");
        String out = unused.toString();
        String[][] invalid = {
            {"predict-v2", out, LINEAGE.toUpperCase(java.util.Locale.ROOT), "10148", "7", "1"},
            {"predict-v2", out, LINEAGE.substring(1), "10148", "7", "1"},
            {"predict-v2", out, LINEAGE + "0", "10148", "7", "1"},
            {"predict-v2", out, "g" + LINEAGE.substring(1), "10148", "7", "1"},
            {"predict-v2", out, LINEAGE, "9999", "7", "1"}, {"predict-v2", out, LINEAGE, "20000", "7", "1"},
            {"predict-v2", out, LINEAGE, "+10148", "7", "1"}, {"predict-v2", out, LINEAGE, "010148", "7", "1"},
            {"predict-v2", out, LINEAGE, " 10148", "7", "1"}, {"predict-v2", out, LINEAGE, "1e4", "7", "1"},
            {"predict-v2", out, LINEAGE, "10148", "-1", "1"}, {"predict-v2", out, LINEAGE, "10148", "07", "1"},
            {"predict-v2", out, LINEAGE, "10148", "9999999999999999999", "1"},
            {"predict-v2", out, LINEAGE, "10148", "x", "1"},
            {"predict-v2", out, LINEAGE, "10148", "7", "0"}, {"predict-v2", out, LINEAGE, "10148", "7", "2"},
            {"predict-v2", out, LINEAGE, "10148", "7", "01"}, {"predict-v2", out, LINEAGE, "10148", "7", " 1"},
            {"predict-v1", out, LINEAGE, "10148", "7", "1"}, {"empty-v2", out}, {"normal", out}, {"lab", out},
            {"empty-v1"}, {"empty-v1", out, "extra"}, {"predict-v2", out, LINEAGE, "10148", "7"}, {}};
        for (String[] arguments : invalid) {
            refused(() -> LabHistoryStore.main(arguments), String.join(" ", arguments));
            check(!Files.exists(unused, LinkOption.NOFOLLOW_LINKS), "output created for " + String.join(" ", arguments));
        }
        refused(() -> LabHistoryStore.creatingHeader(LINEAGE, 9999, SERIAL, signers), "codec app ID");
        refused(() -> LabHistoryStore.creatingHeader(LINEAGE, APP_ID, -1, signers), "codec serial");
        refused(() -> LabHistoryStore.body(LINEAGE, APP_ID, SERIAL, Set.of("A".repeat(64))), "codec signer");
        refused(() -> LabHistoryStore.predict(unused, LINEAGE, APP_ID, SERIAL, 2, signers), "principal 2");
        check(!Files.exists(unused, LinkOption.NOFOLLOW_LINKS), "output created for a codec refusal");
        System.out.println("PASS identifier and mode controls refuse before output");
        System.out.println("Lab history store fixture host controls passed; Android and authority unqualified");
    }
}
