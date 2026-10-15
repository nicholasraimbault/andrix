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
import java.util.Map;
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
    // Each lifecycle guest layout at the fixed values, other app ID 10149, by one digest of its
    // files: each file's path, SHA-256 and length, a line each in path order. The runner holds
    // these to the independent layout oracle.
    private static final int OTHER_ID = 10149;
    private static final Map<String, String> LAYOUT_SHA256 = Map.ofEntries(
            Map.entry("retiring-v1", "0162f96ca342d72939dbb974739f6423deb134f7c92cdfb0657230674be38c6c"),
            Map.entry("v2-slot", "07be4ab36d6dba048cbcbe28e6c4d2f5d1fc81a65c7178a5dfe5a499a91b509a"),
            Map.entry("eligible-v1", "85046f053f0396316c2ef3dcb74aa9e4c7b023a4ac5e68b6ad9aa9b64e42b155"),
            Map.entry("v2-beside-reservation", "a3f841b678e55888ce71d35ecfc63974c37bdc9cf39fde9c6a5e4e177b3d253f"),
            Map.entry("v2-beside-sibling", "6b1ee45c416665689e960fbabbb45980c44bb1a5aa232695a9be100f52ee4205"),
            Map.entry("v2-beside-unrelated-body", "6de53b0219227b4467a347480ee7a4c55dfae2b5be74972e8a090b0d6650d3a9"),
            Map.entry("v2-grant", "41e46d3810e33e31b65244cdaa82f1ee267818cafff7a122c62fbb88c20aab68"),
            Map.entry("v2-scope-1", "bcee1635addd1b40927f68f11d8cfc9f71e136ad4e9e6f3ea8051cf72f368eb7"),
            Map.entry("v2-recovery-hold", "93056da780729ce8bb09cd109c1459587cfdea4e9ef72b7364d2ebef27ef393a"),
            Map.entry("v2-recovery-scope-2", "2c6393c5cb9e1eadaff5f05c0eb1e76950dc8cd344dc875f946d99d4b0cadce7"),
            Map.entry("v2-recovery-scope-3", "ffbc10d7e435322a4a4d5910aa470a7c52e4b821d700a569e414f1b4dc29ca62"),
            Map.entry("v2-noted", "78c2e53f7087922090db38ea4855ec0c8ba5f0bcea5c4dae952d7718995780f1"),
            Map.entry("v2-retiring", "ff0f9824aab08f4784458e7211f9a717e1d64bea7124b867166ce8061c2f19ad"),
            Map.entry("v2-retired", "3a3f330317b80cc80bbaa7f5ecc18ac84e84d78d1da4f500384508399cdb3baf"),
            Map.entry("v2-disposing", "9594eb32f3134be11912bc0139a2800268c75bf78a7089dc03e83bbfdfbc78b4"),
            Map.entry("v2-legacy-suspended", "2fdc5bbb8060c38ca0768f96297da7242f38546e52b5722016971dcf55f59022"),
            Map.entry("legacy-continuation-interrupted",
                    "d86f0a52ada4641730c922438e46ed93afd03a2f5ec98cd06fc2ef2505200585"),
            Map.entry("mixed-suspend-backup", "42f69fbe24e07ecc492b22d5562ba0486eca29d52264744d30cf68c1cd3f63f4"),
            Map.entry("mixed-lift-backup", "33e471f461861964c0f1bbe0bfce23e7f3fe89c13bbb1e0600b4efe0761f3400"),
            Map.entry("mixed-suspend-conflict", "b9f4dadf7f006a37cc5fc6a6b0eda301e5891a0aeb7324f5790f62acb3861074"),
            Map.entry("mixed-lift-conflict", "8ed24d5e4e0e34d80e3b730304dee236dc9815ea83cc00b8993bcc58f8e7583a"),
            Map.entry("tombstone-live", "6d14be4c291f68d2c005440e523a8bba3f9f1919d960398950d905c30c3eec71"),
            Map.entry("tombstone-releasing", "271203ecdb1b768bed9af49b1014326cf60c8245522920e10c06f9890f524f74"),
            Map.entry("releasing-without-directory",
                    "c7c992264b9973e45b1bb49a96205269e5bbea1c8c42063425f1e1e82f7aca0c"),
            Map.entry("maximum-beside-eligible", "538be192e944d68b540be19a5552ec4c7598de862453ae99259d20971eeeabd3"),
            Map.entry("damaged-v2-of-v1", "9267ca3828b3f534def2d3529afcfa5af86c67a7ca8da4680f63c690ed823f85"),
            Map.entry("damaged-retired-unknown-inventory",
                    "b390d76855c4acb1d9bc4b049fb400f8308cc2eefcdd446d55eca6536a31393d"),
            Map.entry("damaged-disposing-work", "62c82eaf73e82b1f7d6398bf7e4d67591e7b234147025426ee162dcb3030c8ab"),
            Map.entry("v3-prefix-valid", "7f459332d9e03f7cad9744d1d54e31e02539134128632f211f7e76f976fa41d5"),
            Map.entry("v3-prefix-broken", "e8c8717277ee9c7b7ecd17ef6f1c1b96e8b173e5a66fc983620ba22832cd21f3"),
            Map.entry("reservation", "f5115a8d6ff76d18925ba2aefa66198c8548f3ae209f190c6b3ac36bfa74b6d7"),
            Map.entry("reservation-wrong-serial", "928c562da8e1a3b96e43c2f7b72e686aabedcebf8873eb424b0017d52158836d"),
            Map.entry("lift-v1", "c8f9b9b86c4892d4290434198cd4d3007aecba958fefdffb9e8ffe063290db59"));
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

    // One digest of a layout: each file's path, SHA-256 and length, a line each in path order.
    private static String layoutDigest(Map<String, byte[]> files) {
        StringBuilder text = new StringBuilder();
        for (Map.Entry<String, byte[]> file : new java.util.TreeMap<>(files).entrySet()) {
            text.append(file.getKey()).append('\t').append(LabHistoryStore.sha256(file.getValue())).append('\t')
                    .append(file.getValue().length).append('\n');
        }
        return LabHistoryStore.sha256(text.toString().getBytes(StandardCharsets.US_ASCII));
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

        // The production format, which the normal image's boot read constructs, reads the generated
        // store, the reservation and the published body as the previous format does.
        NativeIdentityStore.Loaded fresh = new NativeIdentityStore(generated.toFile(), NativeIdentityStore.Format.V3)
                .load();
        check(fresh.creationReady() && fresh.counterRestorable()
                && fresh.header.value.equals(new NativeIdentityRecords.Header(lineage, 0, List.of()))
                && fresh.occupiedAppIds.isEmpty() && fresh.histories().isEmpty(), "V3 reading of the generated store");
        NativeIdentityStore.Loaded v3 = new NativeIdentityStore(reservation.toFile(), NativeIdentityStore.Format.V3)
                .load();
        check(v3.creationReady() && v3.counterRestorable() && history.equals(v3.history(APP_ID))
                && v3.histories().equals(v2.histories()) && v3.occupiedAppIds.equals(v2.occupiedAppIds)
                && !v3.bindingUsable(APP_ID), "V3 reservation history");
        NativeIdentityStore.Loaded published3 = new NativeIdentityStore(published.toFile(),
                NativeIdentityStore.Format.V3).load();
        check(published3.bindingUsable(APP_ID) && published3.history(APP_ID) != null
                && published3.history(APP_ID).equals(after.history(APP_ID)) && published3.counterRestorable()
                && published3.slots.get(APP_ID).value.equals(bodyValue), "V3 published body history");
        System.out.println("PASS the production format reads them as the previous format does");

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

        // Every lifecycle guest layout at the fixed values: its pinned digest, each valid record
        // the codec's own one encoding, each damaged or later version record an intact frame that
        // the codec refuses for its named rule, the later version's stable prefix read or refused,
        // and the largest record exactly as long as its encoding's measure.
        Map<String, String> refusals = Map.of("damaged-v2-of-v1", "version 1 value in a version 2 record",
                "damaged-retired-unknown-inventory", "an unknown inventory only while RETIRING",
                "damaged-disposing-work", "DISPOSING only on a disposition kind",
                "v3-prefix-valid", "unsupported record version", "v3-prefix-broken", "unsupported record version");
        check(LAYOUT_SHA256.keySet().equals(LabHistoryStore.LIFECYCLE_MODES), "layout goldens name every mode");
        for (String mode : new TreeSet<>(LabHistoryStore.LIFECYCLE_MODES)) {
            Map<String, byte[]> files = LabHistoryStore.lifecycleLayout(mode, LINEAGE, APP_ID, OTHER_ID, SERIAL,
                    signers);
            check(layoutDigest(files).equals(LAYOUT_SHA256.get(mode)), "layout golden of " + mode);
            for (Map.Entry<String, byte[]> record : files.entrySet()) {
                byte[] bytes = record.getValue();
                String what = mode + " " + record.getKey();
                if (record.getKey().startsWith("store.bin")) {
                    check(Arrays.equals(NativeIdentityRecords.encodeHeader(NativeIdentityRecords.decodeHeader(bytes)),
                            bytes), "header encoding of " + what);
                } else if (refusals.containsKey(mode)) {
                    String refusal = null;
                    try {
                        NativeIdentityRecords.decodeSlot(bytes);
                    } catch (IllegalArgumentException refused) {
                        refusal = refused.getMessage();
                    }
                    check(refusals.get(mode).equals(refusal), "refusal of " + what + ": " + refusal);
                    check(NativeIdentityRecords.intactSlotVersion(bytes) == (mode.startsWith("v3") ? 3 : 2),
                            "intact frame of " + what);
                } else {
                    NativeIdentityRecords.Slot value = NativeIdentityRecords.decodeSlot(bytes);
                    check(Arrays.equals(NativeIdentityRecords.encodeSlot(value), bytes)
                            && NativeIdentityRecords.encodedSlotLength(value) == bytes.length, "encoding of " + what);
                }
            }
        }
        byte[] prefix = LabHistoryStore.lifecycleLayout("v3-prefix-valid", LINEAGE, APP_ID, OTHER_ID, SERIAL, signers)
                .get("slots/" + APP_ID + "/record.bin");
        NativeIdentityRecords.SlotPrefix read = NativeIdentityRecords.decodeSlotPrefix(prefix);
        check(read.version == 3 && read.packageName.equals(LabHistoryStore.SUBJECT)
                && read.principalIds.equals(List.of(1L)), "the later version's prefix " + read);
        byte[] broken = LabHistoryStore.lifecycleLayout("v3-prefix-broken", LINEAGE, APP_ID, OTHER_ID, SERIAL, signers)
                .get("slots/" + APP_ID + "/record.bin");
        refused(() -> NativeIdentityRecords.decodeSlotPrefix(broken), "a broken prefix");
        byte[] largest = LabHistoryStore.lifecycleLayout("maximum-beside-eligible", LINEAGE, APP_ID, OTHER_ID, SERIAL,
                signers).get("slots/" + OTHER_ID + "/record.bin");
        check(largest.length == 60_941 && NativeIdentityRecords.decodeSlot(largest).users.size() == 64,
                "the largest record takes " + largest.length + " bytes");
        // The lift is restaged over the suspended layout: its header bytes are the suspended
        // layout's.
        check(Arrays.equals(LabHistoryStore.lifecycleLayout("lift-v1", LINEAGE, APP_ID, OTHER_ID, SERIAL, signers)
                .get("store.bin"), LabHistoryStore.lifecycleLayout("v2-slot", LINEAGE, APP_ID, OTHER_ID, SERIAL,
                signers).get("store.bin")), "the lift's header");
        refused(() -> LabHistoryStore.lifecycleLayout("reservation-wrong-serial", LINEAGE, APP_ID, OTHER_ID,
                Long.MAX_VALUE, signers), "a wrong serial past the largest");
        // A layout goes only to a fresh target: an existing one, even a partial earlier attempt, is
        // refused and kept as it was.
        Path layout = work.resolve("layout");
        cli("v2-grant", layout.toString(), LINEAGE, Integer.toString(APP_ID), Long.toString(SERIAL));
        byte[] staged = Files.readAllBytes(layout.resolve("slots/" + APP_ID + "/record.bin"));
        refused(() -> LabHistoryStore.main(new String[] {"v2-grant", layout.toString(), LINEAGE,
                Integer.toString(APP_ID), Long.toString(SERIAL)}), "an existing layout");
        check(Arrays.equals(staged, Files.readAllBytes(layout.resolve("slots/" + APP_ID + "/record.bin"))),
                "an existing layout changed");
        Path attempt = Files.createDirectory(work.resolve("attempt"));
        refused(() -> LabHistoryStore.main(new String[] {"maximum-beside-eligible", attempt.toString(), LINEAGE,
                Integer.toString(APP_ID), Integer.toString(OTHER_ID), Long.toString(SERIAL)}), "a partial attempt");
        check(entries(attempt).isEmpty(), "a partial attempt was reused");
        System.out.println("PASS lifecycle guest layouts equal their goldens and the codec's own reading");
        System.out.println("Lab history store fixture host controls passed; Android and authority unqualified");
    }
}
