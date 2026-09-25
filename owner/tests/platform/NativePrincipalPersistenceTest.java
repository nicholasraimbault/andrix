// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import android.os.FileUtils;
import android.system.Os;
import android.util.Xml;
import com.android.modules.utils.TypedXmlSerializer;
import com.android.modules.utils.TypedXmlPullParser;
import com.android.internal.util.XmlUtils;
import org.xmlpull.v1.XmlPullParser;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/** Real host files/writer FDs with text XML and Android API facades, not device durability proof. */
public final class NativePrincipalPersistenceTest {
    private static byte[] xml(NativePrincipalPins.Snapshot snapshot, boolean blocked) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        TypedXmlSerializer out = Xml.serializer(bytes);
        out.startTag(null, "packages");
        out.startTag(null, "package"); out.attribute(null, "name", "unrelated"); out.endTag(null, "package");
        NativePrincipalPinsXml.write(out, snapshot, blocked);
        out.endTag(null, "packages");
        return bytes.toByteArray();
    }
    private static ResilientAtomicFile file(Path directory) {
        return new ResilientAtomicFile(directory.resolve("main").toFile(),
                directory.resolve("backup").toFile(), directory.resolve("reserve").toFile(),
                0600, "native-pin-host", null);
    }
    private static void failure(IoCall call) throws Exception {
        try { call.run(); } catch (IOException expected) { return; }
        throw new AssertionError("I/O failure was not reported");
    }
    private interface IoCall { void run() throws Exception; }
    private static void rejectedExtensionPreservesPackageParsing(
            NativePrincipalPins.Snapshot snapshot) throws Exception {
        String valid = new String(xml(snapshot, false), StandardCharsets.UTF_8);
        String section = valid.substring(valid.indexOf("<andrix-native-principals"),
                valid.indexOf("</andrix-native-principals>") + "</andrix-native-principals>".length());
        for (String rejected : List.of(section.replace("version=\"1\"", "version=\"2\""),
                section.replace("version=\"1\"", "version=\"1\" extra=\"future\""),
                section.replace("userId=\"0\"", "userId=\"1\""),
                section.replace("appId=\"10123\"", "appId=\"0\""))) {
            String settings = "<packages><package name=\"before\"/>" + rejected
                    + "<package name=\"after\"/></packages>";
            TypedXmlPullParser input = Xml.resolvePullParser(new ByteArrayInputStream(
                    settings.getBytes(StandardCharsets.UTF_8)));
            assert input.nextTag() == XmlPullParser.START_TAG;
            assert input.nextTag() == XmlPullParser.START_TAG
                    && "before".equals(input.getAttributeValue(null, "name"));
            XmlUtils.skipCurrentTag(input);
            assert input.nextTag() == XmlPullParser.START_TAG;
            NativePrincipalPinsXml.Parsed result = NativePrincipalPinsXml.readForSettings(input);
            assert result.recoveryBlocked;
            assert input.getEventType() == XmlPullParser.END_TAG
                    && NativePrincipalPinsXml.TAG.equals(input.getName());
            assert input.nextTag() == XmlPullParser.START_TAG
                    && "after".equals(input.getAttributeValue(null, "name"));
            XmlUtils.skipCurrentTag(input);
            assert input.nextTag() == XmlPullParser.END_TAG && "packages".equals(input.getName());
        }
    }

    public static void main(String[] args) throws Exception {
        if (!NativePrincipalPersistenceTest.class.desiredAssertionStatus()) throw new AssertionError("-ea");
        if (args.length != 1) throw new IllegalArgumentException("private temporary directory required");
        Path directory = Path.of(args[0]);
        NativePrincipalPins.Record first = new NativePrincipalPins.Record(1, "dev.andrix.first", 10123, 0, 7);
        NativePrincipalPins.Record second = new NativePrincipalPins.Record(2, "dev.andrix.second", 10124, 0, 7);
        NativePrincipalPins.Snapshot snapshot = new NativePrincipalPins.Snapshot(2, List.of(first, second), Set.of(2L));
        rejectedExtensionPreservesPackageParsing(snapshot);
        Path main = directory.resolve("main"), backup = directory.resolve("backup"), reserve = directory.resolve("reserve");
        Files.writeString(main, "old");
        try (ResilientAtomicFile atomic = file(directory)) {
            FileOutputStream stream = atomic.startWrite();
            stream.write(xml(snapshot, false));
            int unchecked = FileUtils.uncheckedSyncs;
            atomic.finishWriteStrict(stream);
            assert FileUtils.uncheckedSyncs == unchecked; // No swallowed boolean fsync result.
        }
        assert !Files.exists(backup) && Files.mismatch(main, reserve) == -1;
        assert NativePrincipalPinsXml.confirm(main.toFile(), reserve.toFile(), backup.toFile(), snapshot);
        assert !NativePrincipalPinsXml.confirm(main.toFile(), reserve.toFile(), backup.toFile(),
                new NativePrincipalPins.Snapshot(2, List.of(first, second)));
        Files.writeString(backup, "preferred old copy");
        assert !NativePrincipalPinsXml.confirm(main.toFile(), reserve.toFile(), backup.toFile(), snapshot);
        Files.delete(backup);
        for (String bad : List.of("<wrong/>", new String(xml(snapshot, true), StandardCharsets.UTF_8),
                new String(xml(snapshot, false), StandardCharsets.UTF_8).replace("appId=\"10123\"", "appId=\"0\""),
                new String(xml(snapshot, false), StandardCharsets.UTF_8) + "<extra/>")) {
            Files.writeString(main, bad);
            assert !NativePrincipalPinsXml.confirm(main.toFile(), reserve.toFile(), backup.toFile(), snapshot);
        }
        Files.write(main, xml(snapshot, false));
        Files.write(reserve, xml(snapshot, false));

        // Main-writer failure is observed before the recovery copy is retired.
        try (ResilientAtomicFile atomic = file(directory)) {
            FileOutputStream stream = atomic.startWrite();
            stream.write("partial".getBytes(StandardCharsets.UTF_8));
            stream.close(); // Real closed writing descriptor, not a fake success boolean.
            failure(() -> atomic.finishWriteStrict(stream));
        }
        assert Files.exists(backup);
        try (ResilientAtomicFile atomic = file(directory); FileInputStream old = atomic.openRead()) {
            assert java.util.Arrays.equals(old.readAllBytes(), xml(snapshot, false));
        }
        // Restore a normal committed base for the next independent writer failure.
        Files.write(main, xml(snapshot, false)); Files.deleteIfExists(backup);
        try (ResilientAtomicFile atomic = file(directory)) {
            FileOutputStream stream = atomic.startWrite();
            stream.write(xml(snapshot, false));
            Field field = ResilientAtomicFile.class.getDeclaredField("mReserveOutStream");
            field.setAccessible(true); // Host test only, not an Android hidden API exemption.
            ((FileOutputStream) field.get(atomic)).close();
            failure(() -> atomic.finishWriteStrict(stream));
        }
        assert Files.exists(backup);
        Files.deleteIfExists(main); Files.move(backup, main);
        // A directory sync failure remains unknown even when both files match.
        try (ResilientAtomicFile atomic = file(directory)) {
            FileOutputStream stream = atomic.startWrite();
            stream.write(xml(snapshot, false));
            Os.failSync = true;
            failure(() -> atomic.finishWriteStrict(stream));
            assert !NativePrincipalPinsXml.confirm(main.toFile(), reserve.toFile(), backup.toFile(), snapshot);
            Os.failSync = false;
        } finally { Os.failSync = false; }
        assert Os.allClosed();
        System.out.println("Native reservation XML/writer failure controls passed; Android ABX/fs-verity/storage unqualified");
    }
}
