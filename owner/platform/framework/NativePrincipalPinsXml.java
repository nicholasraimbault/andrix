// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.util.Xml;
import android.util.Slog;

import com.android.internal.util.XmlUtils;
import com.android.modules.utils.TypedXmlPullParser;
import com.android.modules.utils.TypedXmlSerializer;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;

/** Persistence of UID reservations inside Package Manager's own settings. */
final class NativePrincipalPinsXml {
    static final String TAG = "andrix-native-principals";
    private static final String ENTRY = "principal";
    private static final int VERSION = 1;
    static final int CAPACITY = 64; // Initial implementation bound, not an account product quota.

    static final class Parsed {
        final NativePrincipalPins.Snapshot snapshot;
        final boolean recoveryBlocked;
        Parsed(NativePrincipalPins.Snapshot snapshot, boolean recoveryBlocked) {
            this.snapshot = snapshot;
            this.recoveryBlocked = recoveryBlocked;
        }
    }

    static void write(TypedXmlSerializer out, NativePrincipalPins.Snapshot snapshot,
            boolean recoveryBlocked)
            throws IOException {
        out.startTag(null, TAG);
        out.attributeInt(null, "version", VERSION);
        out.attributeLong(null, "lastId", snapshot.lastId);
        out.attributeBoolean(null, "recoveryBlocked", recoveryBlocked);
        for (NativePrincipalPins.Record record : snapshot.records) {
            out.startTag(null, ENTRY);
            out.attributeLong(null, "id", record.id);
            out.attribute(null, "package", record.packageName);
            out.attributeInt(null, "appId", record.appId);
            out.attributeInt(null, "userId", record.userId);
            out.attributeLong(null, "userSerial", record.userSerial);
            out.attributeBoolean(null, "retiring", snapshot.retiringIds.contains(record.id));
            out.endTag(null, ENTRY);
        }
        out.endTag(null, TAG);
    }

    static Parsed read(TypedXmlPullParser in)
            throws IOException, XmlPullParserException {
        if (!TAG.equals(in.getName()) || in.getAttributeCount() != 3
                || in.getAttributeInt(null, "version") != VERSION) {
            throw new XmlPullParserException("Unsupported native principal settings");
        }
        long last = in.getAttributeLong(null, "lastId");
        boolean recoveryBlocked = in.getAttributeBoolean(null, "recoveryBlocked");
        ArrayList<NativePrincipalPins.Record> records = new ArrayList<>();
        HashSet<Long> retiring = new HashSet<>();
        final int depth = in.getDepth();
        for (;;) {
            int event = in.nextTag();
            if (event == XmlPullParser.END_TAG && in.getDepth() == depth) break;
            if (event != XmlPullParser.START_TAG || !ENTRY.equals(in.getName())
                    || in.getDepth() != depth + 1 || in.getAttributeCount() != 6
                    || records.size() >= CAPACITY) {
                throw new XmlPullParserException("Malformed native principal settings");
            }
            String packageName = in.getAttributeValue(null, "package");
            if (packageName == null) throw new XmlPullParserException("Missing principal package");
            NativePrincipalPins.Record record = new NativePrincipalPins.Record(
                    in.getAttributeLong(null, "id"), packageName,
                    in.getAttributeInt(null, "appId"), in.getAttributeInt(null, "userId"),
                    in.getAttributeLong(null, "userSerial"));
            // The first platform integration deliberately supports only user 0.
            // A user-ID reuse barrier is required before other users are enabled.
            if (record.userId != 0) {
                throw new XmlPullParserException("Unsupported native principal user");
            }
            records.add(record);
            if (in.getAttributeBoolean(null, "retiring")) retiring.add(record.id);
            if (in.nextTag() != XmlPullParser.END_TAG || !ENTRY.equals(in.getName())
                    || in.getDepth() != depth + 1) {
                throw new XmlPullParserException("Nested native principal entry");
            }
        }
        NativePrincipalPins.Snapshot snapshot = new NativePrincipalPins.Snapshot(last, records, retiring);
        // Validate the entire candidate before the real registry is touched.
        NativePrincipalPins check = new NativePrincipalPins(CAPACITY);
        try {
            check.restore(snapshot);
        } catch (IllegalArgumentException | IllegalStateException error) {
            throw new XmlPullParserException("Invalid native principal settings", in, error);
        }
        return new Parsed(snapshot, recoveryBlocked);
    }

    /** Reject only this extension, never the ordinary Package Manager state. */
    static Parsed readForSettings(TypedXmlPullParser in)
            throws IOException, XmlPullParserException {
        int depth = in.getDepth();
        try {
            return read(in);
        } catch (XmlPullParserException | IllegalArgumentException | IllegalStateException error) {
            // Unsupported versions/attributes/users are not corruption of the
            // surrounding package database. Leave its parser at our end tag.
            skipRejectedSection(in, depth);
            Slog.e("NativePrincipalPins", "Native reservation metadata needs recovery", error);
            return new Parsed(new NativePrincipalPins.Snapshot(0, java.util.List.of()), true);
        }
    }

    static void skipRejectedSection(TypedXmlPullParser in, int depth)
            throws IOException, XmlPullParserException {
        int event = in.getEventType();
        while (event != XmlPullParser.END_TAG || in.getDepth() != depth) {
            if (event == XmlPullParser.END_DOCUMENT || in.getDepth() < depth) {
                throw new XmlPullParserException("Truncated native reservation section");
            }
            event = in.next();
        }
    }

    private static Parsed readSettingsFile(File file)
            throws IOException, XmlPullParserException {
        try (FileInputStream input = new FileInputStream(file)) {
            TypedXmlPullParser in = Xml.resolvePullParser(input);
            if (in.nextTag() != XmlPullParser.START_TAG || !"packages".equals(in.getName())) {
                throw new XmlPullParserException("Missing Package Manager settings root");
            }
            Parsed result = null;
            int depth = in.getDepth();
            for (;;) {
                int event = in.nextTag();
                if (event == XmlPullParser.END_TAG && in.getDepth() == depth) break;
                if (event != XmlPullParser.START_TAG || in.getDepth() != depth + 1) {
                    throw new XmlPullParserException("Malformed Package Manager settings");
                }
                if (TAG.equals(in.getName())) {
                    if (result != null) throw new XmlPullParserException("Duplicate native settings");
                    result = read(in);
                } else {
                    XmlUtils.skipCurrentTag(in);
                }
            }
            if (result == null) throw new XmlPullParserException("Native settings not committed");
            for (int event; (event = in.next()) != XmlPullParser.END_DOCUMENT;) {
                if (event != XmlPullParser.TEXT || !in.isWhitespace()) {
                    throw new XmlPullParserException("Trailing Package Manager settings data");
                }
            }
            // Readback verifies the serialization, not durability. The caller
            // must already have checked the original writing descriptors.
            return result;
        }
    }

    /**
     * The normal Settings writer does not return a durability acknowledgement.
     * Before activating or releasing a pin, confirm the exact native records in
     * both recovery copies and absence of the preferred old backup after strict
     * writer completion. A reopened reader cannot acknowledge an earlier writer
     * error. Failure keeps the original pin and its publication outcome pending.
     * Caller holds Package Manager's settings mutation lock throughout.
     */
    static boolean confirm(File main, File reserve, File backup,
            NativePrincipalPins.Snapshot expected) {
        try {
            if (backup.exists()) return false;
            Parsed first = readSettingsFile(main);
            Parsed second = readSettingsFile(reserve);
            if (first.recoveryBlocked || second.recoveryBlocked
                    || !same(first.snapshot, expected) || !same(second.snapshot, expected)) return false;
            FileDescriptor directory = Os.open(main.getParent(),
                    OsConstants.O_RDONLY | OsConstants.O_CLOEXEC, 0);
            try {
                if (!OsConstants.S_ISDIR(Os.fstat(directory).st_mode)) {
                    throw new IOException("Native reservation parent is not a directory");
                }
                Os.fsync(directory);
            } finally {
                Os.close(directory);
            }
            return !backup.exists();
        } catch (IOException | XmlPullParserException | ErrnoException
                | IllegalArgumentException error) {
            return false;
        }
    }

    private static boolean same(NativePrincipalPins.Snapshot a, NativePrincipalPins.Snapshot b) {
        if (a.lastId != b.lastId || a.records.size() != b.records.size()
                || !a.retiringIds.equals(b.retiringIds)) return false;
        // Snapshot order is canonical by ID, not hash-map iteration order.
        for (int index = 0; index < a.records.size(); ++index) {
            NativePrincipalPins.Record x = a.records.get(index), y = b.records.get(index);
            if (x.id != y.id || x.appId != y.appId || x.userId != y.userId
                    || x.userSerial != y.userSerial || !x.packageName.equals(y.packageName)) {
                return false;
            }
        }
        return true;
    }
    private NativePrincipalPinsXml() {}
}
