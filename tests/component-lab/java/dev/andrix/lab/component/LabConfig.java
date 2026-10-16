// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

/**
 * The bridge's durable configuration, written once by the lab driver at admission and read by every
 * coordinator generation. Its SHA-256 is in the broker's admission and in every HELLO, so a reopened
 * generation runs with the same installation, component, coordinator, trust policy, source manifest
 * and store, and no command line can quietly change one of them. Exactly these lines, in order,
 * each ending with a newline:
 *
 * <pre>
 * andrix-lab-bridge 1
 * installation &lt;32 hexadecimal digits&gt;
 * component &lt;package&gt;
 * coordinator &lt;32 hexadecimal digits&gt;
 * trust &lt;64 hexadecimal digits&gt;
 * manifest &lt;64 hexadecimal digits&gt;
 * store &lt;absolute path of the deployment store&gt;
 * </pre>
 *
 * Version 2, which the lab driver writes, has the header {@code andrix-lab-bridge 2} and one more line,
 * {@code host <64 hexadecimal digits>}: the SHA-256 of the lab host configuration that a generation
 * must use. The admission that binds this file's digest so binds the host configuration too.
 *
 * <p>Version 3, the next campaign profile's, has the header {@code andrix-lab-bridge 3}, version
 * 2's lines and one more, {@code profile <name>}, exactly the profile its version 3 admission
 * names. Its bridge speaks protocol version 2, and only it.
 */
public final class LabConfig {
    public static final String HEADER = "andrix-lab-bridge 1";
    public static final String HEADER_2 = "andrix-lab-bridge 2";
    public static final String HEADER_3 = "andrix-lab-bridge 3";
    /** The one profile a version 3 configuration names. */
    public static final String PROFILE = "d5-next-vehicle-1";
    private static final List<String> KEYS = Arrays.asList("installation", "component", "coordinator", "trust",
            "manifest", "store");
    private static final List<String> KEYS_2 = Arrays.asList("installation", "component", "coordinator", "trust",
            "manifest", "store", "host");
    private static final List<String> KEYS_3 = Arrays.asList("installation", "component", "coordinator", "trust",
            "manifest", "store", "host", "profile");

    public final String installation;
    public final String component;
    public final String coordinator;
    public final String trustPolicy;
    public final String manifest;
    public final Path store;
    /** The lab host configuration's SHA-256 in versions 2 and 3, null in version 1. */
    public final String host;
    /** The profile in version 3, null before. */
    public final String profile;
    /** The protocol version this configuration's generation speaks: 2 for version 3, else 1. */
    public final int protocol;
    /** SHA-256 of the exact file bytes. */
    public final String digest;

    private LabConfig(String[] values, String digest) {
        this.installation = values[0];
        this.component = values[1];
        this.coordinator = values[2];
        this.trustPolicy = values[3];
        this.manifest = values[4];
        this.store = Paths.get(values[5]);
        this.host = values.length > 6 ? values[6] : null;
        this.profile = values.length > 7 ? values[7] : null;
        this.protocol = profile != null ? LabProtocol.VERSION_2 : LabProtocol.VERSION;
        this.digest = digest;
    }

    /** The configuration a file holds, read without following a link. */
    public static LabConfig read(Path path) throws IOException {
        if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("the configuration is not a regular file");
        }
        byte[] data = Files.readAllBytes(path);
        if (data.length > 4096) throw new IOException("the configuration is too large");
        return parse(data);
    }

    /** The configuration exact bytes hold. */
    public static LabConfig parse(byte[] data) {
        for (byte b : data) {
            if (b != '\n' && (b < 0x20 || b > 0x7e)) throw new IllegalArgumentException("not printable ASCII");
        }
        String text = new String(data, StandardCharsets.US_ASCII);
        if (!text.endsWith("\n")) throw new IllegalArgumentException("the last line has no newline");
        String[] lines = text.substring(0, text.length() - 1).split("\n", -1);
        List<String> keys = lines.length > 0 && lines[0].equals(HEADER_2) ? KEYS_2
                : lines.length > 0 && lines[0].equals(HEADER_3) ? KEYS_3 : KEYS;
        if (lines.length != keys.size() + 1
                || !(lines[0].equals(HEADER) || lines[0].equals(HEADER_2) || lines[0].equals(HEADER_3))) {
            throw new IllegalArgumentException("not a version 1, 2 or 3 bridge configuration");
        }
        String[] values = new String[keys.size()];
        for (int i = 0; i < keys.size(); i++) {
            String prefix = keys.get(i) + " ";
            String line = lines[i + 1];
            if (!line.startsWith(prefix) || line.length() == prefix.length()) {
                throw new IllegalArgumentException("line " + (i + 2) + " is not " + keys.get(i));
            }
            values[i] = line.substring(prefix.length());
        }
        LabProtocol.checkHex(values[0], 16, "installation", false);
        LabProtocol.checkPackage(values[1], "component");
        LabProtocol.checkHex(values[2], 16, "coordinator", false);
        LabProtocol.checkHex(values[3], 32, "trust", false);
        LabProtocol.checkHex(values[4], 32, "manifest", false);
        Path store = Paths.get(values[5]);
        if (!store.isAbsolute() || !store.normalize().equals(store) || values[5].contains(" ")) {
            throw new IllegalArgumentException("the store is an absolute normal path without spaces");
        }
        if (values.length > 6) LabProtocol.checkHex(values[6], 32, "host", false);
        if (values.length > 7 && !values[7].equals(PROFILE)) throw new IllegalArgumentException("another profile");
        return new LabConfig(values, LabProtocol.sha256Hex(data));
    }

    /** The one encoding of a configuration with these values. */
    public static byte[] encode(String installation, String component, String coordinator, String trust,
            String manifest, Path store) {
        String text = HEADER + "\ninstallation " + installation + "\ncomponent " + component + "\ncoordinator "
                + coordinator + "\ntrust " + trust + "\nmanifest " + manifest + "\nstore " + store + "\n";
        byte[] data = text.getBytes(StandardCharsets.US_ASCII);
        parse(data);
        return data;
    }

    /** The one version 2 encoding: version 1's values and the lab host configuration's SHA-256. */
    public static byte[] encode(String installation, String component, String coordinator, String trust,
            String manifest, Path store, String host) {
        String text = HEADER_2 + "\ninstallation " + installation + "\ncomponent " + component + "\ncoordinator "
                + coordinator + "\ntrust " + trust + "\nmanifest " + manifest + "\nstore " + store + "\nhost " + host + "\n";
        byte[] data = text.getBytes(StandardCharsets.US_ASCII);
        parse(data);
        return data;
    }

    /** The one version 3 encoding: version 2's values and the next campaign profile. */
    public static byte[] encode(String installation, String component, String coordinator, String trust,
            String manifest, Path store, String host, String profile) {
        String text = HEADER_3 + "\ninstallation " + installation + "\ncomponent " + component + "\ncoordinator "
                + coordinator + "\ntrust " + trust + "\nmanifest " + manifest + "\nstore " + store + "\nhost " + host
                + "\nprofile " + profile + "\n";
        byte[] data = text.getBytes(StandardCharsets.US_ASCII);
        parse(data);
        return data;
    }
}
