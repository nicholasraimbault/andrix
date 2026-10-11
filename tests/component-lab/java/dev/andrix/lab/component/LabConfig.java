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
 */
public final class LabConfig {
    public static final String HEADER = "andrix-lab-bridge 1";
    private static final List<String> KEYS = Arrays.asList("installation", "component", "coordinator", "trust",
            "manifest", "store");

    public final String installation;
    public final String component;
    public final String coordinator;
    public final String trustPolicy;
    public final String manifest;
    public final Path store;
    /** SHA-256 of the exact file bytes. */
    public final String digest;

    private LabConfig(String[] values, String digest) {
        this.installation = values[0];
        this.component = values[1];
        this.coordinator = values[2];
        this.trustPolicy = values[3];
        this.manifest = values[4];
        this.store = Paths.get(values[5]);
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
        if (lines.length != KEYS.size() + 1 || !lines[0].equals(HEADER)) {
            throw new IllegalArgumentException("not a version 1 bridge configuration");
        }
        String[] values = new String[KEYS.size()];
        for (int i = 0; i < KEYS.size(); i++) {
            String prefix = KEYS.get(i) + " ";
            String line = lines[i + 1];
            if (!line.startsWith(prefix) || line.length() == prefix.length()) {
                throw new IllegalArgumentException("line " + (i + 2) + " is not " + KEYS.get(i));
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
}
