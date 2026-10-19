// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * A test generation whose JVM first starts one library style child, which inherits the standard
 * streams as a library's helper process would, then runs {@link LabBridgeTestMain}. The child is
 * {@code andrix.lab.childPython -B andrix.lab.childScript andrix.lab.childMode
 * andrix.lab.childRelease}, from the system properties; its process ID goes to the file
 * {@code andrix.lab.childPid}, and the generation waits until the child says it runs.
 */
public final class LabChildTestMain {
    private LabChildTestMain() {}

    public static void main(String[] args) throws Exception {
        String release = System.getProperty("andrix.lab.childRelease");
        Process child = new ProcessBuilder(System.getProperty("andrix.lab.childPython"), "-B",
                System.getProperty("andrix.lab.childScript"), System.getProperty("andrix.lab.childMode"), release)
                .inheritIO().start();
        Files.writeString(Path.of(System.getProperty("andrix.lab.childPid")), Long.toString(child.pid()));
        long end = System.nanoTime() + 10_000_000_000L;
        while (!Files.exists(Path.of(release + ".ready")) && System.nanoTime() < end) Thread.sleep(10);
        if ("early".equals(System.getProperty("andrix.lab.childMode"))) child.waitFor();
        LabBridgeTestMain.main(args);
    }
}
