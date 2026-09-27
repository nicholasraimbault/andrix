// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import java.io.File;
import java.io.IOException;

/**
 * Host only write fault seam. The fault harness copies the actual store and strict writer
 * sources and inserts calls to {@link #at} at named write steps. Production sources never
 * call it. An armed step runs once, for one record file name, and by default throws an
 * injected IOException there. These are host injected failures, not Android crash evidence.
 */
final class NativeHeaderWriteFaults {
    interface Action { void run() throws IOException; }

    private static String armedStep, armedFile;
    private static Action armedAction;
    private static int reached;

    /** Throws an injected IOException at the first matching step. */
    static void arm(String step, String fileName) {
        arm(step, fileName, () -> { throw new IOException("host injected failure at " + step); });
    }

    /** Runs action at the first matching step instead. */
    static void arm(String step, String fileName, Action action) {
        armedStep = step;
        armedFile = fileName;
        armedAction = action;
        reached = 0;
    }

    static void disarm() {
        armedStep = null;
        armedFile = null;
        armedAction = null;
    }

    /** Whether the armed step was reached since it was armed. */
    static boolean reached() { return reached > 0; }

    static void at(String step, File main) throws IOException {
        if (armedStep == null || !armedStep.equals(step) || !main.getName().equals(armedFile)) return;
        Action action = armedAction;
        disarm();
        ++reached;
        action.run();
    }

    private NativeHeaderWriteFaults() {}
}
