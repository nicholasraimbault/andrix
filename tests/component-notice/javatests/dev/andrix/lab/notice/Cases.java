// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.notice;

import java.util.ArrayList;
import java.util.List;

/** A minimal case runner for the host suites: one PASS or FAIL line for each case. */
final class Cases {
    interface Body {
        void run(List<String> problems) throws Exception;
    }

    private int failed;
    private int passed;

    void run(String name, Body body) {
        List<String> problems = new ArrayList<>();
        try {
            body.run(problems);
        } catch (Exception | AssertionError e) {
            problems.add("threw " + e);
        }
        if (problems.isEmpty()) {
            passed++;
            System.out.println("PASS " + name);
        } else {
            failed++;
            System.out.println("FAIL " + name + ": " + String.join("; ", problems));
        }
    }

    static void check(List<String> problems, boolean ok, String what) {
        if (!ok) problems.add(what);
    }

    /** Whether the body is refused with an IllegalArgumentException. */
    static boolean refused(Runnable body) {
        try {
            body.run();
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }

    int finish() {
        System.out.println("RESULT passed=" + passed + " failed=" + failed);
        return failed == 0 ? 0 : 1;
    }
}
