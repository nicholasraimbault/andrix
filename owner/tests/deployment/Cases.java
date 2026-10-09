// SPDX-License-Identifier: Apache-2.0
package dev.andrix.server.deployment;

import java.util.ArrayList;
import java.util.List;

/**
 * Named host checks. Each case prints "PASS name" or "FAIL name: problems", which the runner
 * reads up to the first colon and space. A case that throws fails with the exception named.
 */
final class Cases {
    interface Body {
        void run(List<String> problems) throws Exception;
    }

    private final List<String> failures = new ArrayList<>();
    private final List<String> names = new ArrayList<>();
    private int passed;

    void run(String name, Body body) {
        if (names.contains(name)) throw new IllegalStateException("duplicate case name");
        if (name.contains(": ")) throw new IllegalStateException("a case name holds the failure separator");
        names.add(name);
        List<String> problems = new ArrayList<>();
        try {
            body.run(problems);
        } catch (Exception | AssertionError error) {
            problems.add("error " + error);
        }
        if (problems.isEmpty()) {
            ++passed;
            System.out.println("PASS " + name);
        } else {
            failures.add(name);
            System.out.println("FAIL " + name + ": " + String.join("; ", problems));
        }
    }

    static void check(List<String> problems, boolean ok, String problem) {
        if (!ok) problems.add(problem);
    }

    /** Prints the totals and throws when any case failed. */
    void finish(String what) {
        System.out.println(passed + " passed, " + failures.size() + " failed");
        if (!failures.isEmpty()) throw new AssertionError("failed: " + failures);
        System.out.println(what + "; host JVM only, Android, device storage and activation unqualified");
    }

    static void requireAssertions(Class<?> type) {
        if (!type.desiredAssertionStatus()) throw new AssertionError("run with -ea");
    }
}
