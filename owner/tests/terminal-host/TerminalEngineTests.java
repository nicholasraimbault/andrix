// SPDX-License-Identifier: Apache-2.0
// Host-only runner: upstream parser tests, not Android View/session qualification.
import junit.framework.TestCase;
import junit.framework.TestResult;
import junit.framework.TestSuite;
import java.util.Enumeration;

public final class TerminalEngineTests {
    @SuppressWarnings("unchecked")
    public static void main(String[] classes) throws Exception {
        TestSuite suite = new TestSuite();
        for (String name : classes)
            suite.addTestSuite((Class<? extends TestCase>) Class.forName(name));
        TestResult result = new TestResult();
        suite.run(result);
        for (Enumeration<?> e = result.failures(); e.hasMoreElements();) System.err.println(e.nextElement());
        for (Enumeration<?> e = result.errors(); e.hasMoreElements();) System.err.println(e.nextElement());
        System.out.println("tests=" + result.runCount() + " failures=" + result.failureCount()
                + " errors=" + result.errorCount());
        if (!result.wasSuccessful()) System.exit(1);
    }
}
