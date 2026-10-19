// SPDX-License-Identifier: Apache-2.0
// Host stub of android.app.ActivityManager: only its error state record, with its public fields.
package android.app;

public class ActivityManager {
    public static class ProcessErrorStateInfo {
        public int condition;
        public String processName;
        public int pid;
        public int uid;
        public String tag;
        public String shortMsg;
        public String longMsg;
        public String stackTrace;
    }
}
