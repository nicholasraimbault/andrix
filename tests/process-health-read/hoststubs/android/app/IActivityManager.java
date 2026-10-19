// SPDX-License-Identifier: Apache-2.0
// Host stub of android.app.IActivityManager: the two reads the helper makes, answered from the
// script, and Stub.asInterface. Every call is traced.
package android.app;

import andrixstub.Script;
import android.content.pm.ParceledListSlice;
import android.os.IBinder;
import android.os.RemoteException;
import java.util.ArrayList;
import java.util.List;

public interface IActivityManager {
    List<ActivityManager.ProcessErrorStateInfo> getProcessesInErrorState() throws RemoteException;

    ParceledListSlice<ApplicationExitInfo> getHistoricalProcessExitReasons(String packageName, int pid, int maxNum,
            int userId) throws RemoteException;

    abstract class Stub implements IActivityManager {
        public static IActivityManager asInterface(IBinder binder) {
            Script.trace("asInterface()");
            return new IActivityManager() {
                @Override
                public List<ActivityManager.ProcessErrorStateInfo> getProcessesInErrorState() throws RemoteException {
                    Script.trace("getProcessesInErrorState()");
                    String answer = Script.value("errors.answer", "null");
                    Script.raise(answer);
                    if (answer.equals("null")) return null;
                    List<ActivityManager.ProcessErrorStateInfo> found = new ArrayList<>();
                    for (String[] f : Script.rows("errors.")) {
                        ActivityManager.ProcessErrorStateInfo e = new ActivityManager.ProcessErrorStateInfo();
                        e.condition = Integer.parseInt(f[0]);
                        e.pid = Integer.parseInt(f[1]);
                        e.uid = Integer.parseInt(f[2]);
                        e.processName = Script.nullable(f[3]);
                        e.tag = Script.nullable(f[4]);
                        e.shortMsg = Script.nullable(f[5]);
                        e.longMsg = Script.nullable(f[6]);
                        e.stackTrace = Script.nullable(f[7]);
                        found.add(e);
                    }
                    return found;
                }

                @Override
                public ParceledListSlice<ApplicationExitInfo> getHistoricalProcessExitReasons(String packageName,
                        int pid, int maxNum, int userId) throws RemoteException {
                    Script.trace("getHistoricalProcessExitReasons(" + packageName + "," + pid + "," + maxNum + ","
                            + userId + ")");
                    String answer = Script.value("history.answer", "rows");
                    Script.raise(answer);
                    if (answer.equals("null")) return null;
                    if (answer.equals("list-null")) return new ParceledListSlice<>(null);
                    List<ApplicationExitInfo> found = new ArrayList<>();
                    for (String[] f : Script.rows("history.")) found.add(new ApplicationExitInfo(f));
                    return new ParceledListSlice<>(found);
                }
            };
        }
    }
}
