// SPDX-License-Identifier: Apache-2.0
package android.app;

import android.content.ComponentName;

/** Host model stub with the pinned WaitResult's public fields. */
public class WaitResult {
    public int result;
    public boolean timeout;
    public ComponentName who;
    public long totalTime;
    public int launchState;
}
