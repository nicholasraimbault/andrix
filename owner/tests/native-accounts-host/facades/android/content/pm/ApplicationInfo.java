// SPDX-License-Identifier: Apache-2.0
// Host test input only. Not an Android build input.
package android.content.pm;
public final class ApplicationInfo {
    public int uid;
    public String sourceDir;
    public boolean system, privileged;
    public boolean isSystemApp() { return system; }
    public boolean isPrivilegedApp() { return privileged; }
}
