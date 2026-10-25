// SPDX-License-Identifier: Apache-2.0
// Host test input only. Not an Android build input.
package android.content;
import android.content.pm.PackageManager;
public final class Context {
    private final PackageManager pm;
    public Context(PackageManager pm) { this.pm=pm; }
    public PackageManager getPackageManager() { return pm; }
}
