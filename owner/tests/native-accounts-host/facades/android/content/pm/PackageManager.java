// SPDX-License-Identifier: Apache-2.0
// Host test input only. Not an Android build input.
package android.content.pm;
/** Caller-visible records are supplied by tests, not resolved by Android PMS. */
public abstract class PackageManager {
    public static final int GET_SIGNING_CERTIFICATES=0x08000000, MATCH_FACTORY_ONLY=0x00200000;
    @SuppressWarnings("serial")
    public static final class NameNotFoundException extends Exception { }
    public abstract String[] getPackagesForUid(int uid);
    public abstract PackageInfo getPackageInfoAsUser(String packageName, int flags, int user)
            throws NameNotFoundException;
}
