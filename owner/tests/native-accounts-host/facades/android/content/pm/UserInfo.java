// SPDX-License-Identifier: Apache-2.0
// Host test input only. Not an Android build input.
package android.content.pm;
public final class UserInfo {
    public boolean partial;
    public int serialNumber;
    public UserInfo(int serial, boolean partial) { serialNumber=serial; this.partial=partial; }
}
