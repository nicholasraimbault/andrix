// SPDX-License-Identifier: Apache-2.0
// Host test input only. Not an Android build input.
package android.os;
public final class UserHandle {
    public static final int USER_SYSTEM=0;
    private static volatile int currentUser;
    private UserHandle() { }
    public static int getUserId(int uid) { return uid / 100000; }
    public static int getAppId(int uid) { return uid % 100000; }
    public static int getUid(int user, int appId) { return user * 100000 + appId; }
    public static int myUserId() { return currentUser; }
    public static void setMyUserIdForHostTest(int user) { currentUser=user; }
}
