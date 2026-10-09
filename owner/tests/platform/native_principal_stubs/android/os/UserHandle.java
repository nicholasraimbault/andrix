// SPDX-License-Identifier: Apache-2.0
// Host facade only. Not Android behavior or authority.
package android.os;
public final class UserHandle { public static final int USER_SYSTEM=0; private UserHandle(){}
 public static int getUid(int userId,int appId){return userId*100000+appId;} }
