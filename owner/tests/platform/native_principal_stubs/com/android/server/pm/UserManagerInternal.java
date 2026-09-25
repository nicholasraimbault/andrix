// SPDX-License-Identifier: Apache-2.0
// Host facade only. Not Android behavior or authority.
package com.android.server.pm;
import android.content.pm.UserInfo;
public final class UserManagerInternal {
 public UserInfo info=new UserInfo(); public UserInfo getUserInfo(int id){return id==0?info:null;}
}
