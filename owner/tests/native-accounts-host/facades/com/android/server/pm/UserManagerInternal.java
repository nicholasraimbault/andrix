// SPDX-License-Identifier: Apache-2.0
// Host test input only. Not an Android build input.
package com.android.server.pm;
import android.content.pm.UserInfo;
public interface UserManagerInternal { UserInfo getUserInfo(int userId); }
