// SPDX-License-Identifier: Apache-2.0
// Host facade only. Not Android behavior or authority.
package com.android.server.pm;
import com.android.server.pm.pkg.PackageStateInternal;
import java.util.ArrayList;
import java.util.List;
final class SharedUserSetting extends SettingBase {
 final List<PackageStateInternal> states=new ArrayList<>();
 List<PackageStateInternal> getPackageStates(){return states;}
}
