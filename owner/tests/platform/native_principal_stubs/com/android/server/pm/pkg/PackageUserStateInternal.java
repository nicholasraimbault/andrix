// SPDX-License-Identifier: Apache-2.0
// Host facade only. Not Android behavior or authority.
package com.android.server.pm.pkg;
public final class PackageUserStateInternal {
 public boolean installed=true,instant,hidden,suspended; public Object archive;
 public boolean isInstalled(){return installed;} public boolean isInstantApp(){return instant;}
 public boolean isHidden(){return hidden;} public boolean isSuspended(){return suspended;}
 public Object getArchiveState(){return archive;}
}
