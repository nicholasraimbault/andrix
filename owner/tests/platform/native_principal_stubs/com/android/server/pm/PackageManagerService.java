// SPDX-License-Identifier: Apache-2.0
// Host facade only. Not Android behavior or authority.
package com.android.server.pm;
import java.util.HashMap;
import java.util.HashSet;
final class PackageManagerService {
 static void reportSettingsProblem(int level,String message){}
 final Object mLock=new Object(); final PackageManagerTracedLock mInstallLock=new PackageManagerTracedLock();
 final HashMap<String,Integer> mFrozenPackages=new HashMap<>(); final HashSet<String> installing=new HashSet<>();
 final Settings mSettings;
 PackageManagerService(){mSettings=new Settings();}
 PackageManagerService(java.nio.file.Path root,boolean initialize){mSettings=new Settings(root,initialize);}
 Object snapshotComputer(){return this;}
 boolean isInstallingNativePrincipalPackage(String name){return installing.contains(name);}
}
