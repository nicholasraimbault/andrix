// SPDX-License-Identifier: Apache-2.0
// Host facade only. Not Android behavior or authority.
package com.android.server.pm;
import com.android.server.pm.pkg.PackageUserStateInternal;
final class PackageSetting extends SettingBase {
 private final String name; int appId; boolean shared,system,updated,apex,external;
 String volume; boolean parsed=true; final Pkg pkg=new Pkg(); final PackageUserStateInternal state=new PackageUserStateInternal();
 PackageSetting(String n){name=n;} String getPackageName(){return name;}
 Pkg getPkg(){return parsed?pkg:null;} boolean hasSharedUser(){return shared;} int getAppId(){return appId;}
 boolean isSystem(){return system;} boolean isUpdatedSystemApp(){return updated;} boolean isApex(){return apex;}
 boolean isExternalStorage(){return external;} String getVolumeUuid(){return volume;}
 PackageUserStateInternal readUserState(int user){return state;}
 static final class Pkg { boolean sdk,library; boolean isSdkLibrary(){return sdk;} boolean isStaticSharedLibrary(){return library;} }
}
