// SPDX-License-Identifier: Apache-2.0
// Host facade only. Not Android behavior or authority.
package com.android.server.pm;
import java.util.HashMap;
import java.util.HashSet;
final class Settings {
 NativePrincipalPins pins=new NativePrincipalPins(64); final AppIdSettingMap ids=new AppIdSettingMap();
 final HashMap<String,PackageSetting> packages=new HashMap<>(); final HashSet<String> mutating=new HashSet<>();
 boolean recoveryBlocked,writeOk=true,storeOnFailure; int writes; NativePrincipalPins.Snapshot persisted;
 NativePrincipalPins nativePrincipalPinsLPr(){return pins;}
 boolean nativePrincipalRecoveryBlockedLPr(){return recoveryBlocked;}
 boolean nativePrincipalMutationInProgressLPr(String name){return mutating.contains(name);}
 PackageSetting getPackageLPr(String name){return packages.get(name);}
 SettingBase getSettingLPr(int id){return ids.getSetting(id);}
 void refreshNativePrincipalAppIdsLPw(){ids.setNativePrincipalAppIds(pins.reservedAppIds());}
 boolean persistNativePrincipalPinsLPr(Object ignored){return persistNativePrincipalPinsLPr(ignored,pins.snapshotForWrite());}
 boolean persistNativePrincipalPinsLPr(Object ignored,NativePrincipalPins.Snapshot candidate){
  writes++;if(writeOk||storeOnFailure)persisted=candidate;return writeOk;
 }
 PackageSetting add(String name,int uid){PackageSetting p=new PackageSetting(name);p.appId=uid;packages.put(name,p);if(!ids.registerExistingAppId(uid,p,name))throw new AssertionError();return p;}
}
