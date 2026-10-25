// SPDX-License-Identifier: Apache-2.0
// Host test input only. Not an Android build input.
package dev.andrix.server;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.SigningInfo;
import android.content.pm.UserInfo;
import android.os.Binder;
import android.os.UserHandle;
import com.android.server.LocalServices;
import com.android.server.pm.NativePrincipalManager;
import com.android.server.pm.UserManagerInternal;
import dev.andrix.lifecycle.INativeAccountQuery;
import dev.andrix.lifecycle.NativeAccountRow;
import dev.andrix.lifecycle.NativeAccountSnapshot;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.util.List;
import java.util.function.Consumer;

/** Executes the actual production endpoint with declared inert platform facts. */
public final class EndpointHostTest {
    private static final String CONSOLE="dev.andrix.terminal";
    private static int cases;
    private EndpointHostTest() { }
    private static void check(boolean condition, String why) {
        if (!condition) throw new AssertionError(why);
    }
    private static void run(String name, Runnable test) {
        test.run(); System.out.println("PASS endpoint " + name); cases++;
    }
    private static final class PM extends PackageManager {
        String[] names={CONSOLE};
        PackageInfo installed, factory;
        int installedReads, factoryReads, uidReads;
        int requestedUser=-1;
        @Override public String[] getPackagesForUid(int uid) { uidReads++;return names; }
        @Override public PackageInfo getPackageInfoAsUser(String name, int flags, int user)
                throws NameNotFoundException {
            check(CONSOLE.equals(name),"target changed"); requestedUser=user;
            check((flags & GET_SIGNING_CERTIFICATES)!=0,"signer flag omitted");
            if ((flags & MATCH_FACTORY_ONLY)!=0) {
                factoryReads++; if (factory==null) throw new NameNotFoundException(); return factory;
            }
            installedReads++; if (installed==null) throw new NameNotFoundException();
            return installed;
        }
    }
    private static final class Users implements UserManagerInternal {
        int requestedUser=-1, reads;
        UserInfo first=new UserInfo(7,false), next=first;
        Runnable onSecondRead;
        @Override public UserInfo getUserInfo(int user) {
            requestedUser=user;
            if (++reads==1) return first;
            if (onSecondRead!=null) onSecondRead.run();
            return next;
        }
    }
    private static PackageInfo pkg(int uid, String current, String[] history, String path) {
        PackageInfo p=new PackageInfo();p.packageName=CONSOLE;
        p.applicationInfo=new ApplicationInfo();p.applicationInfo.uid=uid;
        p.applicationInfo.system=true;p.applicationInfo.privileged=true;
        p.applicationInfo.sourceDir=path;
        p.signingInfo=new SigningInfo(current==null ? null : new String[]{current},history);
        return p;
    }
    private static final class Fixture {
        final PM pm=new PM();
        final Users users=new Users();
        final NativePrincipalManager manager=new NativePrincipalManager();
        final OwnerNativeAccountQuery endpoint;
        final int uid;
        Fixture(int user) {
            uid=UserHandle.getUid(user,10123);
            Binder.setCallerForHostTest(uid,42);
            pm.installed=pkg(uid,"console-current",new String[]{"retired"},"/data/app/console.apk");
            pm.factory=pkg(UserHandle.getUid(0,10123),"console-current",new String[0],
                    "/system_ext/priv-app/AndrixTerminal/AndrixTerminal.apk");
            users.first=new UserInfo(user==0 ? 7 : 77,false);users.next=users.first;
            LocalServices.resetForHostTest();
            LocalServices.setForHostTest(UserManagerInternal.class,users);
            manager.next=NativePrincipalManager.Inspection.available(user,users.first.serialNumber,
                    List.of(new NativePrincipalManager.Row(81L,10123,"dev.andrix.native",
                    "0123456789abcdef0123456789abcdef","BODY","RETIRING",
                    "RETIRED","PRESENT")));
            LocalServices.setForHostTest(NativePrincipalManager.class,manager);
            endpoint=new OwnerNativeAccountQuery(new Context(pm));
        }
        NativeAccountSnapshot call() { return endpoint.inspectCurrentUser(); }
    }
    private static void denied(String name, Consumer<Fixture> alter) {
        run(name,()->{
            Fixture f=new Fixture(0);alter.accept(f);
            try { f.call(); throw new AssertionError("inspection allowed for "+name); }
            catch (SecurityException expected) { /* no account read after rejection */ }
            check(f.manager.calls==0,"unauthorized manager read");
        });
    }
    private static void withheld(String name, Consumer<Fixture> alter, int expectedStatus,
            boolean managerCalled) {
        run(name,()->{
            Fixture f=new Fixture(0);alter.accept(f);
            NativeAccountSnapshot result=f.call();
            check(result.status==expectedStatus,"status "+name);
            check(result.rows.length==0,"prior user row escaped "+name);
            check(result.userSerial==-1,"stale serial exposed "+name);
            check((f.manager.calls!=0)==managerCalled,"wrong PMS capture count "+name);
        });
    }
    public static void main(String[] args) {
        denied("root UID",f->Binder.setCallerForHostTest(0,42));
        denied("shell UID",f->Binder.setCallerForHostTest(2000,42));
        denied("native coordinator UID7500",f->Binder.setCallerForHostTest(7500,42));
        denied("system UID",f->Binder.setCallerForHostTest(1000,42));
        denied("invalid Binder pid",f->Binder.setCallerForHostTest(f.uid,1));
        denied("foreign application",f->f.pm.names=new String[]{"dev.foreign"});
        denied("platform signed other package",f->{ f.pm.names=new String[]{"dev.platform"};
            f.pm.installed.signingInfo=new SigningInfo(new String[]{"platform"},new String[0]); });
        denied("shared UID two visible members",f->f.pm.names=new String[]{CONSOLE,"dev.peer"});
        denied("hidden shared UID peer, singleton filtered list",f->f.pm.installed.sharedUserId="peer");
        denied("factory shared UID",f->f.pm.factory.sharedUserId="peer");
        denied("missing UID package list",f->f.pm.names=null);
        denied("empty UID package list",f->f.pm.names=new String[0]);
        denied("missing installed record",f->f.pm.installed=null);
        denied("missing factory record",f->f.pm.factory=null);
        denied("fallback factory from data/app",f->{f.pm.factory=f.pm.installed;});
        denied("nonprivileged factory",f->f.pm.factory.applicationInfo.privileged=false);
        denied("nonsystem factory",f->f.pm.factory.applicationInfo.system=false);
        denied("wrong factory path",f->f.pm.factory.applicationInfo.sourceDir="/system/priv-app/X.apk");
        denied("factory path not apk",f->f.pm.factory.applicationInfo.sourceDir="/system_ext/priv-app/X");
        denied("missing factory image",f->f.pm.factory.applicationInfo=null);
        denied("wrong factory app ID",f->f.pm.factory.applicationInfo.uid=10124);
        denied("wrong installed UID",f->f.pm.installed.applicationInfo.uid=f.uid+1);
        denied("wrong installed name",f->f.pm.installed.packageName="dev.foreign");
        denied("wrong factory name",f->f.pm.factory.packageName="dev.foreign");
        denied("missing installed signing",f->f.pm.installed.signingInfo=null);
        denied("no current signers",f->f.pm.installed.signingInfo=new SigningInfo(new String[0],new String[0]));
        denied("null current signers",f->f.pm.factory.signingInfo=new SigningInfo(null,new String[0]));
        denied("rotation old cert only in signing history",f->f.pm.installed.signingInfo=
                new SigningInfo(new String[]{"rotated"},new String[]{"console-current"}));
        denied("platform signer replacing Console",f->f.pm.installed.signingInfo=
                new SigningInfo(new String[]{"platform"},new String[0]));
        denied("added current cosigner",f->f.pm.installed.signingInfo=
                new SigningInfo(new String[]{"console-current","cosigner"},new String[0]));
        run("multisigner exact current set order independent",()->{
            Fixture f=new Fixture(0);
            f.pm.installed.signingInfo=new SigningInfo(new String[]{"a","b"},new String[]{"old"});
            f.pm.factory.signingInfo=new SigningInfo(new String[]{"b","a"},new String[0]);
            check(f.call().status==NativeAccountSnapshot.AVAILABLE,"exact set rejected");
            check(f.manager.calls==1,"no capture");
        });
        run("genuine current unupdated factory",()->{
            Fixture f=new Fixture(0);f.pm.installed=f.pm.factory;
            f.pm.installed.applicationInfo.uid=f.uid;
            NativeAccountSnapshot s=f.call();
            check(s.status==NativeAccountSnapshot.AVAILABLE && s.complete && s.rows.length==1,
                    "unupdated current factory rejected");
            check(f.manager.calls==1 && f.manager.lastUser==0 && f.manager.lastSerial==7,
                    "capture target not authoritative");
            check(f.pm.factoryReads==2 && f.pm.installedReads==2 && f.users.reads==2,
                    "caller/serial not rechecked");
            NativeAccountRow r=s.rows[0];
            check(r.source==NativeAccountRow.BODY && r.phase==NativeAccountRow.RETIRING_PIN
                    && r.lifecycle==NativeAccountRow.RETIRED
                    && r.suspension==NativeAccountRow.SUSPENSION_PRESENT,
                    "actual endpoint marshal did not preserve BODY state");
            check(r.principalId==81 && r.lineage.equals("0123456789abcdef0123456789abcdef"),
                    "identity lost");
        });
        run("independent factory entry on data/app update",()->{
            Fixture f=new Fixture(0);
            check(f.pm.installed!=f.pm.factory && f.pm.installed.applicationInfo!=f.pm.factory.applicationInfo,
                    "factory not independent");
            check(f.call().rows.length==1 && f.pm.factoryReads==2,"update not accepted");
        });
        run("auth denied on second pass after package replacement",()->{
            Fixture f=new Fixture(0);f.users.onSecondRead=()->f.pm.installed.signingInfo=
                    new SigningInfo(new String[]{"replacement"},new String[]{"console-current"});
            try { f.call();throw new AssertionError("replaced caller accepted"); }
            catch (SecurityException expected) { check(f.manager.calls==1,"capture not reached"); }
        });
        withheld("user vanished during capture",f->f.users.next=null,
                NativeAccountSnapshot.UNAVAILABLE,true);
        withheld("user serial reused during capture",f->f.users.next=new UserInfo(8,false),
                NativeAccountSnapshot.UNAVAILABLE,true);
        withheld("user partial during capture",f->f.users.next=new UserInfo(7,true),
                NativeAccountSnapshot.UNAVAILABLE,true);
        withheld("user absent at first read",f->f.users.first=null,
                NativeAccountSnapshot.UNAVAILABLE,false);
        withheld("initial partial",f->f.users.first=new UserInfo(7,true),
                NativeAccountSnapshot.UNAVAILABLE,false);
        withheld("initial invalid serial",f->f.users.first=new UserInfo(-1,false),
                NativeAccountSnapshot.UNAVAILABLE,false);
        run("PMS capture missing is unavailable not empty",()->{
            Fixture f=new Fixture(0);LocalServices.setForHostTest(NativePrincipalManager.class,null);
            NativeAccountSnapshot s=f.call();
            check(s.status==NativeAccountSnapshot.UNAVAILABLE && !s.complete && s.rows.length==0,
                    "missing PMS treated as complete empty");
        });
        run("PMS state exception is unavailable not empty",()->{
            Fixture f=new Fixture(0);f.manager.throwUnavailable=true;
            NativeAccountSnapshot s=f.call();
            check(s.status==NativeAccountSnapshot.UNAVAILABLE && !s.complete && s.rows.length==0,
                    "PMS exception became empty");
        });
        run("secondary Console authenticates but no primary rows",()->{
            Fixture f=new Fixture(2);f.manager.next=NativePrincipalManager.Inspection.unsupported(2,77);
            NativeAccountSnapshot s=f.call();
            check(s.status==NativeAccountSnapshot.UNSUPPORTED_USER && s.userId==2
                    && s.userSerial==77 && s.rows.length==0 && f.manager.lastUser==2
                    && f.manager.lastSerial==77 && f.pm.requestedUser==2
                    && f.users.requestedUser==2,"secondary obtained primary data");
        });
        run("secondary vanished user returns unsupported with no rows",()->{
            Fixture f=new Fixture(2);f.users.next=null;
            NativeAccountSnapshot s=f.call();
            check(s.status==NativeAccountSnapshot.UNSUPPORTED_USER
                    && s.userSerial==-1 && s.rows.length==0,"secondary fallback failed");
        });
        run("dump enforces caller and omits account contents",()->{
            Fixture f=new Fixture(0);StringWriter buffer=new StringWriter();
            f.endpoint.dump(null,new PrintWriter(buffer,true),new String[0]);
            check(!buffer.toString().contains("dev.andrix.native"),"dump leaks rows");
            Binder.setCallerForHostTest(7500,42);
            try {f.endpoint.dump(null,new PrintWriter(new StringWriter()),new String[0]);
                throw new AssertionError("unauthorized dump"); }
            catch (SecurityException expected) { /* expected */ }
        });
        run("no caller supplied IDs in AIDL shaped read API and DTO",()->{
            try { check(INativeAccountQuery.class.getMethod("inspectCurrentUser")
                    .getParameterCount()==0,"caller target argument"); }
            catch (NoSuchMethodException e) { throw new AssertionError(e); }
            for (Field field : NativeAccountSnapshot.class.getDeclaredFields()) {
                check(!field.getName().equals("callerUid") && !field.getName().equals("callingPid"),
                        "raw caller leaked into DTO");
            }
        });
        System.out.println("ENDPOINT HOST PASS " + cases + " CASES; manager is an inert capture, not PMS");
    }
}
