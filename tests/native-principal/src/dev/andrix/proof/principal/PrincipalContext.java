// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.principal;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Looper;
import android.os.Process;
import java.lang.reflect.Method;

/** The previously measured private reference binding, not a production native API. */
final class PrincipalContext {
    static final String ATTRIBUTION = "native-principal-proof";
    private PrincipalContext() {}

    static Context create() throws Exception {
        if (Looper.getMainLooper() == null) Looper.prepareMainLooper();
        Class<?> activityThread = Class.forName("android.app.ActivityThread");
        Object thread = activityThread.getMethod("systemMain").invoke(null);
        Context systemContext = (Context) activityThread.getMethod("getSystemContext").invoke(thread);
        PackageManager packages = systemContext.getPackageManager();
        String principal = ProbePrincipal.fixtureForUid(packages.getPackagesForUid(Process.myUid()));
        ApplicationInfo application = packages.getApplicationInfo(principal, 0);
        ProbePrincipal.requireOwnApplication(Process.myUid(), application.uid);
        if (!principal.equals(application.packageName)) {
            throw new SecurityException("Package Manager returned a different application");
        }

        Class<?> compatibility = Class.forName("android.content.res.CompatibilityInfo");
        Object defaults = compatibility.getField("DEFAULT_COMPATIBILITY_INFO").get(null);
        // The checked package-info path, with resource-only flags. No INCLUDE_CODE,
        // IGNORE_SECURITY, getPackageInfoNoCheck, foreign package or caller-supplied identity.
        Object loaded = activityThread.getMethod("getPackageInfo", ApplicationInfo.class,
                compatibility, int.class).invoke(thread, application, defaults, 0);
        Class<?> loadedApk = Class.forName("android.app.LoadedApk");
        Class<?> contextImpl = Class.forName("android.app.ContextImpl");
        Method create = contextImpl.getDeclaredMethod("createAppContext", activityThread, loadedApk);
        // Bounded access to Java package visibility for this private diagnostic factory.
        // This does not exempt ART hidden APIs or change native permission/MAC enforcement.
        // Refuse if the lookup/access fails. Never override the operation-package field.
        create.setAccessible(true);
        Context context = (Context) create.invoke(null, thread, loaded);
        ProbePrincipal.requireOwnContext(Process.myUid(), principal, context.getApplicationInfo().uid,
                context.getPackageName(), context.getAttributionSource().getUid(),
                context.getAttributionSource().getPackageName());
        return context.createAttributionContext(ATTRIBUTION);
    }
}
