// SPDX-License-Identifier: GPL-3.0-or-later
package dev.andrix.server;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.UserInfo;
import android.os.Binder;
import android.os.Process;
import android.os.UserHandle;

import com.android.server.LocalServices;
import com.android.server.pm.NativePrincipalManager;
import com.android.server.pm.UserManagerInternal;

import dev.andrix.lifecycle.INativeAccountQuery;
import dev.andrix.lifecycle.NativeAccountRow;
import dev.andrix.lifecycle.NativeAccountSnapshot;

import java.io.FileDescriptor;
import java.io.PrintWriter;

/** Dedicated read endpoint. The Console's image signer is the anchor, not the platform key. */
final class OwnerNativeAccountQuery extends INativeAccountQuery.Stub {
    private static final String CONSOLE = "dev.andrix.terminal";
    private static final String FACTORY_DIR = "/system_ext/priv-app/";
    private final PackageManager packages;

    OwnerNativeAccountQuery(Context context) {
        packages = context.getPackageManager();
    }

    private void enforceConsole(int uid, int userId) {
        final int appId = UserHandle.getAppId(uid);
        if (Binder.getCallingPid() <= 1 || userId != UserHandle.getUserId(uid)
                || appId < Process.FIRST_APPLICATION_UID || appId > Process.LAST_APPLICATION_UID) {
            throw new SecurityException("Native account inspection denied");
        }
        // UID membership alone is insufficient: a hidden shared UID peer may not appear in a
        // filtered package list. Reject sharedUserId independently for both installed and factory.
        String[] names = packages.getPackagesForUid(uid);
        if (names == null || names.length != 1 || !CONSOLE.equals(names[0])) {
            throw new SecurityException("Native account inspection denied");
        }
        try {
            int signers = PackageManager.GET_SIGNING_CERTIFICATES;
            PackageInfo installed = packages.getPackageInfoAsUser(CONSOLE, signers, userId);
            PackageInfo factory = packages.getPackageInfoAsUser(CONSOLE,
                    signers | PackageManager.MATCH_FACTORY_ONLY, userId);
            ApplicationInfo image = factory.applicationInfo;
            if (!CONSOLE.equals(installed.packageName) || !CONSOLE.equals(factory.packageName)
                    || installed.applicationInfo == null || image == null
                    || installed.applicationInfo.uid != uid
                    || UserHandle.getAppId(image.uid) != appId
                    || installed.sharedUserId != null || factory.sharedUserId != null
                    || !image.isSystemApp() || !image.isPrivilegedApp()
                    || image.sourceDir == null || !image.sourceDir.startsWith(FACTORY_DIR)
                    || !image.sourceDir.endsWith(".apk")
                    || installed.signingInfo == null || factory.signingInfo == null
                    || installed.signingInfo.getApkContentsSigners() == null
                    || installed.signingInfo.getApkContentsSigners().length == 0
                    || factory.signingInfo.getApkContentsSigners() == null
                    || factory.signingInfo.getApkContentsSigners().length == 0
                    || !installed.signingInfo.signersMatchExactly(factory.signingInfo)) {
                throw new SecurityException("Native account inspection denied");
            }
        } catch (PackageManager.NameNotFoundException | IllegalArgumentException error) {
            throw new SecurityException("Native account inspection denied", error);
        }
    }

    @Override public NativeAccountSnapshot inspectCurrentUser() {
        final int uid = Binder.getCallingUid();
        final int userId = UserHandle.getUserId(uid);
        enforceConsole(uid, userId); // No identity clearing, proxy or caller target argument.
        UserManagerInternal users = LocalServices.getService(UserManagerInternal.class);
        UserInfo info = users == null ? null : users.getUserInfo(userId);
        final long serial = info == null || info.partial || info.serialNumber < 0
                ? -1 : info.serialNumber;
        NativePrincipalManager.Inspection capture;
        if (serial < 0) {
            capture = userId == UserHandle.USER_SYSTEM
                    ? NativePrincipalManager.Inspection.unavailable(userId, serial)
                    : NativePrincipalManager.Inspection.unsupported(userId, serial);
        } else {
            NativePrincipalManager manager = LocalServices.getService(NativePrincipalManager.class);
            try {
                capture = manager == null ? NativePrincipalManager.Inspection.unavailable(userId, serial)
                        : manager.inspectUser(userId, serial);
            } catch (IllegalStateException unavailable) {
                capture = NativePrincipalManager.Inspection.unavailable(userId, serial);
            }
        }
        // A stopped/reused user, replaced APK or delayed query cannot obtain a prior user's rows.
        UserInfo now = users == null ? null : users.getUserInfo(userId);
        if (now == null || now.partial || now.serialNumber != serial || serial < 0) {
            capture = userId == UserHandle.USER_SYSTEM
                    ? NativePrincipalManager.Inspection.unavailable(userId, -1)
                    : NativePrincipalManager.Inspection.unsupported(userId, -1);
        }
        enforceConsole(uid, userId);
        return marshal(capture);
    }

    private static NativeAccountSnapshot marshal(NativePrincipalManager.Inspection capture) {
        NativeAccountSnapshot result = new NativeAccountSnapshot();
        result.userId = capture.userId;
        result.userSerial = capture.userSerial;
        result.status = switch (capture.status) {
            case AVAILABLE -> NativeAccountSnapshot.AVAILABLE;
            case UNAVAILABLE -> NativeAccountSnapshot.UNAVAILABLE;
            case UNSUPPORTED -> NativeAccountSnapshot.UNSUPPORTED_USER;
        };
        result.store = switch (capture.store) {
            case READY -> NativeAccountSnapshot.STORE_READY;
            case MISSING -> NativeAccountSnapshot.STORE_MISSING;
            case DAMAGED -> NativeAccountSnapshot.STORE_DAMAGED;
            case CONFLICT -> NativeAccountSnapshot.STORE_CONFLICT;
            case UNSUPPORTED -> NativeAccountSnapshot.STORE_NEWER;
            case UNAVAILABLE -> NativeAccountSnapshot.STORE_UNAVAILABLE;
        };
        result.complete = capture.complete;
        result.rows = new NativeAccountRow[capture.rows.size()];
        for (int i = 0; i < capture.rows.size(); ++i) {
            NativePrincipalManager.Row source = capture.rows.get(i);
            NativeAccountRow row = new NativeAccountRow();
            row.principalId = source.principalId;
            row.appId = source.appId;
            row.packageName = source.packageName;
            row.lineage = source.lineage;
            row.source = switch (source.source) {
                case "BODY" -> NativeAccountRow.BODY;
                case "RESERVATION" -> NativeAccountRow.RESERVATION;
                default -> throw new IllegalStateException("Unknown account history source");
            };
            row.phase = switch (source.phase) {
                case "PENDING" -> NativeAccountRow.PENDING;
                case "ACTIVE" -> NativeAccountRow.ACTIVE;
                case "RETIRING" -> NativeAccountRow.RETIRING_PIN;
                case "NOT_PINNED" -> NativeAccountRow.NOT_PINNED;
                default -> throw new IllegalStateException("Unknown account pin phase");
            };
            row.lifecycle = switch (source.lifecycle) {
                case "NOT_OBSERVED" -> NativeAccountRow.LIFECYCLE_NOT_OBSERVED;
                case "ELIGIBLE" -> NativeAccountRow.ELIGIBLE;
                case "RETIRING" -> NativeAccountRow.RETIRING;
                case "RETIRED" -> NativeAccountRow.RETIRED;
                default -> throw new IllegalStateException("Unknown account lifecycle");
            };
            row.suspension = switch (source.suspension) {
                case "NOT_OBSERVED" -> NativeAccountRow.SUSPENSION_NOT_OBSERVED;
                case "NONE" -> NativeAccountRow.SUSPENSION_NONE;
                case "PRESENT" -> NativeAccountRow.SUSPENSION_PRESENT;
                default -> throw new IllegalStateException("Unknown account suspension");
            };
            result.rows[i] = row;
        }
        return result;
    }

    @Override protected void dump(FileDescriptor fd, PrintWriter out, String[] args) {
        enforceConsole(Binder.getCallingUid(), UserHandle.getUserId(Binder.getCallingUid()));
        out.println("Native accounts: read endpoint, no account contents in dumps");
    }
}
