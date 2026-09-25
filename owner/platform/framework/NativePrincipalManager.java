// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import android.content.pm.UserInfo;
import android.content.pm.Signature;
import android.os.Process;
import android.os.UserHandle;

import com.android.server.LocalServices;
import com.android.server.pm.pkg.PackageUserStateInternal;

import java.util.IdentityHashMap;
import java.util.Set;
import java.util.TreeSet;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Package Manager's internal native account identity reservation. Not a Binder
 * service, manifest role, UID setter, owner consent provider or launch permission.
 * Only a trusted account authority may call this after validating designation.
 * The initial platform adapter supports user 0. Other users require a separate
 * UserManager ID lifetime barrier before they can be admitted. Calls may block
 * on package persistence and must not hold AMS, WM, native work control or
 * admission locks. This API must never run on the native Stop lane.
 */
@SuppressWarnings("try") // Scoped install-lock guards are used for their close operation.
public final class NativePrincipalManager {
    /**
     * Exact installed subject selected for a separate owner designation decision.
     * Selection is metadata, not consent, a pin or an execution credential.
     * Private instance ownership prevents reconstructed/cross-service selections.
     */
    public static final class Selection {
        public final String packageName;
        public final int appId, userId;
        public final long userSerial, versionCode;
        public final Set<String> currentSignerSha256;
        private final NativePrincipalManager owner;
        private final PackageSetting setting;
        private Handle prepared; // PMS mutation lock. One reservation result per selection.
        private Selection(NativePrincipalManager owner, PackageSetting setting, int user,
                long serial) {
            this.owner = owner;
            this.setting = setting;
            packageName = setting.getPackageName();
            appId = setting.getAppId(); userId = user; userSerial = serial;
            versionCode = setting.getVersionCode();
            currentSignerSha256 = signerDigests(setting);
        }
    }

    public static final class Handle {
        private final NativePrincipalManager owner;
        private final NativePrincipalPins.Pin pin;
        private boolean retirementCommitted;
        private Selection selection; // Current service incarnation's designation binding.
        private boolean retired; // Guarded by the Package Manager mutation lock.
        private Handle(NativePrincipalManager owner, NativePrincipalPins.Pin pin) {
            this.owner = owner;
            this.pin = pin;
        }
    }

    private final PackageManagerService pm;
    // Exact prepare/find retries share a handle. Retired handles are removed
    // here, while any caller still holding one can reconcile its own result.
    private final IdentityHashMap<NativePrincipalPins.Pin, Handle> handles = new IdentityHashMap<>();

    NativePrincipalManager(PackageManagerService pm) {
        this.pm = pm;
    }

    /** Capture identity for the trusted designation UI/controller, with no pin or grant. */
    public Selection select(String packageName, int userId) {
        try (PackageManagerTracedLock ignored = pm.mInstallLock.acquireLock()) {
            synchronized (pm.mLock) {
                requireRecoveryReady();
                long serial = primaryUserSerial(userId);
                PackageSetting setting = subject(packageName, userId);
                requireNoMutation(packageName);
                return new Selection(this, setting, userId, serial);
            }
        }
    }

    /**
     * Called by the trusted account authority after designation of THIS selection.
     * It must authenticate owner intent itself: possession of a Selection is not
     * consent. Installed object, UID, serial, version and exact current signer set
     * are compared under the same mutation lock, never supplied as credentials.
     * A changed selection requires a new decision. Signer rotation during normal
     * account maintenance is separate from this exact initial selection contract.
     * A failed write retains PENDING. A retired selection cannot create a new pin.
     */
    public Handle prepare(Selection selection) {
        try (PackageManagerTracedLock ignored = pm.mInstallLock.acquireLock()) {
            synchronized (pm.mLock) {
                requireRecoveryReady();
                if (selection == null || selection.owner != this) {
                    throw new IllegalArgumentException("Foreign native principal selection");
                }
                PackageSetting setting = validateSelection(selection);
                if (selection.prepared != null) {
                    checked(selection.prepared);
                    requireDesignationBinding(selection.prepared);
                    if (selection.prepared.pin.phase() == NativePrincipalPins.Phase.RETIRING) {
                        throw new IllegalStateException("Native account selection is retiring");
                    }
                    return selection.prepared;
                }
                NativePrincipalPins.Pin pin = pm.mSettings.nativePrincipalPinsLPr().prepare(
                        selection.packageName, setting.getAppId(), selection.userId,
                        selection.userSerial);
                Handle prepared = handle(pin);
                if (prepared.selection == null) prepared.selection = selection;
                else validateSelection(prepared.selection);
                selection.prepared = prepared;
                pm.mSettings.refreshNativePrincipalAppIdsLPw();
                return prepared;
            }
        }
    }

    /**
     * Confirm reservation persistence in both Package Manager recovery copies.
     * True means a durable UID pin, not permission to run, a CE check or a complete
     * credential profile. Admission must still bind the exact manager/user epoch.
     * False leaves this exact handle pending, including uncertain publication.
     */
    public boolean commit(Handle handle) {
        try (PackageManagerTracedLock ignored = pm.mInstallLock.acquireLock()) {
            synchronized (pm.mLock) {
                requireRecoveryReady();
                NativePrincipalPins pins = checked(handle);
                NativePrincipalPins.Record record = handle.pin.record();
                requireDesignationBinding(handle);
                revalidate(record);
                if (handle.pin.phase() == NativePrincipalPins.Phase.RETIRING) {
                    throw new IllegalStateException("Native principal is retiring");
                }
                if (!pm.mSettings.persistNativePrincipalPinsLPr(pm.snapshotComputer())) return false;
                // Under the same package mutation lock, with no caller chosen UID.
                revalidate(record);
                pins.commit(handle.pin);
                return true;
            }
        }
    }

    /** Metadata for the exact handle. It is not proof of live native authority. */
    public NativePrincipalPins.Record identity(Handle handle) {
        synchronized (pm.mLock) {
            checked(handle);
            return handle.pin.record();
        }
    }

    /**
     * Revalidate the current installed identity of a durable pin. This still
     * supplies no CE, execution, group/MAC profile or foreground authority.
     */
    public NativePrincipalPins.Record currentIdentity(Handle handle) {
        synchronized (pm.mLock) {
            requireRecoveryReady();
            checked(handle);
            if (handle.pin.phase() != NativePrincipalPins.Phase.ACTIVE) {
                throw new IllegalStateException("Native principal reservation is not active");
            }
            requireDesignationBinding(handle);
            revalidate(handle.pin.record());
            return handle.pin.record();
        }
    }

    public NativePrincipalPins.Phase phase(Handle handle) {
        synchronized (pm.mLock) {
            checked(handle);
            return handle.pin.phase();
        }
    }

    /**
     * Recover a persisted reservation, never an old process or launch. Restored
     * handles remain PENDING until subject revalidation and durable commit.
     */
    public Handle find(String packageName, int userId) {
        synchronized (pm.mLock) {
            primaryUserSerial(userId);
            NativePrincipalPins.Pin pin = pm.mSettings.nativePrincipalPinsLPr().find(packageName,
                    userId);
            return pin == null ? null : handle(pin);
        }
    }

    /**
     * Close new admission and durably mark retirement BEFORE the account
     * authority starts destructive removal/quiescence. False retains this exact
     * retiring pin but does not authorize the removal transaction to advance.
     * Restored retiring pins cannot be committed as active again.
     */
    public boolean beginRetirement(Handle handle) {
        try (PackageManagerTracedLock ignored = pm.mInstallLock.acquireLock()) {
            synchronized (pm.mLock) {
                requireRecoveryReady();
                NativePrincipalPins pins = checked(handle);
                pins.beginRetire(handle.pin);
                if (!pm.mSettings.persistNativePrincipalPinsLPr(pm.snapshotComputer())) return false;
                handle.retirementCommitted = true;
                return true;
            }
        }
    }

    /**
     * Called only AFTER beginRetirement is durably confirmed and the trusted
     * account authority has confirmed exact work/manager/API retirement and the
     * owner's data/removal policy. PMS does not infer that from Binder death,
     * a PID lookup, a timeout or a caller boolean. No public transport or
     * automatic close/finalizer exposes this operation.
     *
     * The candidate omits ONLY this quiesced reservation. Other retiring pins
     * may still own work and remain durable. False retains the original pin and
     * still blocks reuse. Retry this same handle to reconcile an unknown result.
     */
    public boolean finishRetirementAfterQuiescence(Handle handle) {
        try (PackageManagerTracedLock ignored = pm.mInstallLock.acquireLock()) {
            synchronized (pm.mLock) {
                if (handle == null || handle.owner != this) {
                    throw new IllegalArgumentException("Foreign native principal handle");
                }
                if (handle.retired) return true;
                requireRecoveryReady();
                NativePrincipalPins pins = checked(handle);
                if (!handle.retirementCommitted) {
                    throw new IllegalStateException("Retirement marker is not durably confirmed");
                }
                NativePrincipalPins.Snapshot candidate = pins.snapshotWithout(handle.pin);
                if (!pm.mSettings.persistNativePrincipalPinsLPr(pm.snapshotComputer(), candidate)) {
                    return false;
                }
                pins.finishRetire(handle.pin);
                pm.mSettings.refreshNativePrincipalAppIdsLPw();
                handle.retired = true;
                handles.remove(handle.pin);
                return true;
            }
        }
    }

    private void requireRecoveryReady() {
        if (pm.mSettings.nativePrincipalRecoveryBlockedLPr()) {
            throw new IllegalStateException("Native principal settings require recovery");
        }
    }

    private Handle handle(NativePrincipalPins.Pin pin) {
        return handles.computeIfAbsent(pin, key -> new Handle(this, key));
    }

    private NativePrincipalPins checked(Handle handle) {
        if (handle == null || handle.owner != this) {
            throw new IllegalArgumentException("Foreign native principal handle");
        }
        NativePrincipalPins pins = pm.mSettings.nativePrincipalPinsLPr();
        if (pins.findId(handle.pin.record().id) != handle.pin) {
            throw new IllegalStateException("Stale native principal handle");
        }
        return pins;
    }

    private long primaryUserSerial(int userId) {
        if (userId != UserHandle.USER_SYSTEM) {
            throw new IllegalArgumentException("Native principal user is not supported yet");
        }
        UserManagerInternal users = LocalServices.getService(UserManagerInternal.class);
        UserInfo info = users == null ? null : users.getUserInfo(userId);
        if (info == null || info.partial || info.serialNumber < 0) {
            throw new IllegalStateException("Authoritative user identity unavailable");
        }
        return info.serialNumber;
    }

    private PackageSetting subject(String packageName, int userId) {
        PackageSetting setting = pm.mSettings.getPackageLPr(packageName);
        if (setting == null || setting.getPkg() == null || setting.hasSharedUser()
                || setting.getAppId() < Process.FIRST_APPLICATION_UID
                || setting.getAppId() > Process.LAST_APPLICATION_UID
                || setting.isSystem() || setting.isUpdatedSystemApp() || setting.isApex()
                || setting.isExternalStorage() || setting.getVolumeUuid() != null
                || setting.getPkg().isSdkLibrary() || setting.getPkg().isStaticSharedLibrary()
                || pm.mSettings.getSettingLPr(setting.getAppId()) != setting) {
            throw new IllegalStateException("Ordinary installed subject required");
        }
        PackageUserStateInternal state = setting.readUserState(userId);
        if (!state.isInstalled() || state.isInstantApp() || state.isHidden()
                || state.isSuspended() || state.getArchiveState() != null) {
            throw new IllegalStateException("Native principal subject unavailable");
        }
        return setting;
    }

    private void requireDesignationBinding(Handle handle) {
        if (handle.selection == null) {
            throw new IllegalStateException("Restored pin needs an explicit designation binding");
        }
        validateSelection(handle.selection);
    }

    private PackageSetting validateSelection(Selection selection) {
        PackageSetting setting = subject(selection.packageName, selection.userId);
        if (setting != selection.setting || setting.getAppId() != selection.appId
                || primaryUserSerial(selection.userId) != selection.userSerial
                || setting.getVersionCode() != selection.versionCode
                || !signerDigests(setting).equals(selection.currentSignerSha256)) {
            throw new IllegalStateException("Native account selection changed");
        }
        requireNoMutation(selection.packageName);
        return setting;
    }

    private void requireNoMutation(String packageName) {
        if (pm.mFrozenPackages.containsKey(packageName)
                || pm.isInstallingNativePrincipalPackage(packageName)
                || pm.mSettings.nativePrincipalMutationInProgressLPr(packageName)) {
            throw new IllegalStateException("Package mutation is in progress");
        }
    }

    private static Set<String> signerDigests(PackageSetting setting) {
        Signature[] signatures = setting.getSigningDetails().getSignatures();
        if (signatures == null || signatures.length == 0) {
            throw new IllegalStateException("Installed signing identity unavailable");
        }
        TreeSet<String> digests = new TreeSet<>();
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            final char[] hex = "0123456789abcdef".toCharArray();
            for (Signature signature : signatures) {
                if (signature == null) throw new IllegalStateException("Missing installed signer");
                byte[] digest = sha256.digest(signature.toByteArray());
                char[] text = new char[digest.length * 2];
                for (int i = 0; i < digest.length; ++i) {
                    text[2 * i] = hex[(digest[i] & 0xff) >>> 4];
                    text[2 * i + 1] = hex[digest[i] & 15];
                }
                if (!digests.add(new String(text))) {
                    throw new IllegalStateException("Duplicate installed signer");
                }
            }
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 unavailable", error);
        }
        return Set.copyOf(digests);
    }

    private void revalidate(NativePrincipalPins.Record record) {
        if (primaryUserSerial(record.userId) != record.userSerial
                || subject(record.packageName, record.userId).getAppId() != record.appId
                || pm.mFrozenPackages.containsKey(record.packageName)
                || pm.isInstallingNativePrincipalPackage(record.packageName)
                || pm.mSettings.nativePrincipalMutationInProgressLPr(record.packageName)) {
            throw new IllegalStateException("Native principal binding changed");
        }
    }
}
