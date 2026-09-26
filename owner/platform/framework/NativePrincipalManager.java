// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import android.content.pm.UserInfo;
import android.content.pm.Signature;
import android.content.pm.SigningDetails;
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
 * on native identity persistence and must not hold AMS, WM, native work control or
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
        private final String lineage;
        private final Set<String> storedSignerSha256;
        private boolean retired; // Guarded by the Package Manager mutation lock.
        private Handle(NativePrincipalManager owner, NativePrincipalPins.Pin pin, String lineage,
                Set<String> signers) {
            this.owner = owner;
            this.pin = pin;
            this.lineage = lineage;
            storedSignerSha256 = Set.copyOf(signers);
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
                NativePrincipalPins pins = pm.mSettings.nativePrincipalPinsLPr();
                NativePrincipalPins.Pin existing = pins.find(selection.packageName, selection.userId);
                if (existing == null && (!pm.mSettings.nativePrincipalCreationReadyLPr()
                        || pm.mSettings.isNativePrincipalAppIdLPr(setting.getAppId()))) {
                    throw new IllegalStateException("Native identity issuance requires recovery");
                }
                NativePrincipalPins.Pin pin = pins.prepare(selection.packageName, setting.getAppId(),
                        selection.userId, selection.userSerial);
                Handle prepared = handle(pin, selection, existing == null);
                if (!prepared.storedSignerSha256.equals(selection.currentSignerSha256)) {
                    throw new IllegalStateException("Current signer does not match prior native binding");
                }
                if (prepared.selection == null) prepared.selection = selection;
                else validateSelection(prepared.selection);
                selection.prepared = prepared;
                pm.mSettings.rememberNativeSubjectLPw(setting);
                pm.mSettings.refreshNativePrincipalAppIdsLPw();
                return prepared;
            }
        }
    }

    /**
     * Confirm the exact binding in the separate Package Manager owned slot store.
     * True means a durable UID pin, not permission to run, a CE check or a complete
     * credential profile. Admission must still bind the exact manager/user epoch.
     * False leaves this exact handle pending, including uncertain publication.
     */
    public boolean commit(Handle handle) {
        try (PackageManagerTracedLock ignored = pm.mInstallLock.acquireLock()) {
            final NativeIdentityPersistence persistence;
            final NativePrincipalPins.Snapshot issued;
            synchronized (pm.mLock) {
                NativePrincipalPins pins = checked(handle);
                requireDesignationBinding(handle);
                revalidate(handle.pin.record());
                if (handle.pin.phase() == NativePrincipalPins.Phase.RETIRING) {
                    throw new IllegalStateException("Native principal is retiring");
                }
                persistence = pm.mSettings.nativeIdentityPersistenceLPr();
                issued = pins.hasKnownCounter() ? pins.snapshotForWrite() : null;
            }
            // No PMS state/control lock is held during persistence.
            boolean durable = persistBinding(handle, persistence, issued);
            NativeIdentityStore.Loaded observed = persistence.load();
            synchronized (pm.mLock) {
                pm.mSettings.observeNativeIdentityStoreLPw(observed);
                NativePrincipalPins pins = checked(handle);
                if (!durable) return false;
                // A changed subject after publication retains the original pin;
                // it must never be reported as a new request with no effects.
                try {
                    requireDesignationBinding(handle);
                    requirePublishedBinding(handle);
                    revalidate(handle.pin.record());
                } catch (IllegalStateException changed) { return false; }
                pins.commit(handle.pin);
                return true;
            }
        }
    }

    private boolean persistBinding(Handle handle, NativeIdentityPersistence persistence,
            NativePrincipalPins.Snapshot issued) {
        NativePrincipalPins.Record record = handle.pin.record();
        if (persistence.binding(record) == null) {
            if (issued == null || !persistence.reservePending(issued)) return false;
        }
        return persistence.publish(record, handle.storedSignerSha256);
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
            checked(handle);
            if (handle.pin.phase() != NativePrincipalPins.Phase.ACTIVE) {
                throw new IllegalStateException("Native principal reservation is not active");
            }
            requireDesignationBinding(handle);
            requirePublishedBinding(handle);
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
            return pin == null ? null : handle(pin, null, false);
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
            final NativeIdentityPersistence persistence;
            final NativePrincipalPins.Snapshot issued;
            synchronized (pm.mLock) {
                NativePrincipalPins pins = checked(handle);
                pins.beginRetire(handle.pin);
                persistence = pm.mSettings.nativeIdentityPersistenceLPr();
                issued = pins.hasKnownCounter() ? pins.snapshotForWrite() : null;
            }
            boolean present = persistence.binding(handle.pin.record()) != null;
            if (!present) present = persistBinding(handle, persistence, issued);
            boolean durable = present && persistence.markRetiring(handle.pin.record(),
                    handle.storedSignerSha256);
            NativeIdentityStore.Loaded observed = persistence.load();
            synchronized (pm.mLock) {
                pm.mSettings.observeNativeIdentityStoreLPw(observed);
                checked(handle);
                if (durable) handle.retirementCommitted = true;
                return durable;
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
     * The slot transaction omits ONLY this quiesced reservation. Other retiring pins
     * may still own work and remain durable. False retains the original pin and
     * still blocks reuse. Retry this same handle to reconcile an unknown result.
     */
    public boolean finishRetirementAfterQuiescence(Handle handle) {
        try (PackageManagerTracedLock ignored = pm.mInstallLock.acquireLock()) {
            final NativeIdentityPersistence persistence;
            synchronized (pm.mLock) {
                if (handle == null || handle.owner != this) {
                    throw new IllegalArgumentException("Foreign native principal handle");
                }
                if (handle.retired) return true;
                checked(handle);
                if (!handle.retirementCommitted) {
                    throw new IllegalStateException("Retirement marker is not durably confirmed");
                }
                persistence = pm.mSettings.nativeIdentityPersistenceLPr();
            }
            boolean durable = persistence.finishRetirement(handle.pin.record(), handle.lineage,
                    handle.storedSignerSha256);
            NativeIdentityStore.Loaded observed = persistence.load();
            synchronized (pm.mLock) {
                pm.mSettings.observeNativeIdentityStoreLPw(observed);
                NativePrincipalPins pins = checked(handle);
                if (!durable) return false;
                pm.mSettings.finishNativeIdentityReleaseLPw(handle.pin.record(), observed);
                pins.finishRetire(handle.pin);
                pm.mSettings.refreshNativePrincipalAppIdsLPw();
                handle.retired = true;
                handles.remove(handle.pin);
                return true;
            }
        }
    }

    private Handle handle(NativePrincipalPins.Pin pin, Selection selection, boolean newlyIssued) {
        Handle old = handles.get(pin);
        if (old != null) return old;
        NativeIdentityRecords.Slot prior = pm.mSettings.nativePrincipalStoredBindingLPr(pin.record());
        final Handle created;
        if (prior != null) created = new Handle(this, pin, prior.lineage, prior.signerSha256);
        else {
            if (selection == null || !newlyIssued) throw new IllegalStateException("Prior native identity unavailable");
            created = new Handle(this, pin, pm.mSettings.nativeIdentityLineageLPr(),
                    selection.currentSignerSha256);
        }
        handles.put(pin, created);
        return created;
    }

    private void requirePublishedBinding(Handle handle) {
        NativeIdentityRecords.Slot slot = pm.mSettings.nativePrincipalBindingLPr(handle.pin.record());
        if (slot == null || !slot.lineage.equals(handle.lineage)
                || !slot.signerSha256.equals(handle.storedSignerSha256)) {
            throw new IllegalStateException("Prior native identity is not currently verified");
        }
        for (NativeIdentityRecords.UserEntry user : slot.users) {
            if (user.id == handle.pin.record().id && user.retiring) {
                throw new IllegalStateException("Native identity is retiring");
            }
        }
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
        if (!handle.selection.currentSignerSha256.equals(handle.storedSignerSha256)) {
            throw new IllegalStateException("Native designation signer changed");
        }
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
        if (pm.mSettings.nativePrincipalDesignationDeferredLPr(packageName)
                || pm.mFrozenPackages.containsKey(packageName)
                || pm.isInstallingNativePrincipalPackage(packageName)
                || pm.mSettings.nativePrincipalMutationInProgressLPr(packageName)) {
            throw new IllegalStateException("Package mutation is in progress");
        }
    }

    private static Set<String> signerDigests(PackageSetting setting) {
        return signerDigests(setting.getSigningDetails());
    }

    static Set<String> signerDigests(SigningDetails details) {
        Signature[] signatures = details == null ? null : details.getSignatures();
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
