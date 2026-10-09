// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import android.content.pm.UserInfo;
import android.content.pm.Signature;
import android.content.pm.SigningDetails;
import android.os.Process;
import android.os.UserHandle;

import com.android.server.LocalServices;
import com.android.server.pm.pkg.PackageUserStateInternal;

import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

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
        // Where a restored pin's prior identity came from: its stored history's source, read
        // under the PMS lock when this handle was made and never changed. Null for an issuance
        // this manager owns, which keeps its original selection instead.
        private final NativeIdentityStore.Source priorSource;
        private boolean retired; // Guarded by the Package Manager mutation lock.
        // The lifecycle record's handle state, guarded by the Package Manager mutation lock.
        // Suspended: this instance closed the account's admission in memory, which nothing reopens
        // before a new instance. Released: the release engine's omission is durable and the pin
        // ended. The ticket of this handle's release, made once so every retry names it again.
        private boolean suspended;
        private boolean released;
        private NativeIdentityRecords.ReleaseTicket ticket;
        private Handle(NativePrincipalManager owner, NativePrincipalPins.Pin pin, String lineage,
                Set<String> signers, NativeIdentityStore.Source priorSource) {
            this.owner = owner;
            this.pin = pin;
            this.lineage = lineage;
            storedSignerSha256 = Set.copyOf(signers);
            this.priorSource = priorSource;
        }
    }

    /** Original issuance inputs survive failure before a Handle can be returned or indexed. */
    private static final class Issuance {
        final NativePrincipalManager owner;
        final Selection selection;
        final NativePrincipalPins.Record record;
        final String lineage;
        Handle handle; // One canonical handle, guarded by the PMS mutation lock.

        Issuance(NativePrincipalManager owner, Selection selection,
                NativePrincipalPins.Record record, String lineage) {
            this.owner = owner;
            this.selection = selection;
            this.record = record;
            this.lineage = lineage;
        }
    }

    private final PackageManagerService pm;
    // Exact prepare/find retries share a handle. Retired and released handles are removed
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
     * A thrown call may already have issued a pin; its original issuer inputs remain
     * owned, and retry or find must reconcile them rather than issue a replacement.
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
                    requireAdmissible(selection.prepared);
                    requireDesignationBinding(selection.prepared);
                    if (selection.prepared.pin.phase() == NativePrincipalPins.Phase.RETIRING) {
                        throw new IllegalStateException("Native account selection is retiring");
                    }
                    // A prior response may have failed after issuance but before
                    // these idempotent metadata updates finished.
                    pm.mSettings.rememberNativeSubjectLPw(setting);
                    pm.mSettings.refreshNativePrincipalAppIdsLPw();
                    return selection.prepared;
                }
                NativePrincipalPins pins = pm.mSettings.nativePrincipalPinsLPr();
                NativePrincipalPins.Pin existing = pins.find(selection.packageName, selection.userId);
                if (existing == null && (!pm.mSettings.nativePrincipalCreationReadyLPr()
                        || pm.mSettings.isNativePrincipalAppIdLPr(setting.getAppId()))) {
                    throw new IllegalStateException("Native identity issuance requires recovery");
                }
                final NativePrincipalPins.Pin pin;
                if (existing == null) {
                    NativePrincipalPins.Preparation proposal = pins.previewPrepare(selection.packageName,
                            setting.getAppId(), selection.userId, selection.userSerial);
                    // The proposal carries this selection's original signer set before issuance.
                    if (!pm.mSettings.nativeIdentityReservationFitsLPr(ownedPlan(pins,
                            proposal.snapshot, proposal.record, selection.currentSignerSha256))) {
                        throw new IllegalStateException("Native identity reservation admission unavailable");
                    }
                    String lineage = pm.mSettings.nativeIdentityLineageLPr();
                    if (pm.mSettings.nativePrincipalStoredHistoryLPr(proposal.record) != null) {
                        throw new IllegalStateException("Native issuance overlaps stored binding");
                    }
                    Issuance issuance = new Issuance(this, selection, proposal.record, lineage);
                    pin = pins.prepare(proposal, issuance);
                } else {
                    pin = pins.retry(selection.packageName, setting.getAppId(),
                            selection.userId, selection.userSerial);
                }
                Handle prepared = handle(pin);
                requireAdmissible(prepared);
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
            final NativeIdentityPersistence.CreationPlan issued;
            synchronized (pm.mLock) {
                NativePrincipalPins pins = checked(handle);
                requireAdmissible(handle);
                requireDesignationBinding(handle);
                revalidate(handle.pin.record());
                if (handle.pin.phase() == NativePrincipalPins.Phase.RETIRING) {
                    throw new IllegalStateException("Native principal is retiring");
                }
                persistence = pm.mSettings.nativeIdentityPersistenceLPr();
                issued = pins.hasKnownCounter()
                        ? ownedPlan(pins, pins.snapshotForWrite(), null, null) : null;
            }
            // No PMS state/control lock is held during persistence. The designation gates above
            // hold, so this handle may create its own body.
            boolean durable = persistBinding(handle, persistence, issued, true);
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

    // Without a fresh durable binding only a handle that may create its own body reserves and
    // publishes one. Otherwise this refuses before any write.
    private boolean persistBinding(Handle handle, NativeIdentityPersistence persistence,
            NativeIdentityPersistence.CreationPlan issued, boolean mayCreateBody) {
        NativePrincipalPins.Record record = handle.pin.record();
        if (persistence.binding(record) == null) {
            if (!mayCreateBody || issued == null || !persistence.reservePending(issued)) return false;
        }
        return persistence.publish(record, handle.storedSignerSha256);
    }

    // Whether this handle may create its own body: an owned issuance or an explicit rebind has a
    // designation binding, and a pin restored from its own published body republishes that
    // original body. A pin restored from a header reservation, with no eligible body in its view,
    // and never rebound may not. Read under the PMS lock.
    private static boolean mayCreateBody(Handle handle) {
        return handle.selection != null
                || handle.priorSource == NativeIdentityStore.Source.BODY;
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
            requireOpen(handle);
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
     * Reconcile a reservation, never an old process or launch. This can recover
     * the original in-memory issuance after prepare threw before returning its
     * handle. A pin restored from disk still needs explicit designation binding,
     * subject revalidation and durable commit.
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
     *
     * A pin restored from a header reservation, whose view had no eligible
     * published body, and never explicitly rebound has no designation to create
     * a body. Unless the cached view already holds its published body, this
     * throws IllegalStateException before any pin or store effect. Creating that
     * body is a separate cancellation join. If the cached body is gone from the
     * fresh store, this returns false without a write; the pin may already be
     * RETIRING, and no marker is committed.
     */
    public boolean beginRetirement(Handle handle) {
        return retire(handle, null);
    }

    // The retirement body of both paths: the version 1 marker, with no block, and the lifecycle
    // record's retirement block, which refuses under a format without lifecycle records and for a
    // block no writer writes before the pin change. Each publishes a pending creation first when the
    // handle may create its own body.
    private boolean retire(Handle handle, NativeIdentityRecords.Retirement retirement) {
        try (PackageManagerTracedLock ignored = pm.mInstallLock.acquireLock()) {
            final NativeIdentityPersistence persistence;
            final NativeIdentityPersistence.CreationPlan issued;
            final boolean mayCreateBody;
            synchronized (pm.mLock) {
                if (retirement != null) {
                    lifecycle(handle);
                    NativePrincipalPins.Record record = handle.pin.record();
                    if (!NativeIdentityStore.writableRetirement(record.userId, record.userSerial,
                            retirement)) {
                        throw new IllegalArgumentException("Retirement outside the writer rules");
                    }
                }
                NativePrincipalPins pins = checked(handle);
                mayCreateBody = mayCreateBody(handle);
                if (!mayCreateBody
                        && pm.mSettings.nativePrincipalBindingLPr(handle.pin.record()) == null) {
                    throw new IllegalStateException(
                            "Restored native reservation needs its designation before retirement");
                }
                pins.beginRetire(handle.pin);
                persistence = pm.mSettings.nativeIdentityPersistenceLPr();
                issued = pins.hasKnownCounter()
                        ? ownedPlan(pins, pins.snapshotForWrite(), null, null) : null;
            }
            boolean present = persistence.binding(handle.pin.record()) != null;
            if (!present) present = persistBinding(handle, persistence, issued, mayCreateBody);
            boolean durable = present && (retirement == null
                    ? persistence.markRetiring(handle.pin.record(), handle.storedSignerSha256)
                    : persistence.markRetiring(handle.pin.record(), handle.storedSignerSha256,
                    retirement));
            NativeIdentityStore.Loaded observed = persistence.load();
            synchronized (pm.mLock) {
                pm.mSettings.observeNativeIdentityStoreLPw(observed);
                checked(handle);
                // Only the version 1 marker admits the old release, which the lifecycle record's
                // retirement never does: its release needs the durable RETIRED record.
                if (durable && retirement == null) handle.retirementCommitted = true;
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

    /*
     * The lifecycle record's operations. No production caller exists: the account authority, the
     * recovery route and the disposition owners that call them come in later steps. Each one runs
     * under the install lock, makes its checks under the PMS lock before any effect and does its
     * store I/O with no PMS state lock held. Under a store format without lifecycle records each
     * one refuses first, before the in memory closure, any pin change and any write.
     */

    /**
     * Suspend: the account's user, or the grant holder for an account in scope. The manager
     * closes admission in memory first: it defers the package name in the recovery view for the
     * rest of this instance, which refuses designation and data preparation, and marks the handle,
     * so every activation point refuses it. Then the entry is written. An uncertain or refused
     * write keeps the closure. After a restart the durable record is the truth, so the caller
     * keeps its own durable intent and retries until the entry is confirmed, and applies pending
     * intents before it designates anything at boot. FULL keeps that intent pending too. A
     * repeated suspension by the same actor confirms the existing entry unchanged. Resuming needs a
     * new instance.
     *
     * @throws IllegalArgumentException for an entry no writer of this stage writes, before any
     *     effect
     * @throws IllegalStateException under a format without lifecycle records, or for a stale
     *     handle, before any effect
     */
    NativeIdentityPersistence.SuspensionResult suspend(Handle handle,
            NativeIdentityRecords.Suspension entry) {
        Objects.requireNonNull(entry, "entry");
        try (PackageManagerTracedLock ignored = pm.mInstallLock.acquireLock()) {
            final NativeIdentityPersistence persistence;
            final NativePrincipalPins.Record record;
            synchronized (pm.mLock) {
                persistence = lifecycle(handle);
                record = handle.pin.record();
                if (!NativeIdentityStore.writableSuspension(record.userId, record.userSerial, entry)) {
                    throw new IllegalArgumentException("Suspension entry outside the writer rules");
                }
                close(handle);
            }
            NativeIdentityPersistence.SuspensionResult result =
                    persistence.suspend(record, handle.storedSignerSha256, entry);
            observe(persistence, handle);
            return result;
        }
    }

    /**
     * Lift: removes exactly this entry, which its own actor placed, as the record holds it. A
     * recovery hold has no lift path in this stage. A lift takes effect when it is durable; the
     * caller learns that from true or, after an uncertain result, from a later read. Nothing
     * reopens here: this instance's closure stays, and eligibility returns only through a fresh
     * designation in a new instance.
     *
     * @throws IllegalArgumentException for a recovery hold, or an account user entry of another
     *     user or serial, before any effect
     * @throws IllegalStateException under a format without lifecycle records, or for a stale
     *     handle, before any effect
     */
    boolean lift(Handle handle, NativeIdentityRecords.Suspension entry) {
        Objects.requireNonNull(entry, "entry");
        try (PackageManagerTracedLock ignored = pm.mInstallLock.acquireLock()) {
            final NativeIdentityPersistence persistence;
            synchronized (pm.mLock) {
                persistence = lifecycle(handle);
            }
            boolean durable = persistence.lift(handle.pin.record(), handle.storedSignerSha256, entry);
            observe(persistence, handle);
            return durable;
        }
    }

    /**
     * Retire: the account's user with their credential, or the grant holder with authentication,
     * which the caller establishes. Closes admission in memory with an irrevocable RETIRING pin,
     * then durably writes RETIRING with this block, its actor and every kind outstanding, BEFORE
     * quiescence starts. Every suspension entry is kept. A pin that may create its own body
     * publishes it first. False keeps the RETIRING pin but does not let quiescence start; retry
     * with the same block. A restored legacy marker takes the legacy continuation block.
     *
     * @throws IllegalArgumentException for a block no writer of this stage writes, before any
     *     effect
     * @throws IllegalStateException under a format without lifecycle records, for a stale
     *     handle, and for a restored reservation without its designation, before any effect
     */
    boolean beginRetirement(Handle handle, NativeIdentityRecords.Retirement retirement) {
        return retire(handle, Objects.requireNonNull(retirement, "retirement"));
    }

    /**
     * Confirm retired: the account authority, once every retirement kind's owner gave its
     * receipt, one DISCHARGED receipt per retirement kind in kind order. The durable record becomes
     * RETIRED. It releases nothing: every disposition kind, suspension entry, pin and hold stays.
     * Disposition and release need a later instance that begins with the account RETIRED.
     *
     * @throws IllegalArgumentException for receipts outside the writer rules, before any effect
     * @throws IllegalStateException under a format without lifecycle records, for a stale handle
     *     and for a pin that is not RETIRING, before any effect
     */
    boolean confirmRetired(Handle handle, java.util.List<NativeIdentityRecords.Obligation> receipts) {
        java.util.List<NativeIdentityRecords.Obligation> copy =
                java.util.List.copyOf(Objects.requireNonNull(receipts, "receipts"));
        try (PackageManagerTracedLock ignored = pm.mInstallLock.acquireLock()) {
            final NativeIdentityPersistence persistence;
            synchronized (pm.mLock) {
                persistence = lifecycle(handle);
                if (!NativeIdentityStore.writableReceipts(copy)) {
                    throw new IllegalArgumentException("Not one receipt of each retirement kind");
                }
                requireRetiring(handle);
            }
            boolean durable = persistence.markRetired(handle.pin.record(), handle.storedSignerSha256,
                    copy);
            observe(persistence, handle);
            return durable;
        }
    }

    /**
     * Begin deletion or migration: the account's own user, or across users only the grant holder
     * with destructive confirmation, which the caller establishes. Never automatic. Allowed only in
     * a retired boot: this Settings instance's boot facts must show the account RETIRED. Every
     * disposition kind becomes DISPOSING at once, before anything is deleted, and then completes.
     *
     * @throws IllegalStateException under a format without lifecycle records, for a stale handle,
     *     for a pin that is not RETIRING and when this instance recorded no boot facts, before any
     *     effect
     */
    boolean beginDisposition(Handle handle) {
        try (PackageManagerTracedLock ignored = pm.mInstallLock.acquireLock()) {
            final NativeIdentityPersistence persistence;
            final NativeIdentityPersistence.BootFacts facts;
            synchronized (pm.mLock) {
                persistence = lifecycle(handle);
                requireRetiring(handle);
                facts = pm.mSettings.nativeBootFactsLPr();
            }
            boolean durable = persistence.beginDisposition(handle.pin.record(),
                    handle.storedSignerSha256, facts);
            observe(persistence, handle);
            return durable;
        }
    }

    /**
     * Confirm disposal: the storage, key and policy owners, on observed evidence, in a retired
     * boot. Each receipt moves its disposition kind from DISPOSING to DISCHARGED.
     *
     * @throws IllegalArgumentException for receipts outside the writer rules, before any effect
     * @throws IllegalStateException under a format without lifecycle records, for a stale handle,
     *     for a pin that is not RETIRING and when this instance recorded no boot facts, before any
     *     effect
     */
    boolean confirmDisposition(Handle handle,
            java.util.List<NativeIdentityRecords.Obligation> receipts) {
        java.util.List<NativeIdentityRecords.Obligation> copy =
                java.util.List.copyOf(Objects.requireNonNull(receipts, "receipts"));
        try (PackageManagerTracedLock ignored = pm.mInstallLock.acquireLock()) {
            final NativeIdentityPersistence persistence;
            final NativeIdentityPersistence.BootFacts facts;
            synchronized (pm.mLock) {
                persistence = lifecycle(handle);
                if (!NativeIdentityStore.writableDispositionReceipts(copy)) {
                    throw new IllegalArgumentException("Not receipts of disposition kinds");
                }
                requireRetiring(handle);
                facts = pm.mSettings.nativeBootFactsLPr();
            }
            boolean durable = persistence.confirmDisposition(handle.pin.record(),
                    handle.storedSignerSha256, copy, facts);
            observe(persistence, handle);
            return durable;
        }
    }

    /**
     * The gated release of this account's UID, which is off: nobody chooses it, and only the
     * release engine's tests hold its capability. The engine starts only when the durable record
     * is RETIRED with every obligation discharged and no suspension entry, and only in a retired
     * boot: this Settings instance's boot facts, recorded once from its boot read, must show the
     * account RETIRED. A suspension this instance closed in memory refuses too. After the engine's
     * acknowledged omission, Settings forgets the history but keeps the app ID held until a new
     * instance, the pin ends and the holds are refreshed. The handle is then stale, and a retry of
     * it returns true.
     *
     * <p>False keeps the pin, the hold and every obligation: retry this same handle, which names
     * the same ticket. The boot that wrote the tombstone does not continue it. A durable omission
     * whose reply was lost is acknowledged by a retry in this instance; in a later boot no fact
     * names the account, and the app ID is free there, with no hold.
     *
     * @throws IllegalStateException under a format without lifecycle records, for a stale handle,
     *     for a pin that is not RETIRING, for a suspension closed in this instance and when this
     *     instance recorded no boot facts, before any effect
     */
    boolean releaseUid(Handle handle, NativeIdentityPersistence.ReleaseCapability capability) {
        Objects.requireNonNull(capability, "capability");
        try (PackageManagerTracedLock ignored = pm.mInstallLock.acquireLock()) {
            final NativeIdentityPersistence persistence;
            final NativeIdentityPersistence.BootFacts facts;
            final NativeIdentityRecords.ReleaseTicket ticket;
            synchronized (pm.mLock) {
                if (handle == null || handle.owner != this) {
                    throw new IllegalArgumentException("Foreign native principal handle");
                }
                persistence = lifecycleStore();
                if (handle.released) return true;
                checked(handle);
                requireRetiring(handle);
                requireOpen(handle);
                facts = pm.mSettings.nativeBootFactsLPr();
                ticket = ticket(handle);
            }
            boolean durable = persistence.release(handle.pin.record(), handle.lineage,
                    handle.storedSignerSha256, ticket, capability, facts);
            NativeIdentityStore.Loaded observed = persistence.load();
            synchronized (pm.mLock) {
                pm.mSettings.observeNativeIdentityStoreLPw(observed);
                NativePrincipalPins pins = checked(handle);
                if (!durable) return false;
                pm.mSettings.finishNativeIdentityReleaseLPw(handle.pin.record(), observed);
                pins.finishRelease(handle.pin);
                pm.mSettings.refreshNativePrincipalAppIdsLPw();
                handle.released = true;
                handles.remove(handle.pin);
                return true;
            }
        }
    }

    // The checks every lifecycle operation makes first, under the PMS lock and before any effect:
    // this manager's current handle, and a store format that carries lifecycle records.
    private NativeIdentityPersistence lifecycle(Handle handle) {
        if (handle == null || handle.owner != this) {
            throw new IllegalArgumentException("Foreign native principal handle");
        }
        NativeIdentityPersistence persistence = lifecycleStore();
        checked(handle);
        return persistence;
    }

    // The store of this Settings instance, only under a format that carries lifecycle records.
    private NativeIdentityPersistence lifecycleStore() {
        NativeIdentityPersistence persistence = pm.mSettings.nativeIdentityPersistenceLPr();
        if (!persistence.lifecycleFormat()) {
            throw new IllegalStateException("Native lifecycle records need the lifecycle format");
        }
        return persistence;
    }

    private static void requireRetiring(Handle handle) {
        if (handle.pin.phase() != NativePrincipalPins.Phase.RETIRING) {
            throw new IllegalStateException("Native principal is not retiring");
        }
    }

    // The in memory closure of a suspension, under the PMS lock: the package name is deferred in
    // the recovery view through Settings' deferral for the rest of this instance, and the handle
    // is marked. Nothing reopens it before a new instance.
    private void close(Handle handle) {
        NativePrincipalPins.Record record = handle.pin.record();
        PackageSetting setting = pm.mSettings.getPackageLPr(record.packageName);
        pm.mSettings.deferNativePackage(record.packageName, setting == null ? null : setting.getPath());
        handle.suspended = true;
    }

    // The read after a lifecycle write, taken with no PMS state lock held, then observed under it.
    private void observe(NativeIdentityPersistence persistence, Handle handle) {
        NativeIdentityStore.Loaded observed = persistence.load();
        synchronized (pm.mLock) {
            pm.mSettings.observeNativeIdentityStoreLPw(observed);
            checked(handle);
        }
    }

    // The ticket of this handle's release, made once under the PMS lock: the last principal, user
    // and serial, and a random nonzero ticket ID. Every retry in this instance names it again. The
    // random source is made here, so nothing of it exists outside the release path.
    private static NativeIdentityRecords.ReleaseTicket ticket(Handle handle) {
        if (handle.ticket != null) return handle.ticket;
        NativePrincipalPins.Record record = handle.pin.record();
        SecureRandom random = new SecureRandom();
        byte[] id = new byte[16];
        StringBuilder text = new StringBuilder();
        do {
            random.nextBytes(id);
            text.setLength(0);
            for (byte value : id) text.append(String.format("%02x", value & 0xff));
        } while (text.toString().equals(NativeIdentityRecords.NO_REFERENCE));
        handle.ticket = new NativeIdentityRecords.ReleaseTicket(record.id, record.userId,
                record.userSerial, text.toString());
        return handle.ticket;
    }

    /**
     * The reservation plan of one complete core snapshot, built under the PMS mutation lock
     * with no I/O. A signer row comes only from a pin whose issuance this manager owns: the
     * immutable signer set its original selection captured. A proposal not yet issued supplies
     * its own selection's set. Nothing is taken from the current PackageSetting, the handle
     * index, a remembered or restored binding, or another manager. Pins without a row keep
     * their durable entries unchanged, and a new entry without one refuses.
     */
    private NativeIdentityPersistence.CreationPlan ownedPlan(NativePrincipalPins pins,
            NativePrincipalPins.Snapshot snapshot, NativePrincipalPins.Record proposed,
            Set<String> proposedSigners) {
        Map<Long, Set<String>> rows = new HashMap<>();
        for (NativePrincipalPins.Record record : snapshot.records) {
            NativePrincipalPins.Pin pin = pins.findId(record.id);
            if (pin == null) {
                if (proposed == null || !record.equals(proposed)) {
                    throw new IllegalStateException("Native reservation snapshot changed");
                }
                rows.put(record.id, proposedSigners);
            } else if (!pin.record().equals(record)) {
                throw new IllegalStateException("Native reservation snapshot changed");
            } else if (pin.issuance() instanceof Issuance issuance && issuance.owner == this) {
                if (!issuance.record.equals(record)) {
                    throw new IllegalStateException("Native issuance provenance changed");
                }
                rows.put(record.id, issuance.selection.currentSignerSha256);
            }
        }
        return new NativeIdentityPersistence.CreationPlan(snapshot, rows);
    }

    private Handle handle(NativePrincipalPins.Pin pin) {
        Handle old = handles.get(pin);
        if (old != null) return old;
        if (pin.issuance() instanceof Issuance issuance && issuance.owner == this) {
            if (!pin.record().equals(issuance.record)) {
                throw new IllegalStateException("Native issuance provenance changed");
            }
            if (issuance.handle == null) {
                Handle created = new Handle(this, pin, issuance.lineage,
                        issuance.selection.currentSignerSha256, null);
                created.selection = issuance.selection;
                issuance.handle = created;
            }
            // Indexing may fail, but the pin still owns the original facts and
            // canonical handle. A retry never takes history from a new APK.
            handles.put(pin, issuance.handle);
            return issuance.handle;
        }
        // A restored pin: its original stored history, a body or a header reservation, with
        // that history's lineage and signers and its immutable source. Never the current APK.
        NativeIdentityStore.History prior = pm.mSettings.nativePrincipalStoredHistoryLPr(pin.record());
        if (prior == null) throw new IllegalStateException("Prior native identity unavailable");
        Handle created = new Handle(this, pin, prior.lineage, prior.signerSha256, prior.source);
        handles.put(pin, created);
        return created;
    }

    private void requirePublishedBinding(Handle handle) {
        NativeIdentityRecords.Slot slot = pm.mSettings.nativePrincipalBindingLPr(handle.pin.record());
        if (slot == null || !slot.lineage.equals(handle.lineage)
                || !slot.signerSha256.equals(handle.storedSignerSha256)) {
            throw new IllegalStateException("Prior native identity is not currently verified");
        }
        // Only an ELIGIBLE account without a suspension entry is active. This replaces the check
        // of the retiring flag, which covers RETIRING and RETIRED.
        for (NativeIdentityRecords.UserEntry user : slot.users) {
            if (user.id == handle.pin.record().id && !active(user.lifecycle)) {
                throw new IllegalStateException("Native identity is retiring or suspended");
            }
        }
    }

    private static boolean active(NativeIdentityRecords.Lifecycle lifecycle) {
        return lifecycle.state == NativeIdentityRecords.LifecycleState.ELIGIBLE
                && lifecycle.suspensions.isEmpty();
    }

    // The suspension refusal of an activation point that writes or admits before it reads any
    // published binding: preparation and commit. Read under the PMS lock, before any effect.
    private void requireAdmissible(Handle handle) {
        requireOpen(handle);
        NativeIdentityRecords.Slot slot = pm.mSettings.nativePrincipalBindingLPr(handle.pin.record());
        if (slot == null) return;
        for (NativeIdentityRecords.UserEntry user : slot.users) {
            if (user.id == handle.pin.record().id && !user.lifecycle.suspensions.isEmpty()) {
                throw new IllegalStateException("Native account is suspended");
            }
        }
    }

    // This instance's in memory closure of a suspension, which nothing reopens before a new
    // instance. Read under the PMS lock.
    private static void requireOpen(Handle handle) {
        if (handle.suspended) throw new IllegalStateException("Native account is suspended");
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
