// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeLifecycleTestSupport.*;

import android.system.Os;
import com.android.server.LocalServices;
import com.android.server.pm.NativeIdentityPersistence.SuspensionResult;
import com.android.server.pm.NativeIdentityRecords.Lifecycle;
import com.android.server.pm.NativeIdentityRecords.Slot;
import com.android.server.pm.NativeIdentityRecords.Suspension;
import com.android.server.pm.NativeIdentityRecords.SuspensionReason;
import com.android.server.pm.NativeIdentityRecords.UserEntry;
import com.android.server.pm.NativeIdentityStore.Format;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The manager's lifecycle operations over the actual store, persistence, pins and the Settings
 * facade, which carries every Settings fragment verbatim: the format refusals before any effect,
 * the in memory closure of a suspension, every activation point's suspension refusal, the retired
 * boot rule and the gated release.
 *
 * <p>Locks: production's Settings lock is the Package Manager lock. The host PMS facade has its own
 * lock object, which every case names as the forbidden monitor of store I/O. The host Os facade
 * checks it when the store opens a directory to sync it, which every store write does, and the
 * runner injects the same check at the start of every store load into the store copy this suite
 * compiles. So a store load or a directory sync under that lock fails the case. The facade's
 * Settings keeps a separate lock of its own, which only serializes its deferral, as production's
 * same lock does. Host files and facades only, not Android boot or authority.
 */
final class NativeLifecycleManagerTest {
    private static final String FORMAT_REFUSAL = "Native lifecycle records need the lifecycle format";
    private static final String SUSPENDED = "Native account is suspended";
    private static final String NOT_ACTIVE = "Native identity is retiring or suspended";
    // The installed host package's signer set: the facade's PackageSetting signs with one fixed key.
    private static final Set<String> INSTALLED = NativePrincipalManager.signerDigests(
            new PackageSetting(PKG_A).getSigningDetails());
    private static final NativePrincipalPins.Record RECORD = new NativePrincipalPins.Record(ID_A, PKG_A, A, 0, SERIAL);

    interface Call { void run() throws Exception; }

    /** One booted Settings instance with its PMS facade and a manager. */
    static final class Booted {
        final Path root;
        final PackageManagerService pm;
        final NativePrincipalManager manager;

        Booted(Path root, Format format, boolean mapped) {
            this.root = root;
            pm = new PackageManagerService(root, false, format);
            if (mapped) pm.mSettings.add(PKG_A, A);
            pm.mSettings.restoreAfterPackageSettings();
            manager = new NativePrincipalManager(pm);
            Os.forbiddenMonitor = pm.mLock;
        }

        NativePrincipalManager.Handle handle() {
            return manager.find(PKG_A, 0);
        }

        NativePrincipalManager.Handle designate() {
            return manager.prepare(manager.select(PKG_A, 0));
        }

        NativePrincipalRecovery view() {
            return pm.mSettings.mNativeRecoveryView;
        }

        /** A read this instance observes, as every manager write does after its store I/O. */
        void observe() {
            NativeIdentityStore.Loaded loaded = load(root, pm.mSettings.store.format());
            synchronized (pm.mLock) {
                pm.mSettings.observeNativeIdentityStoreLPw(loaded);
            }
        }
    }

    /** A's account at this generation with the installed package's signers. */
    static Slot account(long generation, Lifecycle lifecycle) {
        return new Slot(LINEAGE, A, PKG_A, generation, INSTALLED, List.of(new UserEntry(ID_A, 0, SERIAL, lifecycle)));
    }

    /** A LIVE store of A, eligible with no suspension: version 1 bytes. */
    static Path eligibleStore() throws Exception {
        return layout(account(1, eligible()));
    }

    /** The message of the IllegalStateException this call throws, or null when it throws none. */
    static String refusal(Call call) throws Exception {
        try {
            call.run();
            return null;
        } catch (IllegalStateException refused) {
            return refused.getMessage();
        }
    }

    static Lifecycle lifecycle(Path root) {
        Slot slot = stored(root, V3);
        return slot == null ? null : slot.users.get(0).lifecycle;
    }

    /** The receipts of A's retirement: one DISCHARGED receipt for each retirement kind. */
    static final List<NativeIdentityRecords.Obligation> RECEIPTS = receipts();

    // ------------------------------------------------------------------ format refusals

    /**
     * Every lifecycle operation of the manager under a format without lifecycle records: each
     * refuses with the format refusal, the store's every byte, file identity and time unchanged, the
     * pin's phase unchanged and no closure, so the account still designates and commits.
     */
    static void earlierFormat(List<String> problems, Format format) throws Exception {
        Path root = eligibleStore();
        Booted booted = new Booted(root, format, true);
        NativePrincipalManager manager = booted.manager;
        NativePrincipalManager.Handle handle = booted.handle();
        Map<String, Call> calls = new java.util.LinkedHashMap<>();
        calls.put("suspend", () -> manager.suspend(handle, byUser(SuspensionReason.USER_PAUSED)));
        calls.put("lift", () -> manager.lift(handle, byUser(SuspensionReason.USER_PAUSED)));
        calls.put("beginRetirement", () -> manager.beginRetirement(handle, byUserRetirement()));
        calls.put("confirmRetired", () -> manager.confirmRetired(handle, RECEIPTS));
        calls.put("beginDisposition", () -> manager.beginDisposition(handle));
        calls.put("confirmDisposition", () -> manager.confirmDisposition(handle,
                disposals(dispositionKinds())));
        calls.put("releaseUid", () -> manager.releaseUid(handle, capability(new Keys())));
        for (Map.Entry<String, Call> call : calls.entrySet()) {
            age(root);
            Map<String, String> before = footprint(root);
            String refused = refusal(call.getValue());
            check(problems, FORMAT_REFUSAL.equals(refused), format + " " + call.getKey() + " gave " + refused);
            check(problems, footprint(root).equals(before), format + " " + call.getKey() + " changed the store");
            check(problems, manager.phase(handle) == NativePrincipalPins.Phase.PENDING,
                    format + " " + call.getKey() + " changed the pin");
            check(problems, !booted.view().defersName(PKG_A), format + " " + call.getKey() + " closed admission");
        }
        // Nothing closed the account: it designates and commits as before.
        check(problems, booted.designate() == handle && manager.commit(handle)
                && manager.currentIdentity(handle).equals(RECORD), format + ": the account no longer activates");
    }

    private static void formatCases() {
        run("V1 / every lifecycle operation refuses before any effect", problems -> earlierFormat(problems, V1));
        run("V2 / every lifecycle operation refuses before any effect", problems -> earlierFormat(problems, V2));
    }

    // ------------------------------------------------------------------ suspension and its closure

    private static void suspensionCases() {
        run("V3 / suspension closes admission in memory and then writes its entry", problems -> {
            Path root = eligibleStore();
            Booted booted = new Booted(root, V3, true);
            NativePrincipalManager manager = booted.manager;
            NativePrincipalManager.Handle handle = booted.handle();
            check(problems, booted.designate() == handle && manager.commit(handle), "the account did not activate");
            Suspension entry = byUser(SuspensionReason.USER_PAUSED);
            check(problems, manager.suspend(handle, entry) == SuspensionResult.SUSPENDED, "not suspended");
            Lifecycle durable = lifecycle(root);
            check(problems, durable != null && durable.suspensions.equals(List.of(entry)), "no durable entry");
            check(problems, booted.view().defersName(PKG_A), "the package name is not deferred");
            check(problems, refusal(() -> manager.select(PKG_A, 0)) != null, "designation still selects");
            check(problems, SUSPENDED.equals(refusal(() -> manager.currentIdentity(handle))), "currentIdentity");
            check(problems, SUSPENDED.equals(refusal(() -> manager.commit(handle))), "commit");
            // A repeated suspension by the same actor confirms the existing entry unchanged.
            check(problems, manager.suspend(handle, entry) == SuspensionResult.SUSPENDED
                    && manager.suspend(handle, byUser(SuspensionReason.DEVICE_HANDOVER))
                    == SuspensionResult.HELD_UNCHANGED && lifecycle(root).suspensions.equals(List.of(entry)),
                    "the repeated suspension changed the entry");
        });
        run("V3 / a lift is durable but nothing reopens in this instance", problems -> {
            Path root = eligibleStore();
            Booted booted = new Booted(root, V3, true);
            NativePrincipalManager manager = booted.manager;
            NativePrincipalManager.Handle handle = booted.handle();
            check(problems, booted.designate() == handle && manager.commit(handle), "the account did not activate");
            Suspension entry = byUser(SuspensionReason.USER_PAUSED);
            check(problems, manager.suspend(handle, entry) == SuspensionResult.SUSPENDED, "not suspended");
            check(problems, manager.lift(handle, entry), "not lifted");
            Lifecycle durable = lifecycle(root);
            check(problems, durable != null && durable.suspensions.isEmpty()
                    && stored(root, V3).version == 1, "the lift is not durable version 1 bytes");
            check(problems, booted.view().defersName(PKG_A), "the closure reopened");
            check(problems, SUSPENDED.equals(refusal(() -> manager.currentIdentity(handle))), "currentIdentity");
            // A new instance designates the account again.
            Booted next = new Booted(root, V3, true);
            NativePrincipalManager.Handle again = next.handle();
            check(problems, next.designate() == again && next.manager.commit(again)
                    && next.manager.currentIdentity(again).equals(RECORD), "a new instance does not admit it");
        });
        run("V3 / a refused or uncertain suspension write keeps the closure", problems -> {
            Path root = eligibleStore();
            Booted booted = new Booted(root, V3, true);
            NativePrincipalManager manager = booted.manager;
            NativePrincipalManager.Handle handle = booted.handle();
            check(problems, booted.designate() == handle && manager.commit(handle), "the account did not activate");
            Os.failSync = true;
            SuspensionResult uncertain;
            try {
                uncertain = manager.suspend(handle, byUser(SuspensionReason.USER_PAUSED));
            } finally {
                Os.failSync = false;
            }
            check(problems, uncertain == SuspensionResult.REFUSED, "an uncertain write gave " + uncertain);
            check(problems, booted.view().defersName(PKG_A), "the uncertain write dropped the deferral");
            check(problems, SUSPENDED.equals(refusal(() -> manager.currentIdentity(handle))), "currentIdentity");
            check(problems, SUSPENDED.equals(refusal(() -> manager.commit(handle))), "commit");
            // The caller retries from its own durable intent until the entry is confirmed.
            check(problems, manager.suspend(handle, byUser(SuspensionReason.USER_PAUSED)) == SuspensionResult.SUSPENDED
                    && lifecycle(root).suspensions.size() == 1, "the retry did not confirm the entry");
        });
        run("V3 / suspension refuses an entry no writer writes before any effect", problems -> {
            Path root = eligibleStore();
            Booted booted = new Booted(root, V3, true);
            NativePrincipalManager.Handle handle = booted.handle();
            invalid(problems, root, "a recovery hold", () -> {
                booted.manager.suspend(handle, hold(0));
                return true;
            });
            check(problems, !booted.view().defersName(PKG_A), "the refused entry closed admission");
        });
    }

    // ------------------------------------------------------------------ activation points

    /** A durable suspension this instance did not close: written by the store's transaction, then observed. */
    static void suspendedElsewhere(Booted booted) {
        if (persistence(booted.root, V3).suspend(RECORD, INSTALLED, byGrant(1, SuspensionReason.CREDENTIAL_EXPOSED))
                != SuspensionResult.SUSPENDED) throw new AssertionError("fixture suspension");
        booted.observe();
    }

    /**
     * A closure whose write was refused before any effect, with the store's durable record still
     * eligible: the slot directory is moved away for the write and back after it. The deferral is
     * then taken back out of the facade's recovery view, so the handle's mark alone stands.
     */
    static void markedOnly(List<String> problems, Booted booted, NativePrincipalManager.Handle handle)
            throws Exception {
        NativePrincipalRecovery open = booted.view();
        Path slots = booted.root.resolve("slots");
        Path away = booted.root.resolveSibling("slots-away");
        Files.move(slots.resolve(String.valueOf(A)), away);
        SuspensionResult result;
        try {
            result = booted.manager.suspend(handle, byUser(SuspensionReason.USER_PAUSED));
        } finally {
            Files.move(away, slots.resolve(String.valueOf(A)));
        }
        booted.observe();
        check(problems, result == SuspensionResult.REFUSED && booted.view().defersName(PKG_A),
                "the refused write gave " + result + " or no closure");
        Lifecycle durable = lifecycle(booted.root);
        check(problems, durable != null && durable.suspensions.isEmpty(), "the refused write left an entry");
        booted.pm.mSettings.mNativeRecoveryView = open;
    }

    private static void activationCases() {
        run("V3 / preparation refuses a durably suspended account", problems -> {
            Booted booted = new Booted(eligibleStore(), V3, true);
            NativePrincipalManager.Handle handle = booted.handle();
            suspendedElsewhere(booted);
            check(problems, SUSPENDED.equals(refusal(booted::designate)), "preparation admitted it");
            check(problems, booted.manager.phase(handle) == NativePrincipalPins.Phase.PENDING, "the pin changed");
        });
        run("V3 / preparation refuses a handle closed in memory", problems -> {
            Booted booted = new Booted(eligibleStore(), V3, true);
            NativePrincipalManager.Handle handle = booted.handle();
            markedOnly(problems, booted, handle);
            check(problems, SUSPENDED.equals(refusal(booted::designate)), "preparation admitted it");
        });
        run("V3 / commit refuses a durably suspended account before any write", problems -> {
            Booted booted = new Booted(eligibleStore(), V3, true);
            NativePrincipalManager.Handle handle = booted.handle();
            check(problems, booted.designate() == handle, "not designated");
            suspendedElsewhere(booted);
            age(booted.root);
            Map<String, String> before = footprint(booted.root);
            check(problems, SUSPENDED.equals(refusal(() -> booted.manager.commit(handle))), "commit did not refuse");
            check(problems, footprint(booted.root).equals(before), "commit changed the store");
            check(problems, booted.manager.phase(handle) == NativePrincipalPins.Phase.PENDING, "the pin changed");
        });
        run("V3 / commit refuses a handle closed in memory", problems -> {
            Booted booted = new Booted(eligibleStore(), V3, true);
            NativePrincipalManager.Handle handle = booted.handle();
            check(problems, booted.designate() == handle, "not designated");
            markedOnly(problems, booted, handle);
            check(problems, SUSPENDED.equals(refusal(() -> booted.manager.commit(handle))), "commit admitted it");
            check(problems, booted.manager.phase(handle) == NativePrincipalPins.Phase.PENDING, "the pin changed");
        });
        run("V3 / currentIdentity refuses a handle closed in memory", problems -> {
            Booted booted = new Booted(eligibleStore(), V3, true);
            NativePrincipalManager.Handle handle = booted.handle();
            check(problems, booted.designate() == handle && booted.manager.commit(handle), "not active");
            markedOnly(problems, booted, handle);
            check(problems, SUSPENDED.equals(refusal(() -> booted.manager.currentIdentity(handle))),
                    "currentIdentity admitted it");
        });
        run("V3 / the published binding check refuses a durably suspended account", problems -> {
            Booted booted = new Booted(eligibleStore(), V3, true);
            NativePrincipalManager.Handle handle = booted.handle();
            check(problems, booted.designate() == handle && booted.manager.commit(handle), "not active");
            suspendedElsewhere(booted);
            check(problems, NOT_ACTIVE.equals(refusal(() -> booted.manager.currentIdentity(handle))),
                    "currentIdentity admitted it");
        });
    }

    // ------------------------------------------------------------------ retirement

    private static void retirementCases() {
        run("V3 / retirement moves the pin and then writes its block", problems -> {
            Path root = eligibleStore();
            Booted booted = new Booted(root, V3, true);
            NativePrincipalManager manager = booted.manager;
            NativePrincipalManager.Handle handle = booted.handle();
            check(problems, booted.designate() == handle && manager.commit(handle), "not active");
            check(problems, manager.beginRetirement(handle, byUserRetirement()), "not retiring");
            Lifecycle durable = lifecycle(root);
            check(problems, durable != null && durable.state == NativeIdentityRecords.LifecycleState.RETIRING
                    && byUserRetirement().equals(durable.retirement), "no durable retirement block");
            check(problems, manager.phase(handle) == NativePrincipalPins.Phase.RETIRING, "the pin is not retiring");
            check(problems, manager.beginRetirement(handle, byUserRetirement()), "the retry was not confirmed");
            // The old release never follows the lifecycle record's retirement.
            check(problems, refusal(() -> manager.finishRetirementAfterQuiescence(handle)) != null,
                    "the old release followed");
            check(problems, manager.confirmRetired(handle, RECEIPTS), "not retired");
            durable = lifecycle(root);
            check(problems, durable != null && durable.state == NativeIdentityRecords.LifecycleState.RETIRED
                    && retiredBlock().equals(durable.retirement), "no durable RETIRED record");
            check(problems, manager.phase(handle) == NativePrincipalPins.Phase.RETIRING
                    && booted.pm.mSettings.isNativePrincipalAppIdLPr(A), "confirming retired released something");
        });
        run("V3 / retirement refuses a block no writer writes before the pin change", problems -> {
            Path root = eligibleStore();
            Booted booted = new Booted(root, V3, true);
            NativePrincipalManager.Handle handle = booted.handle();
            invalid(problems, root, "a legacy marker over an eligible account", () ->
                    booted.manager.beginRetirement(handle, legacyMarker()));
            check(problems, booted.manager.phase(handle) == NativePrincipalPins.Phase.PENDING, "the pin changed");
        });
    }

    // ------------------------------------------------------------------ the release gate

    private static final String PROBE = "dev.andrix.lifecycle.probe";

    /** A RETIRED with every obligation discharged and no suspension entry, under the installed signers. */
    static Slot releasable() {
        return account(3, retired(allDischarged(byUserRetirement())));
    }

    /** Whether A's release is durably omitted: no header entry, no slot read and no directory. */
    static boolean omitted(Path root) {
        NativeIdentityStore.Loaded loaded = load(root, V3);
        if (loaded.header.status != NativeIdentityStore.Status.VALID || loaded.slots.containsKey(A)) return false;
        for (NativeIdentityRecords.HeaderEntry entry : loaded.header.value.entries) if (entry.appId == A) return false;
        return !Files.exists(root.resolve("slots/" + A));
    }

    /** What this instance keeps of a released account until a new instance, and what it forgets. */
    static void heldUntilANewInstance(List<String> problems, Booted booted, NativePrincipalManager.Handle handle)
            throws Exception {
        NativePrincipalRecovery view = booted.view();
        check(problems, booted.pm.mSettings.isNativePrincipalAppIdLPr(A)
                && !booted.pm.mSettings.pins.isAppIdPinned(A), "the hold");
        check(problems, view.protectsKeystore(A) && view.protectsObservedUid(A), "the key and data fences");
        check(problems, booted.manager.find(PKG_A, 0) == null
                && booted.pm.mSettings.nativePrincipalStoredHistoryLPr(RECORD) == null, "the pin or history");
        check(problems, refusal(() -> booted.manager.phase(handle)) != null, "the handle is not stale");
        check(problems, !booted.pm.mSettings.ids.registerExistingAppId(A, new PackageSetting(PROBE), PROBE),
                "the allocator");
    }

    /** A new instance holds nothing of the released account: the app ID is free there. */
    static void freeInANewInstance(List<String> problems, Path root) {
        Booted next = new Booted(root, V3, false);
        NativePrincipalRecovery view = next.view();
        check(problems, !next.pm.mSettings.isNativePrincipalAppIdLPr(A) && !view.protectsKeystore(A)
                && !view.protectsObservedUid(A) && !view.defersName(PKG_A) && next.handle() == null
                && next.pm.mSettings.ids.registerExistingAppId(A, new PackageSetting(PROBE), PROBE),
                "a new instance kept the app ID");
    }

    private static void releaseCases() {
        run("V3 / disposition and release need an instance that began with the account RETIRED", problems -> {
            Path root = layout(account(2, retiring(byUserRetirement())));
            Booted booted = new Booted(root, V3, false);
            NativePrincipalManager manager = booted.manager;
            NativePrincipalManager.Handle handle = booted.handle();
            check(problems, manager.confirmRetired(handle, RECEIPTS), "not retired");
            unchanged(problems, root, "disposition in the instance that confirmed retired", () ->
                    manager.beginDisposition(handle));
            // The record becomes releasable in this instance: its boot facts still lack it.
            slot(root, releasable());
            booted.observe();
            Keys keys = new Keys();
            unchanged(problems, root, "release in the instance that confirmed retired", () ->
                    manager.releaseUid(handle, capability(keys)));
            check(problems, keys.cleared.isEmpty() && manager.phase(handle) == NativePrincipalPins.Phase.RETIRING,
                    "the refused release cleared keys or ended the pin");
            Booted next = new Booted(root, V3, false);
            NativePrincipalManager.Handle again = next.handle();
            check(problems, next.manager.beginDisposition(again), "disposition in a retired boot");
            check(problems, next.manager.releaseUid(again, capability(new Keys())) && omitted(root),
                    "release in a retired boot");
        });
        run("V3 / the release body keeps the app ID held until a new instance", problems -> {
            Path root = layout(releasable());
            Booted booted = new Booted(root, V3, false);
            NativePrincipalManager manager = booted.manager;
            NativePrincipalManager.Handle handle = booted.handle();
            Keys keys = new Keys();
            check(problems, handle != null && manager.releaseUid(handle, capability(keys)) && omitted(root),
                    "not released");
            check(problems, keys.cleared.equals(List.of(A)), "keys cleared " + keys.cleared);
            heldUntilANewInstance(problems, booted, handle);
            // A retry of the released handle acknowledges it again, with no effect.
            age(root);
            Map<String, String> before = footprint(root);
            check(problems, manager.releaseUid(handle, capability(new Keys())) && footprint(root).equals(before),
                    "the retry");
            freeInANewInstance(problems, root);
        });
        run("V3 / a lost reply after the omission is acknowledged in the instance and freed at the next boot",
                problems -> {
            // The release's directory syncs, counted on a twin store.
            Booted twin = new Booted(layout(releasable()), V3, false);
            int start = Os.syncCalls;
            check(problems, twin.manager.releaseUid(twin.handle(), capability(new Keys())), "the twin release");
            int syncs = Os.syncCalls - start;
            Path root = layout(releasable());
            Booted booted = new Booted(root, V3, false);
            NativePrincipalManager.Handle handle = booted.handle();
            // The last sync fails: the omission is durable, and its acknowledgement is lost.
            Os.failSyncAt = Os.syncCalls + syncs;
            boolean first;
            try {
                first = booted.manager.releaseUid(handle, capability(new Keys()));
            } finally {
                Os.failSyncAt = 0;
            }
            check(problems, !first && omitted(root), "the first reply " + first + " omitted " + omitted(root));
            check(problems, booted.manager.phase(handle) == NativePrincipalPins.Phase.RETIRING
                    && booted.pm.mSettings.nativePrincipalStoredHistoryLPr(RECORD) != null,
                    "an unacknowledged release ended the pin or forgot the history");
            check(problems, booted.manager.releaseUid(handle, capability(new Keys())), "the retry");
            heldUntilANewInstance(problems, booted, handle);
            freeInANewInstance(problems, root);
        });
        run("V3 / release refuses before any effect without its gate", problems -> {
            // A durable suspension entry.
            Path suspended = layout(account(3, retired(allDischarged(byUserRetirement()),
                    byUser(SuspensionReason.USER_PAUSED))));
            Booted held = new Booted(suspended, V3, false);
            Keys keys = new Keys();
            unchanged(problems, suspended, "release of a suspended account", () ->
                    held.manager.releaseUid(held.handle(), capability(keys)));
            // Open obligations: the disposition kinds are outstanding.
            Path open = layout(account(3, retired(retiredBlock())));
            Booted outstanding = new Booted(open, V3, false);
            unchanged(problems, open, "release with open obligations", () ->
                    outstanding.manager.releaseUid(outstanding.handle(), capability(keys)));
            // A durable record that is not RETIRED.
            Path retiring = layout(account(2, retiring(byUserRetirement())));
            Booted early = new Booted(retiring, V3, false);
            unchanged(problems, retiring, "release of a retiring account", () ->
                    early.manager.releaseUid(early.handle(), capability(keys)));
            check(problems, keys.cleared.isEmpty(), "keys cleared " + keys.cleared);
            // No capability, and no recorded boot facts, as for a snapshot: refused by exception.
            Path root = layout(releasable());
            Booted booted = new Booted(root, V3, false);
            NativePrincipalManager.Handle handle = booted.handle();
            age(root);
            Map<String, String> before = footprint(root);
            try {
                booted.manager.releaseUid(handle, null);
                problems.add("released without a capability");
            } catch (NullPointerException expected) {
                // Refused before any effect.
            }
            NativeIdentityPersistence.BootFacts facts = booted.pm.mSettings.mNativeBootFacts;
            booted.pm.mSettings.mNativeBootFacts = null;
            check(problems, "Native boot facts are not recorded".equals(refusal(() ->
                    booted.manager.releaseUid(handle, capability(new Keys())))), "released without boot facts");
            booted.pm.mSettings.mNativeBootFacts = facts;
            check(problems, footprint(root).equals(before)
                    && booted.manager.phase(handle) == NativePrincipalPins.Phase.RETIRING, "a refusal had an effect");
        });
        run("V3 / release refuses a suspension closed in memory before any effect", problems -> {
            Path root = layout(releasable());
            Booted booted = new Booted(root, V3, false);
            NativePrincipalManager.Handle handle = booted.handle();
            markedOnly(problems, booted, handle);
            Keys keys = new Keys();
            age(root);
            Map<String, String> before = footprint(root);
            check(problems, SUSPENDED.equals(refusal(() -> booted.manager.releaseUid(handle, capability(keys)))),
                    "released while a suspension is pending");
            check(problems, footprint(root).equals(before) && keys.cleared.isEmpty(), "the refusal had an effect");
        });
    }

    public static void main(String[] args) throws Exception {
        if (!NativeLifecycleManagerTest.class.desiredAssertionStatus()) throw new AssertionError("run with java -ea");
        LocalServices.addService(UserManagerInternal.class, new UserManagerInternal());
        start(Path.of(args[0]).resolve("lifecycle-manager"));
        formatCases();
        suspensionCases();
        activationCases();
        retirementCases();
        releaseCases();
        Os.forbiddenMonitor = null;
        finish(Os.allClosed());
        System.out.println("Manager lifecycle operations over the actual store and the Settings facade;"
                + " Android unqualified");
    }
}
