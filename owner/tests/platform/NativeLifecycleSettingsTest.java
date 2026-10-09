// SPDX-License-Identifier: Apache-2.0
package com.android.server.pm;

import static com.android.server.pm.NativeLifecycleTestSupport.*;

import android.system.Os;
import com.android.server.pm.NativeIdentityRecords.SuspensionReason;
import com.android.server.pm.NativeIdentityStore.Format;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.List;

/**
 * The lifecycle rules of Settings, through both host copies of the adapted Settings text: the
 * facade, which carries every Settings fragment verbatim, and the history harness, which runs the
 * candidate's own boot method, observation, hold refresh, seeding, boot facts, retired boot queries
 * and release finish. A fragment defect therefore reaches both. Seeding defers retiring, retired and
 * suspended accounts. The boot facts are recorded once from the boot read, defer each package they
 * name and never follow the cached view, so disposition and release need a Settings instance that
 * began with the account RETIRED. A durable release keeps the app ID held until a new instance.
 * Host files and facades only, not Android boot.
 */
final class NativeLifecycleSettingsTest {
    private static final List<String> COPIES = List.of("facade", "harness");
    private static final String PROBE = "dev.andrix.lifecycle.probe";

    /** One booted copy of the adapted Settings text. */
    private interface Copy {
        NativePrincipalRecovery view();
        // Whether the allocator skips this app ID. The facade probes its exact allocator, which
        // registers the probe if the app ID is free, so this is asked last of a free ID.
        boolean allocatorSkips(int appId);
        boolean held(int appId);
        NativeIdentityPersistence.BootFacts facts();
        boolean retiredBoot(NativePrincipalPins.Record record);
        void observe(NativeIdentityStore.Loaded loaded);
        void finishRelease(NativePrincipalPins.Record record, NativeIdentityStore.Loaded loaded);
        NativePrincipalPins pins();
        void refresh();
        NativeIdentityStore.History stored(NativePrincipalPins.Record record);
        Object target();
    }

    private static final class FacadeCopy implements Copy {
        final Settings settings;

        FacadeCopy(Path root, Format format, boolean mapped) {
            settings = new Settings(root, false, format);
            if (mapped) settings.add(PKG_A, A);
            settings.restoreAfterPackageSettings();
        }
        @Override public NativePrincipalRecovery view() { return settings.mNativeRecoveryView; }
        @Override public boolean allocatorSkips(int appId) {
            return !settings.ids.registerExistingAppId(appId, new PackageSetting(PROBE), PROBE);
        }
        @Override public boolean held(int appId) { return settings.isNativePrincipalAppIdLPr(appId); }
        @Override public NativeIdentityPersistence.BootFacts facts() { return settings.nativeBootFactsLPr(); }
        @Override public boolean retiredBoot(NativePrincipalPins.Record record) {
            return settings.nativeRetiredBootLPr(record);
        }
        @Override public void observe(NativeIdentityStore.Loaded loaded) { settings.observeNativeIdentityStoreLPw(loaded); }
        @Override public void finishRelease(NativePrincipalPins.Record record, NativeIdentityStore.Loaded loaded) {
            settings.finishNativeIdentityReleaseLPw(record, loaded);
        }
        @Override public NativePrincipalPins pins() { return settings.nativePrincipalPinsLPr(); }
        @Override public void refresh() { settings.refreshNativePrincipalAppIdsLPw(); }
        @Override public NativeIdentityStore.History stored(NativePrincipalPins.Record record) {
            return settings.nativePrincipalStoredHistoryLPr(record);
        }
        @Override public Object target() { return settings; }
    }

    private static final class HarnessCopy implements Copy {
        final NativeHistoryHarness harness = new NativeHistoryHarness();

        HarnessCopy(Path root, Format format, boolean mapped) {
            if (mapped) harness.map(A, new NativeHistoryHarness.PackageSetting(PKG_A, A, false));
            harness.apply(load(root, format));
        }
        @Override public NativePrincipalRecovery view() { return harness.mNativeRecoveryView; }
        @Override public boolean allocatorSkips(int appId) {
            return harness.mAppIds.nativePrincipalAppIds().contains(appId);
        }
        @Override public boolean held(int appId) { return harness.isNativePrincipalAppIdLPr(appId); }
        @Override public NativeIdentityPersistence.BootFacts facts() { return harness.nativeBootFactsLPr(); }
        @Override public boolean retiredBoot(NativePrincipalPins.Record record) {
            return harness.nativeRetiredBootLPr(record);
        }
        @Override public void observe(NativeIdentityStore.Loaded loaded) { harness.observeNativeIdentityStoreLPw(loaded); }
        @Override public void finishRelease(NativePrincipalPins.Record record, NativeIdentityStore.Loaded loaded) {
            harness.finishNativeIdentityReleaseLPw(record, loaded);
        }
        @Override public NativePrincipalPins pins() { return harness.nativePrincipalPinsLPr(); }
        @Override public void refresh() { harness.refreshNativePrincipalAppIdsLPw(); }
        @Override public NativeIdentityStore.History stored(NativePrincipalPins.Record record) {
            return harness.nativePrincipalStoredHistoryLPr(record);
        }
        @Override public Object target() { return harness; }
    }

    /** A new Settings instance of this copy over the store: package settings first, then the boot. */
    private static Copy boot(String copy, Path root, Format format, boolean mapped) {
        return copy.equals("facade") ? new FacadeCopy(root, format, mapped) : new HarnessCopy(root, format, mapped);
    }

    /** Whether a second record of the boot facts throws IllegalStateException. */
    private static boolean recordAgainThrows(Copy copy, NativeIdentityStore.Loaded loaded) throws Exception {
        Method record = copy.target().getClass().getDeclaredMethod("recordNativeBootFactsLPw",
                NativeIdentityStore.Loaded.class);
        record.setAccessible(true);
        try {
            record.invoke(copy.target(), loaded);
            return false;
        } catch (InvocationTargetException thrown) {
            return thrown.getCause() instanceof IllegalStateException;
        }
    }

    private static void seedingCases() {
        run("V2 / a version 1 retiring body is deferred at seeding", problems -> {
            for (String copy : COPIES) {
                Copy booted = boot(copy, layout(slotA(2, retiring(legacyMarker()))), V2, true);
                check(problems, booted.view().defersName(PKG_A) && booted.facts().retired.isEmpty(),
                        copy + ": the retiring body's package is not deferred");
            }
        });
        run("V3 / a retiring account is deferred at seeding", problems -> {
            for (String copy : COPIES) {
                Copy booted = boot(copy, layout(slotA(2, retiring(byUserRetirement()))), V3, true);
                check(problems, booted.view().defersName(PKG_A) && booted.facts().retired.isEmpty(),
                        copy + ": the retiring account's package is not deferred");
            }
        });
        run("V3 / a suspended account is deferred at seeding", problems -> {
            for (String copy : COPIES) {
                Copy booted = boot(copy, layout(slotA(2, eligible(byUser(SuspensionReason.USER_PAUSED)))), V3, true);
                check(problems, booted.view().defersName(PKG_A) && !booted.retiredBoot(RECORD_A),
                        copy + ": the suspended account's package is not deferred");
            }
        });
        run("V3 / an eligible account stays recoverable", problems -> {
            for (String copy : COPIES) {
                Copy booted = boot(copy, layout(slotA(1, eligible())), V3, true);
                check(problems, !booted.view().defersName(PKG_A) && booted.view().protectsName(PKG_A)
                        && booted.facts().retired.isEmpty() && !booted.retiredBoot(RECORD_A),
                        copy + ": the eligible account is deferred or a fact");
            }
        });
    }

    private static void bootFactCases() {
        run("V3 / a retired account is a retired boot and is deferred", problems -> {
            for (String copy : COPIES) {
                Copy booted = boot(copy, layout(slotA(3, retired(retiredBlock()))), V3, true);
                check(problems, booted.retiredBoot(RECORD_A) && booted.facts().retired.containsKey(A)
                        && booted.view().defersName(PKG_A), copy + ": no retired boot or no deferral");
            }
        });
        run("V3 / the boot facts defer an unmapped ticketed tombstone", problems -> {
            for (String copy : COPIES) {
                Copy booted = boot(copy, layout(tombstoneA()), V3, false);
                check(problems, booted.facts().ticketedTombstones.containsKey(A)
                        && booted.view().defersName(PKG_A), copy + ": the tombstone's package is not deferred");
            }
        });
        run("V3 / the boot facts are recorded once and survive later reads", problems -> {
            for (String copy : COPIES) {
                Path root = layout(slotA(3, retired(retiredBlock())));
                Copy booted = boot(copy, root, V3, true);
                NativeIdentityPersistence.BootFacts facts = booted.facts();
                check(problems, recordAgainThrows(booted, load(root, V3)), copy + ": a second record");
                // A later read that no longer shows the account changes no fact.
                slot(root, slotA(4, retired(retiredBlock())));
                booted.observe(load(root, V3));
                slot(root, tombstoneA());
                booted.observe(load(root, V3));
                check(problems, booted.facts() == facts && booted.retiredBoot(RECORD_A)
                        && facts.ticketedTombstones.isEmpty(), copy + ": the facts changed");
            }
        });
        run("V2 / the production format gives no lifecycle fact", problems -> {
            for (String copy : COPIES) {
                Copy booted = boot(copy, layout(slotA(3, retired(retiredBlock()))), V2, true);
                check(problems, booted.facts().retired.isEmpty() && booted.facts().ticketedTombstones.isEmpty()
                        && !booted.retiredBoot(RECORD_A), copy + ": a version 2 slot gave a fact");
            }
        });
    }

    private static void retiredBootCases() {
        run("V3 / disposition needs an instance that began with the account RETIRED", problems -> {
            for (String copy : COPIES) {
                Path root = layout(slotA(2, retiring(byUserRetirement())));
                Copy booted = boot(copy, root, V3, true);
                NativeIdentityPersistence persistence = persistence(root, V3);
                check(problems, persistence.markRetired(RECORD_A, SIGNERS, receipts()), copy + ": markRetired");
                // The cached view now shows the account RETIRED. The boot facts do not.
                booted.observe(load(root, V3));
                check(problems, !booted.retiredBoot(RECORD_A) && booted.facts().retired.isEmpty(),
                        copy + ": the facts follow the cached view");
                unchanged(problems, root, copy + ": disposition in the same instance",
                        () -> persistence.beginDisposition(RECORD_A, SIGNERS, booted.facts()));
                Copy next = boot(copy, root, V3, true);
                check(problems, next.retiredBoot(RECORD_A)
                        && persistence.beginDisposition(RECORD_A, SIGNERS, next.facts()),
                        copy + ": disposition in a retired boot");
            }
        });
        run("V3 / release needs an instance that began with the account RETIRED", problems -> {
            for (String copy : COPIES) {
                Path root = layout(slotA(2, retiring(byUserRetirement())));
                Copy booted = boot(copy, root, V3, false);
                // A releasable record this instance did not begin with.
                slot(root, releasableA());
                booted.observe(load(root, V3));
                Keys keys = new Keys();
                unchanged(problems, root, copy + ": release in the same instance", () -> persistence(root, V3)
                        .release(RECORD_A, LINEAGE, SIGNERS, TICKET_A, capability(keys), booted.facts()));
                check(problems, keys.cleared.isEmpty(), copy + ": keys cleared " + keys.cleared);
                Copy next = boot(copy, root, V3, false);
                check(problems, persistence(root, V3).release(RECORD_A, LINEAGE, SIGNERS, TICKET_A,
                        capability(new Keys()), next.facts()) && releasePhase(root).equals("omitted"),
                        copy + ": release in a retired boot left " + releasePhase(root));
            }
        });
    }

    private static void releaseCases() {
        run("V3 / a durable release keeps the app ID held until a new instance", problems -> {
            for (String copy : COPIES) {
                Path root = layout(releasableA());
                Copy booted = boot(copy, root, V3, false);
                NativePrincipalPins.Pin pin = booted.pins().findId(ID_A);
                check(problems, pin != null && pin.phase() == NativePrincipalPins.Phase.RETIRING
                        && booted.stored(RECORD_A) != null && booted.retiredBoot(RECORD_A), copy + ": the boot");
                check(problems, persistence(root, V3).release(RECORD_A, LINEAGE, SIGNERS, TICKET_A,
                        capability(new Keys()), booted.facts()) && releasePhase(root).equals("omitted"),
                        copy + ": release left " + releasePhase(root));
                // The release body as the manager runs it: the release finish, the pin's end and the
                // hold refresh, in the same Settings instance.
                booted.finishRelease(RECORD_A, load(root, V3));
                if (pin != null) booted.pins().finishRetire(pin);
                booted.refresh();
                NativePrincipalRecovery view = booted.view();
                check(problems, booted.held(A) && !booted.pins().isAppIdPinned(A), copy + ": the hold");
                check(problems, booted.allocatorSkips(A), copy + ": the allocator");
                check(problems, view.protectsKeystore(A), copy + ": the key fence");
                check(problems, view.protectsObservedUid(A) && view.defersName(PKG_A), copy + ": preparation");
                check(problems, view.protectsName(PKG_A) && view.defersName(PKG_A), copy + ": mutation");
                check(problems, booted.stored(RECORD_A) == null, copy + ": the history is still remembered");
                Copy next = boot(copy, root, V3, false);
                NativePrincipalRecovery freed = next.view();
                check(problems, !next.held(A) && !freed.protectsKeystore(A) && !freed.protectsObservedUid(A)
                        && !freed.defersName(PKG_A) && !freed.protectsName(PKG_A) && !next.allocatorSkips(A),
                        copy + ": a new instance kept the app ID");
            }
        });
        run("V3 / the release finish refuses without a durable omission", problems -> {
            for (String copy : COPIES) {
                Path root = layout(releasableA());
                Copy booted = boot(copy, root, V3, false);
                try {
                    booted.finishRelease(RECORD_A, load(root, V3));
                    check(problems, false, copy + ": finished before the omission");
                } catch (IllegalStateException expected) {
                    check(problems, booted.held(A) && booted.stored(RECORD_A) != null, copy + ": changed on refusal");
                }
            }
        });
    }

    public static void main(String[] args) throws Exception {
        if (!NativeLifecycleSettingsTest.class.desiredAssertionStatus()) throw new AssertionError("run with java -ea");
        start(Path.of(args[0]).resolve("lifecycle-settings"));
        seedingCases();
        bootFactCases();
        retiredBootCases();
        releaseCases();
        finish(Os.allClosed());
        System.out.println("Settings lifecycle seeding, boot facts and release finish over both host copies;"
                + " Android unqualified");
    }
}
