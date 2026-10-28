# SPDX-License-Identifier: Apache-2.0
"""Bounded pure source checks. Android/JVM execution requires separate admission."""
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import native_account_inspection as guard
import grapheneos_candidate as candidate


def source(path):
    return (ROOT / path).read_text()


class NativeAccountInspectionSourceTests(unittest.TestCase):
    def test_selected_candidate_and_exact_new_fragment(self):
        self.assertIn('selected in-place Settings inspection', guard.inspect())
        # Selected current recipe names the real Manager, adapted Settings and tracked fragment.
        selected = guard.pins.profile()
        settings = next(row for row in selected['files'] if row['path'].endswith('/Settings.java'))
        self.assertEqual(settings['candidate_sha256'],
                         'eab4ec31c8bad9153065400db9935edb3de499f3ce4169bddd4e9a159625ffaa')
        self.assertEqual(selected['fragments'][-1]['name'], 'inspection')
        self.assertIn('inspection', guard.pins.FRAGMENTS)
        self.assertIn('nativeAccountInspectionLPr', source(
            'owner/tests/platform/native_principal_stubs/com/android/server/pm/Settings.java'))
        self.assertIn('nativeAccountInspectionLPr',
                      source('patches/grapheneos-2026081300/native-principal-pins.patch'))

    def test_selected_profile_boolean_version_refused(self):
        decode = guard.pins.json.loads

        def substituted(data, **kwargs):
            value = decode(data, **kwargs)
            if isinstance(value, dict) and 'files' in value and 'added' in value and 'fragments' in value:
                value['version'] = True
            return value

        with mock.patch.object(guard.pins.json, 'loads', side_effect=substituted):
            with self.assertRaisesRegex(ValueError, 'native principal profile drift'):
                guard.inspect()

    def test_selected_six_family_source_inventory(self):
        # This is the existing source-only checker, not its network/checkout/build mode.
        report = candidate.patch_set()
        self.assertEqual(set(report['patches']), set(candidate.PATCH_NAMES))
        selected = guard.pins.PROFILE.parent
        expected = {name + extension for name in candidate.PATCH_NAMES
                    for extension in ('.json', '.patch')}
        self.assertEqual({entry.name for entry in selected.iterdir()} - {'README.md'}, expected)
        self.assertNotIn('native-account-inspection.patch', expected)

    def test_immutable_cached_projection_no_mutator_or_store_io(self):
        manager = source('owner/platform/framework/NativePrincipalManager.java')
        inspected = manager[manager.index('public static final class Inspection {'):
                            manager.index('    private final PackageManagerService pm;')]
        self.assertIn('List.copyOf(rows)', inspected)
        self.assertIn('MAX_ROWS = 64', inspected)
        self.assertIn('new TreeMap<>(loaded.histories())', inspected)
        self.assertIn('loaded.occupiedAppIds.size() != loaded.histories().size()', inspected)
        self.assertIn('loaded.creationBlocked || loaded.unselectedFootprint', inspected)
        self.assertIn('pins.reservedAppIds()', inspected)
        self.assertIn('keySet().containsAll(lifetimeHolds)', inspected)
        self.assertIn('NativeIdentityPersistence.identifies(history, pin.record())', inspected)
        self.assertIn('Object issuer = pin.issuance()', inspected)
        self.assertIn('owned.lineage.equals(history.lineage)', inspected)
        self.assertIn('owned.selection.currentSignerSha256.equals(history.signerSha256)', inspected)
        self.assertIn('NativeIdentityStore.History first = firstHistories.get(history.id)', inspected)
        self.assertIn('first.lineage.equals(history.lineage)', inspected)
        self.assertIn('first.signerSha256.equals(history.signerSha256)', inspected)
        self.assertNotIn('history.equals(first)', inspected)
        self.assertIn('lineage = history.lineage;', inspected)
        self.assertIn('history.lineage.length() != 32', inspected)
        self.assertIn('history.source == NativeIdentityStore.Source.RESERVATION', inspected)
        self.assertIn('lifecycle = "NOT_OBSERVED";', inspected)
        self.assertIn('suspension = "NOT_OBSERVED";', inspected)
        self.assertIn('lifecycle = history.state.name();', inspected)
        self.assertIn('history.suspensions.isEmpty() ? "NONE" : "PRESENT"', inspected)
        self.assertNotIn('suspended = !history.suspensions.isEmpty()', inspected)
        self.assertNotIn('handle.suspended', inspected)
        self.assertIn('NativeIdentityStore.Status.UNSUPPORTED', inspected)
        self.assertIn('NativeIdentityStore.Status.CONFLICT', inspected)
        self.assertIn('NativeIdentityStore.Status.MISSING', inspected)
        self.assertIn('!loaded.enumerationComplete', inspected)
        self.assertIn('store != Inspection.Store.READY', inspected)
        self.assertIn('Status.AVAILABLE', inspected)
        self.assertIn('return Inspection.unavailable', inspected)
        self.assertIn('pm.mSettings.nativeAccountInspectionLPr(userId, userSerial)', inspected)
        self.assertIn('userId != UserHandle.USER_SYSTEM', inspected)
        self.assertIn('Inspection.unsupported(userId, userSerial)', inspected)
        self.assertIn('userSerial != authoritativeSerial(userId)', inspected)
        self.assertEqual(inspected.count('userSerial != authoritativeSerial(userId)'), 2)
        for effect in ('mInstallLock', '.load(', '.store(', '.initializeNew(',
                       '.select(', '.prepare(', '.commit(', '.find(', '.handle(',
                       '.releaseUid(', '.suspend(', '.beginRetirement(', 'snapshotForWrite(',
                       'new NativeIdentityStore(', 'new NativePrincipalPins('):
            self.assertNotIn(effect, inspected, effect)
        self.assertEqual(source('owner/tests/platform/native_recovery_fragments/inspection.java.inc').count(
            'NativePrincipalManager.project('), 1)

    def test_future_host_fixture_covers_immutable_read_and_serial_reuse(self):
        fixture = source('owner/tests/platform/NativeAccountInspectionTest.java')
        for case in ('empty.rows.add(null)', 'footprint(pm.mSettings.root)',
                     'manager.inspectUser(0, 7)', 'users.info.serialNumber = 8',
                     'other.userId == 10', 'absent.status == NativePrincipalManager.Inspection.Status.UNAVAILABLE',
                     'Header.newV2(', 'changedLineage.rows.isEmpty()', 'changedSigner.rows.isEmpty()',
                     'restoredChangedLineage.rows.isEmpty()',
                     'store.writeHeader(emptyHeader, creating)',
                     'reservationView.slots.get(10124).status == NativeIdentityStore.Status.MISSING',
                     '!Files.exists(reservationPm.mSettings.root.resolve("slots/10124"))',
                     'reservationRow.lifecycle.equals("NOT_OBSERVED")',
                     'reservationRow.suspension.equals("NOT_OBSERVED")',
                     'row.suspension.equals("NONE")',
                     'suspendedRow.suspension.equals("PRESENT")',
                     'retiringRow.lifecycle.equals("RETIRING")'):
            self.assertIn(case, fixture)

    def test_binder_exact_console_and_current_serial_no_coordinator_widening(self):
        binder = source('owner/platform/java/dev/andrix/server/OwnerNativeAccountQuery.java')
        aidl = source('owner/platform/aidl/dev/andrix/lifecycle/INativeAccountQuery.aidl')
        self.assertIn('NativeAccountSnapshot inspectCurrentUser();', aidl)
        self.assertNotIn('int userId', aidl)
        self.assertNotIn('long uid', aidl)
        self.assertIn('final int uid = Binder.getCallingUid();', binder)
        self.assertIn('final int userId = UserHandle.getUserId(uid);', binder)
        self.assertLess(binder.index('enforceConsole(uid, userId); // No identity clearing'),
                        binder.index('LocalServices.getService(UserManagerInternal.class)'))
        self.assertIn('appId < Process.FIRST_APPLICATION_UID', binder)
        self.assertIn('appId > Process.LAST_APPLICATION_UID', binder)
        self.assertIn('names.length != 1 || !CONSOLE.equals(names[0])', binder)
        self.assertIn('installed.sharedUserId != null || factory.sharedUserId != null', binder)
        self.assertIn('PackageManager.MATCH_FACTORY_ONLY', binder)
        self.assertIn('signersMatchExactly(factory.signingInfo)', binder)
        self.assertIn('image.sourceDir.startsWith(FACTORY_DIR)', binder)
        self.assertIn('installed.applicationInfo.uid != uid', binder)
        self.assertIn('manager.inspectUser(userId, serial)', binder)
        self.assertIn('now.serialNumber != serial', binder)
        self.assertEqual(binder.count('enforceConsole(uid, userId);'), 2)
        self.assertNotIn('clearCallingIdentity', binder)
        self.assertNotIn('7500', binder)
        self.assertNotIn('IPlatformLifecycle', binder)
        service = source('owner/platform/java/dev/andrix/server/OwnerLifecycleService.java')
        self.assertIn('publishBinderService(ACCOUNTS_SERVICE, new OwnerNativeAccountQuery(getContext()))', service)
        self.assertIn('private static void enforceCoordinator()', service)
        self.assertIn('Binder.getCallingUid() != OWNER_UID', service)

    def test_bounded_typed_response_and_read_only_policy(self):
        row = source('owner/platform/aidl/dev/andrix/lifecycle/NativeAccountRow.aidl')
        snap = source('owner/platform/aidl/dev/andrix/lifecycle/NativeAccountSnapshot.aidl')
        binder = source('owner/platform/java/dev/andrix/server/OwnerNativeAccountQuery.java')
        self.assertIn('NativeAccountRow[] rows', snap)
        self.assertIn('STORE_NEWER', snap)
        self.assertIn('UNSUPPORTED_USER', snap)
        self.assertIn('int lifecycle;', row)
        self.assertIn('String lineage;', row)
        self.assertIn('row.lineage = source.lineage;', binder)
        self.assertIn('int phase;', row)
        self.assertIn('int source;', row)
        self.assertIn('const int LIFECYCLE_NOT_OBSERVED = 0;', row)
        self.assertIn('const int SUSPENSION_NOT_OBSERVED = 0;', row)
        self.assertIn('const int SUSPENSION_NONE = 1;', row)
        self.assertIn('const int SUSPENSION_PRESENT = 2;', row)
        self.assertIn('int suspension;', row)
        self.assertNotIn('boolean suspended;', row)
        self.assertIn('case "NOT_OBSERVED" -> NativeAccountRow.LIFECYCLE_NOT_OBSERVED;', binder)
        self.assertIn('case "NOT_OBSERVED" -> NativeAccountRow.SUSPENSION_NOT_OBSERVED;', binder)
        self.assertIn('case "NONE" -> NativeAccountRow.SUSPENSION_NONE;', binder)
        self.assertIn('case "PRESENT" -> NativeAccountRow.SUSPENSION_PRESENT;', binder)
        fields = [line.split('//', 1)[0].strip() for line in row.splitlines()
                  if line.strip().endswith(';')]
        self.assertFalse(any(word in field for field in fields
                             for word in ('actor', 'reason', 'note')))
        self.assertIn('new NativeAccountRow[capture.rows.size()]', binder)
        for forbidden in ('home', '.keepWork(', '.attach(', '.create(', '.commit(', '.suspend('):
            self.assertNotIn(forbidden, binder)

    def test_view_explicit_refresh_stale_suppression_and_no_work_rpc(self):
        activity = source('owner/terminal/src/dev/andrix/terminal/ConsoleActivity.java')
        view = source('owner/terminal/src/dev/andrix/terminal/NativeAccountController.java')
        self.assertIn('add(accountActions, "Refresh", () -> accounts.refresh())', activity)
        self.assertIn('"dev.andrix.terminal.NativeAccounts"', activity)
        self.assertIn('accountMode = savedInstanceState == null ? accountsEntry', activity)
        self.assertIn('savedInstanceState.getBoolean(STATE_ACCOUNT_MODE, accountsEntry)', activity)
        self.assertIn('outState.putBoolean(STATE_ACCOUNT_MODE, accountMode)', activity)
        self.assertLess(activity.index('savedInstanceState.getBoolean(STATE_ACCOUNT_MODE, accountsEntry)'),
                        activity.index('controller.bind(this)'))
        self.assertIn('controller.foreground(this, !accountMode, focused)', activity)
        self.assertNotIn('outState.putParcelable', activity)
        self.assertIn('<activity-alias android:name=".NativeAccounts"',
                      source('owner/terminal/AndroidManifest.xml'))
        self.assertIn('accounts.open(); // Only the explicit Refresh makes a read request.', activity)
        self.assertIn('controller.foreground(this, false, false)', activity)
        self.assertIn('new ArrayBlockingQueue<>(1)', view)
        self.assertIn('private static final ThreadPoolExecutor QUERY_LANE', view)
        self.assertNotIn('private final ThreadPoolExecutor', view)
        self.assertNotIn('shutdownNow()', view)
        self.assertIn('WeakReference<NativeAccountController>', view)
        self.assertIn('QUERY_LANE.getQueue().clear()', view)
        self.assertIn('QUERY_LANE.remove(query)', view)
        self.assertIn('main.removeCallbacks(timeout)', view)
        self.assertIn('main.postDelayed(expiry, DISPLAY_TIMEOUT_MS)', view)
        self.assertIn('generation++; // An eventual late Binder reply is stale', view)
        self.assertIn('generation == request && user == UserHandle.myUserId()', view)
        worker = view[view.index('@Override public void run()'):view.index('private static boolean isCurrent')]
        self.assertLess(worker.index('service.inspectCurrentUser()'),
                        worker.index('NativeAccountController target = owner.get()'))
        self.assertNotIn('this.view', worker)
        self.assertIn('ServiceManager.checkService(SERVICE) != observed', view)
        finish = view[view.index('private void finish('):view.index('    static String render(')]
        self.assertLess(finish.index('current(query.request, query.user)'),
                        finish.index('ServiceManager.checkService(SERVICE) == binder'))
        self.assertLess(finish.index('ServiceManager.checkService(SERVICE) == binder'),
                        finish.index('render(accepted, query.user)'))
        self.assertIn('binder.isBinderAlive()', finish)
        self.assertIn('catch (RuntimeException unavailable)', finish)
        self.assertNotIn('waitForService', view)
        self.assertNotIn('getService(', view)
        self.assertIn('catch (RejectedExecutionException busy)', view)
        self.assertIn('void hide()', view)
        self.assertIn('generation++;', view)
        self.assertIn('store != NativeAccountSnapshot.STORE_READY', view)
        self.assertIn('snapshot.rows.length == 0', view)
        self.assertIn('No recorded native accounts in a complete', view)
        self.assertIn('state unavailable, not an empty account list', view)
        self.assertIn('No primary user accounts shown', view)
        self.assertIn('recorded retired; retirement alone deletes no data and releases no UID', view)
        self.assertNotIn('retired, data and UID kept', view)
        self.assertIn('!validLineage(row.lineage)', view)
        self.assertIn('append(" (lineage ").append(row.lineage)', view)
        self.assertIn('recorded suspension', view)
        self.assertIn('lifecycle not observed', view)
        self.assertIn('suspension not observed', view)
        self.assertIn('no recorded suspension', view)
        self.assertIn('row.source == NativeAccountRow.RESERVATION', view)
        self.assertIn('row.lifecycle != NativeAccountRow.LIFECYCLE_NOT_OBSERVED', view)
        self.assertIn('row.suspension != NativeAccountRow.SUSPENSION_NOT_OBSERVED', view)
        self.assertIn('Current data availability and in-memory admission closure are not reported.', view)
        for forbidden in ('TerminalController.get(', '.registerController(', '.attach(',
                          '.startKept(', '.keepWork(', '.renew(', 'owner.session'):
            self.assertNotIn(forbidden, view)

    def test_soong_and_selinux_are_separate_read_service_only(self):
        platform = source('owner/platform/Android.bp')
        client = source('owner/Android.bp')
        self.assertIn('srcs: ["aidl/dev/andrix/lifecycle/*.aidl"]', platform)
        self.assertIn('"andrix_platform_lifecycle-java", "AndrixTerminalLibraries"', client)
        self.assertIn('certificate: ":dev.andrix.usr.certificate"', client)
        self.assertIn('vendor/andrix/keys/dev.andrix.usr.x509.pem',
                      source('owner/sepolicy/keys.conf'))
        self.assertIn('andrix.owner.accounts     u:object_r:andrix_native_accounts_service:s0',
                      source('owner/platform/sepolicy/service_contexts'))
        accounts_policy = source('owner/platform/sepolicy/native_accounts.te')
        # The platform bridge must exclude this new private label from upstream
        # broad shell/system-app lookup sets before the extension asserts denial.
        declaration = ('type andrix_native_accounts_service, service_manager_type, '
                       'system_server_service;')
        self.assertNotIn(declaration, accounts_policy)
        self.assertIn(declaration, source('scripts/proof/owner_policy.py'))
        self.assertIn('add_service(system_server, andrix_native_accounts_service)', accounts_policy)
        self.assertIn('neverallow { appdomain -andrix_terminal }', accounts_policy)
        self.assertIn('allow andrix_terminal andrix_native_accounts_service:service_manager find',
                      source('owner/sepolicy/andrix_terminal.te'))
        self.assertIn('binder_call(andrix_terminal, system_server)',
                      source('owner/sepolicy/andrix_terminal.te'))
        self.assertIn('name=dev.andrix.terminal domain=andrix_terminal',
                      source('owner/sepolicy/seapp_contexts'))
        self.assertIn('<package name="dev.andrix.terminal">',
                      source('owner/sepolicy/mac_permissions.xml'))
        self.assertNotIn('andrix_native_accounts_service', source('owner/platform/sepolicy/owner_lifecycle.te'))
        product = source('products/andrix_gos_cf_arm64_only_phone.mk')
        self.assertIn('PRODUCT_SYSTEM_SERVER_JARS_EXTRA += system_ext:andrix-owner-lifecycle', product)
        self.assertIn('SYSTEM_OPTIMIZE_JAVA := true', product)
        flags = source('owner/platform/proguard.flags')
        self.assertNotIn('NativePrincipalManager', flags)
        self.assertNotIn('-keep class com.android.server.pm.', flags)


class QueuedCallbackServiceModelTests(unittest.TestCase):
    """Controlled queue and tokens only, NOT Android Binder or ServiceManager execution.

    The source checks above tie this model's acceptance boundary to finish on Main.
    The queue lets a registration replacement occur after the worker's check, before
    delivery, while the old binder token remains alive. Identity, not liveness alone,
    decides whether the queued success can be displayed.
    """

    @staticmethod
    def run_callback(replace):
        class BinderToken:
            alive = True

        old = BinderToken()
        registry = {'current': old}
        queued = []
        generation = 1
        user = 0
        # Worker completed an RPC and checked the old registration before posting.
        observed = registry['current']
        assert observed.alive and registry['current'] is observed
        queued.append(lambda: generation == 1 and user == 0 and observed.alive
                      and registry['current'] is observed)
        if replace:
            registry['current'] = BinderToken()  # Old binder is deliberately still alive.
        return queued.pop(0)(), old.alive

    def test_replaced_service_with_live_old_binder_rejects_queued_success(self):
        accepted, old_alive = self.run_callback(replace=True)
        self.assertTrue(old_alive)
        self.assertFalse(accepted)

    def test_unchanged_service_identity_accepts_queued_success(self):
        accepted, old_alive = self.run_callback(replace=False)
        self.assertTrue(old_alive)
        self.assertTrue(accepted)


if __name__ == '__main__':
    unittest.main()
