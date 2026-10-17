# SPDX-License-Identifier: Apache-2.0
"""Host protocol/parser/refusal checks. No Android runtime, image or guest qualification."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import zlib
import unittest
from unittest import mock

import fixtures as f
import ledger
import observations as obs
import produce
import protocol as p
import stored

HERE = Path(__file__).resolve().parent


class CryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='b2-crypto-tests-')
        cls.root = Path(cls.temporary.name)
        cls.public = []
        for index in range(3):
            key = cls.root / f'{index}.pem'
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt',
                            'ec_paramgen_curve:prime256v1', '-out', str(key)],
                           check=True, capture_output=True, timeout=10)
            result = subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'],
                                    check=True, capture_output=True, timeout=10)
            cls.public.append(result.stdout)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def reply(self, operation='observe', key_indices=(0, 1)):
        value = dict(version=1, operation=operation, nonce=f.NONCE, setup=f.CONTRACT['setup'],
                     contract_sha256=f.CONTRACT['contract_sha256'], phase='lifted',
                     guest_binding_sha256=f.GUEST, package=p.PACKAGE, uid=f.UID, user_serial=0,
                     apk_signer_sha256=p.SIGNER, pid=1234, elapsed_ms=15000, user_unlocked=True,
                     ce_sha256=f.CONTRACT['ce_sha256'], de_sha256=f.CONTRACT['de_sha256'],
                     intent_sha256=f.CONTRACT['intent_sha256'],
                     post_notifications_granted=operation == 'observe', job_id=p.JOB_ID,
                     job_namespace='null', job_service=p.SERVICE, job_persisted=True,
                     job_periodic=False, job_min_latency_ms=p.LATENCY - 1000,
                     job_max_delay_ms=0, job_setup=f.CONTRACT['setup'],
                     job_contract_sha256=f.CONTRACT['contract_sha256'], stage='complete', passed=True)
        value.update({k: operation == 'observe' for k in p.BEFORE})
        for i, key in enumerate(key_indices):
            value[f'key{i}_sha256'] = p.sha(self.public[key])
            value[f'key{i}_spki_b64'] = base64.b64encode(self.public[key]).decode()
        data = p.payload(value)
        for i, key in enumerate(key_indices):
            result = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(self.root / f'{key}.pem')],
                                    input=data, check=True, capture_output=True, timeout=10)
            value[f'key{i}_signature_b64'] = base64.b64encode(result.stdout).decode()
        return value

    @staticmethod
    def envelope(value):
        return ('INSTRUMENTATION_RESULT: b2_state_result=' + json.dumps(value, separators=(',', ':'))
                + '\nINSTRUMENTATION_CODE: -1\n')

    def assess(self, value, operation='observe', **kwargs):
        return p.assess_reply(self.envelope(value), '', 0, f.CONTRACT, operation, f.NONCE,
                              'lifted', f.GUEST,
                              None if operation == 'initialize' else tuple(p.sha(x) for x in self.public[:2]),
                              **kwargs)

    def test_both_fresh_signatures_under_original_keys(self):
        value = self.reply()
        self.assertEqual(self.assess(value), value)
        initialized = self.reply('initialize')
        self.assertEqual(self.assess(initialized, 'initialize'), initialized)
        self.assertNotEqual(value['key0_sha256'], value['key1_sha256'])

    def test_signed_binding_or_state_tamper_fails(self):
        original = self.reply()
        variants = {'nonce': 'a' * 32, 'phase': 'floor', 'guest_binding_sha256': 'a' * 64,
                    'setup': 'b' * 32, 'uid': 10124, 'user_serial': 1, 'package': p.PACKAGE + 'peer',
                    'apk_signer_sha256': 'c' * 64, 'ce_sha256': 'c' * 64, 'de_sha256': 'c' * 64,
                    'intent_sha256': 'c' * 64, 'contract_sha256': 'c' * 64, 'pid': 1235,
                    'elapsed_ms': 15001, 'job_min_latency_ms': 120, 'user_unlocked': False,
                    'key0_existed_before': False, 'job_setup': 'b' * 32, 'job_service': 'other',
                    'post_notifications_granted': False}
        for key, value in variants.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                changed = dict(original); changed[key] = value; self.assess(changed)

    def test_self_consistent_replacement_and_swapped_keys_fail(self):
        for indices in [(0, 2), (2, 1), (1, 0), (0, 0)]:
            with self.subTest(indices=indices), self.assertRaises(ValueError):
                self.assess(self.reply(key_indices=indices))

    def test_strict_types_and_field_inventory(self):
        original = self.reply()
        for name in p.INT_FIELDS:
            with self.subTest(name=name), self.assertRaises(ValueError):
                value = dict(original); value[name] = True; self.assess(value)
        for name in p.BOOL_FIELDS:
            with self.subTest(name=name), self.assertRaises(ValueError):
                value = dict(original); value[name] = 1; self.assess(value)
        for field in p.PAYLOAD_FIELDS:
            with self.subTest(field=field), self.assertRaises(ValueError):
                value = dict(original); del value[field]; self.assess(value)
        for key, item in [('unknown', 1), ('key0_spki_b64', 'AA=='),
                          ('key0_signature_b64', 'AA=='), ('job_periodic', True),
                          ('stage', 'partial'), ('passed', False)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                value = dict(original); value[key] = item; self.assess(value)

    def test_envelope_duplicates_and_transport_cannot_pass(self):
        text = self.envelope(self.reply())
        variants = [text + text, text.replace('"version":1', '"version":1,"version":1'),
                    text + 'extra\n', text[:-1], text.replace('"pid":1234', '"pid":NaN'),
                    text.replace('INSTRUMENTATION_CODE: -1', 'INSTRUMENTATION_CODE: 0'),
                    'INSTRUMENTATION_FAILED: no component\n', text.replace('\n', '\r\n')]
        keys = tuple(p.sha(x) for x in self.public[:2])
        for changed in variants:
            with self.subTest(text=changed[-80:]), self.assertRaises(ValueError):
                p.assess_reply(changed, '', 0, f.CONTRACT, 'observe', f.NONCE, 'lifted', f.GUEST, keys)
        for stderr, code in [('warning\n', 0), ('', 1), ('', True)]:
            with self.assertRaises(ValueError):
                p.assess_reply(text, stderr, code, f.CONTRACT, 'observe', f.NONCE, 'lifted', f.GUEST, keys)
        with self.assertRaises(ValueError):
            p.assess_reply(text, '', 0, f.CONTRACT, 'observe', f.NONCE, 'lifted', f.GUEST)


class ContractTests(unittest.TestCase):
    def test_contract_commits_exact_independent_canaries(self):
        c = f.CONTRACT
        self.assertTrue(c['ce_bytes'].startswith(b'andrix-b2-canary-v1\nstorage=CE\n'))
        self.assertNotEqual(c['ce_sha256'], c['de_sha256'])
        self.assertEqual(c['contract_sha256'], p.sha(c['contract_bytes']))
        self.assertIn(c['contract_sha256'].encode(), c['intent_bytes'])
        p.validate_contract(c)
        for name in ('uid', 'serial', 'setup', 'ce_token', 'ce_sha256', 'intent_bytes'):
            changed = copy.deepcopy(c); changed[name] = None
            with self.subTest(name=name), self.assertRaises(ValueError):
                p.validate_contract(changed)
        for args in [(True, 0, '1' * 32, '2' * 32, '3' * 32),
                     (9999, 0, '1' * 32, '2' * 32, '3' * 32),
                     (10123, -1, '1' * 32, '2' * 32, '3' * 32),
                     (10123, 0, 'x', '2' * 32, '3' * 32),
                     (10123, 0, '1' * 32, '2' * 32, '2' * 32)]:
            with self.assertRaises(ValueError):
                p.make_contract(*args)

    def test_argv_uses_no_privileged_instrumentation_options(self):
        argv = p.instrumentation_argv(f.CONTRACT, 'observe', f.NONCE, 'lifted', f.GUEST,
                                     ['a' * 64, 'b' * 64])
        self.assertIn('--no-test-api-access', argv)
        self.assertIn('--always-check-signature', argv)
        self.assertEqual(argv[-1], p.PACKAGE + '/.B2StateInstrumentation')
        self.assertNotIn('shell', argv)
        commands = p.setup_commands(f.CONTRACT, f.NONCE)
        self.assertEqual(len(commands), 4)
        self.assertEqual(commands[-1], p.notification_setup_argv(f.CONTRACT, f.NONCE))
        self.assertFalse(any('set_bubbles_channel' in command for command in commands))
        self.assertIn(b'notification_setup=channel-bubbles-copy-v1\n', f.CONTRACT['contract_bytes'])
        for bad in [('observe', None), ('initialize', ['a' * 64, 'b' * 64])]:
            with self.assertRaises(ValueError):
                p.instrumentation_argv(f.CONTRACT, bad[0], f.NONCE, 'lifted', f.GUEST, bad[1])

    def test_java_payload_order_and_contract_constants(self):
        java = (HERE / 'src/dev/andrix/proof/principalclosed/ObserveState.java').read_text()
        fields = re.findall(r'"([a-z0-9_]+)"', java.split('PAYLOAD_FIELDS = {')[1].split('};')[0])
        self.assertEqual(tuple(fields), p.PAYLOAD_FIELDS)
        contract = (HERE / 'src/dev/andrix/proof/principalclosed/Contract.java').read_text()
        self.assertIn(p.SIGNER, contract)
        self.assertIn(str(p.LATENCY) + 'L', contract)
        self.assertIn(str(p.TRIAL_LIMIT) + 'L', contract)

    def test_observe_call_graph_contains_no_selected_state_setter(self):
        java = (HERE / 'src/dev/andrix/proof/principalclosed/ObserveState.java').read_text()
        forbidden = r'\.(?:generateKeyPair|schedule|enqueue|cancel|createNotificationChannel|' \
                    r'deleteEntry|getFilesDir|getNotificationChannel|newFile|make)\s*\('
        self.assertIsNone(re.search(forbidden, java))
        self.assertNotIn('InitializeState', java)
        self.assertIsNotNone(re.search(forbidden, java + '\nx.schedule(job);'))
        files = (HERE / 'src/dev/andrix/proof/principalclosed/StateFiles.java').read_text()
        read = files.split('static byte[] readExact(')[1].split('    void preflight(')[0]
        self.assertIn('O_NOFOLLOW', read); self.assertIn('S_ISREG', read)
        self.assertNotIn('O_CREAT', read); self.assertNotIn('Os.write', read)
        init = (HERE / 'src/dev/andrix/proof/principalclosed/InitializeState.java').read_text()
        self.assertLess(init.index('files.preflight()'), init.index('StateFiles.make('))
        self.assertLess(init.index('StateFiles.newFile(files.intent'), init.index('generateKeyPair()'))
        self.assertEqual(init.count('scheduler.schedule('), 1)
        self.assertEqual(init.count('keys.getKey(alias, null)'), 2)
        self.assertLess(init.index('keys.getKey(alias, null)'), init.index('StateFiles.make('))
        self.assertNotIn('catch (', init)
        self.assertNotIn('deleteEntry', init)
        entry = (HERE / 'src/dev/andrix/proof/principalclosed/B2StateInstrumentation.java').read_text()
        self.assertIn('if (request.operation.equals("initialize"))', entry)
        self.assertEqual(entry.count('InitializeState.run('), 1)
        self.assertNotIn('UiAutomation', re.sub(r'/\*.*?\*/|//[^\n]*', '', entry, flags=re.S))


class ServiceTests(unittest.TestCase):
    def permission(self, text):
        return obs.permissionmgr(f.capture(p.dumpsys_argv('permissionmgr', '--app-id', str(f.UID)), text), f.UID)

    def notification(self, text):
        return obs.notification(f.capture(p.dumpsys_argv('notification', '--noredact', '--package', p.PACKAGE),
                                          text), f.UID)

    def job(self, text, admitted=True):
        return obs.jobscheduler(f.capture(p.dumpsys_argv('jobscheduler'), text), f.CONTRACT, admitted)

    def test_permission_and_package_operation_exact_scope(self):
        value = self.permission(f.permission_text())
        obs.require_permission_state(value, 15)
        self.assertEqual(value['package_ops'], {'android:vibrate': 'ignore'})
        c = f.capture(p.dumpsys_argv('permissionmgr', '--package', p.PACKAGE), f.permission_text())
        self.assertEqual(obs.permissionmgr(c, f.UID, 'package'), value)
        obs.require_permission_state(self.permission(f.permission_text(False)), 15, False)
        for old, new in [('flags=[RUNTIME_GRANTED|USER_SET]', 'flags=[RUNTIME_GRANTED]'),
                         ('granted=true, flags=[RUNTIME_GRANTED', 'granted=false, flags=[RUNTIME_GRANTED'),
                         ('version=15', 'version=16'), ('mode=ignore', 'mode=allow')]:
            with self.assertRaises(ValueError):
                obs.require_permission_state(self.permission(f.permission_text().replace(old, new)), 15)
        variants = [f.permission_text() + '        android:vibrate: mode=ignore\n',
                    f.permission_text().replace('  User: 0', '  User: 1'),
                    f.permission_text().replace('App ID: 10123', 'App ID: 10124'),
                    f.permission_text().replace('    App ops:\n', '    App ops:\n'
                                                '      android:vibrate: mode=ignore\n'),
                    f.permission_text().replace('    Package: ', '      Package: '),
                    f.permission_text() + f.permission_text()]
        for text in variants:
            with self.subTest(text=text[-80:]), self.assertRaises(ValueError):
                obs.require_permission_state(self.permission(text), 15)

    def test_appops_no_uid_override_or_history(self):
        package_argv = ['cmd', 'appops', 'get', '--user', '0', p.PACKAGE, 'VIBRATE']
        uid_argv = ['cmd', 'appops', 'get', str(f.UID), 'VIBRATE']
        self.assertEqual(obs.appops(f.capture(package_argv, 'VIBRATE: ignore\n'), f.UID)['mode'], 'ignore')
        obs.appops(f.capture(uid_argv, 'No operations.\nDefault mode: allow\n'), f.UID, False)
        for text in ['Uid mode: VIBRATE: ignore\n', 'VIBRATE: ignore\nVIBRATE: ignore\n',
                     'VIBRATE: ignore; time=+1s0ms ago\n', 'No operations.\nDefault mode: allow\n']:
            with self.assertRaises(ValueError):
                obs.appops(f.capture(package_argv, text), f.UID)

    def test_complete_channel_and_hexadecimal_lock(self):
        value = self.notification(f.notification_text())
        self.assertEqual(value['channel']['mUserLockedFields'], 256)
        self.assertEqual(value['channel']['mAllowBubbles'], 1)
        for old, new in [('mUserLockedFields=100', 'mUserLockedFields=256'),
                         ('mAllowBubbles=1', 'mAllowBubbles=-1'), ('mDeleted=false', 'mDeleted=true'),
                         (f'({f.UID})', '(10124)'), ('mImportance=2', 'mImportance=2, mImportance=2'),
                         ('mSound=null', 'mSound=content://sound'),
                         ('mParent=null', 'mParent=conversation'), ('emoji=null', 'unknown=null'),
                         ('PackagePreferences:', 'PackagePreferences:\nPackagePreferences:')]:
            with self.subTest(old=old), self.assertRaises(ValueError):
                self.notification(f.notification_text().replace(old, new))
        for text in [f.notification_text().replace('Restored without uid:', ''),
                     f.notification_text().replace('        ' + f.channel_text(),
                                                    '        ' + f.channel_text() + '\n        ' + f.channel_text()),
                     f.notification_text().split('Restored without uid:')[0]]:
            with self.assertRaises(ValueError):
                self.notification(text)
        with self.assertRaises(ValueError):
            obs.notification(f.capture(p.dumpsys_argv('notification', '--noredact', '--package', p.PACKAGE),
                                        f.notification_text()), f.UID, stage='absent')

    def test_old_aliasing_result_and_reset_never_qualify(self):
        for preference in ('old-shell', 'reset'):
            text = f.notification_text(preference=preference)
            xml = f.notification_xml(preference=preference)
            with self.subTest(preference=preference, oracle='dump'), self.assertRaises(ValueError):
                self.notification(text)
            with self.subTest(preference=preference, oracle='stored'), self.assertRaises(ValueError):
                stored.notification_policy(xml, f.UID)
        # The old command's 1/0 result is not even the pristine -1/0 setup precondition.
        cap = f.capture(p.dumpsys_argv('notification', '--noredact', '--package', p.PACKAGE),
                        f.notification_text(preference='old-shell'))
        with self.assertRaises(ValueError):
            obs.notification(cap, f.UID, stage='created')
        with self.assertRaises(ValueError):
            stored.notification_policy(f.notification_xml(preference='old-shell'), f.UID,
                                       stage='created')

    def test_shell_setup_acknowledgement_is_not_preference_evidence(self):
        digest = 'c' * 64
        jar = f.capture(['sha256sum', p.SETUP_JAR], digest + '  ' + p.SETUP_JAR + '\n')
        self.assertEqual(obs.notification_setup_file(jar, digest), {p.SETUP_JAR: digest})
        with self.assertRaises(ValueError):
            obs.notification_setup_file(jar, 'd' * 64)
        argv = p.notification_setup_argv(f.CONTRACT, f.NONCE)
        cap = f.capture(argv, f.notification_setup_ack())
        self.assertIs(obs.notification_setup(cap, f.CONTRACT, f.NONCE)['state_proven'], False)
        value = p.strict_json(cap['stdout'].split(': ', 1)[1])
        for key, changed in [('nonce', 'a' * 32), ('uid', f.UID + 1), ('process_uid', 0),
                             ('contract_sha256', 'b' * 64), ('setter_calls', 2), ('version', True),
                             ('state_proven', True), ('unknown', 1)]:
            altered = dict(value); altered[key] = changed
            text = 'ANDRIX_B2_NOTIFICATION_SETUP: ' + json.dumps(altered) + '\n'
            with self.subTest(key=key), self.assertRaises(ValueError):
                obs.notification_setup(dict(cap, stdout=text), f.CONTRACT, f.NONCE)
        for text in (cap['stdout'] * 2, cap['stdout'].replace('"version": 1',
                     '"version": 1, "version": 1'), cap['stdout'].replace('\n', '\r\n')):
            with self.assertRaises(ValueError):
                obs.notification_setup(dict(cap, stdout=text), f.CONTRACT, f.NONCE)
        old_argv = ['cmd', 'notification', 'set_bubbles_channel', p.PACKAGE, p.CHANNEL, 'true', '0']
        with self.assertRaises(ValueError):
            obs.notification_setup(dict(cap, argv=old_argv), f.CONTRACT, f.NONCE)
        # Even a valid acknowledgement cannot rescue missing user lock in either owner oracle.
        self.test_old_aliasing_result_and_reset_never_qualify()

    def test_job_retained_deferred_and_admitted_with_parcelled_extras(self):
        for admitted in (True, False):
            value = self.job(f.job_text(admitted), admitted)
            self.assertIs(value['component'], admitted)
            self.assertFalse(value['extras']['marker_observable'])
            self.assertEqual(value['namespace'], None)
        self.assertTrue(self.job(f.job_text(parcelled=False))['extras']['marker_observable'])
        # A waiting job is also legitimately mentioned by TimeController and quota controllers.
        self.job(f.job_text().replace('  tracked', '  ##u0a123/21802 from u0a123: Delay=+1d0h0m0s0ms'))

    def test_job_malformed_or_replaced_state_refused(self):
        text = f.job_text()
        variants = [('Registered 1 jobs:', 'Registered 2 jobs:'),
                    ('JOB #u0a123/', 'JOB alternate:u0a123/'), ('/21802:', '/21803:'),
                    ('    Source: uid=u0a123', '    Source: uid=u0a124'),
                    ('      PERSISTED\n', ''), ('      PERSISTED\n', '      PERIODIC\n'),
                    ('!active=true', '!active=false'), ('!pending=true', '!pending=false'),
                    ('comp=true', 'comp=false'), ('earliest=+29d23h59m59s0ms', 'earliest=-1ms'),
                    ('      Priority: 300 [DEFAULT]', '      Priority: 500 [MAX]'),
                    ('      Extras: mParcelledData.dataSize=248', '      Extras: ...'),
                    ('    Restricted due to:', '    Num failures: 1\n    Restricted due to:'),
                    ('    Tracking: TIME QUOTA', '    Tracking: TIME QUOTA\n    Last successful run: today'),
                    ('    JobInfo:', '    JobInfo:\n      Transient extras: something'),
                    ('[0x80000000]', '[0x80000001]')]
        for old, new in variants:
            if old == new:
                continue
            with self.subTest(old=old), self.assertRaises(ValueError):
                self.job(text.replace(old, new))
        for bad in [text.split('Pending queue:')[0], text + 'JOB #u0a123/21802: completed\n',
                    text.replace('  JOB #u0a123/21802: 123abc ' + p.PACKAGE + '/.B2StateJobService\n',
                                 ('  JOB #u0a123/21802: 123abc ' + p.PACKAGE + '/.B2StateJobService\n') * 2)]:
            with self.assertRaises(ValueError):
                self.job(bad)

    def test_shell_job_lookup_does_not_prove_retention(self):
        argv = ['cmd', 'jobscheduler', 'get-job-state', '-u', '0', p.PACKAGE, str(p.JOB_ID)]
        self.assertFalse(obs.job_state(f.capture(argv, 'waiting\n'), f.UID, True)['retention_proven'])
        c = f.capture(argv, f'unknown({p.PACKAGE})\n', 24, f'Package not found: {p.PACKAGE} / user 0\n')
        self.assertEqual(obs.job_state(c, f.UID, False, 24)['service_error'], -1000)
        with self.assertRaises(ValueError):
            obs.job_state(c, f.UID, False)
        with self.assertRaises(ValueError):
            obs.job_state(f.capture(argv, 'unknown(u0a123/jid21802)\n', 23,
                                    f'Could not find job 21802 in package {p.PACKAGE} / user 0\n'),
                          f.UID, False, 23)

    def test_created_channel_precondition_is_not_final_preference(self):
        text = f.notification_text().replace('mAllowBubbles=1', 'mAllowBubbles=-1').replace(
            'mUserLockedFields=100', 'mUserLockedFields=0')
        cap = f.capture(p.dumpsys_argv('notification', '--noredact', '--package', p.PACKAGE), text)
        self.assertEqual(obs.notification(cap, f.UID, stage='created')['channel']['mAllowBubbles'], -1)
        with self.assertRaises(ValueError):
            obs.notification(cap, f.UID)
        xml = f.notification_xml().replace(b' locked="256"', b'').replace(b' allow_bubbles="1"', b'')
        stored.notification_policy(xml, f.UID, stage='created')
        with self.assertRaises(ValueError):
            stored.notification_policy(xml, f.UID)

    def test_pm_admission_and_retained_unscanned_setting(self):
        code = '/data/app/fixture/base.apk'
        all_cap = f.capture(['cmd', 'package', 'list', 'packages', '-U', '-u', p.PACKAGE],
                            f'package:{p.PACKAGE} uid:{f.UID}\n')
        for admitted in (True, False):
            package = 'Package{abc ' + p.PACKAGE + '}' if admitted else 'null'
            detail = (f'Packages:\n  Package [{p.PACKAGE}] (abc):\n    appId={f.UID}\n'
                      f'    pkg={package}\n    codePath=/data/app/fixture\n'
                      '    versionCode=1 minSdk=37 targetSdk=37\n'
                      '    User 0: ceDataInode=123 installed=true stopped=false\n')
            admitted_cap = f.capture(['cmd', 'package', 'list', 'packages', '-U', p.PACKAGE],
                                     all_cap['stdout'] if admitted else '')
            path = f.capture(['pm', 'path', p.PACKAGE], 'package:' + code + '\n' if admitted else '',
                             0 if admitted else 1)
            details = f.capture(p.dumpsys_argv('package', p.PACKAGE), detail)
            self.assertEqual(obs.pm_surface(all_cap, admitted_cap, path, details, f.UID, code,
                                             admitted)['admitted'], admitted)
            for old, new in [('appId=10123', 'appId=10124'), ('installed=true', 'installed=false'),
                             ('pkg=' + package, 'pkg=' + package + '\n    pkg=' + package)]:
                with self.assertRaises(ValueError):
                    obs.pm_surface(all_cap, admitted_cap, path,
                                   dict(details, stdout=detail.replace(old, new)), f.UID, code, admitted)

    def test_existing_native_observer_requires_the_image_schema(self):
        b2 = ('andrix-native-identities-v3\nlive_settings=true\nauthority=not-reported\n'
              'counter_known=true\ncached_header=VALID\ncached_enumeration_complete=true\n'
              'creation_ready=true\nallocator_search_start=10000\nunidentified_code=false\n'
              'deferred_count=1\nslot_count=1\nhold=10123\tVALID\ttrue\tpackage\t'
              + base64.b64encode(p.PACKAGE.encode()).decode() + '\n'
              'slot=10123\t2\tELIGIBLE\ttrue\ndeferred='
              + base64.b64encode(p.PACKAGE.encode()).decode() + '\n')
        cap = f.capture(p.dumpsys_argv('package', '--andrix-native-identities'), b2)
        value = obs.native_dump(cap, 3)
        self.assertEqual(value['deferred_names'], [p.PACKAGE])
        b1 = b2.replace('andrix-native-identities-v3', 'andrix-native-identities-v2').replace(
            'slot_count=1\n', '').replace('slot=10123\t2\tELIGIBLE\ttrue\n', '')
        floor = obs.native_dump(dict(cap, stdout=b1), 2)
        self.assertEqual(floor['schema_version'], 2)
        self.assertNotIn('slots', floor)
        with self.assertRaises(ValueError):
            obs.native_dump(cap, 2)
        with self.assertRaises(ValueError):
            obs.native_dump(dict(cap, stdout=b2 + 'slot=10123\t2\tELIGIBLE\ttrue\n'), 3)
        packages = f.capture(p.dumpsys_argv('package', 'packages'),
                             f'Packages:\n  Package [{p.PACKAGE}] (abc):\n    appId={f.UID}\n')
        shared = f.capture(p.dumpsys_argv('package', 'shared-users'),
                           'Shared users:\n  SharedUser [android.uid.system] (ff):\n    appId=1000\n')
        self.assertEqual(obs.package_maps(packages, shared)['shared'], {'android.uid.system': 1000})

    def test_every_dump_kind_cut_at_the_dumpsys_timeout_is_unavailable(self):
        # Each subject dump is read only in its bounded form, and a dump that carries dumpsys's
        # timeout line is unavailable with its own reason, never parsed as complete.
        self.assertEqual(p.dumpsys_argv('jobscheduler'), ['dumpsys', '-t', str(p.DUMPSYS_TIMEOUT_SECONDS), 'jobscheduler'])
        self.assertTrue(0 < p.DUMPSYS_TIMEOUT_SECONDS < 90)
        native = ('andrix-native-identities-v3\nlive_settings=true\nauthority=not-reported\n'
                  'counter_known=false\ncached_header=MISSING\ncached_enumeration_complete=false\n'
                  'creation_ready=false\nallocator_search_start=10000\nunidentified_code=false\n'
                  'deferred_count=0\nslot_count=0\n')
        detail = (f'Packages:\n  Package [{p.PACKAGE}] (abc):\n    appId={f.UID}\n'
                  f'    pkg=Package{{abc {p.PACKAGE}}}\n    codePath=/data/app/fixture\n'
                  '    versionCode=1 minSdk=37 targetSdk=37\n'
                  '    User 0: ceDataInode=123 installed=true stopped=false\n')
        packages = f'Packages:\n  Package [{p.PACKAGE}] (abc):\n    appId={f.UID}\n'
        shared = 'Shared users:\n  SharedUser [android.uid.system] (ff):\n    appId=1000\n'
        code = '/data/app/fixture/base.apk'
        all_cap = f.capture(['cmd', 'package', 'list', 'packages', '-U', '-u', p.PACKAGE], f'package:{p.PACKAGE} uid:{f.UID}\n')
        admitted = f.capture(['cmd', 'package', 'list', 'packages', '-U', p.PACKAGE], all_cap['stdout'])
        path = f.capture(['pm', 'path', p.PACKAGE], 'package:' + code + '\n')
        maps = f.capture(p.dumpsys_argv('package', 'shared-users'), shared)
        readers = [
            ('permissionmgr --app-id', f.permission_text(), p.dumpsys_argv('permissionmgr', '--app-id', str(f.UID)),
             lambda c: obs.permissionmgr(c, f.UID)),
            ('permissionmgr --package', f.permission_text(), p.dumpsys_argv('permissionmgr', '--package', p.PACKAGE),
             lambda c: obs.permissionmgr(c, f.UID, 'package')),
            ('notification --noredact --package', f.notification_text(), p.dumpsys_argv('notification', '--noredact', '--package', p.PACKAGE),
             lambda c: obs.notification(c, f.UID)),
            ('jobscheduler', f.job_text(), p.dumpsys_argv('jobscheduler'), lambda c: obs.jobscheduler(c, f.CONTRACT, True)),
            ('package ' + p.PACKAGE, detail, p.dumpsys_argv('package', p.PACKAGE),
             lambda c: obs.pm_surface(all_cap, admitted, path, c, f.UID, code, True)),
            ('package packages', packages, p.dumpsys_argv('package', 'packages'), lambda c: obs.package_maps(c, maps)),
            ('package --andrix-native-identities', native, p.dumpsys_argv('package', '--andrix-native-identities'),
             lambda c: obs.native_dump(c, 3))]
        for name, text, argv, read in readers:
            with self.subTest(dump=name):
                read(f.capture(argv, text))
                marker = "\n*** SERVICE '%s' DUMP TIMEOUT (30000ms) EXPIRED ***\n\n" % argv[3]
                with self.assertRaises(p.DumpUnavailable) as caught:
                    read(f.capture(argv, text + marker + marker))
                self.assertEqual(str(caught.exception), "%s dump unavailable: dumpsys timed out after 30000 ms in service "
                                                        "'%s', the dump is cut" % (' '.join(argv[3:]), argv[3]))
                # The unbounded command, dumpsys's default 10 s, is not the read the observers admit.
                with self.assertRaises(ValueError):
                    read(f.capture(['dumpsys'] + argv[3:], text))
                # The whole capture passes the completeness gate: a whole dump with dumpsys's service
                # error on stderr, a nonzero exit or an unfinished transport is unavailable, each with
                # the gate's reason, never read.
                for change, reason in (({'stderr': "Error with service '%s' while dumping: FAILED_TRANSACTION\n" % argv[3]},
                                        "dumpsys reported service '%s' failing while dumping: FAILED_TRANSACTION" % argv[3]),
                                       ({'exit_code': 1}, 'dumpsys exited 1'),
                                       ({'complete': False}, 'its transport did not complete with a result (retired, timed out or stopped)')):
                    with self.assertRaises(p.DumpUnavailable) as caught:
                        read(dict(f.capture(argv, text), **change))
                    self.assertEqual(str(caught.exception), '%s dump unavailable: %s' % (' '.join(argv[3:]), reason))
        with self.assertRaises(p.DumpUnavailable):
            obs.package_maps(f.capture(p.dumpsys_argv('package', 'packages'), packages),
                             dict(maps, stdout=shared + "\n*** SERVICE 'package' DUMP TIMEOUT (30000ms) EXPIRED ***\n\n"))

    def test_capture_errors_types_and_complete_mark(self):
        argv = ['cmd', 'appops', 'get', '--user', '0', p.PACKAGE, 'VIBRATE']
        for key, value in [('complete', False), ('stderr', 'warning'), ('exit_code', True),
                           ('argv', ['cmd', 'appops', 'set']), ('unknown', 1),
                           ('stdout', 'VIBRATE: ignore\r\n')]:
            c = f.capture(argv, 'VIBRATE: ignore\n'); c[key] = value
            with self.assertRaises(ValueError):
                obs.appops(c, f.UID)

    def test_dummy_file_hash_metadata_labels_and_time_admission(self):
        path = '/data/user/0/' + p.PACKAGE + '/files/b2-state/canary.bin'
        expected = {path: f.CONTRACT['ce_sha256']}
        cap = f.capture(['sha256sum', path], f'{expected[path]}  {path}\n')
        self.assertEqual(obs.file_hashes(cap, expected), expected)
        cap['stdout'] *= 2
        with self.assertRaises(ValueError):
            obs.file_hashes(cap, expected)
        argv = ['stat', '-c', '%n|%f|%u|%g|%h|%s', path]
        cap = f.capture(argv, f'{path}|8180|10123|10123|1|200\n')
        self.assertEqual(obs.file_stats(cap, [path], f.UID)[path]['uid'], f.UID)
        for old, new in [('|8180|', '|a180|'), ('|1|200', '|2|200'), ('|10123|10123|', '|10124|10124|')]:
            with self.assertRaises(ValueError):
                bad = dict(cap, stdout=cap['stdout'].replace(old, new)); obs.file_stats(bad, [path], f.UID)
        cap = f.capture(['ls', '-Zd', path], 'u:object_r:app_data_file:s0:c123,c456 ' + path + '\n')
        self.assertIn(path, obs.file_labels(cap, [path]))
        obs.trial_clock(100000, 100001, 100000 + p.LATENCY, 100000 + p.LATENCY)
        for now, due in [(99999, 100000 + p.LATENCY), (100000 + p.TRIAL_LIMIT + 1, 100000 + p.LATENCY),
                         (100001, 1)]:
            with self.assertRaises(ValueError):
                obs.trial_clock(100000, now, 100000 + p.LATENCY, due)


class StoredTests(unittest.TestCase):
    def test_access_permission_and_scoped_mode(self):
        self.assertEqual(stored.access(f.access_xml(), f.UID, 15)['permission_flags'], 48)
        stored.access(f.access_xml(False), f.UID, 15, False)
        for old, new in [(b'flags="48"', b'flags="16"'), (b'mode="1"', b'mode="0"'),
                         (b'id="10123"', b'id="10124"'), (b'version="15"', b'version="16"'),
                         (b'<app-id-app-ops/>', b'<app-id-app-ops><app-id id="10123">'
                          b'<app-op name="android:vibrate" mode="1"/></app-id></app-id-app-ops>')]:
            with self.subTest(old=old), self.assertRaises(ValueError):
                stored.access(f.access_xml().replace(old, new), f.UID, 15)
        bad = f.access_xml().replace(b'</app-id>', b'<permission name="android.permission.POST_NOTIFICATIONS"'
                                     b' flags="48"/></app-id>')
        with self.assertRaises(ValueError):
            stored.access(bad, f.UID, 15)

    def test_stored_channel_decimal_mask_and_defaults(self):
        self.assertEqual(stored.notification_policy(f.notification_xml(), f.UID)['channel']['locked'], '256')
        stored.notification_policy(f.notification_xml(False), f.UID, stage='absent')
        for old, new in [(b'locked="256"', b'locked="100"'), (b'allow_bubbles="1"', b'allow_bubbles="-1"'),
                         (b'uid="10123"', b'uid="10124"'), (b'orig_imp="2"', b'deleted="true"'),
                         (b'orig_imp="2"', b'unknown="2"')]:
            with self.assertRaises(ValueError):
                stored.notification_policy(f.notification_xml().replace(old, new), f.UID)
        data = f.notification_xml()
        channel = re.search(rb'<channel [^>]+/>', data)[0]
        with self.assertRaises(ValueError):
            stored.notification_policy(data.replace(b'</package>', channel + b'</package>'), f.UID)

    def test_job_typed_markers_time_and_duplicate_files(self):
        files = {'jobs_10123.xml': f.job_xml()}
        self.assertEqual(stored.jobs(files, f.CONTRACT, f.DUE)['delay_utc_ms'], f.DUE)
        self.assertEqual(stored.jobs({}, f.CONTRACT, initialized=False), {'uid': f.UID, 'jobs': []})
        with self.assertRaises(ValueError):
            stored.jobs(files, f.CONTRACT, initialized=False)
        for old, new in [(b'<one-off ', b'<periodic '), (b'jobid="21802"', b'jobid="21803"'),
                         (b'flags="0"', b'flags="1"'), (b'sourceUserId="0"', b'sourceUserId="1"'),
                         (b'<constraints/>', b'<constraints charging="true"/>'),
                         (b'cumulativeExecutionTime="0"', b'cumulativeExecutionTime="1"'),
                         (b'<job jobid', b'<job namespace="other" jobid'),
                         (b'<string ', b'<int '), (b'1800000000000', b'1800000100000')]:
            with self.subTest(old=old), self.assertRaises(ValueError):
                stored.jobs({'jobs.xml': f.job_xml().replace(old, new)}, f.CONTRACT, f.DUE)
        with self.assertRaises(ValueError):
            stored.jobs({'jobs.xml': f.job_xml(), **files}, f.CONTRACT, f.DUE)
        for name in ('jobs.xml.bak', 'jobs_10124.xml', 'jobs_010123.xml'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                stored.jobs({name: f.job_xml()}, f.CONTRACT, f.DUE)

    def test_malformed_decoded_inputs_never_yield_facts(self):
        for data in [b'ABX\x00', b'<access>', b'<access/><access/>', b'<access extra="a" extra="b"/>',
                     b'<!DOCTYPE access [<!ENTITY x "y">]><access/>', b'<access><!--x--></access>',
                     b'<access><?bad value?></access>', b'<access><unknown/></access>']:
            with self.subTest(data=data), self.assertRaises(ValueError):
                stored.access(data, f.UID, 15)


class LedgerTests(unittest.TestCase):
    def test_issued_setup_unknown_blocks_replay_under_any_token(self):
        with tempfile.TemporaryDirectory(prefix='b2-ledger-test-') as temp:
            root = Path(temp).resolve()
            prov = {k: 'a' * 64 for k in ('apk', 'pms', 'user', 'permissionmgr', 'appops',
                                        'notification', 'jobscheduler', 'files', 'native', 'image', 'setup_jar')}
            directory = ledger.prepare(root, 'b' * 64, f.CONTRACT, prov, 'setup', f.GUEST)
            argv = ledger.claim(directory, 0, 'c' * 64)
            self.assertEqual(argv[-1], p.PACKAGE + '/.B2StateInstrumentation')
            with self.assertRaises(FileExistsError):
                ledger.claim(directory, 0, 'c' * 64)
            ledger.complete(directory, 0, 'unknown', 'd' * 64)
            with self.assertRaises(ValueError):
                ledger.claim(directory, 1, 'c' * 64)
            for contract in [f.CONTRACT, p.make_contract(10124, 0, '6' * 32, '7' * 32, '8' * 32)]:
                with self.assertRaises(FileExistsError):
                    ledger.prepare(root, 'b' * 64, contract, prov, 'setup', f.GUEST)

    def test_only_ordered_confirmed_effects_can_progress(self):
        with tempfile.TemporaryDirectory(prefix='b2-ledger-test-') as temp:
            prov = {k: 'a' * 64 for k in ('apk', 'pms', 'user', 'permissionmgr', 'appops',
                                        'notification', 'jobscheduler', 'files', 'native', 'image', 'setup_jar')}
            directory = ledger.prepare(Path(temp).resolve(), 'b' * 64, f.CONTRACT, prov, 'setup', f.GUEST)
            with self.assertRaises(OSError):
                ledger.complete(directory, 0, 'observed-success', 'd' * 64)
            for step in range(5):
                ledger.claim(directory, step, 'c' * 64)
                ledger.complete(directory, step, 'observed-success', 'd' * 64)
            with self.assertRaises(ValueError):
                ledger.claim(directory, 4, 'c' * 64)


    def test_issue_changed_after_claim_before_complete_is_refused(self):
        for change in ('argv', 'precondition', 'bytes'):
            with tempfile.TemporaryDirectory(prefix='b2-claim-test-') as temp:
                prov = {k: 'a' * 64 for k in ('apk', 'pms', 'user', 'permissionmgr', 'appops',
                                            'notification', 'jobscheduler', 'files', 'native', 'image', 'setup_jar')}
                directory = ledger.prepare(Path(temp).resolve(), 'b' * 64, f.CONTRACT, prov,
                                           'setup', f.GUEST)
                ledger.claim(directory, 0, 'c' * 64)
                issue_path = directory / '0.issued.json'
                data = issue_path.read_bytes()
                if change == 'bytes':
                    issue_path.write_bytes(data + b' ')
                else:
                    issue = json.loads(data)
                    if change == 'argv':
                        issue['argv'] = ['different-command']
                    else:
                        issue['precondition_sha256'] = 'e' * 64
                    issue_path.write_text(json.dumps(issue) + '\n')
                with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'issue bytes'):
                    ledger.complete(directory, 0, 'observed-success', 'd' * 64)
                self.assertFalse((directory / '0.outcome.json').exists())
                with self.assertRaises(FileExistsError):
                    ledger.claim(directory, 0, 'c' * 64)
                with self.assertRaises(OSError):
                    ledger.claim(directory, 1, 'c' * 64)

    def test_owned_reports_complete_incomplete_and_partial_setups(self):
        prov = {k: 'a' * 64 for k in ('apk', 'pms', 'user', 'permissionmgr', 'appops',
                                    'notification', 'jobscheduler', 'files', 'native', 'image',
                                    'setup_jar')}
        with tempfile.TemporaryDirectory(prefix='b2-owned-test-') as temp:
            root = Path(temp).resolve()
            directory = ledger.prepare(root, 'b' * 64, f.CONTRACT, prov, 'setup', f.GUEST)
            self.assertEqual(ledger.owned(directory)['steps'], [])
            for step in range(5):
                ledger.claim(directory, step, 'c' * 64)
                ledger.complete(directory, step, 'observed-success', 'd' * 64)
            value = ledger.owned(directory)
            self.assertTrue(value['complete'])
            self.assertEqual(value['contract'], f.CONTRACT)
            self.assertEqual([s['state'] for s in value['steps']], ['observed-success'] * 5)
            self.assertEqual(value['steps'][0]['argv'], value['request']['initialize_argv'])
            other = root / ('e' * 64 + '.' + p.PACKAGE)
            directory.rename(other)
            with self.assertRaisesRegex(ValueError, 'directory owner'):
                ledger.owned(other)
        with tempfile.TemporaryDirectory(prefix='b2-owned-test-') as temp:
            directory = ledger.prepare(Path(temp).resolve(), 'b' * 64, f.CONTRACT, prov, 'setup',
                                       f.GUEST)
            ledger.claim(directory, 0, 'c' * 64)
            ledger.complete(directory, 0, 'observed-success', 'd' * 64)
            ledger.claim(directory, 1, 'c' * 64)
            self.assertEqual(ledger.owned(directory)['steps'][1]['state'], 'claimed')
            ledger.complete(directory, 1, 'unknown', 'd' * 64)
            value = ledger.owned(directory)
            self.assertFalse(value['complete'])
            self.assertEqual([s['state'] for s in value['steps']], ['observed-success',
                                                                    'unknown'])
            # A record after the unknown issue can only be drift, never progress.
            (directory / '2.issued.json').write_text('{}\n')
            with self.assertRaisesRegex(ValueError, 'after an incomplete step'):
                ledger.owned(directory)
            (directory / '2.issued.json').unlink()
            outcome = directory / '1.outcome.json'
            data = json.loads(outcome.read_text())
            outcome.write_text(json.dumps(dict(data, issue_sha256='f' * 64)) + '\n')
            with self.assertRaisesRegex(ValueError, 'outcome binding'):
                ledger.owned(directory)
            outcome.write_text(json.dumps(data) + '\n')
            (directory / 'notes.txt').write_text('x')
            with self.assertRaisesRegex(ValueError, 'unexpected ledger record'):
                ledger.owned(directory)
        with tempfile.TemporaryDirectory(prefix='b2-owned-test-') as temp:
            directory = ledger.prepare(Path(temp).resolve(), 'b' * 64, f.CONTRACT, prov, 'setup',
                                       f.GUEST)
            ledger.claim(directory, 0, 'c' * 64)
            (directory / '0.claim.json').unlink()
            self.assertEqual(ledger.owned(directory)['steps'][0]['state'], 'partial-claim')
            request = directory / 'request.json'
            request.write_bytes(request.read_bytes().replace(b'"uid":10123', b'"uid":10124'))
            with self.assertRaises(ValueError):
                ledger.owned(directory)

    def test_prepared_records_and_issued_commands_cannot_drift(self):
        with tempfile.TemporaryDirectory(prefix='b2-ledger-test-') as temp:
            prov = {k: 'a' * 64 for k in ('apk', 'pms', 'user', 'permissionmgr', 'appops',
                                        'notification', 'jobscheduler', 'files', 'native', 'image', 'setup_jar')}
            directory = ledger.prepare(Path(temp).resolve(), 'b' * 64, f.CONTRACT, prov, 'setup', f.GUEST)
            record = directory / 'request.json'
            original = record.read_bytes()
            record.write_bytes(original.replace(b'"uid":10123', b'"uid":10124'))
            with self.assertRaises(ValueError):
                ledger.claim(directory, 0, 'c' * 64)
            self.assertFalse((directory / '0.issued.json').exists())
            # Restore only this synthetic host test input to test issue/outcome binding too.
            record.write_bytes(original)
            ledger.claim(directory, 0, 'c' * 64)
            ledger.complete(directory, 0, 'observed-success', 'd' * 64)
            issue = directory / '0.issued.json'; issue.write_bytes(issue.read_bytes() + b' ')
            with self.assertRaises(ValueError):
                ledger.claim(directory, 1, 'c' * 64)


class ProducerTests(unittest.TestCase):
    def test_public_certificate_digest_and_manifest(self):
        der = produce.certificate_der(HERE / 'signer-certificate.pem')
        self.assertEqual(hashlib.sha256(der).hexdigest(), p.SIGNER)
        produce.manifest_contract((HERE / 'AndroidManifest.xml').read_bytes())
        self.assertEqual(produce.SIGNER, p.SIGNER)

    def test_wrong_certificate_rejected_before_any_write_or_tool(self):
        with tempfile.TemporaryDirectory(prefix='b2-producer-test-') as temp:
            root = Path(temp).resolve()
            der = bytearray(produce.certificate_der(HERE / 'signer-certificate.pem')); der[-1] ^= 1
            cert = root / 'wrong.der'; cert.write_bytes(der)
            before = set(root.iterdir())
            with mock.patch.object(produce.subprocess, 'run', side_effect=AssertionError('tool ran')):
                with self.assertRaisesRegex(ValueError, 'another signer'):
                    produce.build(root / 'missing-tools', HERE, root / 'missing-key', cert, root / 'out')
            self.assertEqual(set(root.iterdir()), before)
            self.assertFalse((root / 'out').exists())

    def test_bad_certificate_forms_and_symlink_refuse(self):
        with tempfile.TemporaryDirectory(prefix='b2-producer-test-') as temp:
            root = Path(temp)
            cert = root / 'cert'
            good = (HERE / 'signer-certificate.pem').read_bytes()
            for data in [b'garbage', good + good, good.replace(b'MIIDOT', b'???DOT'), b'']:
                cert.write_bytes(data)
                with self.assertRaises((ValueError, OSError)):
                    produce.certificate_der(cert)
            link = root / 'link'; link.symlink_to(HERE / 'signer-certificate.pem')
            with self.assertRaises(OSError):
                produce.certificate_der(link)

    def test_manifest_contract_refuses_scope_drift(self):
        original = (HERE / 'AndroidManifest.xml').read_bytes()
        variants = [(b'versionCode="1"', b'versionCode="2"'),
                    (b'targetSdkVersion="37"', b'targetSdkVersion="36"'),
                    (b'android:debuggable="false"', b'android:debuggable="true"'),
                    (b'android:allowBackup="false"', b'android:allowBackup="true"'),
                    (b'android:exported="true"', b'android:exported="false"'),
                    (b'<application ', b'<application android:sharedUserId="android.uid.system" '),
                    (b'android.permission.VIBRATE', b'android.permission.INTERNET'),
                    (b'</application>', b'<receiver android:name=".Repair"/></application>')]
        for old, new in variants:
            with self.subTest(old=old), self.assertRaises(ValueError):
                produce.manifest_contract(original.replace(old, new))

    def test_exact_dex_definition_inventory_and_bounds(self):
        names = ['Ldev/andrix/proof/principalclosed/' + n + ';' for n in (
            'B2StateInstrumentation', 'B2StateJobService', 'Contract', 'InitializeState',
            'ObserveState', 'StateFiles')]

        def dex(descriptors):
            count = len(descriptors)
            string_at = 112; type_at = string_at + 4 * count; class_at = type_at + 4 * count
            data = bytearray(class_at + 32 * count)
            data[:8] = b'dex\n039\0'
            for offset, value in [(36, 112), (40, 0x12345678), (56, count), (60, string_at),
                                  (64, count), (68, type_at), (96, count), (100, class_at)]:
                struct.pack_into('<I', data, offset, value)
            for i, name in enumerate(descriptors):
                struct.pack_into('<I', data, string_at + 4 * i, len(data))
                struct.pack_into('<I', data, type_at + 4 * i, i)
                struct.pack_into('<I', data, class_at + 32 * i, i)
                data += bytes([len(name)]) + name.encode('ascii') + b'\0'
            struct.pack_into('<I', data, 32, len(data))
            data[12:32] = hashlib.sha1(data[32:]).digest()
            struct.pack_into('<I', data, 8, zlib.adler32(data[12:]))
            return bytes(data)

        good = dex(names)
        self.assertEqual(produce.dex_inventory(good), sorted(names))
        for bad in [good[:-1], good + b'\0', dex(names[:-1]), dex(names + ['LForeign;']),
                    dex([*names[:-1], names[0]]), dex([*names[:-1], 'LForeign;']), b'not dex']:
            with self.subTest(size=len(bad)), self.assertRaises(ValueError):
                produce.dex_inventory(bad)

    def test_compiled_manifest_every_attribute_and_component_is_checked(self):
        tree = (HERE / 'fixtures/compiled-manifest.txt').read_text()
        produce.compiled_manifest(tree)
        for old, new in [('=37', '=36'), ('debuggable(0x0101000f)=false', 'debuggable(0x0101000f)=true'),
                         ('E: service', 'E: activity'), ('exported(0x01010010)=true', 'exported(0x01010010)=false'),
                         ('targetPackage(0x01010021)="' + p.PACKAGE + '"',
                          'targetPackage(0x01010021)="other"'),
                         ('A: package=', 'A: unknown=')]:
            with self.subTest(old=old), self.assertRaises(ValueError):
                produce.compiled_manifest(tree.replace(old, new))
        with self.assertRaises(ValueError):
            produce.compiled_manifest(tree + tree)
        with self.assertRaises(ValueError):
            produce.compiled_manifest(tree.replace('      E: instrumentation', '          E: instrumentation'))

    def test_separate_shell_source_and_pinned_reference_closure(self):
        source = (HERE / produce.SETUP_SOURCE).read_text()
        self.assertIn('Process.myUid() == 2000', source)
        self.assertIn('binder.queryLocalInterface(DESCRIPTOR) == null', source)
        self.assertIn('original.writeToParcel(parcel, 0)', source)
        self.assertIn('NotificationChannel.CREATOR.createFromParcel(parcel)', source)
        self.assertIn('NotificationChannel changed = copyChannel(original)', source)
        self.assertEqual(source.count('update.invoke(proxy, PACKAGE, uid, changed)'), 1)
        self.assertFalse(list((HERE / 'src').rglob('NotificationSetup.java')))
        self.assertNotIn('NotificationSetup', (HERE / 'AndroidManifest.xml').read_text())
        for forbidden in ('setAccessible', 'setHiddenApiExemptions', 'clearCallingIdentity',
                          'adoptShellPermissionIdentity', 'setuid(', 'run-as'):
            self.assertNotIn(forbidden, source)
        references = json.loads((HERE / 'setup-api.json').read_text())
        self.assertEqual(set(references), produce.SETUP_REFERENCES)
        self.assertTrue(all(p.hex_value(value) for value in references.values()))

    def test_missing_tool_or_existing_output_refuses_before_writes(self):
        with tempfile.TemporaryDirectory(prefix='b2-producer-test-') as temp:
            root = Path(temp).resolve(); key = root / 'key'; key.write_bytes(b'dummy')
            tools = root / 'android'; tools.mkdir()
            before = set(root.iterdir())
            with self.assertRaises(OSError):
                produce.preflight(tools, HERE, key, HERE / 'signer-certificate.pem', root / 'out')
            self.assertEqual(set(root.iterdir()), before)
            output = root / 'existing'; output.mkdir()
            with self.assertRaisesRegex(ValueError, 'absent'):
                produce.preflight(root, HERE, key, HERE / 'signer-certificate.pem', output)


if __name__ == '__main__':
    unittest.main()
