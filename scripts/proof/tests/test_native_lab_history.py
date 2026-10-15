# SPDX-License-Identifier: Apache-2.0
"""The guarded lab history runner: its read only source checks, independent goldens, transcript
assessment rules and refusals, and the build scope audit that no build definition selects a lab
file. These tests start no compiler or JVM. The actual fixture transcripts run only in the
guarded runner. Not Android runtime proof."""
from pathlib import Path
import base64
import contextlib
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import native_identity_writer as writer  # noqa: E402
import native_lab_history as runner  # noqa: E402
import native_principal_pins as pins  # noqa: E402

# The build source allowlist, checked for completeness against tracked build definitions. Untracked output, evidence,
# download and node trees are never inputs, whatever they contain.
BUILD_SCOPE = ('Android.bp', 'AndroidProducts.mk', 'andrix.mk', 'apex', 'board', 'experiments', 'init', 'keys',
               'overlays', 'owner', 'products', 'sepolicy', 'supervision', 'tests', 'third_party', 'toolchain',
               'scripts/proof/tests/fixtures')
PRUNED = {'out', 'node_modules', 'downloads'}
# The lab preparation's remaining files, with the writer fixture and the observers it drives.
LAB_FILES = ('scripts/proof/native_lab_history.py', 'scripts/proof/native_lab_history_predictions.json',
             'tests/native-identity/lab_history_observe.py', 'tests/native-identity/writer_observe.py',
             'tests/native-identity/lab-history/LabHistoryStore.java',
             'tests/native-identity/lab-history/LabHistoryStoreTest.java',
             'tests/native-identity/lab-history/NativeWriterLabRehearsal.java',
             'tests/native-identity/lab-history/README.md',
             'tests/native-identity/writer/NativePrincipalWriterFixture.java')
LAB_TOKENS = ('lab-history', 'LabHistoryStore', 'NativeWriterLabRehearsal', 'NativePrincipalWriterFixture',
              'lab_history_observe')
INSTANCE, NONCE = 'a' * 32, '1' * 32
SELECTED = {'app_id': 10148, 'user_id': 0, 'user_serial': 7, 'version_code': 1,
            'signer_sha256': '039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81'}


def scratch(test):
    directory = Path(tempfile.mkdtemp()).resolve()
    test.addCleanup(shutil.rmtree, directory)
    return directory


def build_definitions(root):
    """Build and product definitions inside the explicit source allowlist, never outside it."""
    found = []
    for name in BUILD_SCOPE:
        path = root / name
        if path.is_symlink():
            continue
        if path.is_file():
            found.append(path)
        elif path.is_dir():
            for current, directories, files in os.walk(path):
                directories[:] = sorted(item for item in directories
                                        if item not in PRUNED and not item.startswith('.'))
                found.extend(Path(current) / item for item in sorted(files) if item.endswith(('.mk', '.bp'))
                             and not (Path(current) / item).is_symlink())
    return found


def glob_matches(pattern, path):
    regex, index = '', 0
    while index < len(pattern):
        if pattern.startswith('**/', index):
            regex, index = regex + '(?:[^/]+/)*', index + 3
        elif pattern.startswith('**', index):
            regex, index = regex + '.*', index + 2
        elif pattern[index] == '*':
            regex, index = regex + '[^/]*', index + 1
        else:
            regex, index = regex + re.escape(pattern[index]), index + 1
    return re.fullmatch(regex, path) is not None


def lab_selections(root, definitions):
    """Definitions that name the lab, or whose source globs reach one of its named files."""
    found = []
    for path in definitions:
        text = path.read_text(errors='replace')
        base = path.parent.relative_to(root).as_posix()
        inside = [name if base == '.' else name[len(base) + 1:] for name in LAB_FILES
                  if base == '.' or name.startswith(base + '/')]
        if (any(token in text for token in LAB_TOKENS)
                or any(glob_matches(pattern, name) for pattern in re.findall(r'"([^"]*\*[^"]*)"', text)
                       for name in inside)):
            found.append(path)
    return found


def false_reply(**changes):
    value = dict(SELECTED, version=1, instance=INSTANCE, subject='dev.andrix.proof.principalclosed', request=NONCE,
                 state='uncertain', selection_intent='select-new', intent_violated=False, rebind_verified=False,
                 busy=False, result='recorded', attempt=3, operation='commit', observation_attempt=3,
                 error_class='', observation_error_class='', prepare_acknowledged=True, prepare_ack_attempt=2,
                 first_prepare_ack_attempt=2, commit_acknowledged=False, commit_ack_attempt=0,
                 first_commit_ack_attempt=0, last_commit_result='false', unexpected_handle_retained=False,
                 execution_authorized=False, retirement_complete=False, principal_id='1', pin_phase='PENDING')
    value.update(changes)
    return json.dumps(value)


def info_reply(instance=INSTANCE):
    value = json.loads(false_reply())
    for name in SELECTED:
        del value[name]
    del value['principal_id'], value['pin_phase']
    value.update(instance=instance, request='', state='empty', selection_intent='', result='info', attempt=0,
                 operation='', observation_attempt=0, prepare_acknowledged=False, prepare_ack_attempt=0,
                 first_prepare_ack_attempt=0, last_commit_result='not-called')
    return json.dumps(value)


def reply(text, operation='commit', code=0, stderr='', instance=INSTANCE, nonce=NONCE):
    return {'operation': operation, 'instance': instance, 'nonce': nonce, 'reply': True, 'returncode': code,
            'stdout': text, 'stderr': stderr}


def line(label, text, operation='commit', code=0, stderr='', instance=INSTANCE, nonce=NONCE):
    encode = lambda value: base64.b64encode(value.encode()).decode()
    return '\t'.join(('REPLY', label, operation, instance, nonce, str(code), encode(text), encode(stderr)))


class LabHistoryRunnerTests(unittest.TestCase):
    def test_source_checks_pass(self):
        self.assertEqual(runner.source_checks(), [])

    def test_store_fixture_reads_under_the_production_format(self):
        # The store fixture reads its stores under Format.V3 too, after its earlier readers, and its
        # production control fails exactly there: every earlier block passes first.
        expected = runner.strict(runner.PREDICTIONS.read_text())['store_fixture']
        production = 'the production format reads them as the previous format does'
        self.assertEqual(expected['pass'][expected['pass'].index('readers classify the predictions') + 1], production)
        control = expected['production_control']
        self.assertEqual(control['pass'], expected['pass'][:expected['pass'].index(production)])
        self.assertIn(control['mutant'], runner.b1.PRODUCTION_MUTANTS)
        code = runner.b1.strip_java_comments((runner.LAB_DIR / 'LabHistoryStoreTest.java').read_text())
        self.assertEqual(code.count('System.out.println("PASS %s");' % production), 1)
        block = code[code.index('System.out.println("PASS readers classify the predictions");'):
                     code.index('System.out.println("PASS %s");' % production)]
        self.assertEqual(block.count('NativeIdentityStore.Format.V3'), 3)
        self.assertNotRegex(block, r'Format\s*\.\s*V[12]\b')
        self.assertEqual(code.count('"%s"' % control['failure']), 1)
        self.assertIn('"%s"' % control['failure'], block)
        # The control's store differs from the current one only in the production format's line.
        store = (runner.FRAMEWORK / 'NativeIdentityStore.java').read_text()
        self.assertEqual(store.count(runner.b1.PRODUCTION_ENUM), 1)

    def test_goldens_follow_the_documented_layout_and_match_the_java_test(self):
        goldens = runner.goldens()
        self.assertEqual({name: len(data) for name, data in goldens.items()},
                         {'EMPTY': 70, 'CREATING': 164, 'LIVE': 85, 'BODY': 163})
        for name, data in goldens.items():
            self.assertEqual(data[:4], b'AXID')
            self.assertEqual(int.from_bytes(data[8:12], 'little'), len(data))
            self.assertEqual(runner.hashlib.sha256(data[:-32]).digest(), data[-32:])
        self.assertEqual((goldens['EMPTY'][4:8], goldens['CREATING'][4:8], goldens['LIVE'][4:8], goldens['BODY'][4:8]),
                         (b'\x01\x00\x01\x00', b'\x01\x00\x02\x00', b'\x01\x00\x02\x00', b'\x02\x00\x01\x00'))
        test = (runner.LAB_DIR / 'LabHistoryStoreTest.java').read_text()
        for name, data in goldens.items():
            self.assertEqual(runner.java_constant(test, name + '_SHA256'), runner.sha(data))
        self.assertNotEqual(runner.goldens(serial=8)['CREATING'], goldens['CREATING'])
        with self.assertRaises(ValueError):
            runner.java_constant(test + '\n    private static final int EMPTY_BYTES = 70;', 'EMPTY_BYTES')

    def test_rehearsal_injection_guard(self):
        text = (runner.LAB_DIR / 'NativeWriterLabRehearsal.java').read_text()
        self.assertEqual(runner.rehearsal_problems(text), [])
        anchor = '        PackageManagerService rebooted = boot(store);\n'
        self.assertEqual(text.count(anchor), 1)
        for injected in ('rebooted.mSettings.pins.restore(null);', 'rebooted.mSettings.storeHolds.add(APP_ID);',
                         'rebooted.mSettings.persistence.reservePending(null);', 'Files.write(store, new byte[0]);',
                         'rebooted.mSettings.store.initializeNew("0");', 'rebooted.mSettings.mNativeIdentityLoaded = null;',
                         'Object x = NativeIdentityStore.Format.V1;',
                         'Object x = NativeIdentityStore.Format.V2;',
                         'Object x = NativeIdentityStore.Format . V2;',
                         'Object x = NativeIdentityStore.Format.V3;',
                         'rebooted.manager.releaseUid(null, null);',
                         'rebooted.mSettings.pins.finishRelease(null);',
                         'rebooted.manager.suspend(null, null);',
                         'rebooted.manager.lift(null, null);',
                         'rebooted.manager.beginDisposition(null);',
                         'rebooted.manager.confirmDisposition(null, null);',
                         'rebooted.mSettings.store.omitReleasedSlot(null, 0);',
                         'rebooted.mSettings.store.dropReleasedUser(null, 0, null);',
                         'Object f = rebooted.manager :: releaseUid;'):
            changed = text.replace(anchor, anchor + '        ' + injected + '\n', 1)
            self.assertTrue(runner.rehearsal_problems(changed), injected)
        # A mention inside a comment is not an injection.
        self.assertEqual(runner.rehearsal_problems(text.replace(anchor, '        // reservePending(\n' + anchor, 1)), [])

    def test_labels_and_predictions_are_consistent(self):
        predictions = runner.strict(runner.PREDICTIONS.read_text())
        labels = runner.labels_in((runner.LAB_DIR / 'NativeWriterLabRehearsal.java').read_text())
        self.assertEqual(len(labels), len(set(labels)))
        self.assertEqual(set(labels), set(predictions['rehearsal']['labels']))
        self.assertEqual({want['kind'] for want in predictions['rehearsal']['labels'].values()},
                         {'info', 'parse', 'false-commit', 'positive-commit', 'refusal', 'unknown'})
        self.assertEqual(predictions['status'], 'PREDICTIONS_NOT_RESULTS')
        self.assertEqual(runner.sha(bytes([9])), predictions['rehearsal']['changed_signer_sha256'])
        self.assertEqual(runner.sha(bytes([1, 2, 3])), predictions['rehearsal']['facade_signer_sha256'])

    def test_not_run_creates_and_starts_nothing(self):
        directory = scratch(self)
        evidence, work = directory / 'evidence.json', directory / 'work'
        arguments = ['--evidence', str(evidence), '--work', str(work), '--pinned-framework', str(directory)]
        with mock.patch.object(subprocess, 'run', side_effect=AssertionError('started a process')), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            with mock.patch.object(runner.b1, 'resource_guard', return_value='required bounds absent'):
                self.assertEqual(runner.main(arguments), 2)
            with mock.patch.object(runner.b1, 'resource_guard', return_value=None), \
                    mock.patch.object(runner.shutil, 'which', return_value=None):
                self.assertEqual(runner.main(arguments), 2)
        reports = [json.loads(part) for part in output.getvalue().replace('}\n{', '}\x00{').split('\x00')]
        self.assertEqual([(report['status'], report['reason']) for report in reports],
                         [('NOT_RUN', 'required bounds absent'), ('NOT_RUN', 'no JDK on PATH')])
        self.assertTrue(all(report['runtime_qualified'] is False for report in reports))
        self.assertFalse(evidence.exists() or work.exists())
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            runner.main(['--evidence', str(evidence), '--work', str(work)])

    def test_fresh_outside_refuses_repository_existing_and_sealed_paths(self):
        directory = scratch(self)
        (directory / 'sealed').mkdir()
        (directory / 'sealed/SHA256SUMS').write_text('closed\n')
        for path in (ROOT / 'new-evidence.json', ROOT, directory, directory / 'sealed/new.json'):
            with self.assertRaises(ValueError):
                runner.fresh_outside(path, 'test path')
        self.assertEqual(runner.fresh_outside(directory / 'fresh', 'test path'), directory / 'fresh')

    def test_parse_transcript_refuses_replays_and_unknown_lines(self):
        stdout = '\n'.join([line('commit', false_reply()), line('commit', false_reply()), 'PASS one',
                            'ISSUED\tlost\tcommit\t%s\t%s' % (INSTANCE, NONCE), 'ISSUED\tlost\tcommit\ta\tb',
                            'ISSUED\tshort\tcommit\ta', 'CONTEXT\tselected\t{}', 'CONTEXT\tselected\t{}',
                            'REPLY\tbad\tcommit\ta\tb\t0\t!!\t', 'noise', 'DONE\tfinished'])
        events, context, passes, done, problems = runner.parse_transcript(stdout)
        self.assertEqual(([label for label, _ in events], passes, done), (['commit', 'lost'], ['one'], ['finished']))
        self.assertEqual(events[1][1], {'operation': 'commit', 'instance': INSTANCE, 'nonce': NONCE, 'reply': False})
        self.assertEqual(problems.count('replayed operation label commit'), 1)
        self.assertEqual(problems.count('replayed operation label lost'), 1)
        self.assertTrue(any(item.startswith('undecodable reply bad') for item in problems))
        self.assertEqual(sum(item.startswith('unexpected transcript line') for item in problems), 3)

    def test_assessment_kinds_refuse_the_wrong_arm(self):
        observe = runner.observer()
        false_commit = reply(false_reply())
        self.assertEqual(runner.assess_label(observe, false_commit, {'kind': 'false-commit', 'origin': 'commit-reply'},
                                             SELECTED, INSTANCE), 'commit-reply')
        self.assertEqual(runner.assess_label(observe, reply(false_reply(), operation='status'),
                                             {'kind': 'false-commit', 'origin': 'status-reconciliation'},
                                             SELECTED, INSTANCE), 'status-reconciliation')
        exception = reply(false_reply(last_commit_result='exception', error_class='aborted-operation'), 'status')
        self.assertEqual(runner.assess_label(observe, exception, {'kind': 'unknown', 'reason': 'reply-exception'},
                                             SELECTED, INSTANCE), 'reply-exception')
        unavailable = reply('', code=1, stderr=observe.UNAVAILABLE + '\n')
        retained_later = {'kind': 'unknown', 'reason': 'reply-unavailable', 'retained_by': 'status'}
        self.assertEqual(runner.assess_label(observe, unavailable, retained_later, SELECTED, INSTANCE),
                         'reply-unavailable')
        issued_only = {'operation': 'commit', 'instance': INSTANCE, 'nonce': NONCE, 'reply': False}
        self.assertEqual(runner.assess_label(observe, issued_only, {'kind': 'unknown', 'reason': 'reply-missing',
                                                                   'retained_by': 'status'}, SELECTED, INSTANCE),
                         'reply-missing')
        for case, want, current in (
                # Without reply fields a retention claim needs a named later status.
                (unavailable, {'kind': 'unknown', 'reason': 'reply-unavailable'}, INSTANCE),
                (issued_only, {'kind': 'unknown', 'reason': 'reply-missing'}, INSTANCE),
                (issued_only, {'kind': 'unknown', 'reason': 'reply-missing', 'retained_by': 'status'}, 'b' * 32),
                (issued_only, {'kind': 'false-commit', 'origin': 'commit-reply'}, INSTANCE),
                (dict(issued_only, operation='prepare'), {'kind': 'unknown', 'reason': 'reply-missing',
                                                          'retained_by': 'status'}, INSTANCE),
                # A reply that lost the original request retains nothing for it.
                (reply(false_reply(last_commit_result='exception', request='2' * 32)),
                 {'kind': 'unknown', 'reason': 'reply-exception'}, INSTANCE),
                (reply(false_reply(last_commit_result='exception', attempt=4, observation_attempt=4,
                                   prepare_ack_attempt=3, first_prepare_ack_attempt=3)),
                 {'kind': 'unknown', 'reason': 'reply-exception'}, INSTANCE),
                (false_commit, {'kind': 'false-commit', 'origin': 'status-reconciliation'}, INSTANCE),
                (false_commit, {'kind': 'unknown', 'reason': 'reply-false'}, INSTANCE),
                (false_commit, {'kind': 'parse', 'state': 'uncertain'}, INSTANCE),
                (false_commit, {'kind': 'positive-commit', 'origin': 'commit-reply'}, INSTANCE),
                (false_commit, {'kind': 'false-commit', 'origin': 'commit-reply'}, 'b' * 32),
                (reply(false_reply(), operation='select-new'), {'kind': 'false-commit', 'origin': 'commit-reply'},
                 INSTANCE),
                (exception, {'kind': 'false-commit', 'origin': 'status-reconciliation'}, INSTANCE),
                (reply(false_reply(attempt=4, observation_attempt=4, first_prepare_ack_attempt=2,
                                   prepare_ack_attempt=3)), {'kind': 'unknown', 'reason': 'reply-false'}, INSTANCE),
                (false_commit, {'kind': 'invented'}, INSTANCE)):
            with self.subTest(want=want), self.assertRaises(ValueError):
                runner.assess_label(observe, case, want, SELECTED, current)
        # A weakened positive assessor that accepted the false arm would be reported.
        with mock.patch.object(observe.writer, 'assess_commit', lambda *args, **options: {}), \
                self.assertRaisesRegex(ValueError, 'positive assessor accepted a false commit'):
            runner.assess_label(observe, false_commit, {'kind': 'false-commit', 'origin': 'commit-reply'},
                                SELECTED, INSTANCE)

    def test_retention_needs_a_later_status_of_the_same_issued_request(self):
        predictions = {'rehearsal': {
            'pass': [], 'done': 'finished', 'facade_signer_sha256': SELECTED['signer_sha256'],
            'changed_signer_sha256': '0' * 64, 'snapshots': {}, 'modes': {},
            'labels': {'info': {'kind': 'info'},
                       'lost-commit': {'kind': 'unknown', 'reason': 'reply-missing', 'retained_by': 'lost-status'},
                       'lost-status': {'kind': 'false-commit', 'origin': 'status-reconciliation'}}}}
        head = ['CONTEXT\tselected\t' + json.dumps(SELECTED), line('info', info_reply(), 'info', instance='-', nonce='-')]
        issued = 'ISSUED\tlost-commit\tcommit\t%s\t%s' % (INSTANCE, NONCE)
        status = line('lost-status', false_reply(), 'status')

        def retention(lines):
            problems, outcomes = runner.check_transcript('\n'.join(head + lines + ['DONE\tfinished']),
                                                         scratch(self), predictions)
            return [item for item in problems if 'retention' in item or item.startswith('lost')], outcomes
        problems, outcomes = retention([issued, status])
        self.assertEqual(problems, [])
        self.assertEqual((outcomes['lost-commit'], outcomes['lost-commit retained by']), ('reply-missing', 'lost-status'))
        for lines in ([status, issued],
                      [issued, line('lost-status', false_reply(request='2' * 32), 'status', nonce='2' * 32)],
                      [issued, line('lost-status', false_reply(attempt=4, observation_attempt=4, prepare_ack_attempt=3,
                                                               first_prepare_ack_attempt=3), 'status')],
                      [issued]):
            with self.subTest(lines=[item.split('\t')[1] for item in lines]):
                self.assertTrue(retention(lines)[0])

    def test_store_observations_refuse_consistent_but_wrong_bytes_manifest_and_modes(self):
        lineage = 'ab' * 16
        signer = SELECTED['signer_sha256']
        modes = {'p2-root': 'rwx------', 'p3-slots': 'r-x------'}
        predictions = {'rehearsal': {
            'pass': [], 'done': 'finished', 'facade_signer_sha256': signer, 'changed_signer_sha256': '0' * 64,
            'snapshots': {'empty': 'empty-v1', 'creating': 'creating', 'live': 'live'}, 'modes': modes,
            'labels': {'info': {'kind': 'info'}, 'prepare': {'kind': 'parse', 'state': 'prepared'}}}}
        prepared = false_reply(state='prepared', attempt=2, operation='prepare', observation_attempt=2,
                               last_commit_result='not-called')
        gold = runner.goldens(lineage=lineage, signer=signer)
        wrong = {'EMPTY': b'E' * 70, 'CREATING': b'C' * 164, 'LIVE': b'L' * 85, 'BODY': b'B' * 163}

        def observe_store(records, serial=7, observed=modes):
            work = scratch(self)
            for name, header, body in (('empty', 'EMPTY', None), ('creating', 'CREATING', None),
                                       ('live', 'LIVE', 'BODY'), ('store', 'LIVE', 'BODY')):
                root = work / ('snapshots/' + name if name != 'store' else name)
                (root / 'slots').mkdir(parents=True)
                for copy in ('store.bin', 'store.bin.reservecopy'):
                    (root / copy).write_bytes(records[header])
                if body:
                    (root / 'slots/10148').mkdir()
                    for copy in ('record.bin', 'record.bin.reservecopy'):
                        (root / 'slots/10148' / copy).write_bytes(records[body])
            files = {'v2-creating-header.bin': records['CREATING'], 'v2-live-header.bin': records['LIVE'],
                     'v2-slot-body.bin': records['BODY']}
            (work / 'host-prediction').mkdir()
            for name, data in files.items():
                (work / 'host-prediction' / name).write_bytes(data)
            manifest = json.dumps({'version': 1, 'mode': 'predict-v2', 'format': 'V2', 'prediction_only': True,
                                   'authority': False, 'subject': 'dev.andrix.proof.principalclosed',
                                   'signer_sha256': signer, 'lineage': lineage, 'app_id': 10148, 'user_id': 0,
                                   'user_serial': serial, 'principal_id': 1,
                                   'files': {name: {'sha256': runner.sha(data), 'bytes': len(data)}
                                             for name, data in files.items()}}, separators=(',', ':'))
            (work / 'host-prediction/prediction.json').write_text(manifest + '\n')
            generation = {'version': 1, 'mode': 'empty-v1', 'format': 'V1', 'lab_input_only': True,
                          'authority': False, 'lineage': lineage, 'header_sha256': runner.sha(records['EMPTY']),
                          'header_bytes': 70, 'entries': ['slots', 'store.bin', 'store.bin.reservecopy']}
            stdout = '\n'.join(['CONTEXT\tselected\t' + json.dumps(SELECTED),
                                'CONTEXT\tgeneration\t' + json.dumps(generation, separators=(',', ':')),
                                'CONTEXT\tmodes\t' + json.dumps(observed), 'CONTEXT\tprediction\t' + manifest,
                                line('info', info_reply(), 'info', instance='-', nonce='-'),
                                line('prepare', prepared, 'prepare'), 'DONE\tfinished'])
            return runner.check_transcript(stdout, work, predictions)[0]
        self.assertEqual(observe_store(gold), [])
        self.assertTrue(any('independent layout oracle' in item for item in observe_store(wrong)))
        self.assertEqual(observe_store(gold, serial=8), ['predictor inputs differ from the captured prediction manifest'])
        self.assertEqual(observe_store(gold, observed={'p2-root': 'rwx------', 'p3-slots': 'rwx------'}),
                         ["observed live store modes {'p2-root': 'rwx------', 'p3-slots': 'rwx------'}"])

    def test_a_later_timeout_keeps_the_compiler_record_and_earlier_failures(self):
        directory = scratch(self)
        evidence, work = directory / 'evidence.json', directory / 'work'
        compiled = {'args': ['javac'], 'returncode': 0, 'stdout': 'compiler output', 'stderr': 'compiler notes'}
        calls = []

        def fake_run(args, timeout, cwd=None, env=None):
            calls.append([str(item) for item in args])
            if len(calls) == 1:
                return compiled
            raise subprocess.TimeoutExpired(calls[-1], timeout, output=b'partial output', stderr=b'partial errors')

        def fake_jdk(work, predictions, pinned, record, problems, save):
            record['bounded'] = 'synthetic'
            problems.append('an earlier phase failure')
            save()
        # The runner points tempfile at its own work directory; this test restores the caller's.
        with mock.patch.object(runner.b1, 'resource_guard', return_value=None), \
                mock.patch.object(runner.shutil, 'which', return_value='/usr/bin/java'), \
                mock.patch.object(runner, 'run', side_effect=fake_run), \
                mock.patch.object(tempfile, 'tempdir', tempfile.tempdir), \
                mock.patch.dict(runner.STEPS, {'jdk': fake_jdk}), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(runner.main(['--evidence', str(evidence), '--work', str(work),
                                          '--pinned-framework', str(directory)]), 1)
        report = json.loads(evidence.read_text())
        self.assertEqual(report, json.loads((work / 'progress.json').read_text()))
        self.assertEqual(report['status'], 'NOT_COMPLETE')
        self.assertEqual(report['store fixture'], {'complete': False, 'stub_overlaps': [], 'compile': compiled})
        self.assertEqual((report['exception']['type'], report['exception']['stdout'], report['exception']['stderr']),
                         ('TimeoutExpired', 'partial output', 'partial errors'))
        self.assertEqual(report['exception']['command'][0], 'java')
        self.assertEqual((report['completed_phases'], report['not_completed_phases'], report['running_phase']),
                         (['jdk'], ['store fixture', 'guest inputs', 'rehearsal', 'writer regression', 'pure suites'],
                          'store fixture'))
        self.assertEqual(report['problems'], ['an earlier phase failure', 'qualification did not complete'])
        self.assertEqual(report['jdk'], {'complete': True, 'bounded': 'synthetic'})
        self.assertEqual(len(calls), 2)

    def test_stub_overlaps_are_reviewed_never_silent(self):
        platform = runner.PLATFORM
        facades, overlaps = runner.stubs(platform / 'native_principal_stubs', platform / 'native_principal_xml_stubs',
                                         runner.NATIVE_IDENTITY / 'writer/stubs')
        self.assertEqual(overlaps, ['android/util/Log.java'])
        self.assertIn(platform / 'native_principal_xml_stubs/android/util/Log.java', facades)
        self.assertNotIn(platform / 'native_principal_stubs/android/util/Log.java', facades)
        self.assertEqual(runner.stubs(platform / 'native_principal_xml_stubs')[1], [])
        root = scratch(self)
        for base in ('first', 'second'):
            for name in ('android/os/Clash.java', 'android/util/Log.java', 'android/util/Xml.java'):
                path = root / base / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('// ' + base + '\n')
        with self.assertRaisesRegex(ValueError, 'unreviewed host facade overlap: android/os/Clash.java'):
            runner.stubs(root / 'first', root / 'second')
        (root / 'second/android/os/Clash.java').unlink()
        facades, overlaps = runner.stubs(root / 'first', root / 'second')
        self.assertEqual((overlaps, sorted(path.relative_to(root).as_posix() for path in facades)),
                         (['android/util/Log.java'], ['first/android/os/Clash.java', 'second/android/util/Log.java']))

    def test_compilers_and_jvms_run_inside_work_with_bounded_diagnostics(self):
        work = scratch(self)
        calls = []

        def fake_run(args, timeout, cwd=None, env=None):
            calls.append({'args': [str(item) for item in args], 'cwd': cwd, 'env': env})
            return {'args': args, 'returncode': 0, 'stdout': '', 'stderr': ''}
        options = ['-Xmx256m', '-XX:-UsePerfData', '-XX:ErrorFile=%s/jvm/hs_err_%%p.log' % work,
                   '-XX:ReplayDataFile=%s/jvm/replay_%%p.log' % work, '-XX:-CreateCoredumpOnCrash',
                   '-Djava.io.tmpdir=%s/tmp' % work]
        self.assertEqual(runner.jvm_options(work), options)
        with mock.patch.object(runner, 'run', side_effect=fake_run):
            runner.javac(work, [work / 'A.java'], work / 'classes')
            runner.java(work, 'Main', 'argument', classes=work / 'classes')
            runner.java(work, 'Main', classes=work / 'classes', assertions=False, cwd=work / 'cli-cwd')
            for outside in (work.parent, ROOT, Path('/tmp')):
                with self.assertRaisesRegex(ValueError, 'outside --work'):
                    runner.java(work, 'Main', classes=work / 'classes', cwd=outside)
            runner.writer_regression(work, {'writer_regression': {'module': 'x.py', 'tests': 1}}, None, {}, [], lambda: None)
            runner.pure_suites(work, {'pure_suites': ['y.py']}, work, {}, [], lambda: None)
        self.assertEqual(calls[0]['args'], ['javac', *('-J' + option for option in options), '--release', '17',
                                            '-Xlint:all', '-Werror', '-d', str(work / 'classes'), str(work / 'A.java')])
        self.assertEqual(calls[1]['args'], ['java', *options, '-ea', '-cp',
                                            str(work / 'classes'), 'Main', 'argument'])
        self.assertNotIn('-ea', calls[2]['args'])
        self.assertEqual([call['cwd'] for call in calls],
                         [work / 'jvm', work / 'jvm', work / 'cli-cwd', work / 'suites', work / 'suites'])
        self.assertTrue((work / 'jvm').is_dir())
        for call in calls[3:]:
            self.assertEqual((call['env']['JAVA_TOOL_OPTIONS'], call['env']['TMPDIR']),
                             (' '.join(options), str(work / 'tmp')))
        self.assertEqual(calls[4]['env']['ANDRIX_PINNED_FRAMEWORK'], str(work))

    def test_the_jdk_must_apply_every_bounded_option(self):
        work = scratch(self)
        values = {'ErrorFile': str(work / 'jvm/hs_err_%p.log'), 'ReplayDataFile': str(work / 'jvm/replay_%p.log'),
                  'CreateCoredumpOnCrash': 'false', 'UsePerfData': 'false', 'MaxHeapSize': str(256 << 20)}

        def table(flags):
            return ''.join('    %s %s = %s {product} {command line}\n' % ('ccstr', name, value)
                           for name, value in flags.items())
        for flags, code, accepted in ((values, 0, True), (dict(values, CreateCoredumpOnCrash='true'), 0, False),
                                      ({k: v for k, v in values.items() if k != 'ReplayDataFile'}, 0, False),
                                      (dict(values, ErrorFile='/tmp/hs_err_%p.log'), 0, False), (values, 1, False)):
            record = {}
            with self.subTest(flags=flags, code=code), \
                    mock.patch.object(runner, 'run', return_value={'args': [], 'returncode': code,
                                                                    'stderr': '    java.io.tmpdir = %s/tmp\n' % work,
                                                                    'stdout': table(flags)}):
                if accepted:
                    runner.jdk_phase(work, {}, None, record, [], lambda: None)
                    self.assertEqual(record['bounded'], values)
                else:
                    with self.assertRaisesRegex(ValueError, 'does not apply the bounded JVM options'):
                        runner.jdk_phase(work, {}, None, record, [], lambda: None)

    def test_required_pure_suite_skips_do_not_qualify(self):
        work = scratch(self)
        record, problems = {}, []
        result = {'args': [], 'returncode': 0, 'stdout': '',
                  'stderr': 'Ran 20 tests\nOK (skipped=9)\n'}
        with mock.patch.object(runner, 'run', return_value=result):
            runner.pure_suites(work, {'pure_suites': ['required.py']}, work, record, problems, lambda: None)
        self.assertEqual(record['required.py']['skipped_tests'], 9)
        self.assertEqual(problems, ['required pure suite checks skipped: required.py'])

    def test_compiler_and_suite_preflights_check_the_actual_effective_options(self):
        work = scratch(self)
        values = {'ErrorFile': str(work / 'jvm/hs_err_%p.log'), 'ReplayDataFile': str(work / 'jvm/replay_%p.log'),
                  'CreateCoredumpOnCrash': 'false', 'UsePerfData': 'false', 'MaxHeapSize': str(256 << 20)}
        def captured(args, timeout, cwd=None, env=None):
            fields = values if args[0] != 'javac' else dict(values, UsePerfData='true')
            return {'returncode': 0, 'stdout': ''.join('ccstr %s = %s\n' % item for item in fields.items()),
                    'stderr': '    java.io.tmpdir = %s/tmp\n' % work}
        record = {}
        with mock.patch.object(runner, 'run', side_effect=captured), self.assertRaisesRegex(ValueError, 'compiler JVM'):
            runner.jdk_phase(work, {}, None, record, [], lambda: None)
        self.assertIn('javac_flags', record)
        self.assertNotIn('suite_flags', record)
        def wrong_tmp(args, timeout, cwd=None, env=None):
            return {'returncode': 0, 'stdout': ''.join('ccstr %s = %s\n' % item for item in values.items()),
                    'stderr': '    java.io.tmpdir = /tmp\n'}
        record = {}
        with mock.patch.object(runner, 'run', side_effect=wrong_tmp), self.assertRaisesRegex(ValueError, 'suite JVM'):
            runner.jdk_phase(work, {}, None, record, [], lambda: None)
        self.assertEqual(record['suite_tmpdir'], ['/tmp'])

    def test_unsafe_work_paths_are_not_run(self):
        directory = scratch(self)
        self.assertIsNone(runner.work_path_problem(directory / 'work'))
        for name in ('two words', 'tab\tname', 'percent%p', "single'quote", 'double"quote'):
            work, evidence = directory / name, directory / (name + '.json')
            self.assertEqual(runner.work_path_problem(work), 'work path contains whitespace, a quote or a percent sign')
            with mock.patch.object(runner.b1, 'resource_guard', side_effect=AssertionError('guard reached')), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(runner.main(['--evidence', str(evidence), '--work', str(work),
                                              '--pinned-framework', str(directory)]), 2)
            self.assertEqual(json.loads(output.getvalue())['status'], 'NOT_RUN')
            self.assertFalse(work.exists() or evidence.exists())

    def test_oracle_compares_actual_bytes_at_the_actual_values(self):
        directory = scratch(self)
        values = dict(lineage='f' * 32, app_id=10200, serial=9, signer='0' * 64)
        gold = runner.goldens(**values)
        good, wrong = directory / 'good', directory / 'wrong'
        good.write_bytes(gold['CREATING'])
        wrong.write_bytes(runner.goldens()['CREATING'])
        self.assertEqual(runner.oracle_problems({good: 'CREATING'}, gold, 'test values'), [])
        self.assertEqual(len(runner.oracle_problems({good: 'CREATING', wrong: 'CREATING'}, gold, 'test values')), 1)
        for changed in ({'lineage': 'e' * 32}, {'app_id': 10201}, {'serial': 10}, {'signer': '1' * 64}):
            self.assertNotEqual(runner.goldens(**dict(values, **changed))['CREATING'], gold['CREATING'], changed)
        self.assertNotEqual(runner.goldens(**dict(values, app_id=10201))['BODY'], gold['BODY'])

    def test_subject_is_parsed_from_the_pinned_writer_fixture(self):
        text = (ROOT / runner.FIXTURE).read_text()
        subject = runner.fixture_subject()
        self.assertEqual(subject, runner.subject_constants(text))
        self.assertEqual(runner.UNCHANGED[runner.FIXTURE], runner.sha(text.encode()))
        changes = {'signer': (subject['signer_sha256'], '0' * 64),
                   'version': ('chosen.versionCode != %d' % subject['version_code'],
                               'chosen.versionCode != %d' % (subject['version_code'] + 1)),
                   'user': ('chosen.userId != %d' % subject['user_id'],
                            'chosen.userId != %d' % (subject['user_id'] + 10)),
                   'package': ('"%s"' % subject['package'], '"%s.other"' % subject['package'])}
        for name, (old, new) in changes.items():
            changed = text.replace(old, new)
            self.assertNotEqual(changed, text, name)
            self.assertNotEqual(runner.subject_constants(changed), subject, name)
        for broken in (text.replace('Set.of(FIXTURE_SIGNER)', 'Set.of()'), text + '\n' + text):
            with self.assertRaises(ValueError):
                runner.subject_constants(broken)
        # A fixture that differs from its pin is never parsed for a subject.
        with mock.patch.dict(runner.UNCHANGED, {runner.FIXTURE: '0' * 64}), \
                self.assertRaisesRegex(ValueError, 'differs from its pin'):
            runner.fixture_subject()

    def test_generator_and_observer_subject_are_compared_with_the_fixture(self):
        subject = runner.fixture_subject()
        store = (runner.LAB_DIR / 'LabHistoryStore.java').read_text()
        observe = runner.observer()
        self.assertEqual(runner.subject_problems(subject, store, observe), [])
        for name, changed in (('signer', dict(subject, signer_sha256='0' * 64)),
                              ('package', dict(subject, package=subject['package'] + '.other')),
                              ('user', dict(subject, user_id=subject['user_id'] + 10))):
            with self.subTest(name=name):
                self.assertTrue(runner.subject_problems(changed, store, observe))
        wrong_store = store.replace('"%s"' % subject['signer_sha256'], '"%s"' % ('1' * 64))
        self.assertNotEqual(wrong_store, store)
        self.assertTrue(runner.subject_problems(subject, wrong_store, observe))
        for name in ('FIXTURE_SIGNER', 'SUBJECT'):
            other = types.SimpleNamespace(FIXTURE_SIGNER=observe.FIXTURE_SIGNER, SUBJECT=observe.SUBJECT)
            setattr(other, name, 'x')
            with self.subTest(observer=name):
                self.assertTrue(runner.subject_problems(subject, store, other))

    def test_rehearsal_runs_the_production_boot_format(self):
        text = (runner.LAB_DIR / 'NativeWriterLabRehearsal.java').read_text()
        self.assertEqual(runner.b1.boot_literal(), runner.b1.PRODUCTION)
        self.assertEqual(runner.b1.PRODUCTION, 'NativeIdentityStore.Format.V3')
        self.assertEqual(runner.rehearsal_problems(text), [])
        # Its two facade boots construct the production format, and no other text names a format.
        code = runner.b1.strip_java_comments(text)
        self.assertEqual(code.count(runner.b1.PRODUCTION), 2)
        self.assertEqual(re.findall(r'\bFormat\s*\.\s*V[0-9]+\b', code), ['Format.V3'] * 2)
        # A rehearsal under either earlier format, or a boot literal naming one, is refused.
        for earlier in (runner.b1.PREVIOUS, runner.b1.RETIRED):
            with self.subTest(earlier=earlier):
                self.assertEqual(runner.rehearsal_problems(text.replace(runner.b1.PRODUCTION, earlier)),
                                 ['rehearsal format selection'])
                with mock.patch.object(runner.b1, 'boot_literal', return_value=earlier):
                    self.assertEqual(runner.rehearsal_problems(text), ['rehearsal format selection'])

    def test_source_checks_take_no_work_pinned_copies_or_evidence(self):
        directory = scratch(self)
        for extra in (['--work', str(directory / 'work')], ['--pinned-framework', str(directory)],
                      ['--evidence', str(directory / 'evidence.json')]):
            with self.subTest(extra=extra[0]), self.assertRaises(SystemExit), \
                    contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                runner.main(['--source-checks-only', *extra])
        self.assertEqual(sorted(os.listdir(directory)), [])
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(runner.main(['--source-checks-only']), 0)
        self.assertEqual(json.loads(output.getvalue())['status'], 'SOURCE_ONLY')

    def test_build_scope_reads_no_untracked_output_download_or_evidence_tree(self):
        root = scratch(self)
        for name in ('Android.bp', 'owner/Android.bp', 'products/phone.mk', 'tests/native-identity/Android.bp'):
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text('clean\n')
        for decoy in ('out/native-history-lab/Android.bp', 'out/evidence/product.mk', 'node_modules/a/Android.bp',
                      'downloads/b.mk', 'private/c.bp', 'owner/out/d.mk', 'tests/node_modules/e.bp'):
            path = root / decoy
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('NativePrincipalWriterFixture LabHistoryStore lab-history\n')
        with mock.patch.object(pathlib.Path, 'read_text', autospec=True, side_effect=pathlib.Path.read_text) as read:
            scanned = build_definitions(root)
            self.assertEqual(lab_selections(root, scanned), [])
        self.assertEqual(sorted(path.relative_to(root).as_posix() for path in scanned),
                         ['Android.bp', 'owner/Android.bp', 'products/phone.mk', 'tests/native-identity/Android.bp'])
        self.assertFalse(any('out' in Path(call.args[0]).parts or 'node_modules' in Path(call.args[0]).parts
                             for call in read.call_args_list))
        # A scoped definition that names or globs the lab files is found.
        (root / 'owner/Android.bp').write_text('srcs: ["tests/native-identity/lab-history/LabHistoryStore.java"]\n')
        (root / 'tests/native-identity/Android.bp').write_text('srcs: ["**/*.java"]\n')
        self.assertEqual(len(lab_selections(root, build_definitions(root))), 2)
        # The writer fixture is reached by a glob too, and by its name.
        (root / 'tests/native-identity/Android.bp').write_text('srcs: ["writer/*.java"]\n')
        (root / 'owner/Android.bp').write_text('name: "NativePrincipalWriterFixture"\n')
        self.assertEqual(len(lab_selections(root, build_definitions(root))), 2)

    def test_build_scope_covers_every_tracked_build_definition(self):
        tracked = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '-z', '--', '*.bp', '*.mk'],
                                 capture_output=True, check=True, timeout=30).stdout
        paths = {name.decode('utf-8') for name in tracked.split(b'\0') if name}
        covered = {path.relative_to(ROOT).as_posix() for path in build_definitions(ROOT)}
        self.assertTrue(paths)
        self.assertEqual(paths - covered, set(), 'new build source needs an explicit audit scope')

    def test_native_execution_factory_stays_off_and_nothing_selects_the_lab(self):
        self.assertIs(writer.profile()['native_execution_enabled'], False)
        self.assertIn('owner account designation/factory not connected', pins.profile()['activation_fences'])
        for name in LAB_FILES:
            self.assertTrue((ROOT / name).is_file(), name)
        scanned = build_definitions(ROOT)
        self.assertIn(ROOT / 'tests/native-identity/Android.bp', scanned)
        self.assertEqual(lab_selections(ROOT, scanned), [])
        # No production framework source names a lab file either.
        framework = ''.join(path.read_text() for path in sorted((ROOT / runner.b1.FRAMEWORK_DIR).glob('*.java')))
        for token in LAB_TOKENS:
            self.assertNotIn(token, framework)

    def test_progress_checkpoints_and_timeout_records(self):
        directory = scratch(self)
        report = {}
        progress = runner.Progress(report, directory / 'progress.json')
        progress.begin('jdk')
        self.assertEqual(json.loads((directory / 'progress.json').read_text())['running_phase'], 'jdk')
        progress.done('jdk')
        saved = json.loads((directory / 'progress.json').read_text())
        self.assertEqual((saved['status'], saved['completed_phases'], saved['running_phase']),
                         ('RUNNING', ['jdk'], None))
        record = runner.exception_record(subprocess.TimeoutExpired(['java'], 1, output=b'out', stderr=b'err'))
        self.assertEqual((record['type'], record['stdout'], record['stderr']), ('TimeoutExpired', 'out', 'err'))


class GuestInputTests(unittest.TestCase):
    """The lifecycle guest layouts: the phase, the pinned codec, and the oracle against the lifecycle
    runner's independent decoder."""

    def test_the_phase_and_its_predictions(self):
        self.assertEqual(runner.PHASES, ('jdk', 'store fixture', 'guest inputs', 'rehearsal', 'writer regression',
                                         'pure suites'))
        self.assertIs(runner.STEPS['guest inputs'], runner.guest_inputs)
        predicted = json.loads(runner.PREDICTIONS.read_text())['guest_inputs']
        self.assertEqual(predicted['codec_sha256'], runner.GUEST_CODEC[1])
        self.assertEqual(list(predicted['modes']), list(runner.observer().LIFECYCLE_MODES))
        for mode, names in predicted['modes'].items():
            self.assertEqual(sorted(runner.lifecycle_goldens(mode)), names)
        # Each mode's exact files at the fixed values, by digest, and the second set of values.
        self.assertEqual(predicted['layouts'], {mode: runner.layout_digest(runner.lifecycle_goldens(mode))
                                                for mode in predicted['modes']})
        self.assertEqual((tuple(predicted['values']), tuple(predicted['future_values'])),
                         (runner.GUEST_VALUES, runner.GUEST_FUTURE_VALUES))
        self.assertEqual(len(predicted['refusals']), 15)
        self.assertNotEqual(runner.GUEST_VALUES[1:], runner.GUEST_FUTURE_VALUES[1:])

    def test_the_codec_is_its_pinned_git_object(self):
        path, digest = runner.GUEST_CODEC
        self.assertEqual(runner.sha(runner.b1.git_bytes(runner.GUEST_REVISION, path)), digest)

    def test_a_changed_working_tree_codec_forces_a_re_pin(self):
        self.assertEqual(runner.codec_pin_problems(), [])
        path, digest = runner.GUEST_CODEC
        with mock.patch.object(runner, 'GUEST_CODEC', (path, '0' * 64)):
            self.assertEqual(runner.codec_pin_problems(), [
                'the working tree codec differs from the guest generator pin: re-pin GUEST_REVISION and GUEST_CODEC'])
            self.assertIn('the working tree codec differs from the guest generator pin: re-pin GUEST_REVISION and'
                          ' GUEST_CODEC', runner.source_checks())

    def test_the_oracle_agrees_with_the_independent_decoder(self):
        import native_lifecycle_record as lifecycle
        lineage, app_id, other_app_id, serial = runner.GUEST_VALUES
        for mode in runner.observer().LIFECYCLE_MODES[:6]:
            files = runner.lifecycle_goldens(mode, lineage, app_id, other_app_id, serial)
            header = lifecycle.decode_header(files['store.bin'])
            self.assertIsNotNone(header, mode)
            slots = {int(name.split('/')[1]): lifecycle.decode_slot(data) for name, data in files.items()
                     if name.endswith('/record.bin')}
            self.assertTrue(all(slots.values()), mode)
            self.assertEqual(sorted(entry['app_id'] for entry in header['entries']),
                             sorted({app_id, *slots}), mode)
            if mode == 'retiring-v1':
                self.assertEqual((slots[app_id]['version'], slots[app_id]['users'][0]['legacy']), (1, True))
            if mode in ('eligible-v1', 'v2-beside-sibling', 'v2-beside-unrelated-body'):
                self.assertEqual((slots[app_id]['version'], slots[app_id]['users'][0]['legacy'],
                                  slots[app_id]['package']), (1, False, runner.observer().SUBJECT), mode)
                self.assertEqual(header['version'], 1, mode)
            if mode in ('v2-slot', 'v2-beside-reservation', 'v2-beside-sibling', 'v2-beside-unrelated-body'):
                newer = slots[app_id if mode == 'v2-slot' else other_app_id]
                user = newer['users'][0]
                self.assertEqual((newer['version'], user['state'], [entry['class'] for entry in user['entries']]),
                                 (2, 'ELIGIBLE', ['ACCOUNT_USER']), mode)
            if mode == 'v2-beside-reservation':
                self.assertEqual((header['version'], [entry['bound'] for entry in header['entries']]), (2, [True, False]))
                self.assertEqual(slots[other_app_id]['package'], runner.OTHER)
            if mode == 'v2-beside-sibling':
                self.assertEqual((slots[app_id]['package'], slots[other_app_id]['package']),
                                 (runner.observer().SUBJECT,) * 2)
                self.assertNotEqual(slots[app_id]['users'][0]['principal'], slots[other_app_id]['users'][0]['principal'])
            if mode == 'v2-beside-unrelated-body':
                # The sibling layout, except that the unsupported body is another package's.
                self.assertEqual((slots[app_id]['package'], slots[other_app_id]['package']),
                                 (runner.observer().SUBJECT, runner.OTHER))
                self.assertNotEqual(slots[app_id]['users'][0]['principal'], slots[other_app_id]['users'][0]['principal'])
                sibling = runner.lifecycle_goldens('v2-beside-sibling', lineage, app_id, other_app_id, serial)
                self.assertEqual({name: data for name, data in files.items() if str(other_app_id) not in name},
                                 {name: data for name, data in sibling.items() if str(other_app_id) not in name})
            if mode == 'eligible-v1':
                self.assertEqual(sorted(files), sorted(runner.lifecycle_goldens('retiring-v1', lineage, app_id,
                                                                                other_app_id, serial)))

    def test_the_reader_steps_oracle_is_the_lifecycle_runners_independent_encoding(self):
        """Every version 2 record of the reader step's layouts, from the lab oracle, equals the
        lifecycle runner's independent encoder over the same value, written apart from it; every
        version 1 record and header reads back with the independent decoder, and every later version
        frame with the independent prefix decoder."""
        import native_lifecycle_record as lifecycle
        for lineage, app_id, other_app_id, serial in (runner.GUEST_VALUES, runner.GUEST_FUTURE_VALUES):
            signer, subject = runner.fixture_subject()['signer_sha256'], runner.observer().SUBJECT
            zero, time = '00' * 16, 1_700_000_000_000

            def v2(generation, users, ticket=None, app=app_id, package=subject, signers=(signer,)):
                return lifecycle.slot_v2(lineage, app, generation, package, list(signers), users, ticket)

            def receipts(retirement, disposition):
                return lifecycle.all_kinds(lambda code, kind: (
                    kind, disposition if code >= 10 else retirement,
                    '%02x' % (0x10 + code) * 16 if (disposition if code >= 10 else retirement) == 'DISCHARGED'
                    and code % 2 else zero, code if (disposition if code >= 10 else retirement) == 'DISCHARGED' else 0,
                    time + code if (disposition if code >= 10 else retirement) == 'DISCHARGED' else 0))
            user = ('ACCOUNT_USER', 0, 0, serial, zero, 1, time, None)
            disposing = receipts('DISCHARGED', 'DISPOSING')
            expected = {
                'v2-grant': v2(2, [(1, 0, serial, ('ELIGIBLE', [('ADMIN_GRANT', 0, 0, serial, '47' * 16, 2, time,
                                                                 None)], None))]),
                'v2-scope-1': v2(2, [(1, 0, serial, ('ELIGIBLE', [('ACCOUNT_USER', 1, 0, serial, zero, 6, time, None)],
                                                     None))]),
                'v2-noted': v2(2, [(1, 0, serial, ('ELIGIBLE', [('ACCOUNT_USER', 0, 0, serial, zero, 5, time,
                                                                 '5a' * 32)], None))]),
                'v2-retiring': v2(2, [(1, 0, serial, ('RETIRING', [], ('ACCOUNT_USER', 0, serial, zero, time + 100,
                                                                       receipts('OUTSTANDING', 'OUTSTANDING'))))]),
                'v2-retired': v2(3, [(1, 0, serial, ('RETIRED', [], ('ACCOUNT_USER', 0, serial, zero, time + 100,
                                                                     receipts('DISCHARGED', 'OUTSTANDING'))))]),
                'v2-disposing': v2(4, [(1, 0, serial, ('RETIRED', [], ('ACCOUNT_USER', 0, serial, zero, time + 100,
                                                                       disposing)))]),
                'v2-legacy-suspended': v2(2, [(1, 0, serial, ('RETIRING', [user], ('LEGACY_MARKER', 0, 0, zero, 0,
                                                                                   [])))]),
                'damaged-retired-unknown-inventory': v2(2, [(1, 0, serial, ('RETIRED', [user],
                                                                            ('LEGACY_MARKER', 0, 0, zero, 0, [])))]),
                'damaged-disposing-work': v2(4, [(1, 0, serial, ('RETIRED', [], ('ACCOUNT_USER', 0, serial, zero,
                                                                                 time + 100, [('WORK', 'DISPOSING')
                                                                                              + disposing[0][2:]]
                                                                                 + disposing[1:])))]),
                'damaged-v2-of-v1': v2(1, [(1, 0, serial, ('ELIGIBLE', [], None))]),
                'tombstone-live': v2(4, [], (1, 0, serial, '54' * 16)),
                'tombstone-releasing': v2(4, [], (1, 0, serial, '54' * 16)),
            }
            for scope, mode in ((0, 'v2-recovery-hold'), (2, 'v2-recovery-scope-2'), (3, 'v2-recovery-scope-3')):
                expected[mode] = v2(2, [(1, 0, serial, ('ELIGIBLE', [('RECOVERY_HOLD', scope, 0, serial, zero, 7, time,
                                                                     None)], None))])
            for mode, data in expected.items():
                files = runner.lifecycle_goldens(mode, lineage, app_id, other_app_id, serial)
                with self.subTest(mode=mode, app_id=app_id):
                    self.assertEqual(files['slots/%d/record.bin' % app_id], data)
                    self.assertEqual(files['slots/%d/record.bin.reservecopy' % app_id], data)
            # The largest record, by the same encoder.
            note = '5a' * 32
            users = []
            for index in range(64):
                user_serial = serial if index == 0 else 100 + index
                entries = [('ACCOUNT_USER', 0, index, user_serial, zero, 1, time, note)]
                entries += [('ADMIN_GRANT', 0, 0, serial, '%02x' % (0x40 + grant) * 16, 3, time + grant, note)
                            for grant in range(1, 5)]
                entries.append(('RECOVERY_HOLD', 2, 0, serial, zero, 7, time + 9, note))
                users.append((2 + index, index, user_serial, ('RETIRING', entries, (
                    'ACCOUNT_USER', index, user_serial, zero, time + 100, receipts('OUTSTANDING', 'OUTSTANDING')))))
            largest = v2(2, users, app=other_app_id, package=runner.MAXIMUM,
                         signers=['%064x' % index for index in range(1, 33)])
            files = runner.lifecycle_goldens('maximum-beside-eligible', lineage, app_id, other_app_id, serial)
            self.assertEqual(files['slots/%d/record.bin' % other_app_id], largest)
            self.assertEqual(len(largest), lifecycle.PLAN_SIZES['largest'])
            # Each copy of the mixed layouts and the legacy continuation is the record its name
            # says.
            suspended = runner.lifecycle_goldens('v2-slot', lineage, app_id, other_app_id, serial)[
                'slots/%d/record.bin' % app_id]
            directory = 'slots/%d/' % app_id
            for mode, copies in (('mixed-suspend-backup', ((2, 'v2', True), (2, 'v2', True), (1, 'v1', False))),
                                 ('mixed-lift-backup', ((3, 'v1', False), (3, 'v1', False), (2, 'v2', True))),
                                 ('mixed-suspend-conflict', ((2, 'v2', True), (1, 'v1', False))),
                                 ('mixed-lift-conflict', ((3, 'v1', False), (2, 'v2', True))),
                                 ('legacy-continuation-interrupted', ((2, 'v2', False), (2, 'v2', False),
                                                                      (1, 'v1', False)))):
                files = runner.lifecycle_goldens(mode, lineage, app_id, other_app_id, serial)
                for name, (generation, version, entries) in zip(('record.bin', 'record.bin.reservecopy',
                                                                 'record.bin-backup'), copies):
                    data = files[directory + name]
                    read = lifecycle.decode_slot(data)
                    with self.subTest(mode=mode, copy=name):
                        self.assertEqual((read['version'], runner.struct.unpack_from('<q', data, 32)[0],
                                          bool(read['users'][0]['entries'])), (int(version[1]), generation, entries))
                        if version == 'v2' and entries:
                            self.assertEqual(data, suspended)
                self.assertEqual(len(files), len(copies) + 2, mode)
            continued = runner.lifecycle_goldens('legacy-continuation-interrupted', lineage, app_id, other_app_id,
                                                 serial)[directory + 'record.bin']
            read = lifecycle.decode_slot(continued)['users'][0]
            self.assertEqual((read['state'], read['retirement']['class'], read['retirement']['inventory']),
                             ('RETIRING', 'LEGACY_MARKER', 1))
            lifted = runner.lifecycle_goldens('lift-v1', lineage, app_id, other_app_id, serial)
            self.assertEqual(lifted[directory + 'record.bin'], runner.lifecycle_goldens(
                'mixed-lift-backup', lineage, app_id, other_app_id, serial)[directory + 'record.bin'])
            # Later version frames, by the independent prefix decoder.
            for mode, prefix in (('v3-prefix-valid', {'version': 3, 'app_id': app_id, 'package': subject,
                                                      'principals': [1]}), ('v3-prefix-broken', None)):
                data = runner.lifecycle_goldens(mode, lineage, app_id, other_app_id, serial)[directory + 'record.bin']
                self.assertEqual((lifecycle.decode_frame(data, lifecycle.TYPE_SLOT)[0], lifecycle.decode_prefix(data)),
                                 (3, prefix))
            # The headers, by the independent decoder.
            for mode, version, entries in (('releasing-without-directory', 1, [(app_id, 'RELEASING', False)]),
                                           ('tombstone-releasing', 1, [(app_id, 'RELEASING', False)]),
                                           ('reservation', 2, [(app_id, 'CREATING', True)]),
                                           ('reservation-wrong-serial', 2, [(app_id, 'CREATING', True)]),
                                           ('maximum-beside-eligible', 1, [(app_id, 'LIVE', False),
                                                                           (other_app_id, 'LIVE', False)])):
                header = lifecycle.decode_header(runner.lifecycle_goldens(mode, lineage, app_id, other_app_id,
                                                                          serial)['store.bin'])
                self.assertEqual((header['version'], [(entry['app_id'], entry['phase'], entry['bound'])
                                                      for entry in header['entries']]), (version, entries), mode)
            # The serial control differs from its twin by the binding's serial alone.
            right, wrong = (runner.lifecycle_goldens(mode, lineage, app_id, other_app_id, serial)['store.bin']
                            for mode in ('reservation', 'reservation-wrong-serial'))
            self.assertEqual(right, runner.lifecycle_goldens('reservation', lineage, app_id, other_app_id,
                                                             serial)['store.bin'])
            self.assertEqual(wrong, runner.lifecycle_goldens('reservation', lineage, app_id, other_app_id,
                                                             serial + 1)['store.bin'])

    def test_a_wrong_signer_serial_or_value_is_another_layout(self):
        """The oracle at another serial, signer, lineage or app ID differs from the layout at the
        requested values, so the comparison refuses each; at the requested values it is equal."""
        values = dict(zip(('lineage', 'app_id', 'other_app_id', 'serial'), runner.GUEST_VALUES))
        signer_free = {'releasing-without-directory'}
        serial_free = {'releasing-without-directory'}
        for mode in runner.READER_STEP_MODES:
            gold = runner.lifecycle_goldens(mode, **values)
            self.assertEqual(runner.lifecycle_goldens(mode, **values), gold)
            for change, free in (({'serial': 8}, serial_free), ({'signer': '0' * 64}, signer_free),
                                 ({'lineage': 'f' * 32}, set()), ({'app_id': 10150}, set())):
                with self.subTest(mode=mode, change=change):
                    self.assertEqual(runner.lifecycle_goldens(mode, **dict(values, **change)) == gold, mode in free)

    def test_a_changed_byte_or_checksum_is_refused_even_resealed(self):
        """A staged copy of a generated layout passes the observer against its manifest; a body byte
        changed under a fresh, valid frame checksum, or only the checksum changed, is refused by the
        observer and differs from the oracle. A checksum is no authority over the expected bytes."""
        observe = runner.observer()
        lineage, app_id, other_app_id, serial = runner.GUEST_VALUES
        mode = 'mixed-lift-backup'
        gold = runner.lifecycle_goldens(mode, lineage, app_id, other_app_id, serial)
        manifest = json.dumps({'version': 1, 'mode': mode, 'lab_input_only': True, 'authority': False,
                               'subject': observe.SUBJECT, 'lineage': lineage, 'app_id': app_id,
                               'other_app_id': None, 'user_id': 0, 'user_serial': serial,
                               'files': {name: {'sha256': runner.sha(data), 'bytes': len(data)}
                                         for name, data in sorted(gold.items())}}, separators=(',', ':'))
        generation = observe.load_lifecycle_generation(manifest)

        def staged(files):
            root = scratch(self) / 'store'
            (root / 'slots').mkdir(parents=True)
            for name, data in files.items():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_bytes(data)
            return root
        self.assertEqual(observe.assess_store(staged(gold), mode, generation=generation)['phase'], mode)
        backup = 'slots/%d/record.bin-backup' % app_id
        record = bytearray(gold[backup])
        record[40] ^= 1
        resealed = bytes(record[:-32]) + runner.hashlib.sha256(bytes(record[:-32])).digest()
        import native_lifecycle_record as lifecycle
        self.assertIsNotNone(lifecycle.decode_frame(resealed, lifecycle.TYPE_SLOT))
        checksum = gold[backup][:-1] + bytes([gold[backup][-1] ^ 1])
        for changed in (resealed, checksum):
            files = dict(gold, **{backup: changed})
            self.assertNotEqual(files, gold)
            with self.assertRaises(ValueError):
                observe.assess_store(staged(files), mode, generation=generation)


if __name__ == '__main__':
    unittest.main()
