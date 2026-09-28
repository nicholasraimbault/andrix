# SPDX-License-Identifier: Apache-2.0
"""The guarded lab history runner: its read only source checks, independent goldens, transcript
assessment rules and refusals. These tests start no compiler or JVM. The actual fixture
transcripts run only in the guarded runner. Not Android runtime proof."""
from pathlib import Path
import base64
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import native_lab_history as runner  # noqa: E402

PINNED = os.environ.get('ANDRIX_PINNED_FRAMEWORK')
INSTANCE, NONCE = 'a' * 32, '1' * 32
SELECTED = {'app_id': 10148, 'user_id': 0, 'user_serial': 7, 'version_code': 1,
            'signer_sha256': '039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81'}


def scratch(test):
    directory = Path(tempfile.mkdtemp()).resolve()
    test.addCleanup(shutil.rmtree, directory)
    return directory


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
                         'Object x = NativeIdentityStore.Format.V1;'):
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

        def fake_source(work, predictions, pinned, record, problems, save):
            record['pinned'] = {'synthetic': True}
            problems.append('an earlier source failure')
            save()

        def fake_jdk(work, predictions, pinned, record, problems, save):
            record['bounded'] = 'synthetic'
            save()
        # The runner points tempfile at its own work directory; this test restores the caller's.
        with mock.patch.object(runner.b1, 'resource_guard', return_value=None), \
                mock.patch.object(runner.shutil, 'which', return_value='/usr/bin/java'), \
                mock.patch.object(runner, 'run', side_effect=fake_run), \
                mock.patch.object(tempfile, 'tempdir', tempfile.tempdir), \
                mock.patch.dict(runner.STEPS, {'source': fake_source, 'jdk': fake_jdk}), \
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
                         (['source', 'jdk'], ['store fixture', 'rehearsal', 'writer regression', 'pure suites'],
                          'store fixture'))
        self.assertEqual(report['problems'], ['an earlier source failure', 'qualification did not complete'])
        self.assertTrue(report['source']['complete'])
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

    def test_guard_trip_uses_the_unmodified_guard(self):
        work = scratch(self)
        self.assertEqual(runner.guard_trip(work), [])
        self.assertEqual(runner.b1.ROOT, ROOT)
        with mock.patch.object(runner.lab, 'PATCH', runner.LAB_DIR / 'native-store-format-v2.json'):
            self.assertTrue(runner.guard_trip(scratch(self)))

    @unittest.skipUnless(PINNED, 'ANDRIX_PINNED_FRAMEWORK not set')
    def test_pinned_rebuild_changes_only_settings(self):
        report, problems = runner.pinned_checks(Path(PINNED).resolve(strict=True))
        self.assertEqual(problems, [])
        self.assertEqual((report['changed_bytes'], len(report['other_outputs'])), (1, 9))

    def test_progress_checkpoints_and_timeout_records(self):
        directory = scratch(self)
        report = {}
        progress = runner.Progress(report, directory / 'progress.json')
        progress.begin('source')
        self.assertEqual(json.loads((directory / 'progress.json').read_text())['running_phase'], 'source')
        progress.done('source')
        saved = json.loads((directory / 'progress.json').read_text())
        self.assertEqual((saved['status'], saved['completed_phases'], saved['running_phase']),
                         ('RUNNING', ['source'], None))
        record = runner.exception_record(subprocess.TimeoutExpired(['java'], 1, output=b'out', stderr=b'err'))
        self.assertEqual((record['type'], record['stdout'], record['stderr']), ('TimeoutExpired', 'out', 'err'))


if __name__ == '__main__':
    unittest.main()
