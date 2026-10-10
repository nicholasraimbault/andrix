# SPDX-License-Identifier: Apache-2.0
"""Pure checks of the header only false commit observers. The actual fixture transcripts and
store snapshots are assessed by scripts/proof/native_lab_history.py in its guarded JVM phase."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('lab_history_observe', Path(__file__).with_name('lab_history_observe.py'))
observe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observe)
INSTANCE, NONCE = 'a' * 32, '1' * 32
SELECTED = {'app_id': 10148, 'user_id': 0, 'user_serial': 7, 'version_code': 1,
            'signer_sha256': observe.FIXTURE_SIGNER}
LINEAGE = '00112233445566778899aabbccddeeff'


def false_reply():
    return dict(SELECTED, version=1, instance=INSTANCE, subject=observe.SUBJECT, request=NONCE,
                state='uncertain', selection_intent='select-new', intent_violated=False, rebind_verified=False,
                busy=False, result='recorded', attempt=3, operation='commit', observation_attempt=3,
                error_class='', observation_error_class='', prepare_acknowledged=True, prepare_ack_attempt=2,
                first_prepare_ack_attempt=2, commit_acknowledged=False, commit_ack_attempt=0,
                first_commit_ack_attempt=0, last_commit_result='false', unexpected_handle_retained=False,
                execution_authorized=False, retirement_complete=False, principal_id='1', pin_phase='PENDING')


def prepared_reply():
    value = false_reply()
    value.update(state='prepared', attempt=2, operation='prepare', observation_attempt=2,
                 last_commit_result='not-called')
    return value


OPTIONS = dict(instance=INSTANCE, nonce=NONCE, selected=SELECTED, expected_id=1, intent='select-new',
               issued_kind='commit', returncode=0, stderr='')


def assess(value, **changes):
    text = value if isinstance(value, str) else json.dumps(value)
    return observe.assess_false_commit(text, **(OPTIONS | changes))


def scratch(test):
    directory = Path(tempfile.mkdtemp()).resolve()
    test.addCleanup(shutil.rmtree, directory)
    return directory


def generation(header):
    return {'version': 1, 'mode': 'empty-v1', 'format': 'V1', 'lab_input_only': True, 'authority': False,
            'lineage': LINEAGE, 'header_sha256': hashlib.sha256(header).hexdigest(), 'header_bytes': len(header),
            'entries': ['slots', 'store.bin', 'store.bin.reservecopy']}


def write_prediction(root, *, signer=observe.FIXTURE_SIGNER, principal=1, extra=None):
    files = {'v2-creating-header.bin': b'C' * 164, 'v2-live-header.bin': b'L' * 85, 'v2-slot-body.bin': b'B' * 163}
    root.mkdir()
    for name, data in files.items():
        (root / name).write_bytes(data)
    manifest = {'version': 1, 'mode': 'predict-v2', 'format': 'V2', 'prediction_only': True, 'authority': False,
                'subject': observe.SUBJECT, 'signer_sha256': signer, 'lineage': LINEAGE, 'app_id': 10148,
                'user_id': 0, 'user_serial': 7, 'principal_id': principal,
                'files': {name: {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
                          for name, data in files.items()}}
    manifest.update(extra or {})
    (root / 'prediction.json').write_text(json.dumps(manifest, separators=(',', ':')) + '\n')
    return files


def store(root, header, body=None):
    (root / 'slots').mkdir(parents=True)
    for name in observe.HEADERS:
        (root / name).write_bytes(header)
    if body is not None:
        (root / 'slots/10148').mkdir()
        for name in ('record.bin', 'record.bin.reservecopy'):
            (root / 'slots/10148' / name).write_bytes(body)
    return root


class FalseCommitTests(unittest.TestCase):
    def test_direct_reply_and_explicit_status_reconciliation(self):
        result = assess(false_reply())
        self.assertEqual((result['assessment_origin'], result['effects'], result['no_effect_inferred'],
                          result['store_observation_required'], result['retry_authorized']),
                         ('commit-reply', 'unknown', False, True, False))
        self.assertEqual(assess(false_reply(), issued_kind='status')['assessment_origin'], 'status-reconciliation')

    def test_pending_ambiguous_changed_and_positive_replies_refuse(self):
        for change in ({'state': 'durable-pin'}, {'state': 'prepared'}, {'state': 'committing'},
                       {'last_commit_result': 'true'}, {'last_commit_result': 'in-flight'},
                       {'last_commit_result': 'exception'}, {'last_commit_result': 'not-called'},
                       {'result': 'in-flight'}, {'result': 'info'}, {'busy': True},
                       {'operation': 'prepare'}, {'operation': 'select-new'},
                       {'selection_intent': 'select-rebind'}, {'rebind_verified': True},
                       {'expected_principal_id': '1'}, {'intent_violated': True},
                       {'unexpected_handle_retained': True},
                       {'unexpected_handle_retained': True, 'unexpected_principal_id': '2'},
                       {'error_class': 'java.lang.IllegalStateException'}, {'error_class': 'aborted-operation'},
                       {'observation_error_class': 'java.lang.IllegalStateException'},
                       {'observation_attempt': 2},
                       {'commit_acknowledged': True, 'commit_ack_attempt': 3, 'first_commit_ack_attempt': 3},
                       {'prepare_acknowledged': False, 'prepare_ack_attempt': 0, 'first_prepare_ack_attempt': 0},
                       {'first_prepare_ack_attempt': 1},
                       {'attempt': 4, 'observation_attempt': 4},
                       {'pin_phase': 'ACTIVE'}, {'pin_phase': 'RETIRING'}, {'principal_id': '2'},
                       {'instance': 'b' * 32}, {'request': '2' * 32}, {'request': ''}, {'subject': 'dev.andrix.other'},
                       {'app_id': 10149}, {'user_serial': 8}, {'signer_sha256': 'c' * 64}, {'version_code': 2},
                       {'execution_authorized': True}, {'retirement_complete': True}, {'surprise': 1}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                assess(false_reply() | change)
        for missing in ('pin_phase', 'principal_id', 'prepare_ack_attempt'):
            value = false_reply()
            del value[missing]
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                assess(value)

    def test_scope_intent_transport_and_issued_kind_are_required(self):
        for change in ({'instance': None}, {'nonce': None}, {'nonce': '2' * 32}, {'selected': None},
                       {'selected': dict(SELECTED, user_serial=8)}, {'expected_id': 2}, {'expected_id': True},
                       {'expected_id': 0}, {'intent': 'select-rebind'}, {'intent': None},
                       {'issued_kind': 'select-new'}, {'issued_kind': 'prepare'}, {'issued_kind': 'commit-retry'},
                       {'issued_kind': None}, {'returncode': 1}, {'returncode': True}, {'returncode': None},
                       {'stderr': observe.UNAVAILABLE}, {'stderr': None}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                assess(false_reply(), **change)

    def test_malformed_transport_text_refuses(self):
        text = json.dumps(false_reply())
        for bad in ('', 'Success', observe.UNAVAILABLE, text + '\n' + text, text.replace('"version": 1', '"version": 1, "version": 1'),
                    '{"version": 1, "instance": "%s", "result": "refused", "code": "STALE_INSTANCE"}' % INSTANCE,
                    text[:-1] + ', "padding": "' + 'x' * 16384 + '"}', text.replace('"attempt": 3', '"attempt": NaN')):
            with self.subTest(bad=bad[:40]), self.assertRaises(ValueError):
                assess(bad)

    def test_positive_assessor_still_refuses_the_false_arm(self):
        with self.assertRaises(ValueError):
            observe.writer.assess_commit(json.dumps(false_reply()), instance=INSTANCE, nonce=NONCE, selected=SELECTED,
                                         expected_id=1, intent='select-new', transport_operation='commit',
                                         returncode=0, stderr='')


ISSUED = {'kind': 'commit', 'instance': INSTANCE, 'nonce': NONCE}


class UnknownTests(unittest.TestCase):
    def retain(self, text, **changes):
        options = dict(issued=ISSUED, returncode=0, stderr='', selected=SELECTED) | changes
        return observe.retain_unknown(text, **options)

    def assert_envelope(self, result, reason, issued=ISSUED):
        self.assertEqual((result['outcome'], result['reason'], result['issued'], result['no_effect_inferred'],
                          result['retry_authorized'], result['replay_authorized'],
                          result['store_observation_required']),
                         ('UNKNOWN', reason, issued, False, False, False, True))
        self.assertNotIn('assessment', result)
        self.assertNotIn('commit_acknowledged', result)

    def test_unresolved_commits_stay_unknown_and_never_false(self):
        exception = false_reply() | {'last_commit_result': 'exception', 'error_class': 'aborted-operation'}
        status = dict(ISSUED, kind='status')
        for text, changes, reason, issued in (
                (json.dumps(exception), {'issued': status}, 'reply-exception', status),
                (json.dumps(false_reply() | {'observation_attempt': 2, 'observation_error_class': 'X'}), {},
                 'reply-false', ISSUED),
                (json.dumps(false_reply() | {'busy': True, 'result': 'in-flight', 'last_commit_result': 'in-flight'}),
                 {'issued': status}, 'reply-in-flight', status),
                (json.dumps(prepared_reply()), {'issued': status}, 'reply-not-called', status)):
            result = self.retain(text, **changes)
            self.assert_envelope(result, reason, issued)
            self.assertEqual(result['reply_sha256'], hashlib.sha256(text.encode()).hexdigest())
        retained = self.retain(json.dumps(exception))['retained']
        self.assertEqual((retained['request'], retained['subject'], retained['selection_intent'], retained['attempt'],
                          retained['first_prepare_ack_attempt'], retained['commit_ack_attempt'],
                          retained['principal_id']), (NONCE, observe.SUBJECT, 'select-new', 3, 2, 0, '1'))

    def test_the_issued_obligation_survives_a_missing_or_unavailable_reply(self):
        result = self.retain(None, returncode=None, stderr=None)
        self.assert_envelope(result, 'reply-missing')
        self.assertEqual((result['reply_sha256'], result['stderr_sha256'], result['returncode']), (None, None, None))
        self.assertNotIn('retained', result)
        result = self.retain('', returncode=1, stderr=observe.UNAVAILABLE + '\n')
        self.assert_envelope(result, 'reply-unavailable')
        self.assertEqual(result['stderr_sha256'], hashlib.sha256((observe.UNAVAILABLE + '\n').encode()).hexdigest())
        self.assert_envelope(self.retain('\n', returncode=1, stderr='transport closed'), 'reply-missing')

    def test_present_unparseable_or_foreign_replies_keep_the_issued_commit_and_trust_nothing(self):
        foreign = json.dumps(false_reply() | {'instance': 'b' * 32, 'request': '9' * 32})
        refusal = json.dumps({'version': 1, 'instance': INSTANCE, 'result': 'refused', 'code': 'STALE_INSTANCE'})
        for text, reason in (('not json', 'reply-unparseable'), ('[' * 9000, 'reply-unparseable'),
                             (json.dumps(false_reply()) + '\n' + json.dumps(false_reply()), 'reply-unparseable'),
                             (json.dumps(false_reply()).replace('"version": 1', '"version": 1, "version": 1'),
                              'reply-unparseable'),
                             (foreign, 'reply-unrecognized'), (refusal, 'reply-unrecognized'),
                             (json.dumps(false_reply() | {'signer_sha256': 'c' * 64}), 'reply-unrecognized'),
                             (json.dumps(false_reply() | {'surprise': 1}), 'reply-unrecognized')):
            with self.subTest(reason=reason, text=text[:40]):
                result = self.retain(text, returncode=1)
                self.assert_envelope(result, reason)
                self.assertNotIn('retained', result)
                self.assertEqual(result['reply_sha256'], hashlib.sha256(text.encode()).hexdigest())
                self.assertNotIn('b' * 32, json.dumps(result))
        # Another nonce is another operation's reply, even with this operation's instance.
        self.assert_envelope(self.retain(json.dumps(false_reply()), issued=dict(ISSUED, nonce='2' * 32)),
                             'reply-unrecognized', dict(ISSUED, nonce='2' * 32))

    def test_json_content_type_errors_keep_the_issued_request(self):
        for field in ('state', 'pin_phase'):
            for value in ([], {}):
                text = json.dumps(false_reply() | {field: value})
                with self.subTest(field=field, value=value):
                    result = self.retain(text)
                    self.assert_envelope(result, 'reply-unrecognized')
                    self.assertEqual(result['reply_sha256'], hashlib.sha256(text.encode()).hexdigest())
                    self.assertNotIn('retained', result)

    def test_non_utf8_text_is_an_explicit_capture_error(self):
        for text, changes in (('\ud800', {}), (json.dumps(false_reply()), {'stderr': '\udcff'})):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, 'strict UTF-8'):
                self.retain(text, **changes)

    def test_the_ledger_record_and_capture_are_required_inputs(self):
        for changes in ({'issued': dict(ISSUED, kind='select-new')}, {'issued': dict(ISSUED, kind='prepare')},
                        {'issued': dict(ISSUED, nonce='short')}, {'issued': dict(ISSUED, instance=None)},
                        {'issued': dict(ISSUED, extra=1)}, {'issued': None}, {'selected': None},
                        {'selected': dict(SELECTED, app_id='10148')}, {'selected': {}},
                        {'returncode': True}, {'stderr': b''}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.retain(json.dumps(false_reply()), **changes)
        with self.assertRaises(TypeError):
            observe.retain_unknown(json.dumps(false_reply()), issued=ISSUED, returncode=0, stderr='')


class GenerationAndPredictionTests(unittest.TestCase):
    def test_generation_report_is_exact(self):
        good = generation(b'H' * 70)
        self.assertEqual(observe.load_generation(json.dumps(good, separators=(',', ':')))['lineage'], LINEAGE)
        for change in ({'authority': True}, {'lab_input_only': False}, {'mode': 'predict-v2'}, {'format': 'V2'},
                       {'lineage': LINEAGE.upper()}, {'header_bytes': 71}, {'header_bytes': True},
                       {'entries': ['slots', 'store.bin']}, {'version': True}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                observe.load_generation(json.dumps(good | change))
        reordered = dict(reversed(list(good.items())))
        with self.assertRaises(ValueError):
            observe.load_generation(json.dumps(reordered))

    def test_prediction_files_and_manifest_are_exact(self):
        root = scratch(self)
        files = write_prediction(root / 'p')
        loaded = observe.load_prediction(root / 'p')
        self.assertEqual(loaded['bytes'], files)
        write_prediction(root / 'host', signer='0' * 64)
        with self.assertRaises(ValueError):
            observe.load_prediction(root / 'host')
        self.assertEqual(observe.load_prediction(root / 'host', signer='0' * 64)['signer_sha256'], '0' * 64)
        for name, action in (('extra', lambda p: (p / 'store.bin').write_bytes(b'x')),
                             ('missing', lambda p: (p / 'v2-live-header.bin').unlink()),
                             ('changed', lambda p: (p / 'v2-slot-body.bin').write_bytes(b'B' * 162)),
                             ('link', lambda p: ((p / 'v2-slot-body.bin').unlink(),
                                                 (p / 'v2-slot-body.bin').symlink_to(p / 'v2-live-header.bin'))),
                             ('hard', lambda p: ((p / 'v2-slot-body.bin').unlink(),
                                                 os.link(p / 'v2-live-header.bin', p / 'v2-slot-body.bin'))),
                             ('spaced', lambda p: (p / 'prediction.json').write_text(
                                 (p / 'prediction.json').read_text().replace(',', ', ', 1)))):
            directory = root / name
            write_prediction(directory)
            action(directory)
            with self.subTest(name=name), self.assertRaises(ValueError):
                observe.load_prediction(directory)
        for extra in ({'principal_id': 2}, {'authority': True}, {'user_id': 1}, {'app_id': 9999},
                      {'mode': 'empty-v1'}, {'subject': 'dev.andrix.other'}):
            directory = root / ('manifest-' + next(iter(extra)))
            write_prediction(directory, extra=extra)
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                observe.load_prediction(directory)
        with self.assertRaises(ValueError):
            observe.load_prediction(Path('relative'))

    def test_predictor_arguments_come_from_the_recorded_preparation(self):
        good = generation(b'H' * 70)
        self.assertEqual(observe.prediction_arguments(good, prepared_reply(), SELECTED),
                         [LINEAGE, '10148', '7', '1'])
        for change in ({'principal_id': '2'}, {'pin_phase': 'ACTIVE'}, {'selection_intent': 'select-rebind'},
                       {'operation': 'commit'}, {'state': 'uncertain'}, {'prepare_acknowledged': False},
                       {'prepare_ack_attempt': 1}, {'intent_violated': True}, {'app_id': 10149}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                observe.prediction_arguments(good, prepared_reply() | change, SELECTED)
        for selected in (dict(SELECTED, signer_sha256='0' * 64), dict(SELECTED, user_serial=8), {}):
            with self.assertRaises(ValueError):
                observe.prediction_arguments(good, prepared_reply(), selected)
        with self.assertRaises(ValueError):
            observe.prediction_arguments(good | {'authority': True}, prepared_reply(), SELECTED)


class StoreSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.root = scratch(self)
        self.files = write_prediction(self.root / 'prediction')
        self.prediction = observe.load_prediction(self.root / 'prediction')
        self.header = b'E' * 70
        self.generation = generation(self.header)

    def test_each_phase_is_exact(self):
        creating = store(self.root / 'creating', self.files['v2-creating-header.bin'])
        live = store(self.root / 'live', self.files['v2-live-header.bin'], self.files['v2-slot-body.bin'])
        empty = store(self.root / 'empty', self.header)
        self.assertEqual(observe.assess_store(empty, 'empty-v1', generation=self.generation)['directories'],
                         ['', 'slots'])
        self.assertFalse(observe.assess_store(creating, 'creating', prediction=self.prediction)['authority'])
        self.assertEqual(observe.assess_store(live, 'live', prediction=self.prediction,
                                              generation=self.generation)['directories'],
                         ['', 'slots', 'slots/10148'])
        for snapshot, phase in ((creating, 'live'), (live, 'creating'), (empty, 'creating'), (creating, 'empty-v1'),
                                (creating, 'published'), (creating, None)):
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                observe.assess_store(snapshot, phase, generation=self.generation, prediction=self.prediction)
        with self.assertRaises(ValueError):
            observe.assess_store(creating, 'creating')
        with self.assertRaises(ValueError):
            observe.assess_store(creating, 'creating', prediction=self.prediction,
                                 generation=self.generation | {'lineage': 'f' * 32})

    def test_backup_seed_extra_links_aliases_and_missing_copies_refuse(self):
        header = self.files['v2-creating-header.bin']
        changes = {
            'backup': lambda p: (p / 'store.bin-backup').write_bytes(header),
            'seed': lambda p: (p / 'store.bin-seed').write_bytes(header),
            'slot directory': lambda p: (p / 'slots/10148').mkdir(),
            'slot seed': lambda p: ((p / 'slots/10148').mkdir(), (p / 'slots/10148/record.bin-seed').write_bytes(b's')),
            'missing reserve': lambda p: (p / 'store.bin.reservecopy').unlink(),
            'changed reserve': lambda p: (p / 'store.bin.reservecopy').write_bytes(header[:-1] + b'x'),
            'link': lambda p: ((p / 'store.bin.reservecopy').unlink(),
                               (p / 'store.bin.reservecopy').symlink_to(p / 'store.bin')),
            'hard link': lambda p: ((p / 'store.bin.reservecopy').unlink(),
                                    os.link(p / 'store.bin', p / 'store.bin.reservecopy')),
            'directory link': lambda p: (p / 'slots/10148').symlink_to(p / 'slots'),
            'extra file': lambda p: (p / 'notes').write_bytes(b''),
        }
        for name, change in changes.items():
            snapshot = store(self.root / name.replace(' ', '-'), header)
            change(snapshot)
            with self.subTest(name=name), self.assertRaises(ValueError):
                observe.assess_store(snapshot, 'creating', prediction=self.prediction)
        alias = self.root / 'alias'
        alias.symlink_to(store(self.root / 'aliased', header))
        with self.assertRaises(ValueError):
            observe.assess_store(alias, 'creating', prediction=self.prediction)


class LifecycleLayoutTests(unittest.TestCase):
    """The lifecycle guest layouts: the generator's manifest is read exactly, and each snapshot must equal
    it file for file, with nothing extra or missing."""

    def manifest(self, mode, files, other=None):
        value = {'version': 1, 'mode': mode, 'lab_input_only': True, 'authority': False, 'subject': observe.SUBJECT,
                 'lineage': LINEAGE, 'app_id': 10148, 'other_app_id': other, 'user_id': 0, 'user_serial': 7,
                 'files': {name: {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
                           for name, data in sorted(files.items())}}
        return json.dumps(value, separators=(',', ':'))

    def store(self, files):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        snapshot = root / 'store'
        (snapshot / 'slots').mkdir(parents=True)
        for name, data in files.items():
            (snapshot / name).parent.mkdir(parents=True, exist_ok=True)
            (snapshot / name).write_bytes(data)
        return snapshot

    def test_each_mode_equals_its_manifest_exactly(self):
        header = b'header'
        one = {'store.bin': header, 'store.bin.reservecopy': header, 'slots/10148/record.bin': b'slot',
               'slots/10148/record.bin.reservecopy': b'slot'}
        for mode in ('retiring-v1', 'v2-slot'):
            generation = observe.load_lifecycle_generation(self.manifest(mode, one))
            assessed = observe.assess_store(self.store(one), mode, generation=generation)
            self.assertEqual(assessed['directories'], ['', 'slots', 'slots/10148'])
            self.assertFalse(assessed['authority'])
            with self.assertRaises(ValueError):
                observe.assess_store(self.store(one), 'v2-beside-sibling', generation=generation)
        both = dict(one, **{'slots/10149/record.bin': b'other', 'slots/10149/record.bin.reservecopy': b'other'})
        generation = observe.load_lifecycle_generation(self.manifest('v2-beside-sibling', both, other=10149))
        self.assertEqual(observe.assess_store(self.store(both), 'v2-beside-sibling', generation=generation)['phase'],
                         'v2-beside-sibling')
        changed = dict(both, **{'slots/10149/record.bin': b'othes'})
        extra = dict(both, **{'slots/10149/record.bin-backup': b'other'})
        missing = {name: data for name, data in both.items() if name != 'slots/10149/record.bin.reservecopy'}
        torn = dict(both, **{'store.bin.reservecopy': b'headed'})
        for files in (changed, extra, missing, torn):
            with self.assertRaises(ValueError):
                observe.assess_store(self.store(files), 'v2-beside-sibling', generation=generation)

    def test_the_manifest_is_read_exactly(self):
        one = {'store.bin': b'h', 'store.bin.reservecopy': b'h', 'slots/10148/record.bin': b's',
               'slots/10148/record.bin.reservecopy': b's'}
        text = self.manifest('v2-slot', one)
        self.assertEqual(observe.load_lifecycle_generation(text)['mode'], 'v2-slot')
        for bad in (text.replace('"v2-slot"', '"v3-slot"'), text.replace('"authority":false', '"authority":true'),
                    text.replace('"other_app_id":null', '"other_app_id":10149'), text + ' ',
                    self.manifest('v2-beside-reservation', one, other=10149),
                    self.manifest('v2-beside-sibling', one, other=10148)):
            with self.assertRaises(ValueError):
                observe.load_lifecycle_generation(bad)


if __name__ == '__main__':
    unittest.main()
