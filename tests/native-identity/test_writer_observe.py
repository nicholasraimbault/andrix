# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('writer_observe', Path(__file__).with_name('writer_observe.py'))
observe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observe)
INSTANCE, NONCE = 'a' * 32, 'b' * 32
SELECTED = {'app_id': 10148, 'user_id': 0, 'user_serial': 7, 'version_code': 1, 'signer_sha256': 'c' * 64}
ID = (1 << 62) + 9


def positive():
    return dict(SELECTED, version=1, instance=INSTANCE, subject=observe.SUBJECT, request=NONCE,
                state='durable-pin', selection_intent='select-rebind', intent_violated=False,
                rebind_verified=True, busy=False, result='recorded', attempt=3, operation='commit',
                observation_attempt=3, error_class='', observation_error_class='', prepare_acknowledged=True,
                prepare_ack_attempt=2, first_prepare_ack_attempt=2, commit_acknowledged=True,
                commit_ack_attempt=3, first_commit_ack_attempt=3, last_commit_result='true',
                unexpected_handle_retained=False, execution_authorized=False, retirement_complete=False,
                expected_principal_id=str(ID), principal_id=str(ID), pin_phase='ACTIVE')


def assess(value):
    return observe.assess_commit(json.dumps(value), instance=INSTANCE, nonce=NONCE,
                                 selected=SELECTED, expected_id=ID, intent='select-rebind',
                                 transport_operation='commit', returncode=0, stderr='')


class WriterObservationTests(unittest.TestCase):
    def test_full_original_identity_and_acknowledgement(self):
        self.assertEqual(assess(positive())['principal_id'], str(ID))
        retry = positive(); retry.update(attempt=4, observation_attempt=4, commit_ack_attempt=4)
        self.assertEqual(assess(retry)['first_commit_ack_attempt'], 3)

    def test_historical_ack_or_unverified_binding_is_not_success(self):
        for change in ({'state': 'uncertain'}, {'intent_violated': True}, {'rebind_verified': False},
                       {'last_commit_result': 'false'}, {'observation_error_class': 'ObservationFailed'},
                       {'observation_attempt': 2}, {'busy': True}, {'commit_ack_attempt': 2},
                       {'unexpected_handle_retained': True}, {'pin_phase': 'PENDING'}, {'result': 'info'},
                       {'prepare_acknowledged': False, 'prepare_ack_attempt': 0, 'first_prepare_ack_attempt': 0},
                       {'expected_principal_id': str(ID + 1)}):
            value = positive(); value.update(change)
            with self.assertRaises(ValueError): assess(value)

    def test_scope_types_and_exact_schema(self):
        for change in ({'instance': 'd' * 32}, {'request': 'd' * 32}, {'app_id': 10146},
                       {'user_serial': 8}, {'signer_sha256': 'd' * 64}, {'version': True},
                       {'attempt': True}, {'commit_acknowledged': 1}, {'execution_authorized': True},
                       {'retirement_complete': True}, {'first_commit_ack_attempt': 4},
                       {'principal_id': str(1 << 63)}, {'surprise': 1}):
            value = positive(); value.update(change)
            with self.assertRaises(ValueError): assess(value)
        value = positive(); del value['prepare_ack_attempt']
        with self.assertRaises(ValueError): assess(value)
        with self.assertRaises(ValueError):
            observe.parse(json.dumps(positive()), instance=INSTANCE, nonce=NONCE)
        invalid = dict(SELECTED, version_code=True)
        with self.assertRaises(ValueError):
            observe.parse(json.dumps(positive()), instance=INSTANCE, nonce=NONCE, selected=invalid)
        text = json.dumps(positive()).replace('"version": 1', '"version": 1, "version": 1')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            observe.parse(text, instance=INSTANCE, nonce=NONCE, selected=SELECTED)

    def test_scope_intent_transport_and_reconciliation_are_required(self):
        value = positive()
        options = dict(instance=INSTANCE, nonce=NONCE, selected=SELECTED, expected_id=ID,
                       intent='select-rebind', transport_operation='commit', returncode=0, stderr='')
        for changed in ({'instance': None}, {'nonce': None}, {'intent': 'select-new'},
                        {'transport_operation': 'info'}, {'returncode': 1}, {'stderr': 'transport error'}):
            with self.assertRaises(ValueError): observe.assess_commit(json.dumps(value), **(options | changed))
        result = observe.assess_commit(json.dumps(value), **(options | {'transport_operation': 'status'}))
        self.assertEqual(result['assessment_origin'], 'status-reconciliation')
        fresh = dict(value, selection_intent='select-new', rebind_verified=False)
        del fresh['expected_principal_id']
        result = observe.assess_commit(json.dumps(fresh), **(options | {'intent': 'select-new'}))
        self.assertEqual(result['assessment_origin'], 'commit-reply')
        for changed in ({'rebind_verified': True}, {'expected_principal_id': str(ID)}, {'operation': 'prepare'}):
            with self.assertRaises(ValueError):
                observe.assess_commit(json.dumps(fresh | changed), **(options | {'intent': 'select-new'}))
        stale = json.dumps({'version': 1, 'instance': INSTANCE, 'result': 'refused', 'code': 'STALE_INSTANCE'})
        with self.assertRaises(ValueError):
            observe.refusal(stale, 'STALE_INSTANCE', INSTANCE, requested_instance=INSTANCE, returncode=1, stderr='')
        absent = json.dumps({'version': 1, 'instance': '', 'result': 'refused', 'code': 'SERVICE_UNAVAILABLE'})
        observe.refusal(absent, 'SERVICE_UNAVAILABLE', '', requested_instance=None, returncode=1, stderr='')
        observe.refusal(absent, 'SERVICE_UNAVAILABLE', '', requested_instance=INSTANCE, returncode=1, stderr='')
        info = json.dumps(value | {'result': 'info'})
        self.assertEqual(observe.parse_info(info, returncode=0, stderr='', selected=SELECTED)['instance'], INSTANCE)
        for code, stderr in ((1, ''), (False, ''), (0, 'transport error')):
            with self.assertRaises(ValueError): observe.parse_info(info, returncode=code, stderr=stderr, selected=SELECTED)

    def test_specific_refusal_and_missing_reply(self):
        text = json.dumps({'version': 1, 'instance': INSTANCE, 'result': 'refused', 'code': 'STALE_INSTANCE'})
        self.assertEqual(observe.refusal(text, 'STALE_INSTANCE', INSTANCE, requested_instance='d'*32, returncode=1, stderr='')['code'], 'STALE_INSTANCE')
        with self.assertRaises(ValueError): observe.refusal(text, 'NONCE_FORMAT', INSTANCE, requested_instance=INSTANCE, returncode=1, stderr='')
        with self.assertRaises(ValueError): observe.parse(text)
        observe.caller_denied('', 'native writer fixture refused: CALLER_DENIED\n', 1)
        with self.assertRaises(ValueError):
            observe.caller_denied('', 'native writer fixture refused: CALLER_DENIED\n', True)
        for text in ('', 'Success', 'native writer fixture outcome unknown: REPLY_UNAVAILABLE', '{}\n{}'):
            with self.assertRaises(ValueError): observe.parse(text)
            with self.assertRaises(ValueError): observe.caller_denied('', text, 1)


if __name__ == '__main__':
    unittest.main()
