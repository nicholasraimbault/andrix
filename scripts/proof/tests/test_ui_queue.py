# SPDX-License-Identifier: Apache-2.0
"""File-protocol tests with a simulated consumer; no Android execution claims."""
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

spec = importlib.util.spec_from_file_location('ui_queue', Path(__file__).parents[1]/'ui_queue.py')
queue = importlib.util.module_from_spec(spec)
spec.loader.exec_module(queue)


class UiQueueTests(unittest.TestCase):
    def fixture(self, root):
        (root/'state/ui-requests').mkdir(parents=True)
        (root/'evidence/ui').mkdir(parents=True)
        (root/'evidence/ui/ready').write_text('test consumer only')

    def consume(self, root, count, status='COMPLETED', wrong_id=False):
        errors = []
        received = []

        def run():
            try:
                q, evidence = root/'state/ui-requests', root/'evidence/ui'
                deadline = time.monotonic() + 3
                while len(received) < count and time.monotonic() < deadline:
                    paths = sorted(q.glob('*.json'))
                    if not paths:
                        time.sleep(.005)
                        continue
                    self.assertEqual(len(paths), 1, 'next action published before completion')
                    path = paths[0]
                    ident = path.stem
                    received.append(json.loads(path.read_bytes()))
                    (evidence/(ident+'.request.json')).write_bytes(path.read_bytes())
                    path.unlink()
                    time.sleep(.025)
                    self.assertEqual(list(q.glob('*.json')), [])
                    row = {'id': '9999' if wrong_id else ident, 'status': status}
                    temporary = evidence/(ident+'.result.new')
                    temporary.write_text(json.dumps(row))
                    temporary.rename(evidence/(ident+'.result.json'))
                self.assertEqual(len(received), count)
            except Exception as error:
                errors.append(error)
        worker = threading.Thread(target=run)
        worker.start()
        return worker, received, errors

    def test_next_action_waits_for_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.fixture(root)
            worker, received, errors = self.consume(root, 3)
            rows = queue.submit(root, [{'action': 'wait', 'seconds': 0}] * 3, timeout=3)
            worker.join(4)
            self.assertFalse(errors, errors)
            self.assertEqual([r['id'] for r in rows], ['0001', '0002', '0003'])
            self.assertEqual(len(received), 3)

    def test_failed_or_mismatched_result_never_submits_following_action(self):
        for status, wrong_id in [('FAIL', False), ('COMPLETED', True)]:
            with self.subTest(status=status, wrong_id=wrong_id), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); self.fixture(root)
                worker, received, errors = self.consume(root, 1, status, wrong_id)
                with self.assertRaises(RuntimeError):
                    queue.submit(root, [{'action': 'text', 'text': 'a'}, {'action': 'key', 'code': 66}], 3)
                worker.join(4)
                self.assertFalse(errors, errors)
                self.assertEqual(len(received), 1)
                self.assertEqual(list((root/'state/ui-requests').glob('*.json')), [])
                self.assertFalse((root/'evidence/ui/0002.request.json').exists())

    def test_timeout_remains_pending_and_blocks_new_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.fixture(root)
            with self.assertRaisesRegex(RuntimeError, 'uncertain'):
                queue.submit(root, [{'action': 'text', 'text': 'a'}, {'action': 'key', 'code': 66}], .03)
            self.assertEqual([p.name for p in (root/'state/ui-requests').glob('*.json')], ['0001.json'])
            with self.assertRaisesRegex(RuntimeError, 'pending'):
                queue.submit(root, [{'action': 'key', 'code': 66}], 1)

    def test_in_progress_consumed_request_and_orphan_result_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.fixture(root)
            evidence = root/'evidence/ui'
            (evidence/'0001.request.json').write_text('{}')
            with self.assertRaisesRegex(RuntimeError, 'pending'):
                queue.submit(root, [{'action': 'wait'}], 1)
            (evidence/'0001.request.json').unlink()
            (evidence/'0001.result.json').write_text('{"id":"0001","status":"COMPLETED"}')
            with self.assertRaisesRegex(RuntimeError, 'ID reuse'):
                queue.submit(root, [{'action': 'wait'}], 1)

    def test_stopped_controller_and_invalid_batch_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.fixture(root)
            for actions in [[], [{}], [{'action': 'text', 'text': float('nan')}]]:
                with self.assertRaises(ValueError):
                    queue.submit(root, actions)
            self.assertEqual(list((root/'state/ui-requests').glob('*')), [])
            (root/'evidence/controller.status').write_text('exit_code=0')
            with self.assertRaises(RuntimeError):
                queue.submit(root, [{'action': 'wait'}])

    def test_bounded_text_chunks_do_not_implicitly_press_enter(self):
        text = 'ab cd' * 31
        actions = queue.text_actions(text)
        self.assertEqual(''.join(a['text'] for a in actions), text)
        self.assertTrue(all(a['action'] == 'text' and len(a['text']) <= 60 for a in actions))
        for bad in ['', 'a\nb', '%s', '\u2603', 'a' * 8193]:
            with self.assertRaises(ValueError): queue.text_actions(bad)
        with self.assertRaises(ValueError): queue.text_actions('ok', chunk=61)

    def test_readiness_requires_real_view_focus_enabled_and_attached_label(self):
        def xml(label='Attached — native owner UID7500', enabled='true', focused='true',
                package='dev.andrix.terminal'):
            return ('<hierarchy><node package="'+package+'" class="android.widget.TextView" '
                    'text="'+label+'"/><node package="'+package+'" class="android.view.View" '
                    'enabled="'+enabled+'" focused="'+focused+'" text="owner screen"/></hierarchy>')
        self.assertTrue(queue.terminal_input_ready(xml()))
        for args in [dict(label='Attaching — input unavailable until connected'),
                     dict(enabled='false'), dict(focused='false'), dict(package='other.app')]:
            self.assertFalse(queue.terminal_input_ready(xml(**args)))
        with self.assertRaises(ValueError): queue.terminal_input_ready('<!DOCTYPE x><hierarchy/>')
