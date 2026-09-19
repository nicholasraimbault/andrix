# SPDX-License-Identifier: Apache-2.0
"""Kernel process correlation and IO bindings, not Android MAC/runtime proof."""
from pathlib import Path
import json
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
NATIVE = ROOT/'owner/native'


class WorkGatewayTests(unittest.TestCase):
    def compile_and_run(self, name, sources):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory)/name
            command = ['g++', '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror', '-UNDEBUG',
                       '-pthread', '-I'+str(NATIVE), *[str(NATIVE/source) for source in sources],
                       str(ROOT/'owner/tests'/(name+'.cpp')), '-o', str(binary)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=180)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=45)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            return json.loads(result.stdout)

    def test_real_kernel_origin_and_received_descriptor_ownership(self):
        result = self.compile_and_run('work_channel_test', ['work_peer.cpp', 'work_channel.cpp'])
        self.assertTrue(result['actual_kernel_credentials_and_connection_correlation'])
        self.assertTrue(result['same_principal_forwarded_connection_accepted'])
        self.assertTrue(result['same_process_thread_allowed'])
        self.assertTrue(result['control_frame_at_EMFILE'])
        self.assertTrue(result['malformed_received_FDs_closed'])
        self.assertFalse(result['Android_MAC_or_forced_PID_reuse_qualified'])

    def test_immutable_stdio_and_registry_retry_binding(self):
        result = self.compile_and_run('work_io_test',
            ['work_io.cpp', 'work_registry.cpp', 'work_admission.cpp', 'launch_description.cpp'])
        self.assertTrue(result['retained_OFDs_not_numeric_FDs'])
        self.assertTrue(result['Start_matches_actual_binding'])
        self.assertTrue(result['mutable_Unix_offsets_preserved'])
        self.assertTrue(result['metadata_does_not_suppress_EOF'])
        self.assertEqual(result['finite_capture_cancel_races'], 200)
        self.assertEqual(result['finite_duplicate_import_races'], 200)
        self.assertFalse(result['Android_MAC_or_real_work_backend_qualified'])

    def test_no_binder_filter_relaxation_or_legacy_routing(self):
        worker = (NATIVE/'worker_filter.cpp').read_text()
        self.assertIn("uint32_t('b') << 8", worker)
        self.assertIn('SECCOMP_RET_ERRNO | EPERM', worker)
        policy = (ROOT/'owner/sepolicy/andrix_owner.te').read_text()
        self.assertIn('neverallow andrix_owner andrixd:binder call;', policy)
        legacy = (NATIVE/'andrixd.cpp').read_text()
        self.assertNotIn('work_channel.h', legacy)
        self.assertNotIn('AuthorizedWorkPeer', legacy)
        peer = (NATIVE/'work_peer.cpp').read_text()
        self.assertIn('SO_PEERSEC', peer)
        self.assertNotIn('SYS_pidfd_open', peer)
        self.assertNotIn('SO_PEERPIDFD', peer)
        self.assertNotIn('SO_PASSPIDFD', peer)
        self.assertIn('credentials.uid == credentials_.uid', peer)
        self.assertIn('credentials.gid == credentials_.gid', peer)
        header = (NATIVE/'work_peer.h').read_text()
        self.assertIn('NOT the current task SID', header)
        self.assertIn('Missing context fails closed', header)


if __name__ == '__main__':
    unittest.main()
