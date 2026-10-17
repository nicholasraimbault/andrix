# SPDX-License-Identifier: Apache-2.0
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('uid_observe', Path(__file__).with_name('uid_observe.py'))
uid = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uid)


class UidObservationTests(unittest.TestCase):
    def test_named_package_and_shared_identities(self):
        packages = ('Packages:\n  Package [shown.name] (abcd):\n    compat name=stored.name\n'
                    '    appId=10123\n    pkg=null\n  Package [peer.name] (aabb):\n'
                    '    appId=10124\nHidden system packages:\n  Package [peer.name] (cc):\n'
                    '    appId=10124\n')
        result = uid.package_ids(packages)
        self.assertEqual(result['packages'], {'stored.name': 10123, 'peer.name': 10124})
        self.assertEqual(result['hidden'], {'peer.name': 10124})
        self.assertEqual(uid.shared_ids('Shared users:\n  SharedUser [android.uid.system] (ff):\n    appId=1000\n'),
                         {'android.uid.system': 1000})

    def test_missing_duplicate_or_failed_observation_refused(self):
        for text in ('Permission Denial', '', 'Packages:\n  Package [fixture] (ff):\n',
                     'Packages:\n  Package [fixture] (ff):\n    appId=10001\n    appId=10001\n',
                     'Packages:\n  Package [fixture] (ff):\n    appId=10001\n  Package [fixture] (cc):\n    appId=10002\n'):
            with self.assertRaises(ValueError): uid.package_ids(text)
        with self.assertRaises(ValueError): uid.shared_ids('Shared users:\n  SharedUser [x] (1):\n')

    def test_dump_cut_at_the_dumpsys_timeout_is_unavailable(self):
        # The form dumpsys prints when it stops waiting for the service: the partial dump, then its
        # timeout line twice, exit 0 (a real post reboot capture showed 160 of 179 packages).
        packages = ('Packages:\n  Package [shown.name] (abcd):\n    appId=10123\n    pkg=null\n'
                    '  Package [peer.name] (aabb):\n    appId=10124\n')
        cut = packages + "  \n\n*** SERVICE 'package' DUMP TIMEOUT (10000ms) EXPIRED ***\n\n" \
            "\n*** SERVICE 'package' DUMP TIMEOUT (10000ms) EXPIRED ***\n\n"
        self.assertEqual(uid.package_ids(packages)['packages'], {'shown.name': 10123, 'peer.name': 10124})
        with self.assertRaises(uid.DumpUnavailable) as caught:
            uid.package_ids(cut)
        self.assertEqual(str(caught.exception), "package dump unavailable: dumpsys timed out after 10000 ms in service "
                                                "'package', the dump is cut")
        shared = 'Shared users:\n  SharedUser [android.uid.system] (ff):\n    appId=1000\n'
        with self.assertRaises(uid.DumpUnavailable) as caught:
            uid.shared_ids(shared + "\n*** SERVICE 'package' DUMP TIMEOUT (30000ms) EXPIRED ***\n\n")
        self.assertIn('shared user dump unavailable: dumpsys timed out after 30000 ms', str(caught.exception))
        # A dump that ends inside a line is cut too; a ValueError, as every other refusal is.
        for reader, text in ((uid.package_ids, packages[:-1]), (uid.shared_ids, shared[:-1])):
            with self.assertRaises(uid.DumpUnavailable):
                reader(text)
        self.assertTrue(issubclass(uid.DumpUnavailable, ValueError))

    def test_the_completeness_gate_refuses_every_outcome_but_one_complete_dump(self):
        # dumpsys (frameworks/native/cmds/dumpsys/dumpsys.cpp, GrapheneOS 2026081300) exits 0 after a
        # service error, after a failed transfer and after its timeout: only the whole capture shows a
        # dump complete. A line complete partial dump with dumpsys's service error on stderr is the case
        # a stdout reading alone accepts.
        import subprocess
        packages = ('Packages:\n  Package [shown.name] (abcd):\n    appId=10123\n    pkg=null\n'
                    '  Package [peer.name] (aabb):\n    appId=10124\n')
        process = subprocess.CompletedProcess(['adb'], 0, packages, '')
        self.assertIs(uid.complete_capture(process, 'package dump'), packages)
        raw = subprocess.CompletedProcess(['adb'], 0, packages.encode(), b'')
        self.assertEqual(uid.complete_capture(raw, 'package dump'), packages.encode())
        record = {'argv': ['dumpsys', '-t', '30', 'package', 'packages'], 'stdout': packages, 'stderr': '', 'exit_code': 0, 'complete': True}
        self.assertIs(uid.complete_capture(record, 'package dump'), packages)
        self.assertEqual(uid.package_ids(packages)['packages'], {'shown.name': 10123, 'peer.name': 10124})
        marker = "\n*** SERVICE 'package' DUMP TIMEOUT (30000ms) EXPIRED ***\n\n"
        cases = [
            (dict(record, stderr="Error with service 'package' while dumping: FAILED_TRANSACTION\n"),
             "dumpsys reported service 'package' failing while dumping: FAILED_TRANSACTION"),
            (dict(record, stdout='', stderr="Error with service 'package' while dumping PID: DEAD_OBJECT\n"),
             "dumpsys reported service 'package' failing while dumping PID: DEAD_OBJECT"),
            (dict(record, stdout='', stderr="Can't find service: package\n"), "dumpsys found no service 'package'"),
            (dict(record, stdout='', stderr='Failed to create pipe to dump service info for package: Too many open files\n'),
             "dumpsys opened no pipe for service 'package': Too many open files"),
            (dict(record, stderr='Error in poll while dumping service package : Interrupted system call\n'),
             "dumpsys failed polling the dump of service 'package': Interrupted system call, the dump is cut"),
            (dict(record, stderr='Failed to read while dumping service package: Bad file descriptor\n'),
             "dumpsys failed reading the dump of service 'package': Bad file descriptor, the dump is cut"),
            (dict(record, stderr='Failed to write while dumping service package: Broken pipe\n'),
             "dumpsys failed writing the dump of service 'package': Broken pipe, the dump is cut"),
            (dict(record, stdout='', stderr="Error: invalid timeout(seconds) number: '0'\n", exit_code=255),
             "dumpsys exited 255; dumpsys refused its timeout argument in seconds: '0'"),
            (dict(record, stderr='something else\n'), 'dumpsys wrote to stderr: something else'),
            (dict(record, exit_code=1), 'dumpsys exited 1'),
            (dict(record, complete=False), 'its transport did not complete with a result (retired, timed out or stopped)'),
            (dict(record, exit_code=None), 'no recorded stdout, stderr and exit status'),
            (dict(record, stdout=packages + marker + marker), "dumpsys timed out after 30000 ms in service 'package', the dump is cut"),
            (dict(record, stdout=packages[:-1]), 'the dump ends inside a line'),
            (subprocess.CompletedProcess(['adb'], 0, packages, "Error with service 'package' while dumping: FAILED_TRANSACTION\n"),
             "dumpsys reported service 'package' failing while dumping: FAILED_TRANSACTION"),
            (packages, 'not a capture')]
        for capture, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(uid.DumpUnavailable) as caught:
                    uid.complete_capture(capture, 'package dump')
                self.assertEqual(str(caught.exception), 'package dump unavailable: ' + reason)

    def test_actual_hole_exclusion_prediction_and_inconclusive_cases(self):
        packages = {'before': 10000, 'after': 10002}
        self.assertEqual(uid.excluded_hole_candidate(packages, {}, 10000, {10001}, 10001), 10003)
        self.assertEqual(uid.excluded_hole_candidate(packages, {'group': 10003}, 10000, {10001}, 10001), 10004)
        for args in [(packages, {}, 10002, {10001}, 10001),
                     (packages, {}, 10000, {10003}, 10003),
                     ({'after': 10002}, {}, 10000, {10001}, 10001),
                     (packages, {}, 10000, set(), 10001),
                     ({**packages, 'occupied': 10001}, {}, 10000, {10001}, 10001)]:
            with self.assertRaises(ValueError): uid.excluded_hole_candidate(*args)


if __name__ == '__main__':
    unittest.main()
