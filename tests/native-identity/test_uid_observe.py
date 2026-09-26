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
