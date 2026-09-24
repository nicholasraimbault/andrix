# SPDX-License-Identifier: Apache-2.0
import unittest
from location_control import info_nonce, location_arguments


class LocationControlTests(unittest.TestCase):
    def test_generated_info_arguments_obey_the_native_contract(self):
        for number in [1, 16, 99, 100, 999999999]:
            nonce = info_nonce('r41', number)
            self.assertEqual(location_arguments('info', nonce, 0), ['info', nonce, '0'])
        self.assertNotEqual(info_nonce('r41', 16), info_nonce('r41', 17))
        self.assertEqual(location_arguments('watch', 'r41_principal_live', 300000),
                         ['watch', 'r41_principal_live', '300000'])

    def test_bad_generated_or_manual_arguments_fail_before_device_submission(self):
        for args in [('info', 'r40_provider-absent-before', 0), ('info', 'n', 1),
                     ('watch', 'n', 999), ('watch', 'n', 300001), ('watch', 'n', True),
                     ('info', 'n\n', 0), ('watch', None, 1000), ('gps', 'n', 0)]:
            with self.assertRaises(ValueError): location_arguments(*args)
        for args in [('r41-bad', 1), ('r41', 0), ('r41', True), ('r41', 1000000000), (None, 1)]:
            with self.assertRaises(ValueError): info_nonce(*args)


if __name__ == '__main__':
    unittest.main()
