# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ce_epoch import valid_recovery


def point(generation,available,instance=17):
    return {'instance':instance,'generation':generation,'available':available}


class CeEpochObservationTests(unittest.TestCase):
    def test_grant_does_not_need_another_generation_increment(self):
        self.assertTrue(valid_recovery(point(5,True),point(6,False),point(6,True)))
        self.assertTrue(valid_recovery(point(5,True),point(6,False),point(7,True)))

    def test_old_epoch_or_platform_replacement_is_not_recovery(self):
        for restored in [point(5,True),point(6,False),point(6,True,18)]:
            self.assertFalse(valid_recovery(point(5,True),point(6,False),restored))
        self.assertFalse(valid_recovery(point(5,True),point(5,False),point(6,True)))
        self.assertFalse(valid_recovery(point(5,True),point(6,True),point(6,True)))

    def test_malformed_or_failed_epoch_is_not_a_positive(self):
        for change in [{'instance':True},{'generation':False},{'generation':2**63-1},
                       {'available':1},{'instance':0},{'generation':-1}]:
            current=dict(point(6,True),**change)
            self.assertFalse(valid_recovery(point(5,True),point(6,False),current))


if __name__=='__main__':unittest.main()
