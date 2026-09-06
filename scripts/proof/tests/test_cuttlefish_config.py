# SPDX-License-Identifier: Apache-2.0
"""Synthetic r1 configuration checks, not actual host/network qualification."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('cuttlefish_config', Path(__file__).resolve().parents[1]/'cuttlefish_config.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class CuttlefishConfigTests(unittest.TestCase):
    def setUp(self):
        self.config = {'vm_manager':'crosvm','enable_metrics':2,'instances':{'1':{
            'external_network_mode':'tap','enable_tap_devices':True,
            'guest_enforce_security':True,'target_arch':1,
            'ril_dns':'192.168.240.1','ril_ipaddr':'192.168.240.2',
            'ril_gateway':'192.168.240.1','ril_broadcast':'192.168.240.255','ril_prefixlen':24,
            'mobile_bridge_name':'cvd-mbr-1','mobile_tap_name':'cvd-mtap-1'}}}
        self.interfaces = [{'ifname':'cvd-mtap-1','addr_info':[{'family':'inet',
            'local':'192.168.240.1','prefixlen':24,'broadcast':'192.168.240.255'}]}]

    def check(self):return guard.verify(self.config,self.interfaces,'192.168.240.1')

    def test_valid_config_not_runtime_qualified(self):
        result = self.check()
        self.assertTrue(result['config_consistent'])
        self.assertFalse(result['runtime_qualified'])
        self.assertEqual(result['mobile_interfaces'],['cvd-mtap-1'])

    def test_defaults_and_inconsistent_network_are_rejected(self):
        original = copy.deepcopy(self.config['instances']['1'])
        cases = {'external_network_mode':'slirp','enable_tap_devices':False,
                 'guest_enforce_security':False,'target_arch':4,'ril_dns':'8.8.8.8',
                 'ril_ipaddr':'','ril_gateway':'192.168.241.1',
                 'ril_broadcast':'192.168.240.1','ril_prefixlen':255,'mobile_tap_name':''}
        for key,value in cases.items():
            with self.subTest(field=key):
                self.config['instances']['1'] = {**original,key:value}
                with self.assertRaises(ValueError):self.check()

    def test_missing_fields_fail_closed(self):
        original = copy.deepcopy(self.config['instances']['1'])
        for key in original:
            self.config['instances']['1'] = dict(original)
            del self.config['instances']['1'][key]
            with self.assertRaises(ValueError):self.check()

    def test_disabled_metrics_is_enum_not_boolean_or_unknown(self):
        for value in (True,False,0,1,'2',None):
            self.config['enable_metrics']=value
            with self.assertRaises(ValueError):self.check()

    def test_actual_interface_address_must_match(self):
        self.interfaces[0]['addr_info'][0]['broadcast']='192.168.240.1'
        with self.assertRaises(ValueError):self.check()
        self.interfaces=[]
        with self.assertRaises(ValueError):self.check()

    def test_private_fixture_dns_required(self):
        for address in ('8.8.8.8','8.8.4.4','1.1.1.1','127.0.0.1','0.0.0.0','192.0.2.1','dns.example'):
            with self.assertRaises(ValueError):guard.verify(self.config,self.interfaces,address)

    def test_only_one_instance_and_native_profile(self):
        self.config['instances']['2']=copy.deepcopy(self.config['instances']['1'])
        with self.assertRaises(ValueError):self.check()
        del self.config['instances']['2']
        self.config['vm_manager']='qemu_cli'
        with self.assertRaises(ValueError):self.check()

    def test_ambiguous_json_rejected(self):
        with self.assertRaises(ValueError):json.loads('{"enable_metrics":1,"enable_metrics":2}',object_pairs_hook=guard.unique_object)


if __name__ == '__main__':
    unittest.main()
