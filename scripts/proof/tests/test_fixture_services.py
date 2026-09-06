# SPDX-License-Identifier: Apache-2.0
"""Configuration rendering only; no services, DNS/time traffic or host changes."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('fixture_services', Path(__file__).resolve().parents[1]/'fixture_services.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class FixtureServiceConfigTests(unittest.TestCase):
    def settings(self):
        return dict(bind='192.168.240.1',clients=['192.168.240.0/24'],ntp_upstream='192.168.241.1',
                    certificate='/run/fixture/fullchain.pem',key='/run/fixture/private.key',
                    state='/run/fixture/state',dns_root_key='/run/fixture/root.key')

    def test_private_resolver_and_explicit_time_source(self):
        result=fixture.render(**self.settings())
        dns=result['unbound.conf'];ntp=result['chrony.conf']
        self.assertIn('interface: 192.168.240.1@53',dns)
        self.assertIn('interface: 192.168.240.1@853',dns)
        self.assertIn('access-control: 0.0.0.0/0 refuse',dns)
        self.assertIn('access-control: 192.168.240.0/24 allow',dns)
        self.assertIn('auto-trust-anchor-file:',dns)
        self.assertIn('local-zone: "probe.andrix.org." redirect',dns)
        self.assertNotIn('forward-addr:',dns)
        self.assertIn('server 192.168.241.1 iburst',ntp)
        self.assertIn('bindaddress 192.168.240.1',ntp)
        self.assertNotIn('local stratum',ntp)
        self.assertNotIn('makestep',ntp)
        self.assertNotIn('google',dns+ntp)

    def test_public_or_unspecified_exposure_rejected(self):
        for value in ('0.0.0.0','8.8.8.8','192.0.2.1','127.0.0.1','::'):
            args=self.settings();args['bind']=value
            with self.assertRaises(ValueError):fixture.render(**args)
        for clients in ([],['0.0.0.0/0'],['192.0.2.0/24']):
            args=self.settings();args['clients']=clients
            with self.assertRaises(ValueError):fixture.render(**args)

    def test_usable_explicit_ntp_input_required(self):
        for value in ('','0.0.0.0','224.0.0.1','8.8.8.8','8.8.4.4','time.google.com'):
            args=self.settings();args['ntp_upstream']=value
            with self.assertRaises(ValueError):fixture.render(**args)

    def test_paths_cannot_inject_config_or_escape(self):
        for key in ('certificate','key','state','dns_root_key'):
            for value in ('relative', '/run/../key', '/run/key\nserver evil', '/run/"key'):
                args=self.settings();args[key]=value
                with self.assertRaises(ValueError):fixture.render(**args)


if __name__=='__main__':unittest.main()
