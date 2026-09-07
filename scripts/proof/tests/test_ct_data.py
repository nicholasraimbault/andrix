# SPDX-License-Identifier: Apache-2.0
"""Synthetic public CT data tests; no network, existing keys or real signing."""
import base64
from contextlib import redirect_stdout
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parents[1]

def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE/(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

stage, server = load('stage_ct_data'), load('probe_server')


class CtDataTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.source = self.root/'source'
        self.source.mkdir()
        self.now = 2_000_000_000_000
        self.key = base64.b64encode(b'synthetic-public-key-not-a-credential')
        self.allowed = self.root/'allowed.pem'
        self.allowed.write_bytes(b'-----BEGIN PUBLIC KEY-----\n'+self.key+b'\n-----END PUBLIC KEY-----\n')
        files = {'log_list.pub': self.key,
                 'v2/log_list.json': json.dumps({'version':'fixture','log_list_timestamp':self.now}).encode(),
                 'v2/log_list.sig': base64.b64encode(b'public-test-signature'),
                 'v3/log_list.ctfb': b'synthetic-flatbuffer-fixture',
                 'v3/log_list.sig': base64.b64encode(b'public-test-signature')}
        for name, content in files.items():
            path = self.source/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

    def tearDown(self):
        self.tmp.cleanup()

    def verify(self):
        return stage.verify(self.source, self.allowed, self.now)

    @mock.patch.object(stage.subprocess, 'run')
    def test_both_formats_verified_before_manifest(self, run):
        run.return_value.returncode = 0
        files, manifest = self.verify()
        self.assertEqual(run.call_count, 2)
        for call in run.call_args_list:
            self.assertEqual(call.args[0][:4], ['openssl','dgst','-sha256','-verify'])
        self.assertEqual(set(files), set(stage.FILES))
        self.assertEqual(manifest['valid_until_ms'], self.now + stage.MAX_AGE_MS)
        self.assertFalse(manifest['network_access_during_verification'])

    @mock.patch.object(stage.subprocess, 'run')
    def test_unknown_public_key_rejected_before_verifier(self, run):
        (self.source/'log_list.pub').write_bytes(base64.b64encode(b'other'))
        with self.assertRaises(ValueError):self.verify()
        run.assert_not_called()

    @mock.patch.object(stage.subprocess, 'run')
    def test_invalid_signature_rejected(self, run):
        run.return_value.returncode = 1
        with self.assertRaisesRegex(ValueError, 'signature'):self.verify()

    @mock.patch.object(stage.subprocess, 'run')
    def test_stale_future_and_noninteger_timestamps_rejected(self, run):
        run.return_value.returncode = 0
        for value in (self.now+1, self.now-stage.MAX_AGE_MS-1, True, 'timestamp'):
            (self.source/'v2/log_list.json').write_text(json.dumps({'version':'fixture','log_list_timestamp':value}))
            with self.assertRaises(ValueError):self.verify()

    @mock.patch.object(stage.subprocess, 'run')
    def test_missing_symlink_oversized_or_private_input_rejected(self, run):
        run.return_value.returncode = 0
        path = self.source/'log_list.pub'
        for contents in (b'', b'x'*(stage.MAX_FILE+1), b'-----BEGIN PRIVATE KEY-----'):
            path.write_bytes(contents)
            with self.assertRaises(ValueError):self.verify()
        path.unlink();path.symlink_to(self.allowed)
        with self.assertRaises(ValueError):self.verify()

    @mock.patch.object(stage.subprocess, 'run')
    def test_server_loads_only_hash_bound_fresh_whitelist(self, run):
        run.return_value.returncode = 0
        files, manifest = self.verify()
        (self.source/'manifest.json').write_text(json.dumps(manifest))
        with mock.patch.object(server.time, 'time', return_value=self.now/1000):
            assets = server.load_ct_assets(self.source)
            self.assertEqual(len(assets), 5)
            for name, data in files.items():
                key = ('/certificate_transparency/'+name).encode()
                self.assertEqual(assets[key], data)
            (self.source/'v3/log_list.ctfb').write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError, 'digest'):server.load_ct_assets(self.source)

    @mock.patch.object(stage.subprocess, 'run')
    def test_server_rejects_expired_unknown_or_oversized_manifest(self, run):
        run.return_value.returncode = 0
        _, manifest = self.verify()
        path = self.source/'manifest.json'
        path.write_text(json.dumps(manifest))
        with mock.patch.object(server.time, 'time', return_value=(self.now+stage.MAX_AGE_MS+1)/1000):
            with self.assertRaises(ValueError):server.load_ct_assets(self.source)
        manifest['files']['../outside'] = '0'*64
        path.write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):server.load_ct_assets(self.source)
        path.write_bytes(b' ' * 16385)
        with self.assertRaises(ValueError):server.load_ct_assets(self.source)

    def test_only_whitelisted_exact_get_targets(self):
        path = b'/certificate_transparency/v2/log_list.json'
        def request(target):return b'GET '+target+b' HTTP/1.1\r\nHost: probe.andrix.org\r\n\r\n'
        self.assertEqual(server.request_status(request(path)),404)
        self.assertEqual(server.request_status(request(path),[path]),200)
        for bad in (path+b'?x=1', b'/certificate_transparency/../private', b'/unknown'):
            self.assertEqual(server.request_status(request(bad),[path]),404)
        response=server.response_bytes(200,b'public')
        self.assertIn(b'Content-Length: 6\r\n',response)
        self.assertTrue(response.endswith(b'\r\n\r\npublic'))


class CtEndpointInputsTests(unittest.TestCase):
    def test_public_prefix_is_the_only_ct_config_change(self):
        root = HERE.parents[1]
        directory = root/'patches/android-17.0.0_r1'
        series = json.loads((directory/'series.json').read_text())
        project = next(p for p in series['projects'] if p['path']=='packages/modules/Connectivity')
        name = 'networksecurity/service/src/com/android/server/net/ct/Config.java'
        record = next(f for f in project['files'] if f['path']==name)
        original = (Path(__file__).parent/'fixtures/aosp17-ct-config.java').read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(), record['base_sha256'])
        full_path = project['path']+'/'+name
        with tempfile.TemporaryDirectory() as directory_name:
            path = Path(directory_name)/full_path
            path.parent.mkdir(parents=True)
            path.write_bytes(original)
            for options in (['--check'], []):
                subprocess.run(['git', 'apply', *options, '--whitespace=error',
                    '--include='+full_path, str(directory/series['patch'])],
                    cwd=directory_name, check=True, capture_output=True)
            actual = path.read_bytes()
        expected = original.replace(
            b'https://www.gstatic.com/android/certificate_transparency/',
            b'https://ct.probe.andrix.org/certificate_transparency/')
        self.assertNotEqual(original, expected)
        self.assertEqual(actual, expected)
        self.assertEqual(hashlib.sha256(actual).hexdigest(), record['patched_sha256'])


if __name__ == '__main__':
    unittest.main()
