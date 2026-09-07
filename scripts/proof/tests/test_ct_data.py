# SPDX-License-Identifier: Apache-2.0
"""Synthetic CT metadata tests; RSA is mocked, NOT cryptographic/runtime proof.

The byte fixtures encode real FlatBuffer root/vtable/scalar layouts, not log
entries or signed public snapshots. No network, credentials or real signing are used.
"""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
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


def ctfb_metadata(major=90, minor=5, timestamp=2_000_000_000_000):
    """Hand-built binary fixture; None omits a scalar (schema default zero).

    Root at 20, vtable at 8 (10 bytes), object size 28. The int64 fields sit
    at absolute offsets 24, 32, 40. Later root fields/log entries are omitted.
    Layout constants are independent of the reader; this is not flatc output.
    """
    data = bytearray.fromhex('''
        14 00 00 00 43 54 46 42
        0a 00 1c 00 04 00 0c 00 14 00 00 00
        0c 00 00 00
    ''') + bytearray(24)
    for slot, value in enumerate((major, minor, timestamp)):
        if value is None:
            struct.pack_into('<H', data, 12 + 2 * slot, 0)
        else:
            struct.pack_into('<q', data, 24 + 8 * slot, value)
    return bytes(data)


class FlatbufferMetadataTests(unittest.TestCase):
    def test_pinned_r1_schema_contract(self):
        schema = (Path(__file__).parent/'fixtures/aosp17-ct-log-store.fbs').read_bytes()
        self.assertEqual(hashlib.sha256(schema).hexdigest(),
                         'd184e388279da76825bd50fdd66b826e3ab7d16ff9b333b07033385240e30ab3')
        self.assertIn(b'file_identifier "CTFB";', schema)
        self.assertIn(b'table LogList {\n  version_major:long;\n  version_minor:long;\n  timestamp:long;', schema)

    def test_metadata_layout_and_signed_int64_values(self):
        for values in ((90, 5, 1_788_615_428_000),
                       (-(1 << 63), (1 << 63) - 1, -1)):
            with self.subTest(values=values):
                self.assertEqual(stage.read_v3_metadata(ctfb_metadata(*values)), values)

    def test_reordered_fields_and_vtable_after_root(self):
        # A shared vtable may follow its table (negative signed back-offset).
        # This also changes the root location, object size and scalar order.
        data = bytearray(64)
        struct.pack_into('<I4s', data, 0, 16, b'CTFB')
        struct.pack_into('<i', data, 16, -32)
        struct.pack_into('<qqq', data, 24, 1_788_615_428_000, 5, 90)
        struct.pack_into('<5H', data, 48, 10, 32, 24, 16, 8)
        self.assertEqual(stage.read_v3_metadata(data), (90, 5, 1_788_615_428_000))

    def test_default_scalars_and_short_vtables(self):
        self.assertEqual(stage.read_v3_metadata(ctfb_metadata(minor=None)),
                         (90, 0, 2_000_000_000_000))
        self.assertEqual(stage.read_v3_metadata(ctfb_metadata(None, None, None)), (0, 0, 0))
        for size, expected in ((4, (0, 0, 0)), (6, (90, 0, 0)), (8, (90, 5, 0))):
            data = bytearray(ctfb_metadata())
            struct.pack_into('<H', data, 8, size)
            with self.subTest(vtable_size=size):
                self.assertEqual(stage.read_v3_metadata(data), expected)
        # Minimal empty root: vtable at 8, root at 12, both four bytes long.
        empty = bytes.fromhex('0c000000 43544642 04000400 04000000')
        self.assertEqual(stage.read_v3_metadata(empty), (0, 0, 0))

    def test_every_truncation_and_oversized_buffer_rejected(self):
        data = ctfb_metadata()
        for length in range(len(data)):
            with self.subTest(length=length), self.assertRaises(ValueError):
                stage.read_v3_metadata(data[:length])
        with self.assertRaises(ValueError):
            stage.read_v3_metadata(data + b'\0' * (stage.MAX_FILE + 1 - len(data)))

    def test_identifier_and_size_prefixed_buffer_rejected(self):
        data = ctfb_metadata()
        for identifier in (b'ctfb', b'CTF\0', b'NOPE', b'\0' * 4):
            with self.subTest(identifier=identifier), self.assertRaisesRegex(ValueError, 'identifier'):
                stage.read_v3_metadata(data[:4] + identifier + data[8:])
        with self.assertRaises(ValueError):
            stage.read_v3_metadata(struct.pack('<I', len(data)) + data)

    def test_adversarial_root_vtable_object_and_field_bounds(self):
        changes = [
            ('null root', '<I', 0, 0),
            ('root in header', '<I', 0, 4),
            ('unaligned root', '<I', 0, 21),
            ('root at EOF', '<I', 0, 48),
            ('huge root', '<I', 0, 0xffffffff),
            ('zero vtable offset', '<i', 20, 0),
            ('vtable in header', '<i', 20, 16),
            ('unaligned vtable', '<i', 20, 11),
            ('vtable at EOF', '<i', 20, -28),
            ('vtable far before root', '<i', 20, (1 << 31) - 1),
            ('vtable far after root', '<i', 20, -(1 << 31)),
            ('short vtable', '<H', 8, 2),
            ('odd vtable size', '<H', 8, 5),
            ('overlapping vtable', '<H', 8, 14),
            ('oversized vtable', '<H', 8, 65534),
            ('short object', '<H', 10, 3),
            ('field past object but inside file', '<H', 10, 24),
            ('truncated int64 in object', '<H', 10, 27),
            ('object past file', '<H', 10, 29),
            ('huge object', '<H', 10, 65535),
            ('field in table header', '<H', 12, 2),
            ('unaligned int64', '<H', 12, 8),
            ('overlapping metadata fields', '<H', 12, 12),
            ('field at object end', '<H', 16, 28),
            ('huge field offset', '<H', 16, 65528),
        ]
        for label, kind, position, value in changes:
            data = bytearray(ctfb_metadata())
            struct.pack_into(kind, data, position, value)
            with self.subTest(case=label), self.assertRaises(ValueError):
                stage.read_v3_metadata(data)


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
                 'v2/log_list.json': json.dumps({'version':'89.30','log_list_timestamp':self.now}).encode(),
                 'v2/log_list.sig': base64.b64encode(b'public-test-signature'),
                 'v3/log_list.ctfb': ctfb_metadata(timestamp=self.now),
                 'v3/log_list.sig': base64.b64encode(b'public-test-signature')}
        for name, content in files.items():
            path = self.source/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

    def tearDown(self):
        self.tmp.cleanup()

    def verify(self):
        return stage.verify(self.source, self.allowed, self.now)

    def write_v2(self, timestamp, version='89.30'):
        (self.source/'v2/log_list.json').write_text(json.dumps(
            {'version': version, 'log_list_timestamp': timestamp}))

    def write_v3(self, timestamp, major=90, minor=5):
        (self.source/'v3/log_list.ctfb').write_bytes(ctfb_metadata(major, minor, timestamp))

    def write_manifest(self, manifest):
        (self.source/'manifest.json').write_text(json.dumps(manifest))

    def load_assets(self, now=None):
        with mock.patch.object(server.time, 'time', return_value=(self.now if now is None else now)/1000):
            return server.load_ct_assets(self.source)

    @mock.patch.object(stage.subprocess, 'run')
    def test_both_formats_verified_before_manifest(self, run):
        seen = []
        def accept_signature(command, **kwargs):
            # Capture bytes before the temporary files disappear. This checks
            # verifier invocation/order, NOT the validity of these fake keys/signatures.
            self.assertEqual(command[:4], ['openssl', 'dgst', '-sha256', '-verify'])
            self.assertEqual(command[5], '-signature')
            seen.append((Path(command[7]).read_bytes(), Path(command[6]).read_bytes()))
            return subprocess.CompletedProcess(command, 0)
        run.side_effect = accept_signature
        files, manifest = self.verify()
        self.assertEqual(run.call_count, 2)
        self.assertEqual(seen, [(files['v2/log_list.json'], b'public-test-signature'),
                                (files['v3/log_list.ctfb'], b'public-test-signature')])
        self.assertEqual(set(files), set(stage.FILES))
        self.assertEqual(manifest['files'], {name: hashlib.sha256(data).hexdigest()
                                            for name, data in files.items()})
        self.assertEqual(manifest['schema'], 1)
        self.assertEqual(manifest['allowed_keys_sha256'], hashlib.sha256(self.allowed.read_bytes()).hexdigest())
        self.assertEqual(manifest['verified_at_ms'], self.now)
        self.assertEqual(manifest['version'], '89.30')
        self.assertEqual(manifest['log_list_timestamp_ms'], self.now)
        self.assertEqual(manifest['formats'], {
            name: {'version': version, 'log_list_timestamp_ms': self.now,
                   'valid_until_ms': self.now + stage.MAX_AGE_MS}
            for name, version in (('v2', '89.30'), ('v3', '90.5'))})
        self.assertEqual(manifest['valid_until_ms'], self.now + stage.MAX_AGE_MS)
        self.assertFalse(manifest['network_access_during_verification'])

    @mock.patch.object(stage.subprocess, 'run')
    def test_unknown_public_key_rejected_before_verifier(self, run):
        (self.source/'log_list.pub').write_bytes(base64.b64encode(b'other'))
        with self.assertRaises(ValueError):
            self.verify()
        run.assert_not_called()

    @mock.patch.object(stage.subprocess, 'run')
    def test_invalid_signatures_rejected_before_metadata(self, run):
        (self.source/'v2/log_list.json').write_bytes(b'not json')
        (self.source/'v3/log_list.ctfb').write_bytes(b'not a flatbuffer')
        for codes, name in (((1,), 'v2'), ((0, 1), 'v3')):
            run.reset_mock()
            run.side_effect = [subprocess.CompletedProcess([], code) for code in codes]
            with self.subTest(format=name), self.assertRaisesRegex(ValueError, name + ' signature'):
                self.verify()
            self.assertEqual(run.call_count, len(codes))

    @mock.patch.object(stage.subprocess, 'run')
    def test_stale_future_and_noninteger_v2_timestamps_rejected(self, run):
        run.return_value.returncode = 0
        for value in (self.now+1, self.now-stage.MAX_AGE_MS-1, 0, -1,
                      True, float(self.now), 'timestamp', None, 1 << 63):
            self.write_v2(value)
            with self.subTest(timestamp=value), self.assertRaisesRegex(ValueError, 'CT v2'):
                self.verify()

    @mock.patch.object(stage.subprocess, 'run')
    def test_stale_future_and_default_v3_timestamps_rejected_independently(self, run):
        run.return_value.returncode = 0
        for value in (self.now+1, self.now-stage.MAX_AGE_MS-1, 0, -1, None, (1 << 63) - 1):
            run.reset_mock()
            self.write_v3(value)  # v2 remains fresh throughout.
            with self.subTest(timestamp=value), self.assertRaisesRegex(ValueError, 'CT v3'):
                self.verify()
            self.assertEqual(run.call_count, 2)

    @mock.patch.object(stage.subprocess, 'run')
    def test_invalid_v2_versions_rejected(self, run):
        run.return_value.returncode = 0
        for value in (None, True, 90, 90.5, 'fixture', '', '90', '90.5.1',
                      '-1.5', '90.-1', '0.0', '90.5\n', '９０.５',
                      str(1 << 31)+'.0', '90.'+str(1 << 31),
                      str(1 << 63)+'.0', '90.'+str(1 << 63)):
            self.write_v2(self.now, value)
            with self.subTest(version=value), self.assertRaisesRegex(ValueError, 'CT v2 version'):
                self.verify()

    @mock.patch.object(stage.subprocess, 'run')
    def test_negative_default_and_consumer_overflow_v3_versions_rejected(self, run):
        run.return_value.returncode = 0
        for major, minor in ((-1, 5), (90, -1), (-(1 << 63), 5),
                             (90, -(1 << 63)), (0, 5), (None, 5),
                             (1 << 31, 5), (90, 1 << 31)):
            self.write_v3(self.now, major, minor)
            with self.subTest(major=major, minor=minor), self.assertRaisesRegex(ValueError, 'CT v3 version'):
                self.verify()

    @mock.patch.object(stage.subprocess, 'run')
    def test_zero_minor_default_and_consumer_version_limit_valid(self, run):
        run.return_value.returncode = 0
        for major, minor in ((1, None), ((1 << 31) - 1, (1 << 31) - 1)):
            version = f'{major}.{0 if minor is None else minor}'
            self.write_v2(self.now, version)
            self.write_v3(self.now, major, minor)
            _, manifest = self.verify()
            self.assertEqual(manifest['formats']['v2']['version'], version)
            self.assertEqual(manifest['formats']['v3']['version'], version)

    @mock.patch.object(stage.subprocess, 'run')
    def test_missing_or_nonobject_v2_metadata_rejected(self, run):
        run.return_value.returncode = 0
        for value in ([], None, {}, {'version': '89.30'}, {'log_list_timestamp': self.now}):
            (self.source/'v2/log_list.json').write_text(json.dumps(value))
            with self.subTest(metadata=value), self.assertRaisesRegex(ValueError, 'CT v2'):
                self.verify()

    @mock.patch.object(stage.subprocess, 'run')
    def test_malformed_v3_rejected_after_signatures(self, run):
        run.return_value.returncode = 0
        (self.source/'v3/log_list.ctfb').write_bytes(ctfb_metadata()[:-1])
        with self.assertRaisesRegex(ValueError, 'CT v3 FlatBuffer'):
            self.verify()
        self.assertEqual(run.call_count, 2)

    @mock.patch.object(stage.subprocess, 'run')
    def test_freshness_boundaries_are_inclusive_for_each_format(self, run):
        run.return_value.returncode = 0
        for v2_time in (self.now, self.now - stage.MAX_AGE_MS):
            for v3_time in (self.now, self.now - stage.MAX_AGE_MS):
                self.write_v2(v2_time)
                self.write_v3(v3_time)
                with self.subTest(v2=v2_time, v3=v3_time):
                    _, manifest = self.verify()
                    self.assertEqual(manifest['valid_until_ms'], min(v2_time, v3_time) + stage.MAX_AGE_MS)

    @mock.patch.object(stage.subprocess, 'run')
    def test_different_versions_and_timestamps_use_earliest_expiry(self, run):
        run.return_value.returncode = 0
        for v2_time, v3_time in ((self.now - 1000, self.now), (self.now, self.now - 1000)):
            self.write_v2(v2_time)
            self.write_v3(v3_time)
            with self.subTest(v2=v2_time, v3=v3_time):
                _, manifest = self.verify()
                self.assertEqual(manifest['version'], '89.30')
                self.assertEqual(manifest['log_list_timestamp_ms'], v2_time)
                self.assertEqual(manifest['formats']['v2'], {
                    'version': '89.30', 'log_list_timestamp_ms': v2_time,
                    'valid_until_ms': v2_time + stage.MAX_AGE_MS})
                self.assertEqual(manifest['formats']['v3'], {
                    'version': '90.5', 'log_list_timestamp_ms': v3_time,
                    'valid_until_ms': v3_time + stage.MAX_AGE_MS})
                expiry = min(v2_time, v3_time) + stage.MAX_AGE_MS
                self.assertEqual(manifest['valid_until_ms'], expiry)
                self.write_manifest(manifest)
                self.assertEqual(len(self.load_assets()), 5)
                self.assertEqual(len(self.load_assets(expiry)), 5)
                with self.assertRaisesRegex(ValueError, 'expired'):
                    self.load_assets(expiry + 1)

    @mock.patch.object(stage.subprocess, 'run')
    def test_stage_preserves_original_bytes_and_writes_extended_manifest(self, run):
        run.return_value.returncode = 0
        original = {name: (self.source/name).read_bytes() for name in stage.FILES}
        output = self.root/'staged'
        with mock.patch.object(stage.time, 'time', return_value=self.now/1000):
            manifest = stage.stage(self.source, self.allowed, output)
        self.assertEqual(json.loads((output/'manifest.json').read_text()), manifest)
        self.assertEqual(set(manifest['formats']), {'v2', 'v3'})
        for name, data in original.items():
            self.assertEqual((output/name).read_bytes(), data)
            self.assertEqual((self.source/name).read_bytes(), data)
        with mock.patch.object(stage.time, 'time', return_value=self.now/1000):
            with self.assertRaises(FileExistsError):
                stage.stage(self.source, self.allowed, output)

    @mock.patch.object(stage.subprocess, 'run')
    def test_missing_symlink_oversized_or_private_input_rejected(self, run):
        path = self.source/'log_list.pub'
        for contents in (b'', b'x'*(stage.MAX_FILE+1), b'-----BEGIN PRIVATE KEY-----'):
            path.write_bytes(contents)
            with self.assertRaises(ValueError):
                self.verify()
        path.unlink()
        with self.assertRaises(ValueError):
            self.verify()
        path.symlink_to(self.allowed)
        with self.assertRaises(ValueError):
            self.verify()
        run.assert_not_called()

    @mock.patch.object(stage.subprocess, 'run')
    def test_server_loads_only_hash_bound_fresh_whitelist(self, run):
        run.return_value.returncode = 0
        files, manifest = self.verify()
        self.write_manifest(manifest)
        assets = self.load_assets()
        self.assertEqual(len(assets), 5)
        for name, data in files.items():
            key = ('/certificate_transparency/'+name).encode()
            self.assertEqual(assets[key], data)
        (self.source/'v3/log_list.ctfb').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'digest'):
            self.load_assets()

    @mock.patch.object(stage.subprocess, 'run')
    def test_server_preserves_legacy_schema1_manifest_loading(self, run):
        run.return_value.returncode = 0
        _, manifest = self.verify()
        del manifest['formats']  # Old stager output; only v2 metadata was read.
        self.write_manifest(manifest)
        self.assertEqual(len(self.load_assets()), 5)
        with self.assertRaises(ValueError):
            self.load_assets(self.now + stage.MAX_AGE_MS + 1)
        with self.assertRaises(ValueError):
            self.load_assets(self.now - 1)
        manifest['valid_until_ms'] -= 1  # Original exact-lifetime check remains.
        self.write_manifest(manifest)
        with self.assertRaises(ValueError):
            self.load_assets()

    @mock.patch.object(stage.subprocess, 'run')
    def test_server_rejects_missing_or_malformed_format_records(self, run):
        run.return_value.returncode = 0
        _, manifest = self.verify()
        for value in (None, [], {}, {'v2': manifest['formats']['v2']},
                      {'v2': {}, 'v3': {}}, {'v2': None, 'v3': None},
                      {**manifest['formats'], 'v4': {}}):
            self.write_manifest({**manifest, 'formats': value})
            with self.subTest(formats=value), self.assertRaises(ValueError):
                self.load_assets()

    @mock.patch.object(stage.subprocess, 'run')
    def test_server_checks_each_format_time_and_expiry(self, run):
        run.return_value.returncode = 0
        _, manifest = self.verify()
        for name in ('v2', 'v3'):
            for timestamp in (self.now + 1, self.now - stage.MAX_AGE_MS - 1):
                bad = copy.deepcopy(manifest)
                bad['formats'][name]['log_list_timestamp_ms'] = timestamp
                bad['formats'][name]['valid_until_ms'] = timestamp + stage.MAX_AGE_MS
                bad['log_list_timestamp_ms'] = bad['formats']['v2']['log_list_timestamp_ms']
                bad['valid_until_ms'] = min(item['valid_until_ms'] for item in bad['formats'].values())
                self.write_manifest(bad)
                with self.subTest(format=name, timestamp=timestamp), self.assertRaisesRegex(ValueError, 'expired or future'):
                    self.load_assets()
            for field, value in (('log_list_timestamp_ms', True), ('log_list_timestamp_ms', 'bad'),
                                 ('valid_until_ms', None), ('valid_until_ms', self.now + stage.MAX_AGE_MS - 1),
                                 ('version', None), ('version', '')):
                bad = copy.deepcopy(manifest)
                bad['formats'][name][field] = value
                self.write_manifest(bad)
                with self.subTest(format=name, field=field, value=value), self.assertRaises(ValueError):
                    self.load_assets()

    @mock.patch.object(stage.subprocess, 'run')
    def test_server_checks_v2_aliases_and_minimum_overall_expiry(self, run):
        run.return_value.returncode = 0
        self.write_v3(self.now - 1000)
        _, manifest = self.verify()
        for field, value in (('version', '90.5'), ('log_list_timestamp_ms', self.now - 1000),
                             ('log_list_timestamp_ms', True), ('valid_until_ms', True),
                             ('valid_until_ms', self.now + stage.MAX_AGE_MS),
                             ('valid_until_ms', manifest['valid_until_ms'] - 1)):
            self.write_manifest({**manifest, field: value})
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, 'inconsistent'):
                self.load_assets()

    @mock.patch.object(stage.subprocess, 'run')
    def test_server_rejects_expired_unknown_or_oversized_manifest(self, run):
        run.return_value.returncode = 0
        _, manifest = self.verify()
        self.write_manifest(manifest)
        with self.assertRaises(ValueError):
            self.load_assets(self.now + stage.MAX_AGE_MS + 1)
        manifest['files']['../outside'] = '0'*64
        self.write_manifest(manifest)
        with self.assertRaises(ValueError):
            self.load_assets()
        (self.source/'manifest.json').write_bytes(b' ' * 16385)
        with self.assertRaises(ValueError):
            self.load_assets()

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
