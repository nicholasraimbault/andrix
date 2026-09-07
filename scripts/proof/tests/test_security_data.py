# SPDX-License-Identifier: Apache-2.0
"""Synthetic, public-shaped snapshots only; no network, existing keys or Android.

Run from repository root:
python3 -B -m unittest discover -s scripts/proof/tests -p test_security_data.py
"""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_probe_server import MemoryConnection, request

HERE = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


security, server = load("security_data"), load("probe_server")


def timestamp(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SecurityDataTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.fetched = datetime(2026, 9, 7, 1, 30, tzinfo=timezone.utc).timestamp()
        self.now = self.fetched + 3600
        self.expiry = self.fetched + security.MAX_AGE_SECONDS
        self.clock = self.stack.enter_context(mock.patch.object(security.time, "time", return_value=self.now))
        self.monotonic = self.stack.enter_context(mock.patch.object(security.time, "monotonic", return_value=100.0))
        for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname", "gethostbyaddr"):
            self.stack.enter_context(mock.patch.object(server.socket, name,
                                                      side_effect=AssertionError("unexpected network access")))
        self.stack.enter_context(mock.patch.object(server.ssl, "SSLContext",
                                                  side_effect=AssertionError("unexpected credential/TLS access")))
        # Shape/count from the task observation, NOT the real published entries.
        entries = {format(index, "x"): {"status": "REVOKED", "reason": "KEY_COMPROMISE"}
                   for index in range(1, 1743)}
        entries["1"] = {"status": "SUSPENDED", "reason": "SOFTWARE_FLAW",
                        "comment": "Synthetic fixture, not a revocation assertion", "expires": "2020-01-01"}
        self.raw = {security.GSI_PATH: b"{}\n",
                    security.ATTESTATION_PATH: (json.dumps({"entries": entries}, indent=2) + "\n").encode(),
                    security.CATALOG_PATH: b' { "include" : [], "images": [] }\n'}
        self.inputs = {}
        for path, data in self.raw.items():
            self.inputs[path] = self.root / security.FILES[path]
            self.inputs[path].write_bytes(data)
        self.metadata = {"schema": 1, "files": {
            path: {"source_url": security.SOURCE_URLS[path], "fetched_at": timestamp(self.fetched),
                   "expires_at": timestamp(self.expiry)} for path in security.FILES}}
        self.provenance = self.root / "provenance.json"
        self.provenance.write_text(json.dumps(self.metadata))
        self.output = self.root / "bundle"

    def stage(self, **kwargs):
        args = dict(ack_source_observed_tls=True, ack_empty_catalog=True)
        args.update(kwargs)
        return security.stage(self.inputs[security.GSI_PATH], self.inputs[security.ATTESTATION_PATH],
                              self.inputs[security.CATALOG_PATH], self.provenance, self.output, **args)

    def write_manifest(self, manifest):
        (self.output / "manifest.json").write_text(json.dumps(manifest))

    def reply(self, assets, target, tls=True, ct=None, method=b"GET", handshake=None):
        connection = MemoryConnection([request(method=method, target=target)])
        context = mock.Mock(wrap_socket=mock.Mock(return_value=connection)) if tls else None
        connection.do_handshake.side_effect = handshake
        server.handle_connection(connection, context, ct, assets)
        return connection.sent

    def test_preserves_actual_shaped_empty_gsi_and_all_1742_attestation_entries(self):
        manifest = self.stage()
        bundle = server.load_security_assets(self.output)
        self.assertEqual(set(bundle.paths), {path.encode() for path in security.FILES})
        self.assertFalse(manifest["cryptographic_provenance_verified"])
        for path, data in self.raw.items():
            with self.subTest(path=path):
                self.assertEqual((self.output / security.FILES[path]).read_bytes(), data)
                self.assertEqual(self.inputs[path].read_bytes(), data)
                self.assertEqual(bundle.payload(path.encode()), data)
                record = manifest["files"][path]
                self.assertEqual(record["sha256"], hashlib.sha256(data).hexdigest())
                self.assertEqual(record["size"], len(data))
                self.assertEqual(record["source_url"], security.SOURCE_URLS[path])
                self.assertEqual(record["fetched_at"], "2026-09-07T01:30:00Z")
                self.assertEqual(record["expires_at"], "2026-09-08T01:30:00Z")
                self.assertEqual(record["provenance"], security.SOURCE_KINDS[path])
        self.assertEqual(manifest["files"][security.GSI_PATH]["size"], 3)
        entries = json.loads(bundle.payload(security.ATTESTATION_PATH.encode()))["entries"]
        self.assertEqual(len(entries), 1742)
        self.assertEqual(entries["1"]["expires"], "2020-01-01")  # Never filtered out.

    def test_explicit_acknowledgments_and_all_supplied_files_required(self):
        for name in ("ack_source_observed_tls", "ack_empty_catalog"):
            for value in (False, None, "true", 1):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    self.stage(**{name: value})
                self.assertFalse(self.output.exists())
        self.inputs[security.CATALOG_PATH].unlink()
        with self.assertRaises(OSError):
            self.stage()
        self.assertFalse(self.output.exists())

    def test_never_overwrites_an_existing_bundle(self):
        self.stage()
        manifest = (self.output / "manifest.json").read_bytes()
        with self.assertRaises(FileExistsError):
            self.stage()
        self.assertEqual((self.output / "manifest.json").read_bytes(), manifest)

    def test_strict_json_no_duplicate_keys_constants_floats_or_bad_encoding(self):
        for raw in (b'{"entries":{},"entries":{}}', b'{"x":{"status":1,"status":2}}',
                    b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}', b'{"x":1e999}',
                    b'{"x":1.0}', b'{"x":"\xff"}', b'\xef\xbb\xbf{}', b'{} trailing',
                    b'{"x":"\\ud800"}', b'[' * 2000 + b']' * 2000,
                    b'{"x":' + b'9' * 1000 + b'}'):
            with self.subTest(raw=raw[:70]), self.assertRaises(ValueError):
                security.strict_json(raw)

    def test_private_key_markers_including_json_escapes_are_rejected(self):
        for raw in (b'-----BEGIN PRIVATE KEY-----', b'{"x":"private key"}',
                    b'{"x":"PRIVATE\\u0020KEY"}', b'{"x":"RSA PRIVATE\\nKEY"}'):
            path = self.root / "not-public.json"
            path.write_bytes(raw)
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                security.strict_json(security.read_public(path))

    def test_gsi_schema_retains_nonempty_revocations(self):
        entry = {"public_key": "00fa2c6637c399afa893fe83d85f3569998707d5", "status": "REVOKED",
                 "reason": "Synthetic source-method fixture"}
        for value in (None, [], "{}", 0, False, {"entries": {}}, {"unexpected": {}},
                      {"a" * 40: {"status": "REVOKED", "reason": "KEY_COMPROMISE"}},
                      {"entries": [None]}, {"entries": [{**entry, "status": "GOOD"}]},
                      {"entries": [{**entry, "public_key": "not hex"}]},
                      {"entries": [{**entry, "reason": None}]}, {"entries": [entry, entry]}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                security.validate_payload(security.GSI_PATH, json.dumps(value).encode())
        for value in ({}, {"entries": []}, {"entries": [entry]},
                      {"entries": [{"public_key": "abcdef", "status": "REVOKED"}]}):
            security.validate_payload(security.GSI_PATH, json.dumps(value).encode())
        raw = (json.dumps({"entries": [entry]}, indent=2) + "\n").encode()
        self.inputs[security.GSI_PATH].write_bytes(raw)
        self.stage()
        self.assertEqual(security.load_assets(self.output).payload(security.GSI_PATH.encode()), raw)

    def test_catalog_requires_both_empty_arrays_and_no_extra_keys_or_urls(self):
        for value in ({}, [], {"include": []}, {"include": {}, "images": []},
                      {"include": [], "images": [], "extra": 1},
                      {"include": ["https://example.invalid/catalog.json"], "images": []},
                      {"include": [], "images": [{"uri": "https://example.invalid/image.zip"}]}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                security.validate_payload(security.CATALOG_PATH, json.dumps(value).encode())

    def test_attestation_root_and_entry_schema_is_strict(self):
        good = {"status": "REVOKED", "reason": "KEY_COMPROMISE"}
        roots = [None, [], {}, {"entries": None}, {"entries": []}, {"entries": {}},
                 {"entries": {"a": good}, "extra": []}]
        bad_entries = [None, [], True, {}, {"status": "REVOKED"}, {"reason": "KEY_COMPROMISE"},
                       {**good, "extra": 1}, {**good, "status": "GOOD"}, {**good, "status": "revoked"},
                       {**good, "status": []}, {**good, "reason": "unknown"}, {**good, "reason": 1},
                       {**good, "comment": False}, {**good, "comment": "x" * 2049},
                       {**good, "expires": True}, {**good, "expires": "2026-02-30"},
                       {**good, "expires": "2026-09-07T01:30:00Z"}]
        roots += [{"entries": {"a": entry}} for entry in bad_entries]
        for value in roots:
            with self.subTest(value=str(value)[:100]), self.assertRaises(ValueError):
                security.validate_payload(security.ATTESTATION_PATH, json.dumps(value).encode())
        for status in security.STATUSES:
            for reason in security.REASONS:
                security.validate_payload(security.ATTESTATION_PATH,
                                          json.dumps({"entries": {"f" * 40: {"status": status,
                                                                              "reason": reason}}}).encode())

    def test_invalid_serials_and_excessive_entry_count_are_rejected(self):
        entry = {"status": "REVOKED", "reason": "UNSPECIFIED"}
        for serial in ("", "0", "00", "01", "A", "deadBEEF", "-1", "+1", "0x12", "gg", "a ", "a" * 41):
            with self.subTest(serial=serial), self.assertRaises(ValueError):
                security.validate_payload(security.ATTESTATION_PATH,
                                          json.dumps({"entries": {serial: entry}}).encode())
        with mock.patch.object(security, "MAX_ENTRIES", 1), self.assertRaises(ValueError):
            security.validate_payload(security.ATTESTATION_PATH, self.raw[security.ATTESTATION_PATH])

    def test_future_stale_invalid_and_overlong_windows_fail_before_output_creation(self):
        good = self.metadata["files"][security.GSI_PATH].copy()
        cases = [("fetched_at", timestamp(self.now + 1)), ("expires_at", timestamp(self.now)),
                 ("expires_at", timestamp(self.fetched)),
                 ("expires_at", timestamp(self.expiry + 1))]
        cases += [(key, value) for key in ("fetched_at", "expires_at")
                  for value in (None, True, 123, "2026-09-07", "2026-09-07T01:30:00+00:00",
                                "2026-02-30T01:30:00Z", "2026-09-07T01:30:00.1Z")]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                self.metadata["files"][security.GSI_PATH] = {**good, key: value}
                self.provenance.write_text(json.dumps(self.metadata))
                with self.assertRaises(ValueError):
                    self.stage()
                self.assertFalse(self.output.exists())

    def test_provenance_is_required_exact_and_not_a_signature_assertion(self):
        for document in ({}, {**self.metadata, "schema": True}, {**self.metadata, "signed": True},
                         {"schema": 1, "files": {}},
                         {"schema": 1, "files": {**self.metadata["files"], "/extra": {}}}):
            self.provenance.write_text(json.dumps(document))
            with self.assertRaises(ValueError):
                self.stage()
        for path in security.FILES:
            for url in (security.SOURCE_URLS[path].replace("https:", "http:"), "https://example.invalid/"):
                document = json.loads(json.dumps(self.metadata))
                document["files"][path]["source_url"] = url
                self.provenance.write_text(json.dumps(document))
                with self.assertRaises(ValueError):
                    self.stage()
        self.assertFalse(self.output.exists())

    def test_digest_size_paths_and_manifest_claims_are_validated_at_load(self):
        manifest = self.stage()
        for field, value in (("sha256", "0" * 64), ("sha256", "not-a-digest"), ("size", 4), ("size", True),
                             ("provenance", "signed"), ("source_url", "http://example.invalid/"),
                             ("expires_at", timestamp(self.expiry + 1))):
            changed = json.loads(json.dumps(manifest))
            changed["files"][security.GSI_PATH][field] = value
            self.write_manifest(changed)
            with self.subTest(field=field), self.assertRaises(ValueError):
                security.load_assets(self.output)
        for field, value in (("schema", True), ("source_observed_tls_acknowledged", False),
                             ("empty_catalog_acknowledged", False), ("cryptographic_provenance_verified", True)):
            self.write_manifest({**manifest, field: value})
            with self.assertRaises(ValueError):
                security.load_assets(self.output)
        for bad in ("/security/../outside", "/manifest.json", "https://example.invalid/data"):
            changed = json.loads(json.dumps(manifest))
            changed["files"][bad] = changed["files"].pop(security.GSI_PATH)
            self.write_manifest(changed)
            with self.assertRaises(ValueError):
                security.load_assets(self.output)
        self.write_manifest(manifest)
        (self.output / "gsi-keyblacklist.json").write_bytes(b"{} ")  # Same size, different raw digest.
        with self.assertRaisesRegex(ValueError, "digest"):
            security.load_assets(self.output)

    def test_manifest_digest_cannot_bless_an_invalid_payload_schema(self):
        manifest = self.stage()
        raw = b'{"include":[],"images":[],"ignored":"must not be stripped"}'
        (self.output / "catalog.json").write_bytes(raw)
        manifest["files"][security.CATALOG_PATH].update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        self.write_manifest(manifest)
        with self.assertRaises(ValueError):
            security.load_assets(self.output)

    def test_regular_nonsymlink_bounded_inputs_and_bundle_paths(self):
        bad = self.root / "bad"
        for raw in (b"", b" " * (security.MAX_FILE_BYTES + 1)):
            bad.write_bytes(raw)
            with self.assertRaises(ValueError):
                security.read_public(bad)
        bad.unlink()
        os.mkfifo(bad)
        with self.assertRaises(ValueError):
            security.read_public(bad)  # O_NONBLOCK: must not hang on a FIFO.
        bad.unlink()
        bad.symlink_to(self.inputs[security.GSI_PATH])
        with self.assertRaises((ValueError, OSError)):
            security.read_public(bad)
        parent_link = self.root / "linked-parent"
        parent_link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            security.read_public(parent_link / "gsi-keyblacklist.json")
        with self.assertRaises(ValueError):
            security.read_public("-")
        with self.assertRaises((OSError, ValueError)):
            security.read_public(self.root)
        self.stage()
        with self.assertRaises(OSError):
            security.load_assets(parent_link / "bundle")
        path = self.output / "gsi-keyblacklist.json"
        path.unlink()
        path.symlink_to(self.inputs[security.GSI_PATH])
        with self.assertRaises((ValueError, OSError)):
            security.load_assets(self.output)

    def test_manifest_is_bounded_strict_json_and_nonsymlink(self):
        self.stage()
        path = self.output / "manifest.json"
        for raw in (b" " * (security.MAX_METADATA_BYTES + 1), b'{"schema":1,"schema":1}', b'{"schema":NaN}'):
            path.write_bytes(raw)
            with self.assertRaises(ValueError):
                security.load_assets(self.output)
        path.unlink()
        path.symlink_to(self.provenance)
        with self.assertRaises((ValueError, OSError)):
            security.load_assets(self.output)

    def test_load_rejects_expired_and_future_snapshots(self):
        self.stage()
        for now in (self.fetched - 1, self.expiry, self.expiry + 1):
            self.clock.return_value = now
            with self.subTest(now=now), self.assertRaises(ValueError):
                security.load_assets(self.output)

    def test_each_path_has_its_own_shorter_window_and_no_implicit_refresh(self):
        self.metadata["files"][security.GSI_PATH]["expires_at"] = timestamp(self.now + 1)
        self.metadata["files"][security.ATTESTATION_PATH]["fetched_at"] = timestamp(self.fetched + 60)
        self.provenance.write_text(json.dumps(self.metadata))
        self.stage()
        bundle = security.load_assets(self.output)
        self.clock.return_value = self.now + 1
        with self.assertRaises(ValueError):
            bundle.payload(security.GSI_PATH.encode())
        self.assertEqual(bundle.payload(security.ATTESTATION_PATH.encode()), self.raw[security.ATTESTATION_PATH])
        # Restaging/restarting must be explicit; file changes do not refresh in-memory data.
        (self.output / "attestation-status.json").write_bytes(b"not JSON")
        self.assertEqual(bundle.payload(security.ATTESTATION_PATH.encode()), self.raw[security.ATTESTATION_PATH])

    def test_rollback_cannot_extend_deadline_or_revive_observed_expired_data(self):
        self.stage()
        bundle = security.load_assets(self.output)
        self.clock.return_value = self.expiry
        with self.assertRaises(ValueError):
            bundle.payload(security.GSI_PATH.encode())
        self.clock.return_value = self.now
        with self.assertRaises(ValueError):
            bundle.payload(security.GSI_PATH.encode())
        self.monotonic.return_value = 100.0 + self.expiry - self.now
        with self.assertRaises(ValueError):
            bundle.payload(security.ATTESTATION_PATH.encode())
        self.monotonic.return_value = 100.0
        self.clock.return_value = self.fetched - 1
        with self.assertRaises(ValueError):
            bundle.payload(security.CATALOG_PATH.encode())

    def test_only_three_exact_paths_on_https_with_unchanged_204_and_ct(self):
        self.stage()
        bundle = security.load_assets(self.output)
        ct = {b"/certificate_transparency/v2/log_list.json": b"unchanged signed CT fixture"}
        (self.output / "unlisted.json").write_bytes(b"not served")
        for path, data in self.raw.items():
            with self.subTest(path=path):
                self.assertEqual(self.reply(bundle, path.encode()), [server.response_bytes(200, data)])
                self.assertEqual(self.reply(bundle, path.encode(), tls=False), [server.response_bytes(404)])
                self.assertEqual(self.reply(None, path.encode()), [server.response_bytes(404)])
                self.assertEqual(self.reply(bundle, path.encode(), method=b"HEAD"), [server.response_bytes(405)])
                for bad in (path + "?x=1", path + "#fragment", path + "/", "/" + path,
                            "https://probe.andrix.org" + path, path.replace("/", "/../", 1)):
                    self.assertEqual(self.reply(bundle, bad.encode()), [server.response_bytes(404)])
        for bad in (b"/security/%67si-keyblacklist.json", b"/manifest.json", b"/unlisted.json", b"/catalog.json"):
            self.assertEqual(self.reply(bundle, bad), [server.response_bytes(404)])
        for tls in (True, False):
            self.assertEqual(self.reply(bundle, b"/generate_204", tls, ct), [server.response_bytes(204)])
            for path, data in ct.items():
                expected = server.response_bytes(200, data) if tls else server.response_bytes(404)
                self.assertEqual(self.reply(bundle, path, tls, ct), [expected])

    def test_no_stale_200_even_if_expiry_occurs_during_handshake(self):
        self.stage()
        bundle = security.load_assets(self.output)

        def expire():
            self.clock.return_value = self.expiry

        first = True
        for path in security.FILES:
            reply = self.reply(bundle, path.encode(), handshake=expire if first else None)
            first = False
            self.assertEqual(reply, [server.response_bytes(503)])
            self.assertTrue(reply[0].endswith(b"\r\n\r\n"))
            self.assertIn(b"Cache-Control: no-store\r\n", reply[0])
            self.assertEqual(self.reply(bundle, path.encode(), tls=False), [server.response_bytes(404)])
        self.assertEqual(self.reply(bundle, b"/generate_204"), [server.response_bytes(204)])
        ct = {b"/certificate_transparency/log_list.pub": b"unchanged-public-key-fixture"}
        self.assertEqual(self.reply(bundle, next(iter(ct)), ct=ct), [server.response_bytes(200, next(iter(ct.values())))])

    def test_expiry_is_checked_after_header_reads_not_just_at_connection_start(self):
        self.stage()
        bundle = security.load_assets(self.output)
        connection = MemoryConnection([request(target=security.GSI_PATH.encode())])
        context = mock.Mock(wrap_socket=mock.Mock(return_value=connection))
        original_recv = connection.recv

        def receive(size):
            data = original_recv(size)
            self.clock.return_value = self.expiry
            return data

        connection.recv = receive
        server.handle_connection(connection, context, security_assets=bundle)
        self.assertEqual(connection.sent, [server.response_bytes(503)])

    def test_invalid_host_clock_refuses_startup_and_never_returns_a_security_200(self):
        self.stage()
        for value in (float("nan"), float("inf"), None, True):
            self.clock.return_value = self.now
            bundle = security.load_assets(self.output)
            self.clock.return_value = value
            with self.subTest(clock=value), self.assertRaises(ValueError):
                security.load_assets(self.output)
            self.assertEqual(self.reply(bundle, security.GSI_PATH.encode()), [server.response_bytes(503)])

    def test_tls_failure_never_sends_security_data_or_falls_back_to_http(self):
        self.stage()
        bundle = security.load_assets(self.output)
        # A failure-path double, NOT real hostname/trust validation evidence.
        error = server.ssl.SSLCertVerificationError("synthetic wrong-host rejection")
        self.assertEqual(self.reply(bundle, security.GSI_PATH.encode(), handshake=error), [])

    def test_cli_requires_explicit_acknowledgments_and_redacts_arguments(self):
        args = ["--gsi-keyblacklist", str(self.inputs[security.GSI_PATH]),
                "--attestation-status", str(self.inputs[security.ATTESTATION_PATH]),
                "--catalog", str(self.inputs[security.CATALOG_PATH]), "--provenance", str(self.provenance),
                "--output-dir", str(self.output), "--ack-source-observed-tls", "--ack-empty-catalog"]
        for bad in (args[:-1], args + ["--unknown", "accidental-sensitive-text"]):
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err), self.assertRaises(SystemExit) as caught:
                security.main(bad)
            self.assertEqual(caught.exception.code, 2)
            self.assertNotIn("accidental-sensitive-text", err.getvalue())
            self.assertFalse(self.output.exists())
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(security.main(args), 0)
            self.assertEqual(security.main(args), 1)  # No overwrite, no path/exception text.
        self.assertIn("not signed", out.getvalue())
        self.assertNotIn(str(self.root), out.getvalue() + err.getvalue())


if __name__ == "__main__":
    unittest.main()
