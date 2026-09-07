# Offline signed CT staging

`stage_ct_data.py` verifies and copies exactly five already-supplied public files:
`log_list.pub`, `v2/log_list.json`, `v2/log_list.sig`, `v3/log_list.ctfb` and
`v3/log_list.sig`. Supply the unchanged `ct_public_keys.pem` extracted from the
**exact target** `ServiceConnectivityResources.apk`:

```sh
python3 scripts/proof/stage_ct_data.py \
  --source-dir /operator-managed/ct-download \
  --allowed-keys /operator-managed/ct_public_keys.pem \
  --output-dir /operator-managed/ct-verified-new
```

The output directory must not exist. No download, private key, re-signing,
serialization of payloads or Android trust change occurs. Python uses only its
standard library; the existing `openssl dgst -sha256 -verify` invocation remains
required. Each input is bounded to 1 MiB. The signing key must match the supplied
Android allowlist, and **both original RSA signatures must pass before metadata
is read**. File contents are copied byte-for-byte and bound by SHA-256 in the
manifest.

## Independent metadata and freshness

v2 metadata comes from the JSON `version` and `log_list_timestamp` fields.
v3 uses the non-size-prefixed FlatBuffer metadata layout of the pinned AOSP
`android-17.0.0_r1` `external/conscrypt/platform/src/main/ct_log_store.fbs`
([pinned test copy](tests/fixtures/aosp17-ct-log-store.fbs), SHA-256
`d184e388279da76825bd50fdd66b826e3ab7d16ff9b333b07033385240e30ab3`):

| Root slot | Field | Wire type | Absent/default value |
| --- | --- | --- | --- |
| 0 | `version_major` | little-endian signed int64 | 0 |
| 1 | `version_minor` | little-endian signed int64 | 0 |
| 2 | `timestamp` | little-endian signed int64, Unix milliseconds | 0 |

The reader requires the exact `CTFB` file identifier at bytes 4–7. It follows
the root offset and signed vtable offset, checks root/vtable/object bounds and
alignment, and reads only these three scalar slots. A shared vtable may follow
the root; field order and root position are not hard-coded. Present metadata
fields must fit inside the declared object, be int64-aligned and not overlap.
Absent slots (short vtable or zero offset) use their schema default, not bytes
from padding or other fields.

Host metadata validity requires a positive version major and nonnegative minor
within signed-int32 range: the pinned Conscrypt v2 consumer uses `parseInt`, and
v3 uses `Math.toIntExact` despite its int64 wire fields. The timestamp must be a
positive signed-int64 value. An omitted minor is valid zero; an omitted major
or timestamp is rejected. v2 versions must be two
ASCII decimal components separated by a dot (at most 19 digits each); the
original v2 string is retained. v3's version is rendered as `major.minor`.
Each timestamp independently must be no later than verification time and no
older than the pinned Conscrypt 70-day policy; both boundaries are inclusive.
Different v2/v3 versions and timestamps are legitimate, not a mismatch to fix.

**This is bounded metadata extraction, not full FlatBuffer or CT log-entry
validation.** It does not traverse operators, logs, vectors, strings, keys or
states, and does not prove Android parsing, installation or policy enforcement.
Signature verification authenticates bytes; this host reader only adds the
metadata/freshness gate. Android retains its own verification and parsing.

## Manifest compatibility

The manifest remains `schema: 1` with the original five-file hashes, allowlist
hash, verification time, upstream and no-network fields. New manifests add:

```text
formats.v2 = {version, log_list_timestamp_ms, valid_until_ms}
formats.v3 = {version, log_list_timestamp_ms, valid_until_ms}
```

Each per-format expiry equals that format's timestamp plus 70 days. The legacy
top-level `version` and `log_list_timestamp_ms` are **v2 aliases only**, not a
claim that v3 shares them. Top-level `valid_until_ms` is the conservative minimum
of both per-format expiries, including when v3 is older than v2.

`probe_server.py` accepts these extended manifests and checks both timestamps,
per-format lifetimes, v2 aliases and the minimum overall expiry before loading
the hash-bound files. It still accepts old schema-1 manifests without `formats`
under their original v2 timestamp/expiry check. That compatibility does **not**
retroactively verify v3 metadata in old evidence. Keep old public fixtures and
manifests unchanged; reverify original files into a separate new staging
directory when new evidence is needed. Old server copies require updating to
load a bundle whose v3 expires before v2. As before, CT files are loaded once at
startup; restage/restart before the earliest expiry. This change adds no CT
per-request expiry enforcement or upstream refresh.

## Host regression and integration checks

```sh
python3 -m unittest discover -s scripts/proof/tests -p 'test_ct_data.py' -v
python3 -m unittest discover -s scripts/proof/tests -p 'test_probe_server.py' -v
python3 -m unittest discover -s scripts/proof/tests
```

The CT tests hand-build realistic binary root/vtable/scalar layouts, including
reordered fields, signed offsets, omitted defaults and malformed bounds. Their
public keys/signatures and OpenSSL successes are **mocked**: they check the
verification calls, ordering, metadata gates, byte preservation and server
compatibility, not cryptographic authenticity or Android behavior.

Before integration, compare the metadata slot/type/default contract against the
exact r1 schema and independently decode the original signed public v3 snapshot
with the AOSP-built `flatc`. Run the stager on the real five-file snapshot and
target allowlist without mocks, compare per-format metadata to that independent
decode and v2 JSON, and confirm all five output hashes remain unchanged. Keep
these new verification results separate from the preserved published manifest
and earlier runtime evidence.
