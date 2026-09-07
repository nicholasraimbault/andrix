# Bounded owned security-data fixture

`security_data.py` is an **offline Linux host stager**, not an Android module,
proxy, downloader, refresh daemon or signature verifier. It requires two explicit
raw public snapshots, an explicit owner catalog, explicit per-file provenance
metadata, and two acknowledgments. It never generates/filters revocation entries,
invents an image URL, reads signing keys or changes client security checks.

## Provenance and deliberately narrow scope

The source observation supplied for this work was an HTTPS fetch on
**2026-09-07 at 01:30 UTC**:

- `https://dl.google.com/developers/android/gsi/gsi-keyblacklist.json` was exactly
  `{}\n` (3 bytes). This is a genuinely empty published object, not missing data to
  be filled with invented entries.
- `https://android.googleapis.com/attestation/status` was 177,632 bytes with an
  `entries` object containing 1,742 records.
- Both responses had a current `Date` and `Cache-Control: max-age=86400`.
  Neither came with a detached data signature.

These are **source-observed public snapshots over TLS, NOT signed CT data**.
The operator must preserve and review the actual fetch evidence separately.
Acknowledgments, source URLs, timestamps and SHA-256 digests do not authenticate
that evidence or establish cryptographic provenance. The manifest explicitly
records `cryptographic_provenance_verified: false`. An operator who lies about a
fetch time or rewrites both data and manifest is outside this local integrity
check's protection. Never relabel old bytes with a new fetch time to extend life.

The staging profile deliberately supports only:

- A GSI root object equal to `{}` or containing an `entries` array, as consumed
  by the pinned `KeyRevocationList`. Nonempty entries retain `public_key`,
  `status: REVOKED` and optional string `reason`. Keys must be bounded hex and
  unique; malformed or unsupported statuses fail closed, never become an empty
  list. The primary reviewed this parser before adding nonempty-list support.
- A nonempty attestation root `{"entries": {...}}`, with no other root keys.
  Serials are positive, canonical lowercase hex, without leading zeroes, at most
  40 digits. Each entry requires `status` (`REVOKED` or `SUSPENDED`) and `reason`
  (`UNSPECIFIED`, `KEY_COMPROMISE`, `CA_COMPROMISE`, `SUPERSEDED`, `SOFTWARE_FLAW`).
  Only optional string `comment` (at most 2,048 characters) and calendar-date
  `expires` (`YYYY-MM-DD`) are also supported. Record expiry is not snapshot
  freshness: **no record is removed or turned into a positive verdict**.
- An owner-supplied catalog equal to `{"include":[],"images":[]}`, with an explicit
  acknowledgment of this **unreleased Andrix GSI experiment**. Includes and
  installable images are unsupported in this profile and cause failure, not
  filtering. There is no default catalog or silently fabricated response.

The primary compared the pinned `KeyRevocationList.java`,
`CertificateRevocationStatus.java` and `DSULoader.java` consumers and validated
both real source snapshots. This strict profile is not a claim of complete
future upstream schema coverage or Android execution.
If actual data has an unsupported field/shape, preserve the failure and review
the parser; do not strip fields or relax checks merely to make staging pass.

## Explicit inputs and staging

Every input is a nonempty regular nonsymlink file; symlink parent directories,
parent traversal, stdin, devices and FIFOs are refused. Data files are capped at
1 MiB each, provenance/manifest at 16 KiB, attestation at 10,000 entries, and JSON
nesting at eight levels. JSON must be UTF-8, without duplicate keys (at any
level), NaN/Infinity, floating-point numbers or invalid Unicode. Private-key text
markers, including JSON-escaped markers, are refused. Unsupported keys/types
fail closed. Validation does not reserialize the supplied data: all three
payloads, including whitespace and final newlines, are preserved byte for byte.

Prepare a provenance file with exactly this schema. **Example times are the
historical observation, not reusable fresh timestamps**; staging refuses them
once expired. Both timestamps for each file are mandatory, in UTC with seconds
and `Z`. Separate fetch times and shorter lifetimes are supported. Require
`fetched_at <= now < expires_at`, and `0 < expires_at - fetched_at <= 86400`.
The maximum is the observed publisher cache bound, not proof of authenticity or
permission to exceed a subsequently shorter publisher bound. The operator must
review `Date`, `Age`, cache headers and transport success during each explicit
source fetch, and choose an earlier expiry if the source evidence warrants it.

```json
{
  "schema": 1,
  "files": {
    "/security/gsi-keyblacklist.json": {
      "source_url": "https://dl.google.com/developers/android/gsi/gsi-keyblacklist.json",
      "fetched_at": "2026-09-07T01:30:00Z",
      "expires_at": "2026-09-08T01:30:00Z"
    },
    "/security/attestation-status.json": {
      "source_url": "https://android.googleapis.com/attestation/status",
      "fetched_at": "2026-09-07T01:30:00Z",
      "expires_at": "2026-09-08T01:30:00Z"
    },
    "/system-images/catalog.json": {
      "source_url": "https://probe.andrix.org/system-images/catalog.json",
      "fetched_at": "2026-09-07T01:30:00Z",
      "expires_at": "2026-09-08T01:30:00Z"
    }
  }
}
```

For the catalog, `source_url` names the intended **owned publication endpoint**,
and `fetched_at` records when the owner explicitly supplied the catalog. These
fields do not pretend it was downloaded from a deployed server. Its manifest
provenance classification is `owner-supplied-empty-experimental-catalog`, unlike
the two `operator-reported-public-snapshot-over-tls` classifications. Source URLs
are fixed, not arbitrary routing or upstream proxy configuration.

Example only, after the owner supplies all four public files outside Git:

```sh
python3 -B scripts/proof/security_data.py \
  --gsi-keyblacklist /operator-managed/source/gsi-keyblacklist.json \
  --attestation-status /operator-managed/source/attestation-status.json \
  --catalog /operator-managed/owner/catalog.json \
  --provenance /operator-managed/source/security-provenance.json \
  --ack-source-observed-tls --ack-empty-catalog \
  --output-dir /operator-managed/security-staged-new
```

The output's parent must already exist. The stager creates a **new** directory
(mode 0700), never overwrites a bundle, writes the three raw files (mode 0600),
and writes `manifest.json` last. Failed partial output is not loadable; inspect
it rather than silently replacing it. The manifest binds exactly three fixed
paths to SHA-256, size, source URL, fetched/expiry times and provenance kind.
No supplied file path is copied into the manifest. CLI failures suppress input
contents, argument text and exception paths. Exit codes: 0 staged, 1 validation/
filesystem failure, 2 invalid/missing CLI arguments. A staged bundle is not
Android proof or authorization to install an image.

## Serving and expiry

Pass `--security-data-dir /operator-managed/security-staged-new` to
[`probe_server.py`](probe_server.md). Keep `security_data.py` beside the service
when deploying a runtime copy. The optional loader rechecks the manifest schema,
acknowledgments, exact path set, sizes, digests, payload schemas and all freshness
windows **before binding**. It loads only the three fixed files, never the
manifest or arbitrary directory contents as response data.

Only exact HTTPS GETs to `/security/gsi-keyblacklist.json`,
`/security/attestation-status.json` and `/system-images/catalog.json` can succeed.
HTTP, query strings, encoded/traversal paths and absolute/proxy URLs do not expose
them. Success preserves raw bytes and uses `Cache-Control: no-store`.

Each response checks freshness after TLS/header reads, immediately before
response selection. Expiry (including the exact expiry instant), a clock earlier
than fetch time, or an invalid clock yields an empty **503**, never a stale 200,
empty-list success, redirect or upstream fallback. A monotonic deadline also
prevents wall-clock rollback from extending a loaded file's lifetime; an
observed invalid file remains unavailable until restart. Each file has its own
window. No request rereads disk or refreshes a timestamp. Fetch/update remains
an explicit operator action: stage a new bundle and restart before expiry.

`/generate_204`, the existing signed CT assets, TLS policy, hostname validation
expectations, request limits and connection deadlines remain unchanged. This
24-hour policy applies to these security/catalog files, not to CT's separate
signature/allowlist and freshness handling. Do not alter Android trust, CT
assets/keys, revocation checks or image signature verification.

## Verification still required

Credential-free synthetic tests cover empty and populated GSI lists, the
observed nonempty-attestation shape, byte preservation, strict schemas, unsafe
files, manifest/digest/freshness failures, exact HTTPS paths, expiry during a
connection, clock rollback, TLS failure closure, and unchanged 204/CT handling:

```sh
python3 -B -m unittest discover -s scripts/proof/tests -p test_security_data.py
python3 -B -m unittest discover -s scripts/proof/tests -p test_probe_server.py
python3 -B -m unittest discover -s scripts/proof/tests -p test_ct_data.py
```

The primary/operator must run these, compare the strict profile against the
pinned Java consumers and actual data, verify real HTTP/HTTPS bytes and normal
wrong-hostname rejection, and check post-expiry 503s in a real TLS session. Android
consumer behavior and capture-attributed no-Google qualification remain separate;
a host loader or TLS double does not prove them. No product/AOSP integration is
performed by these scripts.
