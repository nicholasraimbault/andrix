# Private Phase 1 HTTP(S) probe fixture

`probe_server.py` is a standalone Python 3 standard-library **host** service for
an operator-controlled lab, not a general public web server or Android module.
It serves exact `GET /generate_204` over **both HTTP and HTTPS**, with empty 204
responses and no redirect. It changes no client/system trust. Android must keep
normal hostname, chain and certificate-validity verification enabled.

Example only; these are placeholders, not provisioning or launch authority:

```sh
python3 -B scripts/proof/probe_server.py \
  --bind 127.0.0.1 --http-port 8080 --https-port 8443 \
  --cert /operator-managed/fullchain.pem \
  --private-key /operator-managed/private.key
```

The defaults are loopback `127.0.0.1`, HTTP 8080 and HTTPS 8443. Bind accepts a
numeric IPv4/IPv6 address only (no DNS lookup or IPv6 scope IDs). Ports must be
1–65535 and distinct. IPv6 listeners are IPv6-only. An explicit private-fixture
or wildcard/external `--bind` is **operator deployment authority**, not automatic
exposure. No daemonization, privilege escalation or firewall/routing changes
are performed. Run under a suitably restricted host identity/supervisor.

Both certificate/fullchain and matching **unencrypted PEM private-key FILE
paths** are required. Keep keys outside Git, protected by host file permissions;
never pass key bytes or paste them into commands, source or logs. Stdin, password
arguments and interactive key-password prompts are unsupported. TLS setup
requires existing regular files and precedes listener creation. TLS is at least
1.2, offers only HTTP/1.1 via ALPN and does not request client certificates.
`CERT_NONE` here is server-side client-certificate policy, **not** disabled
Android server-certificate verification. There is no certificate issuance,
renewal, client-trust change or outbound connection; restart to load renewed
certificate files.

## Deliberate limits and lifecycle

- One active connection at a time across both listeners; pending listen backlog
  8 each (subject to the host kernel). A slow client can delay other probes:
  isolate/restrict fixture access, do not expose this as a public service.
- Five-second **total** connection deadline covers handshake, header reads and
  response write; trickle reads do not reset it. Headers including request line
  and terminators are capped at 8192 bytes and 64 fields.
- Strict HTTP/1.0 or HTTP/1.1 only; HTTP/1.1 needs one nonempty Host field.
  Only the exact path matches: no query, decoding or absolute/proxy URLs.
  Other paths/methods get empty 404/405; malformed/unsupported requests get
  empty 400/431 or close on EOF/timeout/TLS/socket error. Duplicate/folded
  headers, nonzero Content-Length, Transfer-Encoding, Expect and Upgrade are
  rejected. Every connection closes after one response, without processing a
  body or pipelined requests. A 204 has no Content-Length or body.
- No request/peer logging, persistence, arbitrary file serving, upload, proxy or workers.
  Stdout reports only bound listener endpoints after **both** are listening;
  these addresses are not hostname/certificate checks or Android readiness.
  Errors suppress exception text and credential paths. Startup failure closes
  all created listeners. SIGINT/SIGTERM stop cleanly and restore handlers;
  an active connection may take its remaining five-second deadline to close.
  Exit 0 means orderly stop, 1 setup/service failure, 2 invalid CLI/network args.

## Optional signed Certificate Transparency snapshot

The r1 Certificate Transparency updater also needs its signed public log-list
files. The Andrix endpoint adaptation preserves that client, its allowed signing
keys and signature verification, but points it at this controlled service.
`--ct-data-dir DIRECTORY` enables **HTTPS-only** responses for exactly five paths
under `/certificate_transparency/`: `log_list.pub`, `v2/log_list.json`,
`v2/log_list.sig`, `v3/log_list.ctfb` and `v3/log_list.sig`. There is no upstream
proxy or network fetch. HTTP, unknown paths, query strings and traversal do not
expose these files. The 204 endpoint remains unchanged.

Obtain the five public inputs separately from the recorded AOSP CT data source
`https://www.gstatic.com/android/certificate_transparency/`, preserving fetch
metadata. This is staged public data supply, never a relay of device requests.
Extract `res/raw/ct_public_keys.pem` from the exact target's
`ServiceConnectivityResources.apk`, then validate/stage outside Git:

```sh
python3 scripts/proof/stage_ct_data.py \
  --source-dir /operator-managed/ct-download \
  --allowed-keys /operator-managed/ct_public_keys.pem \
  --output-dir /operator-managed/ct-verified
```

The staging tool performs no network access. It requires the fetched signing
key to match the supplied target allowlist, verifies both signatures with
OpenSSL, checks the JSON log-list timestamp against the pinned 70-day freshness
policy, and creates an exact five-file SHA-256 manifest. The service validates
the manifest, digests, bounded sizes and freshness before binding; bytes are
loaded once, not re-read from arbitrary client paths. Restage/restart before
expiry. This is not Android CT parser/runtime proof, and does not alter Android
trust policy or re-sign upstream data. Do not substitute an arbitrary allowlist.
The snapshot and private certificate keys stay outside public source.

## Deployment and proof still owned by the primary/operator

The configured Android URLs use `probe.andrix.org` on ports **80 and 443**.
Arrange authorized fixture DNS/routing and direct port access/mapping, with
**no HTTP-to-HTTPS redirect**, plus restricted exposure and supervision. Present
the normal trusted certificate/full chain for that hostname; independently
check expiry, hostname, chain, correct time and normal-client HTTP(S) responses.
Printing a numeric HTTPS bind address is not a claim that its certificate
matches that IP. This tool does not check certificate hostname/expiry/trust.

DNS/NTP selection, image/RRO integration, real certificate/client checks,
egress capture before first boot, rental/launch and Android proof remain
separate operator work. Host tests or a listening/valid-certificate service
are **not P4, Android readiness or no-Google runtime proof**. See the existing
[network preparation map](../../docs/proof-network.md).

Credential-free host regression tests use in-memory sockets and mocked
TLS/signals/files only; they perform no network or existing-key access:

```sh
python3 -B -m unittest discover -s scripts/proof/tests -p test_probe_server.py
```

These verify response policy and lifecycle logic, not real TLS, OS signal/socket
behavior or reachability. An authorized deployment still needs those checks.
