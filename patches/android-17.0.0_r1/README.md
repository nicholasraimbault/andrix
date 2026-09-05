# Pinned network endpoint adaptation

These six-file changes are limited to network endpoints that have **no**
supported resource/configuration hook in the exact `android-17.0.0_r1` source.
They are not a substitute source distribution or an unrelated platform fork.
The official manifest/project HEADs remain at their pinned release commits;
`series.json` records each base commit and before/after file digest. The patch
and applied diff must accompany build provenance. A pristine manifest alone
no longer describes an image built with this adaptation.

## Changes and preserved behavior

- Native DnsResolver and NetworkStack Private DNS validation keep their random
  cache-bypassing nonce and DNS packet semantics, but query under
  `probe.andrix.org` instead of `metric.gstatic.com`. Native automatic/
  opportunistic DoT is included, not just NetworkMonitor's strict-mode check.
  TLS, certificate checking, validation outcomes, timeouts and UDP/DoT latency
  comparison are unchanged. The native test-server probe classifier follows
  the new suffix rather than silently failing to recognize validation traffic.
- Connectivity diagnostics keep ICMP checks to real gateways and supplied DNS,
  and UDP/DoT checks to configured resolvers. They no longer inject Google DNS
  addresses as extra targets; their nonce qname uses the owned domain too.
  Both `--diag` and high-priority diagnostic dumps can reach this code.
- Tethering continues to use upstream DNS whenever provided. If upstream DNS is
  absent, its fallback is empty instead of silently inventing Google resolvers.
  Pinned netd accepts an empty forwarder list and its `--no-resolv` dnsmasq
  instance clears prior dynamic forwarders. This is not an empty NTP list or
  a way to pretend a functioning resolver exists. The fixture must supply valid
  DNS; tethering without any upstream DNS cannot resolve names through that
  missing service. Tethering/IP forwarding and app/SELinux policy remain intact.

- Certificate Transparency keeps its enabled service, downloaded-key allowlist,
  RSA signature verification and log-list handling. Only its download prefix
  changes to `https://probe.andrix.org/certificate_transparency/`. The fixture
  serves a separately staged, signature-verified copy of the public data; it
  does not proxy device requests upstream. No CT checks, signing keys or trust
  anchors are disabled/replaced. See the [fixture documentation](../../scripts/proof/probe_server.md).

The owned DNS zone/fixture must answer the nonce names appropriately, including
positive records when testing strict Private DNS. Replacing a qname is not
endpoint deployment, a successful encrypted-DNS check or runtime compliance.
No Google-address firewall/DNS blackhole, TLS-disable flag, privileged proxy,
permission relaxation, foreign libc or kernel substitution is introduced.

Google DoH upgrade table entries are not unconditional destinations: they match
explicitly selected DNS IPs/hostnames. A controlled fixture must not supply
Google DNS. Connect-only route/MTU address literals are separately reviewed,
not blindly treated as sent packets or modified to game a string scan.

## Explicit application

Check first (read-only):

```sh
python3 scripts/proof/aosp_patches.py --aosp-root "$AOSP_ROOT"
```

Apply only to the reviewed tree, recording a **new** evidence directory outside
source. This writes the declared working-tree files, not project HEADs/indexes:

```sh
python3 scripts/proof/aosp_patches.py --aosp-root "$AOSP_ROOT" \
  --apply --evidence-dir "$ANDRIX_EVIDENCE/endpoint-patch-application"
```

The helper checks manifest/project revisions, exact source/patch digests,
contained paths, no staged/untracked/unrelated changes, and `git apply --check`
before one application transaction. Known applied state is idempotent; partial
or unexpected state fails closed. Do not use `--reject`, force-sync, replace
source revisions, or restore over unknown edits to make it pass. Preserve the
first failure and inspect any failed post-application state.

Build and test the adapted modules/image, re-run the packaged-artifact oracle,
and record actual image contents. Static patch tests do not prove Android
execution, TLS validation or absence of runtime destinations. Host launch must
still use TAP, valid preconfigured interfaces and explicit fixture RIL/DHCP DNS;
QEMU SLIRP's other hardcoded DNS defaults are not an allowed shortcut.
