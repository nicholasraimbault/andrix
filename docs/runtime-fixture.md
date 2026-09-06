# Phase 1 controlled runtime fixture

This is a prepared procedure, **not** rental, network-administration or boot
authority and not a qualified-host result. Use only after the exact image's P3
review and the owner's bounded runtime authorization. Do not expose the build/
signing host as an Internet service or copy Android signing keys to the fixture.

The separately authorized [offline QEMU smoke](../plans/2026-09-06-qemu-smoke.md)
used CPU emulation and a network-disconnected namespace. Its successful
functional checks are not qualification of the connected native fixture below.

## Isolation, services and observations

Use a fresh native ARM64 Linux/KVM host and a dedicated runtime identity,
directory and network namespace (or an equivalently attributable isolated lab
network). Record the host/guest resource limits, kernel, native host-package
compatibility, `/dev/kvm`, vsock/TUN access and network permissions. The
[host preflight](../scripts/proof/host_preflight.md) is only an initial check;
it does not qualify the complete Cuttlefish stack.

Before any Android process starts, prepare these services on an explicit,
private fixture address reachable from **all** enabled guest networks:

- DNS: a real UDP/TCP resolver, e.g. a locally controlled Unbound instance.
  Supply that address through RIL and every relevant DHCP/RDNSS path. Resolve
  `probe.andrix.org` and the nonce names below it to the fixture. Do not use
  public Google resolvers, rewrite Google names to fake successes, or blackhole
  requests. Unknown/Google-directed attempts must remain visible to capture.
  Recursive resolution or any upstream resolver is part of the reviewed host
  network configuration, not an implicit provider selection in the image.
- NTP: a real UDP-123 time service for `probe.andrix.org`, e.g. a separately
  configured chronyd. Qualify/record its time source, synchronization and
  offset; do not advertise an unsynchronized clock as accurate time. Do not
  step the host clock as a side effect of this proof. HTTPS 204 is not NTP.
- HTTP/HTTPS: [the bounded probe service](../scripts/proof/probe_server.md),
  reachable on ports 80/443, with the issued hostname certificate and the
  verified CT snapshot. Preserve normal TLS validation, serve empty 204 without
  redirects, and return the exact signed CT data only over HTTPS. No live
  upstream proxy is needed. Recheck certificate and CT-list expiry before use.

The config-only renderer prepares bounded Unbound DNS/DoT and chronyd inputs;
it starts nothing and changes no interfaces, firewall, services or clocks:

```sh
python3 scripts/proof/fixture_services.py \
  --bind "$FIXTURE_DNS_IP" --client-cidr "$GUEST_CIDR" \
  --ntp-upstream "$QUALIFIED_NTP_PEER_IP" \
  --certificate /operator-managed/fullchain.pem \
  --private-key /operator-managed/probe.key \
  --dns-root-key /operator-managed/dnssec-root.key \
  --state-dir /operator-managed/fixture-state \
  --output-dir /operator-managed/new-service-configs
```

Use a managed DNSSEC root anchor and an explicitly reviewed NTP peer; there is
no default public resolver/time provider or unsynchronized `local stratum`
shortcut. Unbound supplies local probe/nonce answers and performs normal
recursive resolution for other names, not Google-name blackholing. Run chronyd
with `-x` so it does not adjust the host clock. Run both under an appropriately
restricted fixture identity/supervisor with only required bind permissions.
Check configs with `unbound-checkconf` and `chronyd -p` before starting services;
those parser checks do not prove a reachable peer or synchronized time.

Test these services from the guest-facing network before boot, including DNS,
valid NTP replies, hostname-verified HTTPS, byte-exact CT files and negative TLS
hostname checks. Record actual interfaces, routes, DHCP/DNS configuration and
listeners. Host clock and DNS configuration are required deployment inputs;
this procedure does not invent addresses, public providers or time accuracy.

## Capture before launch

Start external full-packet capture in the dedicated fixture network namespace
**before assembly/launch**, covering every guest interface plus service traffic.
A suitable `tcpdump` profile is `-i any -n -s 0 -U -w <private-evidence.pcap>`.
Confirm the capture process is alive and has reported that it is listening;
record its command, PID, namespace and start time. DNS query logs supplement,
not replace, packet capture. Keep management/host activity attributable and
retain capture errors/dropped-packet counts. A failed capture is not evidence
that no connection occurred.

Do not add a Google-address denylist to force the result. Preserve/explain all
attempted destinations, including failed, blocked and encrypted connections.
TLS/DoT metadata alone does not expose encrypted qnames, so retain the controlled
resolver's query log and raw service records as well. Keep all of this private.

## Pinned Cuttlefish control path

Use the exact ARM64 host package with a new writable **copy** of the reviewed
images and a new runtime home/root; never reset an existing instance or mutate
the archived candidate. The r1 profile uses:

```text
--vm_manager=crosvm
--device_external_network=tap
--enable_tap_devices=true
--ril_dns=<private-fixture-DNS-IP>
--report_anonymous_usage_stats=n
--guest_enforce_security=true
--num_instances=1
--base_instance_num=1
--resume=false
--data_policy=always_create
--system_image_dir=<fresh-reviewed-image-copy>
```

Choose/record explicit CPU and memory limits. Do not use QEMU SLIRP: its Ethernet
DNS is independently hardcoded to Google and its mobile DNS assumes a host-local
resolver. Do not rely on `ril_dns` alone when host interfaces are absent. In r1,
`ConfigureNetworkSettings` requires a valid mobile bridge or TAP address and
broadcast; its failure path writes unusable configuration after an attempted
fallback. Treat that condition as a stop, never a usable default.

For a pre-boot configuration gate, r1 `assemble_cvd` can be run separately with
non-TTY stdin (`/dev/null`), the selected flags and a fresh instance directory.
The pinned `cvd_internal_start` normally invokes it, reads the emitted
`cuttlefish_config.json`, then starts `run_cvd`. Keep those phases separate for
this proof: preserve assembly output and inspect the generated configuration
before starting the runner. This is source-reviewed procedure; it has not yet
been exercised on a qualified ARM64 host.

Capture `ip -j address` in the **same** namespace and check the generated config:

```sh
python3 scripts/proof/cuttlefish_config.py \
  --config /operator-managed/cuttlefish_config.json \
  --interfaces /operator-managed/fixture-ip-addresses.json \
  --expected-dns "$FIXTURE_DNS_IP" --instance 1
```

The check requires the r1 ARM64/crosvm/TAP profile, explicit metrics-off enum,
security enforcement, exact fixture DNS and an observed matching mobile bridge/
TAP address/prefix/broadcast. It does not verify Ethernet/Wi-Fi DHCP, the complete
VMM argv, artifact hashes, host capability or capture: review those separately.
Preserve the final config and actual subprocess command lines. Never start the
runner after a failed configuration check or a dead capture process.

## Boot and proof

Only after all gates above, run the exact host package's runner with the
validated config/instance environment and directory, keeping capture active.
Require boot completion, expected fingerprint and enforcing SELinux. Run the
[milestone](../plans/2026-08-28-phase1-andrix-hello-aosp17.md)'s P4 and separately
authorized P5 checks using the frozen APEX/ELF/APK identities. Inspect active
factory APEX/module state and effective resource/property values, not only
image text or the launcher's return code.

Keep capture through both proofs and shutdown. Stop only owned processes and
remove only the disposable fixture's resources. Save raw logs, hashes and
failure states before cleanup. Explain every destination; any Google-directed
or unexplained attempt defeats the no-Google proof. Successful host tests,
assembly, boot, or a single `andrix-hello` output alone do not complete it.
