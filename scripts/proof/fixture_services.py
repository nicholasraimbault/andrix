#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Render isolated DNS/NTP fixture configs; never start services or edit the host."""
import argparse
import ipaddress
from pathlib import Path
import re
import sys

PRIVATE = tuple(ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
GOOGLE_DNS = {"8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"}


def path_value(value):
    path = Path(value)
    if not path.is_absolute() or not re.fullmatch(r"[A-Za-z0-9_./-]+", str(path)) or ".." in path.parts:
        raise ValueError("Use absolute, whitespace-free operator file paths")
    return str(path)


def render(bind, clients, ntp_upstream, certificate, key, state, dns_root_key):
    address = ipaddress.IPv4Address(bind)
    if not any(address in net for net in PRIVATE):
        raise ValueError("Bind to an explicit private fixture IPv4 address")
    ranges = [ipaddress.IPv4Network(x) for x in clients]
    if not ranges or any(not any(net.subnet_of(parent) for parent in PRIVATE) for net in ranges):
        raise ValueError("Explicit private guest CIDRs are required")
    upstream = ipaddress.ip_address(ntp_upstream)
    if upstream.is_multicast or upstream.is_unspecified or str(upstream) in GOOGLE_DNS:
        raise ValueError("NTP peer must be the separately reviewed, usable time source")
    certificate, key, state, dns_root_key = map(path_value, (certificate, key, state, dns_root_key))
    unbound = f'''# Generated fixture configuration; not a public recursive resolver.
server:
    interface: {address}@53
    interface: {address}@853
    interface-automatic: no
    access-control: 0.0.0.0/0 refuse
'''
    for network in ranges:
        unbound += f'    access-control: {network} allow\n'
    unbound += f'''    username: ""
    chroot: ""
    directory: "{state}"
    pidfile: "{state}/unbound.pid"
    logfile: "{state}/dns.log"
    auto-trust-anchor-file: "{dns_root_key}"
    log-queries: yes
    log-replies: yes
    tls-port: 853
    tls-service-pem: "{certificate}"
    tls-service-key: "{key}"
    local-zone: "probe.andrix.org." redirect
    local-data: "probe.andrix.org. 60 IN A {address}"
    # Keep nonce/probe answers private, but recurse for the public CT site.
    local-zone: "ct.probe.andrix.org." always_transparent
'''
    # No public forwarder is silently selected. Unbound uses normal recursive
    # resolution for non-local names, which remains visible to external capture.
    chrony = f'''# Run chronyd with -x: do not adjust the host clock.
# The operator must qualify this peer, synchronization, and served time first.
server {upstream} iburst
port 123
bindaddress {address}
cmdport 0
pidfile {state}/chronyd.pid
driftfile {state}/chrony.drift
logdir {state}
log measurements statistics tracking
'''
    for network in ranges:
        chrony += f'allow {network}\n'
    return {"unbound.conf": unbound, "chrony.conf": chrony}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", required=True)
    parser.add_argument("--client-cidr", required=True, action="append")
    parser.add_argument("--ntp-upstream", required=True,
                        help="Numeric IP of the operator-qualified time source; no default provider")
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--dns-root-key", required=True,
                        help="Qualified host's managed DNSSEC root-anchor FILE")
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        files = render(args.bind, args.client_cidr, args.ntp_upstream,
                       args.certificate, args.private_key, args.state_dir, args.dns_root_key)
        args.output_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
        for name, contents in files.items():
            (args.output_dir / name).write_text(contents)
        print("DNS/NTP configurations written; no services, network changes or readiness claim.")
    except (ValueError, OSError) as error:
        print("Fixture config refused: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
