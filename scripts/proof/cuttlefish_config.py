#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read-only r1 Cuttlefish network/security config check, not boot authority."""
import argparse
import ipaddress
import json
from pathlib import Path
import sys


class ConfigError(ValueError):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError("Duplicate JSON key")
        result[key] = value
    return result


def load(path):
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def ipv4(value):
    if not isinstance(value, str):
        raise ConfigError("IP address must be an explicit string")
    address = ipaddress.IPv4Address(value)
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        raise ConfigError("Guest network address is not usable")
    return address


def verify(config, interfaces, expected_dns, instance="1"):
    dns = ipv4(expected_dns)
    private_ranges = [ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    if not any(dns in network for network in private_ranges):
        raise ConfigError("Expected DNS must be the private controlled fixture, not a public resolver")
    if config.get("vm_manager") != "crosvm":
        raise ConfigError("This proof requires the qualified native crosvm path")
    # r1 CuttlefishConfig::Answer: Unknown=0, Yes=1, No=2.
    if type(config.get("enable_metrics")) is not int or config["enable_metrics"] != 2:
        raise ConfigError("Usage statistics are not explicitly disabled")
    instances = config.get("instances")
    if not isinstance(instances, dict) or set(instances) != {instance}:
        raise ConfigError("Expected exactly the selected single instance")
    guest = instances[instance]
    if not isinstance(guest, dict):
        raise ConfigError("Malformed instance configuration")
    if guest.get("external_network_mode") != "tap" or guest.get("enable_tap_devices") is not True:
        raise ConfigError("TAP is required; SLIRP has independent DNS defaults")
    if guest.get("guest_enforce_security") is not True:
        raise ConfigError("Guest security enforcement must remain enabled")
    # r1 common/libs/utils/architecture.h: Arm=0, Arm64=1.
    if type(guest.get("target_arch")) is not int or guest["target_arch"] != 1:
        raise ConfigError("Expected ARM64 target architecture")
    if guest.get("ril_dns") != str(dns):
        raise ConfigError("RIL DNS differs from the explicit fixture address")
    address, gateway, broadcast = (ipv4(guest.get(key)) for key in ("ril_ipaddr", "ril_gateway", "ril_broadcast"))
    prefix = guest.get("ril_prefixlen")
    if type(prefix) is not int or not 1 <= prefix <= 30:
        raise ConfigError("Invalid RIL prefix (including failed-interface sentinel)")
    network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
    if (gateway not in network or broadcast != network.broadcast_address
            or address in (gateway, network.network_address, broadcast)
            or gateway in (network.network_address, broadcast)):
        raise ConfigError("Inconsistent RIL address/gateway/broadcast")
    names = [guest.get("mobile_bridge_name"), guest.get("mobile_tap_name")]
    if not all(isinstance(name, str) and name for name in names):
        raise ConfigError("Mobile bridge/tap names are missing")
    matched = []
    for interface in interfaces:
        if interface.get("ifname") not in names:
            continue
        for addr in interface.get("addr_info", []):
            if (addr.get("family") == "inet" and addr.get("local") == str(gateway)
                    and addr.get("prefixlen") == prefix and addr.get("broadcast") == str(broadcast)):
                matched.append(interface["ifname"])
    if not matched:
        raise ConfigError("No observed mobile bridge/tap matches the generated network config")
    return {"config_consistent": True, "instance": instance, "dns": str(dns),
            "mobile_interfaces": matched, "runtime_qualified": False,
            "note": "Does not check DHCP/Wi-Fi/ethernet DNS, image hashes, KVM, capture or services."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--interfaces", required=True, type=Path,
                        help="ip -j address output from the actual fixture network namespace")
    parser.add_argument("--expected-dns", required=True)
    parser.add_argument("--instance", default="1")
    args = parser.parse_args()
    try:
        print(json.dumps(verify(load(args.config), load(args.interfaces), args.expected_dns, args.instance), indent=2))
    except (ValueError, KeyError, TypeError, AttributeError, OSError) as error:
        print("Cuttlefish config rejected: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
