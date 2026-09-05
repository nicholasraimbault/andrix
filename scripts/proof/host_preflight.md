# Local runtime-host preflight (not boot readiness)

For the [current ARM64 rental-first milestone](../../plans/current.md). This
standalone Python 3 standard-library tool needs no AOSP checkout, host package,
Android artifact, credentials or keys. Run locally, as the intended runtime
user, only on a host you are authorized to inspect; it never rents or uses SSH.
Do not start paid testing or boot Android just to run it.

```sh
# Read-only observations; devices remain NOT_RUN. Exit 2 on a supported host.
python3 -B scripts/proof/host_preflight.py --work-dir /existing/work/directory

# Explicitly authorized optional device probe; NOT a VMM launch or Android boot.
python3 -B scripts/proof/host_preflight.py --work-dir /existing/work/directory --probe-kvm
```

JSON on stdout records kernel release, architecture, Python pointer width and
byte order, running ELF machine, page size, CPU count/affinity, procfs MemTotal
and MemAvailable (KiB), directory free bytes available to this user, and current
process effective `CAP_NET_ADMIN` from `CapEff` bit 12. It creates no files or
directories. Memory, page size, disk space and capability presence have **no
qualification thresholds**. Host-visible memory/free space are snapshots, not
reserved resources or cgroup/quota headroom. A capability bit is not permission
to control or capture external egress.

Linux, ARM64 uname, 64-bit little-endian Python and an AArch64 process ELF are
required before any device open. These local checks are not proof of bare metal
or absence of emulation; provider/native-host identity still needs independent
confirmation. Unsupported hosts or missing/malformed required observations fail
closed and leave every device `NOT_RUN`.

With `--probe-kvm`, the only device operations are read/write open/close of
`/dev/kvm`, `KVM_GET_API_VERSION == 12`, `KVM_CREATE_VM` with type 0, close of that
**empty VM**, and open/close of `/dev/vhost-vsock` and `/dev/net/tun`. Every open,
ioctl and close must succeed. There is no vCPU, KVM_RUN, memory/IRQ setup, network
ioctl, VMM, module-load command, privilege escalation or networking/policy change.
Independent device probes continue after a device failure, but the overall
result fails. Nothing retries with greater privileges.

Exit status / JSON `status`:

- **0 / `LIMITED_PROBES_PASSED`**: only the observations and requested minimal
  device operations succeeded, never Cuttlefish or egress qualification.
- **1 / `FAIL`**: unsupported host, observation error or requested probe error.
- **2 / `NOT_RUN`**: observations collected; device probes were not requested.
  This is deliberately not a success/readiness exit code.

`runtime_qualified` is always false. Every report lists the still-unproved full
host-package/loader/library and page-size compatibility; real vCPU, interrupt
and backend support; networking/capture authority and configuration; and Android
P3–P6 gates, including no-Google review and capture **before first boot**. Review
those gates separately; an empty VM and openable tun do not qualify a rental.

Host-only regression tests (all observations, devices and ioctls are mocked):

```sh
python3 -B -m unittest discover -s scripts/proof/tests -p test_host_preflight.py
```

These tests are not runtime or hardware evidence.
