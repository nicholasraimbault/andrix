# Andrix

Andrix is an experimental open-source project to make Android a general-purpose
mobile computer: one native Android/Bionic system with an owner-controlled Unix
environment.

## Status: early development

The current milestone is to prove a tiny `andrix-hello` executable in a signed
APEX exposed through read-only `/usr` on an ARM64-only direct-AOSP-17
Cuttlefish image.
The image and signed APEX build, and host-side artifact checks pass.
An [offline QEMU/TCG smoke test](plans/2026-09-06-qemu-smoke.md) has booted the
ARM64 image on x86-64 and passed the signed APEX, read-only `/usr` and ordinary-app
execution-boundary checks with SELinux enforcing. A subsequent
[connected candidate](plans/2026-09-07-public-ct-runtime.md) runs WebView 152,
passed JavaScript/HTTPS/hostname-rejection tests, and downloaded, verified and
installed signed CT log lists from the owned public endpoint. No Google guest
destination was observed in its measured workload.
**Native ARM64/KVM and complete no-Google qualification remain open.**

This is source and proof tooling, **not a supported OS release or a phone
installation image**. There is no buildable Pixel product in this repository.
Do not flash a phone or treat the accepted design as verified runtime behavior.

## Repository scope

This repository is the Andrix overlay placed at `vendor/andrix` in a separately
pinned AOSP checkout. It does not contain the AOSP source tree, private signing
keys, build images, credentials or raw lab captures. The current baseline is
`android-17.0.0_r1`; the milestone records the exact source and proof gates.

- [Current proof state and remaining work](plans/current.md)
- [Phase 1 milestone](plans/2026-08-28-phase1-andrix-hello-aosp17.md)
- [Accepted architecture and requirements](docs/architecture.md)
- [Network preparation and outstanding controls](docs/proof-network.md)
- [Contributor/agent context](AGENTS.md)

Host-only regression checks:

```sh
python3 -B -m unittest discover -s scripts/proof/tests -p 'test_*.py'
bash -n scripts/gen-apex-keys.sh scripts/proof/*.sh
```

Those tests do not boot Android or establish runtime proof.

## License

Original Andrix code in this repository is licensed under
[Apache-2.0](LICENSE), unless otherwise noted. AOSP, kernel, firmware, toolchain
and other external dependencies retain their own licenses; this license does
not relicense them or imply permission to redistribute every external input.
Preserve applicable third-party copyright and license notices.
