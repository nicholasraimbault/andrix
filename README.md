# Andrix

Andrix is an experimental open-source project to make Android a general-purpose
mobile computer: one native Android/Bionic system with an owner-controlled Unix
environment.

## Status: early development

Andrix has adopted a pinned GrapheneOS-derived Android/Pixel base. The
[isolated migration trial](plans/2026-09-08-grapheneos-migration.md) verified all
1,108 source-project revisions. Its complete ARM64 Cuttlefish image now
[boots and passes offline `/usr`, ordinary-app execution-boundary and normal reboot checks](plans/2026-09-08-grapheneos-first-boot.md).
A [follow-up](plans/2026-09-09-grapheneos-ui.md) also verifies ordinary setup UI
rendering/navigation on an emulator-profile correction. These remain emulated
functional results: the test kernel lacks some GrapheneOS hardening. A later
[connected diagnostic](plans/2026-09-09-grapheneos-connected-baseline.md) corrected
the missing emulator APN input and passed core/P5, ordinary WebView TLS, time/CT
and reboot checks with real Internet. The browser's tested page stayed blank;
a known WebView recovery endpoint remains outside policy. Complete network-policy,
native and Pixel qualification remain open.

The preserved earlier baseline proves a tiny `andrix-hello` executable in a signed
APEX exposed through read-only `/usr` on an ARM64-only direct-AOSP-17 Cuttlefish
image. That image and signed APEX build, and host-side artifact checks pass.
An [offline QEMU/TCG smoke test](plans/2026-09-06-qemu-smoke.md) has booted the
ARM64 image on x86-64 and passed the signed APEX, read-only `/usr` and ordinary-app
execution-boundary checks with SELinux enforcing. A subsequent
[connected candidate](plans/2026-09-07-public-ct-runtime.md) runs WebView 152,
passed JavaScript/HTTPS/hostname-rejection tests, and downloaded, verified and
installed signed CT log lists from the owned public endpoint. No Google guest
destination was observed in its measured workload.
[Vanadium qualification](plans/2026-09-07-webview-qualification.md) passed
configuration-signer rejection and focused recovery checks. A
[split-cohort rehearsal](plans/2026-09-07-webview-cohort-rollback.md) now restores
consumer updates through Android's rollback API, provided the matching library
is retained or restored first. The [retention extension](plans/2026-09-07-rollback-retention.md)
now preserves dependencies through pruning/reboot and has demonstrated automatic
PackageWatchdog recovery. The [lifecycle correction](plans/2026-09-08-rollback-lifecycle.md)
also passes staged restoration, metadata reload and typed in-flight expiry refusal;
power-loss, broader lifecycle and real-version migration gates remain open.
**Native ARM64/KVM and complete no-Google qualification remain open.**

This is source and proof tooling, **not a supported OS release or a phone
installation image**. There is no buildable Pixel product in this repository.
Do not flash a phone or treat the accepted design as verified runtime behavior.

## Repository scope

This repository contains the Andrix layer and proof tooling, historically placed
at `vendor/andrix` in a separately pinned AOSP checkout. The approved migration
follows an exact public GrapheneOS release while preserving that earlier checkout
and evidence. This repository does not contain the full platform source tree,
private signing keys, build images, credentials or raw lab captures. The migration
anchor is GrapheneOS `2026081300`, based on `android-17.0.0_r1`; the milestone records
source authentication, integration and proof gates.

- [Current proof state and remaining work](plans/current.md)
- [Active migration milestone](plans/2026-09-08-grapheneos-migration.md)
- [Preserved direct-AOSP proof milestone](plans/2026-08-28-phase1-andrix-hello-aosp17.md)
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
