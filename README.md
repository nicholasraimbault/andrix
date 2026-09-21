# Andrix

**Andrix is Android you own.** It is an experimental open source OS project for a
phone its owner can program, compose and administer: one Android/Bionic system,
with native Unix execution and APKs equally important.

The [accepted vision](docs/vision.md) includes changing Android itself, from a launcher
or SystemUI to native services and platform components. Good defaults should make it a
usable phone; those defaults remain replaceable. Daily work uses ordinary accounts,
with deliberate elevation for system administration.

## Status: early development

Andrix uses a pinned GrapheneOS-derived Android foundation. Its ARM64 emulator
prototype supports a terminal/editor, native C/C++ compilation, Make, LLDB and tmux
under a dedicated owner identity. Android's application boundaries and authenticated
read-only `/usr` remain intact.

An opt-in **Keep** mode preserves terminal work across Console-process loss and
screen relock. Return creates a fresh presentation of the same work; explicit Stop
or End terminates it. The tested lifecycle and notification controls have a bounded
emulator scope. Keep remains off by default while additional failure cases are
qualified.

The expanded component change workflow, Unix environments for multiple Android users,
general elevation, owner signing, rolling updates and recommended/custom installer are
accepted goals, not completed features. The next platform proof is on Cuttlefish, not
an immediate phone deployment.

This repository contains source and verification tooling, **not a supported OS
release or a phone installation image**. There is no buildable Pixel deployment
product here. Do not flash a phone or treat the accepted design as proof of complete
hardware, networking, privacy or power-loss behavior.

## Development principle

Tests and prototypes inform the long term design; they do not require preserving
prototype code. Correctness, coherence and owner control take priority over time,
effort and ease of implementation. We will replace components or start again when
that is the sound way to build the system. See the
[design method](docs/architecture.md#design-method).

## Repository scope

This repository currently holds Andrix components and integration inputs, placed at
`vendor/andrix` in a separately verified Android checkout. That layout is not the
product boundary: Andrix owns its full OS design, policy, packages, signing and updates.
It initially uses a pinned GrapheneOS source release as a useful engineering foundation,
not a ceiling on owner capabilities or a claim of official GrapheneOS support.

The repository does not contain the full platform tree, private signing keys, build
images, credentials or raw lab captures. GrapheneOS `2026081300`, based on
`android-17.0.0_r1`, is a reproducible migration anchor, not a permanent update policy.
Cuttlefish/QEMU is the first testing environment; a mature Pixel product is later work.
Earlier direct AOSP experiments and Unix proofs remain distinct preserved results.

- [Product vision](docs/vision.md) and [accepted revision](plans/2026-09-21-owner-composable-android.md)
- [Current product progress and remaining work](plans/current.md)
- [Prototypes, evidence and long term intent](docs/design-evidence.md)
- [Accepted architecture](docs/architecture.md)
- [Source provenance](docs/source-provenance.md)
- [GrapheneOS migration](plans/2026-09-08-grapheneos-migration.md)
- [Network policy and verification](docs/proof-network.md)
- [Development artifact handling](docs/development-artifacts.md)
- [Contributor/agent guidance](AGENTS.md)

Host-only regression checks:

```sh
python3 -B -m unittest discover -s scripts/proof/tests -p 'test_*.py'
bash -n scripts/gen-apex-keys.sh scripts/proof/*.sh
```

Those checks do not boot Android or establish runtime qualification. Public documents
record product decisions, reusable procedures and scoped outcomes; operational records
are kept privately.

## License

Original Andrix code is licensed under [Apache-2.0](LICENSE), unless otherwise noted.
Android, kernel, firmware, toolchain and other external dependencies retain their own
licenses. This license does not relicense them or imply permission to redistribute
every external input. Preserve applicable copyright and license notices.
