# Andrix

Andrix is an experimental open-source project to make Android a general-purpose
mobile computer: one native Android/Bionic system with an owner-controlled Unix
environment.

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

This repository contains source and verification tooling, **not a supported OS
release or a phone installation image**. There is no buildable Pixel deployment
product here. Do not flash a phone or treat the accepted design as proof of complete
hardware, networking, privacy or power-loss behavior.

## Repository scope

This is the Andrix layer, placed at `vendor/andrix` in a separately verified Android
checkout. It does not contain the full platform tree, private signing keys, build
images, credentials or raw lab captures. GrapheneOS `2026081300`, based on
`android-17.0.0_r1`, is a reproducible migration anchor, not a permanent update policy.
Earlier direct-AOSP experiments remain distinct from the adopted foundation.

- [Current product progress and remaining work](plans/current.md)
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
