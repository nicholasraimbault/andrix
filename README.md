# Andrix

**Android you own.**

Andrix is building an Android operating system for people who want to program, extend and
administer the computer in their pocket, without giving up what makes it a phone.

The goal is one system where Android apps and native Unix programs are equally important.
Not a separate desktop Linux environment inside an app, but a programmable Android system
whose owner can change its software, policy and defaults.

> **Early development.** Andrix is an engineering prototype, not a supported operating
> system release. This repository provides no phone installation image or supported
> installer. It is not ready for daily use.

## What we are building

- **A programmable phone.** Real native programs, development tools, accounts, homes and
  work that can continue after a terminal window closes.
- **Practical ownership.** An understandable path from source or configuration to a
  working change: edit, build, sign, install and recover from mistakes.
- **Deliberate administration.** Ordinary authority for everyday programs, with explicit
  authorization for system administration, including a root shell when the owner needs it.
- **Replaceable system software.** Changing a launcher, SystemUI, service or platform
  component should be a supported workflow, not require maintaining a private OS fork
  for every small change.
- **Updates that respect local choices.** Compatible, recoverable updates that expose
  conflicts and security divergence rather than silently replacing owner modifications.
- **Useful defaults, without permanent vendor control.** A usable phone and Unix
  environment whose initial choices remain changeable.

Owner control does not mean giving every app root or disabling security by default.
Application isolation, SELinux enforcement and credential encryption remain part of the
[design](docs/architecture.md). The owner should have a deliberate path to changing the
system, not have to weaken every boundary just to do ordinary work.

## What works so far

Development currently targets ARM64 Android with Bionic, using Cuttlefish/QEMU before
physical phone qualification. Bounded prototype work has exercised:

- A terminal and editor, native C/C++ compilation, Make, LLDB and tmux.
- Detached terminal work, returning to the same work and explicit Stop controls.
- Native identity and storage preservation tests in development images.
- Selected signed APK and SystemUI changes, including forward restoration.

These are separate prototype results, not one finished product workflow. Some are opt in
and require lab configuration, host assistance or development keys. Production owner signing,
everyday elevation, complete Unix environments for multiple Android users, general component
updates and phone support remain unfinished. The [current work](plans/current.md) and
[design evidence register](docs/design-evidence.md) describe the results and their limits.

Do not flash a phone from this repository. Emulator results do not establish complete
hardware, networking, privacy, security or power loss behavior.

## Development

Andrix uses GrapheneOS and AOSP as an engineering foundation. It is an independent project,
not an official GrapheneOS distribution. That foundation is not the boundary of Andrix's
OS design or the limit of what its owner should be able to change.

This repository contains Andrix components, platform adaptations and verification tooling.
It is placed at `vendor/andrix` in a separately verified Android source checkout; it is not
that complete checkout. Private keys, credentials, build images and operating records are
not part of the public repository.

Prototypes inform the design. They do not oblige us to preserve an inferior implementation.
Correctness, coherence, maintainability and owner control guide what we keep or replace.

Host regression checks include:

```sh
python3 -B -m unittest discover -s scripts/proof/tests -p 'test_*.py'
python3 -B -m unittest discover -s scripts/pixel/tests -p 'test_*.py'
```

These checks do not boot Android or qualify a device. Start with the architecture and
current work before choosing a development task.

## Documentation

- [Product vision](docs/vision.md)
- [Accepted architecture](docs/architecture.md)
- [Current work and remaining milestones](plans/current.md)
- [Design evidence and prototype limits](docs/design-evidence.md)
- [Source and artifact provenance](docs/source-provenance.md)
- [Contributor and agent guidance](AGENTS.md)

## Licensing

The original Andrix owner control core is licensed under **GPL-3.0-or-later**. Public AIDL
interfaces and other original material outside that explicit scope remain Apache-2.0,
unless noted otherwise. Upstream components retain their own licenses and exceptions.

See the [source licensing map](LICENSING.md), [license texts](LICENSE) and
[licensing policy](docs/licensing.md). Earlier valid Apache grants remain valid. This is
not a claim that the whole Android system, kernel, firmware or every dependency has one
license, or that a phone distribution has completed compliance review.
