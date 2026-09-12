# Native GNU Make profile

GNU Make 4.4.1 is selected for serial-by-default incremental owner builds. The
platform's ARM64 host Make depends on musl and is not a device payload. This profile
builds a dynamic ARM64/API37 Bionic executable using the pinned Android bootstrap 22
and existing SDK, with ThinLTO, indirect-call CFI and the recorded compiler/linker
hardening. The [Android trial](../../plans/2026-09-11-native-build-tools.md) now records
native incremental/no-op/rebuild, recursive-job, fallback-path and reboot results.
Host compilation and regression tests remain separate from that qualification.

`profile.json` pins the GNU archive/signature/keyring, exact signer fingerprints,
Bionic adaptation, SDK and host build inputs. The GNU trust bootstrap is its public
HTTPS release/keyring; the record is not out-of-band maintainer verification. Verify
new keyring/release bytes deliberately rather than accepting changed input hashes.
GNU Make and the adaptation retain GPL-3.0-or-later terms. Corresponding source and
build configuration must accompany any eventual distribution; none is relicensed.

The single `src/job.c` patch uses Bionic's `_PATH_DEFPATH` when a child's PATH is
absent: Bionic omits `confstr(_CS_PATH)`, and its own `execvp()` uses that constant.
Non-Bionic behavior is unchanged. No global path/namespace/libc change is needed.
The image already supplies `/bin -> /system/bin`; the owner runner supplies
`PATH=/usr/bin:/system/bin` and a private TMPDIR.

Configure runs a real cross C++ compiler named `c++` through a build-only wrapper.
That lets upstream save the correct on-device builtin CXX name instead of `g++` or
an absolute host command. This wrapper is not installed and grants no authority.
Optional Guile, native-load extensions and NLS are excluded from this initial
hardened profile. They are not claimed as tested features. Makefiles execute owner
code; this is not isolation for untrusted package hooks.

```sh
python3 -B scripts/proof/native_make.py --source-root "$ANDROID" \
    --downloads "$VERIFIED_DOWNLOADS" --sdk "$FROZEN_SDK" \
    --build-root "$NEW_BUILD" --output "$NEW_FROZEN_OUTPUT" --evidence "$NEW_EVIDENCE"
```

Run under the host heavy-work lease. Downloaded bytes, build directories, binary
outputs, signing keys and raw evidence stay outside Git. The recipe verifies signed
source, every SDK byte, source revisions, compile flags and the final ELF. It creates
separate source/build/evidence directories, uses the normal recursive build target,
and never places orchestration at `build.sh` inside configure's output directory
(which GNU legitimately owns for its bootstrap helper).

The frozen manifest includes Make, COPYING and a source-reference notice. Only
reviewed, pinned output manifests may be adopted into an APEX generation. Preserve
failed attempts and distinguish configure's cross-compilation feature guesses from
actual target behavior. The [milestone](../../plans/2026-09-11-native-build-tools.md)
records qualification and remaining limitations.
