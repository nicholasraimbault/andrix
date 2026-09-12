# Native owner multi-file project fixture

An intentionally small statistics CLI exercises three C++ translation units, a
header, a response file, an archive, exception propagation between translation
units, nonconstant `sqrt`, and a repeatable serial build. It uses the existing
native `c++`, `ar` and `ranlib` tools. It is not an APK, package manager, make
replacement, or claim of numerically robust statistics for arbitrary inputs.

Copy/extract these reviewed sources into an owner project through an authorized
owner operation, then run `sh build.sh` and `./build/stats 2 4 6`. The build uses
private temporary outputs and only replaces the last executable after successful
compilation/linking and a smoke check. `BUILD_OK` is not printed on failure.

Qualification steps:

1. Build/run as the real native owner, recording compiler/output dependencies and
   group resource counters. No observer access to the owner home.
2. Use `vi` to change `revision` from `v1` to `v2` in `include/stats.h`, rebuild,
   and confirm the changed output. The full rebuild is intentional.
3. Invalid numeric arguments must return 2. Introduce a deliberate compile error:
   the build must fail, leave the previous executable unchanged and clean its
   temporary directory. Restore the source and rebuild.
4. Move the whole project and rebuild/run from its new location. Inspect the
   produced ELF: dynamic Bionic, no shared C++ runtime dependency or global RUNPATH.
5. Repeat normal relock/return and reboot/persistence as relevant; keep ordinary-app
   negatives and live positive controls distinct from the compiler tests.

## Incremental Make follow-up

The Makefile adds ordinary incremental builds with compiler-generated header
prerequisites. `make`, a no-op `make -q`, header/source edits and `make --trace`
exercise dependency selection. Archive/link output is first written to a temporary
file so failed work does not overwrite the last working executable. This is not a
concurrent-project or package-transaction guarantee.

`make -j2 jobserver-check` exercises recursive jobserver inheritance using two tiny
shell jobs, not concurrent compiler pressure. `make path-fallback` runs a recipe
with PATH unexported, checking the platform's default command search. `make defaults`
shows the actual configured CC/CXX/AR/SHELL values. Runtime limits remain enforced.
See the [native build-tools milestone](../../plans/2026-09-11-native-build-tools.md)
for the successful bounded native Make qualification, retained observer retries and
remaining limits.

The Python host test really builds and runs this fixture using the host's C++
compiler and libc. That is **not** an Android compiler, identity, or resource pass.
The [Android trial](../../plans/2026-09-11-owner-project-input.md) records the native
build/edit/failure-recovery/relocation/reboot results separately from those host tests.
