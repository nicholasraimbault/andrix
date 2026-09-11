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
3. Invalid numeric arguments must return2. Introduce a deliberate compile error:
   the build must fail, leave the previous executable unchanged and clean its
   temporary directory. Restore the source and rebuild.
4. Move the whole project and rebuild/run from its new location. Inspect the
   produced ELF: dynamic Bionic, no shared C++ runtime dependency or global RUNPATH.
5. Repeat normal relock/return and reboot/persistence as relevant; keep ordinary-app
   negatives and live positive controls distinct from the compiler tests.

The Python host test really builds and runs this fixture using the host's C++
compiler and libc. That is **not** an Android compiler, identity, or resource pass.
Android results belong in the linked milestone, not in fixture source assertions.
