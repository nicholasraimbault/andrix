# Native ARM64/Bionic compiler

**Status:** bounded native C/C++ edit/build/run workflows were demonstrated on
Android. The compiler runs in the owner environment and is packaged in authenticated
read-only `/usr`, not merely supplied as a host cross-compiler.

## Build and ABI boundaries

Use the pinned LLVM, Android API/NDK inputs, Bionic, CRTs and system linker. Preserve
private dependency visibility, CFI/ThinLTO and strict linking. Validate the staged
package against its source/SDK manifests and reject unexpected files or digest drift.
Do not casually repin toolchain inputs to make a test pass.

## Findings and result

The first project-private C++ workflow exposed a global runtime lookup failure under
Android's isolated namespace. The [standalone/shared profile decision](2026-09-11-cxx-defaults.md)
resolved that without adopting another libc or widening global lookup. Later tests
exercised multi-file builds, relocation, failure recovery and rebuilding after reboot.

Broader compiler languages, workloads, JIT/plugin combinations, resource exhaustion,
power-loss and supported-device behavior remain separate qualification.

See [reusable build instructions and source pins](../toolchain/README.md),
[package verifier](../scripts/proof/compiler_package.py) and
[project fixtures](../tests/owner-project/README.md).
