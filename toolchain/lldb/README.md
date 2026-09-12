# Native LLDB feasibility profile

Native startup, interactive/batch input and target/source metadata now work in the
bounded Android trial, but **traced execution is not yet qualified**. LLVM23's own
Android documentation warns that its client is unsupported. The
[feasibility record](../../plans/2026-09-12-native-debugger.md) separates those results
from the observed PTY/tracing denials and remaining authority/feature gates.

`profile.json` pins the source, bootstrap, SDK and Ninja inputs and records the
CMake configuration. `AndroidBionic.cmake` retains the existing compiler ABI and
hardening profile and additionally requires resolved symbols at link time.
Two narrowly scoped source adaptations are applied only to a verified source copy:

- `android-host-selection.patch` includes Android host support when the LLVM-style
  cross toolchain sets `ANDROID`, matching the compiler's `__ANDROID__` headers;
- `android-api-visibility.patch` exports the already-designated public SB API classes
  on Android under hidden-by-default compilation. Internal symbols stay hidden;
  CFI is not disabled and exporting all internal LLDB symbols is not enabled.

Native-only settings keep the private SONAME unversioned and align Clang resources
with the existing authenticated `/usr` layout. The frontend/server/library use the
same pinned shared STL as the compiler; host TableGen/Python generation tools are not
part of the Android payload. Optional scripting, line-editing/curses, XML/LZMA,
protocol-server and HTTP dependencies are excluded from this initial profile.

No owner policy, capabilities, global linker path or SDK release metadata is changed
by this profile. The first packaged image retained exactly the previous policy and
established the tracing-denial baseline. Follow the milestone's next controls before
considering owner-specific PTYs or a same-owner-only ptrace addition.
