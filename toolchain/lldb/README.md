# Native LLDB feasibility profile

**Native C/C++ debugging passed bounded Android qualification**, including launch,
breakpoints, backtrace, stepping, variables, paused-job return, fresh debugging
after reboot and boundary controls.
LLVM23's own Android documentation still warns that its client is unsupported.
The [qualification record](../../plans/2026-09-12-native-debugger.md) separates the
successful downstream profile from the retained denied baseline and remaining
feature, pressure and release gates.

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
by this build profile. The first packaged image established the unchanged-policy
denial baseline. Separate Andrix-owned policy now labels owner-created PTYs and
allows owner-to-owner tracing only, with compiled and runtime cross-identity controls.
It does not permit coordinator/app tracing, generic devpts or new capabilities.
