# Native terminal-multiplexer candidate

This native candidate is preparation for an opt-in retained terminal, not Android
runtime qualification yet. It targets the existing ARM64/Bionic API 37 SDK and
preserves the compiler profile's hardening. The 1,403,056-byte executable passed
ELF/command checks with private static libevent/terminfo dependencies; **Bionic remains
dynamically linked**. Its only runtime libraries are libc/libdl/libm, with no RUNPATH,
PIE/RELRO/NOW/non-executable stack and 16KiB load alignment. CFI remains enabled. Do not use tmux's `--enable-static`, which adds global `-static`.

Candidate sources selected September 13, 2026:

- tmux 3.7c, the latest official GitHub release observed. Its SHA256 matches the
  release API digest; 209 tracked files match the unsigned 3.7c tag's tree, with 11
  generated release files recorded separately. The tag is **not signed**. This
  is official HTTPS source retrieval/content pinning, not maintainer-key proof.
- libevent 2.1.13-stable, the current stable release observed on the project site and
  GitHub. Its official release digest and detached GPG signature verified. The
  signing subkey's certificate was obtained by full fingerprint from a keyserver;
  this is not out-of-band maintainer authentication. This release includes security
  fixes, including AF_UNIX-related handling; the older 2.1.12 was not selected.
- ncurses 6.6-20260912, the current official maintainer snapshot observed. Its GPG
  signature verified against the full fingerprint published on the maintainer's
  HTTPS key page. This includes updates since the 6.6 release, but is not an indefinite
  update policy or independent authentication of that key.

Keep source, build-only host tools and device payload provenance separate. Host
`tic` may generate a small selected terminfo set but must not enter the Android
payload. The config/database paths stay within authenticated `/usr/etc/andrix`,
matching the existing APEX data layout; Android `/etc` remains Android's. The native
terminfo directory is `/usr/etc/andrix/terminfo`. Invoke the pinned build-only Bison
as `bison -y` through its private PATH: tmux's follow-up configure search incorrectly
prepends PATH entries when given an absolute YACC executable name. Optional systemd/cgroup integration, utempter, UTF8Proc,
jemalloc, sixel and OpenSSL dependencies are disabled in the initial candidate.
This does not remove owner control of explicitly executed programs or establish
full terminal compatibility. The opt-in APEX 6 candidate adds 16 pinned payload files
(binary, selected terminfo entries, notices and original source archives) without
changing any prior compiler/SDK/Make/LLDB payload row.

Preserve original license text and per-file notices. Static dependency notices
remain distinct from LLVM and GNU Make's obligations. The intended notice bundle
includes the original source archives as well as their main license files, so
individual notices and generated-parser exceptions are not discarded.

No capability, generic devpts, cgroup-control or cross-app grant is part of this
build profile. Native owner-home Unix socket permissions and positive/negative
runtime controls, reconnect/redraw behavior, inherited filters, resource bounds,
Android lifecycle authority and complete cleanup are separate integration gates.
