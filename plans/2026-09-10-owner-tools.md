# Owner terminal and programming tools

**Status:** the bounded VT/editor/script workflow and normal keyboard interaction
were demonstrated in the Android emulator. The native compiler and subsequent tools
have separate [milestones](2026-09-11-native-compiler.md).

## Terminal design

Use the pinned terminal libraries through an Andrix-owned, process-free adapter,
not the upstream APK/services/environment. Native code owns the PTY; output is framed
by session and offset, and acknowledged only after parsing. Activity recreation can
retain parser/checkpoint state within the Console process. A missing output range
must block input instead of silently inventing a screen.

The UI retains Android foreground/unlocked authority and normal IME selection.
Escape sequences cannot access the Android clipboard. Accessibility exposes bounded
visible rows only while the authorized terminal is foreground, not a transcript or
alternative file-access API.

## Findings and follow-up

Pending attachment ownership must survive main-thread preparation without admitting
input early; see the [cold-attachment correction](2026-09-11-cold-attachment.md).
The [input queue](../scripts/proof/ui_queue.md) requires fresh observed readiness,
bounded text and explicit Enter, not guessed startup delays.

Native C/C++ compilation, Make, LLDB and [tmux-backed Keep](2026-09-14-keep.md) build
on this transport. Broad terminal, IME/language, accessibility, pressure and phone
compatibility remain unqualified by the bounded checks.
