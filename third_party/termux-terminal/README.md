# Reusable Termux terminal libraries

Unmodified selected files from `termux/termux-app` at commit
`3b66f8799635a4dba4a206563048ff0e6792c487`. `SOURCE.json` records the source tree,
archive digest and each selected Git blob/SHA-256. Public HTTPS and hash checks
pin these bytes; they do not independently authenticate a maintainer or establish
runtime safety.

`UPSTREAM-LICENSE.md` preserves the upstream licensing statement: the Termux app is
GPLv3-only with an Apache-2.0 exception for these terminal libraries derived from
Terminal Emulator for Android. `LICENSE` supplies the Apache-2.0 text. Only the
terminal emulator/view and their tests/resources are selected here; the Termux APK,
services, package environment and `termux-shared` library are not imported.

**No Termux process launcher:** upstream `TerminalSession.java`, `JNI.java` and the
JNI implementation are deliberately excluded. Andrix must supply the view's
session API through its existing authenticated native coordinator and revocable
stream. It must not move execution into the console APK or hand it the PTY master.

These sources are not yet an Android build target. First qualify the portable
parser and the bounded replay protocol, then integrate an Andrix session adapter
and native Android view. The active M4 console is unchanged by this import.
Automatic OSC clipboard requests must not silently acquire Android clipboard
access; explicit user copy/paste is a separate UI action.

Keep upstream files byte-identical, including the existing trailing whitespace in
`TextSelectionCursorController.java`. First-party whitespace checks and upstream
blob verification are separate; do not normalize a pinned import merely to silence
`git diff --check`. Record any future required change explicitly, with new hashes
and a reason, rather than silently changing the provenance record.
