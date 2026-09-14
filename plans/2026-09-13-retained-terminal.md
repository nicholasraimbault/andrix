# Native retained terminal presentation

**Status:** tmux operation, owned-client PTY hangup and fresh redraw were demonstrated
in the emulator. [Explicit Keep](2026-09-14-keep.md) adds the separate Android consent
and lifecycle dependency; tmux alone is not that authority.

## Invariants

Start a kept terminal under tmux from creation. Do not silently adopt or replace an
already-running plain editor/shell. Detach retires the owned terminal client/PTY,
not the server and panes; all remain in the original init-owned resource group.
Never signal a guessed external process group to simulate this boundary.

Return needs a new client, PTY, presentation ID, journal and parser. An acknowledged
output tail cannot reconstruct a lost parser, and a gap must never be silently rebased.
Use a validated private CE socket directory and retain ordinary-app/socket boundaries.

## Observed native multiplexer result

Bounded controls exercised client retirement, fresh editor redraw, retained unsaved
state, same-work return and whole-group End/reboot behavior. A missing socket-directory
default was corrected in the runner rather than by widening filesystem permissions.

See [tmux source/build instructions](../toolchain/tmux/README.md),
[owned-PTY fixture](../tests/owner-retained-terminal/README.md) and
[platform lifecycle](2026-09-13-android-lifecycle.md). Services/SSH, general pressure,
suspend and hardware behavior remain separate gates.
