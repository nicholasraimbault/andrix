# Andrix

Andrix aims to make Android a general-purpose mobile computer: one native
Android/Bionic system with an owner-controlled Unix environment.

Before acting, read [current work](plans/current.md); read its linked milestone
when relevant. If `dev/operator-current.md` exists, read it for private local
paths and access context. That ignored operator file is not public project
source or a replacement for the verified public work state.

## Values

- The phone serves and is controlled by its owner.
- The owner can program, extend and change the system.
- Preserve what makes it a phone; reject restrictions that exist to preserve
  vendor control.
- Build clear, coherent and maintainable systems grounded in observed reality.

## Architecture

Preserve the [accepted architecture](docs/architecture.md). Read it before work
that changes or depends on the system design.

## Work

Act autonomously within the request while preserving the values. Changes to
the values or accepted architecture, and destructive or irreversible actions
beyond the request, require an explicit project decision.

Keep one writer per worktree; use independent review only when it can
materially affect a decision; remove task worktrees and branches after
integration or discard.

Ground claims in the exact revision, artifact or running system. Surface a
defeated premise rather than force the intended result. Keep private signing
keys outside Git and communication channels.

For owner-directed automated work, use the owner's configured GitHub-linked
noreply identity. Do not substitute invented agent or localhost identities;
if it is missing, confirm the correct account before committing. Other
contributors should use their own identity, not impersonate the project owner.

Use `master` as this repository's default branch; do not rename it to `main`.

Use Git history only to trace an earlier decision.
