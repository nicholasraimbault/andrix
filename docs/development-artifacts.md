# Development artifacts and working storage

Use this procedure for build outputs, emulator working states and retained evidence.
Machine capacity, inventories, paths and individual operation ledgers are private
operator records; this document describes the reusable method.

## Before building or booting

- Check capacity on the filesystem that will actually receive outputs, including
  temporary overlap, verification work and an explicit reserve. A check on another
  volume is not sufficient.
- Use the configured heavy-work admission mechanism without bypassing its checks.
- Freeze and rehash matching images and host tools before boot. Never substitute
  mutable build output or reuse a consumed fixture queue.
- Verify that staging selected the intended scripts and behavior, not merely that
  an accidentally old script matches its own freshly generated checksum.

## Measure storage accurately

`du`, apparent file sizes and filesystem free space answer different questions.
Account for sparse holes, hard links and reflink-shared extents before estimating
reclamation. Empty-looking, inaccessible or unmeasured areas are not disposable.
A guessed archive compression ratio is not a capacity result.

## Preserve before retiring

1. Establish explicit scope and authority for the exact paths to retire. Recheck
   stopped state, open references, ownership, containment and filesystem boundaries.
   Record limitations of process visibility rather than claiming administrator-wide
   exclusion from an unprivileged inspection.
2. Preserve the complete dependency set. In particular, retain the exact disk bases
   referenced by guest-write overlays and any required configuration/link mappings.
3. Apply a hard archive budget; exceeding it must leave originals intact. Preserve
   recovery tools, keys and instructions under appropriate private permissions.
4. Restore into a new, empty verification workspace. Check full file contents and
   hashes, pathname sets, relevant metadata, symlinks, special files and backing
   references. Cold-file restoration is not a running-memory snapshot or permission
   to resume an old test session.
5. Make archive data, recovery metadata and directory publication durable **before**
   source removal. Successful live restoration is not a crash-atomicity proof.
6. Recheck source mutation fences and references immediately before scoped removal.
   Never follow symlinks into unrelated targets. Retain a private operation ledger
   and verify that non-target state and sealed evidence remain unchanged.
7. Remove only authorized working copies and new verification temporaries. Measure
   actual recovery after processes release their handles; projections are not proof.

Temporary namespace-backed RAM can avoid leaving persistent emulator RAM files after
teardown. It does not authorize deletion of existing disks, overlays or saved state.
Sealed evidence is immutable; corrections belong in a new record, not an appended seal.
