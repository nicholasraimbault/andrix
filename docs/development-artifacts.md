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

## Keep artifact comparisons independent

Check whether an inspection library caches state across objects. The pinned Android
policy test helper stores rule sets at class scope; loading two policy objects in one
process can therefore reuse the first policy's rules. Inspect one frozen policy per
fresh process and compare the resulting records, with a known differing type/rule as
a positive control. Hash the actual policy, inspector and supporting library inputs.
A matching report produced through shared stale state is not independent evidence.
Corrections to an earlier inspection belong in a new record, never an amended seal.

## Close evidence without hashing live outputs

Finish and close every producer before building the manifest. Keep the sealer's stdout,
stderr, completion status, receipts and JSON result outside the input tree. A log hashed
while empty can change when the sealer prints its result, even if the command exits zero.
Keep a correction's source and result paths distinct from the original bundle's paths.

Check output destinations before opening or redirecting them. The
[`require_external_outputs`](../scripts/proof/evidence_outputs.py) helper rejects contained
paths, symlink destinations into the input tree and existing hard link aliases. A check of
inherited output descriptors provides an additional safeguard. It cannot undo a file already
truncated by shell redirection or establish that other processes and pipeline writers ceased.

After sealing, compare every listed file hash, the complete file set and exact symlink
targets. A matching checksum for `SHA256SUMS` authenticates neither its listed bytes nor the
absence of later files. Check artifact reports and downstream staging references separately.

If the seal fails, preserve the original manifest and files unchanged. Put the discrepancy,
extra files, source references and newly observed inventory in a separate correction bundle.
Close that bundle's writers before sealing it, with all sealer outputs outside it. A new
attestation records the current verified state; it does not make the original seal valid
retroactively or prove historical authorship against a compromised host.

## Keep credentials out of command records

A wrapper's private input path does not control every logger. In the inspected Android
source, adbd logs service command arguments independently. Key codes and touch coordinates
can reconstruct a PIN even when its literal value never appears in a command.

Use a constant service command and send credential dependent input through private stdin.
Retain the connection through complete remote execution. Do not publish subprocess output
or exception messages that can contain private arguments or partial data. Refuse unexpected
input debug logging rather than suppress it, then assess the actual captured records. These
checks do not establish secure heap storage or exclude every form of process inspection.

If an earlier capture contains credentials, restrict it as sensitive operating material.
Preserve its original seal and issue a separate correction. Do not silently rewrite the
capture or continue claiming the logging boundary succeeded.

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
