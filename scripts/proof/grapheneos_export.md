# Candidate patch set export

`grapheneos_export.py` writes a candidate GrapheneOS base's patch set from a sealed carry report
whose verdict is `CARRIED`. It carries the selected base's six exact patches to the release the
report targets, with the [carry tool's](grapheneos_carry.md) own functions, and writes the
candidate's patch directory and payload host tested record to new paths. Nothing it writes selects
the candidate. Selecting a base remains a reviewed change of `upstream/selected-base.json`. The
carry tool itself is unchanged: its bytes are the ones the sealed report names.

Run it in a scratch clone of the repository at a reviewed revision, whose own selection is still
the base of the report. First verify the candidate's source tree with the source verifier of a
scratch checkout that selects the candidate, so that the tree is authenticated before anything is
read from it. Then:

```sh
python3 -B scripts/proof/grapheneos_export.py export \
  --report upstream/reports/2026081300-2026100600.json \
  --source-root "$CANDIDATE_TREE" --allowed-signers "$PUBLIC_ALLOWED_SIGNERS" \
  --source-evidence "$SOURCE_VERIFICATION/evidence" --scratch "$SCRATCH/export"
```

The scratch must be new or empty, outside the repository's working tree and outside the source
trees. The tool exits 0 when it wrote the candidate, 1 when it refused or failed, and 128 plus the
signal's number when an ordinary termination signal stopped it. Its evidence record is
`evidence/export.json` there, or `evidence/export.fail.json` while `export.json` is absent. Only
if even the first record cannot be written is there none, and then the export wrote nothing in
the checkout. Once the scratch is accepted, every failure ends stderr with a line that names the
record on disk and what it says.

## Steps

1. **The report and records.** This checkout must have no change. The report must lie in
   `upstream/reports/`, and its seal must verify with no drift of the records, ledger, profiles or
   patches it names. Its verdict must be `CARRIED`, with nothing not run. The carry tool here must
   be the one that wrote it, by its digest. Its base is the selected base, and it names both base
   records by their digests.
2. **The specifications.** `grapheneos_carry.load_patch_set` gives the six patches of the selected
   base, validating every profile with its own tool, as the report names them, each at the base
   record's revision of its project. It takes the selected base's release, so it is not a base
   override, and it refuses any other base.
3. **The source tree.** The `result.json` of the candidate's source verification must pass for the
   target's signed manifest and every declared project, with the patched projects at the target
   record's revisions. The tool checks the tree itself too, read only, as
   [`grapheneos_source.py`](grapheneos_source.md) checks its manifest and projects. The manifest
   bytes, commit, tag object and tag target are the target record's, the tag signature verifies
   with the approved allowed signers, and each patched project is a Git worktree at the target
   record's revision without tracked changes.
4. **The pristine files.** Each patch target, each added path and the `FileUtils.java` of the host
   tested record are read at both releases as Git objects of their projects, with
   `grapheneos_source.run`: no lazy fetch, no replace objects and an isolated configuration. Every
   object must be in the project's own object store. A missing object is refused, and nothing is
   fetched. When the candidate tree lacks the selected base's objects, `--base-source-root` names a
   reviewed tree that holds them, read the same way. Every file must be the one the sealed report
   carried: each target by its SHA-256 at both releases, each added path absent at both releases,
   and `FileUtils.java` by the objects of the report's dependency surface.
5. **The carry.** Each patch goes through `grapheneos_carry.carry_patch`, as the carry check
   applies it: a positive control on the selected base, then the target, with the tools' exact
   command at fuzz 0. The payload sync companion starts from both outputs of package verity. Every
   resulting row must equal the sealed report's row, apart from the upstream commits, which come
   from history this offline tool does not read. That covers the patch and profile digests, every
   class and line offset, every check and added path, and every candidate digest. Each patch must
   apply, each target must be identical, changed clean or moved, and the policy review patch must
   agree with its bridge at both releases. Anything else needs a new reviewed patch, not an export.
6. **The candidate's records**, built in this order:
   1. the framework patches, byte for byte, and their profiles: the selected base's profiles with
      the target's revision and each target file's actual upstream and candidate digests. Every
      helper, fixture and fragment they name must keep its digest;
   2. the target's own host tested record,
      `tests/installer-durability/grapheneos-<release>/pis-reverse-write-sync.candidate.json`. It
      names the target's revision and its package verity profile by path and digest, and the
      target's upstream, package verity, combined and `FileUtils.java` digests. The tested source
      ranges of the shared fragments must hold in the target's bytes, and the selected base's
      `FileUtils.java` must have the digest its own record names;
   3. the payload sync profile, naming the target's package verity profile and its host tested
      record by path and digest. Its patch stays identical to the shared host tested patch;
   4. the policy record, naming the target release, its `system/sepolicy` revision, the upstream
      digest and the digest of the bridge. The upstream policy file must be the one
      [`owner_policy.py`](owner_policy.py) pins, and the review patch must reproduce the bridge that
      `grapheneos_carry.policy_bridge` and `owner_policy.patched` both derive. A different upstream
      file needs a reviewed change of that tool, not a new digest. Activation and scope are kept;
   5. a README: the carried provenance, the exact base, the lab only writer and the source only
      qualification.
7. **A check by the candidate's own tools.** In a scratch checkout of this checkout's revision that
   holds the candidate's files and selects the candidate, the checkout's own copies run the
   production format guard, `grapheneos_candidate.py patch-set` and `grapheneos_export.py
   validate`. Their results must name exactly the candidate's records and the carried digests.
8. **Writing.** Every entry under `patches/`, `tests/installer-durability/` and `upstream/` must
   have kept its bytes. The two candidate directories are created, and every file is created
   exclusively in them in the order above. Every directory on the way is opened from the
   checkout's root one component at a time, never through a link. Each directory and file the
   export creates is held open from the moment it is created, and so is each directory on the way
   from the moment the export first reaches it, until the export is done or its rollback
   complete. An object held open keeps its inode, so no object made meanwhile can take its
   identity, even once the held one is removed. Git must list exactly the candidate's files as
   new and nothing else as changed, every old entry must still have its bytes, and the selection
   must still name the selected base. The complete inventory of the two new directories, reached
   the same way, counts every entry, whether Git ignores it or not. It must be exactly the checked
   files, each a regular file with its checked bytes that is the very file the export holds open
   for its path.
9. **Done.** The final evidence record, with that inventory and status `EXPORTED`, is written to
   a temporary file and synced. The failure record on disk is held open and gains a second name,
   `export.fail.json`, the final record is renamed over `export.json`, the directory is synced and
   the record is read back. Only then is the export done, and the second name is dropped.

## Failure and termination

The evidence record is written first, as a failure record: status `FAIL` and the phase the
export is in. It is replaced whole at each phase and at the end, so a reader finds a complete
record, never a part. Until the export is done, a refusal, any other failure, or an ordinary
termination signal (`SIGTERM`, as `timeout` sends it, `SIGINT` or `SIGHUP`) rolls back what the
export created in this checkout, newest first, and records the failure with what it removed and
what it kept. A signal raises only where the export lets it through: during the checks and their
subprocesses, between the files it writes and during the checks after writing. Elsewhere it
waits, so creating and recording a new path, the final record and the rollback are never cut in
two. The handler blocks further signals before it raises, so a second signal cannot cut the
rollback either. A signal ignored on entry, as under `nohup`, stays ignored. A signal that arrives
while the final record is published waits for it, and then ends nothing: the export is done.

The rollback removes only what the export created and still holds open. It reaches each parent
from the checkout's root one component at a time, never through a link, and the parent must still
be the directory the export holds for it, still linked. Relative to that open parent it removes
an entry only while the entry is the very object the export holds open for that path, by device,
inode and type, and that object is still linked. A file must also hold no more than the bytes the
export wrote there, as an interrupted write leaves it, and a directory must be empty. Anything
else is kept and listed under `left`, with its reason under `left_reasons`: another file or
directory put in place of a created one, whatever its bytes, including one made after the
created one was removed, a link put in place of a created directory, which is never followed, a
file someone rewrote, and an entry someone added, with the directory holding it. Every held
object is released once the rollback is complete.

Nothing outside the two new directories is touched while their parents stay where they are. A
directory is held by its descriptor, not by its place: a parent moved outside the repository
after the rollback reached it is still reached there, and the export's own objects in it are
removed, but nothing else. Two brief windows remain as declared limits, not as guarantees, since
no system call creates a directory as an open descriptor or removes a name only while it names a
given inode. A directory moved in under a new directory's name between its creation and its
opening would be taken for the export's own, though the rollback removes such a directory only
once it is empty. An object moved under a created name between the identity check and the
removal could still lose that name. Both need another process to rename an entry into place in
that instant.

Some complete evidence record is on disk at every moment from the first one on, and no record is
removed before another is durably in its place. A call that reports an error may still have done
its work, so after an error from a record's rename or removal the export learns what the call did
from the disk, never from the error. It takes a call's work to be complete when the call returns,
as on a local filesystem.

While the final record is published, the failure record is held open and keeps its second name,
`export.fail.json`. From that moment the final record may be on disk, whatever a call reports.
A failure from then on first makes the failure record durably the record again, from what the
disk shows. If `export.json` still holds it, nothing moves. Otherwise the second name is renamed
back over `export.json`, which needs no new space, or else the final record is withdrawn and
`export.fail.json` is the record. Either happens only while the second name still holds that
very failure record, still linked and with the bytes the export saved. The rollback runs only
once the disk shows the failure record in place and the directory is synced after it, so no
record claims `EXPORTED` for a candidate being removed. Otherwise nothing is renamed or
withdrawn: the final record and the whole candidate stay, and stderr says so.

A reader takes `export.json`, or `export.fail.json` if `export.json` is absent. If this run's
failure record cannot then be written durably, for example on a full evidence filesystem, stderr
says whether it is on disk anyway, though maybe not durably, or was not written. It also says
what the rollback removed and kept, or that the candidate was kept whole. If even the first
record cannot be written, the export stops before it writes anything in the checkout.

`SIGKILL`, a crash or power loss leaves no chance to clean up, and what remains depends on the
moment. Before the final record's rename, the two new directories may hold some of the
candidate's files, and the record says `FAIL` in the `writing` phase and names them under
`staged`. A kill just after that rename leaves `export.json` saying `EXPORTED`, with the
candidate whole, synced and checked as the record says, and `export.fail.json` beside it holding
the failure record it replaced. That record is honest. Its directory was not synced yet, so after
power loss in that moment the failure record of the `writing` phase may be the one found instead.
A kill during a rollback leaves the record of the `writing` phase, as `export.json` or as
`export.fail.json` alone, with part of the candidate. In every case the next export refuses,
because the checkout has changes or a candidate path exists. Review what remains against the
record, and remove the two directories before exporting again. A record that says `EXPORTED` is
renamed into place only after every candidate file was synced and the inventory checked.

The evidence record keeps the tool digests, this checkout's revision, the report's seal, the source
verification, every file read by release, revision, blob and digest, the carried rows with their
offsets, the candidate's digests, the scratch checkout's results, the written files, the final
inventory and the status. After a failure it keeps what the rollback removed and what it kept,
with the reasons. It also keeps the files read, under `inputs/`. It is private evidence, not a
project file.

The tool never applies or reverts a patch in a source tree, never runs a patch tool's `apply` or
`revert` action, and never syncs, fetches or builds. Patches are applied only to private copies in
its scratch, as the carry tool applies them.

## Validate

```sh
python3 -B scripts/proof/grapheneos_export.py validate --inputs "$UPSTREAM_FILES"
```

`validate` checks the selected base's patch set against upstream files given as
`<project>/<path>`. Each patch tool checks its own profile and derives its candidate from those
files: `native_principal_pins.targets`, `android_lifecycle.targets`, `package_verity.candidate`,
`package_installer_payload_sync.derive` and `native_identity_writer.targets`. The payload host
tool reads both Package Installer states with `inspect_bytes`, as its command does for a tree. The
policy record must name the bridge that `owner_policy.patched` derives and its review patch
reproduces. It reports the digests each tool derived. Run in this repository it checks the
selected base; the export runs a scratch checkout's own copy for the candidate.

## Limits

This is a source step. A written candidate still needs its commit and a `PASS` of
[`grapheneos_candidate.py check`](grapheneos_candidate.md) against the candidate's tree, and the
payload host tool's check on scratch copies of the two Package Installer states. No build, boot or
runtime result follows from an export. The export carries patches that apply at fuzz 0 with the
offsets the sealed report shows. It writes no new patch: a conflict, an overlap or a failed check
needs a reviewed patch and new evidence. Only the payload host tested record is kept per base. Its
patch and source fragments serve every base, so the export refuses a target whose tested source
ranges differ.

Tests use fixture Git projects in scratch, with a signed fixture manifest and a fixture repository
whose records name them: `python3 -B -m unittest scripts/proof/tests/test_grapheneos_export.py`.
They run each refusal, and each fault late in an export, beside an honest twin: a full evidence
filesystem at the first or the final record, a record failure just after the final record's
rename, once or with no record replaceable from then on, and with the failure record's second
name gone too, `SIGKILL` just after that rename, a termination signal through `timeout` or
another signal, another entry in the candidate directories, a created file or directory replaced
by another one, whatever its bytes, or by a link to the selected base's patches, a created file
removed and made again, and a parent replaced while writing. The export cases need the public
upstream files of the patch targets at both bases. Name local copies with `ANDRIX_CARRY_FILES`
(`2026081300=DIR:2026100600=DIR`, each `DIR` holding `<project>/<path>` files of that release).
Without it those cases skip.
