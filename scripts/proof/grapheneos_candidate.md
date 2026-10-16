# Candidate GrapheneOS base check

`grapheneos_candidate.py` checks a GrapheneOS base before it is selected. The repository selects
one base in [`upstream/selected-base.json`](../../upstream/README.md), and every tool builds on
it. A candidate base's patch directory, `patches/grapheneos-<release>/`, can sit beside the
selected base's while the candidate is prepared. Production never reads it. This tool checks it
on its own, in a scratch checkout whose own selection names the candidate. No production tool
takes an argument that selects another base, so nothing builds on an unselected base by accident.

```sh
python3 -B scripts/proof/grapheneos_candidate.py check --release 2026100600 \
  --source-root "$CANDIDATE_TREE" --allowed-signers "$PUBLIC_ALLOWED_SIGNERS" \
  --scratch "$SCRATCH/candidate-2026100600"
```

## Steps

1. It archives one revision of the repository, `HEAD` unless `--revision` names another, into
   `checkout/` in a new or empty scratch directory. The scratch must be outside the repository's
   working tree and outside the source tree. Every file of the checkout must have its blob ID,
   and the checkout holds no other file. A revision with a link or a submodule is refused. The
   candidate's base record and patch directory must be committed at that revision.
2. It writes the checkout's own `upstream/selected-base.json`: the candidate's release, its record
   in `upstream/bases/` and the SHA-256 of that record's bytes.
   [`grapheneos_base.py`](grapheneos_base.py) must accept that selection. The tool refuses to
   write a selection into the repository's working tree or into any other Git checkout.
3. It runs each check with the checkout's own copy of its tool, so each reads the candidate's
   selection:
   - the production format guard, `native_creation_binding.py --format-guard-only`, over the
     candidate's patch directory;
   - the exact patch set check, `grapheneos_candidate.py patch-set`, over the same directory;
   - the [source verifier](grapheneos_source.md), against the candidate's tree;
   - the read only `check` action of each patch tool against that tree: `android_lifecycle.py`,
     `package_verity.py`, `package_installer_payload_sync.py`, `native_principal_pins.py`,
     `native_identity_writer.py` and `owner_policy.py`.
4. It compares the policy record with the policy tool's reading of the tree. The upstream and
   adapted digests the record names must be those of the tree's policy file and of the bridge
   the tool derives from it. This runs only when the patch set and the policy tool checks pass.
5. It reports each result and writes `report.json`, with each check's output under `evidence/`.
   The verdict is `PASS` only when every check passes. The tool exits 0 on `PASS` and 1
   otherwise.

The tool reads the repository's own selection before and after, and refuses if it changed. It
never applies or reverts a patch, syncs or builds. Selecting a base remains a reviewed change of
`upstream/selected-base.json`. Run on the selected base and its own tree, the same procedure is
a control of the candidate's result.

## The exact patch set

`grapheneos_candidate.py patch-set` checks the selected base's patch set without a source tree.
Run in this repository it checks the selected base. Run by a scratch checkout's own copy, it
checks the candidate.

- The patch directory holds exactly the six patches, each beside its profile, and at most a
  `README.md`, all regular files. A missing patch or profile, another file, a link or a nested
  directory is refused.
- The owner session policy record names the selected base, that base's `system/sepolicy`
  revision, the policy file, the upstream digest `owner_policy.py` pins, an adapted digest and
  its review patch beside it by that patch's digest. The policy tool itself reads neither the
  record nor the review patch, so only this check holds them to the base.
- The carry tool's own loader, `grapheneos_carry.load_patch_set`, then checks the same inventory,
  validates every other profile with its own tool and checks the policy record again. A patch
  set passes only if the carry tool accepts it.

## The production guard's scope

The format guard reads the selected base's patch directory as production, and the AOSP track
`patches/android-17.0.0_r1/` of `aosp_patches.py`, which follows no GrapheneOS base. Every other
`patches/grapheneos-<release>/` directory of a base recorded in `upstream/bases/` belongs to a
candidate, and the guard does not read it. Anything else under `patches/` is refused: another
directory, a tag of another form, a release without a base record, a link, a nested directory
and any file but a patch, its JSON record or a README. Both production directories must exist.
The AOSP track must hold the patch that its `series.json` names, so removing or emptying the
track refuses rather than leaving its texts out of the guard.

## Limits

A pass is a source check of one revision against one tree. It is not a build, boot or runtime
result. The source verifier still pins the approved allowed signers digest and the local Repo
tool revision, so a tree synced with another Repo tool revision is refused until that pin is
reviewed. The payload sync profile pins its verity profile through a host tested record in
`tests/installer-durability/` that it shares with the selected base, so a candidate's payload
profile passes only once that record follows the candidate. This check holds the policy review
patch to its digest. The carry check is the one that applies it to the upstream policy file.
The format guard needs no Git history, so it runs in the archive. The other source checks of the
B1 and B2 runners read pinned Git objects of their images, which stay on the selected base, and
are not run here.

Tests use a fixture repository and an empty source tree:
`python3 -B -m unittest scripts/proof/tests/test_grapheneos_candidate.py`.
