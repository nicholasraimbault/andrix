# GrapheneOS release carry check

`grapheneos_carry.py` reports how a GrapheneOS release relates to Andrix's recorded base.
It needs no source tree and leaves the pinned tree untouched. It does not change any patch,
profile or patch tool. The exact pins those tools check stay the gate for what may be built.
This check makes the distance to upstream visible between those decisions.

```sh
TRUST=/path/to/allowed_signers   # the public file grapheneos_source.py pins by digest
python3 -B scripts/proof/grapheneos_carry.py record --tag 2026100600 \
  --allowed-signers "$TRUST" --scratch "$SCRATCH/record" --out upstream/bases/2026100600.json
python3 -B scripts/proof/grapheneos_carry.py ledger --base upstream/bases/2026081300.json \
  --base upstream/bases/2026100600.json --scratch "$SCRATCH/ledger" \
  --out upstream/ledger/frameworks-base.json
python3 -B scripts/proof/grapheneos_carry.py check --base upstream/bases/2026081300.json \
  --target-tag 2026100600 --target-record upstream/bases/2026100600.json \
  --allowed-signers "$TRUST" --ledger upstream/ledger/frameworks-base.json \
  --scratch "$SCRATCH/check" --out upstream/reports/2026081300-2026100600.json
python3 -B scripts/proof/grapheneos_carry.py status upstream/reports/2026081300-2026100600.json
```

`record --verify FILE` derives the record again and compares it. `verify REPORT` checks a
sealed report and names any referenced file that changed since it was written. It exits 0
when nothing changed, 2 when something did and 1 when the seal fails.

## Sources and trust

- **Signed tags.** The manifest tag is fetched alone at depth 1 and checked with real
  `git verify-tag`. It uses the allowed signers file whose digest `grapheneos_source.py`
  pins. The signed tag object must name the requested release and the commit that
  `git ls-remote` reports. For the pinned release, the record must also agree with that
  verifier's constants and its project parser.
- **Single objects.** Trees and blobs are fetched one object at a time by ID. The fetch uses
  `--filter=tree:0` and the `noop` negotiation algorithm, so the server sends exactly the
  wanted object. Every file is bound by object IDs to the signed manifest. GitHub serves
  these. Gitiles does not serve trees by ID. A file in an AOSP hosted project is fetched by
  raw path and checked against its listed blob ID.
- **Commit metadata.** A range is fetched without trees. It is bounded by `--shallow-exclude`
  of the GrapheneOS release tag or by `--shallow-since` the range's base commit. It is never
  bounded by depth, because AOSP history below a release is merge heavy. A range that does
  not reach its base is reported as not run, not guessed.
- **Documents.** Bulletins, Gitiles JSON, Gitiles diffs and the release notes are trusted over
  HTTPS from a fixed host list. Each is recorded with the digest of what was extracted from it.

Git runs with the source verifier's isolated environment. It uses https only, no lazy fetch,
a size limit for each file and a scratch budget. The scratch must be outside the repository
and must be new or empty. Rate limits, network failures and budget overruns end with
`NOT_RUN` (exit 3). Verification failures end with `FAIL` (exit 1). `check` exits 0 when
every patch carries clean or moved. It exits 2 when it wrote a report with an overlap, a
conflict or a missing target.

## Records

A base record holds the tag object, manifest commit, manifest blob and digest. It also holds
the allowed signers digest, the AOSP default revision, the project table digest and count,
and the security patch level. It ends with the kernel prebuilt revisions and the revisions of
the projects Andrix patches. The patch level is resolved for the product's lunch release in
`AndroidProducts.mk`, through build/release aliases and inheritance. A competing definition
fails rather than being chosen.

The project table is the canonical JSON list of path, name, remote, revision, groups and
copyfile or linkfile rows, sorted by path. It is independent of manifest formatting.

## Carry classes

Each patch is applied in private scratch with the tools' exact command,
`/usr/bin/patch --batch --forward --fuzz=0 --no-backup-if-mismatch -p1`. It is first applied
to its own base as a positive control. That control must reproduce the pinned candidates and
pass the tool checks. Candidates are recorded only when every hunk applied. The owner session
policy is applied with `owner_policy.py`'s anchored replacement, as that tool applies it. Its
zero context review record is applied with the exact command to show whether it still agrees.

| Class | Meaning |
|---|---|
| identical | The target bytes equal the base. The candidate equals the pinned one. |
| changed clean | The file changed. Every hunk applied at its reviewed line. |
| moved | The file changed. Some hunk applied at a line offset. |
| overlap | It applies at fuzz 0, but upstream edited near a hunk, in a Java member a hunk edits, or in a host tested fixture, fragment or method. |
| conflict | A hunk failed or was already applied. Upstream may also have added a file at an Andrix added path. |
| missing | The target file or its project is absent at the target. |

Near means within 3 lines of a hunk. The member parser is approximate. No overlap is not a
semantic proof. A renamed upstream file shows as missing. Fuzz 0 still accepts line offsets.
Moved therefore means a hunk landed at a line other than the reviewed one. The candidate
digests pin positions.

The tool rechecks what the patch tools check, without modifying them. These are the native
principal fixtures and fragments, the extracted CE methods, the package verity methods and the
payload sync host fragments.

## Dependency surface

[`upstream/surface.json`](../../upstream/surface.json) declares watched projects and two
lists of paths. A path may be a file or a directory compared by tree ID.

- `paths` are what Andrix builds against. These are the upstream classes behind Andrix's host
  stubs and imports, the policy macros and contexts Andrix's policy builds on, and product
  composition.
- `runtime` is code that Andrix's runtime trials and plans exercise but that Andrix neither
  patches nor imports. Each row cites a file and line in this repository and a term that line
  contains. The tool refuses a row whose citation does not hold.

Every path must exist at the base. A changed project's paths are compared by object ID.
Changed Java files report added and removed member signatures, which host stubs would hide.

## Security ledger

The ledger covers frameworks/base, keyed by Change-Id. Its sources are these.

- The Android security bulletins since the AOSP base month.
- The AOSP `android<N>-security-release` log, with changed paths.
- GrapheneOS commits from the AOSP base to each base record, with their trailers.
- The GrapheneOS preview CVE lists, marked as not public source.

Each fix is also checked by content. Its own diff comes from its AOSP security branch commit,
as one Gitiles object, or from its GrapheneOS commit, rebuilt from single Git objects. The
diff is tried against each base's files in scratch with the patch tools' command plus
`--dry-run`, forward and in reverse. A clean reverse run for every file means present. A clean
forward run for every file means absent. Anything else is unresolved and is never guessed. A
diff that applies both ways is ambiguous and so unresolved. Binary, renamed and mode only file
sections are listed and not checked.

The first evidence that applies decides the status, in this order. The method that decided
is recorded with the status.

1. A GrapheneOS commit with the Change-Id is reachable from the base revision. The fix is
   present by `change_id`.
2. The content check finds the change. The fix is present by `content`. This also finds a fix
   that was already in the AOSP base.
3. [`upstream/backports.json`](../../upstream/backports.json) declares an Andrix patch for it.
   The fix is backported by `backport`.
4. A GrapheneOS commit names the Change-Id in `Merged-In`, or carries one of its CVEs under
   another Change-Id. The fix is backported by `merged_in` or `cve`.
5. The content check finds the change absent. The fix is absent by `content`.
6. The Change-Id lands only in a later base. The fix is absent by `change_id`.
7. Otherwise the fix is unresolved.

The content check also runs where another method decided. Where it contradicts that method,
the ledger lists a disagreement. Where it is unresolved, the ledger lists the case as
unconfirmed. Neither is resolved silently. Preview lists are OS wide and have no public
commit. Their fixes are absent from every public base by necessity. A same subject match for
an absent fix is a review hint, never a status.

## Limits

These are source facts only. No build, boot or runtime result follows. The existing patch
tools still refuse a new base until a reviewed patch directory exists for it. Security preview
fixes and emulator kernel fixes cannot be carried from public source.

Tests use recorded public fixtures and local Git repositories only:
`python3 -B -m unittest scripts/proof/tests/test_grapheneos_carry.py`. One test compares the
committed base record with a local pinned tree when `ANDRIX_GRAPHENEOS_ROOT` names it.
