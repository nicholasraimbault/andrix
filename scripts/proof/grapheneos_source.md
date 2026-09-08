# Pinned GrapheneOS source verifier

`grapheneos_source.py` is a read-only M1 check for the exact public migration
anchor `2026081300`. It does not sync, fetch, reset, apply patches, change trust,
run Repo project hooks, build images or authorize a phone operation.

```sh
python3 -B scripts/proof/grapheneos_source.py \
  --source-root "$GRAPHENEOS_ROOT" \
  --allowed-signers "$PUBLIC_ALLOWED_SIGNERS" \
  --evidence-dir "$EVIDENCE/new-source-check"
```

The explicit public allowed-signers file must match the trust-input digest
recorded by M0. The helper verifies the exact signed manifest/tag/commit and the
pinned Repo tool, invokes real `git verify-tag` with the approved file, rejects
local manifest/group overrides, then checks each expected project's worktree,
HEAD and staged/tracked cleanliness. Git optional locking is disabled; project
checks are bounded to eight concurrent readers. Results go into a **new** evidence
directory outside the project/source trees; an existing directory is never
replaced. Inputs and errors can contain private operator paths; keep raw evidence
outside public Git.

This public manifest already omits the old direct-AOSP Darwin `notdefault`
projects. All **1,108** declarations belong to this M1 selection. Do not subtract
three from it because an older manifest had those exclusions. The parser rejects
unexpected include/submanifest or excluded-group structures for this exact
pinned generation. Advancing the generation requires an explicit pin review.

`repo list -p` alone is not a completeness oracle: it can list only the worktrees
already present. The primary observed 53 during an early sync and 1,108 with
`repo list -a -p` / explicit default-Linux selection. This helper derives the whole
expected set from the authenticated manifest and reports every missing project
as failure, not as an excluded group.

`PASS_PINNED_SOURCE_HEADS` means all declared projects match and tracked source is
clean at observation. It **does not** audit untracked files, materialize/verify
Git LFS or other prebuilts, authenticate proprietary inputs, establish buildability
or establish runtime/security behavior. Those remain separate M2/artifact gates.
It also does not prove source remained unchanged after observation: repeat it at
the relevant build checkpoint and preserve any intended adaptation separately.

Tests use explicit mocked Git results and filesystem fixtures for mismatched
manifest/trust/tool/project revisions, missing projects, wrong worktree mapping,
staged/tracked changes, malformed paths, local/group overrides, signature failure
and evidence-directory protection. M0's real SSH-signature positives/negatives
and the actual final-tree run are separate evidence, not supplied by these mocks.

A task-local short `TMPDIR` may be needed by **Repo sync**, whose Python
multiprocessing sockets have an AF_UNIX path-length limit. The observed first sync
failed before network progress under a deeply nested inherited temp path; a short
owned directory fixed that without modifying Repo or its verification rules.
This helper itself does not run `repo sync` or manufacture any socket.
