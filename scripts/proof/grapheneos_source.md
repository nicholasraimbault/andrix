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
HEAD and staged/tracked cleanliness. Git runs with the restricted execution
profile below; project checks are bounded to eight concurrent readers. Results go
into a **new** evidence
directory outside the project/source trees; an existing directory is never
replaced. A line-buffered `projects.jsonl` records each completed project check;
an interrupted ledger is not a final PASS. Inputs and errors can contain private
operator paths; keep raw evidence outside public Git.

This public manifest already omits the old direct-AOSP Darwin `notdefault`
projects. All **1,108** declarations belong to this M1 selection. Do not subtract
three from it because an older manifest had those exclusions. The parser rejects
unexpected include/submanifest or excluded-group structures for this exact
pinned generation. Advancing the generation requires an explicit pin review.

`repo list -p` alone is not a completeness oracle: it reflects initialized project
metadata, not necessarily completed worktrees/HEADs. The primary observed 53 during
an early sync, then all 1,108 while several large checkouts were still absent.
`repo list -a -p` / explicit default-Linux selection exposes the intended set.
This helper derives the whole expected set from the authenticated manifest and
reports every missing project as failure, not as an excluded group.

## Git execution boundary

Ordinary Git diff/status commands are not automatically read-only. A synthetic
fixture demonstrated that the original `--no-optional-locks` profile could execute
a clean filter, write its marker, and normalize a changed file into a clean result.
That finding corrects the earlier broad read-only claim; it is not evidence that
such a callback ran against the actual platform checkout.

The corrected profile:

- Removes inherited `GIT_*` overrides and ignores system/global Git configuration
  and external attribute files. Repo's local worktree/object-store layout remains.
- Disables fsmonitor, hooks, automatic maintenance, paging and replace refs.
- Uses `--no-lazy-fetch` and an empty transport allowlist. Missing local objects
  fail rather than causing an implicit fetch. Git must support this flag (tested
  with 2.47.3); unsupported options fail closed.
- Enumerates local filter-driver configuration without running it, then disables
  clean/smudge/process commands and required-filter behavior **for each diff
  invocation only**. No Git configuration file is rewritten. Unsupported override
  key shapes fail before a diff. External diff/textconv execution is also disabled.

This does not normalize expanded LFS data by invoking `git-lfs` or add a permissive
content exception. An unchanged pointer is not materialization proof; an expanded
form that differs without its external filter fails closed. Such an exception is
not needed for the inspected 1,108-project anchor. Built-in Git conversions remain
Git behavior; this is not a replacement byte-by-byte filesystem auditor.

Use a stable, owner-controlled checkout and configuration for the observation;
this process-level profile is not an OS sandbox against concurrent filesystem or
configuration replacement. Signature verification may use temporary files and
the verifier writes its new evidence directory, not source changes.

`PASS_PINNED_SOURCE_HEADS` means all declared projects match and tracked source is
clean under this profile. It **does not** audit untracked files, materialize/verify
Git LFS or other prebuilts, authenticate proprietary inputs, establish buildability
or establish runtime/security behavior. Those remain separate M2/artifact gates.
It also does not prove source remained unchanged after observation: repeat it at
the relevant build checkpoint and preserve any intended adaptation separately.

Tests include mocked Git results for pin/selection/error paths and real temporary
Git repositories with clean/process/fsmonitor/diff sentinels, injected global
configuration, pointer/expanded-content controls and a missing promisor object.
The missing-object negative leaves the object store unchanged; a deliberate
local-file positive control confirms that the fixture could fetch otherwise.
No Internet or active platform checkout is used by these tests. M0's real SSH
positives/negatives and the full source-tree run remain separate evidence.

A task-local short `TMPDIR` may be needed by **Repo sync**, whose Python
multiprocessing sockets have an AF_UNIX path-length limit. The observed first sync
failed before network progress under a deeply nested inherited temp path; a short
owned directory fixed that without modifying Repo or its verification rules.
This helper itself does not run `repo sync` or manufacture any socket.
