# Unix lifetime observations

A focused Linux host fixture for the [work supervision design and matrix](../../plans/2026-09-16-unix-work-supervision.md).
It tests real kernel and selected shell behavior before choosing an Andrix supervisor.
It does not implement that supervisor or prove Android authority/cleanup.

## Components

- `lifetime_probe.cpp` uses real PTYs, sessions, fork, signals and control sockets. It
  links the actual owner worker filter, rather than a simulated syscall permission result.
- `probe.py` runs one isolated experiment as a private child subreaper. It creates only
  its own fixture processes, captures pidfds and uses bounded readiness/response handshakes.
- `scripts/proof/tests/test_unix_work_lifetime.py` compiles the helper with warnings as
  errors and runs ten cases. Bash and GNU nohup versions are checked and can be recorded.

The Python supervisor is a host tool. The helper's use of Linux syscalls does not imply
that an Android binary has been compiled, installed or executed. The Android mksh source
has its own option/job handling; Bash is a comparison, not a replacement shell selection.

## Cases and design relevance

| Case | Observation required |
| --- | --- |
| `pty_hangup` | Closing the last PTY master produces actual SIGHUP termination of the controlled session leader. |
| `last_master` | Closing one duplicate does not close the terminal: positive ping and real output still work. Last close then produces SIGHUP. |
| `ignored_hup` | Ignoring SIGHUP preserves the process, not its dead terminal transport. A later PTY write reports EIO. |
| `parent_exit` | An ordinary native child survives parent exit and is adopted by the private subreaper. The parent's parent-death signal is cleared by fork. |
| `setsid_scope` | A child creates another Unix session, redirects streams and survives root exit/hangup, but its observed cgroup membership remains the same. |
| `bash_hangup` | A tracked background job with default HUP disposition ends when the selected interactive Bash loses its real PTY. |
| `bash_nohup` | GNU nohup establishes inherited SIG_IGN; the child and redirected output survive shell hangup. |
| `bash_disown` | Removing the job from the shell job table permits survival here without changing its default HUP disposition. |
| `bash_exit` | An explicitly configured nonlogin Bash with huponexit off exits normally without terminating this background job. |
| `bash_login_exit` | An explicitly configured login Bash with huponexit on terminates this background job on exit. This is not an Andrix default. |

The shell is invoked through exact argv with `--noprofile --norc --noediting -i -c`,
plus `--login` only for the last case. The command enables job control and explicitly
sets huponexit. Standard job streams are redirected. No owner shell configuration is
loaded. The shell acknowledges its job-table/disown setup on a private pipe; the worker
independently connects and reports readiness before the action is triggered.

Host observations have exercised all ten cases with GNU Bash 5.2.37 and GNU coreutils
nohup 9.7. These results do not define every shell's behavior. For a child the shell has
already reaped, pidfd readability establishes exit, not the unavailable wait status.
The fixture records that distinction instead of inventing a status.

## Fixture correction

Early attempts failed in login-shell setup before the lifetime action. A syscall trace
showed the selected login shell marking inherited auxiliary FDs close-on-exec, including
an attempted explicit duplication. Therefore an inherited test observer could disappear
without proving anything about job lifetime. The corrected job establishes its private
Unix control connection after exec; the supervisor checks actual peer credentials.
The failed attempts remain separate evidence. This did not change the production shell
or weaken a lifetime assertion. Supplying setup through argv also avoids terminal input
before shell initialization.

## Bounds and cleanup

Each case has bounded messages and observation deadlines. Readiness/survival requires a
positive message or a real wait result, never sleeping and assuming readiness. Native
workers have an independent alarm. Whole experiments have a separate parent timeout.

Cleanup signals captured pidfds, never a guessed external process group. Setup failures
can leave children not yet announced; only direct unreaped children of this private
subreaper are then collected. Those PIDs remain pinned until this fixture reaps them.
Successful cases require `ECHILD` after all private children have exited and been reaped.
Run these tests under the project's owned cgroup/resource limits and heavy-work guard so
an outer interpreter failure also has a bounded cleanup boundary.

This fixture cleanup is not the product's complete Android work Stop. It neither writes
cgroup controls nor tests cgroup escape prevention. Comparing `/proc/self/cgroup` through
a bounded fingerprint is a membership observation, not a security proof. Host pidfds,
TTY behavior, seccomp and subreaping do not establish Android UID/SID, user/CE authority,
Binder freshness, resource admission, storage durability or phone behavior.

## Running

Within the admitted, bounded host test job:

```sh
python3 -B -m unittest -v scripts.proof.tests.test_unix_work_lifetime
```

To retain per-case JSON observations, tool versions, stderr and exit status, set
`ANDRIX_LIFETIME_PROOF_RESULTS_DIR` to a new external evidence directory. It must not
already exist. The fixture refuses to overwrite results. Do not append to a sealed
attempt or convert fixture setup failure into a product pass.
