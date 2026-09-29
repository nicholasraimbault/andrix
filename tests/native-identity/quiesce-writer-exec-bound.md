# Experimental executable bound quiesce helper

`quiesce_writer_exec_bound.c` is separate from `quiesce_writer.c`. It does not
replace the earlier helper or its evidence. It is a lab tool, not a production
service, native work stop implementation or UID retirement mechanism.

The interface is:

```
helper inspect PID NONCE EXPECTED_STARTTIME EXPECTED_BOOT_ID EXPECTED_HELPER_SHA256
helper stop    PID NONCE EXPECTED_STARTTIME EXPECTED_BOOT_ID EXPECTED_HELPER_SHA256
```

Both modes require root. The nonce is 32 lowercase hex characters. The expected
SHA256 is 64 lowercase hex characters. The helper captures a live PMS PID descriptor
and proc directory. UID, domain, process name, boot ID and start time must match.
It also captures its own process incarnation and running executable descriptor.
The file must be a single linked root owned 0700 ELF64 AArch64 executable, at most
1 MiB, with `/system/bin/linker64` as its sole interpreter.

Before any stop, the fixed `/system/bin/sha256sum` hashes `/proc/PID/exe` for the
helper's actual PID. The result must match the expected digest. Descriptor,
metadata, incarnation and target liveness checks bookend that operation. The child
has a captured PID descriptor, bounded output, checked exit and parent death
handling. Stderr, malformed output, unavailable tooling and timeouts refuse. The
helper restores default SIGCHLD handling so an inherited automatic reap policy
cannot invalidate its child ownership checks. It does not defer owner Stop signals.

The captured acknowledgement includes actual helper PID, start time, boot ID,
digest, executable device, inode and size. Stop proceeds through a gated child only
after the target and child descriptors are captured. Its final acknowledgement
requires the captured PMS exit and stopped zygotes. The overall budget is 30 seconds,
including verification and cleanup. Unconfirmed child retirement or partial stop
requires whole lab scope closure. No retry is implied.

## Harness obligations

Create and verify a fresh root owned 0700 nonce directory before uploading a helper.
ADB push may expand permissions. Explicitly set the uploaded file's owner and mode,
then check its bytes, size, ELF and context before execution. Compare the acknowledgement
with independently captured device, inode and size, and check metadata again after exit.
Self hashing is a consistency check, not independent attestation against a malicious
helper or kernel.

Never execute a retained helper after a cold boot. Same boot inspect and stop may use
the same checked file. All uploads and setup syncs must precede the native writer
sequence. A later stop is not permission for a post write upload, sync or mode repair.
Use a command timeout greater than 30 seconds plus transport margin. Preserve uncertain
outcomes and the original request.

## Qualification

`test_exec_bound.py` requires an actual bounded cgroup before compiling. It runs real
host executable hashing, incarnation, malformed output, stderr, exit, timeout, child
reaping, descriptor count, inherited SIGCHLD, ELF metadata and parent death controls.
`QUIESCE_EXEC_TEST` permits only the fixed host SHA tool and x86_64 interpreter. Test
modes cannot compile for Android. `NDEBUG` is refused.

Host controls and Android compilation are not Android execution. The admitted lab
producer was separately inspected, then its first Android inspect and stop executions
matched running executable and PMS incarnation observations. That scoped result does
not qualify arbitrary future builds or staging paths. Native work, Android data and
keystore retirement remain outside this helper's claim.
