// SPDX-License-Identifier: Apache-2.0
#ifndef ANDRIX_TRACE_ACCESS_H
#define ANDRIX_TRACE_ACCESS_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int complete;
    int error;
} AndrixTraceAccess;

// Linux/Bionic syscall probe, not by itself evidence of Android MAC policy.
// target > 0: the caller supplies a known-live external target and keeps its
// identity/liveness stable for the call. No target memory access or signals.
// target == 0: a fresh tracer seizes its own disposable child (positive control).
// Negative targets, PID1 and the caller's own PID are invalid.
//
// complete == 1: SEIZE returned error (0 means success), and the tracer exited
// and was reaped. ESRCH is a missing target, NOT an access denial. A denial needs
// independently verified live/identity controls and policy evidence.
// complete == 0: invalid input or infrastructure/cleanup failure; error is errno.
//
// The caller must retain exclusive reaping ownership of this call's children:
// SIGCHLD must be default, without SA_NOCLDWAIT; no concurrent child reaper or
// disposition changes. The helper does not change the caller's signal settings,
// credentials, dumpability or tracing permissions. Normal userspace waits total
// at most five seconds, excluding scheduling/kernel stalls. Even SIGKILL cannot
// promise bounded reaping of a task stuck in the kernel; such a result is incomplete.
AndrixTraceAccess andrix_trace_access(pid_t target);

#ifdef __cplusplus
}
#endif

#endif
