// SPDX-License-Identifier: Apache-2.0
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "trace_access.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

enum { TICK_MS = 10, PROBE_POLLS = 200, CLEANUP_POLLS = 100 };

static AndrixTraceAccess failure(int error) {
    AndrixTraceAccess result = {0, error};
    return result;
}

// One atomic, nonblocking pipe write, then exit immediately. In particular, an
// external target is detached by tracer exit, not DETACH/INTERRUPT or a signal.
static void finish(int fd, AndrixTraceAccess result) {
    ssize_t count = write(fd, &result, sizeof(result));
    _exit(count == (ssize_t)sizeof(result) ? 0 : 125);
}

static int receive(int fd, AndrixTraceAccess *result) {
    // Both writers use a single record smaller than PIPE_BUF. Reject short,
    // oversized and absent records rather than interpreting them as denials.
    unsigned char bytes[sizeof(*result) + 1];
    for (unsigned n = 0; n < PROBE_POLLS; ++n) {
        ssize_t count = read(fd, bytes, sizeof(bytes));
        if (count >= 0) {
            if (count != (ssize_t)sizeof(*result)) {
                errno = EPROTO;
                return -1;
            }
            memcpy(result, bytes, sizeof(*result));
            if ((result->complete != 0 && result->complete != 1) ||
                result->error < 0 || (!result->complete && !result->error)) {
                errno = EPROTO;
                return -1;
            }
            return 0;
        }
        if (errno != EAGAIN && errno != EINTR) return -1;
        struct pollfd event = {fd, POLLIN, 0};
        if (poll(&event, 1, TICK_MS) < 0 && errno != EINTR) return -1;
        if (event.revents & POLLNVAL) {
            errno = EBADF;
            return -1;
        }
    }
    errno = ETIMEDOUT;
    return -1;
}

static int wait_bounded(pid_t child, int *status, unsigned polls) {
    for (unsigned n = 0; n < polls; ++n) {
        pid_t found = waitpid(child, status, WNOHANG);
        if (found == child) {
            if (WIFEXITED(*status) || WIFSIGNALED(*status)) return 0;
            // A ptrace stop is not a reap, even without WUNTRACED.
            errno = EPROTO;
            return -1;
        }
        if (found < 0 && errno != EINTR) return -1;
        if (poll(NULL, 0, TICK_MS) < 0 && errno != EINTR) return -1;
    }
    errno = ETIMEDOUT;
    return -1;
}

// Only ever passed a freshly forked, exclusively owned child, never target.
// Check for an already-dead/reaped child before using its numeric PID. Exclusive
// reaping ownership (see header) keeps an unreaped child's PID from being reused.
static int cleanup(pid_t child) {
    int status = 0;
    pid_t found = waitpid(child, &status, WNOHANG);
    if (found == child && (WIFEXITED(status) || WIFSIGNALED(status))) return 0;
    if (found < 0 && errno != EINTR) return -1; // Especially ECHILD: do not kill.
    if (kill(child, SIGKILL) < 0 && errno != ESRCH) return -1;
    return wait_bounded(child, &status, CLEANUP_POLLS);
}

static int protect_child(pid_t parent) {
    // Do not run inherited application signal handlers in these fork-only
    // children. SIGKILL/PDEATHSIG remains effective with this mask.
    sigset_t blocked;
    if (sigfillset(&blocked) < 0 || sigprocmask(SIG_SETMASK, &blocked, NULL) < 0 ||
        prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) < 0) return -1;
    // Covers death before PR_SET_PDEATHSIG, which is not inherited across fork.
    if (getppid() != parent) {
        errno = ECHILD;
        return -1;
    }
    return 0;
}

static AndrixTraceAccess owned_control(int report) {
    int ready[2];
    if (pipe2(ready, O_CLOEXEC | O_NONBLOCK) < 0) return failure(errno);
    pid_t tracer = getpid();
    pid_t owned = fork();
    if (owned == 0) {
        close(ready[0]);
        close(report); // Never keep the parent/tracer report channel alive.
        if (protect_child(tracer) < 0) finish(ready[1], failure(errno));
        const AndrixTraceAccess message = {1, 0};
        if (write(ready[1], &message, sizeof(message)) != (ssize_t)sizeof(message))
            _exit(125);
        close(ready[1]);
        // A disposable live target, with no stop or TRACEME special case. The
        // tracer normally kills/reaps it; PDEATHSIG covers tracer death/timeout.
        // A finite lifetime is a further fallback, not our cleanup mechanism.
        poll(NULL, 0, (2 * PROBE_POLLS + CLEANUP_POLLS) * TICK_MS);
        _exit(0);
    }
    int error = errno;
    close(ready[1]);
    if (owned < 0) {
        close(ready[0]);
        return failure(error);
    }
    AndrixTraceAccess result;
    if (receive(ready[0], &result) < 0) result = failure(errno);
    close(ready[0]);
    if (result.complete) {
        // No options, especially no EXITKILL; no memory reads, stops or signals
        // are needed to measure this access decision.
        result.error = ptrace(PTRACE_SEIZE, owned, NULL, (void *)0) < 0 ? errno : 0;
    }
    // Finish all work on our OWN target before reporting and exiting the tracer.
    if (cleanup(owned) < 0) result = failure(errno);
    return result;
}

AndrixTraceAccess andrix_trace_access(pid_t target) {
    pid_t caller = getpid();
    if (target < 0 || target == 1 || target == caller) return failure(EINVAL);
    struct sigaction action;
    if (sigaction(SIGCHLD, NULL, &action) < 0) return failure(errno);
    if (action.sa_handler != SIG_DFL || (action.sa_flags & SA_NOCLDWAIT))
        return failure(EINVAL);

    int report[2];
    if (pipe2(report, O_CLOEXEC | O_NONBLOCK) < 0) return failure(errno);
    pid_t tracer = fork();
    if (tracer == 0) {
        close(report[0]);
        if (protect_child(caller) < 0) finish(report[1], failure(errno));
        AndrixTraceAccess result;
        if (target == 0) {
            result = owned_control(report[1]);
        } else {
            result.complete = 1;
            result.error = ptrace(PTRACE_SEIZE, target, NULL, (void *)0) < 0 ? errno : 0;
        }
        finish(report[1], result);
    }
    int error = errno;
    close(report[1]);
    if (tracer < 0) {
        close(report[0]);
        return failure(error);
    }

    AndrixTraceAccess result;
    int received = receive(report[0], &result);
    error = errno;
    close(report[0]);
    int status = 0;
    if (received == 0 && wait_bounded(tracer, &status, PROBE_POLLS) == 0) {
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return failure(EPROTO);
        return result;
    }
    if (received == 0) error = errno;
    if (cleanup(tracer) < 0) error = errno;
    return failure(error);
}
