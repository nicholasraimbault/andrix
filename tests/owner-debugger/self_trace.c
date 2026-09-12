// SPDX-License-Identifier: Apache-2.0
// Bounded probe: only a freshly forked child, never a caller-supplied PID.
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile long value = 42;

static int wait_bounded(pid_t child, int *status) {
  const struct timespec pause = {0, 10000000};
  for (int n = 0; n < 500; ++n) {
    pid_t result = waitpid(child, status, WNOHANG | WUNTRACED);
    if (result == child) return 0;
    if (result < 0 && errno != EINTR) return -1;
    nanosleep(&pause, NULL);
  }
  errno = ETIMEDOUT;
  return -1;
}

static void cleanup(pid_t child) {
  kill(child, SIGKILL);
  while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
}

int main(void) {
  int report[2];
  if (pipe(report) != 0) return 1;
  if (fcntl(report[0], F_SETFL, O_NONBLOCK) < 0) {
    close(report[0]);
    close(report[1]);
    return 1;
  }
  pid_t child = fork();
  if (child < 0) {
    close(report[0]);
    close(report[1]);
    return 1;
  }
  if (child == 0) {
    close(report[0]);
    errno = 0;
    int error = ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0 ? errno : 0;
    if (write(report[1], &error, sizeof(error)) != (ssize_t)sizeof(error)) _exit(3);
    close(report[1]);
    if (error) _exit(2);
    raise(SIGSTOP);
    _exit(value == 43 ? 0 : 4);
  }
  close(report[1]);
  int status = 0;
  if (wait_bounded(child, &status) != 0) {
    close(report[0]);
    cleanup(child);
    puts("SELF_TRACE_WAIT_FAILED");
    return 1;
  }
  int error = -1;
  ssize_t bytes = read(report[0], &error, sizeof(error));
  close(report[0]);
  printf("UID=%u EUID=%u NNP=%d SECCOMP=%d CHILD_ERRNO=%d\n",
         (unsigned)getuid(), (unsigned)geteuid(),
         prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0),
         prctl(PR_GET_SECCOMP, 0, 0, 0, 0), error);
  if (bytes != (ssize_t)sizeof(error)) {
    if (WIFSTOPPED(status)) cleanup(child);
    return 1;
  }
  if (error) {
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 2) {
      if (WIFSTOPPED(status)) cleanup(child);
      return 1;
    }
    puts("SELF_TRACE_DENIED");
    return 2;
  }
  if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
    if (WIFSTOPPED(status)) cleanup(child);
    return 1;
  }
  errno = 0;
  long observed = ptrace(PTRACE_PEEKDATA, child, (void *)&value, NULL);
  if (errno || observed != 42 ||
      ptrace(PTRACE_POKEDATA, child, (void *)&value,
             (void *)(uintptr_t)43) < 0 ||
      ptrace(PTRACE_CONT, child, NULL, NULL) < 0) {
    cleanup(child);
    puts("SELF_TRACE_ACCESS_FAILED");
    return 1;
  }
  if (wait_bounded(child, &status) != 0) {
    cleanup(child);
    return 1;
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    if (WIFSTOPPED(status)) cleanup(child);
    return 1;
  }
  puts("SELF_TRACE_READ_WRITE_CONTINUE_OK");
  return 0;
}
