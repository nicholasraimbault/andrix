// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/xattr.h>
#include <termios.h>
#include <unistd.h>
#include "trace_access.h"

static int number(const char *text, int maximum) {
  if (!text || !*text || strspn(text, "0123456789") != strlen(text)) return -1;
  errno = 0;
  char *end = NULL;
  long n = strtol(text, &end, 10);
  return errno || *end || n < 0 || n > maximum ? -1 : (int)n;
}

static int byte_roundtrip(int output, int input, char value) {
  if (write(output, &value, 1) != 1) return -1;
  struct pollfd p = {input, POLLIN, 0};
  if (poll(&p, 1, 5000) != 1 || !(p.revents & POLLIN)) return -1;
  char got = 0;
  return read(input, &got, 1) == 1 && got == value ? 0 : -1;
}

static int pty_check(int hold) {
  int master = -1, slave = -1, rc = 1;
  char path[128] = {0}, sid[256] = {0};
  master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0 ||
      ptsname_r(master, path, sizeof(path)) != 0) goto done;
  slave = open(path, O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (slave < 0) goto done;
  struct termios mode;
  if (tcgetattr(slave, &mode) != 0) goto done;
  cfmakeraw(&mode);
  if (tcsetattr(slave, TCSANOW, &mode) != 0 ||
      byte_roundtrip(master, slave, 'P') != 0 ||
      byte_roundtrip(slave, master, 'Q') != 0) goto done;
  errno = 0;
  ssize_t count = fgetxattr(slave, "security.selinux", sid, sizeof(sid) - 1);
  int label_error = count < 0 ? errno : 0;
  if (count >= (ssize_t)sizeof(sid) - 1) goto done;
#ifdef __ANDROID__
  if (count <= 0 || strcmp(sid, "u:object_r:andrix_owner_devpts:s0") != 0) goto done;
#endif
  char injected = '!';
  errno = 0;
  int injection = ioctl(slave, TIOCSTI, &injected);
  int injection_error = injection < 0 ? errno : 0;
  printf("PTY=%s PID=%d SID=%s LABEL_ERRNO=%d TIOCSTI_ERRNO=%d\n",
         path, getpid(), sid, label_error, injection_error);
  // Kernels may reject this operation with EIO before a usable TIOCSTI path.
  // Record the exact error; rejection alone does not prove an SELinux cause.
  if (injection == 0 || (injection_error != EPERM && injection_error != EACCES &&
                         injection_error != EIO)) goto done;
  puts("OWN_PTY_ROUNDTRIP_OK");
  fflush(stdout);
  while (hold > 0) hold = (int)sleep((unsigned)hold);
  rc = 0;
done:
  if (rc != 0) printf("PTY_PROBE_FAILED errno=%d\n", errno);
  if (slave >= 0) close(slave);
  if (master >= 0) close(master);
  return rc;
}

int main(int argc, char **argv) {
  printf("UID=%u EUID=%u PID=%d NNP=%d SECCOMP=%d\n",
         (unsigned)getuid(), (unsigned)geteuid(), getpid(),
         prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0), prctl(PR_GET_SECCOMP, 0, 0, 0, 0));
  if (argc == 2 && strcmp(argv[1], "self") == 0) {
    AndrixTraceAccess r = andrix_trace_access(0);
    printf("SELF_SEIZE_COMPLETE=%d ERRNO=%d\n", r.complete, r.error);
    return r.complete == 1 && r.error == 0 ? 0 : 1;
  }
  if (argc == 3 && strcmp(argv[1], "deny") == 0) {
    int target = number(argv[2], INT_MAX);
    if (target <= 1 || target == getpid()) return 1;
    AndrixTraceAccess r = andrix_trace_access(target);
    printf("TARGET=%d SEIZE_COMPLETE=%d ERRNO=%d\n", target, r.complete, r.error);
    if (r.complete == 1 && (r.error == EPERM || r.error == EACCES)) {
      puts("DENIED_REQUIRES_LIVE_TARGET_CONTROL");
      return 0;
    }
    puts("DENIAL_NOT_ESTABLISHED");
    return 1;
  }
  if (argc == 3 && strcmp(argv[1], "pty") == 0) {
    int hold = number(argv[2], 300);
    if (hold >= 0) return pty_check(hold);
  }
  fputs("usage: boundary self | deny PID | pty HOLD_SECONDS(0..300)\n", stderr);
  return 1;
}
