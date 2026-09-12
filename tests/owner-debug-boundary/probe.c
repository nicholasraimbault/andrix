// SPDX-License-Identifier: Apache-2.0
#include <jni.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
#include "trace_access.h"

JNIEXPORT jstring JNICALL
Java_dev_andrix_proof_debugboundary_DebugBoundary_nativeProbe(
    JNIEnv *env, jclass clazz, jint owner_pid, jint manager_pid, jstring pty_path) {
  (void)clazz;
  if (owner_pid <= 1 || manager_pid <= 1 || owner_pid == manager_pid ||
      owner_pid == getpid() || manager_pid == getpid() || pty_path == NULL) return NULL;
  const char *path = (*env)->GetStringUTFChars(env, pty_path, NULL);
  if (path == NULL) return NULL;
  const char prefix[] = "/dev/pts/";
  const size_t start = sizeof(prefix) - 1;
  size_t size = strlen(path);
  if (size <= start || size > start + 8 || strncmp(path, prefix, start) != 0 ||
      strspn(path + start, "0123456789") != size - start) {
    (*env)->ReleaseStringUTFChars(env, pty_path, path);
    return NULL;
  }
  errno = 0;
  int fd = open(path, O_RDONLY | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
  int pty_error = fd < 0 ? errno : 0;
  if (fd >= 0) close(fd);
  (*env)->ReleaseStringUTFChars(env, pty_path, path);
  char sid[256] = {0};
  fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
  ssize_t count = fd < 0 ? -1 : read(fd, sid, sizeof(sid) - 1);
  if (fd >= 0) close(fd);
  if (count <= 0 || count >= (ssize_t)sizeof(sid) - 1) return NULL;
  for (ssize_t i = 0; i < count; ++i) {
    if (sid[i] == '\n' || sid[i] == '\0') { sid[i] = '\0'; break; }
    if (sid[i] == '"' || sid[i] == '\\' || sid[i] < 0x20) return NULL;
  }
  AndrixTraceAccess self = andrix_trace_access(0);
  AndrixTraceAccess owner = andrix_trace_access(owner_pid);
  AndrixTraceAccess manager = andrix_trace_access(manager_pid);
  char record[1024];
  int n = snprintf(record, sizeof(record),
      "{\"uid\":%u,\"euid\":%u,\"pid\":%d,\"sid\":\"%s\","
      "\"dumpable\":%d,\"nnp\":%d,\"seccomp\":%d,"
      "\"self_complete\":%d,\"self_errno\":%d,"
      "\"owner_pid\":%d,\"owner_complete\":%d,\"owner_errno\":%d,"
      "\"manager_pid\":%d,\"manager_complete\":%d,\"manager_errno\":%d,"
      "\"pty_errno\":%d}",
      (unsigned)getuid(), (unsigned)geteuid(), getpid(), sid,
      prctl(PR_GET_DUMPABLE, 0, 0, 0, 0), prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0),
      prctl(PR_GET_SECCOMP, 0, 0, 0, 0), self.complete, self.error,
      owner_pid, owner.complete, owner.error, manager_pid, manager.complete,
      manager.error, pty_error);
  if (n < 0 || n >= (int)sizeof(record)) return NULL;
  return (*env)->NewStringUTF(env, record);
}
