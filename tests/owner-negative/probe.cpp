// SPDX-License-Identifier: Apache-2.0
#include <android/binder_manager.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/system_properties.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
int fixed_exec_errno(const char* path) {
  int result[2];
  if (pipe2(result, O_CLOEXEC)) return -2;
  char* arguments[] = {const_cast<char*>(path), nullptr};
  char* environment[] = {nullptr};
  pid_t child = fork();
  if (!child) {
    close(result[0]);
    execve(path, arguments, environment);
    int error = errno;
    write(result[1], &error, sizeof(error));
    _exit(0);
  }
  close(result[1]);
  if (child < 0) {
    close(result[0]);
    return -3;
  }
  pollfd wait{result[0], POLLIN | POLLHUP, 0};
  int error = -4;
  if (poll(&wait, 1, 3000) > 0) {
    int observed = 0;
    ssize_t count = read(result[0], &observed, sizeof(observed));
    error = count == sizeof(observed) ? observed : count == 0 ? 0 : -5;
  }
  close(result[0]);
  if (error <= 0) kill(child, SIGKILL);
  int status = 0;
  while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
  }
  return error;  // Zero means exec actually succeeded, NOT a refusal in main().
}
}  // namespace
extern "C" JNIEXPORT jstring JNICALL
Java_dev_andrix_proof_ownernegative_OwnerNegative_nativeWorkLaunchProbe(
    JNIEnv* env, jclass, jstring reference) {
  const char* input = env->GetStringUTFChars(reference, nullptr);
  if (!input) return nullptr;
  char name[108] = "andrix.work-launch-proof.";
  size_t length = strlen(input);
  bool valid = length > 2 && length < 70;
  for (size_t i = 0; i < length; ++i)
    if ((input[i] < '0' || input[i] > '9') && input[i] != '.') valid = false;
  if (valid && strlen(name) + length + 1 < sizeof(name))
    strcat(name, input);
  else
    valid = false;
  env->ReleaseStringUTFChars(reference, input);
  if (!valid) return nullptr;
  int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  if (fd < 0) return nullptr;
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path + 1, name, strlen(name));
  errno = 0;
  int connected =
      connect(fd, reinterpret_cast<sockaddr*>(&address),
              static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 +
                                     strlen(name)));
  int connect_error = connected < 0 ? errno : 0;
  close(fd);
  int launcher = fixed_exec_errno("/system_ext/bin/andrix-work-launcher");
  int entry = fixed_exec_errno("/system_ext/bin/andrix-work-entry");
  int start = __system_property_set("ctl.start", "andrix-work-launch-proof");
  int stop = __system_property_set("ctl.stop", "andrix-work-launch-proof");
  char record[384];
  snprintf(
      record, sizeof(record),
      "{\"uid\":%u,\"connect_errno\":%d,\"launcher_exec_errno\":%d,\"entry_"
      "exec_errno\":%d,\"ctl_start_result\":%d,\"ctl_stop_result\":%d}",
      getuid(), connect_error, launcher, entry, start, stop);
  return env->NewStringUTF(record);
}

// This platform-specific Binder bootstrap is not an adopted identity or a
// privilege grant. The calling process remains the ordinary installed APK UID.
extern "C" JNIEXPORT jstring JNICALL
Java_dev_andrix_proof_ownernegative_OwnerNegative_nativeProbe(JNIEnv* env, jclass) {
    AIBinder* service = AServiceManager_checkService("andrix.owner.session");
    const bool found = service != nullptr;
    if (service != nullptr) AIBinder_decStrong(service);
    AIBinder* lifecycle = AServiceManager_checkService("andrix.owner.lifecycle");
    const bool lifecycle_found = lifecycle != nullptr;
    if (lifecycle != nullptr) AIBinder_decStrong(lifecycle);
    // Only a live scope-proof positive in the same window makes these useful
    // negatives. Absence from a normal image is not an access-denial pass.
    AIBinder* scope_a = AServiceManager_checkService("andrix.proof.scope.a");
    AIBinder* scope_b = AServiceManager_checkService("andrix.proof.scope.b");
    const bool scope_a_found = scope_a != nullptr, scope_b_found = scope_b != nullptr;
    if (scope_a != nullptr) AIBinder_decStrong(scope_a);
    if (scope_b != nullptr) AIBinder_decStrong(scope_b);
    AIBinder* factory = AServiceManager_checkService("andrix.proof.factory");
    const bool factory_found = factory != nullptr;
    if (factory != nullptr) AIBinder_decStrong(factory);
    errno = 0;
    int home = open("/data/misc_ce/0/andrix", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    const int home_error = home < 0 ? errno : 0;
    if (home >= 0) close(home);
    char sid[256] = {};
    int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    ssize_t size = fd < 0 ? -1 : read(fd, sid, sizeof(sid) - 1);
    if (fd >= 0) close(fd);
    if (size <= 0 || size >= static_cast<ssize_t>(sizeof(sid) - 1)) return nullptr;
    for (ssize_t i = 0; i < size; ++i) {
        if (sid[i] == '\n' || sid[i] == '\0') { sid[i] = '\0'; break; }
        // The kernel context must be safe in this deliberately small JSON record.
        if (sid[i] == '"' || sid[i] == '\\' || sid[i] < 0x20) return nullptr;
    }
    char record[768];
    int length = snprintf(record, sizeof(record),
        "{\"uid\":%u,\"euid\":%u,\"sid\":\"%s\",\"service_found\":%s,"
        "\"lifecycle_service_found\":%s,\"scope_a_found\":%s,\"scope_b_found\":%s,\"factory_found\":%s,\"home_errno\":%d}",
        getuid(), geteuid(), sid, found ? "true" : "false",
        lifecycle_found ? "true" : "false", scope_a_found ? "true" : "false",
        scope_b_found ? "true" : "false", factory_found ? "true" : "false", home_error);
    if (length < 0 || length >= static_cast<int>(sizeof(record))) return nullptr;
    return env->NewStringUTF(record);
}
