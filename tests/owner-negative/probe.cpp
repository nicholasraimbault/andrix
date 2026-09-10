// SPDX-License-Identifier: Apache-2.0
#include <android/binder_manager.h>
#include <jni.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

// This platform-specific Binder bootstrap is not an adopted identity or a
// privilege grant. The calling process remains the ordinary installed APK UID.
extern "C" JNIEXPORT jstring JNICALL
Java_dev_andrix_proof_ownernegative_OwnerNegative_nativeProbe(JNIEnv* env, jclass) {
    AIBinder* service = AServiceManager_checkService("andrix.owner.session");
    const bool found = service != nullptr;
    if (service != nullptr) AIBinder_decStrong(service);
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
        "{\"uid\":%u,\"euid\":%u,\"sid\":\"%s\",\"service_found\":%s,\"home_errno\":%d}",
        getuid(), geteuid(), sid, found ? "true" : "false", home_error);
    if (length < 0 || length >= static_cast<int>(sizeof(record))) return nullptr;
    return env->NewStringUTF(record);
}
