// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#ifndef ANDRIX_SOCKET_HOST_TEST
#include <jni.h>
#endif

static int address(const char *path, struct sockaddr_un *out, socklen_t *length) {
    size_t n = strlen(path);
    if (!n || n >= sizeof(out->sun_path)) return ENAMETOOLONG;
    memset(out, 0, sizeof(*out));
    out->sun_family = AF_UNIX;
    memcpy(out->sun_path, path, n + 1);
    *length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + n + 1);
    return 0;
}

static int connect_errno(const char *path) {
    struct sockaddr_un addr;
    socklen_t length;
    int error = address(path, &addr, &length);
    if (error) return error;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return errno;
    // External control only attempts a connection, sends/reads no payload and
    // closes immediately. Unexpected success is not a non-mutating denial.
    error = connect(fd, (struct sockaddr *)&addr, length) == 0 ? 0 : errno;
    close(fd);
    return error;
}

static int own_socket_control(const char *cache) {
    char directory[sizeof(((struct sockaddr_un *)0)->sun_path)];
    char path[sizeof(directory)];
    int n = snprintf(directory, sizeof(directory), "%s/socket-control.XXXXXX", cache);
    if (n <= 0 || (size_t)n + sizeof("/socket") >= sizeof(directory)) return ENAMETOOLONG;
    if (!mkdtemp(directory)) return errno;
    n = snprintf(path, sizeof(path), "%s/socket", directory);
    if (n <= 0 || (size_t)n >= sizeof(path)) { rmdir(directory); return ENAMETOOLONG; }
    int server = -1, client = -1, accepted = -1, error = 0, bound = 0;
    struct sockaddr_un addr;
    socklen_t length;
    error = address(path, &addr, &length);
    if (error) goto done;
    server = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (server < 0) { error = errno; goto done; }
    if (bind(server, (struct sockaddr *)&addr, length) != 0) { error = errno; goto done; }
    bound = 1;
    if (listen(server, 1) != 0) { error = errno; goto done; }
    client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (client < 0 || connect(client, (struct sockaddr *)&addr, length) != 0) { error = errno; goto done; }
    accepted = accept4(server, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (accepted < 0) { error = errno; goto done; }
    struct ucred peer;
    socklen_t peer_size = sizeof(peer);
    if (getsockopt(accepted, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) != 0 ||
            peer_size != sizeof(peer) || peer.uid != getuid() || peer.pid != getpid()) {
        error = EIO; goto done;
    }
    char value = 'P', received = 0;
    if (send(client, &value, 1, MSG_NOSIGNAL) != 1) { error = EIO; goto done; }
    struct pollfd ready = {.fd=accepted, .events=POLLIN};
    if (poll(&ready, 1, 2000) != 1 || recv(accepted, &received, 1, 0) != 1 || received != value) {
        error = EIO; goto done;
    }
    value = 'Q';
    if (send(accepted, &value, 1, MSG_NOSIGNAL) != 1) { error = EIO; goto done; }
    ready.fd = client;
    if (poll(&ready, 1, 2000) != 1 || recv(client, &received, 1, 0) != 1 || received != value) error = EIO;
done:
    if (accepted >= 0) close(accepted);
    if (client >= 0) close(client);
    if (server >= 0) close(server);
    if (bound && unlink(path) != 0 && !error) error = errno;
    if (rmdir(directory) != 0 && !error) error = errno;
    return error;
}

#ifndef ANDRIX_SOCKET_HOST_TEST
JNIEXPORT jstring JNICALL
Java_dev_andrix_proof_socketboundary_SocketBoundary_nativeProbe(JNIEnv *env, jclass klass,
                                                               jstring cache, jstring path) {
    (void)klass;
    if (!cache || !path) return NULL;
    const char *local = (*env)->GetStringUTFChars(env, cache, NULL);
    if (!local) return NULL;
    const char *external = (*env)->GetStringUTFChars(env, path, NULL);
    if (!external) { (*env)->ReleaseStringUTFChars(env, cache, local); return NULL; }
    int self_error = own_socket_control(local);
    int outside_error = connect_errno(external);
    (*env)->ReleaseStringUTFChars(env, path, external);
    (*env)->ReleaseStringUTFChars(env, cache, local);
    char sid[160] = "unavailable";
    FILE *f = fopen("/proc/self/attr/current", "re");
    if (f) { if (!fgets(sid, sizeof(sid), f)) strcpy(sid, "unavailable"); fclose(f); }
    sid[strcspn(sid, "\r\n")] = 0;
    char report[512];
    int n = snprintf(report, sizeof(report),
        "{\"uid\":%u,\"euid\":%u,\"pid\":%d,\"sid\":\"%s\",\"self_errno\":%d,\"owner_connect_errno\":%d,\"nnp\":%d,\"seccomp\":%d}",
        getuid(), geteuid(), getpid(), sid, self_error, outside_error,
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0), prctl(PR_GET_SECCOMP, 0, 0, 0, 0));
    if (n <= 0 || (size_t)n >= sizeof(report)) return NULL;
    return (*env)->NewStringUTF(env, report);
}
#else
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int result = own_socket_control(argv[1]);
    if (result) { fprintf(stderr, "self error=%d\n", result); return 1; }
    char missing[108];
    if (snprintf(missing, sizeof(missing), "%s/no-socket", argv[1]) >= (int)sizeof(missing)) return 1;
    if (connect_errno(missing) != ENOENT) return 1;
    puts("SELF_NAMED_SOCKET_CONNECT_OK; missing path is not permission denial");
    return 0;
}
#endif
