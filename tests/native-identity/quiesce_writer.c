// SPDX-License-Identifier: Apache-2.0
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __ANDROID__
#include <sys/system_properties.h>
#endif

/* Disposable guest fault fixture only. This closes the captured PMS writer, not native work,
 * UID resources or retirement obligations. It needs already-authorized Android root. */
static int pid_descriptor(pid_t pid) { return (int)syscall(SYS_pidfd_open, pid, 0); }
static int descriptor_exited(int fd, int milliseconds) {
    struct pollfd item = { .fd = fd, .events = POLLIN };
    int result;
    do { result = poll(&item, 1, milliseconds); } while (result < 0 && errno == EINTR);
    if (result < 0 || (item.revents & (POLLERR | POLLNVAL))) return -1;
    return result > 0 && (item.revents & POLLIN) ? 1 : 0;
}
static bool subject(const char *status, const char *context, const char *comm) {
    unsigned real, effective, saved, filesystem;
    const char *uids = strstr(status, "\nUid:");
    if (!uids || sscanf(uids, "\nUid:\t%u\t%u\t%u\t%u", &real, &effective, &saved, &filesystem) != 4) return false;
    return real == 1000 && effective == 1000 && saved == 1000 && filesystem == 1000
            && !strcmp(context, "u:r:system_server:s0") && !strcmp(comm, "system_server");
}
#ifndef QUIESCE_TEST
static bool read_at(int directory, const char *name, char *buffer, size_t size) {
    int fd = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    size_t count = 0;
    while (count < size) {
        ssize_t n = read(fd, buffer + count, size - count);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { close(fd); return false; }
        if (n == 0) break;
        count += (size_t)n;
    }
    close(fd);
    if (count == size) return false;
    while (count && (buffer[count - 1] == '\n' || buffer[count - 1] == '\0')) --count;
    buffer[count] = '\0';
    return true;
}
static long long monotonic_ms(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) return -1;
    return (long long)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}
static int refuse(const char *stage) {
    fprintf(stderr, "quiesce_writer refused or outcome unknown: %s; do not mutate settings\n", stage);
    return 1;
}
int main(int argc, char **argv) {
    if (argc != 3 || geteuid() != 0) return refuse("root, candidate PID and nonce required");
    const char *nonce = argv[2];
    if (strlen(nonce) != 32) return refuse("nonce syntax");
    for (size_t i = 0; i < 32; ++i) {
        if (!((nonce[i] >= '0' && nonce[i] <= '9') || (nonce[i] >= 'a' && nonce[i] <= 'f'))) {
            return refuse("nonce syntax");
        }
    }
    char *end = NULL;
    errno = 0;
    long value = strtol(argv[1], &end, 10);
    if (errno || !end || *end || argv[1][0] < '1' || argv[1][0] > '9' || value <= 1 || value > INT_MAX) return refuse("PID syntax");
    pid_t pid = (pid_t)value;
    int held = pid_descriptor(pid);
    if (held < 0 || descriptor_exited(held, 0) != 0) return refuse("PID descriptor unavailable or dead");
    char path[64];
    if (snprintf(path, sizeof(path), "/proc/%d", pid) >= (int)sizeof(path)) return refuse("PID path");
    int directory = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    char status[65536], context[256], comm[128];
    if (directory < 0 || !read_at(directory, "status", status, sizeof(status))
            || !read_at(directory, "attr/current", context, sizeof(context))
            || !read_at(directory, "comm", comm, sizeof(comm))
            || !subject(status, context, comm) || descriptor_exited(held, 0) != 0) {
        return refuse("captured process is not live system_server");
    }
    close(directory);
#ifndef __ANDROID__
    return refuse("Android fixture only");
#else
    const char *names[] = { "zygote", "zygote_secondary", "zygote_compat", "zygote_next" };
    char *command[6] = { "/system/bin/stop", NULL, NULL, NULL, NULL, NULL };
    size_t count = 1;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        char key[80], state[PROP_VALUE_MAX];
        snprintf(key, sizeof(key), "init.svc.%s", names[i]);
        if (__system_property_get(key, state) > 0) {
            if (strcmp(state, "running") && strcmp(state, "stopping")
                    && strcmp(state, "stopped") && strcmp(state, "restarting")) return refuse("unknown zygote state");
            command[count++] = (char *)names[i];
        }
    }
    if (count == 1 || strcmp(command[1], "zygote")) return refuse("primary zygote unavailable");
    printf("{\"stage\":\"captured\",\"pid\":%d,\"nonce\":\"%s\",\"writer_exited\":false}\n", pid, nonce);
    fflush(stdout);
    long long deadline = monotonic_ms();
    if (deadline < 0) return refuse("clock");
    deadline += 30000;
    pid_t child = fork();
    if (child < 0) return refuse("stop fork");
    if (child == 0) { execv(command[0], command); _exit(127); }
    int child_fd = pid_descriptor(child);
    if (child_fd < 0) return refuse("stop child descriptor unavailable");
    bool reaped = false;
    int result = 0;
    for (;;) {
        long long now = monotonic_ms();
        if (now < 0 || now >= deadline) break;
        if (!reaped) {
            pid_t waited = waitpid(child, &result, WNOHANG);
            if (waited == child) reaped = true;
            else if (waited < 0 && errno != EINTR) return refuse("stop wait");
        }
        bool stopped = reaped && WIFEXITED(result) && WEXITSTATUS(result) == 0;
        for (size_t i = 1; i < count && stopped; ++i) {
            char key[80], state[PROP_VALUE_MAX];
            snprintf(key, sizeof(key), "init.svc.%s", command[i]);
            stopped = __system_property_get(key, state) > 0 && !strcmp(state, "stopped");
        }
        if (stopped && descriptor_exited(held, 0) == 1) {
            printf("{\"stage\":\"quiescent\",\"pid\":%d,\"nonce\":\"%s\",\"writer_exited\":true,\"zygotes_stopped\":true,\"native_retirement_proved\":false}\n", pid, nonce);
            close(child_fd); close(held); return 0;
        }
        struct timespec pause = { .tv_sec = 0, .tv_nsec = 100000000 };
        nanosleep(&pause, NULL);
    }
    if (!reaped) {
        (void)syscall(SYS_pidfd_send_signal, child_fd, SIGKILL, NULL, 0);
        if (descriptor_exited(child_fd, 5000) == 1) {
            while (waitpid(child, &result, 0) < 0 && errno == EINTR) { }
        }
    }
    close(child_fd); close(held);
    return refuse("stop incomplete; captured writer or service state unresolved");
#endif
}
#else
#include <assert.h>
int main(void) {
#ifdef NDEBUG
#error assertions are required
#endif
    const char *status = "Name:\tsystem_server\nState:\tS\nUid:\t1000\t1000\t1000\t1000\n";
    assert(subject(status, "u:r:system_server:s0", "system_server"));
    assert(!subject(status, "u:r:hal_sensors_default:s0", "system_server"));
    assert(!subject(status, "u:r:system_server:s0", "system_server_fake"));
    assert(!subject("\nUid:\t1000\t0\t1000\t1000\n", "u:r:system_server:s0", "system_server"));
    assert(!subject("\nUid:\t1000\t1000\t1000\n", "u:r:system_server:s0", "system_server"));
    int channel[2]; assert(pipe(channel) == 0);
    pid_t child = fork(); assert(child >= 0);
    if (!child) { close(channel[1]); char byte; (void)read(channel[0], &byte, 1); _exit(0); }
    close(channel[0]); int fd = pid_descriptor(child); assert(fd >= 0);
    assert(descriptor_exited(fd, 0) == 0); close(channel[1]);
    assert(descriptor_exited(fd, 2000) == 1); int status_code; assert(waitpid(child, &status_code, 0) == child);
    assert(WIFEXITED(status_code) && WEXITSTATUS(status_code) == 0); close(fd);
    puts("Captured descriptor and exact subject checks passed; Android stop unqualified");
    return 0;
}
#endif
