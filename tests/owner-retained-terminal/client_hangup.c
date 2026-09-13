// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static long long now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) _exit(125);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static void tick(void) {
    struct timespec t = {.tv_sec=0, .tv_nsec=10000000};
    while (nanosleep(&t, &t) < 0 && errno == EINTR) {}
}

int main(int argc, char **argv) {
    // Single-threaded/exclusive child reaping and default SIGCHLD are required.
    // Cleanup signals can target only this probe's fresh tmux client, never the
    // independently existing tmux server or pane processes.
    if (argc != 2 || !argv[1][0] || strlen(argv[1]) > 80) return 2;
    struct sigaction action;
    if (sigaction(SIGCHLD, NULL, &action) != 0 || action.sa_handler != SIG_DFL ||
            (action.sa_flags & SA_NOCLDWAIT)) return 2;
    int master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC | O_NONBLOCK);
    char name[128];
    if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0 ||
            ptsname_r(master, name, sizeof(name)) != 0) return 1;
    int slave = open(name, O_RDWR | O_NOCTTY | O_CLOEXEC);
    struct winsize dimensions = {.ws_row=24, .ws_col=80};
    if (slave < 0 || ioctl(master, TIOCSWINSZ, &dimensions) != 0) return 1;
    pid_t parent = getpid();
    pid_t child = fork();
    if (child == 0) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent ||
                setsid() < 0 || ioctl(slave, TIOCSCTTY, 0) != 0 ||
                dup2(slave, 0) < 0 || dup2(slave, 1) < 0 || dup2(slave, 2) < 0) _exit(125);
        for (int fd=3;fd<128;fd++) close(fd);
        char *args[] = {"tmux", "-L", "andrix-proof", "attach-session", "-t", "lab", NULL};
        execv("/usr/bin/tmux", args);
        _exit(127);
    }
    close(slave);
    if (child < 0) { close(master); return 1; }
    char bytes[65536];
    size_t used = 0;
    int marker = 0, status = 0, reaped = 0, failed = 0;
    long long deadline = now_ms() + 10000;
    while (now_ms() < deadline && used < sizeof(bytes)) {
        pid_t p = waitpid(child, &status, WNOHANG);
        if (p == child) { reaped=1; failed=1; break; }
        if (p < 0 && errno != EINTR) { failed=1; break; }
        struct pollfd ready = {.fd=master, .events=POLLIN};
        int result = poll(&ready, 1, 100);
        if (result < 0 && errno != EINTR) { failed=1; break; }
        if (result <= 0) continue;
        ssize_t n = read(master, bytes + used, sizeof(bytes) - used);
        if (n > 0) used += (size_t)n;
        else if (n < 0 && errno != EINTR && errno != EAGAIN) { failed=1; break; }
        if (memmem(bytes, used, argv[1], strlen(argv[1]))) { marker=1; break; }
    }
    if (!marker) failed=1;
    if (!reaped) {
        pid_t p = waitpid(child, &status, WNOHANG);
        if (p == child) { reaped=1; failed=1; }
        else if (p < 0) failed=1;
    }
    close(master); // This is the event under test, not a guessed process-group kill.
    deadline = now_ms() + 5000;
    while (!reaped && now_ms() < deadline) {
        pid_t p = waitpid(child, &status, WNOHANG);
        if (p == child) reaped=1;
        else if (p < 0 && errno != EINTR) { failed=1; break; }
        if (!reaped) tick();
    }
    if (!reaped) {
        failed=1;
        // Check ownership again; ECHILD is an infrastructure failure, not grounds
        // to signal a potentially reused PID.
        pid_t p = waitpid(child, &status, WNOHANG);
        if (p == child) reaped=1;
        else if (p == 0) {
            kill(child, SIGKILL);
            deadline = now_ms() + 1000;
            while (!reaped && now_ms() < deadline) {
                p=waitpid(child, &status, WNOHANG);
                if (p == child) reaped=1;
                else if (p < 0 && errno != EINTR) break;
                if (!reaped) tick();
            }
        }
    }
    printf("CLIENT_HANGUP uid=%u pid=%d child=%d bytes=%zu marker=%d reaped=%d status=%d result=%s\n",
           getuid(), getpid(), child, used, marker, reaped, status,
           !failed && reaped ? "PASS_REQUIRES_LIVE_SERVER_CONTROL" : "FAIL");
    return !failed && reaped ? 0 : 1;
}
