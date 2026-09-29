// SPDX-License-Identifier: Apache-2.0
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <elf.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
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

#ifdef NDEBUG
#error assertions and explicit verification must remain enabled
#endif
#if defined(__ANDROID__) && (defined(QUIESCE_EXEC_TEST) || defined(QUIESCE_TEST))
#error host test modes must never enter the Android helper
#endif

/* Separately attributed executable-bound helper. Prior helper source is unchanged.
 * Only the same boot, privately staged binary is eligible. Its own running ELF is
 * inspected and independently hashed through /proc/PID/exe before any stop.
 * Separately attributed P3 helper derived from quiesce_writer.c (599a2fc7...).
 * The original helper and its evidence remain unchanged.
 * Disposable guest fault fixture only. This closes the captured PMS writer, not native work,
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
static bool decimal_ticks(const char *value) {
    if (!value || value[0] < '1' || value[0] > '9' || strlen(value) > 20) return false;
    for (const char *p = value; *p; ++p) if (*p < '0' || *p > '9') return false;
    errno = 0; char *end = NULL;
    (void)strtoull(value, &end, 10);
    return !errno && end && !*end;
}
static bool boot_syntax(const char *value) {
    if (!value || strlen(value) != 36) return false;
    for (size_t i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (value[i] != '-') return false; }
        else if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) return false;
    }
    return true;
}
static bool start_ticks(const char *data, pid_t pid, char output[21]) {
    char *end = NULL; errno = 0;
    long observed = strtol(data, &end, 10);
    if (errno || observed != pid || !end || end[0] != ' ' || end[1] != '(') return false;
    const char *closing = strrchr(end + 1, ')');
    if (!closing || closing[1] != ' ') return false;
    const char *p = closing + 2;
    for (unsigned field = 3; field <= 22; ++field) {
        const char *token = p;
        while (*p && *p != ' ' && *p != '\n' && *p != '\t') ++p;
        size_t length = (size_t)(p - token);
        if (!length) return false;
        if (field == 22) {
            if (length > 20) return false;
            memcpy(output, token, length); output[length] = '\0';
            return decimal_ticks(output);
        }
        while (*p == ' ' || *p == '\t') ++p;
    }
    return false;
}
static bool incarnation(int held, int directory, pid_t pid, const char *expected_ticks,
                        const char *expected_boot, char actual_ticks[21], char actual_boot[64]) {
    if (!decimal_ticks(expected_ticks) || !boot_syntax(expected_boot) || descriptor_exited(held, 0) != 0) return false;
    char data[65536];
    int kernel = open("/proc/sys/kernel/random", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (kernel < 0) return false;
    bool read_boot = read_at(kernel, "boot_id", actual_boot, 64); close(kernel);
    if (!read_boot || !boot_syntax(actual_boot) || strcmp(actual_boot, expected_boot)
            || !read_at(directory, "stat", data, sizeof(data)) || !start_ticks(data, pid, actual_ticks)
            || strcmp(actual_ticks, expected_ticks) || descriptor_exited(held, 0) != 0) return false;
    return true;
}

/* Verify the currently executing helper, not an upload path. Hashing is delegated
 * only to the fixed image tool. No shell, arbitrary command or crypto library. */
#define EXE_LIMIT (1024U * 1024U)
struct executable_identity {
    pid_t pid;
    char ticks[21], boot[64], digest[65];
    struct stat object;
};
static long long monotonic_ms(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) return -1;
    return (long long)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}
static bool digest_syntax(const char *value) {
    if (!value || strlen(value) != 64) return false;
    for (size_t i = 0; i < 64; ++i)
        if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) return false;
    return true;
}
static bool exact_pread(int fd, void *data, size_t count, off_t offset) {
    size_t done = 0;
    while (done < count) {
        ssize_t n = pread(fd, (char *)data + done, count - done, offset + (off_t)done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return true;
}
static bool same_executable(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_mode == b->st_mode
        && a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_nlink == b->st_nlink
        && a->st_size == b->st_size && a->st_mtim.tv_sec == b->st_mtim.tv_sec
        && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec && a->st_ctim.tv_sec == b->st_ctim.tv_sec
        && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static bool executable_elf(int fd, struct stat *object) {
    Elf64_Ehdr header;
    if (fstat(fd, object) || !S_ISREG(object->st_mode) || object->st_nlink != 1
            || object->st_uid != geteuid() || object->st_gid != getegid()
            || object->st_size < (off_t)sizeof(header) || object->st_size > EXE_LIMIT
            || (object->st_mode & 07777) != 0700 || !exact_pread(fd, &header, sizeof(header), 0)) return false;
    if (memcmp(header.e_ident, ELFMAG, SELFMAG) || header.e_ident[EI_CLASS] != ELFCLASS64
            || header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_ident[EI_VERSION] != EV_CURRENT
            || header.e_version != EV_CURRENT || header.e_type != ET_DYN
            || header.e_ehsize != sizeof(header) || header.e_phentsize != sizeof(Elf64_Phdr)
            || !header.e_phnum || header.e_phnum > 64
            || header.e_phoff > (uint64_t)object->st_size
            || (uint64_t)header.e_phnum * sizeof(Elf64_Phdr) > (uint64_t)object->st_size - header.e_phoff) return false;
#ifdef QUIESCE_EXEC_TEST
    if (header.e_machine != EM_X86_64) return false;
    const char wanted[] = "/lib64/ld-linux-x86-64.so.2";
#else
    if (header.e_machine != EM_AARCH64) return false;
    const char wanted[] = "/system/bin/linker64";
#endif
    bool found = false;
    for (unsigned i = 0; i < header.e_phnum; ++i) {
        Elf64_Phdr program;
        if (!exact_pread(fd, &program, sizeof(program), (off_t)(header.e_phoff + i * sizeof(program)))) return false;
        if (program.p_type != PT_INTERP) continue;
        if (found || program.p_filesz != sizeof(wanted) || program.p_offset > (uint64_t)object->st_size
                || program.p_filesz > (uint64_t)object->st_size - program.p_offset) return false;
        char path[sizeof(wanted)];
        if (!exact_pread(fd, path, sizeof(path), (off_t)program.p_offset) || memcmp(path, wanted, sizeof(wanted))) return false;
        found = true;
    }
    return found;
}
/* The child remains ours and unreaped. PID fallback below is never used for an
 * unrelated or reaped process. PDEATHSIG remains a second boundary, not an ack. */
static bool retire_child(pid_t child, int descriptor, int *status, long long deadline) {
    if (descriptor >= 0) (void)syscall(SYS_pidfd_send_signal, descriptor, SIGKILL, NULL, 0);
    else (void)kill(child, SIGKILL);
    for (;;) {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result == child) return true;
        if (result < 0 && errno != EINTR) return false;
        long long now = monotonic_ms();
        if (now < 0 || now >= deadline) return false;
        struct timespec pause = { .tv_sec = 0, .tv_nsec = 1000000 };
        (void)nanosleep(&pause, NULL);
    }
}
static void child_parent_guard(pid_t expected_parent) {
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != expected_parent) _exit(125);
}
#ifdef QUIESCE_EXEC_TEST
/* Test hooks never exist in an Android build. */
static int test_hash_behavior;
static pid_t test_hash_child;
#endif
static bool hash_current_executable(const char *path, char digest[65], long long deadline, long long cleanup_deadline) {
    /* Explicit wait ownership. An inherited SIG_IGN or SA_NOCLDWAIT would allow
     * automatic reaping and invalidate the unreaped-child PID fallback. */
    struct sigaction child_policy = { .sa_handler = SIG_DFL };
    if (sigemptyset(&child_policy.sa_mask) || sigaction(SIGCHLD, &child_policy, NULL)) return false;
    int out[2], err[2];
    if (pipe2(out, O_CLOEXEC | O_NONBLOCK)) return false;
    if (pipe2(err, O_CLOEXEC | O_NONBLOCK)) { close(out[0]); close(out[1]); return false; }
    pid_t parent = getpid(), child = fork();
    if (child < 0) { close(out[0]); close(out[1]); close(err[0]); close(err[1]); return false; }
    if (!child) {
        child_parent_guard(parent);
        close(out[0]); close(err[0]);
        if (dup2(out[1], STDOUT_FILENO) < 0 || dup2(err[1], STDERR_FILENO) < 0) _exit(126);
        close(out[1]); close(err[1]);
#ifdef QUIESCE_EXEC_TEST
        if (test_hash_behavior == 1) { (void)write(STDOUT_FILENO, "bad\n", 4); _exit(0); }
        if (test_hash_behavior == 2) { (void)write(STDERR_FILENO, "unexpected\n", 11); _exit(0); }
        if (test_hash_behavior == 3) { for (;;) pause(); }
        if (test_hash_behavior == 4) _exit(7);
        const char tool[] = "/usr/bin/sha256sum";
#else
        const char tool[] = "/system/bin/sha256sum";
#endif
        execl(tool, tool, path, (char *)NULL); _exit(127);
    }
#ifdef QUIESCE_EXEC_TEST
    test_hash_child = child;
#endif
    close(out[1]); close(err[1]);
    int held = pid_descriptor(child), status = 0;
    bool reaped = false, failed = held < 0, output_closed = false, error_closed = false;
    char output[256]; size_t used = 0;
    while (!failed) {
        char extra[16];
        ssize_t n = read(out[0], output + used, sizeof(output) - used);
        if (n > 0) { used += (size_t)n; if (used == sizeof(output)) failed = true; }
        else if (!n) output_closed = true;
        else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) failed = true;
        n = read(err[0], extra, sizeof(extra));
        if (n > 0) failed = true;
        else if (!n) error_closed = true;
        else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) failed = true;
        if (!reaped) {
            pid_t waited = waitpid(child, &status, WNOHANG);
            if (waited == child) reaped = true;
            else if (waited < 0 && errno != EINTR) failed = true;
        }
        if (reaped && output_closed && error_closed) break;
        long long now = monotonic_ms();
        if (now < 0 || now >= deadline) { failed = true; break; }
        struct pollfd channels[2] = {{.fd = out[0], .events = POLLIN}, {.fd = err[0], .events = POLLIN}};
        (void)poll(channels, 2, 10);
    }
    if (!reaped) reaped = retire_child(child, held, &status, cleanup_deadline);
    close(out[0]); close(err[0]); if (held >= 0) close(held);
    if (!reaped) fprintf(stderr, "hash child retirement unconfirmed; whole guest scope must close\n");
    if (failed || !reaped || !WIFEXITED(status) || WEXITSTATUS(status)) return false;
    size_t path_length = strlen(path);
    if (used != 64 + 2 + path_length + 1 || output[64] != ' ' || output[65] != ' '
            || memcmp(output + 66, path, path_length) || output[used - 1] != '\n') return false;
    memcpy(digest, output, 64); digest[64] = '\0';
    return digest_syntax(digest);
}
static bool verify_running_helper(const char *wanted, const char *expected_boot,
                                  struct executable_identity *result, long long overall_deadline) {
    if (!digest_syntax(wanted) || !boot_syntax(expected_boot)) return false;
    result->pid = getpid();
    int held = pid_descriptor(result->pid);
    if (held < 0) return false;
    char directory_path[64], executable_path[80];
    snprintf(directory_path, sizeof(directory_path), "/proc/%d", result->pid);
    snprintf(executable_path, sizeof(executable_path), "/proc/%d/exe", result->pid);
    int directory = open(directory_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int executable = directory >= 0 ? openat(directory, "exe", O_RDONLY | O_CLOEXEC) : -1;
    bool ok = false; char data[65536], verified_ticks[21], verified_boot[64]; struct stat after;
    if (directory < 0 || executable < 0 || !executable_elf(executable, &result->object)
            || !read_at(directory, "stat", data, sizeof(data)) || !start_ticks(data, result->pid, result->ticks)
            || !incarnation(held, directory, result->pid, result->ticks, expected_boot, verified_ticks, result->boot)) goto done;
    long long now = monotonic_ms();
    if (now < 0 || overall_deadline - now < 1000) goto done;
    long long hash_deadline = now + 3000;
    if (hash_deadline > overall_deadline - 500) hash_deadline = overall_deadline - 500;
    if (!hash_current_executable(executable_path, result->digest, hash_deadline, overall_deadline)
            || strcmp(result->digest, wanted) || fstat(executable, &after) || !same_executable(&result->object, &after)
            || !incarnation(held, directory, result->pid, result->ticks, expected_boot, verified_ticks, verified_boot)) goto done;
    int current = openat(directory, "exe", O_RDONLY | O_CLOEXEC);
    if (current < 0) goto done;
    bool same = fstat(current, &after) == 0 && same_executable(&result->object, &after); close(current);
    if (!same) goto done;
    ok = true;
done:
    if (executable >= 0) close(executable);
    if (directory >= 0) close(directory);
    close(held); return ok;
}

#ifndef QUIESCE_EXEC_TEST
static int refuse(const char *stage) {
    fprintf(stderr, "quiesce_writer refused or outcome unknown: %s; do not mutate settings\n", stage);
    return 1;
}
int main(int argc, char **argv) {
    long long deadline = monotonic_ms();
    if (deadline < 0) return refuse("clock");
    deadline += 30000;
    if (argc != 7 || geteuid() != 0) return refuse("root, mode, PID, nonce, starttime, boot ID and expected executable SHA required");
    if (!digest_syntax(argv[6])) return refuse("executable digest syntax");
    bool inspect_only = !strcmp(argv[1], "inspect");
    if (!inspect_only && strcmp(argv[1], "stop")) return refuse("explicit inspect or stop mode required");
    const char *nonce = argv[3];
    const char *expected_ticks = argv[4], *expected_boot = argv[5];
    if (!decimal_ticks(expected_ticks) || !boot_syntax(expected_boot)) return refuse("incarnation syntax");
    if (strlen(nonce) != 32) return refuse("nonce syntax");
    for (size_t i = 0; i < 32; ++i) {
        if (!((nonce[i] >= '0' && nonce[i] <= '9') || (nonce[i] >= 'a' && nonce[i] <= 'f'))) {
            return refuse("nonce syntax");
        }
    }
    char *end = NULL;
    errno = 0;
    long value = strtol(argv[2], &end, 10);
    if (errno || !end || *end || argv[2][0] < '1' || argv[2][0] > '9' || value <= 1 || value > INT_MAX) return refuse("PID syntax");
    pid_t pid = (pid_t)value;
    int held = pid_descriptor(pid);
    if (held < 0 || descriptor_exited(held, 0) != 0) return refuse("PID descriptor unavailable or dead");
    char path[64];
    if (snprintf(path, sizeof(path), "/proc/%d", pid) >= (int)sizeof(path)) return refuse("PID path");
    int directory = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    char status[65536], context[256], comm[128], actual_ticks[21], actual_boot[64];
    if (directory < 0 || !read_at(directory, "status", status, sizeof(status))
            || !read_at(directory, "attr/current", context, sizeof(context))
            || !read_at(directory, "comm", comm, sizeof(comm))
            || !subject(status, context, comm)
            || !incarnation(held, directory, pid, expected_ticks, expected_boot, actual_ticks, actual_boot)) {
        return refuse("captured process is not the expected live system_server incarnation");
    }
    struct executable_identity self;
    if (!verify_running_helper(argv[6], expected_boot, &self, deadline)
            || !read_at(directory, "status", status, sizeof(status))
            || !read_at(directory, "attr/current", context, sizeof(context))
            || !read_at(directory, "comm", comm, sizeof(comm)) || !subject(status, context, comm)
            || !incarnation(held, directory, pid, expected_ticks, expected_boot, actual_ticks, actual_boot)) {
        return refuse("running helper bytes or captured PMS incarnation not confirmed");
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
    printf("{\"stage\":\"captured\",\"pid\":%d,\"nonce\":\"%s\",\"starttime\":\"%s\",\"boot_id\":\"%s\",\"writer_exited\":false,\"helper_pid\":%d,\"helper_starttime\":\"%s\",\"helper_boot_id\":\"%s\",\"helper_exe_sha256\":\"%s\",\"helper_exe_device\":%ju,\"helper_exe_inode\":%ju,\"helper_exe_size\":%jd}\n", pid, nonce, actual_ticks, actual_boot, self.pid, self.ticks, self.boot, self.digest, (uintmax_t)self.object.st_dev, (uintmax_t)self.object.st_ino, (intmax_t)self.object.st_size);
    fflush(stdout);
    if (inspect_only) { close(held); return 0; }
    if (descriptor_exited(held, 0) != 0) { close(held); return refuse("captured incarnation exited before stop"); }
    if (monotonic_ms() < 0 || monotonic_ms() >= deadline - 1000) return refuse("helper budget expired before stop");
    int gate[2];
    if (pipe2(gate, O_CLOEXEC)) return refuse("stop gate pipe");
    pid_t parent = getpid(), child = fork();
    if (child < 0) { close(gate[0]); close(gate[1]); return refuse("stop fork"); }
    if (child == 0) {
        child_parent_guard(parent); close(gate[1]);
        char authorized = 0; ssize_t received;
        do { received = read(gate[0], &authorized, 1); } while (received < 0 && errno == EINTR);
        close(gate[0]);
        if (received != 1 || authorized != 'G') _exit(124);
        execv(command[0], command); _exit(127);
    }
    close(gate[0]);
    int child_fd = pid_descriptor(child), cleanup_status;
    if (child_fd < 0 || descriptor_exited(held, 0) != 0 || write(gate[1], "G", 1) != 1) {
        close(gate[1]);
        bool retired = retire_child(child, child_fd, &cleanup_status, deadline);
        if (child_fd >= 0) close(child_fd);
        close(held);
        return refuse(retired ? "stop dispatch refused; child retired" : "stop child retirement unresolved");
    }
    close(gate[1]);
    bool reaped = false;
    int result = 0;
    for (;;) {
        long long now = monotonic_ms();
        if (now < 0 || now >= deadline - 1000) break;
        if (!reaped) {
            pid_t waited = waitpid(child, &result, WNOHANG);
            if (waited == child) reaped = true;
            else if (waited < 0 && errno != EINTR) break;
        }
        bool stopped = reaped && WIFEXITED(result) && WEXITSTATUS(result) == 0;
        for (size_t i = 1; i < count && stopped; ++i) {
            char key[80], state[PROP_VALUE_MAX];
            snprintf(key, sizeof(key), "init.svc.%s", command[i]);
            stopped = __system_property_get(key, state) > 0 && !strcmp(state, "stopped");
        }
        if (stopped && descriptor_exited(held, 0) == 1) {
            printf("{\"stage\":\"quiescent\",\"pid\":%d,\"nonce\":\"%s\",\"starttime\":\"%s\",\"boot_id\":\"%s\",\"writer_exited\":true,\"zygotes_stopped\":true,\"native_retirement_proved\":false,\"helper_pid\":%d,\"helper_starttime\":\"%s\",\"helper_boot_id\":\"%s\",\"helper_exe_sha256\":\"%s\",\"helper_exe_device\":%ju,\"helper_exe_inode\":%ju,\"helper_exe_size\":%jd}\n", pid, nonce, actual_ticks, actual_boot, self.pid, self.ticks, self.boot, self.digest, (uintmax_t)self.object.st_dev, (uintmax_t)self.object.st_ino, (intmax_t)self.object.st_size);
            close(child_fd); close(held); return 0;
        }
        struct timespec pause = { .tv_sec = 0, .tv_nsec = 100000000 };
        nanosleep(&pause, NULL);
    }
    if (!reaped && !retire_child(child, child_fd, &result, deadline)) fprintf(stderr, "stop child retirement unconfirmed; whole guest scope must close\n");
    close(child_fd); close(held);
    return refuse("stop incomplete; captured writer or service state unresolved");
#endif
}
#else
#include <assert.h>
static int original_incarnation_tests(void) {
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
    assert(descriptor_exited(fd, 0) == 0);
    char path[64], process_stat[65536], actual[21], boot[64], bound_ticks[21], bound_boot[64];
    snprintf(path, sizeof(path), "/proc/%d", child);
    int directory = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW); assert(directory >= 0);
    assert(read_at(directory, "stat", process_stat, sizeof(process_stat)));
    assert(start_ticks(process_stat, child, actual));
    int kernel = open("/proc/sys/kernel/random", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW); assert(kernel >= 0);
    assert(read_at(kernel, "boot_id", boot, sizeof(boot))); close(kernel);
    assert(incarnation(fd, directory, child, actual, boot, bound_ticks, bound_boot));
    assert(!strcmp(actual, bound_ticks) && !strcmp(boot, bound_boot));
    char wrong[21]; snprintf(wrong, sizeof(wrong), "%llu", strtoull(actual, NULL, 10) + 1);
    assert(!incarnation(fd, directory, child, wrong, boot, bound_ticks, bound_boot));
    char other_boot[64]; strcpy(other_boot, boot); other_boot[0] = boot[0] == 'a' ? 'b' : 'a';
    assert(!incarnation(fd, directory, child, actual, other_boot, bound_ticks, bound_boot));
    assert(!start_ticks(process_stat, child + 1, bound_ticks));
    assert(!start_ticks("99 (broken) S 1 2 3", 99, bound_ticks));
    assert(!decimal_ticks("0") && !decimal_ticks("01") && !decimal_ticks("1x"));
    assert(!decimal_ticks("18446744073709551616"));
    assert(decimal_ticks("18446744073709551615"));
    assert(!boot_syntax("a") && !boot_syntax("00000000000000000000000000000000000000"));
    close(channel[1]);
    assert(descriptor_exited(fd, 2000) == 1);
    assert(!incarnation(fd, directory, child, actual, boot, bound_ticks, bound_boot)); close(directory);
    int status_code; assert(waitpid(child, &status_code, 0) == child);
    assert(WIFEXITED(status_code) && WEXITSTATUS(status_code) == 0); close(fd);
    puts("Captured descriptor, exact subject and bound incarnation checks passed; Android stop unqualified");
    return 0;
}

#include <dirent.h>
static unsigned open_count(void) {
    DIR *stream = opendir("/proc/self/fd"); assert(stream);
    unsigned count = 0; struct dirent *entry;
    while ((entry = readdir(stream))) if (entry->d_name[0] != '.') ++count;
    assert(closedir(stream) == 0); return count;
}
int main(int argc, char **argv) {
    assert(argc == 2 && digest_syntax(argv[1]));
    assert(original_incarnation_tests() == 0);
    unsigned before = open_count();
    int kernel = open("/proc/sys/kernel/random", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    char boot[64]; assert(kernel >= 0 && read_at(kernel, "boot_id", boot, sizeof(boot))); close(kernel);
    struct executable_identity self;
    assert(verify_running_helper(argv[1], boot, &self, monotonic_ms() + 5000));
    assert(self.pid == getpid() && !strcmp(self.digest, argv[1]) && !strcmp(self.boot, boot));
    char wrong[65]; memcpy(wrong, argv[1], sizeof(wrong)); wrong[0] = wrong[0] == 'a' ? 'b' : 'a';
    assert(!verify_running_helper(wrong, boot, &self, monotonic_ms() + 5000));
    assert(!verify_running_helper("0", boot, &self, monotonic_ms() + 5000));
    char path[80], digest[65]; snprintf(path, sizeof(path), "/proc/%d/exe", getpid());
    for (int behavior = 1; behavior <= 4; ++behavior) {
        test_hash_behavior = behavior;
        long long start = monotonic_ms();
        assert(!hash_current_executable(path, digest, start + 50, start + 1000));
        assert(monotonic_ms() - start < 1500);
        int status; errno = 0;
        assert(waitpid(test_hash_child, &status, WNOHANG) == -1 && errno == ECHILD);
    }
    test_hash_behavior = 0;
    struct sigaction ignored = { .sa_handler = SIG_IGN, .sa_flags = SA_NOCLDWAIT };
    assert(sigemptyset(&ignored.sa_mask) == 0 && sigaction(SIGCHLD, &ignored, NULL) == 0);
    assert(hash_current_executable(path, digest, monotonic_ms() + 2000, monotonic_ms() + 3000));
    struct sigaction restored;
    assert(sigaction(SIGCHLD, NULL, &restored) == 0 && restored.sa_handler == SIG_DFL && !(restored.sa_flags & SA_NOCLDWAIT));
    assert(!strcmp(digest, argv[1]));
    assert(open_count() == before);
    printf("Actual self executable digest %s matched; malformed/stderr/exit/timeout refusals reaped children; descriptors restored; Android stop unqualified\n", digest);
    return 0;
}
#endif
