#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <jni.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if !defined(__aarch64__)
#error This disposable proof is ARM64 only
#endif

#define FIELDS(X) \
    X(status) X(error_stage) X(error_errno) X(cleanup_errno) \
    X(uid) X(euid) X(gid) X(egid) X(selinux) X(cap_eff) X(mappings) X(page_size) \
    X(source_path) X(source_mode) X(source_uid) X(source_size) X(source_dev_inode) \
    X(copy_path) X(copy_dir_mode) X(copy_mode) X(copy_uid) X(copy_size) \
    X(copy_mount_noexec) X(byte_identity_before) X(byte_identity_after) \
    X(control_outcome) X(control_stage) X(control_errno) X(control_exit) \
    X(control_signal) X(control_reaped) \
    X(copy_outcome) X(copy_stage) X(copy_errno) X(copy_exit) X(copy_signal) X(copy_reaped)
#define ENUM(name) F_##name,
enum field { FIELDS(ENUM) FIELD_COUNT };
#undef ENUM
#define NAME(name) #name,
static const char *const names[] = { FIELDS(NAME) };
#undef NAME

struct report { JNIEnv *env; jobjectArray pairs; };

static void text(struct report *r, enum field field, const char *value) {
    if ((*r->env)->ExceptionCheck(r->env)) return;
    jstring string = (*r->env)->NewStringUTF(r->env, value);
    if (string == NULL) return;
    (*r->env)->SetObjectArrayElement(r->env, r->pairs, 2 * field + 1, string);
    (*r->env)->DeleteLocalRef(r->env, string);
}

static void number(struct report *r, enum field field, intmax_t value) {
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%jd", value);
    text(r, field, buffer);
}

static void mode(struct report *r, enum field field, mode_t value) {
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%04o", (unsigned)(value & 07777));
    text(r, field, buffer);
}

static int read_small(const char *path, char *buffer, size_t capacity) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t used = 0;
    for (;;) {
        ssize_t count = read(fd, buffer + used, capacity - 1 - used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { int error = errno; close(fd); errno = error; return -1; }
        if (count == 0) break;
        used += (size_t)count;
        if (used == capacity - 1) { close(fd); errno = EOVERFLOW; return -1; }
    }
    if (close(fd) != 0) return -1;
    while (used && (buffer[used - 1] == '\n' || buffer[used - 1] == '\0')) --used;
    buffer[used] = '\0';
    if (used == 0) { errno = EINVAL; return -1; }
    return 0;
}

static int proc_fields(struct report *r) {
    char buffer[32768];
    if (read_small("/proc/self/attr/current", buffer, sizeof(buffer)) != 0) return -1;
    text(r, F_selinux, buffer);
    if (read_small("/proc/self/status", buffer, sizeof(buffer)) != 0) return -1;
    char *caps = strstr(buffer, "\nCapEff:\t");
    if (caps == NULL) { errno = EINVAL; return -1; }
    caps += strlen("\nCapEff:\t");
    char *end = strchr(caps, '\n');
    if (end == NULL) { errno = EINVAL; return -1; }
    *end = '\0';
    text(r, F_cap_eff, caps);

    FILE *maps = fopen("/proc/self/maps", "re");
    if (maps == NULL) return -1;
    char line[4096];
    size_t used = 0;
    buffer[0] = '\0';
    while (fgets(line, sizeof(line), maps) != NULL) {
        if (strchr(line, '\n') == NULL) { fclose(maps); errno = EOVERFLOW; return -1; }
        if (strstr(line, "/linker64") == NULL && strstr(line, "/libc.so") == NULL) continue;
        size_t length = strlen(line);
        if (length >= sizeof(buffer) - used) { fclose(maps); errno = EOVERFLOW; return -1; }
        memcpy(buffer + used, line, length + 1);
        used += length;
    }
    if (ferror(maps)) { int error = errno ? errno : EIO; fclose(maps); errno = error; return -1; }
    if (fclose(maps) != 0) return -1;
    if (used == 0) { errno = EINVAL; return -1; }
    text(r, F_mappings, buffer);
    return 0;
}

// A CLOEXEC pipe distinguishes a failed execve from loader/program exit status.
// No JNI, allocation, stdio, logging, or other non-async-signal-safe work in child.
struct child_error { int stage; int error; }; // 1 = stdio setup, 2 = execve
static _Noreturn void child_fail(int fd, int stage, int error) {
    const struct child_error message = { stage, error };
    const char *bytes = (const char *)&message;
    size_t left = sizeof(message);
    while (left) {
        ssize_t count = write(fd, bytes, left);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) _exit(126); // An incomplete error record cannot pass.
        bytes += count;
        left -= (size_t)count;
    }
    _exit(127);
}

struct execution {
    const char *outcome;
    const char *stage;
    int error;
    int exit_code;
    int signal;
    int reaped;
};

// Finite polls, including during SIGKILL cleanup. Never a blocking wait/read.
static int wait_bounded(pid_t child, int *status, unsigned polls) {
    const struct timespec pause = { .tv_sec = 0, .tv_nsec = 10000000 };
    for (unsigned index = 0; index < polls; ++index) {
        pid_t found = waitpid(child, status, WNOHANG);
        if (found == child) return 1;
        if (found < 0 && errno != EINTR) return -1;
        nanosleep(&pause, NULL);
    }
    return 0;
}

static struct execution execute(const char *path) {
    struct execution result = { "setup_error", "open_dev_null", 0, -1, 0, 0 };
    int nullfd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (nullfd < 0) { result.error = errno; return result; }
    int channel[2];
    result.stage = "pipe";
    if (pipe2(channel, O_CLOEXEC | O_NONBLOCK) != 0) {
        result.error = errno; close(nullfd); return result;
    }
    // Do not accidentally overwrite an error-pipe descriptor in the child.
    if (nullfd <= STDERR_FILENO || channel[0] <= STDERR_FILENO || channel[1] <= STDERR_FILENO) {
        result.error = EBADF;
        close(nullfd); close(channel[0]); close(channel[1]); return result;
    }
    char *const argv[] = { (char *)"/system/bin/sh", (char *)"-c", (char *)"exit 0", NULL };
    char *const envp[] = { (char *)"PATH=/system/bin", (char *)"HOME=/", (char *)"LANG=C", NULL };
    pid_t child = fork();
    if (child == 0) {
        close(channel[0]);
        for (int fd = STDIN_FILENO; fd <= STDERR_FILENO; ++fd) {
            if (dup2(nullfd, fd) < 0) child_fail(channel[1], 1, errno);
        }
        close(nullfd);
        execve(path, argv, envp);
        child_fail(channel[1], 2, errno);
    }
    int fork_error = errno;
    close(nullfd);
    close(channel[1]);
    if (child < 0) {
        result.stage = "fork"; result.error = fork_error; close(channel[0]); return result;
    }
    int status = 0;
    int waited = wait_bounded(child, &status, 500);
    if (waited != 1) {
        result.outcome = waited == 0 ? "timeout" : "wait_error";
        result.stage = "waitpid";
        result.error = waited == 0 ? ETIMEDOUT : errno;
        if (waited == 0) {
            // Still our unreaped child, so its PID cannot have been reused.
            if (kill(child, SIGKILL) != 0 && errno != ESRCH) result.error = errno;
            result.reaped = wait_bounded(child, &status, 200) == 1;
            if (result.reaped && WIFEXITED(status)) result.exit_code = WEXITSTATUS(status);
            if (result.reaped && WIFSIGNALED(status)) result.signal = WTERMSIG(status);
        }
        close(channel[0]);
        return result;
    }
    result.reaped = 1;
    if (WIFEXITED(status)) result.exit_code = WEXITSTATUS(status);
    if (WIFSIGNALED(status)) result.signal = WTERMSIG(status);
    unsigned char bytes[sizeof(struct child_error) + 1];
    size_t used = 0;
    int read_error = 0;
    for (;;) {
        ssize_t count = read(channel[0], bytes + used, sizeof(bytes) - used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { read_error = errno; break; }
        if (count == 0) break;
        used += (size_t)count;
        if (used == sizeof(bytes)) break;
    }
    close(channel[0]);
    result.stage = "error_pipe";
    result.outcome = "protocol_error";
    result.error = read_error;
    if (read_error != 0) return result;
    if (used == sizeof(struct child_error)) {
        struct child_error message;
        memcpy(&message, bytes, sizeof(message));
        if (message.error <= 0 || result.exit_code != 127 || result.signal != 0) return result;
        result.error = message.error;
        if (message.stage == 1) { result.stage = "child_stdio"; result.outcome = "setup_error"; }
        if (message.stage == 2) { result.stage = "execve"; result.outcome = "exec_errno"; }
    } else if (used == 0) {
        result.stage = "waitpid";
        result.outcome = WIFEXITED(status) ? "exited" : "signaled";
    }
    return result;
}

static void execution_fields(struct report *r, int copy, struct execution value) {
    text(r, copy ? F_copy_outcome : F_control_outcome, value.outcome);
    text(r, copy ? F_copy_stage : F_control_stage, value.stage);
    number(r, copy ? F_copy_errno : F_control_errno, value.error);
    number(r, copy ? F_copy_exit : F_control_exit, value.exit_code);
    number(r, copy ? F_copy_signal : F_control_signal, value.signal);
    number(r, copy ? F_copy_reaped : F_control_reaped, value.reaped);
}

static int copy_bytes(int source, int destination) {
    char buffer[16384];
    for (;;) {
        ssize_t count = read(source, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) return -1;
        if (count == 0) return 0;
        ssize_t done = 0;
        while (done < count) {
            ssize_t written = write(destination, buffer + done, (size_t)(count - done));
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) { if (written == 0) errno = EIO; return -1; }
            done += written;
        }
    }
}

static int pread_full(int fd, void *buffer, size_t length, off_t offset) {
    size_t done = 0;
    while (done < length) {
        ssize_t count = pread(fd, (char *)buffer + done, length - done, offset + (off_t)done);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { if (count == 0) errno = EIO; return -1; }
        done += (size_t)count;
    }
    return 0;
}

static int identical(int source, int destination, off_t size) {
    char left[16384], right[16384];
    for (off_t offset = 0; offset < size;) {
        size_t count = (size - offset) < (off_t)sizeof(left) ? (size_t)(size - offset) : sizeof(left);
        if (pread_full(source, left, count, offset) || pread_full(destination, right, count, offset)) return -1;
        if (memcmp(left, right, count) != 0) { errno = EINVAL; return -1; }
        offset += (off_t)count;
    }
    struct stat a, b;
    if (fstat(source, &a) || fstat(destination, &b)) return -1;
    if (a.st_size != size || b.st_size != size) { errno = EINVAL; return -1; }
    return 0;
}

JNIEXPORT jobjectArray JNICALL
Java_dev_andrix_proof_p5_P5Instrumentation_probe(JNIEnv *env, jclass klass, jstring directory) {
    (void)klass;
    jclass strings = (*env)->FindClass(env, "java/lang/String");
    if (strings == NULL) return NULL;
    struct report r = { env, (*env)->NewObjectArray(env, FIELD_COUNT * 2, strings, NULL) };
    (*env)->DeleteLocalRef(env, strings);
    if (r.pairs == NULL) return NULL;
    for (int index = 0; index < FIELD_COUNT; ++index) {
        jstring key = (*env)->NewStringUTF(env, names[index]);
        if (key == NULL) return NULL;
        (*env)->SetObjectArrayElement(env, r.pairs, 2 * index, key);
        (*env)->DeleteLocalRef(env, key);
        text(&r, (enum field)index, "");
        if ((*env)->ExceptionCheck(env)) return NULL;
    }
    text(&r, F_status, "error");
    number(&r, F_error_errno, 0);
    number(&r, F_cleanup_errno, 0);
    text(&r, F_control_outcome, "not_run");
    text(&r, F_copy_outcome, "not_run");
    number(&r, F_uid, getuid()); number(&r, F_euid, geteuid());
    number(&r, F_gid, getgid()); number(&r, F_egid, getegid());
    number(&r, F_page_size, sysconf(_SC_PAGESIZE));
    text(&r, F_source_path, "/system/bin/sh");

    const char *files = (*env)->GetStringUTFChars(env, directory, NULL);
    if (files == NULL) return NULL;
    const char *stage = "identity";
    int error = 0, cleanup_error = 0;
    int source = -1, destination = -1, private_dir = -1;
    int made_dir = 0, made_file = 0;
    char dirpath[PATH_MAX] = "", copypath[PATH_MAX] = "";
    struct stat original, copied, parent;
#define REQUIRE(condition) do { if (!(condition)) { error = errno ? errno : EINVAL; goto done; } } while (0)
#define CHECK(condition) do { if (!(condition)) { error = EINVAL; goto done; } } while (0)
    CHECK(getuid() >= 10000 && getuid() <= 19999 && geteuid() == getuid()
            && getgid() == getuid() && getegid() == getuid());
    stage = "proc_identity";
    REQUIRE(proc_fields(&r) == 0);
    stage = "open_source";
    source = open("/system/bin/sh", O_RDONLY | O_CLOEXEC);
    REQUIRE(source >= 0);
    REQUIRE(fstat(source, &original) == 0);
    mode(&r, F_source_mode, original.st_mode);
    number(&r, F_source_uid, original.st_uid);
    number(&r, F_source_size, original.st_size);
    char inode[128];
    snprintf(inode, sizeof(inode), "%ju:%ju", (uintmax_t)original.st_dev, (uintmax_t)original.st_ino);
    text(&r, F_source_dev_inode, inode);
    CHECK(S_ISREG(original.st_mode) && (original.st_mode & 07777) == 0755
            && original.st_uid == 0 && original.st_size > 0 && original.st_size <= 16 * 1024 * 1024);

    stage = "control_not_valid";
    struct execution control = execute("/system/bin/sh");
    execution_fields(&r, 0, control);
    CHECK(strcmp(control.outcome, "exited") == 0 && control.exit_code == 0
            && control.error == 0 && control.reaped == 1);

    stage = "private_directory";
    REQUIRE(lstat(files, &parent) == 0);
    CHECK(S_ISDIR(parent.st_mode) && parent.st_uid == getuid());
    int length = snprintf(dirpath, sizeof(dirpath), "%s/p5.XXXXXX", files);
    CHECK(length > 0 && (size_t)length < sizeof(dirpath));
    REQUIRE(mkdtemp(dirpath) != NULL);
    made_dir = 1;
    private_dir = open(dirpath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    REQUIRE(private_dir >= 0);
    REQUIRE(fstat(private_dir, &parent) == 0);
    mode(&r, F_copy_dir_mode, parent.st_mode);
    CHECK(S_ISDIR(parent.st_mode) && parent.st_uid == getuid() && (parent.st_mode & 07777) == 0700);
    struct statvfs mount;
    REQUIRE(fstatvfs(private_dir, &mount) == 0);
    number(&r, F_copy_mount_noexec, (mount.f_flag & ST_NOEXEC) != 0);
    // Exclude a noexec mount as the reason for EACCES; never change mount flags.
    CHECK((mount.f_flag & ST_NOEXEC) == 0);
    length = snprintf(copypath, sizeof(copypath), "%s/sh", dirpath);
    CHECK(length > 0 && (size_t)length < sizeof(copypath));
    text(&r, F_copy_path, copypath);
    stage = "copy_and_chmod";
    destination = open(copypath, O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
    REQUIRE(destination >= 0);
    made_file = 1;
    REQUIRE(copy_bytes(source, destination) == 0);
    REQUIRE(fchmod(destination, 0700) == 0);
    REQUIRE(fsync(destination) == 0);
    // An open writable fd would cause ETXTBSY, not the policy under test.
    int writable = destination;
    destination = -1;
    REQUIRE(close(writable) == 0);
    destination = open(copypath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    REQUIRE(destination >= 0);
    REQUIRE(fstat(destination, &copied) == 0);
    mode(&r, F_copy_mode, copied.st_mode);
    number(&r, F_copy_uid, copied.st_uid);
    number(&r, F_copy_size, copied.st_size);
    CHECK(S_ISREG(copied.st_mode) && (copied.st_mode & 07777) == 0700
            && copied.st_uid == getuid() && copied.st_nlink == 1);
    stage = "compare_before";
    REQUIRE(identical(source, destination, original.st_size) == 0);
    text(&r, F_byte_identity_before, "identical");

    struct execution denied = execute(copypath);
    execution_fields(&r, 1, denied);
    stage = "compare_after";
    REQUIRE(identical(source, destination, original.st_size) == 0);
    text(&r, F_byte_identity_after, "identical");
    struct stat current;
    REQUIRE(stat("/system/bin/sh", &current) == 0);
    CHECK(current.st_dev == original.st_dev && current.st_ino == original.st_ino
            && current.st_mode == original.st_mode && current.st_size == original.st_size
            && current.st_mtim.tv_sec == original.st_mtim.tv_sec
            && current.st_mtim.tv_nsec == original.st_mtim.tv_nsec);
    REQUIRE(lstat(copypath, &current) == 0);
    CHECK(current.st_dev == copied.st_dev && current.st_ino == copied.st_ino
            && current.st_mode == copied.st_mode && current.st_uid == copied.st_uid);
    stage = "copy_not_EACCES";
    CHECK(strcmp(denied.outcome, "exec_errno") == 0 && denied.error == EACCES
            && denied.exit_code == 127 && denied.signal == 0 && denied.reaped == 1);
    text(&r, F_status, "complete");
    stage = "";

done:
    if (destination >= 0 && close(destination) != 0) cleanup_error = errno;
    if (source >= 0 && close(source) != 0) cleanup_error = errno;
    if (private_dir >= 0 && close(private_dir) != 0) cleanup_error = errno;
    if (made_file && unlink(copypath) != 0) cleanup_error = errno;
    if (made_dir && rmdir(dirpath) != 0) cleanup_error = errno;
    text(&r, F_error_stage, stage);
    number(&r, F_error_errno, error);
    number(&r, F_cleanup_errno, cleanup_error);
    (*env)->ReleaseStringUTFChars(env, directory, files);
    return r.pairs;
#undef REQUIRE
#undef CHECK
}
