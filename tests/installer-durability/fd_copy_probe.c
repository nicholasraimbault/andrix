// SPDX-License-Identifier: Apache-2.0
// Disposable file-write comparison, not installation, recovery or execution authority.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

#ifdef FD_COPY_HOST_TEST
#ifndef FD_COPY_TEST_BASE
#error "host test needs an explicit compiled directory"
#endif
#define BASE FD_COPY_TEST_BASE
#else
#define BASE "/data/local/tmp"
#endif

#define MAX_BYTES 65536
static const char *groups[] = {"durable", "namespace", "unsynced"};
static unsigned int event_number;
static int failed;
#ifdef FD_COPY_FAULT_TEST
static unsigned int fail_sync, sync_calls;
#endif

static uint64_t now_ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_BOOTTIME, &t) != 0) return 0;
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
static void error_at(const char *stage) {
    int saved = errno;
    failed = 1;
    fprintf(stderr, "{\"stage\":\"%s\",\"errno\":%d,\"outcome\":\"unknown; retain original files\"}\n", stage, saved);
}
static bool event(const char *stage, const char *group) {
    if (printf("{\"event\":%u,\"stage\":\"%s\",\"group\":\"%s\",\"boottime_ns\":%" PRIu64 "}\n",
               ++event_number, stage, group, now_ns()) < 0 || fflush(stdout) != 0) {
        error_at("output"); return false;
    }
    return true;
}
static bool closed(int *fd, const char *stage) {
    if (*fd < 0) return true;
    int value = *fd;
    *fd = -1; // Never retry close on a potentially reused descriptor number.
    if (close(value) != 0) { error_at(stage); return false; }
    return true;
}
static bool synced(int fd, const char *stage, const char *group) {
#ifdef FD_COPY_FAULT_TEST
    if (++sync_calls == fail_sync) { errno = EIO; error_at(stage); return false; }
#endif
    if (fsync(fd) != 0) { error_at(stage); return false; }
    return event(stage, group);
}
static bool nonce_ok(const char *nonce) {
    if (strlen(nonce) != 32) return false;
    for (size_t i = 0; i < 32; i++) {
        if (!((nonce[i] >= '0' && nonce[i] <= '9') || (nonce[i] >= 'a' && nonce[i] <= 'f'))) return false;
    }
    return true;
}
static bool regular(int fd, struct stat *st) {
    if (fstat(fd, st) != 0) { error_at("fstat-file"); return false; }
    if (!S_ISREG(st->st_mode) || st->st_nlink != 1 || st->st_size < 0 || st->st_size > MAX_BYTES) {
        errno = EINVAL; error_at("file-shape"); return false;
    }
    return true;
}
static bool same_file(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size
        && a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec
        && a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static bool meta(int fd, const char *group, const char *name) {
    struct stat st;
    struct statfs fs;
    if (fstat(fd, &st) != 0 || fstatfs(fd, &fs) != 0) { error_at("metadata"); return false; }
    long flags = 0;
    int flags_errno = ioctl(fd, FS_IOC_GETFLAGS, &flags) == 0 ? 0 : errno;
    if (printf("{\"group\":\"%s\",\"name\":\"%s\",\"inode\":%" PRIuMAX
               ",\"bytes\":%" PRIdMAX ",\"mode\":%u,\"uid\":%u,\"gid\":%u,\"fs_type\":%" PRIdMAX
               ",\"file_flags\":%ld,\"flags_errno\":%d,\"boottime_ns\":%" PRIu64 "}\n",
               group, name, (uintmax_t)st.st_ino, (intmax_t)st.st_size,
               (unsigned int)(st.st_mode & 07777), (unsigned int)st.st_uid, (unsigned int)st.st_gid,
               (intmax_t)fs.f_type, flags, flags_errno, now_ns()) < 0 || fflush(stdout) != 0) {
        error_at("metadata-output"); return false;
    }
    return true;
}
static bool copy_group(int root, int input, off_t length, unsigned int mode) {
    const char *group = groups[mode];
    char stage[32];
    int directory = -1, output = -1;
    bool ok = false;
    if (snprintf(stage, sizeof(stage), "%s.stage", group) < 0) return false;
    if (!event("create-start", group)) goto done;
    if (mkdirat(root, stage, 0700) != 0) { error_at("mkdir-group"); goto done; }
    directory = openat(root, stage, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) { error_at("open-group"); goto done; }
    output = openat(directory, "payload.apk", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (output < 0) { error_at("open-output"); goto done; }
    int alloc = posix_fallocate(output, 0, length);
    if (alloc != 0) { errno = alloc; error_at("allocate-output"); goto done; }
    off_t offset = 0;
    while (offset < length) {
        ssize_t written = sendfile(output, input, &offset, (size_t)(length - offset));
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) { if (written == 0) errno = EIO; error_at("copy-output"); goto done; }
    }
    if (!event("copy-complete", group)) goto done;
    if (mode == 0 && !synced(output, "writing-fd-synced", group)) goto done;
    if (!meta(output, group, "payload.apk")) goto done;
    if (!closed(&output, "close-output")) goto done;
    if (!event("writing-fd-closed", group)) goto done;
    if (mode == 0 && !synced(directory, "file-entry-synced", group)) goto done;
    if (syscall(SYS_renameat2, root, stage, root, group, RENAME_NOREPLACE) != 0) {
        error_at("rename-group"); goto done;
    }
    if (!event("renamed", group)) goto done;
    if (mode != 2 && !synced(root, "parent-directory-synced", group)) goto done;
    if (!meta(directory, group, "directory")) goto done;
    ok = true;
done:
    if (!closed(&output, "close-output-after-error")) ok = false;
    if (!closed(&directory, "close-group")) ok = false;
    return ok;
}
static bool missing(const char *group, const char *name) {
    return printf("{\"group\":\"%s\",\"name\":\"%s\",\"state\":\"absent\",\"errno\":%d}\n",
                  group, name, ENOENT) >= 0;
}
static bool observe_group(int root, const char *name) {
    int directory = -1, file = -1;
    bool ok = false;
    directory = openat(root, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) {
        if (errno == ENOENT) return missing(name, "directory");
        error_at("observe-directory"); return false;
    }
    if (!meta(directory, name, "directory")) goto done;
    file = openat(directory, "payload.apk", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (file < 0) {
        if (errno == ENOENT) { ok = missing(name, "payload.apk"); goto done; }
        error_at("observe-file"); goto done;
    }
    struct stat before, after;
    if (!regular(file, &before)) goto done;
    unsigned char data[MAX_BYTES + 1];
    size_t size = 0;
    for (;;) {
        ssize_t count = read(file, data + size, sizeof(data) - size);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { error_at("observe-read"); goto done; }
        if (count == 0) break;
        size += (size_t)count;
        if (size == sizeof(data)) { errno = EFBIG; error_at("observe-bound"); goto done; }
    }
    if (!regular(file, &after) || !same_file(&before, &after) || (uintmax_t)size != (uintmax_t)before.st_size) {
        errno = EBUSY; error_at("observe-file-changed"); goto done;
    }
    if (!meta(file, name, "payload.apk")) goto done;
    if (printf("{\"group\":\"%s\",\"name\":\"payload.apk\",\"hex\":\"", name) < 0) goto output_error;
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < size; i++) {
        if (putchar(hex[data[i] >> 4]) == EOF || putchar(hex[data[i] & 15]) == EOF) goto output_error;
    }
    if (puts("\"}") == EOF || fflush(stdout) != 0) goto output_error;
    ok = true;
    goto done;
output_error:
    error_at("observe-output");
done:
    if (!closed(&file, "observe-close-file")) ok = false;
    if (!closed(&directory, "observe-close-directory")) ok = false;
    return ok;
}
int main(int argc, char **argv) {
    if (argc != 3 || !nonce_ok(argv[2]) || (strcmp(argv[1], "prepare") && strcmp(argv[1], "observe"))) return 2;
#ifndef FD_COPY_HOST_TEST
    if (getuid() != 0 || geteuid() != 0) return 2;
#endif
#ifdef FD_COPY_FAULT_TEST
    const char *fail = getenv("FD_COPY_FAIL_SYNC");
    if (fail != NULL) {
        char *end;
        unsigned long value = strtoul(fail, &end, 10);
        if (!*fail || *end || value > 20) return 2;
        fail_sync = (unsigned int)value;
    }
#endif
    char root_name[64], input_name[80];
    (void)snprintf(root_name, sizeof(root_name), "andrix-writeback-%s", argv[2]);
    (void)snprintf(input_name, sizeof(input_name), "andrix-writeback-input-%s.apk", argv[2]);
    int parent = -1, root = -1, input = -1;
    bool ok = false;
    parent = open(BASE, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent < 0) { error_at("open-base"); goto done; }
    if (strcmp(argv[1], "observe") == 0) {
        root = openat(parent, root_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (root < 0) {
            if (errno == ENOENT) { ok = missing("root", "directory"); goto done; }
            error_at("observe-root"); goto done;
        }
        for (unsigned int i = 0; i < 3; i++) {
            char stage[32];
            (void)snprintf(stage, sizeof(stage), "%s.stage", groups[i]);
            if (!observe_group(root, groups[i]) || !observe_group(root, stage)) goto done;
        }
        ok = true;
        goto done;
    }
    input = openat(parent, input_name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (input < 0) { error_at("open-input"); goto done; }
    struct stat before, after;
    if (!regular(input, &before) || before.st_size <= 4096) { errno = EINVAL; error_at("input-size"); goto done; }
    if (!event("prepare-start", "root")) goto done;
    if (mkdirat(parent, root_name, 0700) != 0) { error_at("exclusive-root-create"); goto done; }
    root = openat(parent, root_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) { error_at("open-root"); goto done; }
    if (!synced(root, "empty-root-synced", "root") || !synced(parent, "root-name-synced", "root")) goto done;
    for (unsigned int i = 0; i < 3; i++) if (!copy_group(root, input, before.st_size, i)) goto done;
    if (!regular(input, &after) || !same_file(&before, &after)) { errno = EBUSY; error_at("input-changed"); goto done; }
    ok = true;
done:
    if (!closed(&input, "close-input")) ok = false;
    if (!closed(&root, "close-root")) ok = false;
    if (!closed(&parent, "close-base")) ok = false;
    if (!ok || failed) return 1;
    if (printf("{\"complete\":true,\"operation\":\"%s\",\"nonce\":\"%s\",\"physical_power_loss_proved\":false}\n", argv[1], argv[2]) < 0 || fflush(stdout) != 0) return 1;
    return 0;
}
