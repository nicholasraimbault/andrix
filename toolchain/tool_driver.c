// SPDX-License-Identifier: Apache-2.0
// Ordinary native command. No UID, environment, permission or sandbox changes.
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failed(const char *name) {
    int status = errno == ENOENT ? 127 : 126;
    perror(name);
    return status;
}

int main(int argc, char **argv) {
    if (argc < 1 || (size_t)argc > SIZE_MAX / sizeof(char *) - 3) {
        fputs("clang++: invalid argument count\n", stderr);
        return 126;
    }
    const char *name = strrchr(argv[0], '/');
    name = name ? name + 1 : argv[0];
    if (!strcmp(name, "cc")) {
        execv("/usr/bin/clang", argv);
        return failed(name);
    }
    if (!strcmp(name, "ar") || !strcmp(name, "ranlib") || !strcmp(name, "llvm-ranlib")) {
        // llvm-ar selects archive vs ranlib behavior from the unchanged argv[0].
        execv("/usr/bin/llvm-ar", argv);
        return failed(name);
    }
    char **args = calloc((size_t)argc + 3, sizeof(char *));
    if (!args) {
        perror("clang++");
        return 126;
    }
    args[0] = "/usr/bin/clang";
    args[1] = "--driver-mode=g++";
    args[2] = (!strcmp(name, "clang++-shared") || !strcmp(name, "c++-shared"))
        ? "--config=/usr/etc/andrix/cxx-shared.cfg"
        : "--config=/usr/etc/andrix/cxx.cfg";
    for (int i = 1; i < argc; ++i) args[(size_t)i + 2] = argv[i];
    execv(args[0], args);
    int status = failed("clang++");
    free(args);
    return status;
}
