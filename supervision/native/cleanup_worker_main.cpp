// SPDX-License-Identifier: Apache-2.0
// Fixed internal Android bootstrap. No caller supplied program or profile.
#include "cleanup_worker.h"

#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <selinux/selinux.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <charconv>
#include <cstring>
#include <string_view>
#include <utility>

namespace {
int apply_profile() {
    uid_t real_uid, effective_uid, saved_uid;
    gid_t real_gid, effective_gid, saved_gid;
    if (getppid() != 1 || getresuid(&real_uid, &effective_uid, &saved_uid) ||
        getresgid(&real_gid, &effective_gid, &saved_gid) || real_uid || effective_uid ||
        saved_uid || real_gid || effective_gid || saved_gid)
        return 120;
    char* context = nullptr;
    if (getcon(&context) || !context) return 121;
    const bool role = std::string_view(context) == "u:r:andrix_scope_cleanup:s0";
    freecon(context);
    if (!role || setgroups(0, nullptr) || getgroups(0, nullptr) != 0) return 122;
    if (setpriority(PRIO_PROCESS, 0, 10) || prctl(PR_SET_DUMPABLE, 0)) return 123;
    for (auto [resource, bound] : {std::pair{RLIMIT_CORE, rlim_t(0)},
                                   {RLIMIT_NOFILE, rlim_t(128)},
                                   {RLIMIT_CPU, rlim_t(10)}}) {
        const rlimit wanted{bound, bound};
        rlimit actual{};
        if (setrlimit(resource, &wanted) || getrlimit(resource, &actual) ||
            actual.rlim_cur != bound || actual.rlim_max != bound)
            return 124;
    }
    // SETPCAP remains effective only during this declared bounding-set transition.
    unsigned last = 0;
    for (unsigned cap = 0; cap < 64; ++cap) {
        errno = 0;
        const int present = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        if (present < 0) {
            if (errno != EINVAL || cap <= CAP_DAC_OVERRIDE) return 125;
            last = cap;
            break;
        }
        if (cap == CAP_DAC_OVERRIDE) {
            if (present != 1) return 125;
        } else if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0))
            return 125;
    }
    if (!last) return 125;
    __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
    __user_cap_data_struct capabilities[2]{};
    capabilities[0].effective = capabilities[0].permitted = 1U << CAP_DAC_OVERRIDE;
    if (syscall(SYS_capset, &header, capabilities) ||
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return 126;
    __user_cap_data_struct actual[2]{};
    if (syscall(SYS_capget, &header, actual) || actual[0].effective != (1U << CAP_DAC_OVERRIDE) ||
        actual[0].permitted != (1U << CAP_DAC_OVERRIDE) || actual[0].inheritable ||
        actual[1].effective || actual[1].permitted || actual[1].inheritable)
        return 126;
    for (unsigned cap = 0; cap < last; ++cap) {
        if (prctl(PR_CAPBSET_READ, cap, 0, 0, 0) != static_cast<int>(cap == CAP_DAC_OVERRIDE) ||
            prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0) != 0)
            return 126;
    }
    errno = 0;
    if (getpriority(PRIO_PROCESS, 0) != 10 || errno || prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0 ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
        return 126;
    DIR* descriptors = opendir("/proc/self/fd");
    if (!descriptors) return 127;
    bool closed = true;
    while (auto* entry = readdir(descriptors)) {
        if (entry->d_name[0] == '.') continue;
        int descriptor = -1;
        const auto parsed =
                std::from_chars(entry->d_name, entry->d_name + strlen(entry->d_name), descriptor);
        if (parsed.ec != std::errc{} || *parsed.ptr != 0 || descriptor < 0 ||
            (descriptor > 3 && descriptor != dirfd(descriptors)))
            closed = false;
    }
    closedir(descriptors);
    return closed ? 0 : 127;
}
}  // namespace

int main(int argc, char** argv) {
    if (argc != 2 || std::string_view(argv[1]) != "3") return 119;
    const int result = apply_profile();
    if (result) return result;
    return andrix::supervision::RunCleanupWorker(3, {1, 0, 0});
}
