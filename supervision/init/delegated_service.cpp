// SPDX-License-Identifier: Apache-2.0
// Optional integration candidate. Built only for the delegated-service proof.
#include "delegated_service.h"

#include <fcntl.h>
#include <linux/openat2.h>
#include <poll.h>
#include <selinux/selinux.h>
#include <spawn.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <processgroup/processgroup.h>
#if defined(__BIONIC__)
#include <liblmkd_utils.h>
#endif

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <limits>
#include <map>
#include <optional>

#include "captured_cgroup.h"
#include "cleanup_worker.h"
#include "epoll.h"
#include "init.h"
#include "instance_state.h"
#include "lmkd_service.h"
#include "service.h"
#include "service_utils.h"

namespace android::init {
namespace sup = andrix::supervision;
using android::base::boot_clock;
using android::base::ReadFileToString;
using android::base::SetProperty;
using android::base::unique_fd;
using android::base::WriteStringToFd;
using namespace std::chrono_literals;
namespace {
constexpr auto kReplyTimeout = 5s;
constexpr auto kReadyTimeout = 20s;
constexpr auto kKillGrace = 200ms;
constexpr size_t kMaximumInstances = 4;
constexpr uint64_t kMaximumWorkers = 3;
constexpr uint32_t kQuantum = 32;
constexpr auto kCleanupDeadline = 30s;
struct ReadyMessage {
    uint64_t magic = 0x44454c4547415445ULL;
    uint64_t boot = 0, instance = 0, device = 0, inode = 0;
};
Epoll* event_loop = nullptr;
std::function<void()> wake_main;
unique_fd timer;
unique_fd platform_parent;
std::string platform_path;
bool platform_parent_ready = false;
std::unique_ptr<sup::InstanceAllocator> identities;
std::map<uint64_t, std::weak_ptr<DelegatedInstance>> instances;
bool pumping = false;
// Epoll removes handler map entries after dispatch. Keep their FD numbers owned
// until that point, even when recovery runs from the first reap callback.
std::vector<unique_fd> retired_event_fds;

Result<unique_fd> OpenDirectoryAt(int parent, const char* name) {
    open_how how{};
    how.flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC;
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV;
    unique_fd fd(static_cast<int>(syscall(SYS_openat2, parent, name, &how, sizeof(how))));
    if (fd < 0) return ErrnoError() << "open exact directory " << name;
    return fd;
}
Result<void> WriteRead(int directory, const char* file, const std::string& value) {
    unique_fd fd(openat(directory, file, O_WRONLY | O_CLOEXEC | O_NOFOLLOW));
    if (fd < 0 || !WriteStringToFd(value, fd.get())) return ErrnoError() << "write " << file;
    unique_fd read(openat(directory, file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    std::string actual;
    if (read < 0 || !android::base::ReadFdToString(read.get(), &actual) ||
        android::base::Trim(actual) != value)
        return Error() << "readback " << file;
    return {};
}
Result<void> EnableMemory(int directory) {
    unique_fd fd(openat(directory, "cgroup.subtree_control", O_WRONLY | O_CLOEXEC | O_NOFOLLOW));
    if (fd < 0 || !WriteStringToFd("+memory", fd.get())) return ErrnoError() << "activate memory";
    unique_fd read(openat(directory, "cgroup.subtree_control", O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    std::string text;
    if (read < 0 || !android::base::ReadFdToString(read.get(), &text))
        return ErrnoError() << "read controllers";
    const auto controllers = android::base::Split(android::base::Trim(text), " ");
    if (std::find(controllers.begin(), controllers.end(), "memory") == controllers.end())
        return Error() << "memory unavailable";
    return {};
}
Result<void> DirectoryMode(int fd, uid_t uid, gid_t gid, mode_t mode) {
    if (fchown(fd, uid, gid) || fchmod(fd, mode)) return ErrnoError() << "directory ownership";
    struct stat info{};
    if (fstat(fd, &info) || info.st_uid != uid || info.st_gid != gid ||
        (info.st_mode & 0777) != mode)
        return Error() << "directory ownership readback";
    return {};
}
Result<void> DelegateFile(int directory, const char* name, uid_t uid, gid_t gid) {
    unique_fd fd(openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (fd < 0 || fchown(fd.get(), uid, gid) || fchmod(fd.get(), 0644))
        return ErrnoError() << "delegate " << name;
    struct stat info{};
    if (fstat(fd.get(), &info) || info.st_uid != uid || info.st_gid != gid ||
        (info.st_mode & 0777) != 0644)
        return Error() << "delegation readback " << name;
    return {};
}
Result<void> PrepareParent() {
    if (platform_parent >= 0) {
        if (!platform_parent_ready) return Error() << "platform scope namespace setup failed";
        return {};
    }
    std::string hierarchy;
    if (!CgroupGetControllerPath("cgroup2", &hierarchy))
        return Error() << "cgroup2 path unavailable";
    unique_fd root(open(hierarchy.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (root < 0) return ErrnoError() << "cgroup2 root";
    auto system = OR_RETURN(OpenDirectoryAt(root.get(), "system"));
    // This process owns the namespace from its first creation until shutdown.
    // EEXIST is not adoption of somebody else's subtree.
    if (mkdirat(system.get(), "init-scopes", 0755))
        return ErrnoError() << "fresh init scope namespace";
    platform_parent = OR_RETURN(OpenDirectoryAt(system.get(), "init-scopes"));
    platform_path = hierarchy + "/system/init-scopes";
    OR_RETURN(DirectoryMode(platform_parent.get(), 0, 0, 0755));
    OR_RETURN(EnableMemory(platform_parent.get()));
    platform_parent_ready = true;
    return {};
}
sup::Population Population(sup::GroupPopulation value) {
    switch (value) {
        case sup::GroupPopulation::Empty:
            return sup::Population::Empty;
        case sup::GroupPopulation::Populated:
            return sup::Population::Populated;
        case sup::GroupPopulation::Removed:
            return sup::Population::Removed;
        case sup::GroupPopulation::Unknown:
            return sup::Population::Unknown;
    }
    return sup::Population::Unknown;
}
void CloseEvent(unique_fd& fd) {
    if (fd >= 0 && event_loop) {
        auto removed = event_loop->UnregisterHandler(fd.get());
        if (removed.ok()) {
            // End communication immediately, but do not allow descriptor number
            // reuse while Epoll still owns the old handler. Counts are bounded
            // by the instance and worker limits above.
            shutdown(fd.get(), SHUT_RDWR);
            retired_event_fds.emplace_back(std::move(fd));
            if (wake_main) wake_main();
            return;
        }
        LOG(ERROR) << removed.error();
    }
    fd.reset();
}
}  // namespace

struct DelegatedInstance : std::enable_shared_from_this<DelegatedInstance> {
    Service* service;
    sup::InstanceState state;
    std::shared_ptr<sup::CapturedCgroup> scope;
    unique_fd root, control, ready, initial_pidfd;
    std::string name, path, failure, published;
    std::optional<sup::MutationTicket> preparation;
    std::optional<sup::ObservationTicket> observation;
    std::optional<sup::CleanupTicket> cleanup;
    std::optional<siginfo_t> exit;
    std::optional<InterprocessFifo> activation;
    bool activation_released = false;
    pid_t initial_pid = 0;
    bool assigned = false, bootstrap_ready = false, root_allocated = false;
    bool kill_needed = false, kill_completed = false, confirm_needed = false;
    bool fully_retired = false, finalizing = false, startup_failed = false, quarantined = false;
    bool worker_initialized = false, worker_exited = false, worker_closing = false;
    bool reply_expired = false, worker_term_sent = false;
    pid_t worker_pid = 0;
    unique_fd worker_pidfd, channel;
    uint64_t worker_epoch = 0, sequence = 0;
    std::optional<sup::WorkerPacket> pending;
    sup::CleanupStats checkpoint{};
    boot_clock::time_point reply_deadline{}, ready_deadline{}, poll_after{}, grace_deadline{},
            cleanup_deadline{}, worker_exit_deadline{};

    DelegatedInstance(Service& owner, sup::InstanceId identity)
        : service(&owner), state(identity, {4, 1048576, 1048576}) {}
    std::string Reference() const {
        return std::to_string(state.identity().boot()) + "." +
               std::to_string(state.identity().serial());
    }
    void Publish() {
        std::string phase = fully_retired ? "retired"
                            : state.cleanup() == sup::Cleanup::Blocked || !failure.empty()
                                    ? "blocked"
                            : state.stop_latched() ? "stopping"
                            : state.active()       ? "active"
                                                   : "preparing";
        const std::string value = Reference() + ":" + phase + ":" + std::to_string(worker_pid);
        if (published != value) {
            SetProperty("init.svc_scope." + service->name(), value);
            LOG(INFO) << "delegated service " << service->name() << " instance " << value;
            published = value;
        }
    }
    void Stop() {
        if (cleanup_deadline == boot_clock::time_point{})
            cleanup_deadline = boot_clock::now() + kCleanupDeadline;
        state.stop(state.identity());
        kill_needed = true;
        const bool held = activation.has_value();
        if (activation) {
            activation->Close();
            activation.reset();
        }
        if ((!assigned || held) && initial_pidfd >= 0)
            syscall(SYS_pidfd_send_signal, initial_pidfd.get(), SIGKILL, nullptr, 0);
        Publish();
    }
    void Failed(const std::string& why) {
        failure = why;
        LOG(ERROR) << "delegated service " << service->name() << " " << Reference() << ": " << why;
        Stop();
        // A failed provider must not leave its known initial process able to
        // proceed. The enclosing scope remains owned until fully reconciled.
        if (initial_pidfd >= 0)
            syscall(SYS_pidfd_send_signal, initial_pidfd.get(), SIGKILL, nullptr, 0);
    }
    void Block(const std::string& why) {
        quarantined = true;
        Failed(why);
    }
    void FinishPreparation() {
        if (preparation) {
            state.finish_mutation(*preparation);
            preparation.reset();
        }
    }
    void ParentReady();
    bool SpawnWorker();
    bool Send(sup::WorkerOperation operation, uint32_t quantum = 0);
    void Receive();
    void Tick();
    std::optional<boot_clock::time_point> Deadline() const;
    void Finish();
};

void DelegatedInstance::ParentReady() {
    ReadyMessage message{};
    alignas(cmsghdr) char ancillary[CMSG_SPACE(sizeof(ucred)) + CMSG_SPACE(4 * sizeof(int))]{};
    iovec data{&message, sizeof(message)};
    msghdr packet{};
    packet.msg_iov = &data;
    packet.msg_iovlen = 1;
    packet.msg_control = ancillary;
    packet.msg_controllen = sizeof(ancillary);
    const ssize_t count = recvmsg(ready.get(), &packet, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    if (count < 0 && (errno == EAGAIN || errno == EINTR)) return;
    bool caller = false, invalid = false;
    for (auto* header = CMSG_FIRSTHDR(&packet); header; header = CMSG_NXTHDR(&packet, header)) {
        if (header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS &&
            header->cmsg_len >= CMSG_LEN(0)) {
            const size_t bytes = header->cmsg_len - CMSG_LEN(0);
            for (size_t n = 0; n + sizeof(int) <= bytes; n += sizeof(int)) {
                int owned;
                memcpy(&owned, CMSG_DATA(header) + n, sizeof(owned));
                close(owned);
            }
            invalid = true;
        } else if (!caller && header->cmsg_level == SOL_SOCKET &&
                   header->cmsg_type == SCM_CREDENTIALS &&
                   header->cmsg_len == CMSG_LEN(sizeof(ucred))) {
            ucred actual{};
            memcpy(&actual, CMSG_DATA(header), sizeof(actual));
            caller = actual.pid == initial_pid && actual.uid == service->uid() &&
                     actual.gid == service->gid();
            if (!caller) invalid = true;
        } else
            invalid = true;
    }
    CloseEvent(ready);
    if (state.stop_latched() || !initial_pid) return;
    std::string sid;
    char* actual_context = nullptr;
    if (getpidcon(initial_pid, &actual_context) == 0 && actual_context) {
        sid = actual_context;
        freecon(actual_context);
    }
    if (count != static_cast<ssize_t>(sizeof(message)) ||
        packet.msg_flags & (MSG_TRUNC | MSG_CTRUNC) || invalid || !caller || !scope ||
        message.magic != 0x44454c4547415445ULL || message.boot != state.identity().boot() ||
        message.instance != state.identity().serial() ||
        message.device != scope->identity().device || message.inode != scope->identity().inode ||
        sid != service->seclabel()) {
        Failed("bootstrap readiness identity/profile mismatch");
        return;
    }
    bootstrap_ready = true;
}

bool DelegatedInstance::SpawnWorker() {
    if (worker_pid || !scope || !event_loop || worker_epoch >= kMaximumWorkers) return false;
    int sockets[2];
    if (setsockcreatecon("u:object_r:andrix_cleanup_channel:s0")) {
        Failed("cleanup channel label");
        return false;
    }
    const int created =
            socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sockets);
    const int creation_error = errno;
    unique_fd parent, child;
    if (!created) {
        parent.reset(sockets[0]);
        child.reset(sockets[1]);
    }
    if (setsockcreatecon(nullptr) || created) {
        Failed("cleanup channel allocation/label reset: " + std::to_string(creation_error));
        return false;
    }
    if (sup::ConfigureWorkerSocket(parent.get()) || sup::ConfigureWorkerSocket(child.get())) {
        Failed("cleanup channel credentials");
        return false;
    }
    unique_fd safe_child(fcntl(child.get(), F_DUPFD_CLOEXEC, 10));
    if (safe_child < 0) {
        Failed("cleanup descriptor allocation");
        return false;
    }
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    if (posix_spawn_file_actions_init(&actions)) {
        Failed("cleanup spawn setup");
        return false;
    }
    if (posix_spawnattr_init(&attributes)) {
        posix_spawn_file_actions_destroy(&actions);
        Failed("cleanup spawn attributes");
        return false;
    }
    int result = posix_spawn_file_actions_adddup2(&actions, safe_child.get(), 3);
    result |= posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0);
    result |= posix_spawn_file_actions_addopen(&actions, 1, "/dev/null", O_WRONLY, 0);
    result |= posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0);
#ifdef __BIONIC__
    sigset_t empty, defaults;
    sigemptyset(&empty);
    sigfillset(&defaults);
    result |= posix_spawnattr_setsigmask(&attributes, &empty);
    result |= posix_spawnattr_setsigdefault(&attributes, &defaults);
    result |= posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT |
                                                            POSIX_SPAWN_SETSIGMASK |
                                                            POSIX_SPAWN_SETSIGDEF);
#else
    // Host builds exercise parsing and state construction only. Do not invent
    // a weaker inheritance path for sysroots without CLOEXEC_DEFAULT.
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attributes);
    Failed("cleanup process bootstrap requires the Android adapter");
    return false;
#endif
    const char* argv[] = {"/system/bin/andrix-scope-cleaner", "3", nullptr};
    char* environment[] = {nullptr};
    pid_t pid = 0;
    if (!result)
        result = posix_spawn(&pid, argv[0], &actions, &attributes, const_cast<char* const*>(argv),
                             environment);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attributes);
    if (result) {
        Failed("cleanup fixed bootstrap spawn: " + std::to_string(result));
        return false;
    }
    worker_pid = pid;
    worker_pidfd.reset(static_cast<int>(syscall(SYS_pidfd_open, pid, 0)));
    channel = std::move(parent);
    worker_initialized = false;
    worker_exited = false;
    worker_closing = false;
    worker_term_sent = false;
    reply_expired = false;
    ++worker_epoch;
    sequence = 0;
    const auto epoch = worker_epoch;
    auto weak = weak_from_this();
    auto registered = event_loop->RegisterHandler(channel.get(), [weak, epoch] {
        if (auto current = weak.lock(); current && current->worker_epoch == epoch) {
            current->Receive();
            DelegatedService::Pump();
        }
    });
    if (!registered.ok() || worker_pidfd < 0) {
        Failed("cleanup worker ownership/readiness");
        CloseEvent(channel);
        return false;
    }
    return Send(sup::WorkerOperation::Initialize);
}
bool DelegatedInstance::Send(sup::WorkerOperation operation, uint32_t quantum) {
    if (pending || channel < 0 || !worker_pid) return false;
    sup::WorkerPacket packet;
    packet.boot = state.identity().boot();
    packet.instance = state.identity().serial();
    packet.worker = worker_epoch;
    packet.sequence = ++sequence;
    packet.operation = operation;
    packet.quantum = quantum;
    sup::Failure error;
    std::unique_ptr<sup::CgroupTransfer> transfer;
    if (operation == sup::WorkerOperation::Initialize) {
        transfer = scope->Export(error);
        if (!transfer || transfer->name.size() >= packet.name.size()) {
            Failed("capture cleanup handoff");
            CloseEvent(channel);
            return false;
        }
        packet.objects = transfer->identities;
        packet.limits = transfer->limits;
        packet.stats = checkpoint;
        memcpy(packet.name.data(), transfer->name.c_str(), transfer->name.size() + 1);
    }
    int sent = sup::SendWorkerPacket(channel.get(), packet,
                                     transfer ? transfer->descriptors.data() : nullptr,
                                     transfer ? 4 : 0);
    if (sent) {
        // SOCK_SEQPACKET failure did not accept this complete message. No reader
        // or cursor has been dispatched, so consume only these unissued slots.
        if (observation) {
            state.acknowledge_observation_cancellation(*observation);
            observation.reset();
        }
        if (cleanup) {
            state.acknowledge_cleanup_cancellation(*cleanup);
            cleanup.reset();
        }
        Failed("cleanup command transport: " + std::to_string(sent));
        CloseEvent(channel);
        return false;
    }
    pending = packet;
    reply_expired = false;
    reply_deadline = boot_clock::now() + kReplyTimeout;
    if (operation == sup::WorkerOperation::Step) {
        checkpoint.steps += quantum;
        checkpoint.entry_visits += quantum;
        checkpoint.directory_visits += quantum + 1;
    }
    return true;
}
void DelegatedInstance::Receive() {
    if (!pending || channel < 0) return;
    sup::ReceivedWorkerPacket message;
    const int received = sup::ReceiveWorkerPacket(channel.get(), {worker_pid, 0, 0}, message);
    if (received == EAGAIN || received == EINTR) return;
    if (received) {
        Failed("cleanup reply transport: " + std::to_string(received));
        CloseEvent(channel);
        return;
    }
    auto reply = message.packet;
    if (message.descriptor_count || reply.boot != state.identity().boot() ||
        reply.instance != state.identity().serial() || reply.worker != worker_epoch ||
        reply.sequence != pending->sequence || reply.operation != pending->operation) {
        Failed("cleanup reply identity");
        CloseEvent(channel);
        return;
    }
    auto operation = pending->operation;
    pending.reset();
    reply_expired = false;
    checkpoint = reply.stats;
    if (operation == sup::WorkerOperation::Initialize) {
        worker_initialized = reply.error == sup::GroupError::None;
        if (!worker_initialized) Failed("cleanup handoff rejected");
    } else if (operation == sup::WorkerOperation::Kill) {
        kill_completed =
                reply.error == sup::GroupError::None || reply.error == sup::GroupError::Removed;
        kill_needed = !kill_completed;
        if (!kill_completed) Block("captured group kill failed");
    } else if (operation == sup::WorkerOperation::Observe && observation) {
        state.finish_observation(*observation, Population(reply.population));
        observation.reset();
        if (reply.population == sup::GroupPopulation::Populated) {
            kill_needed = true;
            poll_after = boot_clock::now() + 50ms;
        } else if (reply.population == sup::GroupPopulation::Removed)
            confirm_needed = true;
    } else if (operation == sup::WorkerOperation::ConfirmRemoved && observation) {
        if (reply.error == sup::GroupError::None &&
            reply.population == sup::GroupPopulation::Removed)
            state.finish_confirmed_removal(*observation);
        else {
            state.finish_observation(*observation, sup::Population::Unknown);
            if (reply.error != sup::GroupError::UnknownPopulation)
                Block("captured removal reconciliation refused");
        }
        observation.reset();
        confirm_needed = false;
    } else if (operation == sup::WorkerOperation::Step && cleanup) {
        const auto result = reply.error != sup::GroupError::None ? sup::CleanupResult::Failed
                            : reply.cursor == sup::CursorState::Retired
                                    ? sup::CleanupResult::Reclaimed
                                    : sup::CleanupResult::Progress;
        state.finish_cleanup_step(*cleanup, result);
        cleanup.reset();
        if (result == sup::CleanupResult::Failed) Block("captured subtree reclamation failed");
    } else if (operation == sup::WorkerOperation::Exit) {
        worker_closing = true;
    }
    Publish();
}
void DelegatedInstance::Finish() {
    if (fully_retired || worker_pid || pending || !state.restart_allowed()) return;
    if (!service->reap_callbacks_.empty()) {
        failure = "unqualified late reap callbacks; no retired PID callback will run";
        Publish();
        return;
    }
    fully_retired = true;
    CloseEvent(ready);
    initial_pidfd.reset();
    scope.reset();
    root.reset();
    control.reset();
    Publish();
    if (exit) {
        finalizing = true;
        service->Reap(
                *exit);  // Legacy final policy only, no numeric group operations for this profile.
        finalizing = false;
    } else {
        service->NotifyStateChange("stopped");
    }
    if (wake_main) wake_main();
}
void DelegatedInstance::Tick() {
    if (fully_retired) return;
    const auto now = boot_clock::now();
    if (!state.stop_latched() && now >= ready_deadline && !state.active())
        Failed("bootstrap readiness deadline");
    if (grace_deadline != boot_clock::time_point{} && now >= grace_deadline) {
        grace_deadline = {};
        Stop();
    }
    if (state.stop_latched() && !quarantined && cleanup_deadline != boot_clock::time_point{} &&
        now >= cleanup_deadline)
        Block("cleanup deadline; exact resources retained");
    if (pending && now >= reply_deadline) {
        if (!reply_expired) {
            if (observation) state.observation_timed_out(*observation);
            if (cleanup) state.cleanup_timed_out(*cleanup);
            failure = "cleanup reply deadline; worker still owned";
            reply_expired = true;
            Publish();
        }
        if ((pending->operation == sup::WorkerOperation::Exit || quarantined) &&
            worker_pidfd >= 0 && !worker_term_sent) {
            syscall(SYS_pidfd_send_signal, worker_pidfd.get(), SIGKILL, nullptr, 0);
            worker_term_sent = true;
        }
        // Keep the occupied operation slot. A timeout is not a worker death acknowledgement.
        return;
    }
    if (pending || worker_exited) return;
    if (state.restart_allowed()) {
        if (worker_pid && !worker_closing) {
            worker_closing = true;
            worker_exit_deadline = now + 1s;
            Send(sup::WorkerOperation::Exit);
        } else if (worker_pid && now >= worker_exit_deadline && worker_pidfd >= 0 &&
                   !worker_term_sent) {
            syscall(SYS_pidfd_send_signal, worker_pidfd.get(), SIGKILL, nullptr, 0);
            worker_term_sent = true;
        } else if (!worker_pid)
            Finish();
        return;
    }
    if (quarantined) {
        Publish();
        return;
    }
    if (!scope) {
        Publish();
        return;
    }
    if (!worker_pid) {
        if (!SpawnWorker()) {
            failure = "cleanup worker unavailable; instance quarantined";
            Publish();
        }
        return;
    }
    if (!worker_initialized) return;
    if (!state.stop_latched()) {
        if (activation) {
            auto released = activation->Write(kCgroupsActivated);
            activation->Close();
            activation.reset();
            if (!released.ok()) {
                Failed("held bootstrap activation failed");
                return;
            }
            activation_released = true;
        }
        if (activation_released && bootstrap_ready && !state.active()) {
            state.verify_profile(state.identity());
            if (state.complete_setup(state.identity())) state.activate(state.identity());
            Publish();
        }
        return;
    }
    if (now < poll_after) return;
    if (kill_needed) {
        Send(sup::WorkerOperation::Kill);
        return;
    }
    if (!state.process_reaped() && !state.initial_process_absent()) return;
    if (state.pending_mutations()) return;
    if (confirm_needed) {
        auto ticket = state.begin_observation(state.identity());
        if (ticket) {
            observation.emplace(*ticket);
            Send(sup::WorkerOperation::ConfirmRemoved);
        }
        return;
    }
    if (state.can_begin_cleanup()) {
        auto ticket = state.begin_cleanup_step(state.identity());
        if (ticket) {
            cleanup.emplace(*ticket);
            Send(sup::WorkerOperation::Step, kQuantum);
        }
    } else {
        auto ticket = state.begin_observation(state.identity());
        if (ticket) {
            observation.emplace(*ticket);
            Send(sup::WorkerOperation::Observe);
        }
    }
}

std::optional<boot_clock::time_point> DelegatedInstance::Deadline() const {
    std::optional<boot_clock::time_point> next;
    auto include = [&](boot_clock::time_point value) {
        if (value != boot_clock::time_point{} && (!next || value < *next)) next = value;
    };
    if (fully_retired) return next;
    if (pending && !reply_expired) include(reply_deadline);
    if (!state.stop_latched() && !state.active()) include(ready_deadline);
    if (state.stop_latched() && !quarantined && !state.restart_allowed()) include(cleanup_deadline);
    include(grace_deadline);
    if (worker_closing && worker_pid && !pending && !worker_term_sent)
        include(worker_exit_deadline);
    if (!pending && !quarantined && state.stop_latched() && poll_after > boot_clock::now())
        include(poll_after);
    return next;
}

Result<void> DelegatedService::Configure(Service& service, const std::vector<std::string>& args) {
    if (args.size() != 5 || service.delegation_profile_)
        return Error() << "one complete delegated_scope profile required";
    DelegatedProfile profile;
    if (!android::base::ParseUint(args[1], &profile.memory) ||
        !android::base::ParseUint(args[2], &profile.swap) ||
        !android::base::ParseUint(args[3], &profile.descendants) ||
        !android::base::ParseUint(args[4], &profile.depth) || profile.memory == 0 ||
        profile.memory > 1024ULL * 1024 * 1024 || profile.swap != 0 || profile.descendants < 2 ||
        profile.descendants > 64 || profile.depth < 2 || profile.depth > 8)
        return Error() << "unsupported delegated scope bounds";
    service.delegation_profile_ = profile;
    return {};
}
Result<void> DelegatedService::Validate(const Service& service) {
    if (!service.delegation_profile_) return {};
    if (!service.proc_attr_.parsed_uid || service.uid() == 0 || service.gid() != service.uid() ||
        !service.capabilities_ || service.capabilities_->any() || service.seclabel_.empty())
        return Error() << "explicit complete unprivileged service profile required";
    if (service.flags_ & (SVC_TEMPORARY | SVC_EXEC | SVC_CONSOLE | SVC_GENTLE_KILL | SVC_CRITICAL |
                          SVC_SHUTDOWN_CRITICAL) ||
        service.is_updatable() || service.override_ || service.namespaces_.flags ||
        !service.namespaces_.namespaces_to_enter.empty() || !service.sockets_.empty() ||
        !service.files_.empty() || !service.environment_vars_.empty() ||
        !service.reap_callbacks_.empty() || service.shared_kallsyms_file_ ||
        !service.writepid_files_.empty() || service.on_failure_reboot_target_ ||
        service.disable_hardened_malloc_)
        return Error() << "unsupported delegated service feature";
    if (service.swappiness_ != -1 || service.soft_limit_in_bytes_ != -1 ||
        service.limit_in_bytes_ != -1 || service.limit_percent_ != -1 ||
        !service.limit_property_.empty())
        return Error() << "use the declared scope bounds, not PID-derived memcg options";
    for (const auto& profile : service.task_profiles_)
        if (profile != "SCHED_SP_BACKGROUND" && profile != "ProcessCapacityLow")
            return Error() << "unsupported process profile for delegated path";
    for (const auto& arg : service.args_)
        if (arg.find('$') != std::string::npos)
            return Error() << "fixed bootstrap arguments required";
    if (service.args_.empty() ||
        (service.args_[0].find("/system/") != 0 && service.args_[0].find("/system_ext/") != 0))
        return Error() << "fixed system bootstrap required";
    bool core = false, files = false, processes = false, size = false;
    for (const auto& [resource, limit] : service.proc_attr_.rlimits) {
        if (resource == RLIMIT_CORE) core = limit.rlim_cur == 0 && limit.rlim_max == 0;
        if (resource == RLIMIT_NOFILE)
            files = limit.rlim_cur == limit.rlim_max && limit.rlim_max >= 64 &&
                    limit.rlim_max <= 256;
        if (resource == RLIMIT_NPROC)
            processes = limit.rlim_cur == limit.rlim_max && limit.rlim_max > 0 &&
                        limit.rlim_max <= 1024;
        if (resource == RLIMIT_FSIZE)
            size = limit.rlim_cur == limit.rlim_max && limit.rlim_max != RLIM_INFINITY;
    }
    if (!core || !files || !processes || !size)
        return Error() << "explicit bounded rlimits required";
    if (service.oom_score_adjust_ == DEFAULT_OOM_SCORE_ADJUST)
        return Error() << "explicit memory supervision priority required";
    return {};
}
Result<void> DelegatedService::BeforeStart(Service& service) {
    if (!service.delegation_profile_) return {};
    if (!android::base::GetBoolProperty("ro.debuggable", false))
        return Error() << "delegated proof requires debug product";
    OR_RETURN(Validate(service));
    if (!event_loop || !identities) return Error() << "delegated supervisor not installed";
    if (service.delegation_instance_) {
        const auto& current = service.delegation_instance_;
        if (service.IsRunning() && !current->state.stop_latched() && !current->finalizing)
            return {};
        if (!current->fully_retired || current->finalizing)
            return Error() << "previous exact instance has not retired";
    }
    size_t count = 0;
    for (auto it = instances.begin(); it != instances.end();) {
        auto instance = it->second.lock();
        if (!instance || instance->fully_retired)
            it = instances.erase(it);
        else {
            ++count;
            ++it;
        }
    }
    if (count >= kMaximumInstances) return Error() << "delegated proof instance capacity";
    return {};
}
Result<void> DelegatedService::Prepare(Service& service, std::vector<Descriptor>& descriptors) {
    if (!service.delegation_profile_) return {};
    auto identity = identities->allocate();
    if (!identity) return Error() << "service instance identity exhausted";
    auto current = std::make_shared<DelegatedInstance>(service, *identity);
    service.delegation_instance_ = current;
    instances.emplace(identity->serial(), current);
    current->ready_deadline = boot_clock::now() + kReadyTimeout;
    auto preparation = current->state.begin_mutation(*identity);
    if (!preparation) return Error() << "cannot reserve preparation";
    current->preparation.emplace(*preparation);
    current->name = "instance_" + std::to_string(identity->serial());
    auto build = [&]() -> Result<void> {
        OR_RETURN(PrepareParent());
        current->path = platform_path + "/" + current->name;
        if (mkdirat(platform_parent.get(), current->name.c_str(), 0755))
            return ErrnoError() << "fresh instance root";
        current->root_allocated = true;
        current->root = OR_RETURN(OpenDirectoryAt(platform_parent.get(), current->name.c_str()));
        OR_RETURN(DirectoryMode(current->root.get(), 0, 0, 0755));
        sup::Failure error;
        current->scope = sup::CapturedCgroup::Capture(platform_parent.get(), current->name,
                                                      {8, 512, 16384, 32768, kQuantum}, error);
        if (!current->scope)
            return Error() << "captured root unavailable: " << sup::group_error_name(error.code)
                           << ":" << error.error;
        current->state.capture_root(*identity);
        const auto& profile = *service.delegation_profile_;
        OR_RETURN(WriteRead(current->root.get(), "memory.max", std::to_string(profile.memory)));
        OR_RETURN(WriteRead(current->root.get(), "memory.swap.max", std::to_string(profile.swap)));
        OR_RETURN(WriteRead(current->root.get(), "memory.oom.group", "1"));
        OR_RETURN(WriteRead(current->root.get(), "cgroup.max.descendants",
                            std::to_string(profile.descendants)));
        OR_RETURN(
                WriteRead(current->root.get(), "cgroup.max.depth", std::to_string(profile.depth)));
        OR_RETURN(EnableMemory(current->root.get()));
        if (mkdirat(current->root.get(), "control", 0755) ||
            mkdirat(current->root.get(), "work", 0755))
            return ErrnoError() << "fresh delegated leaves";
        current->control = OR_RETURN(OpenDirectoryAt(current->root.get(), "control"));
        auto work = OR_RETURN(OpenDirectoryAt(current->root.get(), "work"));
        OR_RETURN(DirectoryMode(current->control.get(), 0, 0, 0755));
        OR_RETURN(DirectoryMode(work.get(), service.uid(), service.gid(), 0755));
        OR_RETURN(DelegateFile(current->root.get(), "cgroup.procs", service.uid(), service.gid()));
        OR_RETURN(DelegateFile(work.get(), "cgroup.procs", service.uid(), service.gid()));
        OR_RETURN(DelegateFile(work.get(), "cgroup.subtree_control", service.uid(), service.gid()));
        OR_RETURN(EnableMemory(work.get()));
        int pair[2];
        if (setsockcreatecon("u:object_r:andrix_delegation_ready_socket:s0"))
            return ErrnoError() << "readiness socket label";
        const int created =
                socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, pair);
        const int socket_error = errno;
        unique_fd child;
        if (!created) {
            current->ready.reset(pair[0]);
            child.reset(pair[1]);
        }
        if (setsockcreatecon(nullptr)) return ErrnoError() << "reset socket creation label";
        if (created) {
            errno = socket_error;
            return ErrnoError() << "readiness socket";
        }
        if (sup::ConfigureWorkerSocket(current->ready.get()))
            return Error() << "readiness credentials";
        auto weak = std::weak_ptr<DelegatedInstance>(current);
        const int expected_ready = current->ready.get();
        OR_RETURN(event_loop->RegisterHandler(expected_ready, [weak, expected_ready] {
            if (auto entry = weak.lock();
                entry && entry->ready.get() == expected_ready && !entry->bootstrap_ready) {
                entry->ParentReady();
                DelegatedService::Pump();
            }
        }));
        unique_fd exported(fcntl(current->root.get(), F_DUPFD_CLOEXEC, 3));
        if (exported < 0) return ErrnoError() << "bootstrap scope descriptor";
        unique_fd inherited_ready(fcntl(child.get(), F_DUPFD_CLOEXEC, 3));
        if (inherited_ready < 0) return ErrnoError() << "bootstrap readiness descriptor";
        descriptors.emplace_back("ANDROID_DELEGATED_ROOT_FD", std::move(exported));
        descriptors.emplace_back("ANDROID_DELEGATED_READY_FD", std::move(inherited_ready));
        std::erase_if(service.once_environment_vars_, [](const auto& entry) {
            return entry.first == "ANDROID_DELEGATED_INSTANCE";
        });
        service.once_environment_vars_.emplace_back("ANDROID_DELEGATED_INSTANCE",
                                                    current->Reference());
        if (!current->SpawnWorker()) return Error() << "cleanup ownership unavailable before fork";
        return {};
    };
    auto result = build();
    if (!result.ok()) {
        current->startup_failed = true;
        current->FinishPreparation();
        current->state.report_no_initial_process(*identity);
        current->Failed(result.error().message());
        if (!current->root_allocated)
            current->state.retire_unallocated(*identity);
        else if (!current->scope)
            current->quarantined = true;
        Pump();
        return result;
    }
    current->Publish();
    return {};
}
Result<void> DelegatedService::Assign(Service& service, pid_t process) {
    auto current = service.delegation_instance_;
    if (!service.delegation_profile_ || !current) return Error() << "no delegated preparation";
    current->initial_pid = process;
    current->initial_pidfd.reset(static_cast<int>(syscall(SYS_pidfd_open, process, 0)));
    if (current->initial_pidfd < 0) return ErrnoError() << "capture initial process";
    std::string actual_oom;
    if (!ReadFileToString("/proc/" + std::to_string(process) + "/oom_score_adj", &actual_oom) ||
        android::base::Trim(actual_oom) != std::to_string(service.oom_score_adjust_))
        return Error() << "initial memory priority readback";
    unique_fd destination(
            openat(current->control.get(), "cgroup.procs", O_WRONLY | O_CLOEXEC | O_NOFOLLOW));
    if (destination < 0 || !WriteStringToFd(std::to_string(process), destination.get()))
        return ErrnoError() << "place held initial process";
    // The parent still owns the unreaped child during this numeric operation.
    current->assigned = true;
    current->FinishPreparation();
    return {};
}
void DelegatedService::HoldActivation(Service& service, InterprocessFifo&& gate) {
    auto current = service.delegation_instance_;
    if (!current || current->state.stop_latched()) {
        gate.Close();
        return;
    }
    current->activation.emplace(std::move(gate));
}
void DelegatedService::AfterWait() {
    // Called only after the main Epoll has finished dispatch and erased every
    // deferred handler. No callback can then resolve an old FD to a new worker.
    retired_event_fds.clear();
}
#if !defined(__BIONIC__)
// Host test exercises the actual retirement operation against the actual init
// Epoll class without installing a supervisor or creating any cgroup.
void TestDelegatedEventRetirement(Epoll& epoll, unique_fd& descriptor) {
    auto* saved = event_loop;
    event_loop = &epoll;
    CloseEvent(descriptor);
    event_loop = saved;
}
#endif
void DelegatedService::NoProcess(Service& service) {
    if (auto current = service.delegation_instance_) {
        current->FinishPreparation();
        current->state.report_no_initial_process(current->state.identity());
        current->startup_failed = true;
        current->Stop();
        Pump();
    }
}
void DelegatedService::SetupFailed(Service& service) {
    if (auto current = service.delegation_instance_) {
        current->startup_failed = true;
        current->FinishPreparation();
        current->Failed("initial service setup failed");
        Pump();
    }
}
bool DelegatedService::Signal(Service& service, int signal) {
    if (!service.delegation_profile_) return false;
    auto current = service.delegation_instance_;
    if (!current || current->fully_retired) return true;
    current->Stop();
    if (signal == SIGTERM && current->initial_pidfd >= 0 && !current->state.process_exited()) {
        syscall(SYS_pidfd_send_signal, current->initial_pidfd.get(), SIGTERM, nullptr, 0);
        current->grace_deadline = boot_clock::now() + kKillGrace;
        current->kill_needed = false;
    }
    Pump();
    return true;
}
bool DelegatedService::DeferReap(Service& service, const siginfo_t& status) {
    auto current = service.delegation_instance_;
    if (!service.delegation_profile_ || !current || current->finalizing) return false;
    if (!current->exit) {
        current->exit = status;
        current->Stop();
        current->FinishPreparation();
        current->state.report_initial_process_exit(current->state.identity());
        if (service.oom_score_adjust_ != DEFAULT_OOM_SCORE_ADJUST)
            LmkdUnregisterCaptured(service.name_, service.pid_, current->state.identity().boot(),
                                   current->state.identity().serial());
        service.pid_ = 0;
        service.flags_ &= ~SVC_RUNNING;
        CloseEvent(current->ready);
        service.NotifyStateChange("stopping");
    }
    Pump();
    return true;
}
bool DelegatedService::WorkerExited(pid_t pid, const siginfo_t& status) {
    for (auto& [serial, weak] : instances) {
        auto current = weak.lock();
        if (!current || current->worker_pid != pid) continue;
        current->worker_exited = true;
        LOG(INFO) << "delegated cleanup worker " << pid << " for " << current->Reference()
                  << " exited " << status.si_status;
        return true;
    }
    return false;
}
void DelegatedService::Reaped(pid_t pid) {
    for (auto& [serial, weak] : instances) {
        auto current = weak.lock();
        if (!current) continue;
        if (current->initial_pid == pid && current->state.process_exited()) {
            current->state.report_initial_process_reaped(current->state.identity());
            current->initial_pid = 0;
            current->initial_pidfd.reset();
        }
        if (current->worker_pid == pid && current->worker_exited) {
            CloseEvent(current->channel);
            current->worker_pidfd.reset();
            current->worker_pid = 0;
            current->worker_exited = false;
            current->worker_initialized = false;
            if (current->observation) {
                current->state.acknowledge_observation_cancellation(*current->observation);
                current->observation.reset();
            }
            if (current->cleanup) {
                current->state.acknowledge_cleanup_cancellation(*current->cleanup);
                current->cleanup.reset();
            }
            current->pending.reset();
            current->confirm_needed = current->state.stop_latched();
            current->kill_needed = current->state.stop_latched();
        }
    }
    Pump();
}
bool DelegatedService::Enabled(const Service& service) {
    return service.delegation_profile_.has_value();
}
int DelegatedService::RegisterWithLmkd(int socket, const Service& service) {
#if defined(__BIONIC__)
    auto current = service.delegation_instance_;
    if (!current || !current->scope || !current->assigned || current->initial_pidfd < 0 ||
        current->initial_pid != service.pid_ || current->state.process_exited()) {
        errno = ESTALE;
        return -1;
    }
    sup::Failure error;
    auto cohort = current->scope->Export(error);
    if (!cohort) {
        errno = error.error ? error.error : EIO;
        return -1;
    }
    const lmk_service_instance registration{service.pid_, service.uid(), service.oom_score_adjust_,
                                            current->state.identity().boot(),
                                            current->state.identity().serial()};
    return lmkd_register_service_instance(socket, &registration, current->initial_pidfd.get(),
                                          cohort->descriptors[2]);
#else
    (void)socket;
    (void)service;
    errno = ENOTSUP;
    return -1;
#endif
}
bool DelegatedService::Pending(const Service& service) {
    return service.delegation_instance_ && (!service.delegation_instance_->fully_retired ||
                                            service.delegation_instance_->finalizing);
}
bool DelegatedService::Removable(const Service& service) {
    return !Pending(service);
}
bool DelegatedService::Empty(const Service& service) {
    auto current = service.delegation_instance_;
    return !current || current->fully_retired ||
           current->state.population() == sup::Population::Empty ||
           current->state.population() == sup::Population::Removed;
}
bool DelegatedService::AnyStopping() {
    for (auto& [serial, weak] : instances) {
        auto current = weak.lock();
        if (current && current->state.stop_latched() && !current->fully_retired) return true;
    }
    return false;
}
void DelegatedService::Install(Epoll& epoll, std::function<void()> wake) {
    event_loop = &epoll;
    wake_main = std::move(wake);
    uint64_t boot = 0;
    if (syscall(SYS_getrandom, &boot, sizeof(boot), 0) != static_cast<ssize_t>(sizeof(boot)) ||
        !boot) {
        LOG(ERROR) << "delegated boot identity unavailable";
        return;
    }
    identities =
            std::make_unique<sup::InstanceAllocator>(boot, std::numeric_limits<uint64_t>::max());
    timer.reset(timerfd_create(CLOCK_BOOTTIME, TFD_CLOEXEC | TFD_NONBLOCK));
    if (timer < 0) {
        identities.reset();
        return;
    }
    auto installed = epoll.RegisterHandler(timer.get(), [] {
        uint64_t count;
        while (read(timer.get(), &count, sizeof(count)) == static_cast<ssize_t>(sizeof(count))) {
        }
        DelegatedService::Pump();
    });
    if (!installed.ok()) {
        identities.reset();
        timer.reset();
        LOG(ERROR) << installed.error();
    }
}
void DelegatedService::Pump() {
    if (pumping || timer < 0) return;
    pumping = true;
    std::vector<std::shared_ptr<DelegatedInstance>> entries;
    for (auto& [serial, weak] : instances)
        if (auto entry = weak.lock()) entries.push_back(entry);
    std::optional<boot_clock::time_point> next;
    for (const auto& entry : entries) {
        entry->Receive();
        entry->Tick();
        auto deadline = entry->Deadline();
        if (deadline && (!next || *deadline < *next)) next = deadline;
    }
    itimerspec interval{};
    if (next) {
        auto delay = std::max(
                std::chrono::duration_cast<std::chrono::nanoseconds>(*next - boot_clock::now()),
                1ns);
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(delay);
        interval.it_value.tv_sec = seconds.count();
        interval.it_value.tv_nsec = (delay - seconds).count();
    }
    if (timerfd_settime(timer.get(), 0, &interval, nullptr))
        PLOG(ERROR) << "delegated deadline timer";
    pumping = false;
}
Result<void> DelegatedService::StopExact(Service& service, std::string_view reference) {
    auto current = service.delegation_instance_;
    if (!current || current->Reference() != reference || current->fully_retired)
        return Error() << "stale delegated service instance";
    service.Stop();
    return {};
}
Result<void> DelegatedService::WorkerFault(Service& service, std::string_view reference,
                                           std::string_view operation) {
    auto current = service.delegation_instance_;
    if (!android::base::GetBoolProperty("ro.debuggable", false) || !current ||
        current->Reference() != reference || current->fully_retired || current->worker_pidfd < 0)
        return Error() << "invalid exact worker fault target";
    int signal = operation == "pause"    ? SIGSTOP
                 : operation == "resume" ? SIGCONT
                 : operation == "crash"  ? SIGKILL
                                         : 0;
    if (!signal || syscall(SYS_pidfd_send_signal, current->worker_pidfd.get(), signal, nullptr, 0))
        return ErrnoError() << "worker fault";
    return {};
}
Result<void> DelegatedService::MemoryTest(Service& service, std::string_view reference) {
    auto current = service.delegation_instance_;
    if (!android::base::GetBoolProperty("ro.debuggable", false) || !current ||
        current->Reference() != reference || current->fully_retired || current->initial_pid <= 0 ||
        current->state.stop_latched())
        return Error() << "invalid exact memory test target";
    if (!LmkdTestKillCaptured(current->initial_pid, current->state.identity().boot(),
                              current->state.identity().serial()))
        return Error() << "memory supervisor test request failed";
    return {};
}
}  // namespace android::init
