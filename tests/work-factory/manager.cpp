// SPDX-License-Identifier: Apache-2.0
// Finite lab manager. Both backends use the same request and control surface.
#include <aidl/dev/andrix/proof/factory/BnFactory.h>
#include <aidl/dev/andrix/proof/factory/BnWork.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android/binder_ibinder_platform.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <mutex>
#include <thread>
#include <vector>

#include "common.h"
#include "guards.h"

using namespace andrix::factory_proof;
using android::base::unique_fd;
using ndk::ScopedAStatus;
namespace api = aidl::dev::andrix::proof::factory;
namespace {
#ifdef ANDRIX_FACTORY_INIT
constexpr bool kInit = true;
#else
constexpr bool kInit = false;
#endif
bool caller(bool pid = true) {
  const char* sid = AIBinder_getCallingSid();
  return sid && AIBinder_getCallingUid() == 2000 &&
         (!pid || AIBinder_getCallingPid() > 1) &&
         strcmp(sid, "u:r:shell:s0") == 0;
}
ScopedAStatus denied() { return ScopedAStatus::fromExceptionCode(EX_SECURITY); }
void own_binder(AIBinder* binder) { AIBinder_setRequestingSid(binder, true); }

class Work final : public api::BnWork {
 public:
  Work(uint64_t manager, uint64_t work, bool blocked)
      : manager_id(manager), work_id(work), block(blocked) {}
  ScopedAStatus observe(api::WorkState* out) override {
    if (!caller()) return denied();
    std::lock_guard lock(mutex);
    out->managerId = manager_id;
    out->workId = work_id;
    out->phase = removed ? Removed : (stopped ? Stopping : state.phase);
    out->guardianPid = state.guardian;
    out->entryPid = state.entry;
    out->entryExited = state.entry_exited;
    out->descendants.clear();
    for (auto pid : state.descendants)
      if (pid > 1) out->descendants.push_back(pid);
    out->pulses = state.pulses;
    out->stopRequests = stop_count;
    out->stopCallerPid = stop_pid;
    out->groupPath = path;
    out->creationReturned = creation_returned;
    out->guardianExited = exited;
    out->guardianStatus = exit_status;
    return ScopedAStatus::ok();
  }
  ScopedAStatus hold(int64_t id, bool* accepted) override {
    return command(id, Hold, Ready, accepted);
  }
  ScopedAStatus release(int64_t id, bool* accepted) override {
    return command(id, Release, Held, accepted);
  }
  ScopedAStatus stop(int64_t id, bool crash) override {
    if (!caller(false)) return denied();
    stop_pid = AIBinder_getCallingPid();
    ++stop_count;
    if (id > 0 && uint64_t(id) == work_id) {
      crash_guardian = crash;
      stopped = true;
    }
    return ScopedAStatus::ok();
  }
  ScopedAStatus command(int64_t id, uint32_t op, int phase, bool* accepted) {
    if (!caller()) return denied();
    *accepted = false;
    std::lock_guard lock(mutex);
    if (id <= 0 || uint64_t(id) != work_id || stopped || removed ||
        state.phase != phase || pending || (op == Hold && hold_issued) ||
        (op == Release && release_issued))
      return ScopedAStatus::ok();
    if (op == Hold)
      hold_issued = true;
    else
      release_issued = true;
    pending = op;
    *accepted = true;
    return ScopedAStatus::ok();
  }
  const uint64_t manager_id, work_id;
  const bool block;
  std::atomic<bool> stopped{false}, crash_guardian{false};
  std::atomic<int64_t> stop_count{0};
  std::atomic<int32_t> stop_pid{-1};
  std::mutex mutex;
  Packet state{};
  unique_fd group, pidfd, control;
  std::string path;
  bool creation_returned = false, exited = false, removed = false,
       stop_sent = false, reaped = false;
  bool hold_issued = false, release_issued = false;
  int exit_status = -1;
  uint32_t pending = 0;
};

class Factory final : public api::BnFactory {
 public:
  explicit Factory(std::string owned_root)
      : id(random_id()),
        root(std::move(owned_root)),
        listener(manager_socket(id, true)) {
    if (listener < 0) fail("manager listener");
    int pipe[2];
    if (pipe2(pipe, O_CLOEXEC)) fail("allocator gate");
    allocator_read.reset(pipe[0]);
    allocator_write.reset(pipe[1]);
  }
  ScopedAStatus observe(api::FactoryState* out) override {
    if (!caller()) return denied();
    auto list = works();
    out->managerId = id;
    out->managerPid = getpid();
    out->backend = kInit ? "init" : "delegated";
    out->groupPath = root;
    out->reserved = list.size();
    out->created = 0;
    out->removed = 0;
    for (auto& work : list) {
      std::lock_guard lock(work->mutex);
      out->created += work->state.guardian > 1;
      out->removed += work->removed;
    }
    out->allocatorBlocked = allocator_blocked;
    return ScopedAStatus::ok();
  }
  ScopedAStatus create(int64_t request, bool block,
                       std::shared_ptr<api::IWork>* out) override {
    if (!caller()) return denied();
    if (request <= 0)
      return ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
    std::lock_guard lock(mutex);
    if (closing) return ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
    auto old = requests.find(request);
    if (old != requests.end()) {
      if (old->second->block != block)
        return ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
      *out = old->second;
      return ScopedAStatus::ok();
    }
    if (requests.size() >= 8)
      return ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
    const auto work_id = random_id();
    for (const auto& [old_request, existing] : requests) {
      (void)old_request;
      if (existing->work_id == work_id)
        return ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
    }
    auto work = ndk::SharedRefBase::make<Work>(id, work_id, block);
    work->state.phase = Preparing;
    work->state.manager = id;
    work->state.work = work->work_id;
    auto binder = work->asBinder();
    own_binder(binder.get());
    work_binders.push_back(std::move(binder));  // Preserve this exact SID-requesting Binder.
    requests.emplace(request, work);
    queue.push_back(work);
    *out = work;
    ready.notify_one();
    return ScopedAStatus::ok();
  }
  ScopedAStatus find(int64_t request,
                     std::shared_ptr<api::IWork>* out) override {
    if (!caller()) return denied();
    std::lock_guard lock(mutex);
    auto found = requests.find(request);
    *out = found == requests.end() ? nullptr : found->second;
    return ScopedAStatus::ok();
  }
  ScopedAStatus finish(int64_t manager) override {
    if (!caller(false)) return denied();
    if (manager > 0 && uint64_t(manager) == id) closing = true;
    return ScopedAStatus::ok();
  }
  ScopedAStatus unblockAllocator(int64_t manager, bool* accepted) override {
    if (!caller()) return denied();
    *accepted = false;
    if (manager <= 0 || uint64_t(manager) != id ||
        !allocator_blocked.exchange(false))
      return ScopedAStatus::ok();
    char byte = 'R';
    if (write(allocator_write, &byte, 1) != 1) fail("allocator unblock");
    *accepted = true;
    return ScopedAStatus::ok();
  }
  ScopedAStatus crash(int64_t manager) override {
    if (!caller(false)) return denied();
    if (manager > 0 && uint64_t(manager) == id) _exit(77);
    return ScopedAStatus::ok();
  }
  std::vector<std::shared_ptr<Work>> works() {
    std::lock_guard lock(mutex);
    std::vector<std::shared_ptr<Work>> result;
    for (const auto& [request, work] : requests) {
      (void)request;
      result.push_back(work);
    }
    return result;
  }
  void launch_thread() {
    std::thread([this] { allocator(); }).detach();
  }
  void allocator() {
    for (;;) {
      std::shared_ptr<Work> work;
      {
        std::unique_lock lock(mutex);
        ready.wait(lock, [&] { return !queue.empty(); });
        work = queue.front();
        queue.pop_front();
      }
      if (work->block) {
        allocator_blocked = true;
        char byte = 0;
        if (read(allocator_read, &byte, 1) != 1 || byte != 'R')
          fail("allocator blocked operation");
        // Deliberately finish the already accepted operation after Stop.
        // It must be cleaned up without payload release, never retargeted.
      }
      if (kInit)
        create_init(work);
      else
        create_delegated(work);
    }
  }
  void create_delegated(const std::shared_ptr<Work>& work) {
    const std::string path = root + "/work_" + std::to_string(work->work_id);
    if (mkdir(path.c_str(), 0755)) fail("unique work cgroup");
    auto group = open_group(path);
    if (group < 0 ||
        !write_control(group, "memory.max", std::to_string(kMemory)) ||
        !write_control(group, "memory.swap.max", "0") ||
        !write_control(group, "memory.oom.group", "1"))
      fail("work bounds");
    int gate[2];
    if (pipe2(gate, O_CLOEXEC)) fail("launch gate");
    unique_fd input(gate[0]), output(gate[1]);
    std::string manager = std::to_string(id),
                token = std::to_string(work->work_id);
    char* args[] = {const_cast<char*>(kGuardian), manager.data(), token.data(),
                    nullptr};
    char path_env[] = "PATH=/system/bin";
    char* env[] = {path_env, nullptr};
    pid_t child = fork();
    if (!child) {
      char byte = 0;
      close(output.get());
      if (read(input, &byte, 1) != 1 || byte != 'G') _exit(125);
      for (int fd = 3; fd < 128; ++fd) close(fd);
      execve(kGuardian, args, env);
      _exit(127);
    }
    if (child < 0) fail("guardian fork");
    unique_fd pidfd(syscall(SYS_pidfd_open, child, 0));
    if (pidfd < 0) fail("guardian pidfd");
    if (!write_control(group, "cgroup.procs", std::to_string(child))) {
      syscall(SYS_pidfd_send_signal, pidfd.get(), SIGKILL, nullptr, 0);
      waitpid(child, nullptr, 0);
      fail("guardian assignment");
    }
    {
      std::lock_guard lock(work->mutex);
      work->group = std::move(group);
      work->pidfd = std::move(pidfd);
      work->path = path;
      work->state.guardian = child;
      work->creation_returned = true;
    }
    if (!work->stopped) {
      char byte = 'G';
      if (write(output, &byte, 1) != 1) fail("guardian launch release");
    }
    // Closing an unreleased gate makes the fixed pre-exec bootstrap refuse.
  }
  void create_init(const std::shared_ptr<Work>& work) {
    const std::string ticket =
        std::to_string(id) + ":" + std::to_string(work->work_id);
    if (!android::base::SetProperty("sys.andrix.factory.request", ticket))
      fail("init request delivery");
    auto end = now_ms() + 20000;
    for (;;) {
      auto reply = android::base::GetProperty("sys.andrix.factory.reply", "");
      if (reply.starts_with(ticket + ":")) {
        auto result = reply.substr(ticket.size() + 1);
        uint64_t pid = 0;
        if (!parse_id(result.c_str(), &pid) || pid <= 1 ||
            pid > static_cast<uint64_t>(std::numeric_limits<pid_t>::max()))
          fail("init creation result");
        const auto created_pid = static_cast<pid_t>(pid);
        std::lock_guard lock(work->mutex);
        if (work->state.guardian && work->state.guardian != created_pid)
          fail("init/peer PID disagreement");
        work->state.guardian = created_pid;
        work->creation_returned = true;
        break;
      }
      if (now_ms() >= end)
        fail("init creation deadline; outcome not silently retried");
      usleep(10000);
    }
  }
  void tick() {
    // Only this thread owns the accepted socket collection and scope-control
    // I/O.
    for (;;) {
      int accepted =
          accept4(listener, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
      if (accepted < 0) {
        if (errno != EAGAIN && errno != EINTR) fail("accept");
        break;
      }
      if (unregistered.size() >= 8) {
        close(accepted);
        fail("pending peer bound");
      }
      unregistered.emplace_back(accepted);
    }
    auto list = works();
    for (auto it = unregistered.begin(); it != unregistered.end();) {
      pollfd check{it->get(), POLLIN | POLLHUP | POLLERR, 0};
      poll(&check, 1, 0);
      if (check.revents & (POLLHUP | POLLERR)) {
        it = unregistered.erase(it);
        continue;
      }
      if (!(check.revents & POLLIN)) {
        ++it;
        continue;
      }
      pid_t peer = 0;
      Packet hello;
      if (!peer_is_coordinator(*it, &peer) || !receive_packet(*it, &hello) ||
          hello.operation != Hello || hello.manager != id ||
          hello.guardian != peer)
        fail("registered kernel peer");
      std::shared_ptr<Work> found;
      for (auto& work : list)
        if (work->work_id == hello.work) found = work;
      if (!found) fail("unknown work registration");
      {
        std::lock_guard lock(found->mutex);
        if (found->control >= 0 ||
            (found->state.guardian && found->state.guardian != peer))
          fail("duplicate/wrong guardian");
        found->state.guardian = peer;
        if (kInit) {
          found->path = std::string(kUidGroup) + "/pid_" + std::to_string(peer);
          found->group = open_group(found->path);
          found->pidfd.reset(syscall(SYS_pidfd_open, peer, 0));
          if (found->group < 0 || found->pidfd < 0)
            fail("actual init group binding");
        }
        found->control = std::move(*it);
        Packet reply;
        reply.operation = Accept;
        reply.manager = id;
        reply.work = found->work_id;
        if (!send_packet(found->control, reply))
          fail("registration acceptance");
      }
      it = unregistered.erase(it);
    }
    for (auto& work : list) tick_work(work);
    if (closing && !allocator_blocked) {
      bool done = true;
      for (auto& work : list) {
        std::lock_guard lock(work->mutex);
        done &= work->removed;
      }
      if (done) {
        if (!kInit) {
          auto directory = open_group(root);
          if (!write_control(directory, "cgroup.subtree_control", "-memory") ||
              !write_control(directory, "cgroup.procs",
                             std::to_string(getpid())) ||
              rmdir((root + "/control").c_str()))
            fail("graceful delegated-manager cleanup");
        }
        _exit(0);
      }
    }
  }
  void tick_work(const std::shared_ptr<Work>& work) {
    std::lock_guard lock(work->mutex);
    if (work->removed || !work->state.guardian) return;
    if (work->control >= 0) {
      for (int n = 0; n < 8; ++n) {
        Packet state;
        if (!receive_packet(work->control, &state)) break;
        if (state.operation != State || state.manager != id ||
            state.work != work->work_id ||
            state.guardian != work->state.guardian || state.phase < Ready ||
            state.phase > Released)
          fail("scope snapshot identity");
        work->state = state;
      }
      if (work->stopped && !work->stop_sent) {
        Packet command;
        command.operation = Stop;
        command.manager = id;
        command.work = work->work_id;
        command.crash = work->crash_guardian;
        if (send_packet(work->control, command)) work->stop_sent = true;
      } else if (!work->stopped && work->pending) {
        Packet command;
        command.operation = work->pending;
        command.manager = id;
        command.work = work->work_id;
        if (send_packet(work->control, command)) work->pending = 0;
      }
    }
    if (!kInit && work->creation_returned) {
      siginfo_t info{};
      if (waitid(P_PID, work->state.guardian, &info,
                 WEXITED | WNOHANG | WNOWAIT))
        fail("owned guardian waitid");
      if (info.si_pid) {
        work->exited = true;
        work->exit_status =
            info.si_code == CLD_EXITED ? info.si_status : 128 + info.si_status;
      }
      // A deliberate guardian crash is delivered through its control channel;
      // other Stop paths can end a preparing guardian without waiting for
      // Hello.
      const bool kill =
          work->exited || (work->stopped && !work->crash_guardian);
      if (kill && work->group >= 0 &&
          !write_control(work->group, "cgroup.kill", "1"))
        fail("exact group kill");
      if (work->exited && work->group >= 0 && !populated(work->group)) {
        if (rmdir(work->path.c_str())) fail("leaf group reclamation");
        if (waitpid(work->state.guardian, nullptr, 0) != work->state.guardian)
          fail("reap after group cleanup");
        work->reaped = true;
        work->removed = true;
        work->control.reset();
      }
    } else if (kInit && work->pidfd >= 0) {
      pollfd exited{work->pidfd.get(), POLLIN, 0};
      poll(&exited, 1, 0);
      if (exited.revents & POLLIN) work->exited = true;
      if (work->exited && work->group >= 0) {
        struct stat st{};
        if (lstat(work->path.c_str(), &st) < 0 && errno == ENOENT) {
          work->removed = true;
          work->control.reset();
        }
      }
    }
  }
  const uint64_t id;
  const std::string root;
  unique_fd listener, allocator_read, allocator_write;
  std::atomic<bool> allocator_blocked{false}, closing{false};
  std::mutex mutex;
  std::condition_variable ready;
  std::map<int64_t, std::shared_ptr<Work>> requests;
  std::vector<ndk::SpAIBinder> work_binders;
  std::deque<std::shared_ptr<Work>> queue;
  std::vector<unique_fd> unregistered;
};

void recover(const std::string& previous, const std::string& current) {
  uint64_t pid = 0;
  if (kInit || previous.empty() || !parse_id(previous.c_str(), &pid)) return;
  const std::string path =
      std::string(kUidGroup) + "/pid_" + std::to_string(pid);
  if (path == current) return;
  auto group = open_group(path);
  if (group < 0) return;
  if (populated(group)) fail("prior manager group still populated");
  DIR* directory = fdopendir(dup(group.get()));
  if (!directory) fail("recovery directory");
  while (auto entry = readdir(directory)) {
    if (entry->d_type != DT_DIR || !strcmp(entry->d_name, ".") ||
        !strcmp(entry->d_name, ".."))
      continue;
    const std::string name = entry->d_name;
    uint64_t unused = 0;
    if (name != "control" &&
        (!name.starts_with("work_") || !parse_id(name.c_str() + 5, &unused)))
      fail("unknown recovery subtree");
    auto leaf = open_group(path + "/" + name);
    if (leaf < 0 || populated(leaf)) fail("nonempty recovery leaf");
    if (unlinkat(group, entry->d_name, AT_REMOVEDIR))
      fail("recovery leaf removal");
  }
  closedir(directory);
  // Existing init rmdir runs on its service-control thread, not through a stale
  // asynchronous numeric-PID kill. It may refuse a path now used by a live
  // service.
  if (!android::base::SetProperty("sys.andrix.factory.reclaim_pid", previous))
    fail("reclaim request");
  auto end = now_ms() + 5000;
  while (access(path.c_str(), F_OK) == 0) {
    if (now_ms() > end) fail("reclaim acknowledgement absent");
    usleep(10000);
  }
  if (errno != ENOENT) fail("reclaim observation");
}
}  // namespace

int main(int, char** argv) {
  android::base::InitLogging(argv,
                             android::base::LogdLogger(android::base::SYSTEM));
  if (!android::base::GetBoolProperty("ro.debuggable", false) ||
      getppid() != 1 || !andrix::check_identity().empty() ||
      role() != "u:r:andrixd:s0")
    fail("manager bootstrap");
  const auto root = current_group();
  if (root != std::string(kUidGroup) + "/pid_" + std::to_string(getpid()))
    fail("manager init group");
  auto previous =
      android::base::GetProperty("sys.andrix.factory.manager_pid", "");
  if (!android::base::SetProperty("sys.andrix.factory.manager_pid",
                                  std::to_string(getpid())))
    fail("manager PID publication");
  auto began = now_ms();
  std::string error;
  while (!(error = bounds_error(root, false)).empty()) {
    if (now_ms() - began > 15000) fail(error);
    usleep(10000);
  }
  if (!kInit) {
    auto parent = open_group(root);
    struct stat st{};
    while (stat((root + "/cgroup.procs").c_str(), &st) || st.st_uid != 7500) {
      if (now_ms() - began > 15000) fail("delegated controls");
      usleep(10000);
    }
    recover(previous, root);
    if (mkdir((root + "/control").c_str(), 0755) ||
        !write_control(open_group(root + "/control"), "cgroup.procs",
                       std::to_string(getpid())) ||
        !write_control(parent, "cgroup.subtree_control", "+memory"))
      fail("delegation activation");
  }
  auto factory = ndk::SharedRefBase::make<Factory>(root);
  // The manager occupies its control leaf; work leaves are siblings below its
  // init scope.
  if (!kInit && current_group() != root + "/control")
    fail("manager control membership");
  ABinderProcess_setThreadPoolMaxThreadCount(2);
  ABinderProcess_startThreadPool();
  auto binder = factory->asBinder();
  own_binder(binder.get());
  ndk::SpAIBinder old(AServiceManager_checkService(kManagerService));
  if (old.get() && AIBinder_isAlive(old.get()))
    fail("live factory cannot be replaced");
  if (AServiceManager_addService(binder.get(), kManagerService) != STATUS_OK)
    fail("factory service");
  factory->launch_thread();
  while (now_ms() - began < 300000) {
    factory->tick();
    usleep(10000);
  }
  _exit(0);
}
