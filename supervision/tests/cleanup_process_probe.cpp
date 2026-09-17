// SPDX-License-Identifier: Apache-2.0
// Host mechanism driver. This executable is not installed on Android.
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <regex>
#include <string>

#include "captured_cgroup.h"
#include "cleanup_worker.h"
#include "instance_state.h"

using namespace andrix::supervision;
namespace {
std::string line(const std::string& name) {
  std::ifstream f(name);
  assert(f);
  std::string s;
  std::getline(f, s);
  return s;
}
std::string check_environment() {
  auto member = line("/proc/self/cgroup");
  assert(member.starts_with("0::/user.slice/user-1003.slice/") &&
         member.ends_with("/control"));
  auto path =
      std::string("/sys/fs/cgroup") + member.substr(3, member.size() - 11);
  assert(std::regex_match(
      path.substr(path.find_last_of('/') + 1),
      std::regex(
          "andrix-delegated-worker-kernel-[0-9]{8}t[0-9]{6}z\\.service")));
  assert(line(path + "/memory.max") == "536870912" &&
         line(path + "/memory.swap.max") == "0");
  assert(line(path + "/cpu.max") == "200000 100000" &&
         line(path + "/pids.max") == "128");
  rlimit core{};
  assert(!getrlimit(RLIMIT_CORE, &core) && core.rlim_cur == 0 &&
         core.rlim_max == 0);
  return path;
}
Population converted(GroupPopulation p) {
  switch (p) {
    case GroupPopulation::Empty:
      return Population::Empty;
    case GroupPopulation::Populated:
      return Population::Populated;
    case GroupPopulation::Removed:
      return Population::Removed;
    case GroupPopulation::Unknown:
      return Population::Unknown;
  }
  return Population::Unknown;
}
const char* phase(Cleanup p) {
  switch (p) {
    case Cleanup::NotStarted:
      return "not_started";
    case Cleanup::Stopping:
      return "stopping";
    case Cleanup::Reclaiming:
      return "reclaiming";
    case Cleanup::Blocked:
      return "blocked";
    case Cleanup::Retired:
      return "retired";
  }
  return "unknown";
}
class Worker {
 public:
  Worker(const char* binary, std::shared_ptr<CapturedCgroup> root)
      : binary_(binary), root_(std::move(root)) {}
  ~Worker() {
    if (pid_ > 0) crash();
  }
  void start() {
    assert(pid_ == 0 && epoch_ < 4);
    ++epoch_;
    sequence_ = 0;
    int pair[2];
    assert(!socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair));
    assert(!ConfigureWorkerSocket(pair[0]) && !ConfigureWorkerSocket(pair[1]));
    int childfd = fcntl(pair[1], F_DUPFD_CLOEXEC, 10);
    assert(childfd >= 10);
    close(pair[1]);
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attrs;
    assert(!posix_spawn_file_actions_init(&actions) &&
           !posix_spawnattr_init(&attrs));
    assert(!posix_spawn_file_actions_adddup2(&actions, childfd, 3));
    assert(!posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY,
                                             0));
    assert(!posix_spawn_file_actions_addopen(&actions, 1, "/dev/null", O_WRONLY,
                                             0));
#ifdef __BIONIC__
    assert(!posix_spawnattr_setflags(&attrs, POSIX_SPAWN_CLOEXEC_DEFAULT));
#else
    assert(!posix_spawn_file_actions_addclosefrom_np(&actions, 4));
#endif
    const char* args[]{binary_, "--cleanup-worker", "3", nullptr};
    char* environment[]{nullptr};
    assert(!posix_spawn(&pid_, binary_, &actions, &attrs,
                        const_cast<char* const*>(args), environment));
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attrs);
    close(childfd);
    socket_ = pair[0];
    pidfd_ = static_cast<int>(syscall(SYS_pidfd_open, pid_, 0));
    assert(pidfd_ >= 0);
    Failure failure;
    auto transfer = root_->Export(failure);
    assert(transfer);
    WorkerPacket init;
    init.operation = WorkerOperation::Initialize;
    init.boot = 1;
    init.instance = 1;
    init.worker = epoch_;
    init.sequence = ++sequence_;
    init.objects = transfer->identities;
    init.limits = transfer->limits;
    init.stats = checkpoint_;
    assert(transfer->name.size() < init.name.size());
    memcpy(init.name.data(), transfer->name.c_str(), transfer->name.size() + 1);
    pending_ = init;
    assert(!SendWorkerPacket(socket_, init, transfer->descriptors.data(), 4));
    auto reply = receive();
    assert(reply.error == GroupError::None);
  }
  void send(WorkerOperation operation, uint32_t quantum = 0) {
    if (!pid_) start();
    assert(!pending_);
    WorkerPacket packet;
    packet.boot = 1;
    packet.instance = 1;
    packet.worker = epoch_;
    packet.sequence = ++sequence_;
    packet.operation = operation;
    packet.quantum = quantum;
    pending_ = packet;
    if (operation == WorkerOperation::Step) {
      // Charge a conservative outstanding quantum if the worker loses its
      // reply.
      checkpoint_.steps += quantum;
      checkpoint_.entry_visits += quantum;
      checkpoint_.directory_visits += quantum + 1;
    }
    assert(!SendWorkerPacket(socket_, packet));
  }
  WorkerPacket receive() {
    assert(pending_);
    pollfd ready{socket_, POLLIN, 0};
    assert(poll(&ready, 1, 5000) == 1);
    ReceivedWorkerPacket message;
    assert(!ReceiveWorkerPacket(socket_, {pid_, getuid(), getgid()}, message));
    const auto& packet = message.packet;
    assert(message.descriptor_count == 0 && packet.boot == 1 &&
           packet.instance == 1 && packet.worker == epoch_ &&
           packet.sequence == pending_->sequence &&
           packet.operation == pending_->operation);
    checkpoint_ = packet.stats;
    pending_.reset();
    return packet;
  }
  WorkerPacket call(WorkerOperation operation, uint32_t quantum = 0) {
    send(operation, quantum);
    return receive();
  }
  void signal(int number) {
    assert(pidfd_ >= 0 &&
           !syscall(SYS_pidfd_send_signal, pidfd_, number, nullptr, 0));
  }
  void pause() {
    signal(SIGSTOP);
    int status = 0;
    assert(waitpid(pid_, &status, WUNTRACED) == pid_ && WIFSTOPPED(status));
  }
  void crash() {
    signal(SIGKILL);
    int status = 0;
    assert(waitpid(pid_, &status, 0) == pid_ && WIFSIGNALED(status) &&
           WTERMSIG(status) == SIGKILL);
    close(socket_);
    close(pidfd_);
    socket_ = pidfd_ = -1;
    pid_ = 0;
    pending_.reset();
  }
  uint64_t epoch() const { return epoch_; }
  pid_t pid() const { return pid_; }

 private:
  const char* binary_;
  std::shared_ptr<CapturedCgroup> root_;
  pid_t pid_ = 0;
  int pidfd_ = -1, socket_ = -1;
  uint64_t epoch_ = 0, sequence_ = 0;
  CleanupStats checkpoint_{};
  std::optional<WorkerPacket> pending_;
};
}  // namespace
int main(int argc, char** argv) {
  auto own = check_environment();
  if (argc == 3 && !strcmp(argv[1], "--cleanup-worker")) {
    assert(!strcmp(argv[2], "3"));
    DIR* descriptors = opendir("/proc/self/fd");
    assert(descriptors);
    const int scan = dirfd(descriptors);
    while (auto* entry = readdir(descriptors)) {
      if (entry->d_name[0] == '.') continue;
      int fd = atoi(entry->d_name);
      assert(fd <= 3 || fd == scan);
    }
    closedir(descriptors);
    return RunCleanupWorker(3, {getppid(), getuid(), getgid()});
  }
  assert(argc == 2);
  int parent = open(own.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  assert(parent >= 0);
  Failure error;
  auto scope = CapturedCgroup::Capture(parent, argv[1],
                                       {8, 512, 8192, 16384, 32}, error);
  close(parent);
  assert(scope);
  Worker worker(argv[0], scope);
  worker.start();
  const InstanceId identity(1, 1);
  InstanceState state(identity, {2, 10000, 10000});
  auto mutation = state.begin_mutation(identity);
  assert(mutation && state.capture_root(identity));
  std::optional<CleanupTicket> pending;
  auto output = [&](const char* event, bool accepted,
                    WorkerPacket result = {}) {
    std::cout << "{\"event\":\"" << event
              << "\",\"accepted\":" << (accepted ? "true" : "false")
              << ",\"worker\":" << worker.epoch()
              << ",\"worker_pid\":" << worker.pid() << ",\"cleanup\":\""
              << phase(state.cleanup()) << "\",\"pending\":"
              << (state.cleanup_pending() ? "true" : "false")
              << ",\"restart_allowed\":"
              << (state.restart_allowed() ? "true" : "false") << ",\"error\":\""
              << group_error_name(result.error)
              << "\",\"errno\":" << result.error_number << ",\"population\":\""
              << population_name(result.population)
              << "\",\"steps\":" << result.stats.steps
              << ",\"removed\":" << result.stats.removed_directories << "}\n"
              << std::flush;
  };
  output("ready", true);
  auto finish = [&]() {
    auto reply = worker.receive();
    assert(pending);
    auto result = reply.error != GroupError::None ? CleanupResult::Failed
                  : reply.cursor == CursorState::Retired
                      ? CleanupResult::Reclaimed
                      : CleanupResult::Progress;
    bool accepted = state.finish_cleanup_step(*pending, result);
    pending.reset();
    output("step", accepted, reply);
  };
  for (std::string command; std::getline(std::cin, command);) {
    if (command == "quit") {
      output("quit", true);
      return 0;
    }
    if (command == "kill") {
      state.stop(identity);
      auto reply = worker.call(WorkerOperation::Kill);
      output("kill", reply.error == GroupError::None, reply);
    } else if (command == "exit-fact")
      output("exit", state.report_initial_process_exit(identity));
    else if (command == "reap-fact")
      output("reap", state.report_initial_process_reaped(identity));
    else if (command == "absent-fact")
      output("absent", state.report_no_initial_process(identity));
    else if (command == "finish-mutation") {
      bool ok = mutation && state.finish_mutation(*mutation);
      mutation.reset();
      output("mutation", ok);
    } else if (command == "observe" || command == "confirm") {
      auto ticket = state.begin_observation(identity);
      if (!ticket) {
        output("observe_rejected", false);
        continue;
      }
      auto reply =
          worker.call(command == "observe" ? WorkerOperation::Observe
                                           : WorkerOperation::ConfirmRemoved);
      bool accepted =
          command == "confirm" && reply.error == GroupError::None
              ? state.finish_confirmed_removal(*ticket)
              : state.finish_observation(
                    *ticket, command == "observe" ? converted(reply.population)
                                                  : Population::Unknown);
      output(command.c_str(), accepted, reply);
    } else if (command.starts_with("step ") || command.starts_with("queue ")) {
      auto ticket = state.begin_cleanup_step(identity);
      if (!ticket) {
        output("step_rejected", false);
        continue;
      }
      uint32_t quantum = static_cast<uint32_t>(
          std::stoul(command.substr(command.find(' ') + 1)));
      pending.emplace(*ticket);
      worker.send(WorkerOperation::Step, quantum);
      if (command.starts_with("step "))
        finish();
      else
        output("queued", true);
    } else if (command == "finish-step")
      finish();
    else if (command == "timeout")
      output("timeout", pending && state.cleanup_timed_out(*pending));
    else if (command == "pause-worker") {
      worker.pause();
      output("paused", true);
    } else if (command == "continue-worker") {
      worker.signal(SIGCONT);
      output("continued", true);
    } else if (command == "crash-worker") {
      worker.crash();
      bool acknowledged =
          !pending || state.acknowledge_cleanup_cancellation(*pending);
      pending.reset();
      output("worker_reaped", acknowledged);
    } else if (command == "inspect")
      output("inspect", true);
    else
      return 5;
  }
  return 6;
}
